"""Private KDBX identity records and receipt-only broker operations."""
from __future__ import annotations

import json
import re
import secrets
import unicodedata

from .persistence import SaveError
from .protocol import MAX_MESSAGE
from .versions import active_entries
from .writes import MAX_WRITES, Write, WriteError, group_for

MARKER = 'akdbx.identity'
FIELDS = {
    'name': 'Full name',
    'given-name': 'Given name',
    'additional-name': 'Additional name',
    'family-name': 'Family name',
    'address-line1': 'Address line 1',
    'address-line2': 'Address line 2',
    'address-line3': 'Address line 3',
    'address-level2': 'City or locality',
    'address-level1': 'State, province or region',
    'postal-code': 'Postcode',
    'country': 'Two-letter country code (for example DE)',
    'country-name': 'Country name',
    'tel': 'Phone number',
    'email': 'Email address',
}
FILL_FIELDS = (*FIELDS, 'street-address')
FIELD_LIMIT = 256
COMMANDS = {'create-identity', 'search-identities', 'pin-identity-target', 'fill-identity'}
REFUSED = 'identity operation refused; check label, group and vault readiness'
FAILED = 'identity operation failed'


def is_identity(entry):
    element = getattr(entry, '_element', None)
    if element is not None:
        return element.find('./String[Key="' + MARKER + '"]') is not None
    getter = getattr(entry, 'get_custom_property', None)
    return getter is not None and getter(MARKER) is not None


def property_key(field):
    return f'{MARKER}.{field}'


def _text(value, limit, *, allow_joiners=False):
    joiners = {'\u200c', '\u200d'} if allow_joiners else set()
    return (isinstance(value, str) and len(value) <= limit
            and not any(unicodedata.category(c)[0] == 'C' or c in '\u2028\u2029'
                        for c in value if c not in joiners))


def _value_for(entry, field):
    if field not in FILL_FIELDS or not is_identity(entry) or entry.get_custom_property(MARKER) != 'v1':
        raise WriteError()
    if field == 'street-address':
        value = '\n'.join(filter(None, (_field_value(entry, f'address-line{i}') for i in (1, 2, 3))))
    else:
        value = _field_value(entry, field)
    if not value:
        raise WriteError()
    return value


def _field_value(entry, field):
    value = entry.get_custom_property(property_key(field)) or ''
    if not _text(value, FIELD_LIMIT, allow_joiners=True) or field == 'country' and value and not re.fullmatch('[A-Z]{2}', value):
        raise WriteError()
    return value


class IdentityManager:
    def __init__(self, broker):
        self.broker = broker

    def dispatch(self, request, ready):
        from .browser_card import failure

        action = request['action']
        targets = self.broker.identity_targets
        if action == 'fill-identity':
            try:
                # Both references are single use, even when the other is invalid.
                try:
                    entry = self.broker._resolve(request.get('handle'))
                except ValueError:
                    entry = None
                pin = targets.consume(request.get('target'))
                try:
                    deadline = request.get('start_deadline')
                    if (entry is None or not _protocol_ok(request)
                            or set(request) != {'action', 'identity_protocol', 'handle', 'target', 'field', 'start_deadline'}
                            or type(deadline) not in {int, float}
                            or not self.broker.clock() < deadline <= self.broker.clock() + 4
                            or request['field'] != pin['field'] or not ready()):
                        return failure(kind='identity')
                    value = _value_for(entry, request['field'])
                    return targets.fill(pin, value, request['field'],
                                        lambda: ready() and self.broker.clock() < deadline, deadline)
                finally:
                    targets._close(pin)
            except Exception:
                return failure(kind='identity')
        try:
            if not _protocol_ok(request):
                raise WriteError()
            if action == 'pin-identity-target':
                return targets.pin(request)
            if action == 'create-identity':
                return self.begin(request)
            return self.search(request)
        except WriteError:
            return failure(kind='identity') if action == 'pin-identity-target' else dict(ok=False, error=REFUSED)
        except Exception:
            return failure(kind='identity') if action == 'pin-identity-target' else dict(ok=False, error=FAILED)

    def search(self, request):
        query = request.get('query', '')
        group_filter = request.get('group')
        exact = request.get('exact', False)
        if (set(request) - {'action', 'identity_protocol', 'query', 'group', 'exact'}
                or type(exact) is not bool or not _text(query, 4096 if exact else 500)
                or 'group' in request and (not _text(group_filter, 4096) or len(group_filter.encode()) > 4096)):
            raise WriteError()
        if not exact:
            query = query.casefold()
        matches = []
        remaining = MAX_MESSAGE - len(b'{"ok":true,"entries":[]}')
        for entry in active_entries(self.broker.vault):
            if not is_identity(entry) or entry.get_custom_property(MARKER) != 'v1':
                continue
            title, group = entry.title or '', '/'.join(entry.path[:-1])
            if group_filter is not None and group != group_filter:
                continue
            matched = title == query if exact else query in title.casefold()
            if not matched or any(len(v.encode()) > 4096 for v in (title, group)):
                continue
            item = dict(title=title, group=group)
            # Reserve the exact serialized size before minting a handle.
            size = len(json.dumps(dict(item, handle='0' * 64), separators=(',', ':')))
            if matches:
                size += 1  # Separator between records.
            if size > remaining:
                continue
            matches.append(dict(item, handle=self.broker._new_handle(entry)))
            remaining -= size
            if len(matches) == 20:
                break
        return dict(ok=True, entries=matches)

    def begin(self, request):
        values = request.get('metadata')
        if (set(request) != {'action', 'identity_protocol', 'metadata'}
                or not isinstance(values, dict) or set(values) != {'title', 'group'}
                or any(not _text(v, 4096) or len(v.encode()) > 4096 for v in values.values())
                or not values['title'].strip()):
            raise WriteError()
        writes = self.broker.writes
        writes._require_available()
        group_for(self.broker.vault, values['group'])
        writes._prune()
        if len(writes.operations) >= MAX_WRITES:
            raise WriteError()
        handle = secrets.token_hex(32)
        op = Write(secrets.token_urlsafe(32), self.broker.clock() + 300, writes.revision, dict(values), kind='identity')
        writes.operations[handle] = op
        return dict(ok=True, state='pending', write_handle=handle,
                    private_url=writes.public_base.rstrip('/') + '/identity?token=' + op.token)

    def submit(self, op, values, confirmed):
        if (not confirmed or op.kind != 'identity' or op.state != 'pending'
                or op.revision != self.broker.writes.revision or op.expires <= self.broker.clock()
                or set(values) != set(FIELDS) or any(not _text(v, FIELD_LIMIT, allow_joiners=True) for v in values.values())):
            return dict(ok=False, error='invalid or expired identity save')
        values = {key: value.strip() for key, value in values.items()}
        if not any(values.values()) or values['country'] and not re.fullmatch('[A-Za-z]{2}', values['country']):
            return dict(ok=False, error='enter at least one field and use a two-letter country code if provided')
        values['country'] = values['country'].upper()

        def matches(candidate):
            group = group_for(candidate, op.values['group'])
            return group, [entry for entry in active_entries(candidate)
                           if is_identity(entry) and entry.title == op.values['title'] and entry.group == group]

        def mutate(candidate):
            from pykeepass.entry import Entry

            group, duplicates = matches(candidate)
            if duplicates:
                raise WriteError()
            entry = Entry(title=op.values['title'], username='', password='', kp=candidate)
            group.append(entry)
            entry.set_custom_property(MARKER, 'v1')
            for field, value in values.items():
                if value:
                    entry.set_custom_property(property_key(field), value, protect=True)

        def verify(candidate):
            _, entries = matches(candidate)
            if len(entries) != 1 or entries[0].get_custom_property(MARKER) != 'v1':
                raise SaveError()
            entry = entries[0]
            for field, value in values.items():
                node = entry._element.find('./String[Key="' + property_key(field) + '"]/Value')
                if (entry.get_custom_property(property_key(field)) or '') != value or (
                        value and (node is None or node.get('Protected') != 'True')):
                    raise SaveError()

        vault = self.broker.vault
        try:
            self.broker.vault = vault._akdbx_store.commit(vault, mutate, verify_candidate=verify)
        except Exception:
            op.state = 'failed'
            op.error = 'identity save failed; vault update not confirmed'
            return dict(ok=False, error=op.error)
        op.state = 'saved'
        self.broker.writes.invalidate_revision(op)
        return dict(ok=True, state='saved')


def _protocol_ok(request):
    return type(request.get('identity_protocol')) is int and request['identity_protocol'] == 1
