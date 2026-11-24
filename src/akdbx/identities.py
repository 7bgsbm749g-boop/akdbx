"""Private KDBX identity records and receipt-only broker operations."""
from __future__ import annotations

import json
import re
import secrets
import unicodedata

from .persistence import SaveError
from .protocol import MAX_MESSAGE
from .versions import active_entries
from .writes import MAX_WRITES, Write, WriteError, _entry_changed_at, group_for

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
COMMANDS = {'create-identity', 'update-identity', 'search-identities', 'pin-identity-target', 'fill-identity'}
REFUSED = 'identity operation refused; check label, group and vault readiness'
# Optional ``fields`` on create-identity: the page shows and accepts only these.
FIELDS_PROTOCOL = 1
# update-identity: add or change chosen fields of one selected identity.
UPDATE_PROTOCOL = 1
FAILED = 'identity operation failed'
# pin-identity-target ``field_purpose`` (and ``allow_autocomplete_off``): the agent
# verified the field's purpose on a field without a matching autocomplete token.
FIELD_PURPOSE_PROTOCOL = 1
# fill-identity ``format`` for tel: ``national`` removes the country calling code.
TEL_FORMATS = ('national',)
# Two-digit country calling codes (ITU-T E.164). Codes that start with 1 or 7
# have one digit; every other code has three. The set of codes is prefix-free,
# so these rules split any international number without a full table.
TWO_DIGIT_CODES = frozenset(
    '20 27 30 31 32 33 34 36 39 40 41 43 44 45 46 47 48 49 51 52 53 54 55 56 57 58 '
    '60 61 62 63 64 65 66 81 82 84 86 90 91 92 93 94 95 98'.split())


def capabilities():
    return dict(identity_fields_protocol=FIELDS_PROTOCOL, identity_update_protocol=UPDATE_PROTOCOL,
                identity_field_purpose_protocol=FIELD_PURPOSE_PROTOCOL, identity_tel_formats=list(TEL_FORMATS))


def calling_code(digits):
    """The country calling code at the start of an international number's digits."""
    if digits[:1] in {'1', '7'}:
        return digits[:1]
    return digits[:2] if digits[:2] in TWO_DIGIT_CODES else digits[:3]


def national_number(value, expected_code=None):
    """The national number of a saved international phone number, digits only.

    The saved value must start with ``+`` or ``00`` and the country calling code.
    Spaces, hyphens, dots, slashes and brackets are dropped, and so is a ``(0)``
    trunk prefix (as in ``+44 (0)20 ...``). Anything else refuses, so a value
    with an extension or letters is never cut short. ``expected_code`` (digits)
    must equal the number's calling code, for a separate country picker that
    already shows it.
    """
    text = value.strip()
    if text.startswith('+'):
        text = text[1:]
    elif text.startswith('00'):
        text = text[2:]
    else:
        raise WriteError()
    text = re.sub(r'\(\s*0\s*\)', '', text, count=1)
    if not re.fullmatch(r'[0-9 ().\-/\u00a0]+', text) or text.count('(') != text.count(')'):
        raise WriteError()
    digits = re.sub(r'[^0-9]', '', text)
    code = calling_code(digits)
    national = digits[len(code):]
    if (len(code) < 1 or not 4 <= len(national) <= 14 or len(digits) > 15
            or expected_code is not None and expected_code != code):
        raise WriteError()
    return national


def formatted(value, field, formatting, expected_code):
    if formatting is None:
        if expected_code is not None:
            raise WriteError()
        return value
    if field != 'tel' or formatting not in TEL_FORMATS:
        raise WriteError()
    return national_number(value, expected_code)


def requested_fields(request):
    """The page's fields in FIELDS order: all of them, or the requested subset."""
    if 'fields' not in request:
        return tuple(FIELDS)
    fields = request['fields']
    if (not isinstance(fields, list) or not fields or len(set(map(str, fields))) != len(fields)
            or any(not isinstance(f, str) or f not in FIELDS for f in fields)):
        raise WriteError()
    return tuple(f for f in FIELDS if f in fields)


def _label(entry):
    return entry.title or '', '/'.join(entry.path[:-1])


def _selected(vault, uuid, title, group):
    """The one active v1 identity with this uuid, title and group, if its label is unique."""
    same = [e for e in active_entries(vault) if is_identity(e) and _label(e) == (title, group)]
    if len(same) != 1 or same[0].uuid != uuid or same[0].get_custom_property(MARKER) != 'v1':
        raise WriteError()
    return same[0]


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
        from .browser_slots import SlotError

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
                    expected_code = request.get('calling_code')
                    if (entry is None or not _protocol_ok(request)
                            or set(request) - {'format', 'calling_code'}
                            != {'action', 'identity_protocol', 'handle', 'target', 'field', 'start_deadline'}
                            or 'format' in request and request['format'] not in TEL_FORMATS
                            or 'calling_code' in request and (
                                'format' not in request or not isinstance(expected_code, str)
                                or not re.fullmatch('[1-9][0-9]{0,2}', expected_code))
                            or type(deadline) not in {int, float}
                            or not self.broker.clock() < deadline <= self.broker.clock() + 4
                            or request['field'] != pin['field'] or not ready()):
                        return failure(kind='identity')
                    value = formatted(_value_for(entry, request['field']), request['field'],
                                      request.get('format'), expected_code)
                    return targets.fill(pin, value, request['field'],
                                        lambda: ready() and self.broker.clock() < deadline, deadline)
                finally:
                    targets._close(pin)
            except Exception:
                return failure(kind='identity')
        try:
            if not _protocol_ok(request):
                if action == 'update-identity':
                    # A search handle is single use, even on a refused request.
                    try:
                        self.broker._resolve(request.get('handle'))
                    except ValueError:
                        pass
                raise WriteError()
            if action == 'pin-identity-target':
                return targets.pin(request)
            if action in {'create-identity', 'update-identity'}:
                return self.begin(request)
            return self.search(request)
        except SlotError as exc:
            return dict(ok=False, error=str(exc))
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
        matches = {}
        for entry in active_entries(self.broker.vault):
            if not is_identity(entry) or entry.get_custom_property(MARKER) != 'v1':
                continue
            title, group = entry.title or '', '/'.join(entry.path[:-1])
            if group_filter is not None and group != group_filter:
                continue
            if not label_matches(title, query, exact) or any(len(v.encode()) > 4096 for v in (title, group)):
                continue
            key = (title, group)
            matches[key] = None if key in matches else entry
        # Exclude collisions before counting results or minting handles.
        entries = []
        remaining = MAX_MESSAGE - len(b'{"ok":true,"entries":[]}')
        for (title, group), entry in matches.items():
            if entry is None:
                continue
            item = dict(title=title, group=group)
            # Reserve the exact serialized size before minting a handle.
            size = len(json.dumps(dict(item, handle='0' * 64), separators=(',', ':')))
            if entries:
                size += 1  # Separator between records.
            if size > remaining:
                continue
            entries.append(dict(item, handle=self.broker._new_handle(entry)))
            remaining -= size
            if len(entries) == 20:
                break
        return dict(ok=True, entries=entries)

    def begin(self, request):
        update = request['action'] == 'update-identity'
        # A search handle is single use, even when the request is refused.
        try:
            entry = self.broker._resolve(request.get('handle')) if update else None
        except ValueError:
            raise WriteError() from None
        values = request.get('metadata')
        base = {'action', 'identity_protocol', 'metadata'}
        if (((set(request) != base | {'handle', 'fields'}) if update else
                (not base <= set(request) or set(request) - (base | {'fields'})))
                or not isinstance(values, dict) or set(values) != {'title', 'group'}
                or any(not _text(v, 4096) or len(v.encode()) > 4096 for v in values.values())
                or not values['title'].strip()):
            raise WriteError()
        fields = requested_fields(request)
        writes = self.broker.writes
        writes._require_available()
        if update:
            # The exact title and group path the agent selected, of a unique
            # identity. The entry itself is selected by uuid, so a group path
            # that names two groups does not matter here.
            _selected(self.broker.vault, entry.uuid, values['title'], values['group'])
        else:
            group_for(self.broker.vault, values['group'])
        writes._prune()
        if len(writes.operations) >= MAX_WRITES:
            raise WriteError()
        handle = secrets.token_hex(32)
        op = Write(secrets.token_urlsafe(32), self.broker.clock() + 300, writes.revision, dict(values), kind='identity',
                   fields=fields, uuid=entry.uuid if update else None)
        writes.operations[handle] = op
        return dict(ok=True, state='pending', write_handle=handle,
                    private_url=writes.public_base.rstrip('/') + '/identity?token=' + op.token)

    def submit(self, op, values, confirmed):
        if (not confirmed or op.kind != 'identity' or op.state != 'pending'
                or op.revision != self.broker.writes.revision or op.expires <= self.broker.clock()
                or not op.fields or set(values) != set(op.fields) or any(not _text(v, FIELD_LIMIT, allow_joiners=True) for v in values.values())):
            return dict(ok=False, error='invalid or expired identity save')
        values = {key: value.strip() for key, value in values.items()}
        country = values.get('country', '')
        if not any(values.values()) or country and not re.fullmatch('[A-Za-z]{2}', country):
            return dict(ok=False, error='enter at least one field and use a two-letter country code if provided')
        if 'country' in values:
            values['country'] = country.upper()

        update = op.uuid is not None
        if update:
            # An update changes only the fields the user filled in.
            values = {field: value for field, value in values.items() if value}

        def matches(candidate):
            group = group_for(candidate, op.values['group'])
            return group, [entry for entry in active_entries(candidate)
                           if is_identity(entry) and entry.title == op.values['title'] and entry.group == group]

        def mutate(candidate):
            from pykeepass.entry import Entry

            if update:
                entry = _selected(candidate, op.uuid, op.values['title'], op.values['group'])
                changed_at = _entry_changed_at(entry, self.broker.wall_clock)
                entry.save_history()
            else:
                group, duplicates = matches(candidate)
                if duplicates:
                    raise WriteError()
                entry = Entry(title=op.values['title'], username='', password='', kp=candidate)
                group.append(entry)
                entry.set_custom_property(MARKER, 'v1')
            for field, value in values.items():
                if value:
                    entry.set_custom_property(property_key(field), value, protect=True)
            if update:
                entry.mtime = changed_at

        def verify(candidate):
            if update:
                entry = _selected(candidate, op.uuid, op.values['title'], op.values['group'])
            else:
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


def label_matches(title, query, exact):
    return title == query if exact else query.casefold() in title.casefold()


def _protocol_ok(request):
    return type(request.get('identity_protocol')) is int and request['identity_protocol'] == 1
