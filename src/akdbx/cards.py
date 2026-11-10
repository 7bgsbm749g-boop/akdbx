"""KDBX card records. Card values enter only through the private HTTP form."""
from __future__ import annotations

import re
import secrets
import unicodedata
from datetime import datetime, timezone

from .persistence import SaveError
from .versions import active_entries
from .writes import Write, WriteError, MAX_WRITES, group_for, _entry_changed_at

MARKER = 'akdbx.card'
FIELDS = {key: 'akdbx.card.' + key for key in ('name', 'number', 'month', 'year', 'csc')}
FILL_FIELDS = ('cc-name', 'cc-number', 'cc-exp-month', 'cc-exp-year', 'cc-exp', 'cc-csc')


def is_card(entry):
    getter = getattr(entry, 'get_custom_property', None)
    element = getattr(entry, '_element', None)
    return bool(getter and getter(MARKER) is not None or element is not None
                and element.find('./String[Key="' + MARKER + '"]') is not None)


def validate(values):
    if not isinstance(values, dict) or set(values) != set(FIELDS) or any(
        not isinstance(v, str) or len(v) > 128 or any(unicodedata.category(c).startswith('C') for c in v)
        for v in values.values()
    ):
        raise WriteError('invalid card fields')
    result = dict(values)
    result['number'] = values['number'].replace(' ', '').replace('-', '')
    if (not values['name'].strip() or not re.fullmatch(r'[0-9]{12,19}', result['number'])
            or not re.fullmatch(r'(?:0[1-9]|1[0-2])', values['month'])
            or not re.fullmatch(r'20[0-9]{2}', values['year'])
            or values['csc'] and not re.fullmatch(r'[0-9]{3,4}', values['csc'])):
        raise WriteError('invalid card fields; require name, number, two-digit month and four-digit year')
    digits = [int(c) for c in result['number']]
    if sum(d if i % 2 == 0 else (2*d // 10 + 2*d % 10) for i, d in enumerate(reversed(digits))) % 10:
        raise WriteError('invalid card number checksum')
    return result


def read_card(entry):
    if not is_card(entry) or entry.get_custom_property(MARKER) != 'v1':
        raise WriteError('invalid or unsupported card record')
    return validate({key: entry.get_custom_property(field) or '' for key, field in FIELDS.items()})


def metadata(entry):
    values = read_card(entry)
    number = values['number']
    brand = 'visa' if number.startswith('4') else 'amex' if number[:2] in {'34', '37'} else 'other'
    if 51 <= int(number[:2]) <= 55 or 2221 <= int(number[:4]) <= 2720:
        brand = 'mastercard'
    return dict(title=entry.title or '', group='/'.join(entry.path[:-1]), brand=brand, last_four=number[-4:])


def value_for(entry, field, formatting, now):
    values = read_card(entry)
    current = datetime.fromtimestamp(now, timezone.utc)
    if (int(values['year']), int(values['month'])) < (current.year, current.month):
        raise WriteError('card has expired')
    if field not in FILL_FIELDS:
        raise WriteError('unsupported card field')
    if field == 'cc-exp':
        if formatting not in {'MM/YY', 'MM/YYYY'}:
            raise WriteError('explicit expiry format required')
        return values['month'] + '/' + (values['year'][2:] if formatting == 'MM/YY' else values['year'])
    if field == 'cc-exp-year':
        if formatting not in {'YY', 'YYYY'}:
            raise WriteError('explicit year format required')
        return values['year'][2:] if formatting == 'YY' else values['year']
    if formatting is not None:
        raise WriteError('format is only supported for expiry or year')
    value = values[{'cc-name': 'name', 'cc-number': 'number', 'cc-exp-month': 'month', 'cc-csc': 'csc'}[field]]
    if not value:
        raise WriteError('requested card field is empty')
    return value


class CardManager:
    def __init__(self, broker):
        self.broker = broker

    def dispatch(self, request, ready):
        from .browser_card import CardTargetError, failure
        try:
            if request['action'] == 'fill-card':
                # Consume both authorizations even on malformed requests.
                entry = None
                selection_error = False
                try:
                    entry = self.broker._resolve(request.get('handle'))
                except ValueError:
                    selection_error = True
                pin = self.broker.card_targets.consume(request.get('target'))
                try:
                    if selection_error:
                        raise CardTargetError()
                    if (type(request.get('card_protocol')) is not int or request['card_protocol'] != 1
                            or set(request) - {'action', 'card_protocol', 'handle', 'target', 'field', 'format', 'start_deadline'}):
                        raise CardTargetError()
                    deadline = request.get('start_deadline')
                    if (type(deadline) not in {int, float} or not self.broker.clock() < deadline <= self.broker.clock() + 4):
                        raise CardTargetError()
                    value = value_for(entry, request.get('field'), request.get('format'), self.broker.wall_clock())
                    return self.broker.card_targets.fill(pin, value, request['field'],
                        lambda: ready() and self.broker.clock() < deadline, deadline)
                finally:
                    self.broker.card_targets._close(pin)
            if type(request.get('card_protocol')) is not int or request['card_protocol'] != 1:
                raise WriteError('card protocol 1 required')
            if request['action'] in {'create-card', 'update-card'}:
                return self.begin(request)
            if request['action'] == 'pin-card-target':
                return self.broker.card_targets.pin(request)
            if set(request) - {'action', 'card_protocol', 'query'} or not isinstance(request.get('query', ''), str) or len(request.get('query', '')) > 500:
                raise WriteError('invalid card search')
            query = request.get('query', '').casefold()
            matches = []
            for entry in active_entries(self.broker.vault):
                try:
                    if not is_card(entry):
                        continue
                    item = metadata(entry)
                    if any(len(v.encode('utf-8')) > 4096 for v in item.values()):
                        continue
                except Exception:
                    continue
                if query and not any(query in v.casefold() for v in item.values()):
                    continue
                matches.append((item, entry))
                if len(matches) == 20:
                    break
            # Bound metadata before creating handles or serializing the response.
            import json
            if len(json.dumps([item for item, _ in matches]).encode()) > 45000:
                raise WriteError('card search exceeds response budget')
            return dict(ok=True, entries=[dict(item, handle=self.broker._new_handle(entry)) for item, entry in matches])
        except (CardTargetError, ValueError, TypeError):
            return failure() if request['action'] in {'fill-card', 'pin-card-target'} else dict(ok=False, error='card operation refused; check selection and destination')
        except Exception:
            return failure() if request['action'] in {'fill-card', 'pin-card-target'} else dict(ok=False, error='card operation failed')

    def begin(self, request):
        update = request['action'] == 'update-card'
        entry = self.broker._resolve(request.get('handle')) if update else None
        allowed = {'action', 'card_protocol', 'metadata'} | ({'handle'} if update else set())
        if set(request) != allowed:
            raise WriteError('card save accepts destination metadata only')
        values = request.get('metadata')
        if not isinstance(values, dict) or set(values) != {'title', 'group'} or any(
            not isinstance(v, str) or len(v.encode('utf-8')) > 4096
            or any(unicodedata.category(c).startswith('C') for c in v) for v in values.values()
        ) or not values['title'].strip():
            raise WriteError('invalid card destination metadata')
        writes = self.broker.writes
        if not writes.available():
            raise WriteError('private card writes unavailable')
        group_for(self.broker.vault, values['group'])
        if update and (not is_card(entry) or any(values[k] != metadata(entry)[k] for k in values)):
            raise WriteError('card metadata mismatch')
        writes._prune()
        if len(writes.operations) >= MAX_WRITES:
            raise WriteError('too many pending writes')
        handle = secrets.token_hex(32)
        op = Write(secrets.token_urlsafe(32), self.broker.clock() + 300, writes.revision,
                   dict(values), uuid=entry.uuid if entry else None, kind='card')
        writes.operations[handle] = op
        return dict(ok=True, state='pending', write_handle=handle,
                    private_url=writes.public_base.rstrip('/') + '/card?token=' + op.token)

    def submit(self, op, values, confirmed):
        if (not confirmed or op.kind != 'card' or op.state != 'pending'
                or op.revision != self.broker.writes.revision or op.expires <= self.broker.clock()):
            return dict(ok=False, error='invalid or expired card save')
        try:
            values = validate(values)
            def mutate(candidate):
                group = group_for(candidate, op.values['group'])
                if op.uuid is None:
                    if any(is_card(e) and e.title == op.values['title'] and e.group == group for e in active_entries(candidate)):
                        raise WriteError('duplicate card title in destination group')
                    from pykeepass.entry import Entry
                    entry = Entry(title=op.values['title'], username='', password='', kp=candidate)
                    group.append(entry)
                    changed_at = None
                else:
                    matches = [e for e in active_entries(candidate) if e.uuid == op.uuid]
                    if len(matches) != 1 or not is_card(matches[0]):
                        raise WriteError('card no longer available')
                    entry = matches[0]
                    changed_at = _entry_changed_at(entry, self.broker.wall_clock)
                    entry.save_history()
                entry.set_custom_property(MARKER, 'v1')
                for key, field in FIELDS.items():
                    entry.set_custom_property(field, values[key], protect=True)
                if changed_at is None:
                    entry.touch(modify=True)
                else:
                    entry.mtime = changed_at
            def verify(candidate):
                matches = [e for e in active_entries(candidate) if is_card(e)
                           and e.title == op.values['title'] and '/'.join(e.path[:-1]) == op.values['group']]
                if len(matches) != 1 or read_card(matches[0]) != values or any(
                    matches[0]._element.find('./String[Key="' + key + '"]/Value').get('Protected') != 'True'
                    for key in FIELDS.values()
                ):
                    raise SaveError('card persistence verification failed')
            vault = self.broker.vault
            self.broker.vault = vault._akdbx_store.commit(vault, mutate, verify_candidate=verify)
            op.state = 'saved'
            self.broker.writes.invalidate_revision(op)
            return dict(ok=True, state='saved')
        except (WriteError, SaveError):
            op.state = 'failed'
            op.error = 'card save failed; vault update not confirmed'
            return dict(ok=False, error=op.error)
        except Exception:
            op.state = 'failed'
            op.error = 'card save failed; vault update not confirmed'
            return dict(ok=False, error=op.error)
