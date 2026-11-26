"""KDBX card records. Card values enter only through the private HTTP form."""
from __future__ import annotations

import re
import unicodedata
from datetime import datetime, timezone

from .persistence import SaveError
from .versions import active_entries
from .writes import WriteError, group_for, _entry_changed_at, page_lifetime, prepared_page

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
    if not luhn(result['number']):
        raise WriteError('invalid card number checksum')
    return result


def luhn(number):
    digits = [int(c) for c in number]
    return not sum(d if i % 2 == 0 else (2*d // 10 + 2*d % 10) for i, d in enumerate(reversed(digits))) % 10


def brand(number):
    """Brand from the leading digits of an ASCII digit string."""
    if number[:2] in {'34', '37'}:
        return 'amex'
    if number[:1] == '4':
        return 'visa'
    if len(number) >= 2 and 51 <= int(number[:2]) <= 55 or len(number) >= 4 and 2221 <= int(number[:4]) <= 2720:
        return 'mastercard'
    return 'other'


# The private card page repeats these exact rules and messages in
# portal.CARD_CHECK; tests/test_card_validation.py keeps the two in step.
# Messages never include a submitted value.
LENGTHS = {'visa': (13, 16, 19), 'mastercard': (16,), 'amex': (15,), 'other': tuple(range(12, 20))}
CSC_LENGTHS = {'visa': (3,), 'mastercard': (3,), 'amex': (4,), 'other': (3, 4)}
MESSAGES = dict(
    unsupported='Card details contain unsupported characters or are too long.',
    name='Enter the cardholder name.',
    number_empty='Enter the card number.',
    number_digits='Card number can contain only digits, spaces and hyphens.',
    number_visa='A Visa card number has 13, 16 or 19 digits.',
    number_mastercard='A Mastercard number has 16 digits.',
    number_amex='An American Express card number has 15 digits.',
    number_other='A card number has 12 to 19 digits.',
    number_checksum='This card number is not valid. Check the digits.',
    month='Enter the expiry month as two digits, 01 to 12.',
    year='Enter the expiry year as four digits, for example 2031.',
    expiry='This card has expired. Check the expiry month and year.',
    csc_visa='A Visa security code has 3 digits.',
    csc_mastercard='A Mastercard security code has 3 digits.',
    csc_amex='An American Express security code has 4 digits.',
    csc_other='A security code has 3 or 4 digits.',
)


def problems(values, today):
    """Return (brand or None, {field: message}) for a card being saved now."""
    errors = {}
    number = values['number'].replace(' ', '').replace('-', '')
    kind = brand(number) if re.fullmatch('[0-9]+', number) else None
    if any(unicodedata.category(c).startswith('C') for v in values.values() for c in v):
        errors['name'] = MESSAGES['unsupported']
    elif not values['name'].strip():
        errors['name'] = MESSAGES['name']
    if not number:
        errors['number'] = MESSAGES['number_empty']
    elif kind is None:
        errors['number'] = MESSAGES['number_digits']
    elif len(number) not in LENGTHS[kind]:
        errors['number'] = MESSAGES['number_' + kind]
    elif not luhn(number):
        errors['number'] = MESSAGES['number_checksum']
    month = re.fullmatch('0[1-9]|1[0-2]', values['month'])
    year = re.fullmatch('20[0-9]{2}', values['year'])
    if not month:
        errors['month'] = MESSAGES['month']
    if not year:
        errors['year'] = MESSAGES['year']
    if month and year and (int(values['year']), int(values['month'])) < tuple(today):
        errors['month'] = MESSAGES['expiry']
    csc = values['csc']
    if csc and not (re.fullmatch('[0-9]+', csc) and len(csc) in CSC_LENGTHS[kind or 'other']):
        errors['csc'] = MESSAGES['csc_' + (kind or 'other')]
    return kind, errors


def check_new(values, now):
    """Strict checks for a card the user saves now; stored cards stay readable.

    The expiry month is compared 12 hours behind UTC, so a card that is still
    valid in the user's own time zone is never refused by the broker.
    """
    if not isinstance(values, dict) or set(values) != set(FIELDS) or any(
            not isinstance(v, str) or len(v) > 128 for v in values.values()):
        raise WriteError(MESSAGES['unsupported'])
    current = datetime.fromtimestamp(now - 12 * 3600, timezone.utc)
    _, errors = problems(values, (current.year, current.month))
    if errors:
        raise WriteError(next(iter(errors.values())))
    return validate(values)


def check_destination(values):
    """Title and group rules shared by create-card, update-card and the page."""
    if not isinstance(values, dict) or set(values) != {'title', 'group'} or any(
        not isinstance(v, str) or len(v.encode('utf-8')) > 4096
        or any(unicodedata.category(c).startswith('C') for c in v) for v in values.values()
    ) or not values['title'].strip():
        raise WriteError('invalid card destination metadata')
    return dict(values)


def read_card(entry):
    if not is_card(entry) or entry.get_custom_property(MARKER) != 'v1':
        raise WriteError('invalid or unsupported card record')
    return validate({key: entry.get_custom_property(field) or '' for key, field in FIELDS.items()})


def metadata(entry):
    values = read_card(entry)
    number = values['number']
    return dict(title=entry.title or '', group='/'.join(entry.path[:-1]), brand=brand(number), last_four=number[-4:])


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
        from .browser_slots import SlotError
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
        except SlotError as exc:
            return dict(ok=False, error=str(exc))
        except (CardTargetError, ValueError, TypeError):
            return failure() if request['action'] in {'fill-card', 'pin-card-target'} else dict(ok=False, error='card operation refused; check selection and destination')
        except Exception:
            return failure() if request['action'] in {'fill-card', 'pin-card-target'} else dict(ok=False, error='card operation failed')

    def begin(self, request):
        update = request['action'] == 'update-card'
        entry = self.broker._resolve(request.get('handle')) if update else None
        allowed = {'action', 'card_protocol', 'metadata'} | ({'handle'} if update else set())
        if set(request) - {'valid_minutes'} != allowed:
            raise WriteError('card save accepts destination metadata and a page lifetime only')
        page_lifetime(request, self.broker.session.timeout)
        values = check_destination(request.get('metadata'))
        writes = self.broker.writes
        if not writes.available():
            raise WriteError('private card writes unavailable')
        group_for(self.broker.vault, values['group'])
        if update and (not is_card(entry) or any(values[k] != metadata(entry)[k] for k in values)):
            raise WriteError('card metadata mismatch')
        return prepared_page(self.broker, 'card', request, values, uuid=entry.uuid if entry else None)

    def submit(self, op, values, confirmed, destination=None):
        """Keep invalid forms pending; make attempted persistence failures terminal.

        ``destination`` holds the title and/or group the user chose on the
        page; a missing key keeps the prepared value. The result's ``reason`` tells the page
        which state the save reached: saved, rejected (still pending), expired,
        stale (vault changed) or failed.
        """
        if op.kind != 'card' or op.state != 'pending' or op.expires <= self.broker.clock():
            return dict(ok=False, reason='expired', error=EXPIRED)
        if op.revision != self.broker.writes.revision:
            return dict(ok=False, reason='stale', error=STALE)
        def rejected(message):
            return dict(ok=False, reason='rejected', error=message)
        if not confirmed:
            return rejected('Confirm this card and destination before saving.')
        # The update page sends no group: it keeps the prepared one.
        destination = dict(op.values, **(destination or {}))
        try:
            destination = check_destination(destination)
        except WriteError:
            return rejected('Enter a title without control characters, up to 4096 bytes.')
        if op.uuid is not None and destination['group'] != op.values['group']:
            return rejected('An updated card stays in its current group.')
        try:
            group_for(self.broker.vault, destination['group'])
        except WriteError:
            return rejected('Choose a group from the list.')
        if self._duplicate(self.broker.vault, op, destination):
            return rejected('A card with this title already exists in this group. Choose another title.')
        try:
            values = check_new(values, self.broker.wall_clock())
        except WriteError as error:
            return rejected(str(error))
        try:
            def mutate(candidate):
                group = group_for(candidate, destination['group'])
                if self._duplicate(candidate, op, destination):
                    raise WriteError('duplicate card title in destination group')
                if op.uuid is None:
                    from pykeepass.entry import Entry
                    entry = Entry(title=destination['title'], username='', password='', kp=candidate)
                    group.append(entry)
                    changed_at = None
                else:
                    matches = [e for e in active_entries(candidate) if e.uuid == op.uuid]
                    if len(matches) != 1 or not is_card(matches[0]):
                        raise WriteError('card no longer available')
                    entry = matches[0]
                    changed_at = _entry_changed_at(entry, self.broker.wall_clock)
                    entry.save_history()
                    entry.title = destination['title']
                entry.set_custom_property(MARKER, 'v1')
                for key, field in FIELDS.items():
                    entry.set_custom_property(field, values[key], protect=True)
                if changed_at is None:
                    entry.touch(modify=True)
                else:
                    entry.mtime = changed_at
            def verify(candidate):
                matches = [e for e in active_entries(candidate) if is_card(e)
                           and e.title == destination['title'] and '/'.join(e.path[:-1]) == destination['group']]
                if len(matches) != 1 or read_card(matches[0]) != values or any(
                    matches[0]._element.find('./String[Key="' + key + '"]/Value').get('Protected') != 'True'
                    for key in FIELDS.values()
                ):
                    raise SaveError('card persistence verification failed')
            vault = self.broker.vault
            self.broker.vault = vault._akdbx_store.commit(vault, mutate, verify_candidate=verify)
            op.state = 'saved'
            # write-status reports the final non-secret destination.
            op.values = destination
            self.broker.writes.invalidate_revision(op)
            self.broker.writes.notify_card(op)
            return dict(ok=True, state='saved', reason='saved', **destination)
        except Exception:
            op.state = 'failed'
            op.error = 'card save failed; vault update not confirmed'
            self.broker.writes.notify_card(op)
            return dict(ok=False, reason='failed', error=FAILED)

    @staticmethod
    def _duplicate(vault, op, destination):
        return any(is_card(e) and e.uuid != op.uuid and e.title == destination['title']
                   and '/'.join(e.path[:-1]) == destination['group'] for e in active_entries(vault))


EXPIRED = 'This card page has expired or is no longer valid. Ask for a new card page.'
STALE = 'The vault changed after this page opened, so the card was not saved. Ask for a new card page.'
# The store may have replaced the vault before confirmation failed: never claim
# the card was not written.
FAILED = ('The card save could not be confirmed. Ask for a new card page, and check the '
          'saved cards before you save this card again.')
