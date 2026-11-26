"""Card number, expiry and security-code checks on the page and in the broker.

Synthetic test numbers only. The page script's checkCard() runs in Node against
the same cases as cards.problems(), so the two rule sets cannot drift apart.
"""
import json
import re
import shutil
import subprocess
from datetime import datetime, timezone

import pytest

from akdbx import portal
from akdbx.cards import MESSAGES, check_destination, check_new, problems, validate
from akdbx.writes import WriteError

TODAY = (2026, 11)
CARD = dict(name='Synthetic Cardholder', number='4111111111111111', month='09', year='2031', csc='123')

# (changes, brand, {field: message key})
CASES = [
    ({}, 'visa', {}),
    (dict(number='4111 1111-1111 1111'), 'visa', {}),
    (dict(number='4222222222222'), 'visa', {}),
    (dict(number='4111111111111112'), 'visa', {'number': 'number_checksum'}),
    (dict(number='411111111111111'), 'visa', {'number': 'number_visa'}),
    (dict(number='5555555555554444'), 'mastercard', {}),
    (dict(number='2223003122003222'), 'mastercard', {}),
    (dict(number='555555555555444'), 'mastercard', {'number': 'number_mastercard'}),
    (dict(number='378282246310005', csc='1234'), 'amex', {}),
    (dict(number='378282246310005'), 'amex', {'csc': 'csc_amex'}),
    (dict(number='3782822463100050', csc='1234'), 'amex', {'number': 'number_amex'}),
    (dict(number='6011111111111117'), 'other', {}),
    (dict(number='6011111111111117', csc='1234'), 'other', {}),
    (dict(number='60111111111'), 'other', {'number': 'number_other'}),
    (dict(number=''), None, {'number': 'number_empty'}),
    (dict(number='4111x11111111111'), None, {'number': 'number_digits'}),
    (dict(number='４' * 16), None, {'number': 'number_digits'}),
    (dict(csc='12'), 'visa', {'csc': 'csc_visa'}),
    (dict(csc='1234'), 'visa', {'csc': 'csc_visa'}),
    (dict(csc='12a'), 'visa', {'csc': 'csc_visa'}),
    (dict(csc=''), 'visa', {}),
    (dict(month='13'), 'visa', {'month': 'month'}),
    (dict(month='9'), 'visa', {'month': 'month'}),
    (dict(month='00'), 'visa', {'month': 'month'}),
    (dict(year='31'), 'visa', {'year': 'year'}),
    (dict(year='1931'), 'visa', {'year': 'year'}),
    (dict(month='10', year='2026'), 'visa', {'month': 'expiry'}),
    (dict(month='11', year='2026'), 'visa', {}),
    (dict(month='01', year='2025'), 'visa', {'month': 'expiry'}),
    (dict(name=''), 'visa', {'name': 'name'}),
    (dict(name='   '), 'visa', {'name': 'name'}),
    (dict(name='bad\tname'), 'visa', {'name': 'unsupported'}),
    (dict(number='', month='', year='', name=''), None,
     {'name': 'name', 'number': 'number_empty', 'month': 'month', 'year': 'year'}),
]


def expected(case):
    changes, brand, keys = case
    return dict(CARD, **changes), brand, {field: MESSAGES[key] for field, key in keys.items()}


@pytest.mark.parametrize('case', CASES)
def test_broker_rules(case):
    values, brand, errors = expected(case)
    assert problems(values, TODAY) == (brand, errors)


def test_page_rules_match_broker_rules():
    node = shutil.which('node')
    if node is None:
        pytest.skip('Node.js runs the page script checks')
    cases = [dict(card=expected(case)[0]) for case in CASES]
    program = portal.CARD_CHECK + """
    const cases = JSON.parse(require("fs").readFileSync(0, "utf8"));
    process.stdout.write(JSON.stringify(cases.map(c => checkCard(c.card, %s))));
    """ % json.dumps(list(TODAY))
    run = subprocess.run([node, '-e', program], input=json.dumps(cases), capture_output=True,
                         text=True, timeout=30, check=True)
    page = json.loads(run.stdout)
    for case, result in zip(CASES, page):
        values, brand, errors = expected(case)
        assert (result['brand'], result['errors']) == (brand, errors), case


def test_broker_refuses_bad_cards_even_when_the_page_is_bypassed():
    now = datetime(2026, 11, 20, 12, tzinfo=timezone.utc).timestamp()
    assert check_new(CARD, now) == CARD
    for changes, message in ((dict(number='411111111111111'), 'number_visa'),
                             (dict(number='378282246310005', csc='123'), 'csc_amex'),
                             (dict(month='10', year='2026'), 'expiry'),
                             (dict(number='4111111111111112'), 'number_checksum')):
        with pytest.raises(WriteError) as refused:
            check_new(dict(CARD, **changes), now)
        assert str(refused.value) == MESSAGES[message]
        assert CARD['number'] not in str(refused.value)
    for bad in (dict(CARD, extra='x'), dict(CARD, name='x' * 129), dict(CARD, csc=None)):
        with pytest.raises(WriteError):
            check_new(bad, now)


def test_expiry_allows_the_current_month_in_every_time_zone():
    # 1 December 05:00 UTC is still 30 November in UTC-12.
    early = datetime(2026, 12, 1, 5, tzinfo=timezone.utc).timestamp()
    assert check_new(dict(CARD, month='11', year='2026'), early)
    later = datetime(2026, 12, 1, 13, tzinfo=timezone.utc).timestamp()
    with pytest.raises(WriteError):
        check_new(dict(CARD, month='11', year='2026'), later)


def test_stored_cards_stay_readable_with_the_old_lenient_rules():
    # Expired cards and cards from other clients remain readable for search.
    for stored in (dict(CARD, year='2020'), dict(CARD, number='378282246310005', csc='123')):
        assert validate(stored) == stored


@pytest.mark.parametrize('title', ['', '   ', 'bad\ttitle', 'x' * 4097])
def test_destination_rules_refuse_bad_titles(title):
    with pytest.raises(WriteError):
        check_destination(dict(title=title, group='Web'))


def test_destination_rules_keep_literal_titles():
    title = 'Synthetic "personal" card of O\'Brien'
    assert check_destination(dict(title=title, group='')) == dict(title=title, group='')


def test_page_script_reads_card_values_only_for_local_checks():
    script = portal.SCRIPT
    # The one message the page posts asks the akdbx extension for a hardware key response, on the
    # page's own window and origin. It carries only the vault's challenge and the broker's signed
    # identity, both public; no input value can reach it.
    hardware = script[script.index('function askExtension'):script.index('async function hardwareResponses')]
    assert hardware.count('postMessage(') == 1 and 'value' not in hardware
    assert ('window.postMessage({akdbx_hardware: "request", akdbx_hardware_id: id, challenge, identity, proof}, '
            'location.origin)') in hardware
    script = script.replace(hardware, '')
    assert not re.search(r'\b(console|localStorage|sessionStorage|indexedDB|XMLHttpRequest|sendBeacon|postMessage|innerHTML)\b', script)
    # Card values are read in one place and only compared or measured. The
    # other reads keep the non-secret title and group after a final result.
    assert script.count('.value') == 4
    assert 'card[name] = form.elements.namedItem(name).value;' in script
    assert 'form.elements.namedItem("number").value.replace(/[ -]/g, "").length' in script
    assert '["title", "group"].map(name => form.elements.namedItem(name))' in script
    assert script.count('control.value') == 2
    # The form is sent only by the standard same-origin POST to its own action.
    # The only other request is the SMS setup page's bodiless status GET.
    assert script.count('fetch(') == 2 and 'fetch(form.action, {' in script
    status = 'fetch(panel.getAttribute("data-wait") + "&after=" + count,\n          {credentials: "same-origin", cache: "no-store", redirect: "error"});'
    assert status in script
    assert script.count('new FormData(form)') == 1
