"""SMS code and webhook-URL DOM fills in the isolated card-test Chrome."""
from types import SimpleNamespace

import pytest

from akdbx.sms import SmsInbox
from test_card_chromium import chrome, evaluate  # noqa: F401
from test_target import isolated_x11  # noqa: F401

FIELDS = ('<input id="otp" autocomplete="one-time-code" inputmode="numeric" maxlength="6">'
          '<input id="boxes" maxlength="1"><input id="hook" type="url"><input id="check" type="checkbox">')


@pytest.fixture
def page(chrome, tmp_path):  # noqa: F811
    evaluate(chrome, f"document.body.insertAdjacentHTML('beforeend', {FIELDS!r}); true")
    chrome.broker.sms = SmsInbox(tmp_path / 'state' / 'sms.json')
    chrome.broker.unlock_link = SimpleNamespace(origin='https://box.example.test')
    return chrome


def pin(chrome, selector, field='one-time-code', focus=True):
    if focus:
        evaluate(chrome, f"document.querySelector({selector!r}).focus(); true")
    return chrome.broker.dispatch(dict(action='pin-code-target', sms_protocol=1, page_id=chrome.page,
                                       frame_id=chrome.frame, top_url=chrome.url, frame_url=chrome.url,
                                       selector=selector, field=field))


def message(chrome, text='G-482913 is your Google verification code.'):
    token = chrome.broker.sms.add_source('iphone', 'shortcut', replace=True)
    assert chrome.broker.sms.receive(token, 'Google', text) == 'kept'
    return chrome.broker.dispatch(dict(action='sms-wait', sms_protocol=1))['messages'][0]['id']


def test_code_fills_only_the_pinned_focused_input_and_returns_no_code(page):
    target = pin(page, '#otp')
    assert target['ok'] is True and target['code_delivery'] == 'cdp-code-element-v1'
    receipt = page.broker.dispatch(dict(action='fill-sms-code', sms_protocol=1, message=message(page),
                                        target=target['target'], target_protocol=1))
    assert receipt == dict(ok=True, filled='one-time-code', code_delivery='cdp-code-element-v1')
    assert evaluate(page, 'document.querySelector("#otp").value') == '482913'
    assert evaluate(page, 'events.includes("otp")') is True
    assert evaluate(page, '[...document.querySelectorAll("input")].filter(e => e.type !== "checkbox" && e.value).length') == 1


def test_unfocused_wrong_type_and_too_short_inputs_are_refused(page):
    evaluate(page, 'document.activeElement.blur(); true')
    assert pin(page, '#otp', focus=False)['ok'] is False
    assert pin(page, '#check')['ok'] is False
    assert pin(page, '#hook')['ok'] is False  # a URL input is not a code field
    # Six one-digit boxes need X11 keyboard delivery: the DOM fill refuses and keeps the text.
    target = pin(page, '#boxes')
    assert target['ok'] is True
    message_id = message(page)
    refused = page.broker.dispatch(dict(action='fill-sms-code', sms_protocol=1, message=message_id,
                                        target=target['target'], target_protocol=1))
    assert refused['ok'] is False and evaluate(page, 'document.querySelector("#boxes").value') == ''
    assert [m['id'] for m in page.broker.dispatch(dict(action='sms-wait', sms_protocol=1))['messages']] == [message_id]


def test_webhook_url_is_typed_into_a_pinned_field_and_never_returned(page):
    target = pin(page, '#hook', field='webhook-url')
    assert target['ok'] is True
    receipt = page.broker.dispatch(dict(action='sms-add-source', sms_protocol=1, name='twilio-us', kind='twilio',
                                        target=target['target'], target_protocol=1))
    assert receipt == dict(ok=True, name='twilio-us', kind='twilio', filled='webhook-url',
                           code_delivery='cdp-code-element-v1')
    value = evaluate(page, 'document.querySelector("#hook").value')
    assert value.startswith('https://box.example.test/sms/in/') and len(value.rsplit('/', 1)[1]) == 43
    assert page.broker.sms.source_for(value.rsplit('/', 1)[1]).name == 'twilio-us'
    # A code pin cannot receive a webhook URL.
    code_pin = pin(page, '#otp')
    refused = page.broker.dispatch(dict(action='sms-add-source', sms_protocol=1, name='other', kind='webhook',
                                        target=code_pin['target'], target_protocol=1))
    assert refused['ok'] is False and evaluate(page, 'document.querySelector("#otp").value') == ''
