"""Phone verification texts: extraction, sources, inbox, HTTPS intake and fills."""
import json
import re
import os
import stat
import threading
import time
from http.client import HTTPSConnection
from types import SimpleNamespace
from urllib.parse import urlencode, urlsplit
import ssl

import pytest

from akdbx import sms, sms_cli
from akdbx.broker import Broker
from akdbx.sms import SmsError, SmsInbox, extract_code, mask
from test_broker import Entry, RecordingTyper, Vault
from test_windows_unlock import certificates  # noqa: F401

ORIGIN = 'https://box.example.test'


@pytest.mark.parametrize('text,code', [
    ('G-482913 is your Google verification code.', '482913'),
    ('Your Twilio verification code is: 771204', '771204'),
    ('Your code is 123 456. Do not share it.', '123456'),
    ('Use 4821 to sign in to Example.', '4821'),
    ('Your Example login code: 5512-9983', '55129983'),
    ('Verification code 991122. Not you? Call +447700900123.', '991122'),
    ('Verify at https://x.test/v/123456 with code 778899', '778899'),
    ('Your code is 482913. (c) 2026 Example Ltd', '482913'),
    ('Ihr Bestätigungscode lautet 664422', '664422'),
    ('Tu código de verificación es 908172', '908172'),
])
def test_extract_code_finds_the_one_verification_code(text, code):
    assert extract_code(text) == code


@pytest.mark.parametrize('text', [
    'See you at 1830 tomorrow',            # no verification word
    'Your parcel 12345678 arrives today',  # no verification word
    'code',                                # no digits
    '',
    None,
    'Your code is 12.50 GBP',              # not 4-8 digits alone
    'code ' + '1' * 3000,                   # too long
    'Code 123456 or code 654321',          # ambiguous: two equally near
])
def test_extract_code_drops_texts_without_one_code(text):
    assert extract_code(text) is None


def test_mask_hides_every_digit_and_link():
    preview = mask('G-482913 is your code. https://g.co/x/123 www.example.test/9 ‮end')
    assert preview == 'G-•••••• is your code. [link] [link] end'
    assert not any(c.isdigit() for c in preview)


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def inbox(tmp_path):
    clock = Clock()
    box = SmsInbox(tmp_path / 'state' / 'sms-sources.json', clock=clock, wall_clock=lambda: 1_800_000_000 + clock.now)
    box.test_clock = clock
    return box


def test_sources_keep_only_a_token_hash_in_a_private_file(inbox, tmp_path):
    token = inbox.add_source('iphone', 'shortcut')
    path = tmp_path / 'state' / 'sms-sources.json'
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    raw = path.read_text()
    assert token not in raw
    assert sms._hash(token) in raw
    again = SmsInbox(path)
    assert [s['name'] for s in again.list_sources()] == ['iphone']
    assert again.source_for(token).kind == 'shortcut'
    with pytest.raises(SmsError):
        inbox.add_source('iphone', 'shortcut')
    with pytest.raises(SmsError):
        inbox.add_source('Bad Name', 'shortcut')
    with pytest.raises(SmsError):
        inbox.add_source('other', 'carrier-pigeon')


def test_an_unsafe_state_file_is_refused(tmp_path):
    path = tmp_path / 'state' / 'sms-sources.json'
    SmsInbox(path).add_source('iphone', 'shortcut')
    path.chmod(0o644)
    with pytest.raises(ValueError):
        SmsInbox(path)
    path.chmod(0o600)
    path.write_text('{"version": 1, "sources": [{"name": "x"}]}')
    with pytest.raises(ValueError):
        SmsInbox(path)


def test_replace_rotates_the_token_and_remove_stops_it(inbox):
    old = inbox.add_source('twilio-us', 'twilio')
    new = inbox.add_source('twilio-us', 'twilio', replace=True)
    assert inbox.receive(old, '+15550100', 'code 123456') == 'unknown'
    assert inbox.receive(new, '+15550100', 'code 123456') == 'kept'
    assert inbox.remove_source('twilio-us') is True
    assert inbox.receive(new, '+15550100', 'code 123456') == 'unknown'
    assert inbox.wait() == []
    assert inbox.remove_source('twilio-us') is False


def test_messages_hold_no_code_in_metadata_and_are_used_once(inbox):
    token = inbox.add_source('iphone', 'shortcut')
    assert inbox.receive(token, 'Google', 'Hello there') == 'dropped'
    assert inbox.receive(token, 'Google', 'G-482913 is your Google verification code.') == 'kept'
    [row] = inbox.wait()
    assert set(row) == {'id', 'source', 'sender', 'preview', 'code_length', 'received_at', 'age_seconds'}
    assert '482913' not in json.dumps(row)
    assert row['code_length'] == 6 and row['source'] == 'iphone' and row['sender'] == 'Google'
    assert inbox.list_sources()[0]['last_received'] == row['received_at']
    message = inbox.take(row['id'])
    assert message.code == '482913'
    with pytest.raises(SmsError):
        inbox.take(row['id'])
    inbox.restore(message)
    assert inbox.take(row['id']).code == '482913'


def test_messages_expire_and_since_and_source_filter(inbox):
    phone = inbox.add_source('iphone', 'shortcut')
    virtual = inbox.add_source('twilio-us', 'twilio')
    inbox.receive(phone, 'A', 'code 111111')
    inbox.test_clock.now += 30
    inbox.receive(virtual, 'B', 'code 222222')
    assert [m['source'] for m in inbox.wait()] == ['twilio-us', 'iphone']
    assert [m['source'] for m in inbox.wait(source='iphone')] == ['iphone']
    assert [m['source'] for m in inbox.wait(since=1_800_000_000 + 1010)] == ['twilio-us']
    with pytest.raises(SmsError):
        inbox.wait(source='missing')
    inbox.test_clock.now += sms.MESSAGE_TTL
    assert inbox.wait() == []


def test_rate_limit_per_source(inbox):
    token = inbox.add_source('iphone', 'shortcut')
    results = [inbox.receive(token, 'x', 'code 123456') for _ in range(sms.RATE_LIMIT + 1)]
    assert results[-1] == 'limited' and results.count('kept') == sms.RATE_LIMIT
    inbox.test_clock.now += 61
    assert inbox.receive(token, 'x', 'code 123456') == 'kept'
    assert len(inbox.messages) <= sms.MAX_MESSAGES


def test_wait_returns_when_a_text_arrives():
    box = SmsInbox(None)
    box.sources['iphone'] = sms.Source('iphone', 'shortcut', sms._hash('t' * 43), 'now')
    threading.Timer(0.2, lambda: box.receive('t' * 43, 'x', 'code 654321')).start()
    started = time.monotonic()
    rows = box.wait(timeout=10)
    assert len(rows) == 1 and time.monotonic() - started < 5
    assert box.wait(timeout=1, ready=lambda: False) == rows  # an existing text needs no wait


def test_setup_pages_expire_and_die_with_their_source(inbox):
    token = inbox.add_source('iphone', 'shortcut')
    key = inbox.new_setup('iphone', token)
    assert inbox.setup(key).token == token
    inbox.add_source('iphone', 'shortcut', replace=True)
    assert inbox.setup(key) is None
    token = inbox.add_source('iphone', 'shortcut', replace=True)
    key = inbox.new_setup('iphone', token)
    inbox.test_clock.now += sms.SETUP_TTL
    assert inbox.setup(key) is None


# Broker actions ------------------------------------------------------------


def unlocked_broker(tmp_path):
    broker = Broker(Vault([Entry()]), RecordingTyper(), sms_sources_path=tmp_path / 'state' / 'sms.json')
    broker.unlock_link = SimpleNamespace(origin=ORIGIN)
    return broker


def call(broker, action, **fields):
    return broker.dispatch(dict(action=action, sms_protocol=1, **fields))


def x11_target(broker):
    return broker.dispatch(dict(action='pin-target', pid=os.getpid(), window=7, target_protocol=1))['target']


def test_locked_broker_refuses_sms_actions_but_reports_the_protocol(tmp_path):
    broker = Broker(None, RecordingTyper(), sms_sources_path=tmp_path / 'sms.json')
    assert broker.dispatch(dict(action='ping'))['sms_protocol'] == 1
    assert call(broker, 'sms-sources')['error'] == 'vault locked'


def test_add_source_returns_a_private_setup_link_only(tmp_path):
    broker = unlocked_broker(tmp_path)
    receipt = call(broker, 'sms-add-source', name='iphone', kind='shortcut')
    assert set(receipt) == {'ok', 'name', 'kind', 'private_url'}
    url = urlsplit(receipt['private_url'])
    assert receipt['private_url'].startswith(ORIGIN + '/sms/setup?token=')
    setup = broker.sms.setup(url.query.split('=', 1)[1])
    assert setup.token not in json.dumps(receipt)
    assert call(broker, 'sms-sources') == dict(ok=True, sources=broker.sms.list_sources())
    assert call(broker, 'sms-add-source', name='iphone', kind='shortcut')['ok'] is False
    assert call(broker, 'sms-remove-source', name='iphone') == dict(ok=True, removed=True)
    assert broker.dispatch(dict(action='sms-sources'))['error'] == 'SMS protocol 1 required'


def test_fill_sms_code_types_the_code_once_through_a_pinned_x11_window(tmp_path):
    broker = unlocked_broker(tmp_path)
    token = broker.sms.add_source('iphone', 'shortcut')
    broker.sms.receive(token, 'Google', 'G-482913 is your Google verification code.')
    [row] = call(broker, 'sms-wait')['messages']
    # X11 delivery needs an independently verified challenge URL; the code stays.
    refused = call(broker, 'fill-sms-code', message=row['id'], target=x11_target(broker), target_protocol=1)
    assert refused['ok'] is False and broker.typer.events == []
    receipt = call(broker, 'fill-sms-code', message=row['id'], target=x11_target(broker), target_protocol=1,
                   target_url='https://accounts.google.com/signin/challenge')
    assert receipt == dict(ok=True, filled='one-time-code', target_delivery='x11-send-event-v1')
    assert broker.typer.events == [('type', '482913')]
    assert '482913' not in json.dumps(receipt)
    again = call(broker, 'fill-sms-code', message=row['id'], target=x11_target(broker), target_protocol=1,
                 target_url='https://accounts.google.com/')
    assert again == dict(ok=False, error='unknown or expired SMS message')
    assert broker.typer.events == [('type', '482913')]


def test_a_spent_or_unknown_target_keeps_the_message(tmp_path):
    broker = unlocked_broker(tmp_path)
    token = broker.sms.add_source('iphone', 'shortcut')
    broker.sms.receive(token, 'x', 'code 123456')
    [row] = call(broker, 'sms-wait')['messages']
    assert call(broker, 'fill-sms-code', message=row['id'], target='0' * 64, target_protocol=1)['ok'] is False
    assert [m['id'] for m in call(broker, 'sms-wait')['messages']] == [row['id']]
    expired = call(broker, 'fill-sms-code', message=row['id'], target=x11_target(broker), target_protocol=1,
                   target_url='https://example.com/', start_deadline=time.monotonic() - 1)
    assert expired['ok'] is False and broker.typer.events == []
    assert [m['id'] for m in call(broker, 'sms-wait')['messages']] == [row['id']]


def test_add_source_with_a_target_needs_a_webhook_url_dom_pin(tmp_path):
    broker = unlocked_broker(tmp_path)
    receipt = call(broker, 'sms-add-source', name='twilio-us', kind='twilio', target=x11_target(broker),
                   target_protocol=1)
    assert receipt['ok'] is False and broker.typer.events == []
    assert broker.sms.list_sources() == []


# HTTPS intake --------------------------------------------------------------


def https(port, cafile, method, path, *, host, body=b'', content_type=None, origin=None, user_agent=None):
    client = HTTPSConnection('127.0.0.1', port, context=ssl.create_default_context(cafile=str(cafile)), timeout=30)
    try:
        client.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        client.putheader('Host', host)
        if origin is not None:
            client.putheader('Origin', origin)
        if content_type is not None:
            client.putheader('Content-Type', content_type)
        if user_agent is not None:
            client.putheader('User-Agent', user_agent)
        client.putheader('Content-Length', str(len(body)))
        client.endheaders(body)
        response = client.getresponse()
        return response.status, response.headers, response.read()
    finally:
        client.close()


@pytest.fixture
def served(certificates, tmp_path):  # noqa: F811
    from akdbx.local_https import start_local_unlock_server
    cert, key = certificates
    key.chmod(0o600)
    import socket
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    broker = Broker(Vault([Entry()]), RecordingTyper(), sms_sources_path=tmp_path / 'state' / 'sms.json')
    server, _url = start_local_unlock_server(broker, tmp_path / 'vault.kdbx', None, 'https://node.tailnet.ts.net',
                                             cert, key, local_port=port)
    try:
        yield SimpleNamespace(broker=broker, port=port, cert=cert, host='node.tailnet.ts.net')
    finally:
        server.shutdown()
        server.server_close()
        broker.unlock_notifications.close()


@pytest.mark.skipif(os.name == 'nt', reason='Linux loopback HTTPS fixture')
def test_https_intake_from_a_shortcut_and_twilio(served):
    broker = served.broker
    shortcut = broker.sms.add_source('iphone', 'shortcut')
    twilio = broker.sms.add_source('twilio-us', 'twilio')
    status, headers, body = https(served.port, served.cert, 'POST', '/sms/in/' + shortcut, host=served.host,
                                  body=json.dumps({'text': 'G-482913 is your Google verification code.',
                                                   'from': 'Google'}).encode(), content_type='application/json')
    assert (status, body) == (200, b'{"ok":true}')
    form = urlencode({'Body': 'Your Twilio verification code is: 771204', 'From': '+15550100',
                      'To': '+15550199', 'MessageSid': 'SM' + '0' * 32}).encode()
    status, headers, body = https(served.port, served.cert, 'POST', '/sms/in/' + twilio, host=served.host,
                                  body=form, content_type='application/x-www-form-urlencoded')
    assert status == 200 and headers['Content-Type'] == 'text/xml' and b'<Response>' in body
    codes = sorted(m.code for m in broker.sms.messages)
    assert codes == ['482913', '771204']
    # A text without a code gets the same answer and is not kept.
    status, _, body = https(served.port, served.cert, 'POST', '/sms/in/' + shortcut, host=served.host,
                            body=b'{"text": "Lunch?", "from": "Sam"}', content_type='application/json')
    assert (status, body) == (200, b'{"ok":true}') and len(broker.sms.messages) == 2


@pytest.mark.skipif(os.name == 'nt', reason='Linux loopback HTTPS fixture')
def test_https_intake_refuses_wrong_token_host_origin_method_and_body(served):
    token = served.broker.sms.add_source('iphone', 'shortcut')
    good = json.dumps({'text': 'code 123456'}).encode()
    for method, path, extra in (
            ('POST', '/sms/in/' + 'A' * 43, {}),
            ('POST', '/sms/in/' + token, dict(host='attacker.test')),
            ('POST', '/sms/in/' + token, dict(origin='https://attacker.test')),
            ('GET', '/sms/in/' + token, dict(body=b'')),
            ('POST', '/sms/in/' + token, dict(content_type='text/plain')),
            ('POST', '/sms/in/' + token, dict(body=b'{"from": "x"}')),
            ('POST', '/sms/in/' + token, dict(body=b'x' * (64 * 1024)))):
        options = dict(host=served.host, body=good, content_type='application/json')
        options.update(extra)
        status, _, body = https(served.port, served.cert, method, path, **options)
        assert status in {400, 404}, (method, extra)
    assert served.broker.sms.messages == []


@pytest.mark.skipif(os.name == 'nt', reason='Linux loopback HTTPS fixture')
def test_setup_page_shows_the_webhook_url_for_its_source_only(served):
    broker = served.broker
    broker.unlock_link.origin  # the page's own origin
    receipt = broker.dispatch(dict(action='sms-add-source', sms_protocol=1, name='iphone', kind='shortcut'))
    path = urlsplit(receipt['private_url'])
    status, headers, body = https(served.port, served.cert, 'GET', path.path + '?' + path.query, host=served.host)
    assert status == 200 and headers['Cache-Control'] == 'no-store'
    setup = broker.sms.setup(path.query.split('=', 1)[1])
    assert ('https://node.tailnet.ts.net/sms/in/' + setup.token).encode() in body
    assert b'Get Contents of URL' in body
    # Tapping the box copies the URL: the portal script copies data-copy and says so in the box.
    assert ('data-copy="https://node.tailnet.ts.net/sms/in/' + setup.token + '"').encode() in body
    assert b'class="copy-label" data-idle="Webhook URL (keep it private). Tap to copy." aria-live="polite"' in body
    assert b'Link copied to clipboard' in body and b'navigator.clipboard.writeText' in body
    status, _, body = https(served.port, served.cert, 'GET', '/sms/setup?token=' + 'B' * 43, host=served.host)
    assert status == 404 and setup.token.encode() not in body


# CLI receipts --------------------------------------------------------------


def run_cli(argv, responses, capsys):
    from akdbx.cli import parser
    args = parser().parse_args(argv)
    sent = []

    def request(payload):
        sent.append(payload)
        return responses.pop(0)
    code = sms_cli.run(args, request)
    return code, sent, capsys.readouterr()


PING = dict(ok=True, sms_protocol=1, locked=False, code_browser_configured=True)


def test_cli_prints_metadata_and_refuses_receipts_with_codes(capsys):
    row = dict(id='a' * 32, source='iphone', sender='Google', preview='G-•••• is your code',
               code_length=6, received_at='2026-11-23T10:00:00Z', age_seconds=3)
    code, sent, out = run_cli(['sms-wait', '--recent', '60', '--timeout', '30'], [PING, dict(ok=True, messages=[row])],
                              capsys)
    assert code == 0 and json.loads(out.out)['messages'] == [row]
    assert sent[1]['timeout'] == 30 and abs(sent[1]['since'] - (time.time() - 60)) < 5
    leaked = dict(row, preview='G-482913 is your code')
    code, _, out = run_cli(['sms-wait'], [PING, dict(ok=True, messages=[leaked])], capsys)
    assert code == 2 and '482913' not in out.out + out.err
    code, _, out = run_cli(['fill-sms-code', 'a' * 32, '--target', 'b' * 64],
                           [PING, dict(ok=True, filled='one-time-code', code='482913')], capsys)
    assert code == 2 and '482913' not in out.out + out.err


def test_cli_refuses_an_old_broker_before_sending(capsys):
    code, sent, out = run_cli(['sms-sources'], [dict(ok=True)], capsys)
    assert code == 1 and len(sent) == 1 and 'SMS protocol 1' in out.out


SAFARI_26 = ('Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) '
             'Version/26.1 Mobile/15E148 Safari/604.1')
SAFARI_27 = SAFARI_26.replace('18_6', '18_7').replace('Version/26.1', 'Version/27.0')
SAFARI_17 = SAFARI_26.replace('18_6', '17_5').replace('Version/26.1', 'Version/17.5')
CHROME_16 = ('Mozilla/5.0 (iPhone; CPU iPhone OS 16_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) '
             'CriOS/120.0.6099.119 Mobile/15E148 Safari/604.1')
DESKTOP = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36'


@pytest.mark.parametrize('agent, major, group', [
    (SAFARI_27, 27, 'ios27'), (SAFARI_26, 26, 'ios17'), (SAFARI_17, 17, 'ios17'),
    (CHROME_16, 16, 'ios16'), (DESKTOP, None, 'ios27'), ('', None, 'ios27')])
def test_ios_version_detection_reads_safari_version_not_the_frozen_os_token(agent, major, group):
    from akdbx.sms_web import ios_major, shortcut_group
    assert ios_major(agent) == major and shortcut_group(major) == group


@pytest.mark.skipif(os.name == 'nt', reason='Linux loopback HTTPS fixture')
@pytest.mark.parametrize('agent, group', [(SAFARI_26, 'ios17'), (SAFARI_27, 'ios27'), (CHROME_16, 'ios16')])
def test_setup_page_opens_the_steps_for_the_detected_ios_version(served, agent, group):
    receipt = served.broker.dispatch(dict(action='sms-add-source', sms_protocol=1, name='iphone', kind='shortcut'))
    path = urlsplit(receipt['private_url'])
    status, _, body = https(served.port, served.cert, 'GET', path.path + '?' + path.query, host=served.host,
                            user_agent=agent)
    assert status == 200
    shown = re.findall(rb'<ol data-variant="(\w+)" data-variant-group="ios-steps">', body)
    hidden = re.findall(rb'<ol data-variant="(\w+)" data-variant-group="ios-steps" hidden>', body)
    assert shown == [group.encode()] and len(hidden) == 2
    assert f'<option data-show="{group}" selected>'.encode() in body and body.count(b' selected>') == 1
    assert b'data-variant-select="ios-steps"' in body
