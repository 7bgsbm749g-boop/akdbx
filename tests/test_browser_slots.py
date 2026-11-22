"""Agent desktop browser slots: one profile root, one Chrome per slot.

Each fake browser answers only for its own slot's page, like separate Chrome
processes. The real two-Chrome test is in test_browser_slots_chromium.py.
"""
import json
import os
from pathlib import Path

import pytest

from akdbx import browser_slots, card_hit_test, cli
import akdbx.browser_password as browser_password
from akdbx.broker import Broker
from akdbx.extension_route import DELIVERY as EXTENSION_DELIVERY
from akdbx.browser_slots import BrowserSlots, SlotError
from akdbx.identities import MARKER as IDENTITY_MARKER, property_key
from akdbx.target import TargetError
from test_broker import Entry, RecordingTyper, Vault
from test_card_chromium import CardEntry
from test_cards import CARD

TOP = 'https://example.com/login'
PHONE = '+64 21 555 0100'


class IdentityEntry(Entry):
    def get_custom_property(self, key):
        return {IDENTITY_MARKER: 'v1', property_key('tel'): PHONE}.get(key)


def private(path):
    path.mkdir(mode=0o700)
    return path


@pytest.fixture
def root(tmp_path):
    for path in [tmp_path, tmp_path.parent]:
        if path.stat().st_uid == os.getuid():
            path.chmod(0o700)
    root = private(tmp_path / 'profiles')
    for name in ('slot1', 'slot2', 'slot4'):
        private(root / name)
    return root


def publish(profile, port):
    """What Chrome writes under umask 077 with --remote-debugging-port=0."""
    path = profile / 'DevToolsActivePort'
    path.write_text(f'{port}\n/devtools/browser/synthetic-{profile.name}\n')
    path.chmod(0o600)


class Browsers:
    """One fake Chrome per slot. A browser knows only its own page id."""

    def __init__(self):
        self.delivered, self.connections = {}, []

    def connect(self, profile):
        # The broker's real endpoint check runs on the exact slot directory.
        browser_password.endpoint(profile)
        connection = FakeCDP(self, Path(profile).name)
        self.connections.append(connection)
        return connection


class FakeCDP:
    def __init__(self, browsers, slot):
        self.browsers, self.slot, self.closed = browsers, slot, False

    def close(self):
        self.closed = True

    def call(self, method, params=None, session=None, timeout=3):
        params = params or {}
        page = 'page-' + self.slot
        if method == 'Target.getTargetInfo':
            if params['targetId'] != page:
                raise TargetError()  # Another browser's page does not exist here.
            return {'targetInfo': {'type': 'page', 'url': TOP, 'targetId': page}}
        if method == 'Target.attachToTarget':
            return {'sessionId': 'session-' + self.slot}
        if method == 'Page.getFrameTree':
            return {'frameTree': {'frame': {'id': 'frame-' + self.slot, 'url': TOP}}}
        if method == 'Page.createIsolatedWorld':
            return {'executionContextId': 1}
        if method == 'Runtime.evaluate':
            return {'result': {'type': 'object', 'objectId': 'object-' + self.slot}}
        if method == 'Runtime.callFunctionOn':
            source = params['functionDeclaration']
            values = [a.get('value') for a in params.get('arguments', [])]
            if 'performance.now()' in source and 'return' in source and not values:
                return {'result': {'value': 1000.0}}
            if source == browser_password.FILL:
                self.browsers.delivered.setdefault(self.slot, []).append(tuple(values[:3]))
                return {'result': {'value': True}}
            if 'this.fill(value' in source:
                self.browsers.delivered.setdefault(self.slot, []).append(values[0])
                return {'result': {'value': 'filled'}}
        return {}


@pytest.fixture
def browsers(root, monkeypatch):
    fake = Browsers()
    monkeypatch.setattr(browser_password, 'CDP', fake.connect)
    monkeypatch.setattr(card_hit_test, 'retained_node', lambda *args: 1)
    monkeypatch.setattr(card_hit_test, 'input_point', lambda *args: (10, 10))
    for port, name in ((9101, 'slot1'), (9104, 'slot4')):
        publish(root / name, port)
    return fake


def slot_broker(root, browsers, entries):
    broker = Broker(Vault(entries), RecordingTyper(), browser_profile_root=root)
    broker.card_targets.connector = browsers.connect
    broker.identity_targets.connector = browsers.connect
    return broker


def password_pin(slot, **changes):
    request = dict(action='pin-password-target', password_protocol=1, page_id=f'page-{slot}',
                   frame_id=f'frame-{slot}', top_url=TOP, selector='#password', mode='password')
    if slot is not None:
        request['browser_slot'] = slot
    request.update(changes)
    return request


def element_pin(kind, slot, field):
    request = {'action': f'pin-{kind}-target', f'{kind}_protocol': 1, 'page_id': 'page-' + slot,
               'frame_id': 'frame-' + slot, 'top_url': TOP, 'frame_url': TOP, 'selector': '#field', 'field': field,
               'browser_slot': slot}
    return request


def fill_password(broker, target):
    handle = broker.dispatch(dict(action='search'))['entries'][0]['handle']
    return broker.dispatch(dict(action='fill', handle=handle, mode='password', target=target, target_protocol=1))


def test_password_pin_and_fill_use_the_named_slot(root, browsers):
    broker = slot_broker(root, browsers, [Entry(url=TOP)])
    pin = broker.dispatch(password_pin('slot4'))
    assert pin['ok'] and pin['target_delivery'] == 'chromium-password-dom-v1'
    assert [c.slot for c in browsers.connections] == ['slot4']
    assert broker.passwords.pins[pin['target']][1].slot == 'slot4'
    assert fill_password(broker, pin['target']) == dict(ok=True, filled='password',
                                                       target_delivery='chromium-password-dom-v1')
    assert list(browsers.delivered) == ['slot4'] and browsers.delivered['slot4'][0][2] == Entry.password


def test_card_pin_and_fill_use_the_named_slot(root, browsers):
    broker = slot_broker(root, browsers, [CardEntry()])
    pin = broker.dispatch(element_pin('card', 'slot4', 'cc-number'))
    assert pin['ok'], pin
    assert broker.card_targets.pins[pin['target']]['slot'] == 'slot4'
    handle = broker.dispatch(dict(action='search-cards', card_protocol=1))['entries'][0]['handle']
    result = broker.dispatch(dict(action='fill-card', card_protocol=1, handle=handle, target=pin['target'],
                                  field='cc-number', start_deadline=broker.clock() + 4))
    assert result == dict(ok=True, filled='cc-number', card_delivery='cdp-card-element-v1')
    assert browsers.delivered == {'slot4': [CARD['number']]}


def test_identity_pin_and_fill_use_the_named_slot(root, browsers):
    broker = slot_broker(root, browsers, [IdentityEntry()])
    pin = broker.dispatch(element_pin('identity', 'slot1', 'tel'))
    assert pin['ok'], pin
    handle = broker.dispatch(dict(action='search-identities', identity_protocol=1, query=''))['entries'][0]['handle']
    result = broker.dispatch(dict(action='fill-identity', identity_protocol=1, handle=handle, target=pin['target'],
                                  field='tel', start_deadline=broker.clock() + 4))
    assert result == dict(ok=True, filled='tel', identity_delivery='cdp-identity-element-v1')
    assert browsers.delivered == {'slot1': [PHONE]}


def test_password_frames_use_the_named_slot(root, browsers, monkeypatch):
    seen = []
    monkeypatch.setattr(browser_password.password_frames, 'listing',
                        lambda connection, *args: seen.append(connection.slot) or {'ok': True})
    broker = slot_broker(root, browsers, [])
    request = dict(action='list-password-frames', password_protocol=1, frame_protocol=1, top_url=TOP,
                   page_id='page-slot4', browser_slot='slot4')
    assert broker.dispatch(request) == {'ok': True} and seen == ['slot4']
    assert not broker.dispatch({**request, 'browser_slot': 'slot1'})['ok']  # slot1 has no such page


def test_pin_for_one_slot_never_delivers_into_another(root, browsers):
    broker = slot_broker(root, browsers, [Entry(url=TOP)])
    one = broker.dispatch(password_pin('slot1'))
    four = broker.dispatch(password_pin('slot4'))
    assert one['ok'] and four['ok']
    # A slot4 request cannot pin slot1's page: that page is not in slot4's Chrome.
    assert broker.dispatch(password_pin('slot4', page_id='page-slot1'))['delivery'] == 'not-started'
    # The slot1 pin fills slot1 only, even after a newer slot4 pin.
    assert fill_password(broker, one['target'])['ok']
    assert list(browsers.delivered) == ['slot1']
    assert fill_password(broker, four['target'])['ok']
    assert [len(browsers.delivered[s]) for s in ('slot1', 'slot4')] == [1, 1]
    # A used or unknown target never falls back to another slot's browser.
    assert not fill_password(broker, one['target'])['ok']
    assert [len(browsers.delivered[s]) for s in ('slot1', 'slot4')] == [1, 1]


def test_card_pin_for_one_slot_never_fills_another(root, browsers):
    broker = slot_broker(root, browsers, [CardEntry()])
    one = broker.dispatch(element_pin('card', 'slot1', 'cc-number'))
    assert one['ok']
    wrong = element_pin('card', 'slot4', 'cc-number')
    wrong['page_id'] = 'page-slot1'
    assert broker.dispatch(wrong)['delivery'] == 'not-started'
    handle = broker.dispatch(dict(action='search-cards', card_protocol=1))['entries'][0]['handle']
    assert broker.dispatch(dict(action='fill-card', card_protocol=1, handle=handle, target=one['target'],
                                field='cc-number', start_deadline=broker.clock() + 4))['ok']
    assert browsers.delivered == {'slot1': [CARD['number']]}


REQUIRED = ('browser slot required: this broker fills the Chrome of one agent desktop slot; '
            'pass --browser-slot SLOT or set AGENT_DESKTOP_SLOT (slots: slot1, slot2, slot4)')


@pytest.mark.parametrize('kind', ['password', 'card', 'identity'])
def test_root_without_slot_refuses_and_names_the_slots(root, browsers, kind):
    broker = slot_broker(root, browsers, [])
    request = password_pin('slot1') if kind == 'password' else element_pin(kind, 'slot1', 'tel' if kind == 'identity' else 'cc-number')
    del request['browser_slot']
    assert broker.dispatch(request) == {'ok': False, 'error': REQUIRED}
    assert browsers.connections == []


@pytest.mark.parametrize('name, error', [
    ('slot0', 'browser slot invalid: use a slot name such as slot1'),
    ('slot100', 'browser slot invalid: use a slot name such as slot1'),
    ('../slot1', 'browser slot invalid: use a slot name such as slot1'),
    ('slot1/../slot4', 'browser slot invalid: use a slot name such as slot1'),
    ('/tmp/slot1', 'browser slot invalid: use a slot name such as slot1'),
    ('slot1\n', 'browser slot invalid: use a slot name such as slot1'),
    (1, 'browser slot invalid: use a slot name such as slot1'),
    ('slot3', 'browser slot unknown: slot3 (slots: slot1, slot2, slot4)'),
    ('slot99', 'browser slot unknown: slot99 (slots: slot1, slot2, slot4)'),
])
@pytest.mark.parametrize('kind', ['password', 'card', 'identity'])
def test_invalid_traversal_and_unknown_slots_refuse(root, browsers, name, error, kind):
    broker = slot_broker(root, browsers, [])
    request = password_pin('slot1') if kind == 'password' else element_pin(kind, 'slot1', 'tel' if kind == 'identity' else 'cc-number')
    request['browser_slot'] = name
    assert broker.dispatch(request) == {'ok': False, 'error': error}
    assert browsers.connections == [] and browser_slots.valid_message(error)


def test_slot_without_a_live_browser_refuses_without_connecting(root, browsers):
    broker = slot_broker(root, browsers, [])
    # slot2 exists but runs no Chrome: the endpoint check refuses it.
    assert broker.dispatch(password_pin('slot2'))['delivery'] == 'not-started'
    assert browsers.connections == []


@pytest.mark.parametrize('change', ['symlink', 'group-writable', 'foreign-file', 'symlink-port-file'])
def test_existing_profile_checks_apply_to_the_slot_directory(root, browsers, tmp_path, change):
    broker = slot_broker(root, browsers, [Entry(url=TOP)])
    slot = root / 'slot4'
    if change == 'symlink':
        target = private(tmp_path / 'elsewhere')
        publish(target, 9200)
        (slot / 'DevToolsActivePort').unlink()
        slot.rmdir()
        slot.symlink_to(target)
    elif change == 'group-writable':
        slot.chmod(0o770)
    elif change == 'foreign-file':
        (slot / 'DevToolsActivePort').chmod(0o666)
    else:
        real = tmp_path / 'port'
        (slot / 'DevToolsActivePort').rename(real)
        (slot / 'DevToolsActivePort').symlink_to(real)
    response = broker.dispatch(password_pin('slot4'))
    assert response['ok'] is False and browsers.connections == []
    if change == 'symlink':
        assert response['error'] == 'browser slot unknown: slot4 (slots: slot1, slot2)'


def test_symlinked_root_lists_nothing_and_refuses(root, browsers, tmp_path):
    link = tmp_path / 'link'
    link.symlink_to(root)
    broker = slot_broker(link, browsers, [Entry(url=TOP)])
    assert broker.dispatch(password_pin('slot4'))['ok'] is False
    assert broker.dispatch(dict(action='ping'))['browser_slots_live'] == []
    assert browsers.connections == []


def test_slot_without_a_root_refuses_and_single_profile_still_works(root, browsers):
    broker = Broker(Vault([Entry(url=TOP)]), RecordingTyper(), password_browser_profile=root / 'slot1')
    assert broker.dispatch(password_pin('slot1')) == {'ok': False, 'error': (
        'browser slot not supported: this broker has no --browser-profile-root; omit --browser-slot')}
    assert browsers.connections == []
    # The single-profile option is unchanged: no slot field, same browser.
    pin = broker.dispatch(password_pin(None, page_id='page-slot1', frame_id='frame-slot1'))
    assert pin['ok'] and [c.slot for c in browsers.connections] == ['slot1']
    assert broker.passwords.pins[pin['target']][1].slot is None


def test_extension_route_never_takes_a_slot(root, browsers):
    broker = slot_broker(root, browsers, [])
    message = 'browser slot applies only to the cdp route; omit --browser-slot with --route extension'
    assert broker.dispatch(password_pin('slot1', route='extension')) == {'ok': False, 'error': message}
    assert broker.dispatch({**element_pin('card', 'slot1', 'cc-number'), 'route': 'extension'}) == {'ok': False, 'error': message}
    assert broker.dispatch(dict(action='list-password-frames', password_protocol=1, frame_protocol=1, top_url=TOP,
                                route='extension', browser_slot='slot1')) == {'ok': False, 'error': message}
    assert browsers.connections == []


def test_root_and_single_profiles_are_exclusive(root):
    with pytest.raises(ValueError):
        Broker(None, RecordingTyper(), browser_profile_root=root, password_browser_profile=root / 'slot1')
    with pytest.raises(ValueError):
        Broker(None, RecordingTyper(), browser_profile_root=root, card_browser_profile=root / 'slot1')


def test_status_names_the_root_and_the_live_slots(root, browsers):
    broker = slot_broker(root, browsers, [])
    status = broker.dispatch(dict(action='ping'))
    assert status['browser_profile_root'] == str(root) and status['browser_slot_protocol'] == 1
    assert status['browser_slots'] == ['slot1', 'slot2', 'slot4']
    assert status['browser_slots_live'] == ['slot1', 'slot4']
    assert status['password_browser_configured'] and status['card_browser_configured'] and status['identity_browser_configured']
    for name in ('slot10', 'notaslot', 'slot0'):
        private(root / name)
    (root / 'slot5').symlink_to(root / 'slot4')
    assert broker.dispatch(dict(action='ping'))['browser_slots'] == ['slot1', 'slot2', 'slot4', 'slot10']
    assert browsers.connections == []  # Status reads the port files only.
    single = Broker(None, RecordingTyper())
    assert 'browser_profile_root' not in single.dispatch(dict(action='ping'))


def test_cli_status_shows_root_and_live_slots(root, browsers, monkeypatch, capsys):
    broker = slot_broker(root, browsers, [])
    monkeypatch.setattr(cli, 'request', lambda path, payload, **kwargs: broker.dispatch(payload))
    assert cli.main(['status']) == 0
    status = json.loads(capsys.readouterr().out)
    assert status['browser_profile_root'] == str(root) and status['browser_slots_live'] == ['slot1', 'slot4']


CAPS = dict(ok=True, password_fill_protocol=1, password_fill_delivery='chromium-password-dom-v1',
            browser_slot_protocol=1, cards_supported=True, card_protocol=1, card_delivery='cdp-card-element-v1',
            identity_protocol=1, identity_delivery='cdp-identity-element-v1', identity_browser_configured=True,
            locked=False, password_frame_protocol=1, password_frame_policy='same-site-chain-v1')
PIN_ARGS = {
    'pin-password-target': ['--page-id', 'P', '--frame-id', 'F', '--top-url', TOP, '--selector', '#password'],
    'pin-card-target': ['--page-id', 'P', '--frame-id', 'F', '--top-url', TOP, '--frame-url', TOP,
                        '--selector', '#n', '--field', 'cc-number'],
    'pin-identity-target': ['--page-id', 'P', '--frame-id', 'F', '--top-url', TOP, '--frame-url', TOP,
                            '--selector', '#t', '--field', 'tel'],
    'list-password-frames': ['--top-url', TOP],
}


def recording(monkeypatch, caps=CAPS, response=None):
    calls = []
    def request(path, payload, **kwargs):
        calls.append(payload)
        return caps if payload['action'] == 'ping' else response or {'ok': False, 'error': REQUIRED}
    monkeypatch.setattr(cli, 'request', request)
    return calls


@pytest.mark.parametrize('command', list(PIN_ARGS))
def test_cli_sends_the_explicit_slot_or_agent_desktop_slot(monkeypatch, capsys, command):
    calls = recording(monkeypatch)
    cli.main([command, *PIN_ARGS[command], '--browser-slot', 'slot4'])
    assert calls[-1]['browser_slot'] == 'slot4'
    monkeypatch.setenv('AGENT_DESKTOP_SLOT', 'slot2')
    cli.main([command, *PIN_ARGS[command]])
    assert calls[-1]['browser_slot'] == 'slot2'
    cli.main([command, *PIN_ARGS[command], '--browser-slot', 'slot3'])
    assert calls[-1]['browser_slot'] == 'slot3'  # The option wins over the variable.
    monkeypatch.delenv('AGENT_DESKTOP_SLOT')
    cli.main([command, *PIN_ARGS[command]])
    assert 'browser_slot' not in calls[-1]
    capsys.readouterr()


@pytest.mark.parametrize('command', ['pin-password-target', 'pin-card-target', 'pin-identity-target'])
def test_cli_shows_the_broker_slot_refusal(monkeypatch, capsys, command):
    recording(monkeypatch)
    assert cli.main([command, *PIN_ARGS[command]]) == 1
    assert json.loads(capsys.readouterr().out) == {'ok': False, 'error': REQUIRED}


@pytest.mark.parametrize('command', list(PIN_ARGS))
@pytest.mark.parametrize('value, caps, error', [
    ('../slot1', CAPS, '--browser-slot is not a slot name such as slot1; request not sent'),
    ('slot1', {**CAPS, 'browser_slot_protocol': None},
     'broker lacks browser slot protocol 1; require broker 0.29.0 or newer; request not sent'),
])
def test_cli_refuses_a_bad_name_or_an_old_broker_before_sending(monkeypatch, capsys, command, value, caps, error):
    calls = recording(monkeypatch, caps)
    assert cli.main([command, *PIN_ARGS[command], '--browser-slot', value]) == 1
    assert all(call['action'] == 'ping' for call in calls)
    assert json.loads(capsys.readouterr().out) == {'ok': False, 'error': error}


@pytest.mark.parametrize('command', ['pin-password-target', 'pin-card-target', 'pin-identity-target'])
def test_cli_extension_route_ignores_the_variable_and_refuses_the_option(monkeypatch, capsys, command):
    caps = {**CAPS, 'extension_protocol': 1, 'extension_delivery': EXTENSION_DELIVERY}
    calls = recording(monkeypatch, caps)
    monkeypatch.setenv('AGENT_DESKTOP_SLOT', 'slot2')
    cli.main([command, *PIN_ARGS[command], '--route', 'extension'])
    assert calls[-1]['action'] == command and 'browser_slot' not in calls[-1]
    calls.clear()
    assert cli.main([command, *PIN_ARGS[command], '--route', 'extension', '--browser-slot', 'slot2']) == 1
    assert all(call['action'] == 'ping' for call in calls)
    assert 'only to the cdp route' in capsys.readouterr().out


def test_cli_read_pin_uses_the_slot_even_with_an_extension_default(monkeypatch, capsys):
    caps = {**CAPS, 'default_fill_route': 'extension', 'secret_capture_protocol': 1,
            'secret_capture_delivery': 'chromium-dom-read-v1'}
    calls = recording(monkeypatch, caps)
    cli.main(['pin-password-target', *PIN_ARGS['pin-password-target'], '--mode', 'read', '--browser-slot', 'slot1'])
    assert calls[-1]['action'] == 'pin-password-target' and calls[-1]['browser_slot'] == 'slot1'


def test_serve_refuses_a_root_with_single_profiles(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv('AKDBX_BROWSER_PROFILE_ROOT', str(tmp_path))
    args = cli.parser().parse_args(['serve', str(tmp_path / 'v.kdbx'), '--password-browser-profile', str(tmp_path)])
    assert args.browser_profile_root == tmp_path
    assert cli._serve(args, None, None, None, None) == 2
    assert '--browser-profile-root replaces' in capsys.readouterr().err
