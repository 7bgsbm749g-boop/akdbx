"""KeePassXC/KP2A additional URLs: exact extra origins and the metadata-only write.

All vaults, credentials and targets are synthetic.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

import pytest
from lxml import etree

from akdbx import cli
from akdbx.broker import Broker
from akdbx.browser_password import BrowserPasswords, PasswordPin
from akdbx.target import DeliveryError
from akdbx.writes import additional_origins, additional_urls, allowed_origins
from test_broker import Entry, RecordingTyper, Vault, running_broker
from test_totp import URI, make_totp_broker, totp_fill
from test_writes import MASTER, OLD, deployed, reopened, template  # noqa: F401  (fixtures)


def strings(**fields):
    element = etree.Element('Entry')
    for key, value in fields.items():
        string = etree.SubElement(element, 'String')
        etree.SubElement(string, 'Key').text = key
        etree.SubElement(string, 'Value').text = value
    return element


@dataclass
class UrlEntry(Entry):
    _element: object = field(default_factory=lambda: strings())


def test_kp2a_fields_parse_to_exact_https_origins_only():
    entry = UrlEntry(url='https://soundcloud.com/', _element=strings(**{
        'KP2A_URL_2': 'https://second.example.org/path?q=1',
        'KP2A_URL': 'https://secure.soundcloud.com/',
        'KP2A_URL_1': 'http://insecure.example.org/',            # http grants nothing
        'KP2A_URL_3': '*.wildcard.example.org',                  # wildcard/junk grants nothing
        'KP2A_URL_6': 'https://*.wildcard.example.org/',         # a wildcard host is not a literal origin
        'KP2A_URL_4': 'https://user:pw@creds.example.org/',      # credentials grant nothing
        'KP2A_URL_5': 'https://SECURE.soundcloud.com:443/x',     # duplicate origin collapses
        'KP2A_URL_X': 'https://not-a-kp2a-key.example.org/',     # not a KP2A_URL key
        'URL_EXTRA': 'https://other-field.example.org/',
    }))
    assert additional_urls(entry) == ['https://secure.soundcloud.com', 'https://second.example.org']
    assert allowed_origins(entry) == {('https', 'soundcloud.com', 443), ('https', 'secure.soundcloud.com', 443),
                                      ('https', 'second.example.org', 443)}
    # An entry without an XML element (generated-fill proxy, foreign object) has only its main origin.
    assert allowed_origins(Entry(url='https://example.com/login')) == {('https', 'example.com', 443)}
    assert additional_origins(Entry()) == []
    # An insecure main URL grants nothing; additional origins still need HTTPS.
    assert allowed_origins(UrlEntry(url='http://example.com/', _element=strings(KP2A_URL='https://a.example.com/'))) == {
        ('https', 'a.example.com', 443)}


def test_search_shows_additional_origins_and_matches_them():
    entry = UrlEntry(url='https://soundcloud.com/', _element=strings(KP2A_URL='https://secure.soundcloud.com/'))
    broker = Broker(Vault([entry, Entry(uuid='other', title='Other', url='https://other.test/')]), RecordingTyper())
    found = broker.dispatch({'action': 'search', 'query': 'secure.soundcloud'})
    assert found['ok'] and len(found['entries']) == 1
    assert found['entries'][0]['additional_urls'] == ['https://secure.soundcloud.com']
    assert entry.password not in json.dumps(found)
    plain = broker.dispatch({'action': 'search', 'query': 'Other'})['entries'][0]
    assert 'additional_urls' not in plain


class NoBrowser:
    """Records browser calls; the first one stops delivery (no real page here)."""
    def __init__(self):
        self.calls = []

    def call(self, *args, **kwargs):
        self.calls.append(args[0])
        raise RuntimeError('synthetic: no browser')

    def close(self):
        pass


@pytest.mark.parametrize('field_url,allowed', [
    ('https://soundcloud.com/signin', True),                  # main origin
    ('https://secure.soundcloud.com/web-auth', True),         # additional origin
    ('https://evil.example.net/form', False),                 # not listed
    ('https://soundcloud.com.evil.example.net/', False),      # suffix tricks are not origins
    ('https://secure.soundcloud.com:8443/', False),           # different port is a different origin
    ('https://api.soundcloud.com/', False),                   # same site but not listed
])
def test_delivery_requires_exact_listed_origin(field_url, allowed):
    entry = UrlEntry(url='https://soundcloud.com/', _element=strings(KP2A_URL='https://secure.soundcloud.com/'))
    browser = NoBrowser()
    pin = PasswordPin(browser, 'session', 'object', 'page', 'frame', field_url, 'password')
    with pytest.raises(DeliveryError) as refused:
        BrowserPasswords().deliver(pin, 'password', '', 'synthetic', allowed_origins(entry), lambda: True, 1e18)
    assert refused.value.started is False
    # A listed origin proceeds to the browser checks; any other origin refuses before them.
    assert browser.calls == (['Target.getTargetInfo'] if allowed else [])


def test_totp_fill_accepts_only_main_or_additional_origin():
    broker, typer = make_totp_broker()
    entry = broker.vault.entries[0]
    entry._element = strings(KP2A_URL='https://login.example.com/')
    assert totp_fill(broker, target_url='https://login.example.com/challenge')[0]['ok']
    assert totp_fill(broker, target_url='https://example.com/challenge')[0]['ok']
    refused = totp_fill(broker, target_url='https://other.example.com/challenge')[0]
    assert refused == {'ok': False, 'error': 'autofill not started: TOTP target site mismatch'}
    assert len(typer.events) == 2


# --- metadata-only add-url / remove-url -------------------------------------------------

def selected(broker, query='Synthetic site'):
    return broker.dispatch({'action': 'search', 'query': query})['entries'][0]


def change(broker, url, action='add-url', handle=None, **extra):
    handle = handle or selected(broker)['handle']
    return broker.dispatch({'action': action, 'handle': handle, 'url': url, 'additional_urls_protocol': 1, **extra})


def test_add_and_remove_round_trip_preserves_password_and_keeps_backups(deployed):
    broker, typer, path, _ = deployed
    before = reopened(path).find_entries(title='Synthetic site', first=True)
    history = len(before.history)
    added = change(broker, 'https://secure.example.test/')
    assert added == {'ok': True, 'state': 'saved', 'changed': 'added', 'url': 'https://secure.example.test/',
                     'additional_urls': ['https://secure.example.test'],
                     'metadata': {'title': 'Synthetic site', 'username': 'synthetic-account',
                                  'url': 'https://example.test/login', 'group': 'Web'}}
    assert OLD not in json.dumps(added) and MASTER not in json.dumps(added)
    vault = reopened(path)
    entry = vault.find_entries(title='Synthetic site', first=True)
    assert entry.password == OLD and entry.notes == 'preserve notes'
    assert entry.get_custom_property('custom') == 'preserve property'
    assert entry.get_custom_property('KP2A_URL') == 'https://secure.example.test/'  # KeePassXC "Additional URLs"
    assert len(entry.history) == history + 1 and entry.history[-1].get_custom_property('KP2A_URL') is None
    assert vault.find_entries(title='Unrelated', first=True).password == 'synthetic-unrelated-secret'
    backups = list(path.parent.glob('.*.akdbx-backup-*'))
    assert len(backups) == 1
    assert reopened(backups[0]).find_entries(title='Synthetic site', first=True).get_custom_property('KP2A_URL') is None
    assert not list(path.parent.glob('.*.akdbx-write-*'))
    assert selected(broker)['additional_urls'] == ['https://secure.example.test']

    second = change(broker, 'https://auth.example.test:8443')
    assert second['additional_urls'] == ['https://secure.example.test', 'https://auth.example.test:8443']
    assert reopened(path).find_entries(title='Synthetic site', first=True).get_custom_property('KP2A_URL_1') == 'https://auth.example.test:8443/'

    removed = change(broker, 'https://secure.example.test/', action='remove-url')
    assert removed['ok'] and removed['changed'] == 'removed' and removed['additional_urls'] == ['https://auth.example.test:8443']
    entry = reopened(path).find_entries(title='Synthetic site', first=True)
    assert entry.get_custom_property('KP2A_URL') is None and entry.password == OLD
    # The next addition reuses the free KeePassXC key.
    assert change(broker, 'https://secure.example.test/')['ok']
    assert reopened(path).find_entries(title='Synthetic site', first=True).get_custom_property('KP2A_URL') == 'https://secure.example.test/'
    assert typer.events == []


@pytest.mark.parametrize('url,error', [
    ('http://secure.example.test/', 'exact HTTPS origin'),
    ('https://secure.example.test/path', 'exact HTTPS origin'),
    ('https://secure.example.test/?q=1', 'exact HTTPS origin'),
    ('https://secure.example.test/#x', 'exact HTTPS origin'),
    ('https://user@secure.example.test/', 'exact HTTPS origin'),
    ('https://SECURE.example.test/', 'exact HTTPS origin'),
    ('https://secure.example.test:443/', 'exact HTTPS origin'),
    ('https://secure.example.test//', 'exact HTTPS origin'),
    ('secure.example.test', 'exact HTTPS origin'),
    ('*.example.test', 'exact HTTPS origin'),
    ('https://*.example.test/', 'exact HTTPS origin'),
    ('', 'exact HTTPS origin'),
    ('https://example.test/', 'duplicate URL'),                  # main origin
    ('https://other.test/', 'same site as the saved URL'),
    ('https://example.test.evil.example/', 'same site as the saved URL'),
    ('https://evilexample.test/', 'same site as the saved URL'),
])
def test_add_refuses_non_origins_duplicates_and_cross_site(deployed, url, error):
    broker, _, path, _ = deployed
    before = path.read_bytes()
    result = change(broker, url)
    assert result['ok'] is False and error in result['error'], result
    assert path.read_bytes() == before and not list(path.parent.glob('.*.akdbx-backup-*'))


def test_duplicate_additional_url_and_missing_removal_refuse(deployed):
    broker, _, path, _ = deployed
    assert change(broker, 'https://secure.example.test/')['ok']
    before = path.read_bytes()
    assert 'duplicate URL' in change(broker, 'https://secure.example.test')['error']
    assert 'not found' in change(broker, 'https://other.example.test/', action='remove-url')['error']
    assert path.read_bytes() == before


def test_request_shape_handles_and_protocol(deployed):
    broker, _, path, _ = deployed
    handle = selected(broker)['handle']
    before = path.read_bytes()
    for extra in ({'password': 'x'}, {'additional_urls_protocol': 2}, {'metadata': {}}):
        assert not change(broker, 'https://secure.example.test/', handle=handle, **extra)['ok']
    assert not broker.dispatch({'action': 'add-url', 'handle': handle, 'url': 'https://secure.example.test/'})['ok']
    assert 'search again' in change(broker, 'https://secure.example.test/', handle='0' * 64)['error']
    assert path.read_bytes() == before
    # A successful save invalidates every outstanding handle.
    stale = selected(broker)['handle']
    assert change(broker, 'https://secure.example.test/', handle=handle)['ok']
    assert 'search again' in change(broker, 'https://auth.example.test/', handle=stale)['error']


@pytest.mark.parametrize('main,new,allowed', [
    ('soundcloud.com', 'secure.soundcloud.com', True),
    ('www.example.com', 'secure.example.com', True),
    ('www.example.com', 'example.com', True),
    ('login.example.co.uk', 'auth.example.co.uk', True),
    ('www.example.com', 'www.example.co', False),
    ('example.co.uk', 'other.co.uk', False),            # ICANN multi-label suffix
    ('www.github.io', 'attacker.github.io', False),     # private suffix: other users' sites
    ('user.github.io', 'attacker.github.io', False),
    ('github.io', 'attacker.github.io', False),         # saved host is itself a suffix
    ('co.uk', 'evil.co.uk', False),
    ('a.b.ck', 'c.b.ck', False),                        # wildcard *.ck: b.ck is a suffix
    ('a.www.ck', 'www.ck', True),                       # exception !www.ck
    ('192.0.2.1', 'x.192.0.2.1', False),
    ('192.0.2.1', '192.0.2.1', True),
])
def test_add_url_same_site_uses_public_suffix_list(main, new, allowed):
    from akdbx.writes import _same_owner_host
    assert _same_owner_host(('https', main, 443), ('https', new, 8443)) is allowed


def test_vendored_public_suffix_list_provenance():
    from importlib import resources
    import hashlib
    folder = resources.files('akdbx').joinpath('public_suffix_assets')
    data = folder.joinpath('public_suffix_list.dat').read_bytes()
    vendor = folder.joinpath('VENDOR.txt').read_text()
    assert 'SHA256: ' + hashlib.sha256(data).hexdigest() in vendor
    assert b'===BEGIN PRIVATE DOMAINS===' in data and b'\ngithub.io\n' in data


def test_cli_add_url_and_remove_url_wire_flow(deployed, capsys):
    broker, _, path, socket = deployed
    sock = socket.with_name('cli.sock')
    prefix = ['--socket', str(sock), '--unlock-origin', 'https://node.example:9443']

    def command(*args, expected=0):
        assert cli.main([*prefix, *args]) == expected
        captured = capsys.readouterr()
        assert OLD not in captured.out + captured.err and MASTER not in captured.out + captured.err
        return json.loads(captured.out) if captured.out else captured.err

    with running_broker(sock, broker):
        status = command('status')
        assert status['additional_urls_protocol'] == 1 and status['additional_urls_policy'] == 'kp2a-exact-origin-v1'
        handle = command('search', 'Synthetic site')['entries'][0]['handle']
        added = command('add-url', '--url', 'https://secure.example.test/', '--', handle)
        assert added['ok'] and added['additional_urls'] == ['https://secure.example.test']
        assert command('search', 'Synthetic site')['entries'][0]['additional_urls'] == ['https://secure.example.test']
        handle = command('search', 'Synthetic site')['entries'][0]['handle']
        refused = command('add-url', '--url', 'http://secure.example.test/', '--', handle, expected=1)
        assert refused['ok'] is False
        handle = command('search', 'Synthetic site')['entries'][0]['handle']
        removed = command('remove-url', '--url', 'https://secure.example.test/', '--', handle)
        assert removed['ok'] and removed['additional_urls'] == []
    assert reopened(path).find_entries(title='Synthetic site', first=True).password == OLD


def test_cli_refuses_old_broker_without_sending(monkeypatch, capsys):
    sent = []

    def fake(socket_path, payload, **kwargs):
        sent.append(payload['action'])
        return {'ok': True, 'version': '0.16.0'}
    monkeypatch.setattr(cli, 'request', fake)
    assert cli.main(['--socket', '/nonexistent', 'add-url', '--url', 'https://a.example.com/', '--', 'a' * 64]) == 1
    assert sent == ['ping'] and 'additional URL protocol 1' in capsys.readouterr().out



@pytest.mark.parametrize('action', ['add-url', 'remove-url'])
def test_url_writes_hold_the_vault_lock(action, monkeypatch):
    import threading
    broker = Broker(Vault([Entry()]), RecordingTyper())
    observed = []

    def probe(request):
        result = []
        worker = threading.Thread(target=lambda: result.append(broker._vault_lock.acquire(blocking=False)))
        worker.start()
        worker.join()
        observed.append(result[0])
        return {'ok': True}
    monkeypatch.setattr(broker.writes, 'change_additional_url', probe)
    broker.dispatch({'action': action, 'handle': 'h', 'url': 'https://a.example.com/', 'additional_urls_protocol': 1})
    assert observed == [False]  # Another request cannot enter while a URL write runs.


# --- generated fills (fill-generated) on an additional URL origin --------------------------

from akdbx import browser_password as browser_password_module  # noqa: E402
from akdbx.totp import https_origin  # noqa: E402
from akdbx.target import failure as target_failure  # noqa: E402
from test_writes import begin, commit, reopened as reopened_vault  # noqa: E402

SECURE = 'https://secure.example.test/'
RESET = 'https://secure.example.test/password-reset/synthetic-reset-token'


class OriginCheckingPasswords(browser_password_module.BrowserPasswords):
    """Applies the real field-origin rule of BrowserPasswords._recheck, then records the typing."""
    _recording_fixture = True

    def __init__(self, broker, **kwargs):
        super().__init__(**kwargs)
        self.broker, self.seen = broker, []

    def deliver(self, pin, mode, username, password, site_origins, ready, start_deadline):
        self.seen.append((pin.url, frozenset(site_origins)))
        if mode != pin.mode or https_origin(pin.url) not in site_origins:
            raise DeliveryError(False)
        self.broker.typer.deliver(pin, [password], ready)


def cdp_pin(broker, frame_url):
    """A synthetic CDP DOM pin whose field document has frame_url."""
    import secrets
    if not isinstance(broker.passwords, OriginCheckingPasswords):
        broker.passwords = OriginCheckingPasswords(broker, clock=broker.clock)

    class Connection:
        def call(self, *args, **kwargs):
            return {}

        def close(self):
            pass
    token = secrets.token_hex(32)
    pin = PasswordPin(Connection(), 'synthetic-session', 'synthetic-node', 'synthetic-page', 'synthetic-frame',
                      frame_url, 'password')
    with broker.passwords._lock:
        broker.passwords.pins[token] = broker.clock() + 30, pin
    return dict(target=token, target_protocol=1)


def add_secure_url(broker, url=SECURE):
    handle = broker.dispatch({'action': 'search', 'query': 'Synthetic site'})['entries'][0]['handle']
    added = broker.dispatch({'action': 'add-url', 'handle': handle, 'url': url, 'additional_urls_protocol': 1})
    assert added['ok'] and added['additional_urls'] == [url.rstrip('/')]


def generated_fill(broker, ref, target_url, frame_url=None):
    return broker.dispatch({'action': 'fill-generated', **cdp_pin(broker, frame_url or target_url),
                            'handle': ref, 'target_url': target_url})


def test_status_reports_generated_additional_urls():
    assert Broker(Vault([]), RecordingTyper()).dispatch({'action': 'ping'})['generated_additional_urls'] is True


@pytest.mark.parametrize('target_url', [
    'https://example.test/reset',                              # main URL origin
    RESET,                                                     # additional URL origin
])
def test_generated_reset_fills_main_or_additional_origin_and_commits(deployed, target_url, capsys, caplog):
    broker, typer, path, _ = deployed
    add_secure_url(broker)
    staged = begin(broker, 'generate-password')
    assert staged['ok']
    receipts = [generated_fill(broker, staged['fill_handles'][mode], target_url) for mode in ('password', 'confirmation')]
    assert all(r == {'ok': True, 'filled': 'password', 'target_delivery': browser_password_module.DELIVERY}
               for r in receipts), receipts
    # The delivery route received only the asserted target origin.
    assert {origins for _, origins in broker.passwords.seen} == {frozenset({https_origin(target_url)})}
    assert len(typer.events) == 2 and typer.events[0] == typer.events[1]
    assert commit(broker, staged) == {'ok': True, 'state': 'saved'}
    saved = reopened_vault(path).find_entries(title='Synthetic site', first=True)
    assert saved.password == typer.events[0][1] and saved.password != OLD
    assert saved.get_custom_property('KP2A_URL') == SECURE
    assert saved.password not in json.dumps(receipts) + capsys.readouterr().out + caplog.text


def test_single_field_generated_fill_accepts_additional_origin(deployed):
    broker, typer, path, _ = deployed
    add_secure_url(broker)
    staged = begin(broker, 'generate-password', single_field=True)
    assert generated_fill(broker, staged['fill_handles']['password'], RESET)['ok']
    assert commit(broker, staged) == {'ok': True, 'state': 'saved'}
    assert reopened_vault(path).find_entries(title='Synthetic site', first=True).password == typer.events[0][1]


@pytest.mark.parametrize('target_url,error', [
    ('https://unrelated.test/password-reset', 'target site mismatch; no password filled'),
    ('https://secure.example.test.evil.test/password-reset', 'target site mismatch; no password filled'),
    ('https://secure-example.test/password-reset', 'target site mismatch; no password filled'),
    ('https://secure.example.test:8443/password-reset', 'target site mismatch; no password filled'),
    ('https://api.example.test/password-reset', 'target site mismatch; no password filled'),  # same site, not listed
    ('http://secure.example.test/password-reset',
     'generated resets require a verified ASCII HTTPS site URL without credentials'),
    ('https://user@secure.example.test/password-reset',
     'generated resets require a verified ASCII HTTPS site URL without credentials'),
    ('https://secure.éxample.test/password-reset',
     'generated resets require a verified ASCII HTTPS site URL without credentials'),
])
def test_generated_fill_refuses_other_origins_and_consumes_the_reference(deployed, target_url, error):
    broker, typer, path, _ = deployed
    add_secure_url(broker)
    staged = begin(broker, 'generate-password')
    ref = staged['fill_handles']['password']
    assert generated_fill(broker, ref, target_url) == {'ok': False, 'error': error}
    assert generated_fill(broker, ref, RESET) == {
        'ok': False, 'error': 'unknown or expired generated fill handle; start again'}
    assert not typer.events and not broker.passwords.seen
    assert not commit(broker, staged)['ok']
    assert reopened_vault(path).find_entries(title='Synthetic site', first=True).password == OLD


@pytest.mark.parametrize('target_url,frame_url', [
    (RESET, 'https://example.test/reset'),                    # asserted additional, pinned on main
    ('https://example.test/reset', RESET),                    # asserted main, pinned on additional
    (RESET, 'https://evil.test/password-reset'),              # pinned document on another site
])
def test_pinned_document_must_have_the_asserted_target_origin(deployed, target_url, frame_url):
    broker, typer, path, _ = deployed
    add_secure_url(broker)
    staged = begin(broker, 'generate-password')
    assert generated_fill(broker, staged['fill_handles']['password'], target_url, frame_url) == target_failure(False)
    assert not typer.events and not broker.writes.get(staged['write_handle']).filled


def test_real_cdp_route_refuses_a_pinned_document_on_another_listed_origin(deployed):
    """Uses the real BrowserPasswords.deliver origin gate; NoBrowser records any browser call."""
    broker, typer, _, _ = deployed
    add_secure_url(broker)
    staged = begin(broker, 'generate-password')
    browser = NoBrowser()
    broker.passwords = BrowserPasswords(clock=broker.clock)
    import secrets
    for frame_url, reached in (('https://example.test/reset', False), (RESET, True)):
        token = secrets.token_hex(32)
        pin = PasswordPin(browser, 'session', 'object', 'page', 'frame', frame_url, 'password')
        with broker.passwords._lock:
            broker.passwords.pins[token] = broker.clock() + 30, pin
        mode = 'password' if not reached else 'confirmation'
        result = broker.dispatch({'action': 'fill-generated', 'target': token, 'target_protocol': 1,
                                  'handle': staged['fill_handles'][mode], 'target_url': RESET})
        assert result['ok'] is False
        # Only the pin on the asserted origin reaches the browser checks.
        assert ('Target.getTargetInfo' in browser.calls) is reached
        browser.calls.clear()
    assert not typer.events


def test_additional_url_removed_after_generation_no_longer_permits_a_fill(deployed):
    broker, typer, path, _ = deployed
    add_secure_url(broker)
    staged = begin(broker, 'generate-password')
    # A vault change that removes the field without a broker write (for example
    # a reload of a synchronized file) is read from the entry at fill time.
    [entry] = [e for e in broker.vault.entries if e.title == 'Synthetic site']
    entry.delete_custom_property('KP2A_URL')
    assert generated_fill(broker, staged['fill_handles']['password'], RESET) == {
        'ok': False, 'error': 'target site mismatch; no password filled'}
    # The main origin still works for the other reference.
    assert generated_fill(broker, staged['fill_handles']['confirmation'], 'https://example.test/reset')['ok']
    assert not commit(broker, staged)['ok'] and len(typer.events) == 1


def test_remove_url_or_metadata_change_between_generate_and_fill_refuses(deployed):
    broker, typer, path, _ = deployed
    add_secure_url(broker)
    staged = begin(broker, 'generate-password')
    handle = broker.dispatch({'action': 'search', 'query': 'Synthetic site'})['entries'][0]['handle']
    assert broker.dispatch({'action': 'remove-url', 'handle': handle, 'url': SECURE,
                            'additional_urls_protocol': 1})['ok']
    # A successful vault write retires every pending generated reference.
    assert generated_fill(broker, staged['fill_handles']['password'], RESET) == {
        'ok': False, 'error': 'unknown or expired generated fill handle; start again'}
    # A metadata change (no broker write) refuses as a changed entry.
    add_secure_url(broker)
    staged = begin(broker, 'generate-password')
    [entry] = [e for e in broker.vault.entries if e.title == 'Synthetic site']
    entry.title = 'Renamed synthetic site'
    assert generated_fill(broker, staged['fill_handles']['password'], RESET) == {
        'ok': False, 'error': 'entry changed; search again'}
    assert not typer.events
    assert reopened_vault(path).find_entries(title='Synthetic site', first=True).password == OLD


def test_generate_entry_has_only_its_main_origin(deployed):
    broker, typer, _, _ = deployed
    add_secure_url(broker)  # another entry lists the origin; it grants nothing to a new entry
    staged = broker.dispatch({'action': 'generate-entry', 'metadata': {
        'title': 'New synthetic', 'username': 'new-account', 'url': 'https://example.test/signup', 'group': 'Web'}})
    assert generated_fill(broker, staged['fill_handles']['password'], RESET) == {
        'ok': False, 'error': 'target site mismatch; no password filled'}
    assert generated_fill(broker, staged['fill_handles']['confirmation'], 'https://example.test/signup')['ok']
    assert len(typer.events) == 1


def test_extension_route_generated_fill_on_additional_origin(deployed):
    from akdbx import extension_route as route
    from test_extension_route import Document, attach, pin_password
    broker, typer, path, _ = deployed
    add_secure_url(broker)
    staged = begin(broker, 'generate-password')
    channel, extension = attach(broker, {3: [Document('TOP', RESET)], 4: [Document('MAIN', 'https://example.test/reset')]})

    def fill(mode, tab, document, top, target_url):
        pin = pin_password(broker, channel, tab, document, top)
        assert pin['ok'], pin
        return broker.dispatch({'action': 'fill-generated', 'target': pin['target'], 'target_protocol': 1,
                                'handle': staged['fill_handles'][mode], 'target_url': target_url})

    # The pinned document is on the main origin, the asserted target on the additional one.
    assert fill('password', 4, 'MAIN', 'https://example.test/reset', RESET) == target_failure(False)
    assert extension.filled == []
    staged = begin(broker, 'generate-password')
    for mode in ('password', 'confirmation'):
        assert fill(mode, 3, 'TOP', RESET, RESET) == {'ok': True, 'filled': 'password',
                                                       'target_delivery': route.DELIVERY}
    assert len(extension.filled) == 2 and extension.filled[0] == extension.filled[1]
    assert commit(broker, staged) == {'ok': True, 'state': 'saved'}
    saved = reopened_vault(path).find_entries(title='Synthetic site', first=True)
    assert saved.password == extension.filled[0]['password'] and not typer.events
    # An unrelated origin is still refused on this route.
    staged = begin(broker, 'generate-password')
    channel2, extension2 = attach(broker, {5: [Document('EVIL', 'https://evil.test/password-reset')]})
    pin = pin_password(broker, channel2, 5, 'EVIL', 'https://evil.test/password-reset')
    assert broker.dispatch({'action': 'fill-generated', 'target': pin['target'], 'target_protocol': 1,
                            'handle': staged['fill_handles']['password'],
                            'target_url': 'https://evil.test/password-reset'}) == {
        'ok': False, 'error': 'target site mismatch; no password filled'}
    assert extension2.filled == []
