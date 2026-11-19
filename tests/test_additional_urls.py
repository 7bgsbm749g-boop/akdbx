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
