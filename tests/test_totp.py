"""Public RFC vectors and synthetic vaults/targets only; no live MFA is used."""
import base64
import json
import math
import stat
from urllib.parse import urlencode, urlsplit

import pytest

from akdbx import cli
from akdbx.broker import Broker
from akdbx.target import DeliveryError, failure
from akdbx.totp import (Configuration, TotpError, code_at, configured,
                        parse_setup, read_configuration)
from test_broker import Entry, RecordingTyper, Vault, running_broker, x11_target_request as target_request
from test_web_unlock import call
from test_writes import MASTER, OLD, begin, deployed, private_post, reopened, template


KEY = base64.b32encode(b'12345678901234567890').decode('ascii')
URI = 'otpauth://totp/Example:synthetic-account?secret=' + KEY + '&issuer=Example'


@pytest.mark.parametrize('timestamp,expected', [
    (59, ('94287082', '46119246', '90693936')),
    (1111111109, ('07081804', '68084774', '25091201')),
    (1111111111, ('14050471', '67062674', '99943326')),
    (1234567890, ('89005924', '91819424', '93441116')),
    (2000000000, ('69279037', '90698825', '38618901')),
    (20000000000, ('65353130', '77737706', '47863826')),
])
def test_rfc_6238_appendix_b_all_algorithms(timestamp, expected):
    for algorithm, length, code in zip(('SHA1', 'SHA256', 'SHA512'), (20, 32, 64), expected):
        secret = (b'1234567890' * 7)[:length]
        assert code_at(Configuration(secret, algorithm, 8), timestamp) == code


@pytest.mark.parametrize('timestamp', [-1, True, None, '59', math.inf, math.nan, 30 * 2**64])
def test_invalid_clock_is_rejected(timestamp):
    with pytest.raises(TotpError, match='invalid authenticator clock'):
        code_at(parse_setup(KEY), timestamp)


def test_manual_keys_uri_roundtrip_and_secret_free_repr():
    configuration = parse_setup(KEY.lower()[:8] + ' ' + KEY.lower()[8:], label='synthetic-account')
    assert code_at(configuration, 59) == '287082'
    assert configuration == parse_setup(configuration.uri())
    nondefault = parse_setup(URI + '&algorithm=SHA512&digits=8&period=60')
    assert (nondefault.algorithm, nondefault.digits, nondefault.period) == ('SHA512', 8, 60)
    assert nondefault == parse_setup(nondefault.uri())
    assert KEY not in repr(configuration) and '1234567890' not in repr(configuration)


@pytest.mark.parametrize('value', [
    '', None, 123, 'x' * 4097, '123456', 'abc!', 'JBSWY3DP', 'A' * 207,
    KEY + '=', KEY + '\n' + KEY, 'otpauth-migration://offline?data=synthetic',
    URI.replace('/totp/', '/hotp/'), URI.replace('://totp/', '://user@totp/'),
    URI + '#fragment', URI + '&secret=' + KEY, URI + '&algorithm=MD5',
    URI + '&algorithm=sha1', URI + '&digits=7', URI + '&period=0',
    URI + '&period=14', URI + '&period=121', URI + '&period=NaN',
    URI + '&period=30&period=60', URI + '&counter=1', URI + '&unexpected=value',
    URI.replace('Example:', 'Different:'), URI.replace('Example:', '%FF:'),
    URI.replace('Example:', 'Example%0A:'), URI.replace('Example:', 'Example%XX:'),
    'otpauth://totp/?secret=' + KEY,
])
def test_invalid_setup_has_fixed_secret_free_errors(value):
    with pytest.raises(TotpError) as result:
        parse_setup(value)
    assert str(result.value) == 'invalid TOTP setup; use a Base32 key or supported otpauth TOTP URI'


def prepare(broker, **extra):
    return begin(broker, 'setup-totp', **extra)


def post_setup(socket, prepared, setup=URI, confirmed='yes', **extra):
    parsed = urlsplit(prepared['private_url'])
    return call(socket, 'POST', parsed.path + '?' + parsed.query,
                urlencode(dict(setup=setup, confirmed=confirmed)), **extra)


def test_private_import_persists_protected_otp_preserves_entry_and_returns_no_secrets(deployed, capsys, caplog):
    broker, typer, path, socket = deployed
    before = path.read_bytes()
    prepared = prepare(broker)
    assert prepared['ok'] and prepared['state'] == 'pending'
    assert path.read_bytes() == before and not typer.events
    parsed = urlsplit(prepared['private_url'])
    code, headers, page = call(socket, 'GET', parsed.path + '?' + parsed.query)
    assert code == 200 and headers['Cache-Control'] == 'no-store'
    assert b'name="setup" type="password"' in page
    assert b'synthetic-account' in page and KEY.encode() not in page
    assert "frame-ancestors 'none'" in headers['Content-Security-Policy']
    assert post_setup(socket, prepared, identity=False)[0] == 404
    assert post_setup(socket, prepared, confirmed='no')[0] == 409
    assert path.read_bytes() == before
    code, headers, page = post_setup(socket, prepared)
    assert code == 200 and KEY.encode() not in page
    assert broker.dispatch(dict(action='write-status', write_handle=prepared['write_handle'])) == dict(ok=True, state='saved')
    assert post_setup(socket, prepared)[0] == 404
    vault = reopened(path)
    entry = vault.find_entries(title='Synthetic site', first=True)
    assert entry.password == OLD and entry.notes == 'preserve notes'
    assert entry.get_custom_property('custom') == 'preserve property'
    assert read_configuration(entry) == parse_setup(URI)
    assert entry._element.find('./String[Key="otp"]/Value').get('Protected') == 'True'
    assert entry.history[-1].otp is None
    assert vault.find_entries(title='Unrelated', first=True).password == 'synthetic-unrelated-secret'
    for item in [path, *path.parent.glob('.*.akdbx-backup-*')]:
        assert stat.S_IMODE(item.stat().st_mode) == 0o600
        assert KEY.encode() not in item.read_bytes()
    search = broker.dispatch(dict(action='search', query='Synthetic site'))
    assert search['entries'][0]['totp_configured'] is True
    assert KEY not in json.dumps(search) + json.dumps(prepared) + page.decode() + caplog.text
    assert capsys.readouterr() == ('', '')


def test_private_invalid_inputs_are_not_reflected_and_can_be_corrected(deployed):
    broker, _, path, socket = deployed
    before = path.read_bytes()
    prepared = prepare(broker)
    for value in (URI + '&secret=' + KEY, 'private-invalid-setup<unsafe>', URI + '&digits=7'):
        code, _, page = post_setup(socket, prepared, value)
        assert code == 409 and value.encode() not in page and KEY.encode() not in page
        assert path.read_bytes() == before
    assert post_setup(socket, prepared, KEY)[0] == 200


def test_setup_and_password_tokens_cannot_cross_routes(deployed):
    broker, _, path, socket = deployed
    prepared = prepare(broker)
    password = begin(broker)
    for source, wrong_route in ((prepared, '/write'), (password, '/totp')):
        query = urlsplit(source['private_url']).query
        for method in ('GET', 'POST'):
            assert call(socket, method, wrong_route + '?' + query, urlencode(dict(setup=URI, confirmed='yes')))[0] == 404
    parsed = urlsplit(prepared['private_url'])
    assert call(socket, 'POST', parsed.path + '?' + parsed.query,
                urlencode(dict(setup=URI, confirmed='yes', password='synthetic')))[0] == 400
    assert reopened(path).find_entries(title='Synthetic site', first=True).otp is None


@pytest.mark.parametrize('action', ['setup-totp', 'update-password'])
@pytest.mark.parametrize('status_action', ['write-status', 'cancel-write'])
def test_stale_private_links_refuse_forms_and_submissions(deployed, action, status_action):
    """A real competing save must retire both kinds of private input forms."""
    broker, _, path, socket = deployed
    prepared = begin(broker, action)
    parsed = urlsplit(prepared['private_url'])
    route = parsed.path + '?' + parsed.query
    assert call(socket, 'GET', route)[0] == 200
    winner = begin(broker)
    assert private_post(socket, winner)[0] == 200
    before = path.read_bytes()
    op = broker.writes.get(prepared['write_handle'])
    assert op.state == 'pending' and op.revision != broker.writes.revision
    body = urlencode(dict(setup=URI, confirmed='yes')) if action == 'setup-totp' else urlencode(
        dict(password='synthetic-rejected-password', confirmation='synthetic-rejected-password', confirmed='yes'))
    for method in ('GET', 'POST'):
        code, _, page = call(socket, method, route, body)
        assert code == 404 and b'<form' not in page
        assert KEY.encode() not in page and b'synthetic-rejected-password' not in page
    assert path.read_bytes() == before
    failed = dict(ok=True, state='failed', error='stale write; search and start again')
    for _ in range(2):
        assert broker.dispatch(dict(action=status_action, write_handle=prepared['write_handle'])) == failed
    assert broker.dispatch(dict(action='write-status', write_handle=winner['write_handle'])) == dict(ok=True, state='saved')
    assert path.read_bytes() == before
    fresh = begin(broker, action)
    assert broker.dispatch(dict(action='write-status', write_handle=fresh['write_handle'])) == dict(ok=True, state='pending')
    parsed = urlsplit(fresh['private_url'])
    code, _, page = call(socket, 'GET', parsed.path + '?' + parsed.query)
    assert code == 200 and b'<form' in page


@pytest.mark.parametrize('action', ['setup-totp', 'update-password'])
def test_private_post_rechecks_revision_after_reading_body(deployed, monkeypatch, action):
    """A revision change while reading a private POST must retire the link."""
    import akdbx.web_unlock as web_unlock
    broker, _, path, socket = deployed
    prepared = begin(broker, action)
    before = path.read_bytes()
    original = web_unlock.parse_qs

    def invalidate_during_body_parse(value, *args, **kwargs):
        values = original(value, *args, **kwargs)
        if 'confirmed' in values:
            with broker._vault_lock:
                broker.writes.invalidate_revision()
        return values

    monkeypatch.setattr(web_unlock, 'parse_qs', invalidate_during_body_parse)
    response = post_setup(socket, prepared) if action == 'setup-totp' else private_post(socket, prepared)
    assert response[0] == 404 and b'<form' not in response[2]
    assert path.read_bytes() == before


def test_replace_requires_explicit_intent_preserves_old_key_in_history(deployed):
    broker, _, path, socket = deployed
    assert post_setup(socket, prepare(broker))[0] == 200
    assert not prepare(broker)['ok']
    prepared = prepare(broker, replace=True)
    replacement = URI + '&algorithm=SHA256&digits=8&period=60'
    assert post_setup(socket, prepared, replacement)[0] == 200
    entry = reopened(path).find_entries(title='Synthetic site', first=True)
    assert read_configuration(entry).algorithm == 'SHA256'
    assert read_configuration(entry.history[-1]) == parse_setup(URI)
    assert entry.password == OLD


@pytest.mark.parametrize('reason', ['cancel', 'expire', 'stale', 'external', 'restart', 'close'])
def test_setup_refuses_stale_cancelled_expired_or_changed_vault(deployed, reason):
    broker, _, path, socket = deployed
    prepared = prepare(broker)
    before = path.read_bytes()
    if reason == 'cancel':
        broker.dispatch(dict(action='cancel-write', write_handle=prepared['write_handle']))
    elif reason == 'expire':
        broker.clock = lambda: math.inf
    elif reason == 'stale':
        broker.writes.invalidate_revision()
    elif reason == 'external':
        vault = reopened(path)
        vault.find_entries(title='Unrelated', first=True).notes = 'synthetic external change'
        vault.save()
        before = path.read_bytes()
    elif reason == 'restart':
        broker.writes.operations.clear()
    else:
        broker.writes.public_base = None
    assert post_setup(socket, prepared)[0] in (404, 409)
    assert path.read_bytes() == before


def test_reopened_field_verification_happens_before_replacement(deployed, monkeypatch):
    import akdbx.persistence as persistence
    broker, _, path, socket = deployed
    prepared = prepare(broker)
    before = path.read_bytes()
    original = persistence.open_encrypted

    def damaged(*args, **kwargs):
        vault = original(*args, **kwargs)
        vault.find_entries(title='Synthetic site', first=True).otp = 'synthetic-corruption'
        return vault

    monkeypatch.setattr(persistence, 'open_encrypted', damaged)
    assert post_setup(socket, prepared)[0] == 409
    assert path.read_bytes() == before
    assert not broker.vault.find_entries(title='Synthetic site', first=True).otp


@pytest.mark.parametrize('extra', [dict(setup=KEY), dict(secret=KEY), dict(otp=URI), dict(replace='true')])
def test_rpc_cannot_import_keys_or_silently_replace(deployed, extra):
    broker, typer, path, _ = deployed
    before = path.read_bytes()
    assert not prepare(broker, **extra)['ok']
    assert path.read_bytes() == before and not typer.events


def make_totp_broker(now=1111111111, values=None):
    class TotpEntry(Entry):
        @property
        def otp(self):
            return (values if values is not None else {'otp': URI}).get('otp')
        def get_custom_property(self, key):
            return (values or {}).get(key)
    typer = RecordingTyper()
    return Broker(Vault([TotpEntry()]), typer, wall_clock=lambda: now), typer


def totp_fill(broker, **changes):
    selected = broker.dispatch(dict(action='search'))['entries'][0]
    request = dict(action='fill-totp', handle=selected['handle'], target_url='https://example.com/challenge', **target_request(broker))
    request.update(changes)
    return broker.dispatch(request), request


def test_saved_totp_fill_receipt_and_single_use_handle_and_pin(capsys, caplog):
    broker, typer = make_totp_broker()
    result, request = totp_fill(broker)
    assert result == dict(ok=True, filled='totp', target_delivery='x11-send-event-v1')
    assert typer.events == [('type', '050471')]
    assert not broker.dispatch(request)['ok']
    assert not broker.dispatch({**request, 'handle': broker.dispatch(dict(action='search'))['entries'][0]['handle']})['ok']
    assert KEY not in json.dumps(result) and '050471' not in json.dumps(result)
    assert capsys.readouterr() == ('', '') and not caplog.records


@pytest.mark.parametrize('target', [None, '', 'http://example.com', 'https://attacker.test', 'https://example.com:444',
                                    'https://user@example.com', 'https://example.com\\@evil.test', 'https://exam\nple.com'])
def test_wrong_or_invalid_target_never_reads_setup_or_types(target):
    broker, typer = make_totp_broker(values={'otp': 'invalid-secret'})
    response, request = totp_fill(broker, target_url=target)
    assert not response['ok'] and 'TOTP configuration' not in response['error']
    assert not broker.dispatch({**request, 'target_url': 'https://example.com'})['ok']
    assert not typer.events


@pytest.mark.parametrize('values', [{}, {'otp': ''}, {'otp': KEY}, {'otp': URI + '&digits=7'}, {'otp': 'otpauth://hotp/a?secret=' + KEY}])
def test_missing_or_invalid_saved_setup_fails_without_leaking(values):
    broker, typer = make_totp_broker(values=values)
    response, _ = totp_fill(broker)
    assert not response['ok'] and KEY not in json.dumps(response)
    assert not typer.events


@pytest.mark.parametrize('data', [{}, dict(target='unknown', target_protocol=1), dict(target_protocol=True), dict(unrestricted=True)])
def test_totp_cannot_bypass_required_target_or_consume_same_handle_again(data):
    broker, typer = make_totp_broker()
    handle = broker.dispatch(dict(action='search'))['entries'][0]['handle']
    assert not broker.dispatch(dict(action='fill-totp', handle=handle, target_url='https://example.com', **data))['ok']
    assert not broker.dispatch(dict(action='fill-totp', handle=handle, target_url='https://example.com', **target_request(broker)))['ok']
    assert not typer.events


def test_near_expiry_returns_only_retry_time_and_does_not_sleep():
    broker, typer = make_totp_broker(now=59)
    response, request = totp_fill(broker)
    assert not response['ok'] and response['retry_after'] == 1
    assert not typer.events
    broker.wall_clock = lambda: 60
    assert not broker.dispatch(request)['ok']
    response, _ = totp_fill(broker)
    assert response['ok'] and typer.events == [('type', '359152')]


@pytest.mark.parametrize('started', [False, True])
def test_delivery_failures_do_not_leak_code_or_setup(started, capsys, caplog):
    broker, typer = make_totp_broker()
    def fail(*args, **kwargs):
        exception = DeliveryError(started)
        exception.args = (KEY + '050471',)
        raise exception
    typer.deliver = fail
    response, request = totp_fill(broker)
    assert response == failure(started)
    assert not broker.dispatch(request)['ok']
    assert capsys.readouterr() == ('', '') and not caplog.records


def test_delivery_ready_rechecks_wall_clock_before_start():
    broker, typer = make_totp_broker()
    def delayed(identity, steps, ready, *, guard=None):
        broker.wall_clock = lambda: 1111111140
        if not ready():
            raise DeliveryError(False)
        raise AssertionError('expired code must never be dispatched')
    typer.deliver = delayed
    assert totp_fill(broker)[0] == failure(False)


def test_totp_on_provider_identity_does_not_enable_password_fill():
    from akdbx.writes import SSO_MARKER, AUTH_METHOD
    broker, typer = make_totp_broker(values={'otp': URI, SSO_MARKER: 'v1', AUTH_METHOD: 'google'})
    assert totp_fill(broker)[0]['ok']
    handle = broker.dispatch(dict(action='search'))['entries'][0]['handle']
    assert not broker.dispatch(dict(action='fill', handle=handle, mode='password', **target_request(broker)))['ok']
    assert typer.events == [('type', '050471')]


def test_cli_private_setup_and_fill_over_real_rpc(deployed, tmp_path, capsys, monkeypatch):
    import secrets
    original = secrets.token_urlsafe
    # Force the random-token case that argparse treats as an option. Private
    # URL tokens may contain dashes; CLI authorization handles must remain safe.
    monkeypatch.setattr(secrets, 'token_urlsafe', lambda size: '-test-' + original(size))
    broker, typer, path, web_socket = deployed
    rpc_socket = tmp_path / 'rpc-private' / 'rpc.sock'
    prefix = ['--socket', str(rpc_socket), '--unlock-origin', 'https://node.example:9443']
    with running_broker(rpc_socket, broker):
        selected = broker.dispatch(dict(action='search', query='Synthetic site'))['entries'][0]
        metadata_args = [arg for key in ('title', 'username', 'url', 'group') for arg in ('--' + key, selected[key])]
        assert cli.main([*prefix, 'setup-totp', selected['handle'], *metadata_args]) == 0
        prepared = json.loads(capsys.readouterr().out)
        assert post_setup(web_socket, prepared)[0] == 200
        broker.wall_clock = lambda: 1111111111
        assert cli.main([*prefix, 'write-status', prepared['write_handle']]) == 0
        assert json.loads(capsys.readouterr().out) == dict(ok=True, state='saved')
        selected = broker.dispatch(dict(action='search', query='Synthetic site'))['entries'][0]
        pin = target_request(broker)['target']
        assert cli.main([*prefix, 'fill-totp', selected['handle'], '--target-url', 'https://example.test/challenge', '--target', pin]) == 0
        assert json.loads(capsys.readouterr().out) == dict(ok=True, filled='totp', target_delivery='x11-send-event-v1')
        assert typer.events == [('type', '050471')]
    assert read_configuration(reopened(path).find_entries(title='Synthetic site', first=True)) == parse_setup(URI)


@pytest.mark.parametrize('capabilities', [{}, dict(ok=True, totp_supported=True, totp_protocol=True),
                                         dict(ok=True, totp_supported=False, totp_protocol=1)])
@pytest.mark.parametrize('command', ['fill-totp', 'setup-totp'])
def test_cli_refuses_old_or_incompatible_broker_before_sending(monkeypatch, capsys, capabilities, command):
    sent = []
    def request(*args, **kwargs):
        sent.append(args[1])
        return capabilities
    monkeypatch.setattr(cli, 'request', request)
    args = [command, 'synthetic-handle']
    if command == 'fill-totp':
        args += ['--target-url', 'https://example.test', '--target', 'synthetic-pin']
    else:
        args += ['--title', 'Synthetic', '--username', 'synthetic', '--url', 'https://example.test', '--group', 'Web']
    assert cli.main(args) == 1
    assert sent == [dict(action='ping')]
    assert 'not sent' in capsys.readouterr().out


def test_cli_refuses_unexpected_secret_fields_in_receipt(monkeypatch, capsys):
    responses = iter([dict(ok=True, totp_supported=True, totp_protocol=1),
                      dict(ok=True, target_fill_required=True, target_fill_protocol=1, target_fill_delivery='x11-send-event-v1'),
                      dict(ok=True, filled='totp', target_delivery='x11-send-event-v1', code='050471', secret=KEY)])
    monkeypatch.setattr(cli, 'request', lambda *a, **kw: next(responses))
    assert cli.main(['fill-totp', 'synthetic-handle', '--target-url', 'https://example.test', '--target', 'synthetic-pin']) == 2
    captured = capsys.readouterr()
    assert '050471' not in captured.out + captured.err and KEY not in captured.out + captured.err


def test_fill_totp_disconnect_never_types():
    broker, typer = make_totp_broker()
    handle = broker.dispatch(dict(action='search'))['entries'][0]['handle']
    response = broker.dispatch(dict(action='fill-totp', handle=handle, target_url='https://example.com', **target_request(broker)), delivery_ready=lambda: False)
    assert not response['ok'] and not typer.events


def test_locked_totp_commands_do_not_touch_credentials():
    broker = Broker(None, object())
    for action in ('fill-totp', 'setup-totp'):
        assert broker.dispatch(dict(action=action)) == dict(ok=False, error='vault locked')


@pytest.mark.parametrize('saved,target', [('https://fass.test/login', 'https://faß.test/challenge'),
                                         ('https://faß.test/login', 'https://fass.test/challenge')])
def test_unicode_origin_collision_refused_before_reading_key(saved, target):
    class UnreadableOtp(Entry):
        @property
        def otp(self):
            raise AssertionError('key must not be read for an ambiguous origin')
    entry = UnreadableOtp(url=saved)
    typer = RecordingTyper()
    broker = Broker(Vault([entry]), typer)
    handle = broker._new_handle(entry)
    response = broker.dispatch(dict(action='fill-totp', handle=handle, target_url=target, **target_request(broker)))
    assert not response['ok'] and 'ASCII HTTPS' in response['error'] and not typer.events


def test_ascii_punycode_origin_is_supported_without_collapsing_other_sites():
    from akdbx.totp import https_origin
    assert https_origin('https://xn--fa-hia.test/challenge') != https_origin('https://fass.test/challenge')


def test_import_and_same_second_replacement_advance_merge_timestamps(deployed, monkeypatch):
    import akdbx.writes as writes
    from akdbx.merge import _check_ambiguity
    broker, _, path, socket = deployed
    original = reopened(path).find_entries(title='Synthetic site', first=True).mtime
    now = [original.timestamp() + 1]
    broker.wall_clock = lambda: now[0]
    waited = []
    def advance_clock(delay):
        waited.append(delay)
        now[0] += 1
    monkeypatch.setattr(writes, 'sleep', advance_clock)
    assert post_setup(socket, prepare(broker))[0] == 200
    first = reopened(path).find_entries(title='Synthetic site', first=True)
    assert first.mtime > original and first.history[-1].mtime == original
    assert first.mtime.timestamp() <= now[0] and not waited
    _check_ambiguity(broker.vault)
    assert post_setup(socket, prepare(broker, replace=True), URI + '&digits=8')[0] == 200
    second = reopened(path).find_entries(title='Synthetic site', first=True)
    assert second.mtime > first.mtime and second.history[-1].mtime == first.mtime
    assert second.mtime.timestamp() <= now[0] and waited == [0.05]
    _check_ambiguity(broker.vault)


@pytest.mark.parametrize('future_in', ['active', 'history'])
def test_future_timestamp_refuses_import_and_preserves_encrypted_vault(deployed, future_in):
    from datetime import timedelta
    from lxml.etree import tostring
    from akdbx.broker import open_vault_with_password
    broker, typer, path, socket = deployed
    vault = reopened(path)
    entry = vault.find_entries(title='Synthetic site', first=True)
    now = entry.mtime
    entry.mtime = now + timedelta(days=365)
    if future_in == 'history':
        entry.save_history()
        entry.mtime = now - timedelta(days=1)
    vault.save()
    broker.vault = open_vault_with_password(path, MASTER)
    broker.wall_clock = lambda: now.timestamp()
    before = path.read_bytes()
    history = [tostring(version._element)
               for version in broker.vault.find_entries(title='Synthetic site', first=True).history]
    prepared = prepare(broker)
    code, _, page = post_setup(socket, prepared)
    assert code == 409 and b'future-dated' in page and KEY.encode() not in page
    assert path.read_bytes() == before and not typer.events
    current = reopened(path).find_entries(title='Synthetic site', first=True)
    assert current.otp is None and current.password == OLD
    assert [tostring(version._element) for version in current.history] == history
    assert broker.dispatch(dict(action='write-status', write_handle=prepared['write_handle']))['state'] == 'failed'


@pytest.mark.parametrize('clock_behavior', ['frozen', 'backward'])
def test_nonadvancing_clock_refuses_import_without_timestamp_changes(deployed, monkeypatch, clock_behavior):
    import akdbx.writes as writes
    broker, typer, path, socket = deployed
    timestamp = broker.vault.find_entries(title='Synthetic site', first=True).mtime.timestamp()
    current = [timestamp]
    broker.wall_clock = lambda: current[0]
    ticks = iter([0, 0, 2])
    monkeypatch.setattr(writes, 'monotonic', lambda: next(ticks))
    monkeypatch.setattr(writes, 'sleep', lambda delay: current.__setitem__(0, timestamp - (1 if clock_behavior == 'backward' else 0)))
    before = path.read_bytes()
    code, _, page = post_setup(socket, prepare(broker))
    assert code == 409 and KEY.encode() not in page
    assert (b'future-dated' if clock_behavior == 'backward' else b'clock did not advance') in page
    assert path.read_bytes() == before and not typer.events


@pytest.mark.parametrize('switch_after', [1, 6, 'close'])
def test_production_transport_refuses_expiry_during_and_after_dispatch(switch_after):
    from test_target import Session, session_typer
    from akdbx.target import TargetPins
    broker, _ = make_totp_broker()
    session = Session(123, 456)
    production = session_typer(session)
    broker.typer = production
    broker.targets = TargetPins(production, broker.clock)
    def change_clock(current):
        if len(current.sent) == switch_after:
            broker.wall_clock = lambda: 1111111140
    session.after_send = change_clock
    original_close = session.close
    def close():
        if switch_after == 'close' and session.sent:
            broker.wall_clock = lambda: 1111111140
        original_close()
    session.close = close
    response, _ = totp_fill(broker)
    assert response == failure(True)
    assert len(session.sent) == (switch_after if isinstance(switch_after, int) else 6)
    assert session.closed


@pytest.mark.parametrize('started', [False, True])
def test_cli_preserves_valid_totp_delivery_failure_state(monkeypatch, capsys, started):
    responses = iter([dict(ok=True, totp_supported=True, totp_protocol=1),
                      dict(ok=True, target_fill_required=True, target_fill_protocol=1, target_fill_delivery='x11-send-event-v1'),
                      failure(started)])
    monkeypatch.setattr(cli, 'request', lambda *a, **kw: next(responses))
    assert cli.main(['fill-totp', 'synthetic-handle', '--target-url', 'https://example.test', '--target', 'synthetic-pin']) == 1
    captured = capsys.readouterr()
    assert json.loads(captured.out) == failure(started) and not captured.err


@pytest.mark.parametrize('extra', [dict(delivery='unexpected-private-value'), dict(delivery={}),
                                 dict(retry_after=True), dict(retry_after=0), dict(retry_after=121)])
def test_cli_rejects_invalid_totp_error_values(monkeypatch, capsys, extra):
    responses = iter([dict(ok=True, totp_supported=True, totp_protocol=1),
                      dict(ok=True, target_fill_required=True, target_fill_protocol=1, target_fill_delivery='x11-send-event-v1'),
                      dict(ok=False, error='synthetic failure', **extra)])
    monkeypatch.setattr(cli, 'request', lambda *a, **kw: next(responses))
    assert cli.main(['fill-totp', 'synthetic-handle', '--target-url', 'https://example.test', '--target', 'synthetic-pin']) == 2
    captured = capsys.readouterr()
    assert not captured.out and 'unexpected-private-value' not in captured.err
