"""deliver-secret and the sink writer, with synthetic secrets and temporary sinks only."""
import json
import logging
import os
import pwd
import grp
import secrets
import socket
import stat
import sys

import pytest
from pykeepass import PyKeePass

from akdbx import cli, sink_helper
from akdbx.secrets_capture import CAPTURED_FIELDS, HELPER_ERRORS, SecretCaptures
from akdbx.sink_helper import SinkError, load_config, render, serve_connection, write_sink
from test_writes import MASTER, deployed, template  # noqa: F401  (fixtures)

VALUE = 'SynthSink-' + secrets.token_hex(16)
USER = pwd.getpwuid(os.getuid()).pw_name
GROUP = grp.getgrgid(os.getgid()).gr_name
ORIGIN = 'https://login.example.com'


def sink_definition(target, **changes):
    value = dict(writer='direct', field='client_secret', entry_origin=ORIGIN, path=str(target), key='APP_CLIENT_SECRET',
                 owner=USER, group=GROUP, mode='0600')
    value.update(changes)
    return value


def write_config(directory, sinks, **extra):
    path = directory / 'sinks.json'
    path.write_text(json.dumps(dict(version=1, sinks=sinks, **extra)))
    path.chmod(0o600)
    return path


def sink(tmp_path, **changes):
    directory = tmp_path / 'svc'
    directory.mkdir(mode=0o700, exist_ok=True)
    config = load_config(str(write_config(tmp_path, {'app-env': sink_definition(directory / 'app.env', **changes)})),
                         {os.getuid()})
    return config['sinks']['app-env'], directory / 'app.env'


# ---- sink writer --------------------------------------------------------

def test_write_keeps_other_lines_replaces_key_and_is_atomic(tmp_path):
    definition, path = sink(tmp_path)
    path.write_text('PORT=8080\n# comment\nAPP_CLIENT_SECRET=old\nGITHUB_CLIENT_ID=abc')
    path.chmod(0o644)
    assert write_sink(definition, VALUE) is True
    assert path.read_text() == f'PORT=8080\n# comment\nAPP_CLIENT_SECRET={VALUE}\nGITHUB_CLIENT_ID=abc'
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert write_sink(definition, VALUE) is False  # Unchanged content is not rewritten.
    path.chmod(0o644)
    assert write_sink(definition, VALUE) is True  # A wrong mode is repaired even for the same value.
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert sorted(p.name for p in path.parent.iterdir()) == ['app.env']  # No temporary file left.


def test_write_appends_missing_key_and_creates_missing_file(tmp_path):
    definition, path = sink(tmp_path)
    assert write_sink(definition, VALUE) is True
    assert path.read_text() == f'APP_CLIENT_SECRET={VALUE}\n'
    path.write_text('PORT=1')
    assert write_sink(definition, VALUE) is True
    assert path.read_text() == f'PORT=1\nAPP_CLIENT_SECRET={VALUE}\n'
    assert render(b'export APP_CLIENT_SECRET=x\n', 'APP_CLIENT_SECRET', 'y') == b'export APP_CLIENT_SECRET=y\n'
    # U+2028 is not a line break for env-file consumers: no false assignment inside OTHER.
    assert render('OTHER=a\u2028APP_CLIENT_SECRET=x\n'.encode(), 'APP_CLIENT_SECRET', 'y') == \
        'OTHER=a\u2028APP_CLIENT_SECRET=x\nAPP_CLIENT_SECRET=y\n'.encode()
    assert render(b'APP_CLIENT_SECRET_OLD=x\n', 'APP_CLIENT_SECRET', 'y') == b'APP_CLIENT_SECRET_OLD=x\nAPP_CLIENT_SECRET=y\n'


def test_path_tricks_refuse_without_writing(tmp_path):
    definition, path = sink(tmp_path)
    outside = tmp_path / 'outside.env'
    outside.write_text('KEEP=1\n')
    path.symlink_to(outside)                      # Final component is a symlink.
    with pytest.raises(SinkError):
        write_sink(definition, VALUE)
    path.unlink()
    os.link(outside, path)                        # Hard link to another file.
    with pytest.raises(SinkError):
        write_sink(definition, VALUE)
    path.unlink()
    real = tmp_path / 'real'
    real.mkdir(mode=0o700)
    linked = tmp_path / 'linked'
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(SinkError):               # A symlinked parent directory.
        write_sink(dict(definition, path=str(linked / 'app.env')), VALUE)
    open_dir = tmp_path / 'open'
    open_dir.mkdir()
    open_dir.chmod(0o777)
    with pytest.raises(SinkError):               # Others can write the directory.
        write_sink(dict(definition, path=str(open_dir / 'app.env')), VALUE)
    assert outside.read_text() == 'KEEP=1\n' and not (real / 'app.env').exists() and not (open_dir / 'app.env').exists()


@pytest.mark.parametrize('content', [b'APP_CLIENT_SECRET=a\nAPP_CLIENT_SECRET=b\n', b'\xff\xfe', b'A=1\r\n',
                                     b'NOTE="first\nAPP_CLIENT_SECRET=inside a quoted value"\n', b"A='x\nB=y'\n", b'A=x \\\n'])
def test_ambiguous_or_unusual_files_refuse(tmp_path, content):
    definition, path = sink(tmp_path)
    path.write_bytes(content)
    with pytest.raises(SinkError):
        write_sink(definition, VALUE)
    assert path.read_bytes() == content


@pytest.mark.parametrize('value', ['', '~/token', 'a:~/b', 'a b', 'a\nb', 'a"b', "a'b", 'a$b', 'a#b', 'a`b', 'a\\b', 'x' * 4097, 'é'])
def test_values_that_need_quoting_refuse(tmp_path, value):
    definition, path = sink(tmp_path)
    with pytest.raises(SinkError) as error:
        write_sink(definition, value)
    assert not path.exists() and value not in str(error.value) or value == ''


@pytest.mark.parametrize('name,change', [
    ('../evil', {}), ('UPPER', {}), ('ok', dict(path='relative/app.env')), ('ok', dict(path='/tmp/../etc/passwd')),
    ('ok', dict(path='/tmp/x/')), ('ok', dict(key='BAD KEY')), ('ok', dict(mode='0666')), ('ok', dict(mode='4600')),
    ('ok', dict(mode='0400')), ('ok', dict(writer='sudo')), ('ok', dict(entry_origin='http://login.example.com')),
    ('ok', dict(field='Password')), ('ok', dict(restart=dict(argv=['systemctl', 'restart', 'x']))),
    ('ok', dict(restart=dict(argv=['/bin/true'], env={'PATH': '/tmp'}))), ('ok', dict(extra=1)),
])
def test_invalid_sink_definitions_refuse(tmp_path, name, change):
    if change.get('field') == 'Password':
        change['field'] = 'Pass word'
    path = write_config(tmp_path, {name: sink_definition(tmp_path / 'app.env', **change)})
    with pytest.raises(SinkError):
        load_config(str(path), {os.getuid()})


def test_untrusted_configuration_files_refuse(tmp_path):
    path = write_config(tmp_path, {'app-env': sink_definition(tmp_path / 'app.env')})
    path.chmod(0o622)
    with pytest.raises(SinkError):
        load_config(str(path), {os.getuid()})
    path.chmod(0o600)
    link = tmp_path / 'link.json'
    link.symlink_to(path)
    with pytest.raises(SinkError):
        load_config(str(link), {os.getuid()})
    with pytest.raises(SinkError):               # Only root may own a root-helper configuration.
        load_config(str(path), {0})
    root_helper = write_config(tmp_path, {'app-env': sink_definition(tmp_path / 'app.env', writer='root-helper')})
    with pytest.raises(SinkError):               # root-helper sinks need a helper socket.
        load_config(str(root_helper), {os.getuid()})


def test_quotes_or_backslashes_anywhere_refuse(tmp_path):
    definition, path = sink(tmp_path)
    # An escaped quote plus a quote in a comment balances naive quote counts.
    content = 'OTHER="a \\" # \'\nAPP_CLIENT_SECRET=old\n" # \'\nPORT=1\n'
    for text in (content, "# don't edit\nA=1\n", 'A=1 \\\n'):
        path.write_text(text)
        with pytest.raises(SinkError):
            write_sink(definition, VALUE)
        assert path.read_text() == text


def test_writable_ancestor_directory_refuses(tmp_path):
    shared = tmp_path / 'shared'
    shared.mkdir()
    shared.chmod(0o777)  # Another account could rename the inner directory.
    inner = shared / 'svc'
    inner.mkdir(mode=0o700)
    definition, _ = sink(tmp_path)
    with pytest.raises(SinkError):
        write_sink(dict(definition, path=str(inner / 'app.env')), VALUE)
    assert not (inner / 'app.env').exists()


def test_root_helper_never_restarts_as_root(tmp_path, monkeypatch):
    definition, _ = sink(tmp_path, restart=dict(user='root', argv=['/bin/true']))
    monkeypatch.setattr(sink_helper.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(sink_helper.subprocess, 'run', lambda argv, **kw: pytest.fail('ran ' + repr(argv)))
    with pytest.raises(SinkError):
        sink_helper.restart(definition)
    with pytest.raises(SinkError):  # Refused before the value is written.
        sink_helper.deliver(definition, VALUE)
    assert not (tmp_path / 'svc' / 'app.env').exists()
    monkeypatch.setattr(sink_helper.pwd if hasattr(sink_helper, 'pwd') else __import__('pwd'), 'getpwnam',
                        lambda name: type('P', (), {'pw_uid': 0 if name == 'toor' else os.getuid(), 'pw_gid': os.getgid()})())
    with pytest.raises(SinkError):  # A UID 0 alias is root too.
        sink_helper.restart(dict(definition, restart=dict(definition['restart'], user='toor')))
    ran = []
    monkeypatch.setattr(sink_helper.subprocess, 'run', lambda argv, **kw: ran.append(argv) or
                        type('R', (), {'returncode': 0})())
    assert sink_helper.restart(dict(definition, restart=dict(definition['restart'], user=None))) is True
    assert ran == [[sink_helper.RUNUSER, '-u', USER, '--', '/usr/bin/env', '-i', 'PATH=' + sink_helper.SAFE_PATH,
                    '/bin/true']]  # Defaults to the sink owner; env applies only after the switch.
    ran.clear()
    loader = dict(definition, restart=dict(definition['restart'], user=None, env={'LD_PRELOAD': '/tmp/x.so'}))
    environments = []
    monkeypatch.setattr(sink_helper.subprocess, 'run', lambda argv, **kw: ran.append(argv) or environments.append(kw['env'])
                        or type('R', (), {'returncode': 0})())
    assert sink_helper.restart(loader) is True
    assert environments == [{'PATH': sink_helper.SAFE_PATH}] and ran[0][-2:] == ['LD_PRELOAD=/tmp/x.so', '/bin/true']


def test_restart_command_runs_with_fixed_argv_and_environment(tmp_path):
    marker = tmp_path / 'restarted'
    definition, path = sink(tmp_path, restart=dict(argv=['/bin/sh', '-c', 'printf %s "$MARK" > "$OUT"'],
                                                    env=dict(MARK='restarted', OUT=str(marker))))
    assert sink_helper.deliver(definition, VALUE) == dict(restarted=True)
    assert marker.read_text() == 'restarted'
    failing, _ = sink(tmp_path, restart=dict(argv=['/bin/false']))
    assert sink_helper.deliver(failing, VALUE) == dict(restarted=False)
    plain, _ = sink(tmp_path)
    assert sink_helper.deliver(plain, VALUE) == dict(restarted=None)


def test_root_helper_protocol_checks_peer_sink_and_field(tmp_path):
    directory = tmp_path / 'svc'
    directory.mkdir(mode=0o700)
    config = load_config(str(write_config(tmp_path, {
        'app-env': sink_definition(directory / 'app.env', writer='root-helper'),
        'direct-env': sink_definition(directory / 'other.env')}, helper_socket='/run/akdbx-test.sock',
        broker_uids=[os.getuid()])), {os.getuid()})

    def exchange(request, cfg=config):
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with server, client:
            client.sendall(json.dumps(request).encode() + b'\n')
            client.shutdown(socket.SHUT_WR)
            serve_connection(server, cfg)
            server.shutdown(socket.SHUT_WR)
            return json.loads(client.recv(4096))

    good = dict(sink_protocol=1, sink='app-env', field='client_secret', value=VALUE,
                sink_digest=sink_helper.sink_digest(config['sinks']['app-env']))
    assert exchange(good) == dict(ok=True, restarted=None)
    assert (directory / 'app.env').read_text() == f'APP_CLIENT_SECRET={VALUE}\n'
    for bad in (dict(good, sink='../app-env'), dict(good, sink='direct-env'), dict(good, sink='missing'),
                dict(good, field='other'), dict(good, sink_protocol=2), dict(good, extra=1), dict(good, value='a b'),
                dict(good, sink_digest='0' * 64)):  # The definition the broker authorized changed.
        reply = exchange(bad)
        assert reply['ok'] is False and VALUE not in json.dumps(reply)
    assert not (directory / 'other.env').exists()
    assert exchange(good, dict(config, broker_uids={os.getuid() + 1}))['ok'] is False


# ---- broker capture save and deliver-secret -----------------------------

class FakeReadPin:
    mode = 'read'

    def close(self):
        pass


def configured(broker, tmp_path, **changes):
    directory = tmp_path / 'svc'
    directory.mkdir(mode=0o700, exist_ok=True)
    sinks = {'app-env': sink_definition(directory / 'app.env', **changes)}
    broker.secrets = SecretCaptures(broker, write_config(tmp_path, sinks))
    return directory / 'app.env'


def fake_capture(broker, monkeypatch, value=VALUE, url=ORIGIN + '/apps/1', title='Synthetic OAuth app'):
    monkeypatch.setattr(broker.passwords, 'consume', lambda token: FakeReadPin())
    monkeypatch.setattr(broker.passwords, 'read', lambda pin, origins, ready, deadline: value)
    metadata = dict(title=title, username='synthetic-client-id', url=url, group='Web')
    return broker.dispatch(dict(action='capture-secret', capture_protocol=1, target='t' * 64, field='client_secret',
                                metadata=metadata, create=True))


def handle(broker, query='Synthetic OAuth'):
    return broker.dispatch(dict(action='search', query=query))['entries'][0]['handle']


def deliver(broker, handle_value, sink='app-env', field='client_secret'):
    return broker.dispatch(dict(action='deliver-secret', sink_protocol=1, sink=sink, field=field, handle=handle_value))


def test_capture_save_then_deliver_writes_only_the_configured_sink(deployed, tmp_path, monkeypatch, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    broker, _, path, _ = deployed
    target = configured(broker, tmp_path)
    saved = fake_capture(broker, monkeypatch)
    assert saved['ok'] and saved['length'] == len(VALUE), saved
    entry = PyKeePass(str(path), password=MASTER).find_entries(title='Synthetic OAuth app', first=True)
    assert entry.get_custom_property('client_secret') == VALUE and entry.is_custom_property_protected('client_secret')
    assert entry.get_custom_property(CAPTURED_FIELDS) == 'client_secret' and entry.password in ('', None)
    status = broker.dispatch(dict(action='ping'))
    assert status['secret_sinks'] == ['app-env'] and status['secret_sink_protocol'] == 1
    receipt = deliver(broker, handle(broker))
    assert receipt == dict(ok=True, state='delivered', sink='app-env', field='client_secret', restarted=None)
    assert target.read_text() == f'APP_CLIENT_SECRET={VALUE}\n'
    assert deliver(broker, handle(broker))['ok'] and target.read_text() == f'APP_CLIENT_SECRET={VALUE}\n'
    out = capsys.readouterr()
    assert VALUE not in json.dumps([saved, status, receipt]) + out.out + out.err + caplog.text


def test_deliver_refusals_write_nothing_and_consume_the_handle(deployed, tmp_path, monkeypatch):
    broker, _, _, _ = deployed
    target = configured(broker, tmp_path)
    assert fake_capture(broker, monkeypatch)['ok']
    assert fake_capture(broker, monkeypatch, url='https://other.example.org/x', title='Other origin')['ok']
    responses = []
    for sink, field, query in [('missing', 'client_secret', 'Synthetic OAuth'), ('../app-env', 'client_secret', 'Synthetic OAuth'),
                               ('/etc/passwd', 'client_secret', 'Synthetic OAuth'), ('app-env', 'other', 'Synthetic OAuth'),
                               ('app-env', 'client_secret', 'Other origin'), ('app-env', 'client_secret', 'Synthetic site')]:
        selected = handle(broker, query)
        responses.append(deliver(broker, selected, sink, field))
        assert responses[-1]['ok'] is False, (sink, field, query)
        assert deliver(broker, selected)['error'] == 'unknown or expired handle; search again'
    assert not target.exists() and VALUE not in json.dumps(responses)
    request = dict(action='deliver-secret', sink_protocol=1, sink='app-env', field='client_secret', handle=handle(broker))
    assert broker.dispatch(dict(request, path='/tmp/x'))['ok'] is False
    assert broker.dispatch(dict(request, sink_protocol=2))['ok'] is False
    assert not target.exists()


def test_protected_or_phantom_marker_names_are_not_listed(deployed):
    broker, _, _, _ = deployed

    def mutate(candidate):
        entry = candidate.find_entries(title='Synthetic site', first=True)
        entry.set_custom_property(CAPTURED_FIELDS, 'hiddenvalue', protect=True)
        other = candidate.find_entries(title='Unrelated', first=True)
        other.set_custom_property(CAPTURED_FIELDS, 'missingfield')
    broker.vault = broker.vault._akdbx_store.commit(broker.vault, mutate)
    found = json.dumps(broker.dispatch(dict(action='search', query='')))
    assert 'hiddenvalue' not in found and 'missingfield' not in found and 'captured_fields' not in found


def test_capture_refuses_a_protected_marker_without_changing_it(deployed, monkeypatch):
    broker, _, path, _ = deployed
    broker.vault = broker.vault._akdbx_store.commit(broker.vault, lambda c: c.find_entries(
        title='Synthetic site', first=True).set_custom_property(CAPTURED_FIELDS, 'keepme', protect=True))
    before = path.read_bytes()
    selected = broker.dispatch(dict(action='search', query='Synthetic site'))['entries'][0]
    monkeypatch.setattr(broker.passwords, 'consume', lambda token: FakeReadPin())
    monkeypatch.setattr(broker.passwords, 'read', lambda *a: pytest.fail('read before refusal'))
    result = broker.dispatch(dict(action='capture-secret', capture_protocol=1, target='t' * 64, field='client_secret',
                                  handle=selected['handle'],
                                  metadata={k: selected[k] for k in ('title', 'username', 'url', 'group')}))
    assert result['ok'] is False and 'protected' in result['error'] and path.read_bytes() == before


def test_unprotected_or_uncaptured_fields_are_not_deliverable(deployed, tmp_path, monkeypatch):
    broker, _, _, _ = deployed
    target = configured(broker, tmp_path, entry_origin='https://example.test')

    def mutate(candidate):
        entry = candidate.find_entries(title='Synthetic site', first=True)
        entry.set_custom_property('client_secret', VALUE, protect=False)
        entry.set_custom_property(CAPTURED_FIELDS, 'client_secret')
    broker.vault = broker.vault._akdbx_store.commit(broker.vault, mutate)
    assert deliver(broker, handle(broker, 'Synthetic site'))['ok'] is False
    broker.vault = broker.vault._akdbx_store.commit(broker.vault, lambda c: c.find_entries(
        title='Synthetic site', first=True).set_custom_property(CAPTURED_FIELDS, 'other'))
    assert deliver(broker, handle(broker, 'Synthetic site'))['ok'] is False
    assert not target.exists()


@pytest.mark.parametrize('value', ['', 'two words', 'line\nbreak', 'x' * 4097, 'tab\there', 'zero​width'])
def test_capture_refuses_invalid_values_without_saving(deployed, tmp_path, monkeypatch, value):
    broker, _, path, _ = deployed
    before = path.read_bytes()
    result = fake_capture(broker, monkeypatch, value=value)
    assert result['ok'] is False and 'nothing saved' in result['error']
    assert path.read_bytes() == before


@pytest.mark.parametrize('field', ['Password', 'password', 'URL', 'otp', 'akdbx.card', 'KP2A_URL', 'TOTP_Seed', 'a b', '', '1x'])
def test_capture_refuses_reserved_field_names(deployed, monkeypatch, field):
    broker, _, path, _ = deployed
    monkeypatch.setattr(broker.passwords, 'consume', lambda token: FakeReadPin())
    monkeypatch.setattr(broker.passwords, 'read', lambda *a: pytest.fail('read before validation'))
    result = broker.dispatch(dict(action='capture-secret', capture_protocol=1, target='t' * 64, field=field, create=True,
                                  metadata=dict(title='T', username='u', url=ORIGIN + '/', group='Web')))
    assert result['ok'] is False


def test_helper_socket_must_be_root_owned_before_any_value_is_sent(tmp_path, deployed, monkeypatch):
    broker, _, _, _ = deployed
    fake = tmp_path / 'fake.sock'
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(fake))
    listener.listen(1)
    try:
        broker.secrets.config = dict(helper_socket=str(fake), broker_uids=set(), sinks={
            'app-env': sink_helper.validate_sink('app-env', sink_definition(tmp_path / 'x.env', writer='root-helper'))})
        assert fake_capture(broker, monkeypatch)['ok']
        result = deliver(broker, handle(broker))
        assert result['ok'] is False and 'root' in result['error']
        assert 'sink file is not a regular file' in HELPER_ERRORS and 'caller is not an allowed broker' in HELPER_ERRORS
        listener.settimeout(0.2)
        with pytest.raises(OSError):
            listener.accept()  # Nothing ever connected, so no value was sent.
    finally:
        listener.close()


# ---- CLI ----------------------------------------------------------------

def caps(**changes):
    value = dict(ok=True, locked=False, secret_capture_protocol=1, secret_capture_delivery='chromium-dom-read-v1',
                 password_fill_protocol=1, password_fill_delivery='chromium-password-dom-v1',
                 secret_sink_protocol=1, secret_sinks=['app-env'])
    value.update(changes)
    return value


@pytest.mark.parametrize('capabilities', [caps(secret_sink_protocol=None), caps(secret_sinks=None), caps(secret_sinks=[])])
def test_cli_deliver_sends_nothing_without_capability_or_sink(monkeypatch, capsys, capabilities):
    calls = []
    monkeypatch.setattr(cli, 'request', lambda socket, payload, **kw: calls.append(payload) or capabilities)
    assert cli.main(['deliver-secret', '--sink', 'app-env', '--field', 'client_secret', 'H']) == 1
    assert calls == [{'action': 'ping'}]


@pytest.mark.parametrize('argv', [['--sink', '../x'], ['--sink', '/etc/passwd'], ['--sink', 'app-env', '--field', 'Password']])
def test_cli_deliver_refuses_bad_names_before_connecting(monkeypatch, capsys, argv):
    monkeypatch.setattr(cli, 'request', lambda *a, **k: pytest.fail('request sent'))
    if '--field' not in argv:
        argv = [*argv, '--field', 'client_secret']
    assert cli.main(['deliver-secret', *argv, 'H']) == 2


def test_cli_withholds_receipts_with_unexpected_fields(monkeypatch, capsys):
    replies = iter([caps(), dict(ok=True, state='delivered', sink='app-env', field='client_secret',
                                 restarted=None, value=VALUE)])
    monkeypatch.setattr(cli, 'request', lambda *a, **k: next(replies))
    assert cli.main(['deliver-secret', '--sink', 'app-env', '--field', 'client_secret', 'H']) == 2
    out = capsys.readouterr()
    assert VALUE not in out.out + out.err and 'withheld' in out.err
    replies = iter([caps(), dict(ok=True, state='saved', created=True, field='client_secret', length=3,
                                 metadata=dict(title='T', username='u', url=ORIGIN + '/', group='Web'),
                                 capture_delivery='chromium-dom-read-v1', value=VALUE)])
    monkeypatch.setattr(cli, 'request', lambda *a, **k: next(replies))
    assert cli.main(['capture-secret', '--target', 'T', '--field', 'client_secret', '--new', '--title', 'T',
                     '--username', 'u', '--url', ORIGIN + '/', '--group', 'Web']) == 2
    out = capsys.readouterr()
    assert VALUE not in out.out + out.err


def test_cli_sends_exact_payloads(monkeypatch, capsys):
    calls = []
    def rpc(socket, payload, **kw):
        calls.append(payload)
        if payload['action'] == 'ping':
            return caps()
        if payload['action'] == 'deliver-secret':
            return dict(ok=True, state='delivered', sink='app-env', field='client_secret', restarted=True)
        if payload['action'] == 'pin-password-target':
            return dict(ok=True, target='a' * 64, expires_in=30, target_delivery='chromium-password-dom-v1')
        return dict(ok=True, state='saved', created=False, field='client_secret', length=40, metadata=payload['metadata'],
                    capture_delivery='chromium-dom-read-v1')
    monkeypatch.setattr(cli, 'request', rpc)
    assert cli.main(['deliver-secret', '--sink', 'app-env', '--field', 'client_secret', 'H']) == 0
    assert calls[-1] == dict(action='deliver-secret', sink_protocol=1, sink='app-env', field='client_secret', handle='H')
    assert cli.main(['capture-secret', '--target', 'T', '--field', 'client_secret', '--handle', 'H', '--replace',
                     '--title', 'T', '--username', 'u', '--url', ORIGIN + '/', '--group', 'Web']) == 0
    sent = dict(calls[-1])
    assert sent.pop('start_deadline') > 0
    assert sent == dict(action='capture-secret', capture_protocol=1, target='T', field='client_secret', handle='H',
                        replace=True, metadata=dict(title='T', username='u', url=ORIGIN + '/', group='Web'))
    assert cli.main(['pin-password-target', '--mode', 'read', '--page-id', 'P', '--frame-id', 'F', '--top-url',
                     ORIGIN + '/x', '--selector', '#s']) == 0
    assert calls[-1] == dict(action='pin-password-target', password_protocol=1, page_id='P', frame_id='F',
                             top_url=ORIGIN + '/x', selector='#s', mode='read', capture_protocol=1)
    calls.clear()
    monkeypatch.setattr(cli, 'request', lambda socket, payload, **kw: calls.append(payload) or caps(secret_capture_protocol=None))
    assert cli.main(['pin-password-target', '--mode', 'read', '--page-id', 'P', '--frame-id', 'F', '--top-url',
                     ORIGIN + '/x', '--selector', '#s']) == 1
    assert calls == [{'action': 'ping'}]


def test_installed_helper_is_standalone(tmp_path):
    """The root copy must not import akdbx or anything from a user-writable path."""
    source = (sink_helper.__file__)
    text = open(source, encoding='utf-8').read()
    assert text.startswith('#!/usr/bin/python3 -I\n')
    assert 'from .' not in text and 'import akdbx' not in text
    copy = tmp_path / 'helper.py'
    copy.write_text(text)
    import subprocess
    result = subprocess.run([sys.executable, '-I', str(copy)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 2 and 'must run as root' in result.stderr
