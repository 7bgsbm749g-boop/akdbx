"""save-secret uses only synthetic vaults and synthetic secrets."""
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from akdbx import cli, secret_cli
from akdbx.broker import Broker
from test_broker import RecordingTyper, running_broker
from test_writes import MASTER, OLD, deployed, template, reopened  # noqa: F401

# A base64 line like a service encryption key, plus a trailing newline as `cat` prints it.
SECRET = 'c3ludGhldGljLXNlcnZpY2Uta2V5LW9ubHktZm9yLXRlc3Rz+/=='
VALUES = dict(title='Synthetic service key', username='synthetic-service',
              url='https://service.example.test/', group='Web')
ORIGIN = 'https://node.example:9443'


def args_for(values=VALUES):
    return [arg for key, value in values.items() for arg in ('--' + key, value)]


class Piped(io.TextIOWrapper):
    def isatty(self):
        return False


def pipe(monkeypatch, data: bytes):
    monkeypatch.setattr(sys, 'stdin', Piped(io.BytesIO(data)))


def save(broker, *, secret=SECRET, values=VALUES, **extra):
    return broker.dispatch(dict(action='save-secret', secret_save_protocol=1, metadata=values,
                                secret=secret, **extra))


def no_secret(*texts, secret=SECRET):
    for text in texts:
        assert secret not in text


def test_status_advertises_capability(deployed):
    broker = deployed[0]
    status = broker.dispatch({'action': 'ping'})
    assert status['secret_save_protocol'] == 1 and status['secret_save_field'] == 'password'


def test_create_stores_exact_value_in_protected_password(deployed, capsys, caplog):
    broker, typer, path, _ = deployed
    result = save(broker)
    assert result == dict(ok=True, state='saved', saved='created', metadata=VALUES)
    no_secret(json.dumps(result))
    entry = reopened(path).find_entries(title=VALUES['title'], first=True)
    assert entry.password == SECRET and entry.username == VALUES['username']
    assert entry._element.find('./String[Key="Password"]/Value').get('Protected') == 'True'
    assert reopened(path).find_entries(title='Synthetic site', first=True).password == OLD
    assert len(list(path.parent.glob('.*.akdbx-backup-*'))) == 1
    assert typer.events == [] and capsys.readouterr() == ('', '') and not caplog.records
    # A second create is a duplicate site/account.
    before = path.read_bytes()
    assert save(broker, values={**VALUES, 'title': 'Other'}) == dict(
        ok=False, error='duplicate site/account; select an existing entry')
    assert path.read_bytes() == before


def test_update_keeps_history_and_consumes_handle(deployed):
    broker, typer, path, _ = deployed
    selected = broker.dispatch(dict(action='search', query='Synthetic site'))['entries'][0]
    values = {key: selected[key] for key in ('title', 'username', 'url', 'group')}
    result = save(broker, values=values, handle=selected['handle'])
    assert result == dict(ok=True, state='saved', saved='updated', metadata=values)
    entry = reopened(path).find_entries(title='Synthetic site', first=True)
    assert entry.password == SECRET and entry.notes == 'preserve notes'
    assert entry.get_custom_property('custom') == 'preserve property'
    assert [old.password for old in entry.history] == [OLD]
    refused = save(broker, values=values, handle=selected['handle'], secret='another-synthetic-value')
    assert refused == dict(ok=False, error='unknown or expired handle; search again')


def test_update_requires_exact_metadata(deployed):
    broker, _, path, _ = deployed
    before = path.read_bytes()
    selected = broker.dispatch(dict(action='search', query='Synthetic site'))['entries'][0]
    values = {key: selected[key] for key in ('title', 'username', 'url', 'group')}
    result = save(broker, values={**values, 'title': 'Wrong'}, handle=selected['handle'])
    assert result == dict(ok=False, error='entry metadata mismatch; search again')
    assert path.read_bytes() == before


@pytest.mark.parametrize('secret', ['', 'two\nlines', 'tab\tinside', 'x' * (64 * 1024 + 1), 7, None])
def test_broker_refuses_unsafe_secret_without_echo(deployed, secret):
    broker, _, path, _ = deployed
    before = path.read_bytes()
    result = save(broker, secret=secret)
    assert result['ok'] is False and 'control characters' in result['error']
    if isinstance(secret, str) and secret:
        no_secret(json.dumps(result), secret=secret)
    assert path.read_bytes() == before


@pytest.mark.parametrize('extra', [dict(secret_save_protocol=2), dict(note='x'), dict(password='x')])
def test_broker_refuses_other_request_shapes(deployed, extra):
    broker, _, path, _ = deployed
    before = path.read_bytes()
    request = dict(action='save-secret', secret_save_protocol=1, metadata=VALUES, secret=SECRET)
    request.update(extra)
    result = broker.dispatch(request)
    assert result['ok'] is False and 'protocol 1' in result['error']
    no_secret(json.dumps(result))
    assert path.read_bytes() == before


@pytest.mark.parametrize('state', ['locked', 'unavailable', 'recovery'])
def test_vault_state_refusals(deployed, state, monkeypatch):
    broker, typer, path, _ = deployed
    before = path.read_bytes()
    if state == 'locked':
        broker = Broker(None, typer)
        broker.unlock_url = ORIGIN + '/?token=synthetic-token'
    elif state == 'unavailable':
        monkeypatch.setattr(broker.writes, 'public_base', None)
    else:
        broker.vault._akdbx_store.recovery_required = True
    result = save(broker)
    assert result['ok'] is False
    no_secret(json.dumps(result))
    assert path.read_bytes() == before


def test_missing_group_and_passwordless_refusals(deployed):
    broker, _, path, _ = deployed
    before = path.read_bytes()
    assert 'missing or ambiguous' in save(broker, values={**VALUES, 'group': 'Missing'})['error']
    assert path.read_bytes() == before
    sso = dict(VALUES, title='Synthetic SSO', username='sso-account')
    assert broker.dispatch(dict(action='create-sso-entry', metadata=sso, auth_method='google'))['ok']
    selected = broker.dispatch(dict(action='search', query='Synthetic SSO'))['entries'][0]
    result = save(broker, values=sso, handle=selected['handle'])
    assert result['ok'] is False and 'no separate password' in result['error']


@pytest.mark.parametrize('data,expected', [
    (SECRET.encode() + b'\n', SECRET),
    (SECRET.encode() + b'\r\n', SECRET),
    (SECRET.encode(), SECRET),
    (' padded value '.encode(), ' padded value '),
    ('unicodé-✓'.encode(), 'unicodé-✓'),
])
def test_cli_decoding_strips_exactly_one_line_ending(data, expected):
    assert secret_cli._decode(data) == expected


@pytest.mark.parametrize('data,reason', [
    (b'', 'empty'), (b'\n', 'empty'), (SECRET.encode() + b'\n\n', 'more than one line'),
    (b'a\nb\n', 'more than one line'), (b'\xff\xfe', 'not UTF-8'), ('﻿key'.encode(), 'byte order mark'),
    (b'x' * (64 * 1024 + 3), 'larger'),
])
def test_cli_decoding_refusals_are_fixed_text(data, reason):
    with pytest.raises(secret_cli.InputError) as error:
        secret_cli._decode(data)
    assert reason in str(error.value)
    assert data.decode('utf-8', 'replace').strip() not in str(error.value) or not data.strip()


def cli_run(monkeypatch, capsys, socket, *extra, stdin=None):
    if stdin is not None:
        pipe(monkeypatch, stdin)
    code = cli.main(['--socket', str(socket), '--unlock-origin', ORIGIN, 'save-secret', *args_for(), *extra])
    out, err = capsys.readouterr()
    no_secret(out, err)
    return code, out, err


def test_cli_stdin_round_trip_over_socket(deployed, monkeypatch, capsys):
    broker, typer, path, socket = deployed
    sock = socket.with_name('cli.sock')
    with running_broker(sock, broker):
        code, out, err = cli_run(monkeypatch, capsys, sock, '--stdin', stdin=SECRET.encode() + b'\n')
    assert code == 0 and not err
    assert json.loads(out) == dict(ok=True, state='saved', saved='created', metadata=VALUES)
    assert reopened(path).find_entries(title=VALUES['title'], first=True).password == SECRET
    assert typer.events == []


def test_cli_file_round_trip_and_symlink_refusal(deployed, monkeypatch, capsys, tmp_path):
    broker, _, path, socket = deployed
    key = tmp_path / 'token.key'
    key.write_bytes(SECRET.encode() + b'\n')
    key.chmod(0o600)
    link = tmp_path / 'link.key'
    link.symlink_to(key)
    sock = socket.with_name('cli.sock')
    with running_broker(sock, broker):
        code, out, err = cli_run(monkeypatch, capsys, sock, '--file', str(link))
        assert code == 2 and 'symbolic link' in err and not out
        code, out, err = cli_run(monkeypatch, capsys, sock, '--file', str(tmp_path))
        assert code == 2 and ('could not be opened' in err or 'regular file' in err) and not out
        code, out, err = cli_run(monkeypatch, capsys, sock, '--file', str(key))
    assert code == 0 and json.loads(out)['saved'] == 'created'
    assert reopened(path).find_entries(title=VALUES['title'], first=True).password == SECRET
    assert key.read_bytes() == SECRET.encode() + b'\n'


def test_cli_update_with_handle(deployed, monkeypatch, capsys):
    broker, _, path, socket = deployed
    selected = broker.dispatch(dict(action='search', query='Synthetic site'))['entries'][0]
    values = {key: selected[key] for key in ('title', 'username', 'url', 'group')}
    sock = socket.with_name('cli.sock')
    pipe(monkeypatch, SECRET.encode() + b'\n')
    with running_broker(sock, broker):
        code = cli.main(['--socket', str(sock), '--unlock-origin', ORIGIN, 'save-secret', *args_for(values),
                         '--stdin', '--', selected['handle']])
    out, err = capsys.readouterr()
    no_secret(out, err)
    assert code == 0 and json.loads(out) == dict(ok=True, state='saved', saved='updated', metadata=values)
    assert reopened(path).find_entries(title='Synthetic site', first=True).password == SECRET


def test_cli_refuses_terminal_stdin(deployed, monkeypatch, capsys):
    broker, _, path, socket = deployed
    before = path.read_bytes()

    class Terminal(Piped):
        def isatty(self):
            return True
    monkeypatch.setattr(sys, 'stdin', Terminal(io.BytesIO(SECRET.encode())))
    sock = socket.with_name('cli.sock')
    with running_broker(sock, broker):
        code, out, err = cli_run(monkeypatch, capsys, sock, '--stdin')
    assert code == 2 and 'terminal' in err and path.read_bytes() == before


def fake_broker(monkeypatch, caps, response=None):
    sent = []

    def fake(socket_path, payload, **kwargs):
        sent.append(payload)
        if payload['action'] == 'ping':
            return caps
        if 'before_send' in kwargs:
            kwargs['before_send']()
        return response
    monkeypatch.setattr(cli, 'request', fake)
    return sent


READY = dict(ok=True, version='0.19.0', secret_save_protocol=1, secret_save_field='password',
             locked=False, writes_available=True, recovery_required=False)


@pytest.mark.parametrize('caps,reason', [
    (dict(ok=True, version='0.18.3', locked=False, writes_available=True, recovery_required=False), 'protocol 1'),
    ({**READY, 'secret_save_protocol': 2}, 'protocol 1'),
    ({**READY, 'locked': True, 'writes_available': False, 'unlock_url': ORIGIN + '/?token=t'}, 'vault locked'),
    ({**READY, 'writes_available': False}, 'unavailable'),
    ({**READY, 'recovery_required': True}, 'recovery'),
])
def test_cli_refuses_before_reading_or_sending(monkeypatch, capsys, caps, reason):
    sent = fake_broker(monkeypatch, caps)
    reads = []
    monkeypatch.setattr(secret_cli, 'read_secret', lambda args: reads.append(1) or SECRET)
    assert cli.main(['--socket', '/nonexistent', 'save-secret', *args_for(), '--stdin']) == 1
    out = capsys.readouterr().out
    assert reason in json.loads(out)['error'] and not reads
    assert [payload['action'] for payload in sent] == ['ping']
    if caps.get('locked'):
        assert json.loads(out)['unlock_url'] == caps['unlock_url']


@pytest.mark.parametrize('response', [
    {'ok': False, 'error': 'echo ' + SECRET},
    {'ok': True, 'state': 'saved', 'saved': 'created', 'metadata': VALUES, 'secret': SECRET},
    {'ok': True, 'state': 'saved', 'saved': 'updated', 'metadata': VALUES},
    {'ok': False, 'error': 'x', 'extra': 1},
])
def test_cli_withholds_unexpected_or_echoing_receipts(monkeypatch, capsys, response):
    fake_broker(monkeypatch, READY, response)
    pipe(monkeypatch, SECRET.encode() + b'\n')
    assert cli.main(['--socket', '/nonexistent', 'save-secret', *args_for(), '--stdin']) == 2
    out, err = capsys.readouterr()
    no_secret(out, err)
    assert not out and 'receipt withheld' in err


def test_cli_lost_response_is_uncertain(monkeypatch, capsys):
    def fake(socket_path, payload, **kwargs):
        if payload['action'] == 'ping':
            return READY
        kwargs['before_send']()
        raise TimeoutError('timed out')
    monkeypatch.setattr(cli, 'request', fake)
    pipe(monkeypatch, SECRET.encode())
    assert cli.main(['--socket', '/nonexistent', 'save-secret', *args_for(), '--stdin']) == 2
    out, err = capsys.readouterr()
    no_secret(out, err)
    assert 'outcome uncertain' in err


def test_installed_cli_pipe_never_puts_secret_in_argv_or_output(deployed, tmp_path):
    broker, typer, path, socket = deployed
    sock = socket.with_name('cli.sock')
    executable = str(Path(sys.executable).with_name('akdbx'))
    command = [executable, '--socket', str(sock), '--unlock-origin', ORIGIN, 'save-secret', *args_for(), '--stdin']
    no_secret(*command)
    with running_broker(sock, broker):
        completed = subprocess.run(command, input=(SECRET + '\n').encode(), capture_output=True, timeout=60)
    assert completed.returncode == 0 and not completed.stderr
    no_secret(completed.stdout.decode())
    assert json.loads(completed.stdout)['state'] == 'saved'
    assert reopened(path).find_entries(title=VALUES['title'], first=True).password == SECRET
    # The CLI creates no files next to the vault or in the working directory.
    # Only the encrypted vault and its encrypted backup hold it; no plaintext file is left.
    for item in path.parent.rglob('*'):
        if item.is_file():
            assert SECRET.encode() not in item.read_bytes()


def test_save_secret_holds_the_vault_lock(monkeypatch):
    import threading
    from test_additional_urls import Vault, Entry
    broker = Broker(Vault([Entry()]), RecordingTyper())
    observed = []

    def probe(request):
        result = []
        worker = threading.Thread(target=lambda: result.append(broker._vault_lock.acquire(blocking=False)))
        worker.start()
        worker.join()
        observed.append(result[0])
        return {'ok': True}
    monkeypatch.setattr(broker.writes, 'save_secret', probe)
    broker.dispatch({'action': 'save-secret'})
    assert observed == [False]
