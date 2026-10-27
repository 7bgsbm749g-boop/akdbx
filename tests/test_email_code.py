"""Native email-code identities: synthetic encrypted vaults and recording targets only."""
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest
from pykeepass import PyKeePass

from agentic_kdbx import cli
from agentic_kdbx.broker import Broker, open_vault_with_password
from agentic_kdbx.persistence import VaultStore
from agentic_kdbx.target import DeliveryError, failure
from test_broker import RecordingTyper, running_broker, target_request
from test_writes import MASTER, OLD, CHOSEN, begin, commit, deployed, fills, private_post, reopened, template


VALUES = dict(title='Synthetic email-code site', username='synthetic@example.test',
              url='https://email-code.example.test/login', group='Web')


def create(broker, **changes):
    return broker.dispatch(dict(dict(action='create-passwordless-entry', metadata=VALUES,
                                     auth_method='email_code'), **changes))


def cli_args():
    return ['create-passwordless-entry',
            *[arg for key, value in VALUES.items() for arg in ('--' + key, value)],
            '--auth-method', 'email_code']


def selected(broker):
    return broker.dispatch(dict(action='search', query=VALUES['title']))['entries'][0]


def test_encrypted_save_reread_and_restart_preserve_honest_method(deployed, capsys, caplog):
    broker, typer, path, _ = deployed
    before = path.read_bytes()
    result = create(broker)
    assert result == dict(ok=True, state='saved', metadata=VALUES, auth_method='email_code', passwordless=True)
    entry = reopened(path).find_entries(title=VALUES['title'], first=True)
    assert not entry.password
    assert entry.get_custom_property('akdbx.passwordless') == 'v1'
    assert entry.get_custom_property('akdbx.auth-method') == 'email_code'
    assert entry.get_custom_property('akdbx.passwordless-sso') is None
    assert entry.notes == 'Sign-in method: Email code. No separate site password.'
    assert reopened(path).find_entries(title='Synthetic site', first=True).password == OLD
    backups = list(path.parent.glob('.*.akdbx-backup-*'))
    assert len(backups) == 1 and backups[0].read_bytes() == before
    for encrypted in (path, *backups):
        assert stat.S_IMODE(encrypted.stat().st_mode) == 0o600
        assert all(value.encode() not in encrypted.read_bytes() for value in (MASTER, OLD, CHOSEN, VALUES['username']))
    restarted = Broker(open_vault_with_password(path, MASTER), RecordingTyper())
    for instance in (broker, restarted):
        item = selected(instance)
        assert item['passwordless'] is True and item['auth_method'] == 'email_code'
        assert set(item) == {'handle', *VALUES, 'passwordless', 'auth_method'}
        assert all(secret not in json.dumps(item) for secret in (MASTER, OLD, CHOSEN))
    assert not broker.writes.operations and not typer.events
    assert capsys.readouterr() == ('', '') and not caplog.records


def test_installed_cli_secret_free_receipt_and_help(deployed):
    broker, typer, path, socket = deployed
    executable = str(Path(sys.executable).with_name('akdbx'))
    socket = socket.with_name('cli.sock')
    with running_broker(socket, broker):
        completed = subprocess.run([executable, '--socket', str(socket), *cli_args()],
                                   capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0 and not completed.stderr
    assert json.loads(completed.stdout) == dict(ok=True, state='saved', metadata=VALUES,
                                               auth_method='email_code', passwordless=True)
    assert all(secret not in completed.stdout for secret in (MASTER, OLD, CHOSEN))
    assert not reopened(path).find_entries(title=VALUES['title'], first=True).password
    assert not typer.events
    help_result = subprocess.run([executable, 'create-passwordless-entry', '--help'],
                                 capture_output=True, text=True, timeout=10)
    assert help_result.returncode == 0 and 'email_code' in help_result.stdout
    assert 'no password or saved code' in help_result.stdout


@pytest.mark.parametrize('mode', ['login', 'password', 'username', 'invalid'])
def test_fill_modes_and_single_use_handles(deployed, mode):
    broker, typer, _, _ = deployed
    assert create(broker)['ok']
    item, pin = selected(broker), target_request(broker)
    response = broker.dispatch(dict(action='fill', mode=mode, handle=item['handle'], **pin))
    assert response['ok'] is (mode == 'username')
    assert typer.events == ([('type', VALUES['username'])] if mode == 'username' else [])
    assert not broker.dispatch(dict(action='fill', mode='username', handle=item['handle'], **target_request(broker)))['ok']
    assert not broker.dispatch(dict(action='fill', mode='username', handle=selected(broker)['handle'], **pin))['ok']


@pytest.mark.parametrize('action', ['update-password', 'generate-password'])
def test_password_writes_refuse_and_consume_handle(deployed, action):
    broker, typer, path, _ = deployed
    assert create(broker)['ok']
    before, item = path.read_bytes(), selected(broker)
    result = broker.dispatch(dict(action=action, handle=item['handle'], metadata=VALUES))
    assert not result['ok'] and 'no separate password' in result['error']
    assert not broker.dispatch(dict(action='fill', mode='username', handle=item['handle'], **target_request(broker)))['ok']
    assert path.read_bytes() == before and not typer.events and not broker.writes.operations


@pytest.mark.parametrize('marker,method', [('v1', None), ('', None), ('broken', 'other'),
                                         (None, 'email_code'), (None, '')])
def test_incomplete_passwordless_markers_block_existing_password(deployed, marker, method):
    broker, typer, _, _ = deployed
    entry = broker.vault.find_entries(title='Synthetic site', first=True)
    if marker is not None:
        entry.set_custom_property('akdbx.passwordless', marker)
    if method is not None:
        entry.set_custom_property('akdbx.auth-method', method)
    item = broker.dispatch(dict(action='search', query='Synthetic site'))['entries'][0]
    assert item['passwordless'] is True
    assert not broker.dispatch(dict(action='fill', mode='password', handle=item['handle'], **target_request(broker)))['ok']
    assert not typer.events


@pytest.mark.parametrize('state', ['locked', 'unavailable', 'recovery'])
def test_vault_state_refusals(deployed, state):
    broker, typer, path, _ = deployed
    before = path.read_bytes()
    if state == 'locked':
        broker = Broker(None, typer)
        broker.unlock_url = 'https://node.example:9443/?token=synthetic-token'
    elif state == 'unavailable':
        broker.vault._akdbx_store.writable_path = False
    else:
        broker.vault._akdbx_store.recovery_required = True
    result = create(broker)
    assert not result['ok'] and path.read_bytes() == before and not typer.events
    if state == 'locked':
        assert result['unlock_url'] == broker.unlock_url


@pytest.mark.parametrize('changes', [dict(auth_method=None), dict(auth_method='google'),
                                    dict(auth_method='github'), dict(auth_method=True),
                                    dict(auth_method=[]), dict(password=CHOSEN),
                                    dict(email_code='synthetic-forbidden-code'),
                                    dict(metadata={**VALUES, 'code': 'synthetic-forbidden-code'}),
                                    dict(metadata={**VALUES, 'url': 'https://email-code.example.test?token=private'}),
                                    dict(metadata={**VALUES, 'username': 'bad\naccount'}),
                                    dict(metadata={**VALUES, 'group': 'Missing'})])
def test_invalid_or_secret_fields_never_save_or_echo(deployed, changes, capsys, caplog):
    broker, typer, path, _ = deployed
    before = path.read_bytes()
    result = create(broker, **changes)
    assert not result['ok'] and 'saved' not in result.values()
    assert path.read_bytes() == before and not typer.events
    captured = capsys.readouterr()
    assert all(secret not in json.dumps(result) + captured.out + captured.err + caplog.text
               for secret in (MASTER, OLD, CHOSEN, 'synthetic-forbidden-code'))


@pytest.mark.parametrize('existing', ['password', 'google', 'github', 'email_code'])
def test_duplicates_across_all_authentication_methods(deployed, existing):
    broker, typer, path, socket = deployed
    if existing == 'password':
        assert private_post(socket, broker.dispatch(dict(action='create-entry', metadata=VALUES)))[0] == 200
    elif existing == 'email_code':
        assert create(broker)['ok']
    else:
        assert broker.dispatch(dict(action='create-sso-entry', auth_method=existing, metadata=VALUES))['ok']
    before = path.read_bytes()
    result = create(broker, metadata={**VALUES, 'username': VALUES['username'].upper(), 'group': '',
                                    'title': 'Changed title', 'url': 'https://EMAIL-CODE.EXAMPLE.TEST:443/other'})
    assert not result['ok'] and 'duplicate site/account' in result['error']
    assert path.read_bytes() == before and not typer.events


@pytest.mark.parametrize('stage', ['private', 'generated'])
def test_staged_password_cannot_convert_marked_identity(deployed, stage):
    broker, _, path, socket = deployed
    pending = begin(broker, 'generate-password' if stage == 'generated' else 'update-password')
    if stage == 'generated':
        assert all(result['ok'] for result in fills(broker, pending))
    before = path.read_bytes()
    broker.vault.find_entries(title='Synthetic site', first=True).set_custom_property('akdbx.passwordless', 'v1')
    if stage == 'private':
        assert private_post(socket, pending)[0] == 409
    else:
        assert not commit(broker, pending)['ok']
    assert path.read_bytes() == before


def test_save_invalidates_pending_generation_and_old_search(deployed):
    broker, typer, _, _ = deployed
    old = broker.dispatch(dict(action='search', query='Synthetic site'))['entries'][0]['handle']
    pending = begin(broker, 'generate-password')
    assert create(broker)['ok']
    assert broker.writes.get(pending['write_handle']).password is None
    assert not any(result['ok'] for result in fills(broker, pending))
    assert not commit(broker, pending)['ok']
    assert not broker.dispatch(dict(action='fill', handle=old, **target_request(broker)))['ok']
    assert not typer.events


@pytest.mark.parametrize('guard', ['missing-pin', 'deadline', 'controls', 'partial'])
def test_username_fill_keeps_target_deadline_controls_and_partial_failure_guards(deployed, monkeypatch, guard, capsys, caplog):
    broker, typer, _, _ = deployed
    assert create(broker)['ok']
    item = selected(broker)
    request = dict(action='fill', mode='username', handle=item['handle'], **target_request(broker))
    if guard == 'missing-pin':
        del request['target']
    elif guard == 'deadline':
        request['start_deadline'] = broker.clock() - 1
    elif guard == 'controls':
        broker.vault.find_entries(title=VALUES['title'], first=True).username = 'bad\tusername'
    else:
        def interrupt(*args):
            error = DeliveryError(True)
            error.args = (MASTER + OLD,)
            raise error
        monkeypatch.setattr(typer, 'deliver', interrupt)
    result = broker.dispatch(request)
    assert not result['ok'] and not typer.events
    if guard == 'partial':
        assert result == failure(True)
    assert not broker.dispatch(dict(action='fill', mode='username', handle=item['handle'], **target_request(broker)))['ok']
    captured = capsys.readouterr()
    assert all(secret not in json.dumps(result) + captured.out + captured.err + caplog.text for secret in (MASTER, OLD))


@pytest.mark.parametrize('changes', [dict(passwordless_identity_supported=False), dict(passwordless_identity_protocol=True),
                                    dict(passwordless_identity_protocol=2), dict(passwordless_identity_protocol='1'),
                                    dict(passwordless_auth_methods=[]), dict(passwordless_auth_methods='email_code'),
                                    dict(passwordless_auth_methods=['google', 'github']),
                                    dict(passwordless_auth_methods=['email_code', None]), dict(ok=False)])
def test_cli_requires_exact_capability_before_dispatch(monkeypatch, capsys, changes):
    calls = []
    def request(path, payload, **kwargs):
        calls.append(payload)
        return dict(dict(ok=True, passwordless_identity_supported=True, passwordless_identity_protocol=1,
                         passwordless_auth_methods=['email_code']), **changes)
    monkeypatch.setattr(cli, 'request', request)
    assert cli.main(cli_args()) == 1
    assert 'passwordless creation not sent' in json.loads(capsys.readouterr().out)['error']
    assert calls == [dict(action='ping')]


def test_cli_rejects_malformed_capability_and_unsupported_auth_before_dispatch(monkeypatch, capsys):
    with pytest.raises(cli.ProtocolError):
        cli._validate_response(dict(ok=True, passwordless_identity_supported='true'), cli.DEFAULT_UNLOCK_ORIGIN)
    def unexpected(*args, **kwargs):
        pytest.fail('CLI dispatched an unsupported authentication method')
    monkeypatch.setattr(cli, 'request', unexpected)
    with pytest.raises(SystemExit) as error:
        cli.main([*cli_args()[:-1], 'google'])
    assert error.value.code == 2
    capsys.readouterr()


@pytest.mark.parametrize('outcome', ['timeout', 'protocol', 'wrong-method', 'wrong-metadata', 'not-saved', 'not-passwordless'])
def test_cli_uncertain_save_refuses_success_and_never_retries(monkeypatch, capsys, outcome):
    calls = []
    def request(path, payload, **kwargs):
        calls.append(payload)
        if payload['action'] == 'ping':
            return dict(ok=True, passwordless_identity_supported=True, passwordless_identity_protocol=1,
                        passwordless_auth_methods=['email_code'])
        if outcome == 'timeout':
            raise TimeoutError
        if outcome == 'protocol':
            raise cli.ProtocolError(MASTER + OLD)
        result = dict(ok=True, state='saved', passwordless=True, auth_method='email_code', metadata=VALUES)
        result.update({'wrong-method': dict(auth_method='google'), 'wrong-metadata': dict(metadata={}),
                       'not-saved': dict(state='pending'), 'not-passwordless': dict(passwordless=False)}[outcome])
        return result
    monkeypatch.setattr(cli, 'request', request)
    assert cli.main(cli_args()) == 2
    captured = capsys.readouterr()
    assert not captured.out and 'check status and search before any retry' in captured.err
    assert all(secret not in captured.err for secret in (MASTER, OLD))
    assert len(calls) == 2


@pytest.mark.parametrize('failure_stage', ['serialize', 'backup', 'replace', 'durability'])
def test_persistence_failures_never_claim_saved_or_leak(deployed, monkeypatch, capsys, caplog, failure_stage):
    broker, typer, path, _ = deployed
    before = path.read_bytes()
    def fail(*args, **kwargs):
        raise OSError(MASTER + OLD)
    if failure_stage == 'serialize':
        monkeypatch.setattr(PyKeePass, 'save', fail)
    elif failure_stage == 'backup':
        monkeypatch.setattr(VaultStore, '_write_file', fail)
    elif failure_stage == 'replace':
        monkeypatch.setattr(os, 'replace', fail)
    else:
        real_replace = os.replace
        def replace_then_fail(*args, **kwargs):
            real_replace(*args, **kwargs)
            monkeypatch.setattr(os, 'fsync', fail)
        monkeypatch.setattr(os, 'replace', replace_then_fail)
    result = create(broker)
    assert not result['ok'] and 'state' not in result
    assert not broker.vault.find_entries(title=VALUES['title']) and not typer.events
    if failure_stage == 'durability':
        assert broker.dispatch(dict(action='ping'))['recovery_required'] is True
        assert not create(broker)['ok']
    else:
        assert path.read_bytes() == before
    captured = capsys.readouterr()
    assert all(secret not in json.dumps(result) + captured.out + captured.err + caplog.text for secret in (MASTER, OLD))


def test_frozen_090_broker_refuses_new_creation_and_keeps_fill_guards(deployed, tmp_path):
    broker, _, path, _ = deployed
    assert create(broker)['ok']
    package = tmp_path / 'legacy' / 'agentic_kdbx'
    package.mkdir(parents=True)
    baseline = '0846ca4'
    names = subprocess.run(['git', 'ls-tree', '--name-only', baseline + ':src/agentic_kdbx'],
                           capture_output=True, text=True, check=True, timeout=10).stdout.splitlines()
    for name in names:
        data = subprocess.run(['git', 'show', baseline + ':src/agentic_kdbx/' + name],
                              capture_output=True, check=True, timeout=10).stdout
        (package / name).write_bytes(data)
    socket = tmp_path / 'legacy-runtime' / 'broker.sock'
    script = '''import signal,sys,threading
from pathlib import Path
from agentic_kdbx.broker import Broker,open_vault_with_password,serve
from test_writes import MASTER
from test_broker import RecordingTyper
class Audited(Broker):
    creates = 0
    def dispatch(self, request, **kwargs):
        if request.get('action') == 'create-passwordless-entry':
            self.creates += 1
        result = super().dispatch(request, **kwargs)
        if request.get('action') == 'ping':
            result['synthetic_creation_requests'] = self.creates
        return result
stop=threading.Event()
signal.signal(signal.SIGTERM,lambda *_:stop.set())
serve(Path(sys.argv[2]),Audited(open_vault_with_password(Path(sys.argv[1]),MASTER),RecordingTyper()),stop)
'''
    environment = {**os.environ, 'PYTHONPATH': str(package.parent) + os.pathsep + str(Path(__file__).parent)}
    process = subprocess.Popen([sys.executable, '-c', script, str(path), str(socket)], env=environment,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    before = path.read_bytes()
    try:
        deadline = time.monotonic() + 10
        while not socket.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert socket.exists()
        status = cli.request(socket, dict(action='ping'))
        assert status['version'] == '0.9.0' and status['sso_auth_methods'] == ['google', 'github']
        executable = str(Path(sys.executable).with_name('akdbx'))
        result = subprocess.run([executable, '--socket', str(socket), *cli_args()],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 1 and 'passwordless creation not sent' in json.loads(result.stdout)['error']
        assert cli.request(socket, dict(action='ping'))['synthetic_creation_requests'] == 0
        # An older broker recognizes auth-method as passwordless even though it
        # cannot name email_code; it must not reinterpret it as a password login.
        for mode in ('login', 'password', 'username'):
            item = cli.request(socket, dict(action='search', query=VALUES['title']))['entries'][0]
            assert item['passwordless'] is True and item['auth_method'] == 'unknown'
            pin = cli.request(socket, dict(action='pin-target', pid=123, window=456, target_protocol=1))
            response = cli.request(socket, dict(action='fill', mode=mode, handle=item['handle'],
                                                target=pin['target'], target_protocol=1, start_deadline=time.monotonic()+1))
            assert response['ok'] is (mode == 'username')
        assert path.read_bytes() == before
    finally:
        process.terminate()
        output, errors = process.communicate(timeout=10)
        assert all(secret.encode() not in output + errors for secret in (MASTER, OLD, CHOSEN))
