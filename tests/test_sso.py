"""Passwordless identities use only synthetic vaults and recording keyboards."""
import json
import io
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from pykeepass import PyKeePass, create_database

from akdbx import cli
from akdbx.broker import Broker, open_vault_with_password
from akdbx.persistence import VaultStore
from akdbx.versions import ARCHIVE_UUID
from test_broker import target_request, RecordingTyper, running_broker
from test_writes import MASTER, OLD, CHOSEN, deployed, template, begin, private_post, reopened


VALUES = dict(title='Synthetic SSO site', username='synthetic@example.test',
              url='https://sso.example.test/login', group='Web')


def create(broker, *, values=None, **extra):
    return broker.dispatch(dict(action='create-sso-entry', metadata=VALUES if values is None else values,
                                auth_method='google', **extra))


def test_existing_private_create_refuses_empty_password(deployed):
    broker, typer, path, socket = deployed
    before = path.read_bytes()
    pending = broker.dispatch(dict(action='create-entry', metadata=VALUES))
    assert pending['ok']
    assert private_post(socket, pending, password='', confirmation='')[0] == 409
    assert path.read_bytes() == before and typer.events == []


def test_create_passwordless_sso_round_trip(deployed, capsys, caplog):
    broker, typer, path, _ = deployed
    result = create(broker)
    assert result == dict(ok=True, state='saved', metadata=VALUES,
                          auth_method='google', passwordless=True)
    saved = reopened(path)
    entry = saved.find_entries(title=VALUES['title'], first=True)
    assert not entry.password
    assert entry.get_custom_property('akdbx.passwordless-sso') == 'v1'
    assert entry.get_custom_property('akdbx.auth-method') == 'google'
    assert 'Google SSO' in entry.notes and 'No separate site password' in entry.notes
    assert saved.find_entries(title='Synthetic site', first=True).notes == 'preserve notes'
    assert saved.find_entries(title='Synthetic site', first=True).get_custom_property('custom') == 'preserve property'
    assert len(list(path.parent.glob('.*.akdbx-backup-*'))) == 1
    assert typer.events == [] and not broker.writes.operations
    assert capsys.readouterr() == ('', '') and not caplog.records
    selected = broker.dispatch(dict(action='search', query=VALUES['url']))['entries'][0]
    assert selected['passwordless'] is True and selected['auth_method'] == 'google'


@pytest.mark.parametrize('provider', ['google', 'github'])
def test_installed_cli_and_synthetic_socket(deployed, provider):
    broker, typer, path, socket = deployed
    executable = str(Path(sys.executable).with_name('akdbx'))
    prefix = [executable, '--socket', str(socket.with_name('cli.sock'))]
    args = [arg for key, value in VALUES.items() for arg in ('--' + key, value)]
    with running_broker(socket.with_name('cli.sock'), broker):
        completed = subprocess.run([*prefix, 'create-sso-entry', *args, '--auth-method', provider],
                                   text=True, capture_output=True, timeout=30)
        assert completed.returncode == 0 and not completed.stderr
        assert json.loads(completed.stdout) == dict(ok=True, state='saved', metadata=VALUES,
                                                    auth_method=provider, passwordless=True)
        for secret in (MASTER, OLD, CHOSEN):
            assert secret not in completed.stdout
    assert not reopened(path).find_entries(title=VALUES['title'], first=True).password
    assert typer.events == []


@pytest.mark.parametrize('mode', ['login', 'password', 'username'])
def test_sso_fill_guards_and_single_use_handles(deployed, mode):
    broker, typer, _, _ = deployed
    assert create(broker)['ok']
    selected = broker.dispatch(dict(action='search', query=VALUES['title']))['entries'][0]
    result = broker.dispatch(dict(**target_request(broker), action='fill', handle=selected['handle'], mode=mode))
    if mode == 'username':
        assert result == dict(ok=True, filled='username', target_delivery='x11-send-event-v1')
        assert typer.events == [('type', VALUES['username'])]
    else:
        assert not result['ok'] and 'no keys sent' in result['error']
        assert typer.events == []
    assert not broker.dispatch(dict(**target_request(broker), action='fill', handle=selected['handle'], mode='username'))['ok']


@pytest.mark.parametrize('action', ['update-password', 'generate-password'])
def test_sso_rejects_password_writes_and_consumes_handles(deployed, action):
    broker, typer, path, _ = deployed
    assert create(broker)['ok']
    before = path.read_bytes()
    selected = broker.dispatch(dict(action='search', query=VALUES['title']))['entries'][0]
    result = broker.dispatch(dict(action=action, handle=selected['handle'], metadata=VALUES))
    assert not result['ok'] and 'no separate password' in result['error']
    assert not broker.dispatch(dict(**target_request(broker), action='fill', handle=selected['handle'], mode='username'))['ok']
    assert path.read_bytes() == before and typer.events == []


@pytest.mark.parametrize('marker,method', [('v1', None), (None, 'google'), ('unknown', 'untrusted'), ('', None), (None, '')])
def test_incomplete_markers_fail_closed_even_if_password_present(deployed, marker, method):
    broker, typer, _, _ = deployed
    entry = broker.vault.find_entries(title='Synthetic site', first=True)
    if marker is not None:
        entry.set_custom_property('akdbx.passwordless-sso', marker)
    if method is not None:
        entry.set_custom_property('akdbx.auth-method', method)
    selected = broker.dispatch(dict(action='search', query='Synthetic site'))['entries'][0]
    assert selected['passwordless'] is True
    result = broker.dispatch(dict(**target_request(broker), action='fill', handle=selected['handle'], mode='password'))
    assert not result['ok'] and typer.events == []


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
    assert not result['ok']
    if state == 'locked':
        assert result['error'] == 'vault locked' and result['unlock_url'] == broker.unlock_url
    elif state == 'recovery':
        assert result['error'] == 'save outcome uncertain; restart and unlock'
    else:
        assert 'unavailable' in result['error']
    assert path.read_bytes() == before and typer.events == []


@pytest.mark.parametrize('group_state', ['missing', 'ambiguous', 'archive', 'archive-child'])
def test_group_selection_is_existing_unambiguous_and_not_archive(deployed, group_state):
    broker, typer, path, _ = deployed
    before = path.read_bytes()
    if group_state == 'missing':
        group = 'Missing'
    elif group_state == 'ambiguous':
        broker.vault.add_group(broker.vault.root_group, 'Web')
        group = 'Web'
    else:
        archive = broker.vault.add_group(broker.vault.root_group, 'Archive')
        archive.uuid = ARCHIVE_UUID
        group = 'Archive'
        if group_state == 'archive-child':
            broker.vault.add_group(archive, 'Nested')
            group = 'Archive/Nested'
    result = create(broker, values={**VALUES, 'group': group})
    assert not result['ok'] and 'missing or ambiguous' in result['error']
    assert path.read_bytes() == before and typer.events == []


def test_root_group_and_distinct_account_are_supported(deployed):
    broker, _, path, _ = deployed
    assert create(broker, values={**VALUES, 'group': ''})['ok']
    assert create(broker, values={**VALUES, 'username': 'other@example.test'})['ok']
    assert len(reopened(path).entries) == 5


@pytest.mark.parametrize('existing_sso', [True, False])
def test_duplicate_account_origin_anywhere_active(deployed, existing_sso):
    broker, typer, path, socket = deployed
    original = {**VALUES, 'group': '', 'url': 'https://SSO.EXAMPLE.TEST:443/other'}
    if existing_sso:
        assert create(broker, values=original)['ok']
    else:
        pending = broker.dispatch(dict(action='create-entry', metadata=original))
        assert private_post(socket, pending)[0] == 200
    before = path.read_bytes()
    result = create(broker, values={**VALUES, 'title': 'Another title', 'username': VALUES['username'].upper()})
    assert result == dict(ok=False, error='duplicate site/account; select an existing entry')
    # The ordinary password creation route must also reject SSO duplicates.
    assert not broker.dispatch(dict(action='create-entry', metadata=VALUES))['ok']
    assert path.read_bytes() == before and typer.events == []


def test_concurrent_creates_make_one_record_and_invalidate_stale_work(deployed):
    broker, typer, path, socket = deployed
    handle = broker.dispatch(dict(action='search', query='Synthetic site'))['entries'][0]['handle']
    private = begin(broker)
    generated = begin(broker, 'generate-password')
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: create(broker), range(2)))
    assert sum(result['ok'] for result in outcomes) == 1
    assert len(reopened(path).find_entries(username=VALUES['username'])) == 1
    assert not broker.dispatch(dict(**target_request(broker), action='fill', handle=handle, mode='password'))['ok']
    assert private_post(socket, private)[0] == 409
    assert broker.writes.get(generated['write_handle']).password is None
    assert typer.events == []


@pytest.mark.parametrize('field,value', [
    ('title', ''), ('title', ' '), ('title', 'x' * 4097), ('title', '\ud800'),
    ('username', ''), ('username', ' user@example.test'), ('username', 'user@example.test '),
    ('username', 'user\n@example.test'), ('username', 'user\x85@example.test'),
    ('username', 'user\u202e@example.test'), ('group', None), ('group', 'Web\t'),
    ('url', None), ('url', 'http://sso.example.test'), ('url', 'https://'),
    ('url', 'https://user:secret@sso.example.test'), ('url', 'https://sso.example.test:0'),
    ('url', 'https://sso.example.test:99999'), ('url', 'https://sso.example.test:bad'),
    ('url', 'https://sso.example.test:'), ('url', 'https://sso.example.test./'),
    ('url', 'https://sso.example.test?q=private'), ('url', 'https://sso.example.test#private'),
    ('url', 'https://sso.example.test?'), ('url', 'https://sso.example.test#'),
    ('url', 'https://sso.example.test\n'), ('url', ' https://sso.example.test'),
    ('url', 'https://bad host.test'), ('url', 'https://%65xample.test'),
    ('url', 'https://bad_host.test'), ('url', 'https://sso.example.test\\@evil.test'),
    ('url', 'https://[invalid]/'), ('url', 'https://[fe80::1%25eth0]/'),
    ('url', 'https://sso.example.test/%XX'),
    ('url', 'https://127.1/'), ('url', 'https://2130706433/'),
    ('url', 'https://0x7f000001/'), ('url', 'https://127.0.0.01/'),
    ('url', 'https://[::1]garbage/'), ('url', 'https://[v1.example]/'),
])
def test_malformed_metadata_is_refused_without_echo(deployed, field, value):
    broker, typer, path, _ = deployed
    before = path.read_bytes()
    result = create(broker, values={**VALUES, field: value})
    assert not result['ok'] and result['error'].startswith('invalid SSO metadata;')
    assert path.read_bytes() == before and typer.events == []


@pytest.mark.parametrize('metadata', [None, [], {}, {**VALUES, 'password': 'synthetic-forbidden'}])
def test_missing_or_extra_metadata_fields_are_refused(deployed, metadata):
    broker, _, path, _ = deployed
    before = path.read_bytes()
    assert not broker.dispatch(dict(action='create-sso-entry', metadata=metadata, auth_method='google'))['ok']
    assert path.read_bytes() == before


@pytest.mark.parametrize('extra', [dict(password='synthetic-forbidden'), dict(confirmation='synthetic-forbidden'), dict(site_accepted=True)])
def test_rpc_never_accepts_a_password_or_password_flow_fields(deployed, extra):
    broker, _, path, _ = deployed
    before = path.read_bytes()
    result = create(broker, **extra)
    assert result == dict(ok=False, error='SSO creation accepts only destination metadata and auth_method')
    assert path.read_bytes() == before


@pytest.mark.parametrize('method', [None, '', 'Google', 'password', [], True])
def test_explicit_supported_auth_method_required(deployed, method):
    broker, _, path, _ = deployed
    before = path.read_bytes()
    result = broker.dispatch(dict(action='create-sso-entry', metadata=VALUES, auth_method=method))
    assert result == dict(ok=False, error='SSO auth_method must be google or github')
    assert path.read_bytes() == before


def test_external_change_preserved(deployed):
    broker, typer, path, _ = deployed
    external = reopened(path)
    external.find_entries(title='Unrelated', first=True).notes = 'Synthetic external edit'
    external.save()
    before = path.read_bytes()
    result = create(broker)
    assert not result['ok'] and 'changed on disk' in result['error']
    assert path.read_bytes() == before and typer.events == []
    assert not broker.vault.find_entries(title=VALUES['title'])


def test_ipv6_origin_spelling_does_not_bypass_duplicates(deployed):
    broker, _, path, _ = deployed
    assert create(broker, values={**VALUES, 'url': 'https://[0:0:0:0:0:0:0:1]:443/login'})['ok']
    before = path.read_bytes()
    result = create(broker, values={**VALUES, 'url': 'https://[::1]/other'})
    assert not result['ok'] and 'duplicate' in result['error']
    assert path.read_bytes() == before


def test_two_independent_brokers_do_not_overwrite_each_other(deployed):
    broker, _, path, _ = deployed
    other = Broker(open_vault_with_password(path, MASTER), RecordingTyper())
    other.writes.public_base = 'https://node.example:9443'
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(create, [broker, other]))
    assert sum(result['ok'] for result in results) == 1
    assert any('changed on disk' in result.get('error', '') for result in results)
    assert len(reopened(path).find_entries(username=VALUES['username'])) == 1


def test_pending_private_update_cannot_overwrite_sso_markers(deployed):
    broker, _, path, socket = deployed
    pending = begin(broker)
    before = path.read_bytes()
    broker.vault.find_entries(title='Synthetic site', first=True).set_custom_property('akdbx.auth-method', 'google')
    assert private_post(socket, pending)[0] == 409
    assert path.read_bytes() == before


@pytest.mark.parametrize('failure', ['serialize', 'backup', 'replace', 'durability'])
def test_persistence_failures_never_claim_saved_or_leak(deployed, monkeypatch, caplog, capsys, failure):
    broker, typer, path, _ = deployed
    before = path.read_bytes()
    def fail(*args, **kwargs):
        raise OSError(MASTER + OLD)
    if failure == 'serialize':
        monkeypatch.setattr(PyKeePass, 'save', fail)
    elif failure == 'backup':
        monkeypatch.setattr(VaultStore, '_write_file', fail)
    elif failure == 'replace':
        monkeypatch.setattr(os, 'replace', fail)
    else:
        real_replace = os.replace
        def replace_then_fail(*args, **kwargs):
            real_replace(*args, **kwargs)
            monkeypatch.setattr(os, 'fsync', fail)
        monkeypatch.setattr(os, 'replace', replace_then_fail)
    result = create(broker)
    assert not result['ok'] and 'state' not in result
    assert not broker.vault.find_entries(title=VALUES['title'])
    if failure == 'durability':
        assert broker.dispatch(dict(action='ping'))['recovery_required'] is True
        assert not create(broker)['ok']
        assert not broker.dispatch(dict(action='search', query='Synthetic site'))['ok']
        assert list(path.parent.glob('.*.akdbx-backup-*'))
    else:
        assert path.read_bytes() == before
    captured = capsys.readouterr()
    assert all(secret not in json.dumps(result) + captured.out + captured.err + caplog.text for secret in (MASTER, OLD))
    assert not list(path.parent.glob('.*.akdbx-write-*')) and typer.events == []


def test_held_keyfile_and_attachments_preserved(tmp_path):
    key = tmp_path / 'synthetic.key'
    key.write_bytes(bytes(range(32)))
    path = tmp_path / 'synthetic-keyed.kdbx'
    vault = create_database(io.BytesIO(), password=MASTER, keyfile=str(key))
    params = vault.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    params['I'].value, params['M'].value = 1, 1024 * 1024
    entry = vault.add_entry(vault.root_group, 'Synthetic unrelated', 'synthetic', OLD)
    entry.add_attachment(vault.add_binary(b'synthetic attachment'), 'synthetic.txt')
    vault.save(str(path))
    broker = Broker(open_vault_with_password(path, MASTER, key), RecordingTyper())
    broker.writes.public_base = 'https://node.example:9443'
    assert create(broker, values={**VALUES, 'group': ''})['ok']
    saved = PyKeePass(str(path), password=MASTER, keyfile=str(key))
    assert saved.find_entries(title='Synthetic unrelated', first=True).attachments[0].data == b'synthetic attachment'
    assert not saved.find_entries(title=VALUES['title'], first=True).password
    before = path.read_bytes()
    key.write_bytes(bytes(reversed(range(32))))
    result = create(broker, values={**VALUES, 'group': '', 'username': 'another@example.test'})
    assert not result['ok'] and 'key file changed' in result['error']
    assert path.read_bytes() == before


def cli_args():
    return ['create-sso-entry', *[arg for key, value in VALUES.items() for arg in ('--' + key, value)],
            '--auth-method', 'google']


@pytest.mark.parametrize('changes', [dict(sso_identity_supported=False), dict(sso_identity_protocol=True),
                                    dict(sso_identity_protocol=2), dict(sso_auth_methods=[]),
                                    dict(sso_auth_methods='google'), dict(ok=False)])
def test_cli_capability_gate_before_dispatch(monkeypatch, capsys, changes):
    calls = []
    def request(path, payload, **kwargs):
        calls.append(payload)
        return dict(dict(ok=True, sso_identity_supported=True, sso_identity_protocol=1,
                         sso_auth_methods=['google', 'github']), **changes)
    monkeypatch.setattr(cli, 'request', request)
    assert cli.main(cli_args()) == 1
    assert 'SSO creation not sent' in json.loads(capsys.readouterr().out)['error']
    assert calls == [dict(action='ping')]


def test_cli_rejects_invalid_capability_type():
    with pytest.raises(cli.ProtocolError):
        cli._validate_response(dict(ok=True, sso_identity_supported='true'), cli.DEFAULT_UNLOCK_ORIGIN)


@pytest.mark.parametrize('outcome', ['timeout', 'invalid-receipt'])
def test_cli_uncertain_outcome_never_retries(monkeypatch, capsys, outcome):
    calls = []
    def request(path, payload, **kwargs):
        calls.append(payload)
        if payload['action'] == 'ping':
            return dict(ok=True, sso_identity_supported=True, sso_identity_protocol=1, sso_auth_methods=['google'])
        if outcome == 'timeout':
            raise TimeoutError
        return dict(ok=True, state='pending')
    monkeypatch.setattr(cli, 'request', request)
    assert cli.main(cli_args()) == 2
    captured = capsys.readouterr()
    assert captured.out == '' and 'check status and search before any retry' in captured.err
    assert len(calls) == 2


def test_lost_success_response_can_be_reconciled_by_search(deployed, monkeypatch, capsys):
    broker, _, path, socket = deployed
    real_request = cli.request
    def lose_response(path, payload, **kwargs):
        result = real_request(path, payload, **kwargs)
        if payload['action'] == 'create-sso-entry':
            assert result['state'] == 'saved'
            raise TimeoutError
        return result
    monkeypatch.setattr(cli, 'request', lose_response)
    with running_broker(socket.with_name('lost.sock'), broker):
        assert cli.main(['--socket', str(socket.with_name('lost.sock')), *cli_args()]) == 2
    assert 'uncertain' in capsys.readouterr().err
    assert len(reopened(path).find_entries(username=VALUES['username'])) == 1
    selected = broker.dispatch(dict(action='search', query=VALUES['title']))['entries'][0]
    assert selected['passwordless'] is True and selected['auth_method'] == 'google'


def test_actual_080_broker_is_not_dispatched_to(deployed, tmp_path):
    _, _, path, _ = deployed
    legacy = tmp_path / 'legacy'
    package = legacy / 'akdbx'
    package.mkdir(parents=True)
    baseline = '8e46770'
    names = subprocess.run(['git', 'ls-tree', '--name-only', baseline + ':src/agentic_kdbx'],
                           capture_output=True, text=True, check=True, timeout=10).stdout.splitlines()
    for name in names:
        data = subprocess.run(['git', 'show', baseline + ':src/agentic_kdbx/' + name],
                              capture_output=True, check=True, timeout=10).stdout
        (package / name).write_bytes(data)
    socket = tmp_path / 'legacy-runtime' / 'broker.sock'
    script = '''import signal,sys,threading
from pathlib import Path
from akdbx.broker import Broker,open_vault_with_password,serve
from test_writes import MASTER
from test_broker import RecordingTyper
stop=threading.Event()
signal.signal(signal.SIGTERM,lambda *_:stop.set())
serve(Path(sys.argv[2]),Broker(open_vault_with_password(Path(sys.argv[1]),MASTER),RecordingTyper()),stop)
'''
    environment = {**os.environ, 'PYTHONPATH': str(legacy) + os.pathsep + str(Path(__file__).parent)}
    process = subprocess.Popen([sys.executable, '-c', script, str(path), str(socket)], env=environment,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    before = path.read_bytes()
    try:
        deadline = time.monotonic() + 10
        while not socket.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert socket.exists()
        prefix = [str(Path(sys.executable).with_name('akdbx')), '--socket', str(socket)]
        status = subprocess.run([*prefix, 'status'], capture_output=True, text=True, timeout=10, check=True)
        assert json.loads(status.stdout)['version'] == '0.8.0'
        result = subprocess.run([*prefix, *cli_args()], capture_output=True, text=True, timeout=10)
        assert result.returncode == 1 and 'SSO creation not sent' in json.loads(result.stdout)['error']
        assert path.read_bytes() == before
        assert not list(path.parent.glob('.*.akdbx-backup-*'))
    finally:
        process.terminate()
        output, errors = process.communicate(timeout=10)
        assert MASTER.encode() not in output + errors
