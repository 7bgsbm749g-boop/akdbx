"""Native Windows IPC, ACL and encrypted persistence tests; no desktop input."""
import io
from contextlib import contextmanager
from http.client import HTTPSConnection
import json
import os
from pathlib import Path
import sys
import socket
import ssl
import subprocess
import threading
import time
import uuid
from types import SimpleNamespace
from urllib.parse import urlencode, urlsplit

import pytest

if sys.platform != 'win32':
    pytest.skip('native Windows APIs required', allow_module_level=True)

import pywintypes
import win32con
import win32file
import win32security
import ntsecuritycon
from pykeepass import PyKeePass, create_database

from akdbx import cli
from akdbx.broker import Broker, open_vault_with_password
from akdbx.persistence import SaveError
from akdbx import windows_rpc as rpc, windows_security as security
from akdbx.windows_store import WindowsVaultStore
from akdbx.windows_unlock import start_windows_unlock_server
from test_windows_unlock import certificates


@pytest.fixture
def private_dir(tmp_path):
    path = tmp_path / 'private'
    win32file.CreateDirectory(str(path), security.private_attributes())
    return path


@pytest.fixture
def synthetic_vault(private_dir):
    vault = create_database(io.BytesIO(), password='synthetic master')
    params = vault.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    params['I'].value, params['M'].value = 1, 1024 * 1024
    vault.add_entry(vault.root_group, 'Synthetic', 'synthetic-user', 'synthetic password',
                    url='https://example.test', notes='preserve notes')
    buffer = io.BytesIO()
    vault.save(buffer)
    path = private_dir / 'synthetic.kdbx'
    security.write_new(path, buffer.getvalue())
    return path


def test_windows_cli_imports_without_unix_dependencies():
    assert str(cli.default_socket()).startswith(r'\\.\pipe\akdbx-')
    assert cli.parser().parse_args(['status']).broker_uid is None
    with pytest.raises(SystemExit) as exit:
        cli.main(['--version'])
    assert exit.value.code == 0


def test_native_pipe_roundtrip_verifies_server_and_refuses_second_broker(monkeypatch):
    name = Path(r'\\.\pipe\akdbx-test-' + uuid.uuid4().hex)
    broker = Broker(None, object())
    stop, ready = threading.Event(), threading.Event()
    failures = []
    original = rpc.new_pipe
    def new_pipe(*args, **kwargs):
        result = original(*args, **kwargs)
        ready.set()
        return result
    monkeypatch.setattr(rpc, 'new_pipe', new_pipe)
    def run():
        try:
            rpc.serve(name, broker, stop)
        except BaseException as exc:
            failures.append(exc)
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        assert ready.wait(5)
        assert cli.request(name, {'action': 'ping'})['locked'] is True
        with pytest.raises(pywintypes.error):
            original(str(name), first=True)
        assert cli.request(name, {'action': 'ping'})['target_fill_delivery'] == 'win32-char-v1'
    finally:
        stop.set()
        thread.join(5)
    assert not thread.is_alive() and not failures
    # The first-instance flag permits a clean restart after all owned handles close.
    with security.managed_handle(original(str(name), first=True)):
        pass


@pytest.mark.parametrize('name', [r'\\server\pipe\akdbx-test', r'\\.\pipe\other',
                                 r'C:\tmp\broker.sock', r'\\.\pipe\akdbx-a\b'])
def test_remote_or_invalid_pipe_names_rejected(name):
    with pytest.raises(ValueError):
        rpc.pipe_name(Path(name))


def test_private_file_roundtrip_and_public_acl_refusal(private_dir):
    path = private_dir / 'synthetic-private'
    security.write_new(path, b'synthetic bytes')
    assert security.read_private(path)[0] == b'synthetic bytes'
    acl = win32security.ACL()
    user = win32security.ConvertStringSidToSid(security.current_identity()[0])
    everyone = win32security.CreateWellKnownSid(win32security.WinWorldSid)
    acl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, user)
    acl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.GENERIC_READ, everyone)
    win32security.SetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
                                     win32security.DACL_SECURITY_INFORMATION
                                     | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                                     None, None, acl, None)
    with pytest.raises(PermissionError):
        security.read_private(path)


def test_private_file_refused_under_unsafe_parent(private_dir):
    child = private_dir / 'child'
    win32file.CreateDirectory(str(child), security.private_attributes())
    path = child / 'synthetic-private'
    security.write_new(path, b'synthetic bytes')
    flags = (win32security.DACL_SECURITY_INFORMATION
             | win32security.PROTECTED_DACL_SECURITY_INFORMATION)
    descriptor = win32security.GetNamedSecurityInfo(
        str(private_dir), win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION)
    original_acl = descriptor.GetSecurityDescriptorDacl()
    public_acl = descriptor.GetSecurityDescriptorDacl()
    everyone = win32security.CreateWellKnownSid(win32security.WinWorldSid)
    public_acl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_DELETE_CHILD, everyone)
    win32security.SetNamedSecurityInfo(str(private_dir), win32security.SE_FILE_OBJECT,
                                     flags, None, None, public_acl, None)
    try:
        with pytest.raises(PermissionError, match='grants unsafe access'):
            security.read_private(path)
    finally:
        win32security.SetNamedSecurityInfo(str(private_dir), win32security.SE_FILE_OBJECT,
                                         flags, None, None, original_acl, None)
    assert security.read_private(path)[0] == b'synthetic bytes'


def test_native_encrypted_save_reopens_and_preserves_unrelated_data(synthetic_vault):
    vault = open_vault_with_password(synthetic_vault, 'synthetic master')
    store = vault._akdbx_store
    verified = store.commit(vault, lambda candidate: setattr(candidate.entries[0], 'password', 'synthetic new password'))
    assert verified.entries[0].password == 'synthetic new password'
    persisted = PyKeePass(str(synthetic_vault), password='synthetic master')
    assert persisted.entries[0].password == 'synthetic new password'
    assert persisted.entries[0].notes == 'preserve notes'
    backup = next(synthetic_vault.parent.glob('.*.akdbx-backup-*'))
    assert PyKeePass(str(backup), password='synthetic master').entries[0].password == 'synthetic password'
    receipt = next(synthetic_vault.parent.glob('.*.akdbx-commit-*.json'))
    data, _ = security.read_private(receipt)
    assert json.loads(data)['state'] == 'saved'
    assert b'synthetic new password' not in data
    reopened = open_vault_with_password(synthetic_vault, 'synthetic master')
    assert not reopened._akdbx_store.recovery_required


def test_external_edit_refused_without_replacing_disk(synthetic_vault):
    vault = open_vault_with_password(synthetic_vault, 'synthetic master')
    external = PyKeePass(str(synthetic_vault), password='synthetic master')
    external.entries[0].password = 'synthetic external edit'
    external.save()
    before = synthetic_vault.read_bytes()
    with pytest.raises(SaveError):
        vault._akdbx_store.commit(vault, lambda candidate: None)
    assert synthetic_vault.read_bytes() == before


@pytest.mark.parametrize('after_replace', [False, True])
def test_uncertain_save_survives_restart_and_blocks_use(synthetic_vault, monkeypatch, after_replace):
    vault = open_vault_with_password(synthetic_vault, 'synthetic master')
    store = vault._akdbx_store
    original = store._replace
    def fail(source, destination):
        if after_replace:
            original(source, destination)
        raise OSError('synthetic replace failure')
    monkeypatch.setattr(store, '_replace', fail)
    with pytest.raises(SaveError, match='uncertain'):
        store.commit(vault, lambda candidate: setattr(candidate.entries[0], 'password', 'synthetic uncertain update'))
    assert store.recovery_required
    reopened = open_vault_with_password(synthetic_vault, 'synthetic master')
    assert reopened._akdbx_store.recovery_required
    broker = Broker(reopened, object())
    assert not broker.dispatch({'action': 'search'})['ok']
    persisted = PyKeePass(str(synthetic_vault), password='synthetic master')
    assert persisted.entries[0].password == ('synthetic uncertain update' if after_replace else 'synthetic password')


@pytest.mark.parametrize('artifact', ['commit', 'merge', 'admission'])
def test_recovery_artifacts_match_a_differently_cased_vault_path(synthetic_vault, monkeypatch, artifact):
    if artifact == 'commit':
        vault = open_vault_with_password(synthetic_vault, 'synthetic master')
        store = vault._akdbx_store
        def fail(_source, _destination):
            raise OSError('synthetic replace failure')
        monkeypatch.setattr(store, '_replace', fail)
        with pytest.raises(SaveError, match='uncertain'):
            store.commit(vault, lambda candidate: setattr(candidate.entries[0], 'password', 'synthetic case update'))
    else:
        name = '.' + synthetic_vault.name + ('.akdbx-merge-' + 'c' * 32 if artifact == 'merge'
                                             else '.akdbx-admission.json')
        security.write_new(synthetic_vault.parent / name, b'{}')
    # NTFS opens the same vault through any spelling of its filename.
    differently_cased = synthetic_vault.with_name(synthetic_vault.name.upper())
    reopened = open_vault_with_password(differently_cased, 'synthetic master')
    assert reopened._akdbx_store.recovery_required
    assert not Broker(reopened, object()).dispatch({'action': 'search'})['ok']


def test_short_name_alias_finds_long_name_recovery(private_dir, synthetic_vault, monkeypatch):
    import win32api
    long_path = private_dir / 'synthetic-long-vault-name.kdbx'
    os.rename(synthetic_vault, long_path)
    short_path = Path(win32api.GetShortPathName(str(long_path)))
    if short_path.name.lower() == long_path.name.lower():
        pytest.skip('8.3 short names are disabled on this volume')
    vault = open_vault_with_password(long_path, 'synthetic master')
    store = vault._akdbx_store
    def fail(_source, _destination):
        raise OSError('synthetic replace failure')
    monkeypatch.setattr(store, '_replace', fail)
    with pytest.raises(SaveError, match='uncertain'):
        store.commit(vault, lambda candidate: setattr(candidate.entries[0], 'password', 'synthetic short update'))
    reopened = open_vault_with_password(short_path, 'synthetic master')
    assert reopened._akdbx_store.path.name == long_path.name
    assert reopened._akdbx_store.recovery_required


def test_name_folding_matches_ntfs_single_unit_uppercase():
    from akdbx.windows_store import fold_name
    assert fold_name('.Vault.kdbx.akdbx-commit-ab.json') == '.VAULT.KDBX.AKDBX-COMMIT-AB.JSON'
    assert fold_name('Écrin.kdbx') == fold_name('écrin.KDBX')
    assert fold_name('straße') == 'STRAßE'


def test_readonly_target_and_hard_links_disable_writes(synthetic_vault):
    vault = open_vault_with_password(synthetic_vault, 'synthetic master')
    store = vault._akdbx_store
    assert store.check_write_inputs()
    original = win32file.GetFileAttributes(str(synthetic_vault))
    try:
        win32file.SetFileAttributes(str(synthetic_vault), original | win32con.FILE_ATTRIBUTE_READONLY)
        assert store.check_write_inputs() is False
    finally:
        win32file.SetFileAttributes(str(synthetic_vault), original)
    link = synthetic_vault.parent / 'hard-link.kdbx'
    os.link(synthetic_vault, link)
    assert store.check_write_inputs() is False
    with pytest.raises(PermissionError):
        security.read_private(synthetic_vault)


def test_vault_through_directory_junction_is_refused(synthetic_vault, tmp_path):
    import _winapi
    junction = tmp_path / 'junction'
    _winapi.CreateJunction(str(synthetic_vault.parent), str(junction))
    try:
        with pytest.raises(PermissionError, match='unlinked'):
            security.read_private(junction / synthetic_vault.name)
        with pytest.raises((PermissionError, OSError, SaveError)):
            open_vault_with_password(junction / synthetic_vault.name, 'synthetic master')
    finally:
        os.rmdir(junction)
    assert security.read_private(synthetic_vault)[0]


def test_alternate_data_streams_are_refused(synthetic_vault):
    with pytest.raises(PermissionError):
        security.read_private(str(synthetic_vault) + ':stream')


def test_merge_without_a_trusted_engine_is_unavailable_and_refuses(synthetic_vault, monkeypatch):
    from akdbx import windows_merge
    monkeypatch.setattr(windows_merge, 'engine_version', lambda: None)
    broker = Broker(open_vault_with_password(synthetic_vault, 'synthetic master'), object())
    status = broker.dispatch({'action': 'ping'})
    assert status['merge_available'] is False and status['merge_engine'] is None
    before = synthetic_vault.read_bytes()
    for action in ('merge', 'admit'):
        result = broker.dispatch({'action': action, 'source': str(synthetic_vault), 'operation_id': 'a' * 32,
                                  'policy': 'snapshot-admission-v1', 'verification': 'native-containment-v1',
                                  'snapshot_directory': str(synthetic_vault.parent)})
        assert not result['ok'] and 'merge unavailable' in result['error'], result
    assert 'receipt not found' in broker.dispatch({'action': 'merge-status', 'operation_id': 'a' * 32})['error']
    assert synthetic_vault.read_bytes() == before
    assert sorted(p.name for p in synthetic_vault.parent.iterdir() if 'akdbx-merge' in p.name) == []


def test_user_owned_engine_is_not_trusted(private_dir):
    """A program that this account can replace is never run as the merge engine."""
    from akdbx import windows_merge
    engine = private_dir / 'keepassxc-cli.exe'
    security.write_new(engine, b'MZ synthetic')
    with pytest.raises(PermissionError):
        with windows_merge.trusted_engine(engine):
            pytest.fail('a user-owned engine was accepted')
    # The installed engine, when present, is the only candidate; never PATH.
    assert windows_merge.engine_path().name == 'keepassxc-cli.exe'
    assert 'KeePassXC' in windows_merge.engine_path().parts


def test_until_unlock_subscriptions_survive_a_broker_restart(private_dir):
    from akdbx.notifications import UnlockNotifications
    state = private_dir / 'state' / 'unlock-notifications.json'
    sent = []
    first = UnlockNotifications(state_path=state, sender=lambda url, payload: sent.append((url, payload)))
    receipt = first.subscribe({'notification_protocol': 1, 'webhook_url': 'https://hooks.example.test/synthetic-token'},
                              unlocked=False)
    assert receipt['ok'] and receipt['state'] == 'subscribed' and receipt['expires_in'] is None
    # The folder was created for this user and SYSTEM only.
    with security.checked_handle(state.parent, directory=True):
        pass
    assert json.loads(security.read_private(state)[0])[0]['id'] == receipt['subscription_id']
    first._stop.set()  # A stopped broker: its waiting subscription stays on disk.
    restarted = UnlockNotifications(state_path=state, sender=lambda url, payload: sent.append((url, payload)))
    assert restarted.status(receipt['subscription_id'])['state'] == 'subscribed'
    restarted.publish()
    deadline = time.monotonic() + 5
    while not sent and time.monotonic() < deadline:
        time.sleep(.02)
    assert [(url, payload['event'], payload['subscription_id']) for url, payload in sent] == [
        ('https://hooks.example.test/synthetic-token', 'akdbx.unlocked', receipt['subscription_id'])]
    deadline = time.monotonic() + 5
    while restarted.status(receipt['subscription_id'])['state'] != 'delivered' and time.monotonic() < deadline:
        time.sleep(.02)
    restarted.close()
    assert json.loads(security.read_private(state)[0]) == []


@pytest.mark.parametrize('damage', ['public-folder', 'public-file', 'malformed', 'oversized', 'relative'])
def test_untrusted_notification_state_is_refused_without_repair(private_dir, damage):
    from akdbx.notifications import UnlockNotifications
    folder = private_dir / 'state'
    win32file.CreateDirectory(str(folder), security.private_attributes(directory=True))
    state = folder / 'unlock-notifications.json'
    row = {'id': 'a' * 32, 'url': 'https://hooks.example.test/synthetic-token', 'event_id': 'b' * 32, 'attempts': 0}
    security.write_new(state, b'x' * (512 * 1024 + 1) if damage == 'oversized'
                       else b'{"synthetic":' if damage == 'malformed' else json.dumps([row]).encode())
    public = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor('D:P(A;;FA;;;WD)', 1)
    if damage in {'public-folder', 'public-file'}:
        win32security.SetFileSecurity(str(folder if damage == 'public-folder' else state),
                                      win32security.DACL_SECURITY_INFORMATION, public)
    path = Path('relative-state.json') if damage == 'relative' else state
    with pytest.raises((ValueError, PermissionError)):
        UnlockNotifications(state_path=path)
    # A refused folder or file keeps its permissions: the broker never repairs it.
    if damage in {'public-folder', 'public-file'}:
        target = folder if damage == 'public-folder' else state
        dacl = win32security.GetFileSecurity(str(target), win32security.DACL_SECURITY_INFORMATION).GetSecurityDescriptorDacl()
        assert win32security.ConvertSidToStringSid(dacl.GetAce(0)[2]) == 'S-1-1-0'


@pytest.fixture
def native_https_config(synthetic_vault, certificates):
    certificate, key = synthetic_vault.parent / 'cert.pem', synthetic_vault.parent / 'key.pem'
    security.write_new(certificate, certificates[0].read_bytes())
    security.write_new(key, certificates[1].read_bytes())
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    origin = f'https://127.0.0.1:{port}'
    context = ssl.create_default_context(cafile=str(certificate))

    def submit(url, values):
        connection = HTTPSConnection('127.0.0.1', port, context=context, timeout=10)
        parsed = urlsplit(url)
        try:
            connection.request('POST', parsed.path + '?' + parsed.query, urlencode(values),
                               {'Content-Type': 'application/x-www-form-urlencoded', 'Origin': origin})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    return origin, certificate, key, submit


def test_windows_cli_serves_and_searches_synthetic_vault(synthetic_vault, native_https_config):
    origin, certificate, key, submit = native_https_config
    pipe = rpc.PREFIX + 'akdbx-test-' + uuid.uuid4().hex
    command = [sys.executable, '-m', 'akdbx.cli', '--socket', pipe, '--unlock-origin', origin]
    with subprocess.Popen(
        [*command, 'serve', str(synthetic_vault), '--tls-cert', str(certificate), '--tls-key', str(key)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ) as server:
        try:
            deadline = time.monotonic() + 10
            while True:
                status = subprocess.run([*command, 'status'], capture_output=True, text=True, timeout=10)
                if status.returncode == 0:
                    break
                assert server.poll() is None, 'Windows CLI broker exited during startup'
                assert time.monotonic() < deadline, 'Windows CLI broker did not become ready'
                time.sleep(0.05)
            locked = json.loads(status.stdout)
            assert locked['locked'] and locked['target_fill_delivery'] == 'win32-char-v1'
            assert submit(locked['unlock_url'], {'password': 'synthetic master'})[0] == 200

            search = subprocess.run([*command, 'search', 'example.test'],
                                    capture_output=True, text=True, timeout=10)
            assert search.returncode == 0
            result = json.loads(search.stdout)
            assert [entry['username'] for entry in result['entries']] == ['synthetic-user']
            assert 'synthetic password' not in search.stdout
        finally:
            server.terminate()
            server.wait(timeout=5)


def test_windows_cli_blocks_the_link_after_three_failures_and_makes_a_new_one(synthetic_vault, native_https_config):
    origin, certificate, key, submit = native_https_config
    pipe = rpc.PREFIX + 'akdbx-test-' + uuid.uuid4().hex
    command = [sys.executable, '-m', 'akdbx.cli', '--socket', pipe, '--unlock-origin', origin]
    state = synthetic_vault.parent / 'state' / 'unlock-notifications.json'
    flag = state.with_name(state.name + '.unlock-blocked')

    def run(*args):
        result = subprocess.run([*command, *args], capture_output=True, text=True, timeout=10)
        return result.returncode, json.loads(result.stdout) if result.stdout.strip() else None

    def start():
        return subprocess.Popen(
            [*command, 'serve', str(synthetic_vault), '--tls-cert', str(certificate), '--tls-key', str(key),
             '--notification-state', str(state)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def restart_on_new_port():
        # SO_EXCLUSIVEADDRUSE can refuse the old port while its connections
        # are in TIME_WAIT, so the restarted broker uses another port.
        nonlocal origin, command, submit
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        origin = f'https://127.0.0.1:{port}'
        command = [sys.executable, '-m', 'akdbx.cli', '--socket', pipe, '--unlock-origin', origin]
        context = ssl.create_default_context(cafile=str(certificate))

        def submit(url, values):
            connection = HTTPSConnection('127.0.0.1', port, context=context, timeout=10)
            parsed = urlsplit(url)
            try:
                connection.request('POST', parsed.path + '?' + parsed.query, urlencode(values),
                                   {'Content-Type': 'application/x-www-form-urlencoded', 'Origin': origin})
                response = connection.getresponse()
                return response.status, response.read()
            finally:
                connection.close()
        return start()

    def ready(server):
        deadline = time.monotonic() + 10
        while True:
            code, status = run('status')
            if code == 0:
                return status
            assert server.poll() is None, 'Windows CLI broker exited during startup'
            assert time.monotonic() < deadline, 'Windows CLI broker did not become ready'
            time.sleep(0.05)

    with start() as server:
        try:
            locked = ready(server)
            old = locked['unlock_url']
            assert locked['unlock_link_protocol'] == 1 and 'unlock_blocked' not in locked
            # Refused while the link still works: the CLI does not send it.
            code, refused = run('new-unlock-link', '--user-confirmed')
            assert code == 1 and 'not blocked' in refused['error']

            statuses = [submit(old, {'password': f'wrong-{index}'})[0] for index in range(3)]
            assert statuses == [401, 401, 403]
            status, page = submit(old, {'password': 'synthetic master'})
            assert status == 403 and b'Ask your agent for a new unlock link' in page
            code, blocked = run('status')
            assert code == 0 and blocked['locked'] is True and blocked['unlock_blocked'] is True
            assert 'unlock_url' not in blocked
            assert blocked['unlock_origin'] == origin
            code, search = run('search', 'example.test')
            assert code == 1 and search == {'ok': False, 'error': 'vault locked', 'unlock_blocked': True}
        finally:
            server.terminate()
            server.wait(timeout=5)
    # The block is saved privately and survives a broker restart.
    assert json.loads(security.read_private(flag)[0]) == {'blocked': True}
    with restart_on_new_port() as server:
        try:
            blocked = ready(server)
            assert blocked['locked'] is True and blocked['unlock_blocked'] is True and 'unlock_url' not in blocked
            code, receipt = run('new-unlock-link', '--user-confirmed')
            assert code == 0 and receipt['ok'] is True and receipt['locked'] is True
            fresh = receipt['unlock_url']
            assert fresh.startswith(origin + '/?token=') and fresh != old
            assert submit(origin + '/?' + urlsplit(old).query, {'password': 'synthetic master'})[0] == 404
            assert submit(fresh, {'password': 'synthetic master'})[0] == 200
            code, unlocked = run('status')
            assert code == 0 and unlocked['locked'] is False and 'unlock_blocked' not in unlocked
            assert json.loads(security.read_private(flag)[0]) == {'blocked': False}
        finally:
            server.terminate()
            server.wait(timeout=5)


def test_unlock_block_flag_is_private_and_untrusted_flags_fail_closed(private_dir):
    from akdbx.broker import Broker
    from akdbx.notifications import UnlockNotifications
    from akdbx.web_unlock import UnlockState
    state = private_dir / 'state' / 'unlock-notifications.json'
    flag = state.with_name(state.name + '.unlock-blocked')
    first = UnlockNotifications(state_path=state)
    assert first.load_unlock_blocked() is False
    first.save_unlock_blocked(False)
    assert not state.parent.exists()  # clearing a block that was never saved writes nothing
    first.save_unlock_blocked(True)
    with security.checked_handle(state.parent, directory=True):
        pass
    assert json.loads(security.read_private(flag)[0]) == {'blocked': True}
    first.close()
    assert UnlockNotifications(state_path=state).load_unlock_blocked() is True
    broker = Broker(None, object(), notification_state_path=state)
    assert UnlockState(broker, private_dir / 'unused.kdbx', None, public_base='https://127.0.0.1:9').blocked
    broker.unlock_notifications.close()
    # A flag that another user can write is refused, so the link stays blocked.
    public = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor('D:P(A;;FA;;;WD)', 1)
    security.replace_private(flag, json.dumps({'blocked': False}).encode())
    win32security.SetFileSecurity(str(flag), win32security.DACL_SECURITY_INFORMATION, public)
    with pytest.raises((ValueError, PermissionError, pywintypes.error)):
        UnlockNotifications(state_path=state).load_unlock_blocked()
    broker = Broker(None, object(), notification_state_path=state)
    assert UnlockState(broker, private_dir / 'unused.kdbx', None, public_base='https://127.0.0.1:9').blocked
    broker.unlock_notifications.close()


def test_native_https_unlock_password_totp_and_identity_saves(synthetic_vault, native_https_config):
    origin, certificate, key, submit = native_https_config
    broker = Broker(None, object())
    server, unlock_url = start_windows_unlock_server(broker, synthetic_vault, None, origin, certificate, key)

    def prepare(action):
        selected = broker.dispatch({'action': 'search', 'query': 'Synthetic'})['entries'][0]
        return broker.dispatch({'action': action, 'handle': selected['handle'],
                                'metadata': {key: selected[key] for key in ('title', 'username', 'url', 'group')}})
    try:
        assert submit(unlock_url, {'password': 'synthetic master'})[0] == 200
        assert broker.dispatch({'action': 'ping'})['writes_available'] is True
        password = prepare('update-password')
        assert password['ok']
        assert submit(password['private_url'], {'password': 'synthetic HTTPS update',
                      'confirmation': 'synthetic HTTPS update', 'confirmed': 'yes'})[0] == 200
        assert broker.dispatch({'action': 'write-status', 'write_handle': password['write_handle']})['state'] == 'saved'
        totp = prepare('setup-totp')
        assert totp['ok']
        assert submit(totp['private_url'], {'setup': 'JBSWY3DPEHPK3PXP', 'confirmed': 'yes'})[0] == 200
        identity = broker.dispatch({'action': 'create-sso-entry', 'auth_method': 'google',
            'metadata': {'title': 'Synthetic SSO', 'username': 'sso-user', 'url': 'https://sso.test', 'group': ''}})
        assert identity['ok'] and identity['state'] == 'saved'
        persisted = PyKeePass(str(synthetic_vault), password='synthetic master')
        entry = next(entry for entry in persisted.entries if entry.title == 'Synthetic')
        assert entry.password == 'synthetic HTTPS update' and entry.otp.startswith('otpauth://totp/')
        assert entry.notes == 'preserve notes'
    finally:
        server.shutdown()
        server.server_close()
        broker.unlock_notifications.close()


@pytest.mark.parametrize('failure', [ValueError('synthetic private detail'),
    OSError('synthetic private detail'), pywintypes.error(5, 'synthetic', 'synthetic private detail')])
def test_windows_serve_startup_errors_are_clean_and_private(monkeypatch, capsys, failure):
    def fail(*_args, **_kwargs):
        raise failure
    monkeypatch.setattr('akdbx.windows_unlock.start_windows_unlock_server', fail)
    assert cli.main(['--socket', str(rpc.default_pipe()), 'serve', 'unused.kdbx']) == 2
    captured = capsys.readouterr()
    assert not captured.out and 'could not start Windows HTTPS unlock' in captured.err
    assert 'synthetic private detail' not in captured.err and 'Traceback' not in captured.err


@pytest.mark.parametrize('stage', ['validation', 'write', 'flush'])
def test_failed_new_file_is_removed(private_dir, monkeypatch, stage):
    path = private_dir / 'partial-private-file'
    def fail(*_args, **_kwargs):
        raise OSError('synthetic file failure')
    if stage == 'validation':
        original = security.check_acl
        def check(handle, *, private=True):
            if private:
                fail()
            original(handle, private=private)
        monkeypatch.setattr(security, 'check_acl', check)
    else:
        monkeypatch.setattr(win32file, 'WriteFile' if stage == 'write' else 'FlushFileBuffers', fail)
    with pytest.raises(OSError, match='synthetic file failure'):
        security.write_new(path, b'synthetic partial bytes')
    assert not path.exists()


def test_new_file_collision_preserves_existing_bytes(private_dir):
    path = private_dir / 'existing-private-file'
    security.write_new(path, b'synthetic original')
    with pytest.raises(pywintypes.error):
        security.write_new(path, b'synthetic replacement')
    assert security.read_private(path)[0] == b'synthetic original'


def test_recovery_readiness_during_save_is_busy_without_latching(synthetic_vault, monkeypatch):
    vault = open_vault_with_password(synthetic_vault, 'synthetic master')
    store = vault._akdbx_store
    prepared, release = threading.Event(), threading.Event()
    failures, saved = [], []
    original = security.write_new
    def pause_receipt(path, data):
        original(path, data)
        if '.akdbx-commit-' in Path(path).name:
            prepared.set()
            assert release.wait(5)
    monkeypatch.setattr(security, 'write_new', pause_receipt)
    def save():
        try:
            saved.append(store.commit(vault, lambda candidate: setattr(candidate.entries[0], 'password', 'synthetic concurrent update')))
        except BaseException as error:
            failures.append(error)
    worker = threading.Thread(target=save, daemon=True)
    worker.start()
    try:
        assert prepared.wait(5)
        assert store.check_write_inputs() is False
        assert store.recovery_required is False
        opening = WindowsVaultStore(synthetic_vault)
        with pytest.raises(SaveError, match='busy'):
            opening.open('synthetic master')
        assert opening.recovery_required is False
    finally:
        release.set()
        worker.join(5)
    assert not worker.is_alive() and not failures and len(saved) == 1
    assert store.check_write_inputs() and not store.recovery_required
    assert PyKeePass(str(synthetic_vault), password='synthetic master').entries[0].password == 'synthetic concurrent update'
    reopened = opening.open('synthetic master')
    assert not reopened._akdbx_store.recovery_required
    assert reopened.entries[0].password == 'synthetic concurrent update'


@pytest.mark.parametrize('cleanup_fails', [False, True])
def test_pre_replace_abort_cleans_receipt_or_latches_cleanup_failure(synthetic_vault, monkeypatch, cleanup_fails):
    vault = open_vault_with_password(synthetic_vault, 'synthetic master')
    store = vault._akdbx_store
    external = PyKeePass(str(synthetic_vault), password='synthetic master')
    original = security.write_new
    def edit_after_receipt(path, data):
        original(path, data)
        if '.akdbx-commit-' in Path(path).name:
            external.entries[0].password = 'synthetic external save'
            external.save()
    monkeypatch.setattr(security, 'write_new', edit_after_receipt)
    if cleanup_fails:
        unlink = Path.unlink
        def refuse_receipt(path, *args, **kwargs):
            if '.akdbx-commit-' in path.name:
                raise OSError('synthetic cleanup denial')
            return unlink(path, *args, **kwargs)
        monkeypatch.setattr(Path, 'unlink', refuse_receipt)
    with pytest.raises(SaveError, match='changed on disk'):
        store.commit(vault, lambda candidate: None)
    assert store.recovery_required is cleanup_fails
    receipts = list(synthetic_vault.parent.glob('.*.akdbx-commit-*.json'))
    assert bool(receipts) is cleanup_fails
    reopened = open_vault_with_password(synthetic_vault, 'synthetic master')
    assert reopened._akdbx_store.recovery_required is cleanup_fails
    assert reopened.entries[0].password == 'synthetic external save'


@pytest.mark.parametrize('receipt_state', ['saved', 'prepared'])
def test_recovery_scan_ignores_unrelated_entries_but_finds_receipts(synthetic_vault, monkeypatch, receipt_state):
    store = WindowsVaultStore(synthetic_vault)
    receipt = synthetic_vault.parent / ('.' + synthetic_vault.name + '.akdbx-commit-' + 'a' * 32 + '.json')
    security.write_new(receipt, json.dumps({'state': receipt_state, 'policy': 'windows-save-v1',
                       'previous_sha256': '0' * 64, 'candidate_sha256': '1' * 64}).encode())
    @contextmanager
    def scan(_path):
        def entries():
            for index in range(10001):
                yield SimpleNamespace(name=f'unrelated-{index}')
            yield SimpleNamespace(name=receipt.name)
        yield entries()
    monkeypatch.setattr('akdbx.windows_store.os.scandir', scan)
    store._check_recovery()
    assert store.recovery_required is (receipt_state == 'prepared')


def test_matching_recovery_artifacts_still_have_a_budget(synthetic_vault, monkeypatch):
    store = WindowsVaultStore(synthetic_vault)
    prefix = '.' + synthetic_vault.name + '.akdbx-backup-'
    @contextmanager
    def scan(_path):
        yield (SimpleNamespace(name=prefix + str(index)) for index in range(10001))
    monkeypatch.setattr('akdbx.windows_store.os.scandir', scan)
    with pytest.raises(SaveError, match='scan budget'):
        store._check_recovery()


@pytest.mark.parametrize('stage', ['validation', 'write', 'flush'])
def test_cleanup_denial_preserves_original_file_error(private_dir, monkeypatch, stage):
    path = private_dir / 'cleanup-denied-file'
    primary = PermissionError('synthetic validation failure') if stage == 'validation' else OSError('synthetic I/O failure')
    def fail(*_args, **_kwargs):
        raise primary
    if stage == 'validation':
        original = security.check_acl
        def check(handle, *, private=True):
            if private:
                fail()
            original(handle, private=private)
        monkeypatch.setattr(security, 'check_acl', check)
    else:
        monkeypatch.setattr(win32file, 'WriteFile' if stage == 'write' else 'FlushFileBuffers', fail)
    unlink = Path.unlink
    def deny(created, *args, **kwargs):
        if created == path:
            raise OSError('synthetic cleanup failure')
        return unlink(created, *args, **kwargs)
    monkeypatch.setattr(Path, 'unlink', deny)
    with pytest.raises(type(primary)) as error:
        security.write_new(path, b'synthetic bytes')
    assert error.value is primary and path.exists()


@pytest.mark.parametrize('data', [b'{"state":', b'\xffinvalid UTF-8', b'x' * 16385])
def test_malformed_receipt_unlocks_into_blocked_recovery(synthetic_vault, data):
    receipt = synthetic_vault.parent / ('.' + synthetic_vault.name + '.akdbx-commit-' + 'b' * 32 + '.json')
    security.write_new(receipt, data)
    reopened = open_vault_with_password(synthetic_vault, 'synthetic master')
    broker = Broker(reopened, object())
    status = broker.dispatch({'action': 'ping'})
    assert status['locked'] is False and status['recovery_required'] is True
    assert status['writes_available'] is False
    assert broker.dispatch({'action': 'search'})['ok'] is False


PASSWORD_COMMANDS = [['fill', 'synthetic', '--mode', 'password', '--target', 'synthetic'],
                     ['fill', 'synthetic', '--mode', 'login', '--target', 'synthetic'],
                     ['fill', 'synthetic', '--target', 'synthetic'],
                     ['fill-generated', 'synthetic', '--target-url', 'https://example.test/reset',
                      '--target', 'synthetic'],
                     ['pin-password-target', '--page-id', 'synthetic', '--frame-id', 'synthetic',
                      '--top-url', 'https://example.test/login', '--selector', '#password']]


def status_of(broker, **changes):
    return {**broker.dispatch({'action': 'ping'}), **changes}


@pytest.mark.parametrize('argv', PASSWORD_COMMANDS)
@pytest.mark.parametrize('missing', ['profile', 'delivery'])
def test_windows_cli_refuses_password_requests_the_broker_cannot_deliver(monkeypatch, capsys, argv, missing):
    """Only the capability check reaches the broker; the credential request is never sent."""
    capabilities = status_of(Broker(type('Vault', (), {'entries': []})(), object()))
    assert capabilities['password_browser_configured'] is False
    if missing == 'delivery':
        capabilities = {**capabilities, 'password_browser_configured': True, 'password_fill_delivery': 'win32-char-v1'}
    sent = []
    def request(_socket, payload, **_options):
        sent.append(payload['action'])
        return capabilities
    monkeypatch.setattr(cli, 'request', request)
    assert cli.main(argv) == 1
    captured = capsys.readouterr()
    assert sent == ['ping'] and not captured.err
    expected = cli.PASSWORD_BROWSER_REFUSAL if missing == 'profile' else 'broker lacks DOM password delivery; target request not sent'
    assert json.loads(captured.out) == {'ok': False, 'error': expected}


@pytest.mark.parametrize('argv', [['pin-card-target', '--page-id', 'synthetic', '--frame-id', 'synthetic',
                                   '--top-url', 'https://example.test/pay', '--frame-url', 'https://example.test/pay',
                                   '--selector', '#number', '--field', 'cc-number'],
                                  ['fill-card', 'synthetic', '--target', 'synthetic', '--field', 'cc-number'],
                                  ['merge', 'synthetic.kdbx'],
                                  ['admit', 'synthetic.kdbx', '--policy', 'snapshot-admission-v1',
                                   '--snapshot-dir', 'synthetic']])
def test_windows_cli_refuses_card_and_merge_requests_the_broker_cannot_deliver(monkeypatch, capsys, argv):
    capabilities = status_of(Broker(type('Vault', (), {'entries': []})(), object()))
    assert capabilities['card_browser_configured'] is False and capabilities['merge_available'] is False
    sent = []
    def request(_socket, payload, **_options):
        sent.append(payload['action'])
        return capabilities
    monkeypatch.setattr(cli, 'request', request)
    assert cli.main(argv) == 1
    captured = capsys.readouterr()
    assert set(sent) == {'ping'}
    expected = cli.MERGE_UNAVAILABLE_REFUSAL if argv[0] in {'merge', 'admit'} else cli.card_cli.CARD_BROWSER_REFUSAL
    assert json.loads(captured.out) == {'ok': False, 'error': expected}


def test_windows_cli_sends_a_merge_to_a_locked_broker_for_its_unlock_link(monkeypatch, capsys):
    sent = []
    def request(_socket, payload, **_options):
        sent.append(payload['action'])
        if payload['action'] == 'ping':
            return {'ok': True, 'locked': True, 'merge_available': False}
        return {'ok': False, 'error': 'vault locked', 'unlock_url': 'https://localhost:9443/?token=synthetic'}
    monkeypatch.setattr(cli, 'request', request)
    assert cli.main(['merge', 'synthetic.kdbx']) == 1
    answer = json.loads(capsys.readouterr().out)
    assert sent == ['ping', 'merge'] and answer['error'] == 'vault locked' and 'continuation' in answer


def test_windows_status_advertises_the_dom_route_only_with_a_profile(private_dir):
    from akdbx.browser_password import DELIVERY
    idle = status_of(Broker(type('Vault', (), {'entries': []})(), object()))
    ready = status_of(Broker(type('Vault', (), {'entries': []})(), object(), password_browser_profile=private_dir,
                             card_browser_profile=private_dir))
    for status in (idle, ready):
        assert status['target_fill_delivery'] == 'win32-char-v1' and status['target_fill_modes'] == ['username']
        assert status['password_fill_protocol'] == 1 and status['password_fill_delivery'] == DELIVERY
        assert status['unlock_notifications_until_unlock'] is True and status['generated_entry_protocol'] == 1
    assert (idle['password_browser_configured'], idle['card_browser_configured']) == (False, False)
    assert (ready['password_browser_configured'], ready['card_browser_configured']) == (True, True)


def test_windows_serve_accepts_browser_profiles_and_private_state(synthetic_vault, native_https_config, monkeypatch):
    origin, certificate, key, _submit = native_https_config
    served = []
    def serve(socket_path, broker, stop=None):
        served.append(broker)
    monkeypatch.setattr(cli, 'serve', serve)
    state = synthetic_vault.parent / 'run' / 'unlock-notifications.json'
    assert cli.main(['--socket', rpc.PREFIX + 'akdbx-test-' + uuid.uuid4().hex, '--unlock-origin', origin,
                     'serve', str(synthetic_vault), '--tls-cert', str(certificate), '--tls-key', str(key),
                     '--password-browser-profile', str(synthetic_vault.parent),
                     '--card-browser-profile', str(synthetic_vault.parent),
                     '--notification-state', str(state)]) == 0
    broker = served[0]
    assert broker.passwords.profile == synthetic_vault.parent and broker.card_targets.profile == synthetic_vault.parent
    # A broker without subscriptions writes no state and creates no folder.
    assert broker.unlock_notifications._state_path == state and not state.parent.exists()
    assert str(cli.default_notification_state(Path(rpc.PREFIX + 'akdbx-synthetic'))).endswith(
        r'\akdbx\akdbx-synthetic.unlock-notifications.json')


def test_capture_pipe_name_is_the_rpc_pipe_plus_capture():
    base = rpc.PREFIX + 'akdbx-synthetic'
    assert str(rpc.capture_pipe(Path(base))) == base + '-capture'
    with pytest.raises(ValueError):
        rpc.capture_pipe(Path(base + '-capture'))
    longest = rpc.PREFIX + 'akdbx-' + 'a' * 160  # still a valid RPC pipe
    assert str(rpc.capture_pipe(Path(longest))) == longest + '-capture'


def test_native_host_capture_through_the_capture_pipe(synthetic_vault, native_https_config):
    from akdbx import browser_import
    origin, certificate, key, submit = native_https_config
    # The longest valid RPC name: its capture pipe exceeds the RPC limit by the suffix.
    rpc_pipe = Path(rpc.PREFIX + 'akdbx-' + ('test-' + uuid.uuid4().hex).ljust(160, 'x'))
    capture = rpc.capture_pipe(rpc_pipe)
    broker = Broker(None, object())
    server, unlock_url = start_windows_unlock_server(broker, synthetic_vault, None, origin, certificate, key,
                                                     capture_pipe=capture)
    try:
        # A second broker cannot take the capture pipe name.
        with pytest.raises(pywintypes.error):
            rpc.new_pipe(str(capture), first=True)
        assert submit(unlock_url, {'password': 'synthetic master'})[0] == 200
        selected = broker.dispatch({'action': 'search', 'query': 'Synthetic'})['entries'][0]
        prepared = broker.dispatch({'action': 'setup-totp', 'handle': selected['handle'],
                                    'metadata': {k: selected[k] for k in ('title', 'username', 'url', 'group')}})
        assert prepared['ok']
        config = {'extension_id': 'a' * 32, 'origin': origin, 'socket': str(capture)}
        uri = 'otpauth://totp/Example:synthetic-user?secret=JBSWY3DPEHPK3PXP&issuer=Example'
        message = {'private_url': prepared['private_url'], 'source_url': 'https://example.test/setup', 'payloads': [uri]}
        with pytest.raises(ValueError):
            browser_import.capture({**message, 'source_url': 'https://evil.test/setup'}, config)
        with pytest.raises(ValueError):  # the agent RPC pipe is never a capture endpoint
            browser_import.capture(message, {**config, 'socket': str(rpc_pipe)})
        before = synthetic_vault.read_bytes()
        assert browser_import.capture(message, config) == browser_import.RECEIPT
        assert synthetic_vault.read_bytes() == before
        with pytest.raises(ValueError):  # replay
            browser_import.capture(message, config)
        assert broker.writes.get(prepared['write_handle']).import_candidates
    finally:
        server.shutdown()
        server.server_close()
        broker.unlock_notifications.close()
    # Shutdown released the capture pipe: a new broker can create it.
    with security.managed_handle(rpc.new_pipe(str(capture), first=True)):
        pass


def test_native_host_install_registers_one_browser_and_uninstalls(private_dir, monkeypatch):
    import winreg
    from akdbx import browser_import, extension_host
    test_key = r'Software\akdbx-test-' + uuid.uuid4().hex
    monkeypatch.setitem(extension_host.WINDOWS_KEYS, 'chrome', test_key + r'\Chrome')
    monkeypatch.setitem(extension_host.WINDOWS_KEYS, 'edge', test_key + r'\Edge')
    monkeypatch.setenv('LOCALAPPDATA', str(private_dir))
    pipe = rpc.PREFIX + 'akdbx-synthetic-capture'
    def args(browser, **extra):
        return SimpleNamespace(extension_id='a' * 32, origin='https://node.tailnet.ts.net:9443',
                               browser=browser, socket=extra.get('socket', pipe))
    try:
        where = browser_import.install_host_windows(args('chrome'))
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, where['key']) as handle:
            assert winreg.QueryValueEx(handle, '')[0] == str(where['manifest'])
        manifest = json.loads(where['manifest'].read_text())
        # The console script itself, not a batch file that cmd.exe decodes.
        assert manifest['path'] == str(browser_import.host_executable())
        assert manifest['path'].endswith('akdbx-browser-import.exe')
        assert manifest['allowed_origins'] == ['chrome-extension://' + 'a' * 32 + '/']
        assert browser_import.load_config(browser_import.config_path())['socket'] == pipe
        with pytest.raises(ValueError):  # never replaces a registration
            browser_import.install_host_windows(args('chrome'))
        with pytest.raises(ValueError):  # a second browser must share the configuration
            browser_import.install_host_windows(args('edge', socket=rpc.PREFIX + 'akdbx-other-capture'))
        assert browser_import.install_host_windows(args('edge'))['key'].endswith(r'\Edge\org.akdbx.private_import')
        browser_import.uninstall_host_windows(SimpleNamespace(browser='chrome'))
        with pytest.raises(OSError):
            winreg.OpenKey(winreg.HKEY_CURRENT_USER, where['key'])
        assert not where['manifest'].exists()
        assert browser_import.config_path().exists()  # Edge still uses it.
        browser_import.uninstall_host_windows(SimpleNamespace(browser='edge'))
        assert not browser_import.config_path().exists()
        # With the last registration gone, a new origin and the default pipe install.
        moved = browser_import.install_host_windows(SimpleNamespace(
            extension_id='a' * 32, origin='https://localhost:9443', browser='chrome', socket=None))
        config = browser_import.load_config(browser_import.config_path())
        assert config['origin'] == 'https://localhost:9443' and config['socket'] == ''
        assert moved['key'] == where['key']
        browser_import.uninstall_host_windows(SimpleNamespace(browser='chrome'))
        with pytest.raises(ValueError):  # the RPC pipe is refused as a capture endpoint
            browser_import._check_config({'extension_id': 'a' * 32, 'origin': 'https://x.test',
                                          'socket': rpc.PREFIX + 'akdbx-synthetic'})
    finally:
        for browser in ('chrome', 'edge'):
            browser_import.uninstall_host_windows(SimpleNamespace(browser=browser))
        for name in (r'\Edge', r'\Chrome', ''):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, test_key + name)
            except OSError:
                pass


def _relay_config(enabled=True):
    from akdbx.relay import RelayConfig
    return RelayConfig('https://relay.akdbx.link:8443', 'abcdefghijkl.akdbx.link', 'abcdefghijkl', 8443,
                       enabled, 'S' * 43)


def _relay_tls(name):
    """A key and a self-signed certificate for ``name`` in one PEM, as relay enable saves it."""
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from akdbx.relay import new_key_and_csr
    key_pem, _ = new_key_and_csr(name)
    key = serialization.load_pem_private_key(key_pem, password=None)
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(x509.Name([])).issuer_name(x509.Name([]))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=True)
            .sign(key, hashes.SHA256()))
    return key_pem + cert.public_bytes(serialization.Encoding.PEM)


def test_relay_directory_is_private_per_user_and_refuses_public_files(private_dir, monkeypatch):
    from akdbx import relay
    monkeypatch.setenv('LOCALAPPDATA', str(private_dir))
    store = relay.RelayStore()
    assert store.directory == private_dir / 'akdbx' / 'relay'
    assert store.load() is None and relay.saved_origin(store) is None
    config = _relay_config()
    store.save(config)
    store.save_tls(_relay_tls(config.name))
    assert store.load() == config
    assert relay.saved_origin(store) == 'https://abcdefghijkl.akdbx.link:8443'
    assert store.certificate(config.name) is not None
    # Both files open only through the private-file checks.
    for path in (store.config_path, store.tls_path):
        security.read_private(path)
    acl = win32security.ACL()
    user = win32security.ConvertStringSidToSid(security.current_identity()[0])
    everyone = win32security.CreateWellKnownSid(win32security.WinWorldSid)
    acl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, user)
    acl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.GENERIC_READ, everyone)
    win32security.SetNamedSecurityInfo(str(store.config_path), win32security.SE_FILE_OBJECT,
                                       win32security.DACL_SECURITY_INFORMATION
                                       | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                                       None, None, acl, None)
    with pytest.raises(relay.RelayStoreError):
        store.load()
    assert relay.saved_origin(store) is None
    store.save(config)  # A replacement gets a private ACL again.
    assert store.load() == config
    store.forget()
    assert not store.directory.exists()


def test_relay_lock_admits_one_broker(private_dir, monkeypatch):
    from akdbx import relay
    monkeypatch.setenv('LOCALAPPDATA', str(private_dir))
    store = relay.RelayStore()
    held = store.lock()
    try:
        with pytest.raises(relay.RelayBusy, match='another akdbx process'):
            relay.RelayStore().lock()
    finally:
        held.release()
    store.lock().release()


def test_relay_lock_is_a_file_that_every_logon_session_sees(private_dir, monkeypatch, capsys):
    from akdbx import relay
    monkeypatch.setenv('LOCALAPPDATA', str(private_dir))
    monkeypatch.delenv('AKDBX_UNLOCK_ORIGIN', raising=False)
    store = relay.RelayStore()
    store.save(_relay_config())
    lock_path = store.directory / '.relay.lock'
    held = store.lock()
    try:
        # A file held open with share mode 0, not a session-local mutex: any
        # process in any logon session fails to open it while a broker runs.
        with pytest.raises(pywintypes.error) as error:
            win32file.CreateFile(str(lock_path), win32con.GENERIC_READ,
                                 win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
                                 None, win32con.OPEN_EXISTING, 0, None)
        assert error.value.winerror == 32  # ERROR_SHARING_VIOLATION
        with security.checked_handle(store.directory, directory=True):
            pass  # the folder stays private
        other = subprocess.run(
            [sys.executable, '-c', 'from akdbx import relay\n'
             'try:\n    relay.RelayStore().lock()\nexcept relay.RelayBusy:\n    print("busy")'],
            capture_output=True, text=True, timeout=60, env={**os.environ, 'LOCALAPPDATA': str(private_dir)})
        assert other.stdout.strip() == 'busy', other.stderr
        assert cli.main(['relay', 'disable', '--forget']) == 1
        assert 'stop it' in json.loads(capsys.readouterr().out)['error']
        assert store.config_path.exists()
    finally:
        held.release()
    assert cli.main(['relay', 'disable', '--forget']) == 0
    assert json.loads(capsys.readouterr().out)['forgot'] is True
    assert not store.directory.exists()


def test_relay_tls_file_loads_and_hot_reloads_on_windows(private_dir, monkeypatch):
    from akdbx import relay
    from akdbx.local_https import reload_certificate, server_context
    monkeypatch.setenv('LOCALAPPDATA', str(private_dir))
    store = relay.RelayStore()
    config = _relay_config()
    store.save(config)
    store.save_tls(_relay_tls(config.name))
    # The key and the chain are one private file, given as both certificate and key.
    server = SimpleNamespace(context=server_context(store.tls_path, store.tls_path))
    first = server.context
    store.save_tls(_relay_tls(config.name))
    reload_certificate(server, store.tls_path, store.tls_path)
    assert server.context is not first


def test_windows_cli_uses_the_relay_origin_and_refuses_conflicts(private_dir, monkeypatch, capsys):
    from akdbx import relay
    monkeypatch.setenv('LOCALAPPDATA', str(private_dir))
    monkeypatch.delenv('AKDBX_UNLOCK_ORIGIN', raising=False)
    store = relay.RelayStore()
    store.save(_relay_config())
    args = cli.parser().parse_args(['status'])
    cli.resolve_unlock_origin(args)
    assert args.unlock_origin == 'https://abcdefghijkl.akdbx.link:8443'
    pipe = rpc.PREFIX + 'akdbx-test-' + uuid.uuid4().hex
    vault = str(private_dir / 'unused.kdbx')
    assert cli.main(['--socket', pipe, 'serve', vault]) == 2
    assert "no usable certificate yet: run 'akdbx relay enable' again" in capsys.readouterr().err
    store.save_tls(_relay_tls('abcdefghijkl.akdbx.link'))
    assert cli.main(['--socket', pipe, 'serve', vault, '--tls-cert', 'c.pem', '--tls-key', 'k.pem']) == 2
    assert 'the akdbx relay is enabled' in capsys.readouterr().err
    store.save(_relay_config(enabled=False))
    cli.resolve_unlock_origin(args := cli.parser().parse_args(['status']))
    assert args.unlock_origin == 'https://localhost:9443'
