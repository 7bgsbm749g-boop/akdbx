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
import threading
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


def test_alternate_data_streams_are_refused(synthetic_vault):
    with pytest.raises(PermissionError):
        security.read_private(str(synthetic_vault) + ':stream')


def test_windows_explicitly_refuses_linux_merge_and_admission():
    broker = Broker(type('Vault', (), {'entries': []})(), object())
    status = broker.dispatch({'action': 'ping'})
    assert status['merge_available'] is False and status['admission_supported'] is False
    for action in ('merge', 'admit', 'merge-status'):
        assert 'unavailable on Windows' in broker.dispatch({'action': action})['error']


def test_native_https_unlock_password_totp_and_identity_saves(synthetic_vault, certificates):
    certificate, key = synthetic_vault.parent / 'cert.pem', synthetic_vault.parent / 'key.pem'
    security.write_new(certificate, certificates[0].read_bytes())
    security.write_new(key, certificates[1].read_bytes())
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    origin = f'https://127.0.0.1:{port}'
    broker = Broker(None, object())
    server, unlock_url = start_windows_unlock_server(broker, synthetic_vault, None, origin, certificate, key)
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
    finally:
        release.set()
        worker.join(5)
    assert not worker.is_alive() and not failures and len(saved) == 1
    assert store.check_write_inputs() and not store.recovery_required
    assert PyKeePass(str(synthetic_vault), password='synthetic master').entries[0].password == 'synthetic concurrent update'


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
