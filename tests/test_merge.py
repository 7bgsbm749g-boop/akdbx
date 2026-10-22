"""Synthetic KDBX fixtures only. No production broker, services, or vaults."""
from __future__ import annotations

import fcntl
import base64
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode, urlsplit

import pytest
from lxml import etree
from pykeepass import PyKeePass, create_database

from agentic_kdbx import cli
from agentic_kdbx import merge as merging
from agentic_kdbx.broker import Broker, open_vault_with_password
from agentic_kdbx.persistence import VaultStore
from agentic_kdbx.web_unlock import start_unlock_server
from test_broker import RecordingTyper, running_broker
from test_web_unlock import call

MASTER = '  synthetic !%+& punctuation é 🗝️  '
SECRET = 'synthetic-entry-secret-never-returned'
BASE_TIME = datetime(2024, 1, 1, tzinfo=timezone.utc)


@pytest.fixture(scope='module')
def base(tmp_path_factory):
    path = tmp_path_factory.mktemp('merge-synthetic-base') / 'base.kdbx'
    vault = create_database(io.BytesIO(), password=MASTER)
    params = vault.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    params['I'].value = 1
    params['M'].value = 1024 * 1024
    vault.kdbx.header.value.minor_version = 1
    group = vault.add_group(vault.root_group, 'Synthetic group')
    deleted_group = vault.add_group(vault.root_group, 'Delete empty group')
    deleted_group.mtime = BASE_TIME
    for title in ('Shared', 'Delete me', 'Edit after deletion'):
        e = vault.add_entry(group, title, 'synthetic-account', SECRET)
        e.mtime = BASE_TIME
    vault.database_name = 'Synthetic target metadata'
    vault.save(path)
    return path


@pytest.fixture
def pair(tmp_path, base):
    target, source = tmp_path / 'target.kdbx', tmp_path / 'source.kdbx'
    shutil.copyfile(base, target)
    shutil.copyfile(base, source)
    left, right = PyKeePass(target, password=MASTER), PyKeePass(source, password=MASTER)
    left.add_entry(left.root_group, 'Left only', 'left', SECRET, url='https://synthetic.test')
    right.add_entry(right.root_group, 'Right only', 'right', SECRET)
    left.save()
    right.save()
    broker = Broker(open_vault_with_password(target, MASTER), RecordingTyper())
    return broker, target, source


def merge(pair, **options):
    broker, _, source = pair
    return broker.dispatch({'action': 'merge', 'source': str(source),
                            'operation_id': uuid.uuid4().hex, **options})


def disk(path):
    return PyKeePass(path, password=MASTER)


def receipt_files(result):
    return Path(result['receipt_path']).parent


def test_diverged_round_trip_preview_repeated_refresh_and_receipt(pair, capsys, caplog):
    broker, target, source = pair
    original, incoming = target.read_bytes(), source.read_bytes()
    selected = broker.dispatch({'action': 'search', 'query': 'Shared'})['entries'][0]
    checked = merge(pair, check=True)
    assert checked['state'] == 'checked' and checked['changed']
    assert target.read_bytes() == original and source.read_bytes() == incoming
    assert not broker.dispatch({'action': 'search', 'query': 'Right only'})['entries']
    result = merge(pair)
    assert result['ok'] and result['state'] == 'saved'
    # KeePassXC selects the minimum KDBX minor version needed by the data.
    assert disk(target).version[0] == 4
    assert {e.title for e in disk(target).entries} >= {'Left only', 'Right only', 'Shared'}
    assert broker.dispatch({'action': 'search', 'query': 'Right only'})['entries']
    assert not broker.dispatch({'action': 'fill', 'handle': selected['handle']})['ok']
    assert source.read_bytes() == incoming
    bundle = receipt_files(result)
    assert (bundle / 'target.kdbx').read_bytes() == original
    assert (bundle / 'source.kdbx').read_bytes() == incoming
    assert (bundle / 'candidate.kdbx').read_bytes() == target.read_bytes()
    for p in bundle.iterdir():
        assert stat.S_IMODE(p.stat().st_mode) == 0o600
        assert MASTER.encode() not in p.read_bytes() and SECRET.encode() not in p.read_bytes()
    assert stat.S_IMODE(bundle.stat().st_mode) == 0o700
    saved = target.read_bytes()
    again = merge(pair)
    assert again['ok'] and again['state'] == 'unchanged' and not again['changed'], again
    assert target.read_bytes() == saved
    # Reusing a known operation ID retrieves its receipt, with no second save.
    assert merge(pair, operation_id=result['operation_id']) == result
    assert json.loads(Path(result['receipt_path']).read_text())['state'] == 'saved'
    assert MASTER not in json.dumps(result) + capsys.readouterr().out + caplog.text


def tombstone(vault, obj, stamp):
    deleted = etree.SubElement(vault.tree.find('./Root/DeletedObjects'), 'DeletedObject')
    etree.SubElement(deleted, 'UUID').text = obj._element.findtext('UUID')
    etree.SubElement(deleted, 'DeletionTime').text = vault._encode_time(stamp)
    obj.delete()


def test_newest_conflict_history_deletions_groups_attachments_custom_metadata(pair):
    broker, target, source = pair
    left, right = disk(target), disk(source)
    old = left.find_entries(title='Shared', first=True)
    new = right.find_entries(title='Shared', first=True)
    original_uuid = old.uuid
    old.save_history()
    new.save_history()
    old.password = 'synthetic-older-conflict'
    old.mtime = BASE_TIME + timedelta(days=1)
    new.password = 'synthetic-newest-conflict'
    new.mtime = BASE_TIME + timedelta(days=2)
    new.set_custom_property('Synthetic field', 'preserved custom field', protect=True)
    binary = right.add_binary(b'synthetic attachment bytes')
    new.add_attachment(binary, 'synthetic.txt')
    group = right.add_group(right.root_group, 'Source added group')
    icon_id = base64.b64encode(uuid.uuid4().bytes).decode()
    icons = right.tree.find('./Meta/CustomIcons')
    if icons is None:
        icons = etree.SubElement(right.tree.find('./Meta'), 'CustomIcons')
    icon = etree.SubElement(icons, 'Icon')
    etree.SubElement(icon, 'UUID').text = icon_id
    icon_data = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII='
    etree.SubElement(icon, 'Data').text = icon_data
    etree.SubElement(group._element, 'CustomIconUUID').text = icon_id
    # Same inherited CustomData survives both branches and native serialization.
    for vault in (left, right):
        custom = vault.tree.find('./Meta/CustomData')
        if custom is None:
            custom = etree.SubElement(vault.tree.find('./Meta'), 'CustomData')
        item = etree.SubElement(custom, 'Item')
        etree.SubElement(item, 'Key').text = 'synthetic-metadata-key'
        etree.SubElement(item, 'Value').text = 'synthetic-metadata-value'
    group.mtime = BASE_TIME + timedelta(days=3)
    right.move_entry(new, group)
    new._element.find('Times/LocationChanged').text = right._encode_time(datetime(2030, 1, 1, tzinfo=timezone.utc))
    group_uuid = group.uuid
    tombstone(right, right.find_entries(title='Delete me', first=True), BASE_TIME + timedelta(days=3))
    tombstone(right, right.find_groups(name='Delete empty group', first=True), BASE_TIME + timedelta(days=3))
    newer = left.find_entries(title='Edit after deletion', first=True)
    newer.password = 'synthetic-edited-after-deletion'
    newer.mtime = BASE_TIME + timedelta(days=5)
    tombstone(right, right.find_entries(title='Edit after deletion', first=True), BASE_TIME + timedelta(days=3))
    left.save()
    right.save()
    broker.vault = open_vault_with_password(target, MASTER)
    result = merge(pair)
    assert result['ok'], result
    saved = disk(target)
    entry = saved.find_entries(uuid=original_uuid, first=True)
    assert entry.password == 'synthetic-newest-conflict'
    assert any(h.password == 'synthetic-older-conflict' for h in entry.history)
    assert any(h.password == SECRET for h in entry.history)
    assert entry.mtime == BASE_TIME + timedelta(days=2)
    assert entry.get_custom_property('Synthetic field') == 'preserved custom field'
    assert entry.attachments[0].data == b'synthetic attachment bytes'
    assert entry.group.uuid == group_uuid
    assert saved.find_entries(title='Delete me', first=True) is None
    assert saved.find_groups(name='Delete empty group', first=True) is None
    assert saved.find_entries(title='Edit after deletion', first=True).password == 'synthetic-edited-after-deletion'
    assert saved.tree.findall('./Root/DeletedObjects/DeletedObject')
    assert saved.database_name == 'Synthetic target metadata'
    assert saved.tree.findtext('./Meta/CustomData/Item[Key="synthetic-metadata-key"]/Value') == 'synthetic-metadata-value'
    assert saved.tree.findtext('./Meta/CustomIcons/Icon[UUID="' + icon_id + '"]/Data') == icon_data
    assert result['after']['attachments'] == 1 and result['after']['deletions'] >= 1
    repeated = merge(pair)
    assert repeated['ok'] and repeated['state'] == 'unchanged', repeated


def test_equal_second_conflict_fails_closed(pair):
    broker, target, source = pair
    other = disk(source)
    other.find_entries(title='Shared', first=True).password = 'synthetic-ambiguous'
    other.save()
    before = target.read_bytes()
    result = merge(pair)
    assert not result['ok'] and 'same-second' in result['error']
    assert target.read_bytes() == before
    assert (receipt_files(result) / 'target.kdbx').read_bytes() == before


@pytest.mark.parametrize('damage', ['different-key', 'invalid-file', 'symlink', 'hardlink', 'same-file', 'symlink-parent', 'unsafe-parent', 'missing', 'fifo'])
def test_invalid_source_preserves_target(pair, tmp_path, damage):
    _, target, source = pair
    if damage == 'different-key':
        v = disk(source)
        v.password = 'synthetic-different-key'
        v.save()
    elif damage == 'invalid-file':
        source.write_bytes(b'synthetic invalid encrypted input')
    elif damage == 'symlink':
        source.unlink()
        source.symlink_to(target)
    elif damage == 'hardlink':
        source.unlink()
        os.link(target, source)
    elif damage == 'same-file':
        source = target
    elif damage == 'symlink-parent':
        link = tmp_path / 'link'
        link.symlink_to(tmp_path, target_is_directory=True)
        source = link / source.name
    elif damage == 'missing':
        source.unlink()
    elif damage == 'fifo':
        source.unlink()
        os.mkfifo(source)
    else:
        unsafe = tmp_path / 'unsafe'
        unsafe.mkdir(mode=0o777)
        unsafe.chmod(0o777)
        shutil.copyfile(source, unsafe / source.name)
        source = unsafe / source.name
    before = target.read_bytes()
    result = merge(pair, source=str(source))
    assert not result['ok'] and target.read_bytes() == before


def test_stale_target_and_source_race(pair, monkeypatch):
    broker, target, source = pair
    real_engine = merging.run_engine
    incoming = source.read_bytes()
    def racing_engine(bundle, vault):
        real_engine(bundle, vault)
        source.write_bytes(incoming + b'synthetic external change')
    monkeypatch.setattr(merging, 'run_engine', racing_engine)
    before = target.read_bytes()
    result = merge(pair)
    assert not result['ok'] and 'changed on disk' in result['error']
    assert target.read_bytes() == before
    assert (receipt_files(result) / 'source.kdbx').read_bytes() == incoming
    target.write_bytes(before + b'synthetic target change')
    assert not merge(pair)['ok']
    assert target.read_bytes() == before + b'synthetic target change'


def test_target_changes_during_engine_are_not_overwritten(pair, monkeypatch):
    _, target, _ = pair
    real_engine = merging.run_engine
    external = disk(target)
    external.add_entry(external.root_group, 'External synthetic edit', 'external', SECRET)
    def racing_engine(bundle, vault):
        real_engine(bundle, vault)
        external.save()
    monkeypatch.setattr(merging, 'run_engine', racing_engine)
    result = merge(pair)
    assert not result['ok']
    assert disk(target).find_entries(title='External synthetic edit', first=True)
    assert disk(target).find_entries(title='Right only', first=True) is None


def test_wrong_source_owner_is_rejected(pair, monkeypatch):
    _, target, source = pair
    inode = source.stat().st_ino
    fstat = os.fstat
    def wrong_owner(fd):
        info = fstat(fd)
        if info.st_ino == inode:
            fields = list(info)
            fields[4] = os.getuid() + 1
            return os.stat_result(fields)
        return info
    monkeypatch.setattr(os, 'fstat', wrong_owner)
    before = target.read_bytes()
    result = merge(pair)
    assert not result['ok'] and 'unsafe vault file' in result['error']
    assert target.read_bytes() == before


@pytest.mark.parametrize('failure', ['engine', 'reopen', 'snapshot', 'stage', 'replace', 'replace-after', 'durability', 'receipt'])
def test_save_faults_never_claim_success_or_leak(pair, monkeypatch, capsys, caplog, failure):
    broker, target, source = pair
    before, incoming = target.read_bytes(), source.read_bytes()
    def fail(*args, **kwargs):
        raise OSError(MASTER + SECRET)
    real_engine = merging.run_engine
    if failure == 'engine':
        monkeypatch.setattr(merging, 'run_engine', fail)
    elif failure == 'reopen':
        def corrupt(bundle, vault):
            real_engine(bundle, vault)
            (bundle / 'candidate.kdbx').write_bytes(b'synthetic invalid candidate')
        monkeypatch.setattr(merging, 'run_engine', corrupt)
    elif failure in {'snapshot', 'stage'}:
        real_write = VaultStore._write_file
        def fault_write(directory, name, data):
            if name == 'source.kdbx' and failure == 'snapshot' or name.endswith('.replace') and failure == 'stage':
                fail()
            return real_write(directory, name, data)
        monkeypatch.setattr(VaultStore, '_write_file', staticmethod(fault_write))
    else:
        real_replace = os.replace
        def fault_replace(src, dst, **kwargs):
            if dst == target.name:
                if failure == 'replace':
                    fail()
                real_replace(src, dst, **kwargs)
                if failure == 'replace-after':
                    fail()
                if failure == 'durability':
                    monkeypatch.setattr(os, 'fsync', fail)
                if failure == 'receipt':
                    monkeypatch.setattr(merging.MergeManager, '_receipt', staticmethod(fail))
            else:
                real_replace(src, dst, **kwargs)
        monkeypatch.setattr(os, 'replace', fault_replace)
    result = merge(pair)
    assert not result['ok']
    assert source.read_bytes() == incoming
    assert MASTER not in json.dumps(result) + capsys.readouterr().out + caplog.text
    assert SECRET not in json.dumps(result) + caplog.text
    if failure in {'replace-after', 'durability', 'receipt'}:
        assert result['state'] == 'uncertain'
        assert broker.dispatch({'action': 'ping'})['recovery_required']
        assert not broker.dispatch({'action': 'search', 'query': 'Shared'})['ok']
        assert (receipt_files(result) / 'target.kdbx').read_bytes() == before
        assert disk(target).find_entries(title='Right only', first=True)
    else:
        assert result['state'] == 'failed' and target.read_bytes() == before
        assert broker.vault.find_entries(title='Right only', first=True) is None
    assert not list(target.parent.glob('*.replace'))


def test_advisory_and_in_process_concurrency(pair, monkeypatch):
    broker, target, _ = pair
    lock = os.open(target.parent / ('.' + target.name + '.akdbx.lock'), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert 'busy' in merge(pair)['error']
    finally:
        os.close(lock)
    entered, release = threading.Event(), threading.Event()
    real_engine = merging.run_engine
    def waiting(bundle, vault):
        entered.set()
        assert release.wait(10)
        real_engine(bundle, vault)
    monkeypatch.setattr(merging, 'run_engine', waiting)
    results = []
    thread = threading.Thread(target=lambda: results.append(merge(pair)))
    thread.start()
    try:
        assert entered.wait(10)
        assert 'busy' in merge(pair)['error']
    finally:
        release.set()
        thread.join(10)
    assert results[0]['ok']


def test_missing_unsupported_engine_fails_closed(pair, monkeypatch):
    broker, target, _ = pair
    before = target.read_bytes()
    monkeypatch.setattr(merging, 'ENGINE', Path('/nonexistent/synthetic-engine'))
    broker.merges._engine_checked = False
    assert not merge(pair)['ok'] and target.read_bytes() == before
    monkeypatch.setattr(merging, 'ENGINE', Path('/usr/bin/keepassxc-cli'))
    monkeypatch.setattr(subprocess, 'run', lambda *a, **kw: type('Result', (), {'stdout': b'2.6.0'})())
    assert merging.engine_version() is None


def test_real_cli_locked_private_unlock_merge_and_restart_status(pair, tmp_path):
    _, target, source = pair
    broker = Broker(None, RecordingTyper())
    socket = tmp_path / 'private' / 'rpc.sock'
    web_socket = socket.with_name('web.sock')
    server, url = start_unlock_server(broker, target, None, web_socket, 'https://node.example:9443')
    executable = Path(sys.executable).parent / 'akdbx'
    prefix = [str(executable), '--socket', str(socket), '--unlock-origin', 'https://node.example:9443']
    operation_id = uuid.uuid4().hex
    def command(*args, expected=0):
        result = subprocess.run([*prefix, *args], capture_output=True, text=True, timeout=30)
        assert result.returncode == expected, result.stderr
        assert MASTER not in result.stdout + result.stderr
        return json.loads(result.stdout)
    try:
        with running_broker(socket, broker):
            locked = command('merge', str(source), '--operation-id', operation_id, expected=1)
            assert locked['unlock_url'] == url and 'continuation' in locked
            path = '/?' + urlsplit(url).query
            failed, _, body = call(web_socket, 'POST', path, urlencode({'password': 'synthetic-bad-master'}), timeout=10)
            assert failed == 401 and MASTER.encode() not in body
            code, headers, body = call(web_socket, 'POST', path, urlencode({'password': MASTER}), timeout=10)
            assert code == 200 and headers['Cache-Control'] == 'no-store'
            ready = command('status')
            assert ready['version'] == '0.5.0' and ready['merge_available']
            result = command('merge', str(source), '--operation-id', operation_id)
            assert result['state'] == 'saved'
            assert command('merge-status', operation_id)['state'] == 'saved'
            assert command('search', 'Right only')['entries']
            assert disk(target).find_entries(title='Right only', first=True)
        # A new locked broker can read receipts without another unlock.
        restarted = Broker(None, RecordingTyper())
        restarted.merges.database = target
        with running_broker(socket, restarted):
            assert command('merge-status', operation_id)['state'] == 'saved'
    finally:
        server.shutdown()
        server.server_close()


def test_shared_keyfile_reused_privately_and_changed_keyfile_rejected(pair, tmp_path, monkeypatch):
    _, target, source = pair
    key = tmp_path / 'synthetic.key'
    key.write_bytes(b'synthetic-keyfile-material-only-1234567890')
    for path in (target, source):
        v = disk(path)
        v.keyfile = str(key)
        v.save()
    vault = open_vault_with_password(target, MASTER, key)
    broker = Broker(vault, RecordingTyper())
    real_run = subprocess.run
    def private_run(args, **kwargs):
        assert MASTER not in ' '.join(args)
        assert MASTER not in json.dumps(kwargs.get('env', {}))
        if 'merge' in args:
            assert '--key-file' in args
            assert args[args.index('--key-file') + 1].startswith('/proc/self/fd/')
        return real_run(args, **kwargs)
    monkeypatch.setattr(subprocess, 'run', private_run)
    result = merge((broker, target, source))
    assert result['ok'], result
    assert PyKeePass(target, password=MASTER, keyfile=str(key)).find_entries(title='Right only', first=True)
    before = target.read_bytes()
    key.write_bytes(b'synthetic-changed-keyfile')
    assert not merge((broker, target, source))['ok']
    assert target.read_bytes() == before


def test_pending_password_writes_invalidated(pair):
    broker, _, _ = pair
    broker.writes.public_base = 'https://node.example:9443'
    selected = broker.dispatch({'action': 'search', 'query': 'Left only'})['entries'][0]
    request = {'action': 'generate-password', 'handle': selected['handle'],
               'metadata': {k: selected[k] for k in ('title', 'username', 'url', 'group')}}
    pending = broker.dispatch(request)
    assert pending['ok'], pending
    result = merge(pair)
    assert result['ok'], result
    op = broker.writes.get(pending['write_handle'])
    assert op.state == 'failed' and op.password is None and not op.fill_refs


def test_full_argon2d_41_profile(pair):
    from pykeepass.kdbx_parsing.kdbx4 import kdf_uuids
    _, target, source = pair
    for path in (target, source):
        vault = disk(path)
        vault.kdbx.header.value.minor_version = 1
        params = vault.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
        params['$UUID'].value = kdf_uuids['argon2']
        for key, value in {'I': 119, 'M': 67108864, 'P': 2, 'V': 19}.items():
            params[key].value = value
        vault.save()
    opened = open_vault_with_password(target, MASTER)
    assert opened.version == (4, 1) and opened.encryption_algorithm == 'aes256'
    broker = Broker(opened, RecordingTyper())
    result = merge((broker, target, source))
    assert result['ok'], result
    assert disk(target).find_entries(title='Right only', first=True)
    assert disk(target).kdf_algorithm == 'argon2'


def test_interrupted_intent_blocks_after_restart_and_receipt_remains_readable(pair, monkeypatch):
    broker, target, _ = pair
    real_receipt = merging.MergeManager._receipt
    def interrupted(directory, value):
        real_receipt(directory, value)
        if value['state'] == 'prepared':
            raise KeyboardInterrupt('synthetic interruption')
    monkeypatch.setattr(merging.MergeManager, '_receipt', staticmethod(interrupted))
    before = target.read_bytes()
    operation_id = uuid.uuid4().hex
    with pytest.raises(KeyboardInterrupt):
        merge(pair, operation_id=operation_id)
    assert target.read_bytes() == before
    restarted = Broker(open_vault_with_password(target, MASTER), RecordingTyper())
    assert restarted.dispatch({'action': 'ping'})['recovery_required']
    status = restarted.dispatch({'action': 'merge-status', 'operation_id': operation_id})
    assert status['state'] == 'uncertain' and not status['ok']
    assert (receipt_files(status) / 'candidate.kdbx').exists()
    assert not restarted.dispatch({'action': 'search'})['ok']


def test_history_limit_cannot_silently_drop_values(pair):
    broker, target, source = pair
    left, right = disk(target), disk(source)
    left.tree.find('./Meta/HistoryMaxItems').text = '0'
    old = left.find_entries(title='Shared', first=True)
    old.password = 'synthetic-old-history-needed'
    old.mtime = BASE_TIME + timedelta(days=1)
    new = right.find_entries(title='Shared', first=True)
    new.password = 'synthetic-new-history-needed'
    new.mtime = BASE_TIME + timedelta(days=2)
    left.save()
    right.save()
    before = target.read_bytes()
    broker.vault = open_vault_with_password(target, MASTER)
    result = merge(pair)
    assert not result['ok'] and 'discard entry history' in result['error']
    assert target.read_bytes() == before


def test_cli_merge_timeout_has_recovery_id_and_never_retries(pair, monkeypatch, capsys):
    calls = []
    def lost(*args, **kwargs):
        calls.append(args)
        raise TimeoutError(MASTER)
    monkeypatch.setattr(cli, 'request', lost)
    operation_id = uuid.uuid4().hex
    assert cli.main(['merge', str(pair[2]), '--operation-id', operation_id]) == 2
    output = capsys.readouterr()
    assert len(calls) == 1 and 'merge-status ' + operation_id in output.err
    assert MASTER not in output.out + output.err


def test_native_timeout_discards_raw_output_and_preserves_inputs(pair, monkeypatch, capsys, caplog):
    broker, target, source = pair
    assert broker.merges.capabilities()['merge_available']
    before, incoming = target.read_bytes(), source.read_bytes()
    def native_timeout(args, **kwargs):
        assert kwargs['stdout'] == subprocess.DEVNULL
        assert kwargs['stderr'] == subprocess.DEVNULL
        assert kwargs['input'] == (MASTER + '\n').encode()
        assert MASTER not in ' '.join(args)
        raise subprocess.TimeoutExpired(args, 180, output=SECRET, stderr=MASTER)
    monkeypatch.setattr(subprocess, 'run', native_timeout)
    result = merge(pair)
    assert not result['ok'] and 'engine failed' in result['error']
    assert target.read_bytes() == before and source.read_bytes() == incoming
    output = capsys.readouterr()
    assert all(s not in json.dumps(result) + output.out + output.err + caplog.text for s in (SECRET, MASTER))


def test_line_break_master_password_is_refused_without_native_dispatch(pair, monkeypatch):
    _, target, source = pair
    password = MASTER + '\n'
    for path in (target, source):
        v = disk(path)
        v.password = password
        v.save()
    broker = Broker(open_vault_with_password(target, password), RecordingTyper())
    assert broker.merges.capabilities()['merge_available']
    def unexpected(*args, **kwargs):
        pytest.fail('unsupported password reached native engine')
    monkeypatch.setattr(subprocess, 'run', unexpected)
    before = target.read_bytes()
    result = merge((broker, target, source))
    assert not result['ok'] and 'line-compatible' in result['error']
    assert target.read_bytes() == before
