"""Synthetic-only tests for lossless equal-time merge preservation."""
from __future__ import annotations

import copy
import base64
import io
import json
import os
import shutil
import stat
import subprocess
import struct
import sys
import threading
import uuid
import zlib
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlencode, urlsplit

import pytest
from lxml import etree
from pykeepass import PyKeePass

from agentic_kdbx import cli, merge as merging, versions
from agentic_kdbx.broker import Broker, open_vault_with_password
from agentic_kdbx.persistence import VaultStore
from agentic_kdbx.web_unlock import start_unlock_server
from test_broker import RecordingTyper, running_broker
from test_merge import MASTER, SECRET, BASE_TIME, base, pair, merge, disk, receipt_files, tombstone
from test_refresh_merge import refresh_case, refresh, opened
from test_web_unlock import call, wait_for


def save_pair(pair, left, right):
    broker, target, source = pair
    left.save(target)
    right.save(source)
    broker.vault = open_vault_with_password(target, MASTER)


def record(vault, password, *, title='Shared', days=0, attachment=None):
    entry = vault.find_entries(title=title, first=True)
    entry.password = password
    entry.mtime = BASE_TIME + timedelta(days=days)
    entry.set_custom_property('Synthetic custom field', password, protect=True)
    if attachment is not None:
        entry.add_attachment(vault.add_binary(attachment), 'synthetic record.bin')
    return entry


def ledger(vaults):
    return versions.collect(vaults, capture=True)


def assert_retained(vault, expected):
    actual = versions.archives(vault)
    assert set(expected) <= set(actual)
    for identity, data in expected.items():
        # The opaque original representation and every attachment byte survive.
        assert actual[identity] == data
        assert versions.capsule_identity(json.loads(data)) == identity


def test_target_source_same_time_requires_opt_in_and_preserves_complete_versions(pair, capsys, caplog):
    broker, target, source = pair
    left, right = disk(target), disk(source)
    record(left, 'synthetic target choice', attachment=b'synthetic target attachment')
    record(right, 'synthetic source competing', attachment=b'synthetic source attachment')
    save_pair(pair, left, right)
    originals = [disk(target), disk(source)]
    expected = ledger(originals)
    before, incoming = target.read_bytes(), source.read_bytes()
    store = broker.vault._akdbx_store
    original_expected = store.expected
    broker.writes.public_base = 'https://node.example:9443'
    selected = broker.dispatch({'action': 'search', 'query': 'Left only'})['entries'][0]
    pending = broker.dispatch({'action': 'generate-password', 'handle': selected['handle'],
                               'metadata': {k: selected[k] for k in ('title', 'username', 'url', 'group')}})
    assert pending['ok']
    selected = broker.dispatch({'action': 'search', 'query': 'Shared'})['entries'][0]
    assert not merge(pair)['ok']
    checked = merge(pair, preserve_conflicts=True, check=True)
    assert checked['state'] == 'checked' and target.read_bytes() == before
    assert selected['handle'] in broker._handles and store.expected == original_expected
    assert store.verified_encrypted == before and broker.writes.get(pending['write_handle']).state == 'pending'
    assert not versions.archives(broker.vault)
    assert_retained(disk(receipt_files(checked) / 'candidate.kdbx'), expected)
    result = merge(pair, preserve_conflicts=True)
    assert result['ok'] and result['state'] == 'saved', result
    assert result['preservation_policy'] == 'capsule-v1'
    assert result['preserved_versions'] == len(expected)
    assert selected['handle'] not in broker._handles
    assert broker.writes.get(pending['write_handle']).state == 'failed'
    assert broker.writes.get(pending['write_handle']).password is None
    saved = disk(target)
    assert saved.find_entries(title='Shared', first=True).password == 'synthetic target choice'
    assert_retained(saved, expected)
    assert source.read_bytes() == incoming
    assert (receipt_files(result) / 'target.kdbx').read_bytes() == before
    assert (receipt_files(result) / 'source.kdbx').read_bytes() == incoming
    assert broker.dispatch({'action': 'search', 'query': 'Preserved original record'})['entries'] == []
    assert len(broker.dispatch({'action': 'search', 'query': 'Shared'})['entries']) == 1
    assert all(secret not in json.dumps(result) + capsys.readouterr().out + caplog.text for secret in (MASTER, SECRET, 'synthetic source competing'))
    for path in receipt_files(result).iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert b'synthetic source competing' not in path.read_bytes()


@pytest.mark.parametrize('collision', ['history-history', 'active-history', 'within-source'])
def test_history_collisions_retain_every_original_time_and_record(pair, collision):
    _, target, source = pair
    left, right = disk(target), disk(source)
    a, b = left.find_entries(title='Shared', first=True), right.find_entries(title='Shared', first=True)
    if collision == 'history-history':
        a.password = 'synthetic history A'; a.save_history()
        b.password = 'synthetic history B'; b.save_history()
        a.password = 'synthetic current A'; a.mtime = BASE_TIME + timedelta(days=1)
        b.password = 'synthetic current B'; b.mtime = BASE_TIME + timedelta(days=2)
    elif collision == 'active-history':
        a.password = 'synthetic old active'
        b.password = 'synthetic same-time history'; b.save_history()
        b.password = 'synthetic newer current'; b.mtime = BASE_TIME + timedelta(days=1)
    else:
        for value in ('synthetic source history one', 'synthetic source history two'):
            b.password = value; b.save_history()
        b.password = 'synthetic source active'; b.mtime = BASE_TIME + timedelta(days=1)
    save_pair(pair, left, right)
    expected = ledger([disk(target), disk(source)])
    result = merge(pair, preserve_conflicts=True)
    assert result['ok'], result
    assert_retained(disk(target), expected)
    payloads = [json.loads(data) for data in versions.archives(disk(target)).values()]
    # Raw time encoding is retained with its original format, without fake order.
    for original in (left, right):
        for active in versions.active_entries(original):
            for item in [active, *active.history]:
                raw = versions._packed(item._element.find('Times'))
                assert any(raw == next(node for node in p['record'][3] if node[0] == 'Times') for p in payloads)


def test_history_only_differences_and_attachment_versions_are_independently_verified(pair):
    _, target, source = pair
    left, right = disk(target), disk(source)
    expected_records = set()
    for vault, label in ((left, 'target'), (right, 'source')):
        entry = vault.find_entries(title='Shared', first=True)
        for number in range(2):
            value = 'synthetic ' + label + ' history ' + str(number)
            binary = (label + ' attachment ' + str(number)).encode()
            for attachment in list(entry.attachments):
                attachment.delete()
            entry.password = value
            entry.set_custom_property('Exact field', value + ' ', protect=True)
            entry.add_attachment(vault.add_binary(binary), 'same filename.bin')
            entry.mtime = BASE_TIME
            entry.save_history()
            expected_records.add((value, value + ' ', binary))
        for attachment in list(entry.attachments):
            attachment.delete()
        entry.password = 'synthetic identical active value'
        entry.delete_custom_property('Exact field')
        entry.mtime = BASE_TIME + timedelta(days=10)
    save_pair(pair, left, right)
    assert not merge(pair)['ok']  # Both active records are identical.
    result = merge(pair, preserve_conflicts=True)
    assert result['ok'], result
    actual_records = set()
    for data in versions.archives(disk(target)).values():
        payload = json.loads(data)
        fields = {}
        # Independent reader for the documented structured record schema.
        for node in payload['record'][3]:
            if node[0] == 'String':
                children = {child[0]: child[2] or '' for child in node[3]}
                fields[children['Key']] = children['Value']
        if fields.get('Password', '').startswith('synthetic ') and payload['attachments']:
            import base64
            actual_records.add((fields['Password'], fields.get('Exact field'), base64.b64decode(payload['attachments'][0]['data'])))
    assert expected_records <= actual_records
    assert disk(target).find_entries(title='Shared', first=True).password == 'synthetic identical active value'


@pytest.mark.parametrize('difference', ['formatting', 'field-order', 'boolean', 'empty-defaults', 'autotype-defaults'])
def test_benign_serialization_is_normalized_without_opt_in(pair, difference):
    _, target, source = pair
    left, right = disk(target), disk(source)
    a, b = left.find_entries(title='Shared', first=True), right.find_entries(title='Shared', first=True)
    if difference == 'formatting':
        b._element.text = '\n    '
        for child in b._element:
            child.tail = '\n    '
        b._element.append(etree.Comment('synthetic formatting comment'))
        b._element.append(etree.ProcessingInstruction('synthetic', 'formatting'))
    elif difference == 'field-order':
        b._element[:] = list(reversed(list(b._element)))
    elif difference == 'boolean':
        b._element.find('./String[Key="Password"]/Value').set('Protected', 'true')
        b._element.find('AutoType/Enabled').text = 'true'
    elif difference == 'empty-defaults':
        for field in ('URL', 'Notes'):
            item = etree.SubElement(b._element, 'String')
            etree.SubElement(item, 'Key').text = field
            etree.SubElement(item, 'Value').set('Protected', 'False')
        etree.SubElement(b._element, 'IconID').text = '0'
    else:
        b._element.remove(b._element.find('AutoType'))
    assert merging._entry_signature(a) == merging._entry_signature(b)
    if difference == 'boolean':
        # PyKeePass's writer only encrypts Protected="True". Exercise the
        # spelling normalization above without generating a malformed fixture.
        b._element.find('./String[Key="Password"]/Value').set('Protected', 'True')
    save_pair(pair, left, right)
    result = merge(pair)
    assert result['ok'], result


@pytest.mark.parametrize('difference', ['unknown-order', 'autotype-order', 'unknown-attribute', 'meaningful-tail', 'protected-empty'])
def test_canonical_identity_keeps_meaningful_metadata(pair, difference):
    _, target, source = pair
    left, right = disk(target), disk(source)
    a, b = left.find_entries(title='Shared', first=True), right.find_entries(title='Shared', first=True)
    if difference == 'unknown-order':
        for entry, values in ((a, ('first', 'second')), (b, ('second', 'first'))):
            extension = etree.SubElement(entry._element, 'SyntheticOrderedMetadata')
            for value in values:
                etree.SubElement(extension, 'Value').text = value
    elif difference == 'autotype-order':
        for entry, values in ((a, ('first', 'second')), (b, ('second', 'first'))):
            for value in values:
                association = etree.SubElement(entry._element.find('AutoType'), 'Association')
                etree.SubElement(association, 'Window').text = value
                etree.SubElement(association, 'KeystrokeSequence').text = '{PASSWORD}'
    elif difference == 'unknown-attribute':
        etree.SubElement(b._element, 'Tags', {'SyntheticAttribute': 'preserve'})
    elif difference == 'meaningful-tail':
        b._element.find('Times').tail = 'synthetic significant mixed content '
    else:
        a.set_custom_property('Empty protected', '', protect=False)
        b.set_custom_property('Empty protected', '', protect=True)
    assert merging._entry_signature(a) != merging._entry_signature(b)
    expected = ledger([left, right])
    shared = [json.loads(data) for data in expected.values() if json.loads(data)['uuid'] == str(a.uuid)]
    assert len(shared) == 2
    # Structured payloads round-trip mixed text, comments and extensions without
    # any plaintext export or timestamp change.
    for entry in (a, b):
        packed = versions._packed(entry._element)
        assert versions._packed(versions._unpacked(packed)) == packed


@pytest.mark.parametrize('difference', ['password-spaces', 'unicode-password', 'custom-empty', 'custom-space', 'attachment', 'expiry', 'unknown-metadata'])
def test_distinct_legitimate_records_are_not_conflated(pair, difference):
    _, target, source = pair
    left, right = disk(target), disk(source)
    a, b = left.find_entries(title='Shared', first=True), right.find_entries(title='Shared', first=True)
    if difference == 'password-spaces':
        b.password = (a.password or '') + ' '
    elif difference == 'unicode-password':
        b.password = '  synthetic é 🦊 !&<>\t\n  '
    elif difference == 'custom-empty':
        b.set_custom_property('Empty custom', '')
    elif difference == 'custom-space':
        a.set_custom_property('Custom', 'value'); b.set_custom_property('Custom', 'value ')
    elif difference == 'attachment':
        for vault, e, value in ((left, a, b'one'), (right, b, b'two')):
            e.add_attachment(vault.add_binary(value), 'same name.bin')
    elif difference == 'expiry':
        b.expires = True
        b.expiry_time = BASE_TIME + timedelta(days=900)
    else:
        etree.SubElement(b._element, 'SyntheticApplicationMetadata').text = 'synthetic exact metadata '
    save_pair(pair, left, right)
    expected = ledger([disk(target), disk(source)])
    versions_for_shared = [json.loads(data) for data in expected.values() if json.loads(data)['uuid'] == str(a.uuid)]
    assert len(versions_for_shared) == 2
    result = merge(pair, preserve_conflicts=True)
    assert result['ok'], result
    assert_retained(disk(target), expected)


def test_three_way_same_time_uses_current_target_and_preserves_broker_and_incoming(refresh_case):
    case = refresh_case
    # Existing fixture already has three distinct values; make the active times
    # equal by writing synthetic inputs before opening the isolated broker.
    broker_image = PyKeePass(io.BytesIO(case.broker_bytes), password=MASTER)
    external = opened(case, case.target)
    incoming = opened(case, case.source)
    for vault in (broker_image, external, incoming):
        vault.find_entries(title='Shared', first=True).mtime = BASE_TIME + timedelta(days=3)
    buffer = io.BytesIO(); broker_image.save(buffer)
    case.target.write_bytes(buffer.getvalue())
    case.broker.vault = open_vault_with_password(case.target, MASTER)
    external.save(case.target); incoming.save(case.source)
    expected = ledger([external, broker_image, incoming])
    assert not refresh(case)['ok']
    result = refresh(case, preserve_conflicts=True)
    assert result['ok'], result
    saved = opened(case, case.target)
    assert saved.find_entries(title='Shared', first=True).password == 'synthetic-external-conflict'
    assert {e.title for e in versions.active_entries(saved)} >= {'Broker only', 'External only', 'Incoming only'}
    assert saved.find_entries(title='Delete me', first=True) is None
    assert saved.find_entries(title='Edit after deletion', first=True)
    assert_retained(saved, expected)


def test_referenced_custom_icon_bytes_remain_with_original_versions(pair):
    _, target, source = pair
    def png(rgb):
        def chunk(kind, data):
            return struct.pack('!I', len(data)) + kind + data + struct.pack('!I', zlib.crc32(kind + data))
        return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('!2I5B', 1, 1, 8, 2, 0, 0, 0))
                + chunk(b'IDAT', zlib.compress(b'\x00' + bytes(rgb))) + chunk(b'IEND', b''))
    icon_uuid = base64.b64encode(uuid.uuid4().bytes).decode()
    left, right = disk(target), disk(source)
    originals = [png((255, 0, 0)), png((0, 0, 255))]
    for vault, data in zip((left, right), originals):
        icon = etree.SubElement(vault.tree.find('./Meta/CustomIcons'), 'Icon')
        etree.SubElement(icon, 'UUID').text = icon_uuid
        etree.SubElement(icon, 'Data').text = base64.b64encode(data).decode()
        etree.SubElement(vault.find_entries(title='Shared', first=True)._element, 'CustomIconUUID').text = icon_uuid
    save_pair(pair, left, right)
    result = merge(pair, preserve_conflicts=True)
    assert result['ok'], result
    retained = set()
    for data in versions.archives(disk(target)).values():
        for packed in json.loads(data)['custom_icons']:
            retained.add(base64.b64decode(next(child[2] for child in packed[3] if child[0] == 'Data')))
    assert set(originals) <= retained


@pytest.mark.parametrize('history_limit', ['0', '1'])
def test_history_limits_repeated_native_merges_and_reconciliation_cannot_drop_capsules(pair, history_limit):
    broker, target, source = pair
    left, right = disk(target), disk(source)
    left.tree.find('./Meta/HistoryMaxItems').text = history_limit
    a = left.find_entries(title='Shared', first=True)
    b = right.find_entries(title='Shared', first=True)
    for value in ('synthetic first', 'synthetic second', 'synthetic third'):
        a.password = value; a.save_history()
    b.password = 'synthetic competing'
    save_pair(pair, left, right)
    expected = ledger([disk(target), disk(source)])
    for iteration in range(3):
        result = merge(pair, preserve_conflicts=True)
        assert result['ok'], result
        assert_retained(disk(target), expected)
        if iteration == 0:
            cardinality = len(versions.archives(disk(target)))
        else:
            assert len(versions.archives(disk(target))) == cardinality
    # A subsequent native-only default save must preserve the opaque capsules.
    merging.run_engine(receipt_files(result), broker.vault)
    native = disk(receipt_files(result) / 'candidate.kdbx')
    assert_retained(native, expected)
    # An external replacement lacks the archive; held broker image restores it.
    external = disk(source)
    external.add_entry(external.root_group, 'Later external', 'external', SECRET)
    replacement = target.with_name('later.kdbx'); external.save(replacement); os.replace(replacement, target)
    result = merge(pair, preserve_conflicts=True, refresh_target=True)
    assert result['ok'], result
    assert_retained(disk(target), expected)


def test_password_writes_preserve_capsules_and_archive_cannot_be_a_destination(pair):
    broker, target, source = pair
    left, right = disk(target), disk(source)
    record(left, 'synthetic base'); record(right, 'synthetic competing')
    save_pair(pair, left, right)
    assert merge(pair, preserve_conflicts=True)['ok']
    retained = versions.archives(broker.vault)
    store = broker.vault._akdbx_store
    def mutate(vault):
        active = vault.find_entries(title='Shared', first=True)
        active.save_history(); active.password = 'synthetic password write'
    broker.vault = store.commit(broker.vault, mutate)
    assert_retained(broker.vault, retained)
    broker.writes.public_base = 'https://node.example:9443'
    result = broker.dispatch({'action': 'create-entry', 'metadata': {'title': 'Synthetic', 'username': 'synthetic', 'url': 'https://synthetic.test', 'group': 'akdbx preserved versions'}})
    assert not result['ok']


def test_corrupt_capsule_fails_closed(pair):
    broker, target, source = pair
    left, right = disk(target), disk(source)
    record(right, 'synthetic competing'); save_pair(pair, left, right)
    assert merge(pair, preserve_conflicts=True)['ok']
    corrupt = disk(source)
    versions.ensure(corrupt, versions.archives(broker.vault))
    group = corrupt.find_groups(uuid=versions.ARCHIVE_UUID, first=True)
    group.entries[0].attachments[0].delete()
    corrupt.save(source)
    original = target.read_bytes()
    result = merge(pair, preserve_conflicts=True)
    assert not result['ok'] and 'capsule' in result['error']
    assert target.read_bytes() == original


@pytest.mark.parametrize('failure', ['capsule-save', 'reopen', 'replace', 'durability', 'receipt'])
def test_preservation_faults_never_claim_success_or_leak(pair, monkeypatch, failure, capsys, caplog):
    broker, target, source = pair
    left, right = disk(target), disk(source)
    record(right, 'synthetic competing'); save_pair(pair, left, right)
    before, incoming = target.read_bytes(), source.read_bytes()
    def fail(*args, **kwargs):
        raise OSError(MASTER + SECRET)
    if failure == 'capsule-save':
        monkeypatch.setattr(PyKeePass, 'save', fail)
    elif failure == 'reopen':
        real_open = merging._open
        def broken(data, vault):
            opened_vault = real_open(data, vault)
            if any(g.uuid == versions.ARCHIVE_UUID for g in opened_vault.groups):
                fail()
            return opened_vault
        monkeypatch.setattr(merging, '_open', broken)
    else:
        replace = os.replace
        def broken_replace(src, dst, **kwargs):
            if dst == target.name:
                if failure == 'replace':
                    fail()
                replace(src, dst, **kwargs)
                if failure == 'durability':
                    monkeypatch.setattr(os, 'fsync', fail)
                if failure == 'receipt':
                    monkeypatch.setattr(merging.MergeManager, '_receipt', staticmethod(fail))
            else:
                replace(src, dst, **kwargs)
        monkeypatch.setattr(os, 'replace', broken_replace)
    result = merge(pair, preserve_conflicts=True)
    assert not result['ok']
    assert source.read_bytes() == incoming
    assert (receipt_files(result) / 'target.kdbx').read_bytes() == before
    if failure in {'durability', 'receipt'}:
        assert result['state'] == 'uncertain' and broker.dispatch({'action': 'ping'})['recovery_required']
    else:
        assert result['state'] == 'failed' and target.read_bytes() == before
    output = capsys.readouterr()
    assert all(s not in json.dumps(result) + output.out + output.err + caplog.text for s in (MASTER, SECRET))


@pytest.mark.parametrize('changed_input', ['source', 'target'])
def test_preservation_interrupt_and_concurrent_race_stay_fail_closed(pair, monkeypatch, changed_input):
    broker, target, source = pair
    left, right = disk(target), disk(source)
    record(right, 'synthetic competing'); save_pair(pair, left, right)
    engine = merging.run_engine
    entered, release = threading.Event(), threading.Event()
    def waiting(bundle, vault, **kwargs):
        entered.set(); assert release.wait(10)
        engine(bundle, vault, **kwargs)
        changed = source if changed_input == 'source' else target
        changed.write_bytes(changed.read_bytes() + b'synthetic external change')
    monkeypatch.setattr(merging, 'run_engine', waiting)
    results = []
    worker = threading.Thread(target=lambda: results.append(merge(pair, preserve_conflicts=True, refresh_target=True)))
    worker.start()
    try:
        assert entered.wait(10)
        assert 'busy' in merge(pair, preserve_conflicts=True)['error']
    finally:
        release.set(); worker.join(10)
    assert not results[0]['ok'] and 'changed on disk' in results[0]['error']


@pytest.mark.parametrize('capability', [None, False, True])
def test_cli_rejects_old_or_wrong_policy_before_merge(monkeypatch, capsys, capability):
    calls = []
    def old(path, payload, **kwargs):
        calls.append(payload)
        return {'ok': True, 'version': '0.4.0', 'merge_refresh_target_supported': True,
                'merge_preserve_conflicts_supported': capability, 'merge_preservation_policy': 'unknown'}
    monkeypatch.setattr(cli, 'request', old)
    assert cli.main(['merge', '/synthetic/source.kdbx', '--refresh-target', '--preserve-conflicts']) == 1
    assert calls == [{'action': 'ping'}]
    assert 'merge not sent' in json.loads(capsys.readouterr().out)['error']


@pytest.mark.parametrize('commit,legacy_version', [('4ee31cb9e2b6bb7682427b03ce18722c463080a3', '0.4.0'), ('c50afe49efef6f4f37143b989048d4b73ff1c361', '0.5.0')])
def test_actual_old_broker_rejects_policy_through_new_cli(pair, tmp_path, commit, legacy_version):
    _, target, source = pair
    legacy = tmp_path / 'legacy'
    package = legacy / 'agentic_kdbx'
    package.mkdir(parents=True)
    modules = ('__init__', 'broker', 'cli', 'merge', 'persistence', 'protocol', 'runtime', 'web_unlock', 'writes')
    for name in (*modules, *(('versions',) if legacy_version == '0.5.0' else ())):
        contents = subprocess.run(['git', 'show', commit + ':src/agentic_kdbx/' + name + '.py'], capture_output=True, check=True).stdout
        (package / (name + '.py')).write_bytes(contents)
    socket = tmp_path / 'private' / 'old.sock'
    script = """import signal,sys,threading
from pathlib import Path
from agentic_kdbx.broker import Broker,open_vault_with_password,serve
from test_merge import MASTER
class Typer:
 def type_text(self,value): raise RuntimeError('typing forbidden in synthetic legacy test')
 def press_tab(self): raise RuntimeError('typing forbidden in synthetic legacy test')
stop=threading.Event()
signal.signal(signal.SIGTERM,lambda *_:stop.set())
serve(Path(sys.argv[2]),Broker(open_vault_with_password(Path(sys.argv[1]),MASTER),Typer()),stop)
"""
    environment = {**os.environ, 'PYTHONPATH': str(legacy) + os.pathsep + str(Path(__file__).parent)}
    process = subprocess.Popen([sys.executable, '-c', script, str(target), str(socket)], env=environment,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    before, incoming = target.read_bytes(), source.read_bytes()
    try:
        wait_for(socket.exists, timeout=10)
        prefix = [str(Path(sys.executable).parent / 'akdbx'), '--socket', str(socket)]
        status = subprocess.run([*prefix, 'status'], capture_output=True, text=True, check=True)
        assert json.loads(status.stdout)['version'] == legacy_version
        result = subprocess.run([*prefix, 'merge', str(source), '--refresh-target', '--preserve-conflicts'], capture_output=True, text=True)
        assert result.returncode == 1 and 'merge not sent' in json.loads(result.stdout)['error']
        assert target.read_bytes() == before and source.read_bytes() == incoming
        assert not list(target.parent.glob('.*.akdbx-merge-*'))
    finally:
        process.terminate()
        output, errors = process.communicate(timeout=10)
        assert MASTER.encode() not in output + errors


@pytest.mark.parametrize('refresh_case', [True], indirect=True)
def test_policy_keyfiles_and_wrong_current_credentials_are_fail_closed(refresh_case):
    case = refresh_case
    originals = [opened(case, case.target), PyKeePass(io.BytesIO(case.broker_bytes), password=MASTER, keyfile=str(case.keyfile)), opened(case, case.source)]
    expected = ledger(originals)
    result = refresh(case, preserve_conflicts=True)
    assert result['ok'], result
    assert_retained(opened(case, case.target), expected)
    stable = case.target.read_bytes()
    wrong = opened(case, case.target)
    wrong.password = 'synthetic different current master'
    wrong.save()
    before = case.target.read_bytes()
    result = refresh(case, preserve_conflicts=True)
    assert not result['ok'] and case.target.read_bytes() == before
    assert case.broker.vault._akdbx_store.verified_encrypted == stable


def test_wrong_source_key_with_policy_preserves_target(pair):
    _, target, source = pair
    wrong = disk(source)
    wrong.password = 'synthetic different source master'
    wrong.save()
    before = target.read_bytes()
    result = merge(pair, preserve_conflicts=True)
    assert not result['ok'] and target.read_bytes() == before


def test_noncanonical_protected_fields_are_refused_without_dependency_logs(pair, capsys, caplog):
    _, target, source = pair
    wrong = disk(source)
    wrong.find_entries(title='Shared', first=True)._element.find('./String[Key="Password"]/Value').set('Protected', 'true')
    wrong.save()
    before = target.read_bytes()
    result = merge(pair, preserve_conflicts=True)
    assert not result['ok'] and target.read_bytes() == before
    output = capsys.readouterr()
    assert 'could not unprotect' not in output.err + caplog.text
    assert all(s not in json.dumps(result) + output.err + caplog.text for s in (MASTER, SECRET))


def test_policy_prepared_interruption_stays_blocked(pair, monkeypatch):
    broker, target, source = pair
    left, right = disk(target), disk(source)
    record(right, 'synthetic competing'); save_pair(pair, left, right)
    receipt = merging.MergeManager._receipt
    def interrupted(directory, value):
        receipt(directory, value)
        if value['state'] == 'prepared':
            raise KeyboardInterrupt
    monkeypatch.setattr(merging.MergeManager, '_receipt', staticmethod(interrupted))
    operation_id = uuid.uuid4().hex
    before = target.read_bytes()
    with pytest.raises(KeyboardInterrupt):
        merge(pair, preserve_conflicts=True, operation_id=operation_id)
    assert target.read_bytes() == before
    assert broker.dispatch({'action': 'ping'})['recovery_required']
    status = broker.dispatch({'action': 'merge-status', 'operation_id': operation_id})
    assert status['state'] == 'uncertain'
    assert status['preservation_policy'] == 'capsule-v1'
    assert_retained(disk(receipt_files(status) / 'candidate.kdbx'), ledger([left, right]))


def test_reserved_group_and_alias_collisions_are_not_overwritten(pair, monkeypatch):
    _, target, source = pair
    right = disk(source)
    right.add_group(right.root_group, 'Synthetic unrelated group').uuid = versions.ARCHIVE_UUID
    right.save()
    before = target.read_bytes()
    result = merge(pair, preserve_conflicts=True)
    assert not result['ok'] and target.read_bytes() == before
    monkeypatch.setattr(versions, '_alias', lambda identity: uuid.UUID(int=3))
    candidate = disk(target)
    with pytest.raises(versions.PreservationError, match='UUID collision'):
        versions.ensure(candidate, ledger([candidate]))
    candidate = disk(target)
    monkeypatch.setattr(versions, '_alias', lambda identity: candidate.root_group.uuid)
    with pytest.raises(versions.PreservationError, match='UUID collision'):
        versions.ensure(candidate, ledger([candidate]))


def test_unverified_dependency_disables_policy_without_a_merge(pair, monkeypatch):
    broker, target, source = pair
    before, incoming = target.read_bytes(), source.read_bytes()
    monkeypatch.setattr(versions, 'supported', lambda: False)
    status = broker.dispatch({'action': 'ping'})
    assert not status['merge_preserve_conflicts_supported'] and status['merge_preservation_policy'] is None
    result = merge(pair, preserve_conflicts=True)
    assert not result['ok'] and 'PyKeePass 4.2.0' in result['error']
    assert target.read_bytes() == before and source.read_bytes() == incoming


def test_real_cli_preservation_preview_save_and_refresh(pair, tmp_path):
    broker, target, source = pair
    left, right = disk(target), disk(source)
    record(left, 'synthetic target tie'); record(right, 'synthetic source tie')
    save_pair(pair, left, right)
    held, incoming = disk(target), disk(source)
    external = disk(target)
    external.delete_entry(external.find_entries(title='Left only', first=True))
    external.add_entry(external.root_group, 'External only', 'external', SECRET)
    record(external, 'synthetic external tie')
    replacement = tmp_path / 'external.kdbx'
    external.save(replacement)
    os.replace(replacement, target)
    expected = ledger([disk(target), held, incoming])
    external_bytes, source_bytes = target.read_bytes(), source.read_bytes()
    socket = tmp_path / 'private' / 'rpc.sock'
    prefix = [str(Path(sys.executable).parent / 'akdbx'), '--socket', str(socket)]
    def command(*args, status=0):
        completed = subprocess.run([*prefix, *args], capture_output=True, text=True, timeout=60)
        assert completed.returncode == status, completed.stderr
        assert all(s not in completed.stdout + completed.stderr for s in (MASTER, SECRET, 'synthetic source tie'))
        return json.loads(completed.stdout)
    with running_broker(socket, broker):
        caps = command('status')
        assert caps['version'] == '0.6.0' and caps['merge_preservation_policy'] == 'capsule-v1'
        assert not command('merge', str(source), '--refresh-target', status=1)['ok']
        checked = command('merge', str(source), '--refresh-target', '--preserve-conflicts', '--check')
        assert checked['state'] == 'checked'
        result = command('merge', str(source), '--refresh-target', '--preserve-conflicts')
        assert result['state'] == 'saved' and result['target_refreshed'], result
        assert command('merge-status', result['operation_id'])['preservation_policy'] == 'capsule-v1'
        assert len(command('search', 'Shared')['entries']) == 1
        for title in ('Left only', 'External only', 'Right only'):
            assert command('search', title)['entries']
        assert broker.vault.find_entries(title='Shared', first=True).password == 'synthetic external tie'
        assert (receipt_files(result) / 'target.kdbx').read_bytes() == external_bytes
        assert (receipt_files(result) / 'source.kdbx').read_bytes() == source_bytes
        assert source.read_bytes() == source_bytes
    assert_retained(disk(target), expected)


def test_policy_locked_cli_uses_existing_private_unlock(pair, tmp_path):
    _, target, source = pair
    left, right = disk(target), disk(source)
    record(left, 'synthetic private-unlock target'); record(right, 'synthetic private-unlock source')
    save_pair(pair, left, right)
    expected = ledger([disk(target), disk(source)])
    broker = Broker(None, RecordingTyper())
    socket = tmp_path / 'private' / 'rpc.sock'
    web_socket = socket.with_name('web.sock')
    server, url = start_unlock_server(broker, target, None, web_socket, 'https://node.example:9443')
    prefix = [str(Path(sys.executable).parent / 'akdbx'), '--socket', str(socket), '--unlock-origin', 'https://node.example:9443']
    operation_id = uuid.uuid4().hex
    command = [*prefix, 'merge', str(source), '--refresh-target', '--preserve-conflicts', '--operation-id', operation_id]
    try:
        with running_broker(socket, broker):
            locked = subprocess.run(command, capture_output=True, text=True, timeout=30)
            response = json.loads(locked.stdout)
            assert locked.returncode == 1 and response['unlock_url'] == url and response['continuation']
            assert not list(target.parent.glob('.*.akdbx-merge-*'))
            path = '/?' + urlsplit(url).query
            code, headers, body = call(web_socket, 'POST', path, urlencode({'password': MASTER}), timeout=10)
            assert code == 200 and headers['Cache-Control'] == 'no-store' and MASTER.encode() not in body
            saved = subprocess.run(command, capture_output=True, text=True, timeout=30)
            result = json.loads(saved.stdout)
            assert saved.returncode == 0 and result['state'] == 'saved' and result['preservation_policy'] == 'capsule-v1'
            assert all(s not in locked.stdout + locked.stderr + saved.stdout + saved.stderr for s in (MASTER, SECRET))
            assert_retained(disk(target), expected)
    finally:
        server.shutdown(); server.server_close()


def test_full_cost_41_argon2d_preservation(pair):
    from pykeepass.kdbx_parsing.kdbx4 import kdf_uuids
    broker, target, source = pair
    left, right = disk(target), disk(source)
    record(left, 'synthetic full-cost target'); record(right, 'synthetic full-cost source')
    # Force legitimate native protection and CustomData normalization at full
    # Argon2d cost; keep the exact original representation in capsule-v1.
    left.find_entries(title='Shared', first=True)._element.find('./String[Key="Password"]/Value').set('Protected', 'False')
    left.tree.find('./Meta/MemoryProtection/ProtectNotes').text = 'True'
    from test_selection import custom_data
    custom_data(left.find_entries(title='Shared', first=True), timed=True)
    for vault, path in ((left, target), (right, source)):
        vault.kdbx.header.value.minor_version = 1
        params = vault.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
        params['$UUID'].value = kdf_uuids['argon2']
        for key, value in {'I': 119, 'M': 67108864, 'P': 2, 'V': 19}.items():
            params[key].value = value
        vault.save(path)
    broker.vault = open_vault_with_password(target, MASTER)
    expected = ledger([disk(target), disk(source)])
    result = merge(pair, preserve_conflicts=True, refresh_target=True)
    assert result['ok'], result
    assert disk(target).encryption_algorithm == 'aes256' and disk(target).kdf_algorithm == 'argon2'
    assert_retained(disk(target), expected)
