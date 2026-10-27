"""Generated synthetic KDBXs only; real KeePassXC semantic verification."""
from __future__ import annotations

import base64
import io
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from lxml import etree
from pykeepass import PyKeePass

from agentic_kdbx import cli, merge as merging, selection, versions
from agentic_kdbx.broker import open_vault_with_password
from test_broker import running_broker
from test_merge import MASTER, SECRET, BASE_TIME, base, pair, disk, merge, receipt_files
from test_versions import assert_retained, ledger, save_pair, record


def put(parent, tag, value):
    node = parent.find(tag)
    if node is None:
        node = etree.SubElement(parent, tag)
    node.text = value
    return node


def custom_data(entry, key='synthetic metadata key', value='synthetic metadata value', *, timed=False):
    container = entry._element.find('CustomData')
    if container is None:
        container = etree.SubElement(entry._element, 'CustomData')
    item = etree.SubElement(container, 'Item')
    etree.SubElement(item, 'Key').text = key
    etree.SubElement(item, 'Value').text = value
    if timed:
        etree.SubElement(item, 'LastModificationTime').text = entry._kp._encode_time(BASE_TIME)


CASES = ('unprotected-password', 'protect-notes', 'protect-all', 'missing-password',
         'empty-protected-password', 'protect-in-memory', 'custom-protected', 'custom-unprotected',
         'quality-true', 'quality-false', 'previous-null', 'custom-data', 'custom-data-timed',
         'knownbad-true', 'knownbad-false', 'tags', 'tags-unicode', 'icon-numeric', 'null-custom-icon',
         'autotype', 'autotype-associations', 'expiry-year1', 'expiry-year9999', 'expired',
         'creation-non-epoch', 'iso-times', 'iso-offset-times', 'iso-fractional-times', 'missing-statistics',
         'autotype-numeric', 'custom-reserved-name', 'knownbad-uppercase')
OLD_REFUSAL = {'unprotected-password', 'protect-notes', 'protect-all', 'missing-password',
               'protect-in-memory', 'quality-true', 'previous-null', 'custom-data', 'custom-data-timed',
               'knownbad-true', 'knownbad-false', 'tags', 'tags-unicode', 'icon-numeric', 'null-custom-icon'}


def style(vault, case):
    entry = vault.find_entries(title='Shared', first=True)
    if case == 'unprotected-password':
        entry._element.find('./String[Key="Password"]/Value').set('Protected', 'False')
    elif case in {'protect-notes', 'protect-all'}:
        for flag in (('ProtectNotes',) if case == 'protect-notes' else ('ProtectTitle', 'ProtectUserName', 'ProtectPassword', 'ProtectURL', 'ProtectNotes')):
            # KeePass's XML uses ProtectUserName (native API calls it Username).
            put(vault.tree.find('./Meta/MemoryProtection'), flag, 'True')
    elif case == 'missing-password':
        entry._element.remove(entry._element.find('./String[Key="Password"]'))
    elif case == 'empty-protected-password':
        entry.password = ''
    elif case == 'protect-in-memory':
        node = entry._element.find('./String[Key="Password"]/Value')
        node.set('Protected', 'False'); node.set('ProtectInMemory', 'True')
    elif case in {'custom-protected', 'custom-unprotected'}:
        entry.set_custom_property('synthetic custom field', '  synthetic value 🦊 !\t\n ', protect=case == 'custom-protected')
    elif case in {'quality-true', 'quality-false'}:
        put(entry._element, 'QualityCheck', 'True' if case == 'quality-true' else 'False')
    elif case == 'previous-null':
        put(entry._element, 'PreviousParentGroup', base64.b64encode(bytes(16)).decode())
    elif case in {'custom-data', 'custom-data-timed'}:
        custom_data(entry, timed=case == 'custom-data-timed')
    elif case.startswith('knownbad-'):
        custom_data(entry, 'KnownBad', 'True' if case.endswith('uppercase') else 'true' if case.endswith('true') else 'false', timed=True)
    elif case == 'custom-reserved-name':
        entry.set_custom_property('_LAST_MODIFIED', 'synthetic ordinary field value', protect=True)
    elif case in {'tags', 'tags-unicode'}:
        put(entry._element, 'Tags', ' tag1,tag2;tag1 ' if case == 'tags' else '\u00a0🦊,é;é\u2003;z\t🦊')
    elif case == 'icon-numeric':
        put(entry._element, 'IconID', '0001')
    elif case == 'null-custom-icon':
        put(entry._element, 'CustomIconUUID', base64.b64encode(bytes(16)).decode())
    elif case == 'autotype':
        put(entry._element.find('AutoType'), 'Enabled', 'False')
        put(entry._element.find('AutoType'), 'DefaultSequence', '{USERNAME}{TAB}{PASSWORD}')
    elif case == 'autotype-numeric':
        put(entry._element.find('AutoType'), 'DataTransferObfuscation', '0001')
    elif case == 'autotype-associations':
        for title in ('synthetic first window', 'synthetic second window'):
            association = etree.SubElement(entry._element.find('AutoType'), 'Association')
            etree.SubElement(association, 'Window').text = title
            etree.SubElement(association, 'KeystrokeSequence').text = '{PASSWORD}{ENTER}'
    elif case.startswith('expiry-year'):
        entry.expires = False
        entry.expiry_time = datetime(1 if case == 'expiry-year1' else 9999, 1, 1, tzinfo=timezone.utc)
    elif case == 'expired':
        entry.expires = True
        entry.expiry_time = BASE_TIME - timedelta(days=70)
    elif case == 'creation-non-epoch':
        entry.ctime = datetime(1997, 3, 27, 17, 14, 33, tzinfo=timezone.utc)
    elif case in {'iso-times', 'iso-offset-times', 'iso-fractional-times'}:
        for node in entry._element.find('Times'):
            if node.tag.endswith('Time') or node.tag == 'LocationChanged':
                stamp = BASE_TIME
                if case == 'iso-offset-times':
                    stamp = stamp.astimezone(timezone(timedelta(hours=2)))
                if case == 'iso-fractional-times':
                    stamp += timedelta(microseconds=123000)
                node.text = stamp.isoformat()
    elif case == 'missing-statistics':
        for name in ('LastAccessTime', 'UsageCount'):
            entry._element.find('Times').remove(entry._element.find('Times/' + name))
    return entry


@pytest.mark.parametrize('case', CASES)
def test_native_legitimate_metadata_keeps_selected_values_and_exact_capsules(pair, case):
    broker, target, source = pair
    left, right = disk(target), disk(source)
    selected = style(left, case)
    original_uuid = selected.uuid
    password = selected.password or ''
    save_pair(pair, left, right)
    expected = ledger([disk(target), disk(source)])
    before, incoming = target.read_bytes(), source.read_bytes()
    checked = merge(pair, refresh_target=True, preserve_conflicts=True, check=True)
    assert checked['ok'] and checked['state'] == 'checked', checked
    assert target.read_bytes() == before and broker.vault._akdbx_store.verified_encrypted == before
    result = merge(pair, refresh_target=True, preserve_conflicts=True)
    assert result['ok'] and result['state'] == 'saved', result
    assert result['target_refreshed'] is False
    assert result['active_verification'] == 'semantic-v1'
    saved = disk(target)
    actual = saved.find_entries(uuid=original_uuid, first=True)
    assert (actual.password or '') == password
    assert actual.uuid == original_uuid
    assert_retained(saved, expected)
    assert source.read_bytes() == incoming
    assert (receipt_files(result) / 'target.kdbx').read_bytes() == before
    if case in OLD_REFUSAL:
        assert versions.entry_signature(actual) != versions.entry_signature(left.find_entries(uuid=original_uuid, first=True))
    repeated = merge(pair, refresh_target=True, preserve_conflicts=True)
    assert repeated['ok'], repeated
    assert_retained(disk(target), expected)


@pytest.mark.parametrize('newer', ['target', 'source', 'tie'])
def test_native_location_is_checked_independently_of_active_value(pair, newer):
    broker, target, source = pair
    left, right = disk(target), disk(source)
    a = record(left, 'synthetic chosen target', days=2)
    b = record(right, 'synthetic remote value', days=3 if newer == 'source' else 2 if newer == 'tie' else 1)
    a._element.find('Times/LocationChanged').text = left._encode_time(BASE_TIME)
    destination = right.add_group(right.root_group, 'synthetic independent location')
    right.move_entry(b, destination)
    b._element.find('Times/LocationChanged').text = right._encode_time(BASE_TIME + timedelta(days=4))
    save_pair(pair, left, right)
    expected = ledger([disk(target), disk(source)])
    result = merge(pair, refresh_target=True, preserve_conflicts=True)
    assert result['ok'], result
    actual = broker.vault.find_entries(uuid=a.uuid, first=True)
    assert actual.group.uuid == destination.uuid
    assert actual.password == (b.password if newer == 'source' else a.password)
    assert selection.time_value(actual, 'LocationChanged') == selection.time_value(b if newer == 'source' else a, 'LocationChanged')
    assert_retained(disk(target), expected)


@pytest.mark.parametrize('mutation,category', [
    ('missing', 'missing_entry'), ('unexpected', 'unexpected_entry'), ('password', 'standard_fields'),
    ('username', 'standard_fields'), ('custom', 'custom_fields'), ('custom-empty', 'custom_fields'),
    ('attachment', 'attachments'), ('attachment-name', 'attachments'), ('mtime', 'modification_time'),
    ('ctime', 'times_metadata'), ('expires', 'times_metadata'), ('expiry', 'times_metadata'),
    ('location', 'location'), ('location-time', 'location'), ('previous', 'location'),
    ('protection', 'field_protection'), ('autotype', 'entry_metadata'), ('tags', 'entry_metadata'),
    ('quality', 'entry_metadata'), ('custom-data', 'custom_data'),
    ('reserved-custom', 'custom_fields'), ('duplicate', 'duplicate_entry'),
])
def test_real_native_result_corruption_is_refused_with_private_durable_categories(pair, monkeypatch, capsys, caplog, mutation, category):
    broker, target, source = pair
    left, right = disk(target), disk(source)
    a = left.find_entries(title='Shared', first=True)
    a.set_custom_property('synthetic private field name', 'synthetic custom secret', protect=True)
    a.set_custom_property('_LAST_MODIFIED', 'synthetic ordinary field secret', protect=True)
    a.add_attachment(left.add_binary(b'synthetic exact original attachment'), 'synthetic original filename')
    a.expires = True; a.expiry_time = BASE_TIME + timedelta(days=1000)
    custom_data(a)
    save_pair(pair, left, right)
    before, incoming = target.read_bytes(), source.read_bytes()
    original_image = broker.vault._akdbx_store.verified_encrypted
    engine = merging.run_engine
    def corrupted(bundle, vault, **kwargs):
        engine(bundle, vault, **kwargs)
        candidate = disk(bundle / 'candidate.kdbx')
        entry = candidate.find_entries(uuid=a.uuid, first=True)
        if mutation == 'missing': candidate.delete_entry(entry)
        elif mutation == 'unexpected': candidate.add_entry(candidate.root_group, 'synthetic unexpected', '', SECRET)
        elif mutation == 'password': entry.password = 'synthetic incorrect active secret'
        elif mutation == 'username': entry.username = 'synthetic incorrect user'
        elif mutation == 'custom': entry.set_custom_property('synthetic private field name', 'synthetic incorrect custom', protect=True)
        elif mutation == 'custom-empty': entry.set_custom_property('synthetic empty private field', '')
        elif mutation in {'attachment', 'attachment-name'}:
            entry.attachments[0].delete()
            entry.add_attachment(candidate.add_binary(b'incorrect' if mutation == 'attachment' else b'synthetic exact original attachment'), 'wrong name' if mutation == 'attachment-name' else 'synthetic original filename')
        elif mutation == 'mtime': entry.mtime += timedelta(days=1)
        elif mutation == 'ctime': entry.ctime += timedelta(days=1)
        elif mutation == 'expires': entry.expires = False
        elif mutation == 'expiry': entry.expiry_time += timedelta(days=1)
        elif mutation == 'location': candidate.move_entry(entry, candidate.root_group)
        elif mutation == 'location-time': entry._element.find('Times/LocationChanged').text = candidate._encode_time(BASE_TIME)
        elif mutation == 'previous': put(entry._element, 'PreviousParentGroup', base64.b64encode(uuid.uuid4().bytes).decode())
        elif mutation == 'protection': entry._element.find('./String[Key="Password"]/Value').set('Protected', 'False')
        elif mutation == 'autotype': put(entry._element.find('AutoType'), 'DefaultSequence', '{PASSWORD}')
        elif mutation == 'tags': put(entry._element, 'Tags', 'synthetic incorrect tag')
        elif mutation == 'quality': put(entry._element, 'QualityCheck', 'False')
        elif mutation == 'custom-data': entry._element.find('./CustomData/Item[Key="synthetic metadata key"]/Value').text = 'incorrect'
        elif mutation == 'reserved-custom': entry.set_custom_property('_LAST_MODIFIED', 'incorrect', protect=True)
        elif mutation == 'duplicate':
            duplicate = candidate.add_entry(candidate.root_group, 'synthetic duplicate', '', '')
            duplicate.uuid = a.uuid
        candidate.save()
    monkeypatch.setattr(merging, 'run_engine', corrupted)
    result = merge(pair, refresh_target=True, preserve_conflicts=True)
    assert result['state'] == 'failed' and not result['ok'], result
    assert result['verification_diagnostics'].get(category) == 1
    assert set(result['verification_diagnostics']) <= selection.CATEGORIES
    assert json.loads(Path(result['receipt_path']).read_bytes())['verification_diagnostics'] == result['verification_diagnostics']
    assert target.read_bytes() == before and source.read_bytes() == incoming
    assert broker.vault._akdbx_store.verified_encrypted == original_image
    output = capsys.readouterr()
    status = broker.dispatch({'action': 'merge-status', 'operation_id': result['operation_id']})
    serialized = json.dumps(result) + json.dumps(status) + output.out + output.err + caplog.text
    for private in (MASTER, SECRET, str(a.uuid), 'Shared', 'synthetic private field name', 'synthetic custom secret',
                    'synthetic original filename', 'synthetic incorrect active secret'):
        assert private not in serialized


@pytest.mark.parametrize('case,category', [('unknown-entry', 'unsupported_metadata'), ('missing-creation', 'unsupported_times'), ('invalid-modification', 'unsupported_times')])
def test_unsupported_selected_structure_has_a_fixed_nonsecret_reason(pair, case, category):
    _, target, source = pair
    left, right = disk(target), disk(source)
    entry = left.find_entries(title='Shared', first=True)
    if case == 'unknown-entry':
        etree.SubElement(entry._element, 'SyntheticPrivateExtensionName').text = 'synthetic extension secret'
    elif case == 'missing-creation':
        entry._element.find('Times').remove(entry._element.find('Times/CreationTime'))
    else:
        entry._element.find('Times/LastModificationTime').text = 'synthetic invalid private value'
    save_pair(pair, left, right)
    before = target.read_bytes()
    result = merge(pair, preserve_conflicts=True)
    assert result['verification_diagnostics'] == {category: 1}, result
    assert target.read_bytes() == before
    assert 'SyntheticPrivate' not in json.dumps(result) and 'synthetic extension secret' not in json.dumps(result)


def test_newer_history_does_not_replace_active_and_input_versions_stay_exact(pair):
    _, target, source = pair
    left, right = disk(target), disk(source)
    entry = left.find_entries(title='Shared', first=True)
    entry.password = 'synthetic future history'; entry.mtime = BASE_TIME + timedelta(days=20)
    entry.save_history()
    entry.password = 'synthetic actual active'; entry.mtime = BASE_TIME
    save_pair(pair, left, right)
    expected = ledger([disk(target), disk(source)])
    result = merge(pair, preserve_conflicts=True, refresh_target=True)
    assert result['ok'], result
    assert disk(target).find_entries(title='Shared', first=True).password == 'synthetic actual active'
    assert_retained(disk(target), expected)


def test_source_root_uuid_maps_to_destination_root_without_changing_entry_ids(pair):
    _, target, source = pair
    incoming = disk(source)
    incoming.root_group.uuid = uuid.uuid4()
    incoming.save()
    identity = incoming.find_entries(title='Right only', first=True).uuid
    expected = ledger([disk(target), disk(source)])
    result = merge(pair, preserve_conflicts=True)
    assert result['ok'], result
    saved = disk(target)
    assert saved.find_entries(uuid=identity, first=True).group.uuid == saved.root_group.uuid
    assert_retained(saved, expected)


def test_capsule_v1_payload_and_identity_remain_compatible_with_050(pair):
    broker, target, source = pair
    code = subprocess.run(['git', 'show', 'c50afe49efef6f4f37143b989048d4b73ff1c361:src/agentic_kdbx/versions.py'], capture_output=True, check=True).stdout
    import types
    old = types.ModuleType('synthetic_050_versions')
    exec(compile(code, '<frozen 0.5.0 versions>', 'exec'), old.__dict__)
    left, right = disk(target), disk(source)
    style(left, 'unprotected-password'); style(left, 'custom-data-timed')
    originals = old.collect([left, right], capture=True)
    old.ensure(left, originals); left.save(target)
    broker.vault = open_vault_with_password(target, MASTER)
    assert versions.archives(broker.vault) == originals
    for identity, payload in originals.items():
        assert versions.capsule_identity(json.loads(payload)) == old.capsule_identity(json.loads(payload)) == identity
    result = merge(pair, preserve_conflicts=True, refresh_target=True)
    assert result['ok'], result
    assert_retained(disk(target), originals)


@pytest.mark.parametrize('capability', [None, 'unknown', False])
def test_cli_demands_semantic_capability_even_with_valid_capsule_policy(monkeypatch, capsys, capability):
    calls = []
    def request(path, payload, **kwargs):
        calls.append(payload)
        return {'ok': True, 'merge_refresh_target_supported': True, 'merge_preserve_conflicts_supported': True,
                'merge_preservation_policy': 'capsule-v1', 'merge_active_verification': capability}
    monkeypatch.setattr(cli, 'request', request)
    assert cli.main(['merge', '/synthetic/source.kdbx', '--preserve-conflicts', '--refresh-target']) == 1
    assert calls == [{'action': 'ping'}]
    assert 'semantic-v1' in json.loads(capsys.readouterr().out)['error']


def test_unknown_requested_verification_is_not_silently_ignored(pair):
    _, target, source = pair
    before, incoming = target.read_bytes(), source.read_bytes()
    result = merge(pair, preserve_conflicts=True, active_verification='unknown')
    assert not result['ok'] and 'unsupported active verification' in result['error']
    assert not list(target.parent.glob('.*.akdbx-merge-*'))
    assert target.read_bytes() == before and source.read_bytes() == incoming


@pytest.mark.parametrize('use_keyfile', [False, True])
def test_real_cli_semantics_three_inputs_metadata_location_and_refresh(pair, tmp_path, use_keyfile):
    broker, target, source = pair
    held, incoming = disk(target), disk(source)
    a = record(held, 'synthetic held value', days=4, attachment=b'synthetic held attachment')
    a._element.find('Times/LocationChanged').text = held._encode_time(BASE_TIME + timedelta(days=6))
    record(incoming, 'synthetic incoming tie', days=4, attachment=b'synthetic incoming attachment')
    destination = incoming.add_group(incoming.root_group, 'Synthetic incoming location')
    incoming.move_entry(incoming.find_entries(title='Shared', first=True), destination)
    incoming.find_entries(title='Shared', first=True)._element.find('Times/LocationChanged').text = incoming._encode_time(BASE_TIME + timedelta(days=5))
    external = disk(target)
    external.delete_entry(external.find_entries(title='Left only', first=True))
    external.add_entry(external.root_group, 'External only', 'external', SECRET)
    record(external, 'synthetic disk tie', days=4, attachment=b'synthetic disk attachment')
    style(external, 'unprotected-password'); style(external, 'custom-data-timed'); style(external, 'tags')
    external_group = external.add_group(external.root_group, 'Synthetic external location')
    entry = external.find_entries(title='Shared', first=True)
    external.move_entry(entry, external_group)
    entry._element.find('Times/LocationChanged').text = external._encode_time(BASE_TIME + timedelta(days=4))
    keyfile = tmp_path / 'synthetic.key' if use_keyfile else None
    if keyfile:
        keyfile.write_bytes(b'synthetic semantic verification key bytes')
        for vault in (held, external, incoming): vault.keyfile = str(keyfile)
    held.save(target); incoming.save(source)
    broker.vault = open_vault_with_password(target, MASTER, keyfile)
    held_bytes = target.read_bytes()
    replacement = tmp_path / 'synthetic-external.kdbx'
    external.save(replacement); os.replace(replacement, target)
    key = str(keyfile) if keyfile else None
    expected = ledger([PyKeePass(target, password=MASTER, keyfile=key),
                       PyKeePass(io.BytesIO(held_bytes), password=MASTER, keyfile=key),
                       PyKeePass(source, password=MASTER, keyfile=key)])
    disk_bytes, source_bytes = target.read_bytes(), source.read_bytes()
    socket = tmp_path / 'private' / 'broker.sock'
    prefix = [str(Path(sys.executable).parent / 'akdbx'), '--socket', str(socket)]
    def command(*args):
        done = subprocess.run([*prefix, *args], capture_output=True, text=True, timeout=60)
        assert done.returncode == 0, done.stderr
        assert all(value not in done.stdout + done.stderr for value in (MASTER, SECRET, 'synthetic disk tie'))
        return json.loads(done.stdout)
    with running_broker(socket, broker):
        capabilities = command('status')
        assert capabilities['version'] == '0.8.1' and capabilities['merge_active_verification'] == 'semantic-v1'
        assert capabilities['merge_diagnostics'] == 'categories-v1'
        selected = command('search', 'Shared')['entries'][0]['handle']
        checked = command('merge', str(source), '--refresh-target', '--preserve-conflicts', '--check')
        assert checked['state'] == 'checked' and target.read_bytes() == disk_bytes
        assert broker.vault._akdbx_store.verified_encrypted == held_bytes and selected in broker._handles
        result = command('merge', str(source), '--refresh-target', '--preserve-conflicts')
        assert result['state'] == 'saved' and result['active_verification'] == 'semantic-v1'
        assert command('merge-status', result['operation_id'])['active_verification'] == 'semantic-v1'
        assert selected not in broker._handles
        for title in ('Left only', 'External only', 'Right only'):
            assert command('search', title)['entries']
    vault = PyKeePass(target, password=MASTER, keyfile=str(keyfile) if keyfile else None)
    assert vault.find_entries(title='Shared', first=True).password == 'synthetic disk tie'
    assert vault.find_entries(title='Shared', first=True).group.uuid == destination.uuid
    assert_retained(vault, expected)
    assert source.read_bytes() == source_bytes
    assert (receipt_files(result) / 'broker.kdbx').read_bytes() == held_bytes
    assert (receipt_files(result) / 'target.kdbx').read_bytes() == disk_bytes
    assert (receipt_files(result) / 'source.kdbx').read_bytes() == source_bytes


def test_real_cli_diagnostic_receipt_is_safe_and_failed_merge_keeps_broker_revision(pair, tmp_path, monkeypatch):
    broker, target, source = pair
    engine = merging.run_engine
    before, incoming = target.read_bytes(), source.read_bytes()
    handle = broker.dispatch({'action': 'search', 'query': 'Shared'})['entries'][0]['handle']
    def corrupted(bundle, vault, **kwargs):
        engine(bundle, vault, **kwargs)
        candidate = disk(bundle / 'candidate.kdbx')
        for title in ('Shared', 'Left only'):
            candidate.find_entries(title=title, first=True).password = 'synthetic wrong active value'
        candidate.save()
    monkeypatch.setattr(merging, 'run_engine', corrupted)
    socket = tmp_path / 'private' / 'broker.sock'
    prefix = [str(Path(sys.executable).parent / 'akdbx'), '--socket', str(socket)]
    with running_broker(socket, broker):
        done = subprocess.run([*prefix, 'merge', str(source), '--preserve-conflicts', '--refresh-target'], capture_output=True, text=True, timeout=60)
        result = json.loads(done.stdout)
        assert done.returncode == 1 and result['state'] == 'failed'
        assert result['verification_diagnostics'] == {'standard_fields': 2}
        status = subprocess.run([*prefix, 'merge-status', result['operation_id']], capture_output=True, text=True, timeout=30)
        assert json.loads(status.stdout)['verification_diagnostics'] == {'standard_fields': 2}
        assert all(value not in done.stdout + done.stderr + status.stdout + status.stderr for value in (MASTER, SECRET, 'synthetic wrong active value', 'Shared', 'Left only'))
    assert target.read_bytes() == before and source.read_bytes() == incoming
    assert broker.vault._akdbx_store.verified_encrypted == before and handle in broker._handles


def test_real_cli_same_image_normalizes_metadata_without_wrong_active_selection(pair, tmp_path):
    broker, target, source = pair
    left, right = disk(target), disk(source)
    record(left, 'synthetic current selected value', attachment=b'synthetic chosen attachment')
    record(right, 'synthetic competing source value', attachment=b'synthetic other attachment')
    style(left, 'unprotected-password'); style(left, 'protect-notes'); style(left, 'custom-data-timed')
    save_pair(pair, left, right)
    expected = ledger([disk(target), disk(source)])
    before, incoming = target.read_bytes(), source.read_bytes()
    socket = tmp_path / 'private' / 'broker.sock'
    prefix = [str(Path(sys.executable).parent / 'akdbx'), '--socket', str(socket)]
    with running_broker(socket, broker):
        checked = subprocess.run([*prefix, 'merge', str(source), '--refresh-target', '--preserve-conflicts', '--check'], capture_output=True, text=True, timeout=60)
        preview = json.loads(checked.stdout)
        assert checked.returncode == 0 and preview['state'] == 'checked' and preview['target_refreshed'] is False
        assert target.read_bytes() == before
        done = subprocess.run([*prefix, 'merge', str(source), '--refresh-target', '--preserve-conflicts'], capture_output=True, text=True, timeout=60)
        result = json.loads(done.stdout)
        assert done.returncode == 0 and result['state'] == 'saved' and result['target_refreshed'] is False
        assert result['active_verification'] == 'semantic-v1' and result['preservation_policy'] == 'capsule-v1'
        assert broker.vault.find_entries(title='Shared', first=True).password == 'synthetic current selected value'
    saved = disk(target)
    active = saved.find_entries(title='Shared', first=True)
    assert active.password == 'synthetic current selected value' and active.attachments[0].data == b'synthetic chosen attachment'
    assert versions.entry_signature(active) != versions.entry_signature(left.find_entries(title='Shared', first=True))
    assert_retained(saved, expected)
    assert source.read_bytes() == incoming
    assert all(value not in done.stdout + done.stderr + checked.stdout + checked.stderr for value in (MASTER, SECRET, 'synthetic current selected value', 'synthetic competing source value'))
