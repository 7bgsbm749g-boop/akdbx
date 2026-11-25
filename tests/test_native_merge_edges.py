"""Regression cases for the built-in merge engine, using synthetic vaults."""
from datetime import timedelta
from pathlib import Path
import shutil

from lxml import etree
from pykeepass import PyKeePass, create_database
from pykeepass.kdbx_parsing.kdbx import KDBX
import pytest

from akdbx import versions
from akdbx.broker import Broker, open_vault_with_password
from test_merge import BASE_TIME, MASTER, RecordingTyper, base, disk, merge, pair


def test_history_limit_counts_tag_contents(pair):
    broker, target, source = pair
    left, right = disk(target), disk(source)
    original = left.find_entries(title='Shared', first=True)
    tags = [f'tag{n}' for n in range(64)]
    original.tags = tags
    strings = original._element.xpath('./String/Key | ./String/Value')
    size = sum(len((field.text or '').encode()) for field in strings) + sum(map(len, tags))
    left.tree.find('./Meta/HistoryMaxSize').text = str(size)
    left.save()
    newer = right.find_entries(uuid=original.uuid, first=True)
    newer.mtime = original.mtime + timedelta(days=1)
    newer.password = 'synthetic revision'
    right.save()
    broker.vault = open_vault_with_password(target, MASTER)
    assert merge(pair)['state'] == 'saved'
    assert disk(target).find_entries(uuid=original.uuid, first=True).history[0].tags == tags


def set_metadata(vault, key, value):
    container = vault.tree.find('./Meta/CustomData')
    if container is None:
        container = etree.SubElement(vault.tree.find('Meta'), 'CustomData')
    for item in container.xpath('./Item[Key=$key]', key=key):
        container.remove(item)
    if value is not None:
        item = etree.SubElement(container, 'Item')
        etree.SubElement(item, 'Key').text = key
        etree.SubElement(item, 'Value').text = value


def test_imported_dictionary_clock_does_not_age_target_keys_or_copy_slug(pair):
    broker, target, source = pair
    left, right = disk(target), disk(source)
    set_metadata(left, 'KPXC_RANDOM_SLUG', None)
    set_metadata(left, '_LAST_MODIFIED', '2026-01-01T00:00:00Z')
    set_metadata(left, 'Retained', 'original')
    left.save()
    set_metadata(right, 'KPXC_RANDOM_SLUG', 'synthetic source slug')
    set_metadata(right, '_LAST_MODIFIED', '2026-01-03T00:00:00Z')
    set_metadata(right, 'Imported', 'newest')
    right.save()
    broker.vault = open_vault_with_password(target, MASTER)
    assert merge(pair)['state'] == 'saved'
    result = disk(target)
    assert result.tree.find('./Meta/CustomData/Item[Key="KPXC_RANDOM_SLUG"]') is None
    set_metadata(right, '_LAST_MODIFIED', '2026-01-02T00:00:00Z')
    set_metadata(right, 'Retained', 'updated')
    set_metadata(right, 'Imported', 'older')
    right.save()
    assert merge(pair)['state'] == 'saved'
    result = disk(target)
    assert result.tree.findtext('./Meta/CustomData/Item[Key="Retained"]/Value') == 'updated'
    assert result.tree.findtext('./Meta/CustomData/Item[Key="Imported"]/Value') == 'newest'


def test_move_backup_coexists_with_active_record_on_repeat(pair):
    broker, target, source = pair
    left, right = disk(target), disk(source)
    local = left.find_entries(title='Shared', first=True)
    remote = right.find_entries(uuid=local.uuid, first=True)
    local.password = 'synthetic local update'
    local.mtime = BASE_TIME + timedelta(days=1)
    local._element.find('Times/LocationChanged').text = left._encode_time(BASE_TIME)
    remote._element.find('Times/LocationChanged').text = right._encode_time(BASE_TIME + timedelta(days=2))
    right.move_entry(remote, right.root_group)
    left.save()
    right.save()
    broker.vault = open_vault_with_password(target, MASTER)
    assert merge(pair)['state'] == 'saved'
    entry = broker.vault.find_entries(uuid=local.uuid, first=True)
    assert entry.group == broker.vault.root_group and entry.password == local.password
    saved = target.read_bytes()
    assert merge(pair)['state'] == 'unchanged' and target.read_bytes() == saved


@pytest.mark.parametrize('ids,missing', [((2, 0, 1), False), ((500, 23, 99), False),
                                          ((1, 1, 2), False), ((2, 0, 1), True)])
def test_legacy_attachments_use_declared_ids(tmp_path, ids, missing):
    password = 'synthetic format fixture'
    target, source = tmp_path / 'target.kdbx', tmp_path / 'source.kdbx'
    shutil.copyfile(Path(__file__).parent / 'fixtures/empty-3.1.kdbx', target)
    vault = PyKeePass(target, password=password)
    entry = vault.add_entry(vault.root_group, 'Attachments', 'account', 'synthetic')
    payloads = (b'first', b'second', b'third')
    for number, payload in enumerate(payloads):
        entry.add_attachment(versions.append_binary(vault, payload), f'{number}.bin')
    entry.save_history()
    for node, identity in zip(vault.tree.findall('./Meta/Binaries/Binary'), ids):
        node.set('ID', str(identity))
    for node in entry._element.xpath('./Binary/Value | ./History/Entry/Binary/Value'):
        node.set('Ref', str(ids[int(node.get('Ref'))]))
    if missing:
        entry._element.find('Binary/Value').set('Ref', '7')
    # Keep the fixture's authenticated header and the intentionally unordered IDs.
    source.write_bytes(KDBX.build(vault.kdbx, password=password, keyfile=None, transformed_key=None, decrypt=True))
    before = source.read_bytes()
    broker = Broker(open_vault_with_password(target, password), RecordingTyper())
    original = target.read_bytes()
    receipt = merge((broker, target, source))
    if missing or len(set(ids)) < len(ids):
        assert receipt['state'] == 'failed' and target.read_bytes() == original
        return
    assert receipt['state'] == 'saved'
    result = PyKeePass(target, password=password)
    active = result.find_entries(uuid=entry.uuid, first=True)
    for record in [active, *active.history]:
        assert tuple(result.binaries[int(v.get('Ref'))] for v in record._element.findall('Binary/Value')) == payloads
    assert source.read_bytes() == before


@pytest.mark.parametrize('owner', ['group', 'entry', 'capsule'])
def test_legacy_target_refuses_plugin_data(tmp_path, owner):
    password = 'synthetic format fixture'
    target, source = tmp_path / 'target.kdbx', tmp_path / 'source.kdbx'
    shutil.copyfile(Path(__file__).parent / 'fixtures/empty-3.1.kdbx', target)
    incoming = create_database(str(source), password=password)
    group = incoming.add_group(incoming.root_group, 'Plugin group')
    entry = incoming.add_entry(group, 'Plugin entry', 'synthetic', 'synthetic')
    if owner != 'capsule':
        node = group._element if owner == 'group' else entry._element
        item = etree.SubElement(etree.SubElement(node, 'CustomData'), 'Item')
        etree.SubElement(item, 'Key').text = 'plugin'
        etree.SubElement(item, 'Value').text = 'synthetic'
    incoming.save()
    before = target.read_bytes()
    broker = Broker(open_vault_with_password(target, password), RecordingTyper())
    result = merge((broker, target, source), preserve_conflicts=owner == 'capsule')
    assert result['state'] == 'failed' and target.read_bytes() == before
