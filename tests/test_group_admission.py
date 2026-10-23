"""Synthetic group read/write projections; never native-mobile verification.

Projection follows public KeePassium 2.5.171 Group2.load/toXml and TagHelper
(commit 4dc000da761217d1f8fab7ac40c4195d7b2ff37b, retrieved 2026-10-23),
with complete valid Times. Native references use actual KeePassXC 2.7.10.
No XML is exported; encrypted test databases alone are written to disk.
"""
import base64
import copy
import hashlib
import json
import re
import shutil
import subprocess
import types
import uuid
from datetime import timedelta, timezone

import pytest
from lxml import etree
from pykeepass import PyKeePass

from agentic_kdbx import admission, cli, merge as merging, selection, versions
from agentic_kdbx.broker import open_vault_with_password
from test_admission import case, admit, bundle, edit
from test_broker import running_broker
from test_merge import MASTER, SECRET, BASE_TIME, base
from test_selection import put
from upload_lab import Lab, servers, http, KeePassiumSequence

ZERO = base64.b64encode(bytes(16)).decode()


def project_group(vault, group):
    """Valid Group2 reader defaults and writer ordering, including KDBX4.1 Tags.

    Deliberately not an admission implementation: explicit independent test
    model of the two public Swift methods. Complete Times retain their values;
    disabled expiry timestamps are not changed by this projection.
    """
    old = group._element
    new = etree.Element('Group')
    for tag, default in [('UUID', ZERO), ('Name', ''), ('Notes', ''), ('IconID', '48')]:
        put(new, tag, old.findtext(tag) or default)
    if old.findtext('CustomIconUUID', ZERO) != ZERO:
        put(new, 'CustomIconUUID', old.findtext('CustomIconUUID'))
    times = etree.SubElement(new, 'Times')
    for tag in ('CreationTime', 'LastModificationTime', 'LastAccessTime', 'ExpiryTime',
                'Expires', 'UsageCount', 'LocationChanged'):
        text = old.findtext('Times/' + tag)
        assert text is not None, 'projection fixture requires complete Times'
        if tag == 'Expires': text = 'True' if selection._boolean(text) else 'False'
        elif tag == 'UsageCount': text = str(int(text))
        else: text = vault._encode_time(selection.decode_time(text, vault.version))
        put(times, tag, text)
    put(new, 'IsExpanded', old.findtext('IsExpanded', 'True'))
    put(new, 'DefaultAutoTypeSequence', old.findtext('DefaultAutoTypeSequence') or '')
    for tag in ('EnableAutoType', 'EnableSearching'):
        value = old.findtext(tag, 'null').lower()
        assert value in {'null', 'true', 'false'}
        put(new, tag, {'null': 'null', 'true': 'True', 'false': 'False'}[value])
    put(new, 'LastTopVisibleEntry', old.findtext('LastTopVisibleEntry') or ZERO)
    if old.findtext('PreviousParentGroup', ZERO) != ZERO:
        put(new, 'PreviousParentGroup', old.findtext('PreviousParentGroup'))
    # Public TagHelper splits comma/semicolon, trims whitespace, removes empty
    # tags and writes comma separators. Ordinary fixtures are already canonical.
    tags = [tag.strip(' \t') for tag in re.split('[,;]', old.findtext('Tags') or '')]
    put(new, 'Tags', ','.join(tag for tag in tags if tag))
    custom = old.find('CustomData')
    if custom is not None and len(custom):
        new.append(copy.deepcopy(custom))
    for child in list(old):
        if child.tag in {'Entry', 'Group'}:
            new.append(child)
    new.tail = old.tail
    old.getparent().replace(old, new)


def project(vault):
    # Children first because PyKeePass group wrappers refer to XML nodes.
    for group in reversed(vault.groups): project_group(vault, group)


@pytest.fixture
def native_case(case, tmp_path):
    broker, target, source, snapshots = case
    vault = PyKeePass(target, password=MASTER)
    recycle = vault.add_group(vault.root_group, 'Synthetic recycle bin')
    put(vault.tree.find('./Meta'), 'RecycleBinUUID', recycle._element.findtext('UUID'))
    put(vault.tree.find('./Meta'), 'RecycleBinEnabled', 'True')
    for group in vault.groups:
        put(group._element, 'Tags', 'synthetic,group')
        for name in ('CreationTime', 'LastModificationTime', 'LastAccessTime', 'ExpiryTime', 'LocationChanged'):
            put(group._element.find('Times'), name, vault._encode_time(BASE_TIME))
    vault.save()
    shutil.copyfile(target, source)
    incoming = PyKeePass(source, password=MASTER)
    incoming.add_entry(incoming.root_group, 'Native roundtrip trigger', 'synthetic', SECRET)
    incoming.save()
    reference = tmp_path / 'native'; reference.mkdir(mode=0o700)
    shutil.copyfile(target, reference / 'candidate.kdbx')
    shutil.copyfile(source, reference / 'source.kdbx')
    merging.run_engine(reference, vault)
    shutil.copyfile(reference / 'candidate.kdbx', target)
    broker.vault = open_vault_with_password(target, MASTER)
    assert versions.archives(broker.vault)
    shutil.copyfile(target, source)
    return case


def test_native_groups_untouched_keepassium_projection(native_case):
    broker, target, source, _ = native_case
    ledger = versions.archives(broker.vault)
    incoming = PyKeePass(source, password=MASTER)
    project(incoming); incoming.save()
    # Reproduce the old check on the final faithful public writer projection,
    # not only a hand-edited string or a mock capability response.
    frozen = subprocess.run(['git', 'show', 'd3657b7f9337895ce65068a4b9a57341fe90e783:src/agentic_kdbx/admission.py'], capture_output=True, check=True)
    legacy = types.ModuleType('agentic_kdbx._legacy_group_admission')
    exec(compile(frozen.stdout, 'legacy_group_admission.py', 'exec'), legacy.__dict__)
    with pytest.raises(legacy.AdmissionError) as refused:
        legacy.verify(incoming, (broker.vault, broker.vault))
    assert refused.value.diagnostics == {'group_metadata': 5}
    before, uploaded = target.read_bytes(), source.read_bytes()
    checked = admit(native_case, check=True)
    assert checked['ok'] and checked['state'] == 'checked', checked.get('verification_diagnostics', checked)
    assert target.read_bytes() == before
    result = admit(native_case)
    assert result['ok'] and result['state'] == 'saved', result
    assert source.read_bytes() == target.read_bytes() == uploaded
    assert versions.archives(broker.vault) == ledger
    assert (bundle(result) / 'target.kdbx').read_bytes() == before



@pytest.mark.parametrize('variation', ['omitted-defaults', 'zero-optionals', 'tristate-case', 'empty-custom-data', 'iso-times'])
def test_public_reader_defaults_and_optional_serialization(native_case, variation, tmp_path):
    broker, target, source, _ = native_case
    vault = PyKeePass(target, password=MASTER)
    for group in vault.groups:
        node = group._element
        # Isolate each default case from the separate nonempty-Tags ordering bug.
        node.remove(node.find('Tags'))
        if variation == 'omitted-defaults':
            for tag in ('Notes', 'DefaultAutoTypeSequence', 'IconID', 'EnableAutoType', 'EnableSearching'):
                child = node.find(tag)
                # Do not turn the archive's explicit disabled state into inherit.
                if child is not None and child.text in (None, '', 'null', '48'): node.remove(child)
        elif variation == 'zero-optionals':
            for tag in ('CustomIconUUID', 'PreviousParentGroup'): put(node, tag, ZERO)
        elif variation == 'tristate-case':
            for tag in ('EnableAutoType', 'EnableSearching'): node.find(tag).text = node.findtext(tag).upper()
        elif variation == 'empty-custom-data':
            if node.find('CustomData') is None: etree.SubElement(node, 'CustomData')
        elif variation == 'iso-times':
            for child in node.find('Times'):
                if child.tag.endswith('Time') or child.tag == 'LocationChanged':
                    child.text = selection.decode_time(child.text, vault.version).isoformat()
    vault.save(); broker.vault = open_vault_with_password(target, MASTER)
    shutil.copyfile(target, source)
    incoming = PyKeePass(source, password=MASTER); project(incoming); incoming.save()
    result = admit(native_case, check=True)
    assert result['ok'], result.get('verification_diagnostics', result)

    # Native reference independently resolves the public reader defaults, zero
    # optional UUIDs and tristate spelling into its ordinary group properties.
    reference = tmp_path / 'defaults-reference'; reference.mkdir(mode=0o700)
    shutil.copyfile(target, reference / 'candidate.kdbx')
    incoming.add_entry(incoming.root_group, 'Force native writer', 'synthetic', SECRET); incoming.save()
    shutil.copyfile(source, reference / 'source.kdbx')
    merging.run_engine(reference, broker.vault)
    native = PyKeePass(reference / 'candidate.kdbx', password=MASTER)
    for group in native.groups:
        assert group._element.findtext('Notes') in (None, '')
        assert group._element.findtext('DefaultAutoTypeSequence') in (None, '')
        assert group._element.findtext('CustomIconUUID') is None
        assert group._element.findtext('PreviousParentGroup') is None
        assert group._element.findtext('EnableSearching') == ('false' if versions.is_archive_group(group) else 'null')


def metadata(group, vault):
    custom = etree.SubElement(group._element, 'CustomData')
    for key in ('Synthetic property', '_LAST_MODIFIED', 'KnownBad'):
        item = etree.SubElement(custom, 'Item')
        put(item, 'Key', key); put(item, 'Value', 'synthetic group metadata')
        put(item, 'LastModificationTime', vault._encode_time(BASE_TIME))


@pytest.mark.parametrize('state', ['null', 'true', 'false'])
def test_all_tristates_custom_data_and_disabled_expiry_remain_intact(native_case, state):
    broker, target, source, _ = native_case
    vault = PyKeePass(target, password=MASTER)
    group = vault.find_groups(name='Synthetic group', first=True)
    metadata(group, vault)
    for tag in ('EnableAutoType', 'EnableSearching'): put(group._element, tag, state)
    put(group._element.find('Times'), 'Expires', 'False')
    put(group._element.find('Times'), 'ExpiryTime', vault._encode_time(BASE_TIME + timedelta(days=14)))
    vault.save(); broker.vault = open_vault_with_password(target, MASTER); shutil.copyfile(target, source)
    incoming = PyKeePass(source, password=MASTER); project(incoming)
    # Same CustomData clock represented in ISO with a nonzero UTC offset.
    for clock in incoming.tree.findall('.//Group/CustomData/Item/LastModificationTime'):
        clock.text = BASE_TIME.astimezone(timezone(timedelta(hours=3))).isoformat()
    incoming.save(); encrypted = source.read_bytes(); ledger = versions.archives(broker.vault)
    result = admit(native_case); assert result['ok'], result
    assert target.read_bytes() == source.read_bytes() == encrypted
    assert versions.archives(broker.vault) == ledger
    active = broker.vault.find_groups(name='Synthetic group', first=True)
    assert active._element.findtext('EnableAutoType').lower() == state
    assert active._element.findtext('EnableSearching').lower() == state
    assert active._element.findtext('Times/Expires') == 'False'
    assert selection.decode_time(active._element.findtext('Times/ExpiryTime'), broker.vault.version) == BASE_TIME + timedelta(days=14)
    assert len(active._element.findall('CustomData/Item')) == 3


TRUE_CHANGES = ('rename', 'root-rename', 'notes', 'move', 'created', 'modified', 'location',
                'expiry-disabled', 'expiry-enabled', 'expires', 'tags', 'autotype', 'enable-autotype',
                'enable-search', 'custom-value', 'custom-clock', 'custom-key', 'custom-drop',
                'dictionary-clock-value', 'knownbad-value', 'icon', 'previous-parent', 'unknown',
                'created-fractional', 'modified-fractional', 'location-fractional', 'expiry-fractional',
                'custom-clock-fractional')


@pytest.mark.parametrize('change', TRUE_CHANGES)
def test_true_group_mutations_still_refuse_with_private_diagnostics(native_case, change, caplog, capsys):
    broker, target, source, _ = native_case
    v = PyKeePass(target, password=MASTER); g = v.find_groups(name='Synthetic group', first=True)
    metadata(g, v)
    if change == 'expiry-enabled': put(g._element.find('Times'), 'Expires', 'True')
    v.save(); broker.vault = open_vault_with_password(target, MASTER); shutil.copyfile(target, source)
    v = PyKeePass(source, password=MASTER); project(v)
    g = v.find_groups(name='Synthetic group', first=True); node = g._element
    if change == 'rename': put(node, 'Name', 'synthetic different group')
    elif change == 'root-rename': put(v.root_group._element, 'Name', 'synthetic different root')
    elif change == 'notes': put(node, 'Notes', 'synthetic changed group notes')
    elif change == 'move': v.move_group(g, v.find_groups(name='Synthetic recycle bin', first=True))
    elif change.endswith('-fractional'):
        stamp = BASE_TIME.replace(microsecond=500000).isoformat()
        if change == 'custom-clock-fractional': node.find('CustomData/Item/LastModificationTime').text = stamp
        else:
            tag = {'created-fractional': 'CreationTime', 'modified-fractional': 'LastModificationTime',
                   'location-fractional': 'LocationChanged', 'expiry-fractional': 'ExpiryTime'}[change]
            put(node.find('Times'), tag, stamp)
    elif change in {'created', 'modified', 'location', 'expiry-disabled', 'expiry-enabled'}:
        tag = {'created': 'CreationTime', 'modified': 'LastModificationTime', 'location': 'LocationChanged'}.get(change, 'ExpiryTime')
        put(node.find('Times'), tag, v._encode_time(BASE_TIME + timedelta(days=1)))
    elif change == 'expires': put(node.find('Times'), 'Expires', 'True')
    elif change == 'tags': put(node, 'Tags', 'synthetic different tags')
    elif change == 'autotype': put(node, 'DefaultAutoTypeSequence', '{PASSWORD}')
    elif change.startswith('enable-'): put(node, 'EnableAutoType' if change == 'enable-autotype' else 'EnableSearching', 'True')
    elif change.startswith('custom-') or change in {'dictionary-clock-value', 'knownbad-value'}:
        key = {'dictionary-clock-value': '_LAST_MODIFIED', 'knownbad-value': 'KnownBad'}.get(change, 'Synthetic property')
        item = node.find('./CustomData/Item[Key="' + key + '"]')
        if change == 'custom-drop': item.getparent().remove(item)
        elif change == 'custom-key': item.find('Key').text = 'synthetic changed key'
        elif change == 'custom-clock': item.find('LastModificationTime').text = v._encode_time(BASE_TIME + timedelta(days=1))
        else: item.find('Value').text = 'synthetic changed metadata'
    elif change == 'icon': put(node, 'IconID', '49')
    elif change == 'previous-parent': put(node, 'PreviousParentGroup', v.root_group._element.findtext('UUID'))
    elif change == 'unknown': put(node, 'SyntheticUnknown', 'synthetic unknown metadata')
    v.save(); before, uploaded = target.read_bytes(), source.read_bytes()
    result = admit(native_case)
    assert result['ok'] is False and result['state'] == 'failed'
    assert result['verification_diagnostics'] == {'group_metadata': 1}
    assert target.read_bytes() == before and source.read_bytes() == uploaded
    assert (bundle(result) / 'source.kdbx').read_bytes() == uploaded
    output = json.dumps(result) + caplog.text + capsys.readouterr().out
    for value in (MASTER, SECRET, 'Synthetic group', 'Synthetic property', 'synthetic changed metadata', str(g.uuid)):
        assert value not in output


def test_equal_fractional_group_instants_normalize_only_timezone(native_case):
    broker, target, source, _ = native_case
    v = PyKeePass(target, password=MASTER)
    g = v.find_groups(name='Synthetic group', first=True)
    metadata(g, v)
    stamp = BASE_TIME.replace(microsecond=500000)
    for tag in ('CreationTime', 'LastModificationTime', 'ExpiryTime', 'LocationChanged'):
        put(g._element.find('Times'), tag, stamp.isoformat())
    g._element.find('CustomData/Item/LastModificationTime').text = stamp.isoformat()
    v.save(); broker.vault = open_vault_with_password(target, MASTER); shutil.copyfile(target, source)
    v = PyKeePass(source, password=MASTER)
    g = v.find_groups(name='Synthetic group', first=True)
    for tag in ('CreationTime', 'LastModificationTime', 'ExpiryTime', 'LocationChanged'):
        put(g._element.find('Times'), tag, stamp.astimezone(timezone(timedelta(hours=3))).isoformat())
    g._element.find('CustomData/Item/LastModificationTime').text = stamp.astimezone(timezone(timedelta(hours=3))).isoformat()
    v.save()
    result = admit(native_case)
    assert result['ok'], result
    assert target.read_bytes() == source.read_bytes()


@pytest.mark.parametrize('malformation', ['duplicate-tags', 'duplicate-times', 'duplicate-custom-key', 'invalid-tristate', 'tristate-attributes', 'time-attributes', 'excess-time-precision'])
def test_malformed_group_metadata_fails_closed(native_case, malformation):
    _, target, source, _ = native_case
    v = PyKeePass(source, password=MASTER); project(v)
    node = v.find_groups(name='Synthetic group', first=True)._element
    if malformation == 'duplicate-tags': node.append(copy.deepcopy(node.find('Tags')))
    elif malformation == 'duplicate-times': node.find('Times').append(copy.deepcopy(node.find('Times/Expires')))
    elif malformation == 'duplicate-custom-key':
        metadata(v.find_groups(name='Synthetic group', first=True), v)
        custom = node.find('CustomData'); custom.append(copy.deepcopy(custom[0]))
    elif malformation == 'invalid-tristate': put(node, 'EnableSearching', 'synthetic invalid bool')
    elif malformation == 'tristate-attributes': node.find('EnableSearching').set('SyntheticAttribute', 'value')
    elif malformation == 'time-attributes': node.find('Times/CreationTime').set('SyntheticAttribute', 'value')
    elif malformation == 'excess-time-precision': node.find('Times/CreationTime').text = '2024-01-01T00:00:00.1234567+00:00'
    v.save(); before = target.read_bytes()
    result = admit(native_case)
    assert not result['ok'] and result['state'] == 'failed'
    assert result['verification_diagnostics'] == {'unsupported_structure': 1}
    assert target.read_bytes() == before


def test_custom_icon_and_optional_parent_survive_projection(native_case):
    broker, target, source, _ = native_case
    v = PyKeePass(target, password=MASTER); node = v.find_groups(name='Synthetic group', first=True)._element
    icon_uuid = base64.b64encode(uuid.uuid4().bytes).decode()
    container = v.tree.find('./Meta/CustomIcons')
    if container is None: container = etree.SubElement(v.tree.find('./Meta'), 'CustomIcons')
    icon = etree.SubElement(container, 'Icon'); put(icon, 'UUID', icon_uuid)
    # Valid 1x1 PNG; public synthetic data only.
    put(icon, 'Data', 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aD1sAAAAASUVORK5CYII=')
    put(node, 'CustomIconUUID', icon_uuid); put(node, 'IconID', '0')
    parent_uuid = v.root_group._element.findtext('UUID'); put(node, 'PreviousParentGroup', parent_uuid)
    v.save(); broker.vault = open_vault_with_password(target, MASTER); shutil.copyfile(target, source)
    v = PyKeePass(source, password=MASTER); project(v); v.save()
    result = admit(native_case); assert result['ok'], result
    actual = broker.vault.find_groups(name='Synthetic group', first=True)._element
    assert actual.findtext('CustomIconUUID') == icon_uuid
    assert actual.findtext('PreviousParentGroup') == parent_uuid
    # A real change/removal is still a group conflict, not optional-zero cleanup.
    v = PyKeePass(source, password=MASTER)
    put(v.find_groups(name='Synthetic group', first=True)._element, 'CustomIconUUID', ZERO); v.save()
    refused = admit(native_case)
    assert not refused['ok'] and refused['verification_diagnostics'] == {'group_metadata': 1}


@pytest.mark.parametrize('full_cost', [False, True])
def test_cli_http_consecutive_group_projection_and_restart_recovery(native_case, tmp_path, full_cost):
    broker, target, source, snapshots = native_case
    if full_cost:
        from pykeepass.kdbx_parsing.kdbx4 import kdf_uuids
        v = PyKeePass(target, password=MASTER)
        params = v.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
        params['$UUID'].value = kdf_uuids['argon2']
        for key, value in {'I': 119, 'M': 67108864, 'P': 2, 'V': 19}.items(): params[key].value = value
        assert v.kdbx.header.value.dynamic_header.cipher_id.data == 'aes256'
        v.kdbx.header.value.minor_version = 1; v.save()
        broker.vault = open_vault_with_password(target, MASTER); shutil.copyfile(target, source)
    ledger = versions.archives(broker.vault)
    handle = broker.dispatch({'action': 'search', 'query': 'Shared'})['entries'][0]['handle']
    staging = tmp_path / 'uploads'; staging.mkdir(mode=0o700)
    socket = tmp_path / 'runtime' / 'broker.sock'; lab = Lab(target, snapshots, staging, socket)
    with running_broker(socket, broker), servers(lab) as address:
        caps = lab.command('status')
        assert caps['version'] == '0.7.1' and caps['admission_group_verification'] == 'group-semantic-v1'
        client = KeePassiumSequence(address); client.read()
        for day in (2, 3):
            v = edit(source, day=day)
            # 2.5.171 AddEntryURLOperation updates entry data/time, not parent
            # modification clocks. Access-only parent touches remain UI state.
            v.find_entries(title='Shared', first=True).url = 'https://synthetic.test/remembered'
            for group in v.groups:
                put(group._element.find('Times'), 'LastAccessTime', v._encode_time(BASE_TIME + timedelta(days=day)))
                put(group._element.find('Times'), 'UsageCount', str(day))
            project(v); v.save()
            uploaded = source.read_bytes()
            assert client.save(uploaded, timeout=30) == 204
            result = next(reversed(lab.results.values()))
            assert result['group_verification'] == 'group-semantic-v1'
            assert result['target_refreshed'] is False
            assert http(address, 'GET')[1] == target.read_bytes() == uploaded
            assert http(address, 'HEAD')[2]['ETag'] == '"' + hashlib.sha256(uploaded).hexdigest() + '"'
            assert lab.command('merge-status', result['operation_id']) == result
            assert versions.archives(broker.vault) == ledger
        assert not broker.dispatch({'action': 'fill', 'handle': handle})['ok']
        assert broker.vault.find_entries(title='Shared', first=True).mtime == BASE_TIME + timedelta(days=3)
        # An actual property edit must receive a retained-upload 409, preserving
        # the exact canonical bytes. No automatic merge or false 204.
        v = PyKeePass(source, password=MASTER); v.root_group.name = 'synthetic changed root'; v.save()
        canonical = target.read_bytes(); assert client.save(source.read_bytes(), timeout=30) == 409
        assert target.read_bytes() == canonical
        failed = next(reversed(lab.results.values()))
        assert failed['verification_diagnostics'] == {'group_metadata': 1}
    restarted = open_vault_with_password(target, MASTER)
    from agentic_kdbx.broker import Broker
    from test_broker import RecordingTyper
    restored = Broker(restarted, RecordingTyper())
    assert restored.merges.status(result['operation_id']) == result
    assert restored.merges.status(failed['operation_id']) == failed
    assert not restarted._akdbx_store.recovery_required


def test_requested_group_verifier_cannot_be_ignored(native_case, monkeypatch, capsys):
    broker, target, source, snapshots = native_case
    result = admit(native_case, group_verification='unsupported-group-policy')
    assert not result['ok'] and 'operation not started' in result['error']
    assert not list(snapshots.iterdir())
    calls = []
    actual_caps = broker.dispatch({'action': 'ping'})
    def previous(sock, payload, **kwargs):
        calls.append(payload)
        return {key: value for key, value in actual_caps.items() if key != 'admission_group_verification'}
    monkeypatch.setattr(cli, 'request', previous)
    args = ['admit', str(source), '--policy', admission.POLICY, '--snapshot-dir', str(snapshots)]
    assert cli.main(args) == 1 and [c['action'] for c in calls] == ['ping']
    assert 'admission not sent' in capsys.readouterr().out
    def downgraded(sock, payload, **kwargs):
        if payload['action'] == 'ping': return actual_caps
        return {**broker.dispatch(payload), 'group_verification': None}
    monkeypatch.setattr(cli, 'request', downgraded)
    assert cli.main(args) == 2
    assert 'outcome unconfirmed' in capsys.readouterr().err


@pytest.mark.parametrize('text', ['synthetic;group', ' synthetic , group '])
def test_tag_text_rewrites_remain_a_documented_conservative_refusal(native_case, text, tmp_path):
    broker, target, source, _ = native_case
    v = PyKeePass(target, password=MASTER)
    put(v.find_groups(name='Synthetic group', first=True)._element, 'Tags', text)
    v.save(); broker.vault = open_vault_with_password(target, MASTER); shutil.copyfile(target, source)
    v = PyKeePass(source, password=MASTER); project(v)
    assert v.find_groups(name='Synthetic group', first=True)._element.findtext('Tags') == 'synthetic,group'
    v.save(); before = target.read_bytes(); uploaded = source.read_bytes()
    result = admit(native_case)
    assert not result['ok'] and result['verification_diagnostics'] == {'group_metadata': 1}
    assert target.read_bytes() == before and source.read_bytes() == uploaded
    # Independent native reference: existing group Tags remain the target's
    # raw string. A fresh read/phone rewrite can repeat this conflict; do not
    # claim explicit reconciliation permanently cures this structural shape.
    reference = tmp_path / 'tag-reference'; reference.mkdir(mode=0o700)
    shutil.copyfile(target, reference / 'candidate.kdbx')
    v.add_entry(v.root_group, 'Native tag reference trigger', 'synthetic', SECRET); v.save()
    shutil.copyfile(source, reference / 'source.kdbx')
    merging.run_engine(reference, broker.vault)
    native = PyKeePass(reference / 'candidate.kdbx', password=MASTER)
    assert native.find_groups(name='Synthetic group', first=True)._element.findtext('Tags') == text
