"""Conditional, byte-preserving admission; never a merge or capsule-v1 capture.

The deliberately conservative envelope proves active containment using the
native selection verifier. Full encrypted snapshots retain versions omitted
from ordinary history. Existing capsule payloads must remain byte-for-byte.
"""
from __future__ import annotations

import copy
import re
from collections import Counter
from datetime import datetime, timezone
from lxml import etree

from . import group_tags, selection, versions

POLICY = 'snapshot-admission-v1'
VERIFICATION = 'native-containment-v1'
GROUP_VERIFICATION = 'group-semantic-v1'
TAG_GROUP_VERIFICATION = 'group-tag-sequence-v1'
NATIVE_GROUP_VERIFICATION = 'native-group-selection-v1'
GROUP_VERIFIERS = (GROUP_VERIFICATION, TAG_GROUP_VERIFICATION, NATIVE_GROUP_VERIFICATION)
CATEGORIES = frozenset({'encryption_policy', 'database_settings', 'group_metadata',
                        'managed_capsules', 'deletion', 'field_protection', 'unsupported_structure'})
META_FIELDS = frozenset({'Generator', 'DatabaseName', 'DatabaseNameChanged', 'DatabaseDescription',
    'DatabaseDescriptionChanged', 'DefaultUserName', 'DefaultUserNameChanged', 'MaintenanceHistoryDays',
    'Color', 'MasterKeyChanged', 'MasterKeyChangeRec', 'MasterKeyChangeForce', 'MasterKeyChangeForceOnce',
    'MemoryProtection', 'CustomIcons', 'RecycleBinEnabled', 'RecycleBinUUID', 'RecycleBinChanged',
    'EntryTemplatesGroup', 'EntryTemplatesGroupChanged', 'LastSelectedGroup', 'LastTopVisibleGroup',
    'HistoryMaxItems', 'HistoryMaxSize', 'SettingsChanged', 'CustomData'})
GROUP_FIELDS = frozenset({'UUID', 'Name', 'Notes', 'IconID', 'CustomIconUUID', 'Times', 'IsExpanded',
    'DefaultAutoTypeSequence', 'EnableAutoType', 'EnableSearching', 'LastTopVisibleEntry',
    'CustomData', 'PreviousParentGroup', 'Tags'})


class AdmissionError(versions.PreservationError):
    def __init__(self, categories):
        super().__init__('snapshot admission refused; reconcile explicitly and read the canonical file again')
        self.diagnostics = {k: min(v, 2**31 - 1) for k, v in sorted(Counter(categories).items())
                            if k in CATEGORIES and type(v) is int and v > 0}


def _crypto(vault):
    if vault.version[0] != 4:
        raise AdmissionError(['encryption_policy'])
    header = vault.kdbx.header.value.dynamic_header
    params = header.kdf_parameters.data.dict
    # Only per-save randomness may differ. This also refuses unknown parameter
    # changes, changed KDF versions and reductions disguised by another KDF.
    return (header.cipher_id.data,
            {k: v.value for k, v in params.items() if k != 'S'},
            vault.kdbx.body.payload.inner_header.protected_stream_id.data,
            {k: v.data for k, v in header.items() if k not in {
                'cipher_id', 'compression_flags', 'master_seed', 'encryption_iv', 'kdf_parameters', 'end'}})


def _group_time(text, vault):
    # Group clocks are not entry-version timestamp buckets. Normalize timezone
    # representation while retaining supplied fractional precision. Ordinary
    # KDBX4 binary times are whole seconds; different ISO instants must refuse.
    try:
        if re.search(r'[.,]\d{7}', text or ''):
            raise ValueError
        value = datetime.fromisoformat(versions._time(text, vault.version))
        return value.replace(tzinfo=value.tzinfo or timezone.utc).astimezone(timezone.utc).isoformat()
    except Exception:
        raise AdmissionError(['unsupported_structure']) from None


def _group_defaults(node, vault):
    """Private representation equivalence, never group conflict selection.

    KeePassXC 2.7.10 Group/parseGroup and KeePassium Group2.load/toXml
    agree on these defaults. Their writers differ in tristate spelling,
    Tags position, and omission of optional zero UUIDs/empty CustomData.
    Keep inheritance distinct from explicit true/false. Essential Times,
    even disabled expiry, and every CustomData value/clock stay significant.
    This projection never changes the incoming file or capsule identities.
    """
    for tag, default in {'Name': '', 'Notes': '', 'IconID': '48',
                         'DefaultAutoTypeSequence': '', 'EnableAutoType': 'null',
                         'EnableSearching': 'null'}.items():
        child = node.find(tag)
        if child is None:
            child = etree.SubElement(node, tag)
            child.text = default
        selection._leaf(child)
    for tag in ('EnableAutoType', 'EnableSearching'):
        child = node.find(tag)
        value = selection._leaf(child).lower()
        if value not in {'null', 'true', 'false'}:
            raise AdmissionError(['unsupported_structure'])
        child.text = value
    for tag in ('CustomIconUUID', 'PreviousParentGroup'):
        child = node.find(tag)
        if child is not None and selection._uuid(selection._leaf(child)) is None:
            node.remove(child)
    times = node.find('Times')
    if times is None or times.attrib:
        raise AdmissionError(['unsupported_structure'])
    seen = set()
    for child in times:
        if child.tag not in selection.TIME_FIELDS or child.tag in seen:
            raise AdmissionError(['unsupported_structure'])
        seen.add(child.tag)
        value = selection._leaf(child)
        if child.tag == 'Expires':
            child.text = str(selection._boolean(value))
        elif child.tag not in {'UsageCount', 'LastAccessTime'}:
            child.text = _group_time(value, vault)
    if not {'CreationTime', 'LastModificationTime', 'ExpiryTime', 'Expires', 'LocationChanged'} <= seen:
        raise AdmissionError(['unsupported_structure'])
    custom = node.find('CustomData')
    if custom is not None:
        if custom.attrib or (custom.text or '').strip():
            raise AdmissionError(['unsupported_structure'])
        keys = set()
        for item in custom:
            tags = [child.tag for child in item]
            if (item.tag != 'Item' or item.attrib or tags.count('Key') != 1 or tags.count('Value') != 1
                    or tags.count('LastModificationTime') > 1
                    or set(tags) - {'Key', 'Value', 'LastModificationTime'}):
                raise AdmissionError(['unsupported_structure'])
            key = selection._leaf(item.find('Key'))
            selection._leaf(item.find('Value'))
            if key in keys:
                raise AdmissionError(['unsupported_structure'])
            keys.add(key)
            clock = item.find('LastModificationTime')
            if clock is not None:
                clock.text = _group_time(selection._leaf(clock), vault)
        if not len(custom):
            node.remove(custom)


def _shape(node, vault, *, group=False, tag_equivalence=False):
    if node is None:
        return None
    node = copy.deepcopy(node)
    fields = GROUP_FIELDS if group else META_FIELDS
    seen = set()
    for child in node:
        if child.tag in fields:
            if child.tag in seen:
                raise AdmissionError(['unsupported_structure'])
            seen.add(child.tag)
    if group:
        _group_defaults(node, vault)
        if tag_equivalence:
            tags = node.find('Tags')
            if tags is not None:
                values = group_tags.sequence(selection._leaf(tags))
                if values:
                    tags.text = versions._json(values).decode('utf-8')
                else:
                    node.remove(tags)
    ignored = ({'Entry', 'Group', 'IsExpanded', 'LastTopVisibleEntry'} if group else
               {'Generator', 'LastSelectedGroup', 'LastTopVisibleGroup', 'CustomIcons', 'CustomData'})
    for child in list(node):
        if child.tag in ignored:
            node.remove(child)
    for child in node.iter():
        if child.tag in {'LastAccessTime', 'UsageCount'} and child.getparent().tag == 'Times':
            child.getparent().remove(child)
        elif child.tag.endswith('Changed') or child.tag in {'MasterKeyChanged'}:
            child.text = (_group_time(child.text, vault) if group else
                          selection.decode_time(child.text, vault.version).isoformat())
        elif child.tag.startswith('Protect') or child.tag == 'RecycleBinEnabled':
            child.text = str(selection._boolean(child.text))
    projected = versions._canonical(node, {}, vault.version, times=True)
    # Known singleton fields are unordered in the KDBX format. Preserve order
    # for unknown metadata rather than assume it has the same convention.
    if all(child[0] in fields for child in projected[3]):
        projected[3].sort(key=versions._json)
    for child in projected[3]:
        if child[0] == 'MemoryProtection' and all(
                field[0] in {'ProtectTitle', 'ProtectUserName', 'ProtectPassword', 'ProtectURL', 'ProtectNotes'}
                for field in child[3]):
            if len({field[0] for field in child[3]}) != len(child[3]):
                raise AdmissionError(['unsupported_structure'])
            child[3].sort(key=versions._json)
    return projected


def _custom_data(vault):
    from types import SimpleNamespace
    meta = vault.tree.find('./Meta')
    values = selection._custom_data(SimpleNamespace(_element=meta, _kp=vault))
    # KnownBad is an entry-only legacy flag, not a database-level exception.
    node = meta.find('./CustomData/Item[Key="KnownBad"]/Value')
    if node is not None:
        values['KnownBad'] = node.text or ''
    return values


def _deleted(vault):
    result = {}
    for node in vault.tree.findall('./Root/DeletedObjects/DeletedObject'):
        identity = node.findtext('UUID')
        if selection._uuid(identity) is None:
            raise AdmissionError(['unsupported_structure'])
        if (identity in result or len(node) != 2 or node.attrib
                or set(c.tag for c in node) != {'UUID', 'DeletionTime'}
                or any(c.attrib or len(c) for c in node)):
            raise AdmissionError(['unsupported_structure'])
        result[identity] = selection.decode_time(node.findtext('DeletionTime'), vault.version)
    return result


def verify(incoming, originals, *, trusted_archives=None, group_verification=GROUP_VERIFICATION):
    """No mutations, digests of secrets, native output or identities in errors.

    Existing group properties/database settings must agree. Deliberately refuse
    concurrent group/settings edits rather than guess their partial native
    combination. Entry locations and active data use semantic-v1 selection.
    """
    if group_verification not in GROUP_VERIFIERS:
        raise AdmissionError(['unsupported_structure'])
    errors = Counter()
    all_inputs = (*originals, incoming)
    for vault in all_inputs:
        root = vault.tree.getroot()
        if (root.tag != 'KeePassFile' or len(root.findall('Meta')) != 1
                or len(root.findall('Root')) != 1
                or len(root.findall('./Root/Group')) != 1
                or len(root.findall('./Root/DeletedObjects')) > 1):
            raise AdmissionError(['unsupported_structure'])
        for node in vault.tree.findall('.//Entry') + vault.tree.findall('.//Group'):
            identities = node.findall('UUID')
            if (len(identities) != 1 or identities[0].attrib or len(identities[0])
                    or selection._uuid(identities[0].text) is None
                    or len(node.findall('Times')) != 1 or len(node.findall('History')) > 1):
                raise AdmissionError(['unsupported_structure'])
        ids = [item.uuid for item in [*vault.entries, *vault.groups]]
        if len(ids) != len(set(ids)):
            raise AdmissionError(['unsupported_structure'])
        size = len(vault.kdbx.body.payload.inner_header.binary)
        for node in vault.tree.findall('.//Binary/Value'):
            try:
                if not 0 <= int(node.get('Ref')) < size:
                    raise ValueError
            except Exception:
                raise AdmissionError(['unsupported_structure']) from None
    base = originals[0]
    if any(_crypto(v) != _crypto(base) for v in all_inputs):
        errors['encryption_policy'] += 1
    if any(_shape(v.tree.find('./Meta'), v) != _shape(base.tree.find('./Meta'), base)
           for v in all_inputs):
        errors['database_settings'] += 1
    # Native DB custom-data merging is clock-dependent and can drop keys.
    # This opt-in conservatively permits dictionary-clock changes only.
    if any(_custom_data(v) != _custom_data(base) for v in all_inputs):
        errors['database_settings'] += 1
    icons = {}
    for vault in all_inputs:
        current = {}
        for icon in vault.tree.findall('./Meta/CustomIcons/Icon'):
            key = icon.findtext('UUID')
            if selection._uuid(key) is None:
                raise AdmissionError(['unsupported_structure'])
            if key in current:
                raise AdmissionError(['unsupported_structure'])
            current[key] = versions._canonical(icon, {}, vault.version, times=True)
        if vault is incoming:
            if any(current.get(k) != value for k, value in icons.items()):
                errors['database_settings'] += 1
        else:
            for key, value in current.items():
                if key in icons and icons[key] != value:
                    errors['database_settings'] += 1
                icons[key] = value
    ledger = {}
    for vault in originals:
        cached = (trusted_archives or {}).get(id(vault))
        for key, data in (versions.archives(vault) if cached is None else cached).items():
            if key in ledger and ledger[key] != data:
                errors['managed_capsules'] += 1
            ledger[key] = data
    admitted = versions.archives(incoming, trusted=ledger)
    if any(admitted.get(key) != data for key, data in ledger.items()):
        errors['managed_capsules'] += 1
    deletions = {}
    for vault in all_inputs:
        for key, stamp in _deleted(vault).items():
            deletions[key] = min(stamp, deletions.get(key, stamp))
    if _deleted(incoming) != deletions:
        errors['deletion'] += 1
    # A newer source version must not silently turn off protection of an
    # existing current/held field. Absence is permitted only for a deleted field.
    actual = {e.uuid: e for e in versions.active_entries(incoming)}
    for vault in originals:
        for entry in versions.active_entries(vault):
            chosen = actual.get(entry.uuid)
            if chosen is not None:
                before, after = selection._fields(entry), selection._fields(chosen)
                if any(protected and key in after and not after[key][1]
                       for key, (_, protected) in before.items()):
                    errors['field_protection'] += 1
    if group_verification == NATIVE_GROUP_VERIFICATION:
        from . import group_selection
        group_selection.verify(incoming, originals)
        if errors:
            raise AdmissionError(errors)
        selection.verify(incoming, all_inputs)
        return {'retained_capsules': len(ledger)}, admitted
    groups = {}
    tag_equivalence = group_verification == TAG_GROUP_VERIFICATION
    for vault in originals:
        for group in vault.groups:
            parent = group.parentgroup.uuid if group.parentgroup else None
            value = (_shape(group._element, vault, group=True, tag_equivalence=tag_equivalence), parent)
            if group.uuid in groups and groups[group.uuid][0] != value:
                errors['group_metadata'] += 1
            groups[group.uuid] = (value, group)
    incoming_groups = {g.uuid: g for g in incoming.groups}
    for identity, (value, group) in groups.items():
        chosen = incoming_groups.get(identity)
        if chosen is None:
            stamp = deletions.get(group._element.findtext('UUID'))
            if stamp is None or selection.modification_time(group) > stamp or group == base.root_group:
                errors['group_metadata'] += 1
        elif (_shape(chosen._element, incoming, group=True, tag_equivalence=tag_equivalence), chosen.parentgroup.uuid if chosen.parentgroup else None) != value:
            errors['group_metadata'] += 1
    if errors:
        raise AdmissionError(errors)
    # Input order is intentional: current disk is base, held state second,
    # incoming last. Equal active seconds retain the established base value.
    selection.verify(incoming, all_inputs)
    return {'retained_capsules': len(ledger)}, admitted
