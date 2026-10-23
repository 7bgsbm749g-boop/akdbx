"""Conditional, byte-preserving admission; never a merge or capsule-v1 capture.

The deliberately conservative envelope proves active containment using the
native selection verifier. Full encrypted snapshots retain versions omitted
from ordinary history. Existing capsule payloads must remain byte-for-byte.
"""
from __future__ import annotations

import copy
from collections import Counter

from . import selection, versions

POLICY = 'snapshot-admission-v1'
VERIFICATION = 'native-containment-v1'
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
    'CustomData', 'PreviousParentGroup'})


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


def _shape(node, vault, *, group=False):
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
    ignored = ({'Entry', 'Group', 'IsExpanded', 'LastTopVisibleEntry'} if group else
               {'Generator', 'LastSelectedGroup', 'LastTopVisibleGroup', 'CustomIcons', 'CustomData'})
    for child in list(node):
        if child.tag in ignored:
            node.remove(child)
    for child in node.iter():
        if child.tag in {'LastAccessTime', 'UsageCount'} and child.getparent().tag == 'Times':
            child.getparent().remove(child)
        elif child.tag.endswith('Changed') or child.tag in {'MasterKeyChanged'}:
            child.text = selection.decode_time(child.text, vault.version).isoformat()
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


def verify(incoming, originals, *, trusted_archives=None):
    """No mutations, digests of secrets, native output or identities in errors.

    Existing group properties/database settings must agree. Deliberately refuse
    concurrent group/settings edits rather than guess their partial native
    combination. Entry locations and active data use semantic-v1 selection.
    """
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
    groups = {}
    for vault in originals:
        for group in vault.groups:
            parent = group.parentgroup.uuid if group.parentgroup else None
            value = (_shape(group._element, vault, group=True), parent)
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
        elif (_shape(chosen._element, incoming, group=True), chosen.parentgroup.uuid if chosen.parentgroup else None) != value:
            errors['group_metadata'] += 1
    if errors:
        raise AdmissionError(errors)
    # Input order is intentional: current disk is base, held state second,
    # incoming last. Equal active seconds retain the established base value.
    selection.verify(incoming, all_inputs)
    return {'retained_capsules': len(ledger)}, admitted
