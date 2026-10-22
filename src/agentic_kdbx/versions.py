"""Immutable version capsules inside the encrypted KDBX, never plaintext files.

KeePassXC indexes history by time. Capsules are opaque attachments on separate,
deterministic UUIDs, so equal-time records and history limits cannot erase them.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import struct
import uuid
from datetime import datetime, timedelta, timezone
from importlib.metadata import PackageNotFoundError, version

POLICY = 'capsule-v1'
ARCHIVE_UUID = uuid.UUID('f889158f-848d-5932-9887-364d8b37cb83')
NAMESPACE = uuid.UUID('f5ba0e04-3220-5403-88af-8780ec6da434')
MARKER = 'akdbx.version-capsules'
CHECKSUM = 'akdbx.capsule-sha256'
FILENAME = 'original-record.akdbx'
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class PreservationError(Exception):
    """Only fixed nonsecret messages may leave this module."""


def supported():
    try:
        return version('pykeepass') == '4.2.0'
    except PackageNotFoundError:
        return False


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _packed(node):
    from lxml import etree
    tag = '#comment' if node.tag is etree.Comment else '#pi' if node.tag is etree.ProcessingInstruction else node.tag
    attributes = {'target': node.target} if tag == '#pi' else dict(node.attrib)
    return [tag, attributes, node.text, [_packed(c) for c in node], node.tail]


def _unpacked(value):
    from lxml import etree
    tag, attributes, text, children, *tail = value
    if not isinstance(tag, str) or not isinstance(attributes, dict) or not isinstance(children, list):
        raise ValueError
    if text is not None and not isinstance(text, str):
        raise ValueError
    if tag == '#comment':
        node = etree.Comment(text or '')
    elif tag == '#pi':
        node = etree.ProcessingInstruction(attributes['target'], text or '')
    else:
        node = etree.Element(tag, attrib=attributes)
    node.text = text
    if tail:
        if len(tail) != 1 or tail[0] is not None and not isinstance(tail[0], str):
            raise ValueError
        node.tail = tail[0]
    for child in children:
        node.append(_unpacked(child))
    return node


def _time(text, version):
    if version[0] >= 4:
        try:
            return (datetime(1, 1, 1, tzinfo=timezone.utc) + timedelta(
                seconds=struct.unpack('<Q', base64.b64decode(text, validate=True))[0])).isoformat()
        except (ValueError, struct.error):
            pass
    return datetime.fromisoformat(text.replace('Z', '+00:00')).isoformat()


def _bool(text):
    return {'true': 'True', 'false': 'False', '1': 'True', '0': 'False'}.get(text.lower(), text)


def _canonical(node, binaries, version, *, times):
    """Normalize representation, not secrets or unknown metadata.

    Whitespace between elements, order of record fields, explicit empty standard
    fields, XML boolean spelling and empty default AutoType settings are benign.
    Leaf whitespace, custom empty fields, attachment data and relevant metadata
    remain significant. The full capsule identity includes every original time.
    """
    node = copy.deepcopy(node)
    for child in list(node):
        if child.tag in {'UUID', 'History'} or child.tag == 'Times' and not times:
            node.remove(child)
        elif child.tag in {'ForegroundColor', 'BackgroundColor', 'OverrideURL', 'Tags'} and not child.text and not child.attrib and not len(child):
            node.remove(child)
        elif child.tag == 'IconID' and child.text == '0' and not child.attrib and not len(child):
            node.remove(child)
        elif (child.tag == 'String' and child.findtext('Key') in {'Title', 'UserName', 'Password', 'URL', 'Notes'}
              and not child.findtext('Value') and not child.attrib and len(child) == 2
              and child.find('Key') is not None and not child.find('Key').attrib and not len(child.find('Key'))
              and child.find('Value') is not None and set(child.find('Value').attrib) <= {'Protected'}
              and _bool(child.find('Value').get('Protected', 'False')) == 'False'
              and not len(child.find('Value'))):
            node.remove(child)
    autotype = node.find('AutoType')
    if autotype is not None:
        for child in list(autotype):
            if not child.attrib and (child.tag == 'Enabled' and _bool(child.text or '') == 'True'
                    or child.tag == 'DataTransferObfuscation' and child.text == '0'
                    or child.tag == 'DefaultSequence' and not child.text
                    or child.tag == 'Association' and not child.findtext('Window') and not child.findtext('KeystrokeSequence')
                    and all(c.tag in {'Window', 'KeystrokeSequence'} and not c.attrib and not len(c) for c in child)):
                autotype.remove(child)
        if not len(autotype) and not autotype.attrib and not (autotype.text or '').strip():
            node.remove(autotype)
    unordered = {'Times': {'LastModificationTime', 'CreationTime', 'LastAccessTime', 'ExpiryTime', 'Expires', 'UsageCount', 'LocationChanged'},
                 'String': {'Key', 'Value'}, 'Binary': {'Key', 'Value'},
                 'Item': {'Key', 'Value', 'LastModificationTime'}, 'CustomData': {'Item'},
                 'Association': {'Window', 'KeystrokeSequence'}, 'Icon': {'Data', 'Name', 'LastModificationTime'}}
    entry_fields = {'IconID', 'CustomIconUUID', 'ForegroundColor', 'BackgroundColor', 'OverrideURL', 'Tags',
                    'Times', 'String', 'Binary', 'AutoType', 'CustomData', 'QualityCheck', 'PreviousParentGroup',
                    'LastModificationTime', 'EntryUUID'}
    def visit(element, parent='', inherited_space=False):
        attributes = dict(element.attrib)
        space = attributes.get('{http://www.w3.org/XML/1998/namespace}space', 'preserve' if inherited_space else 'default') == 'preserve'
        if 'Protected' in attributes:
            attributes['Protected'] = _bool(attributes['Protected'])
            if attributes['Protected'] == 'False':
                del attributes['Protected']
        text = element.text or ''
        if len(element) and not text.strip() and not space:
            text = ''
        if element.tag in {'Expires', 'Enabled'}:
            text = _bool(text)
        if parent == 'Times' and (element.tag.endswith('Time') or element.tag == 'LocationChanged'):
            text = _time(text, version)
        if element.tag == 'Binary':
            value = element.find('Value')
            data = binaries[int(value.get('Ref'))]
            value.set('Ref', 'sha256:' + hashlib.sha256(data).hexdigest())
        children = []
        for child in element:
            if isinstance(child.tag, str):
                children.append(visit(child, element.tag, space))
            elif child.tail and (child.tail.strip() or space):
                children.append(['#text', [], child.tail, [], ''])
        if (element.tag == 'Entry' and all(c[0] in entry_fields for c in children)
                or element.tag in unordered and all(c[0] in unordered[element.tag] for c in children)):
            children.sort(key=_json)
        elif element.tag == 'AutoType':
            children = sorted([c for c in children if c[0] != 'Association'], key=_json) + [c for c in children if c[0] == 'Association']
        tail = element.tail or ''
        if not parent or not inherited_space and not tail.strip():
            tail = ''
        return [element.tag, sorted(attributes.items()), text, children, tail]
    return visit(node)


def entry_signature(entry):
    node = copy.deepcopy(entry._element)
    timeinfo = node.find('Times')
    if timeinfo is not None:
        for child in list(timeinfo):
            if child.tag in {'LastAccessTime', 'UsageCount'}:
                timeinfo.remove(child)
    return _json(_canonical(node, entry._kp.binaries, entry._kp.version, times=True))


def _marker(group):
    return group._element.findtext('./CustomData/Item[Key="' + MARKER + '"]/Value')


def is_archive_group(group):
    return group is not None and getattr(group, 'uuid', None) == ARCHIVE_UUID


def active_entries(vault):
    for entry in vault.entries:
        group = getattr(entry, 'group', None)
        while group is not None and not is_archive_group(group):
            group = getattr(group, 'parentgroup', None)
        if group is None:
            yield entry


def _capsule(entry, group):
    element = copy.deepcopy(entry._element)
    history = element.find('History')
    if history is not None:
        element.remove(history)
    attachments = []
    # PyKeePass's find_attachments excludes history by default, even when its
    # element argument is a HistoryEntry. Resolve each original Binary directly.
    for attachment in element.findall('Binary'):
        reference = int(attachment.find('Value').get('Ref'))
        data = entry._kp.binaries[reference]
        attachments.append({'ref': reference, 'data': base64.b64encode(data).decode('ascii')})
    icon_uuid = element.findtext('CustomIconUUID')
    icons = [_packed(icon) for icon in entry._kp.tree.findall('./Meta/CustomIcons/Icon')
             if icon.findtext('UUID') == icon_uuid] if icon_uuid else []
    group_record = copy.deepcopy(group._element)
    for child in list(group_record):
        if child.tag in {'Entry', 'Group'}:
            group_record.remove(child)
    return {'schema': POLICY, 'uuid': str(entry.uuid), 'group_uuid': str(group.uuid),
            'group_path': group.path, 'group_record': _packed(group_record),
            'format': list(entry._kp.version), 'custom_icons': icons,
            'record': _packed(element), 'attachments': attachments}


def capsule_identity(payload):
    node = _unpacked(payload['record'])
    if payload['schema'] != POLICY or node.tag != 'Entry':
        raise ValueError
    original = uuid.UUID(payload['uuid'])
    if base64.b64decode(node.findtext('UUID'), validate=True) != original.bytes:
        raise ValueError
    binaries = {item['ref']: base64.b64decode(item['data'], validate=True) for item in payload['attachments']}
    canonical = _canonical(node, binaries, payload['format'], times=True)
    icons = []
    for packed in payload.get('custom_icons', []):
        icon = _unpacked(packed)
        icon.find('Data').text = hashlib.sha256(base64.b64decode(icon.findtext('Data'))).hexdigest()
        icons.append(_canonical(icon, {}, payload['format'], times=True))
    icons.sort(key=_json)
    return hashlib.sha256(_json([str(original), str(uuid.UUID(payload['group_uuid'])), canonical, icons])).hexdigest()


def _alias(identity):
    return uuid.uuid5(NAMESPACE, identity)


def archives(vault):
    """Validate the reserved group and every capsule before using an input."""
    result = {}
    groups = [g for g in vault.groups if is_archive_group(g)]
    if not groups:
        return result
    if len(groups) != 1 or groups[0] == vault.root_group or _marker(groups[0]) != POLICY or groups[0].subgroups:
        raise PreservationError('invalid preservation archive; merge refused')
    aliases = set()
    for entry in groups[0].entries:
        try:
            if entry.history or len(entry.attachments) != 1 or entry.attachments[0].filename != FILENAME:
                raise ValueError
            data = entry.attachments[0].data
            if entry.get_custom_property(CHECKSUM) != hashlib.sha256(data).hexdigest():
                raise ValueError
            payload = json.loads(data)
            identity = capsule_identity(payload)
            if entry.uuid != _alias(identity) or identity in result or entry.uuid in aliases:
                raise ValueError
            aliases.add(entry.uuid)
            result[identity] = data
        except Exception:
            raise PreservationError('invalid preserved version capsule; merge refused') from None
    return result


def collect(vaults, *, capture):
    ledger = {}
    for vault in vaults:
        for identity, data in archives(vault).items():
            ledger.setdefault(identity, data)
        if capture:
            for entry in active_entries(vault):
                for version in [entry, *entry.history]:
                    payload = _capsule(version, entry.group)
                    ledger.setdefault(capsule_identity(payload), _json(payload))
    return ledger


def ensure(vault, ledger):
    """Restore opaque capsules lost/normalized by a native stage from inputs."""
    from lxml import etree
    groups = [g for g in vault.groups if is_archive_group(g)]
    if not ledger:
        archives(vault)
        return False
    changed = False
    if len(groups) > 1:
        raise PreservationError('duplicate preservation group UUID; merge refused')
    if groups:
        group = groups[0]
        if _marker(group) != POLICY or group.subgroups:
            raise PreservationError('invalid preservation archive; merge refused')
    else:
        group = vault.add_group(vault.root_group, 'akdbx preserved versions')
        group.uuid = ARCHIVE_UUID
        for field in ('ctime', 'mtime', 'atime'):
            setattr(group, field, EPOCH)
        custom = etree.SubElement(group._element, 'CustomData')
        item = etree.SubElement(custom, 'Item')
        etree.SubElement(item, 'Key').text = MARKER
        etree.SubElement(item, 'Value').text = POLICY
        for field in ('EnableSearching', 'EnableAutoType'):
            setting = group._element.find(field)
            if setting is None:
                setting = etree.SubElement(group._element, field)
            setting.text = 'False'
        changed = True
    existing = {entry.uuid: entry for entry in vault.entries}
    group_ids = {group.uuid for group in vault.groups}
    aliases = {}
    for identity, data in ledger.items():
        alias = _alias(identity)
        if alias in group_ids or alias in aliases and aliases[alias] != identity:
            raise PreservationError('preserved version UUID collision; merge refused')
        aliases[alias] = identity
        entry = existing.get(alias)
        if entry is not None:
            if entry.group.uuid != ARCHIVE_UUID:
                raise PreservationError('preserved version UUID collision; merge refused')
            if (not entry.history and len(entry.attachments) == 1 and entry.attachments[0].data == data
                    and entry.get_custom_property(CHECKSUM) == hashlib.sha256(data).hexdigest()):
                continue
            vault.delete_entry(entry)
        entry = vault.add_entry(group, 'Preserved original record', '', '', notes='Managed encrypted recovery record; do not edit.', force_creation=True)
        entry.uuid = alias
        entry.set_custom_property(CHECKSUM, hashlib.sha256(data).hexdigest(), protect=True)
        for field in ('ctime', 'mtime', 'atime'):
            setattr(entry, field, EPOCH)
        entry.add_attachment(vault.add_binary(data, protected=True), FILENAME)
        changed = True
    verify(vault, ledger)
    return changed


def verify(vault, ledger):
    actual = archives(vault)
    if any(identity not in actual or actual[identity] != data for identity, data in ledger.items()):
        raise PreservationError('preserved version verification failed; target not replaced')


def verify_selection(vault, originals):
    """Verify native active semantics without changing capsule-v1 identity."""
    from .selection import verify
    verify(vault, originals)
