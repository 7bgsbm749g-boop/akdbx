"""Merge two opened KDBX trees in memory. Only the target copy is modified."""
from __future__ import annotations

import base64
import copy
import hashlib
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from lxml import etree

from . import selection, versions

ENGINE = 'akdbx-native-v1'


def validate(vault):
    """Check file-local references before comparing them or capturing history."""
    if vault.version[0] == 3:
        header_hash = vault.tree.findtext('./Meta/HeaderHash')
        if header_hash and base64.b64decode(header_hash, validate=True) != hashlib.sha256(vault.kdbx.header.data).digest():
            raise ValueError('incorrect KDBX header hash')
        binaries = vault.tree.findall('./Meta/Binaries/Binary')
        if any(node.get('ID') != str(index) for index, node in enumerate(binaries)):
            raise ValueError('unsupported KDBX binary table')
        count = len(binaries)
    else:
        count = len(vault.payload.inner_header.binary)
    for node in vault.tree.xpath('//Entry/Binary/Value'):
        ref = node.get('Ref', '')
        if not ref.isascii() or not ref.isdecimal() or int(ref) >= count:
            raise ValueError('invalid attachment reference')


def _set(node, tag, value):
    child = node.find(tag)
    if child is None:
        child = etree.SubElement(node, tag)
    child.text = value


def _snapshot(node):
    """Copy a record without recursively copying its children or history."""
    result = etree.Element(node.tag, attrib=node.attrib)
    result.text = node.text
    for child in node:
        if child.tag not in {'Entry', 'Group', 'History'}:
            result.append(copy.deepcopy(child))
    return result


class _Transfer:
    """Translate source-local binary references and KDBX wire-format dates."""
    def __init__(self, target, source):
        self.target = target
        self.source = source
        self.source_pool = source.binaries
        self.target_pool = target.binaries
        self.target_ids = {data: index for index, data in enumerate(self.target_pool)}
        self.protected_ids = {}
        if target.version[0] >= 4:
            self.protected_ids = {data: index for index, data in enumerate(self.target_pool)
                                  if target.payload.inner_header.binary[index].data[0] & 1}

    def translate(self, node):
        for value in node.xpath('./Binary/Value | ./History/Entry/Binary/Value'):
            ref = int(value.get('Ref'))
            data = self.source_pool[ref]
            protected = (self.target.version[0] >= 4 and self.source.version[0] >= 4
                         and self.source.payload.inner_header.binary[ref].data[0] & 1)
            indices = self.protected_ids if protected else self.target_ids
            if data not in indices:
                index = versions.append_binary(self.target, data)
                self.target_ids[data] = self.protected_ids[data] = index
                self.target_pool.append(data)
            value.set('Ref', str(indices[data]))
        if self.source.version[0] != self.target.version[0]:
            for field in node.xpath('./Times/* | ./History/Entry/Times/* | ./CustomData/Item/LastModificationTime | ./History/Entry/CustomData/Item/LastModificationTime | ./LastModificationTime'):
                if field.tag in {'CreationTime', 'LastModificationTime', 'LastAccessTime', 'ExpiryTime', 'LocationChanged'}:
                    field.text = self.date(field.text)
        return node

    def date(self, text):
        if self.source.version[0] == self.target.version[0]:
            return text
        stamp = datetime.fromisoformat(versions._time(text, self.source.version))
        if stamp.microsecond and self.target.version[0] >= 4:
            raise ValueError('timestamp precision exceeds target format')
        return self.target._encode_time(stamp)


def _groups(target, source, transfer):
    mapped = {group.uuid: group._element for group in target.groups}
    target_root, source_root = target.root_group, source.root_group
    group_ids = mapped.keys() | {g.uuid for g in source.groups}
    if any(e.uuid in group_ids for vault in (target, source) for e in vault.entries):
        raise ValueError('entry and group share a UUID')
    if source_root.uuid != target_root.uuid and (
            source_root.uuid in mapped or any(g.uuid == target_root.uuid for g in source.groups)):
        raise ValueError('root and subgroup share a UUID')
    mapped[source_root.uuid] = target_root._element
    changed = False
    for group in source.groups:
        if group.uuid == source_root.uuid:
            continue
        parent = mapped[group.parentgroup.uuid]
        other = group._element
        current = mapped.get(group.uuid)
        if current is None:
            current = transfer.translate(_snapshot(other))
            parent.append(current)
            mapped[group.uuid] = current
            changed = True
            continue
        times = current.find('Times')
        if (current.getparent() is not parent and selection.time_value(group, 'LocationChanged')
                > selection.decode_time(times.findtext('LocationChanged'), target.version)):
            if parent is current or current in parent.iterancestors():
                raise ValueError('cyclic group move')
            _set(current, 'PreviousParentGroup', current.getparent().findtext('UUID'))
            parent.append(current)
            _set(times, 'LocationChanged', transfer.date(other.findtext('Times/LocationChanged')))
            changed = True
        if selection.modification_time(group) > selection.decode_time(times.findtext('LastModificationTime'), target.version):
            for field in ('Name', 'Notes'):
                _set(current, field, other.findtext(field))
            custom_icon = other.findtext('CustomIconUUID')
            if selection._uuid(custom_icon) is not None:
                _set(current, 'CustomIconUUID', custom_icon)
                _set(current, 'IconID', '0')
            elif other.findtext('IconID', '0') != '0':
                _set(current, 'IconID', other.findtext('IconID'))
                old_icon = current.find('CustomIconUUID')
                if old_icon is not None:
                    current.remove(old_icon)
            for field in ('LastModificationTime', 'ExpiryTime'):
                _set(times, field, transfer.date(other.findtext('Times/' + field)))
            changed = True
    return mapped, changed


def _history_bytes(node, pool):
    fields = node.xpath('./String/Key | ./String/Value | ./Binary/Key | ./AutoType/Association/* | ./CustomData/Item/Key | ./CustomData/Item/Value | ./Tags')
    size = sum(len((field.text or '').encode('utf-8')) for field in fields)
    return size + sum(len(pool[int(value.get('Ref'))]) for value in node.findall('./Binary/Value'))


def _merge_entry(current, incoming, parent, transfer, history_limit, size_limit):
    left, right = current._element, incoming._element
    left_time, right_time = selection.modification_time(current), selection.modification_time(incoming)
    moved = parent is not left.getparent() and selection.time_value(incoming, 'LocationChanged') > selection.time_value(current, 'LocationChanged')
    # Use target history first on ties. The transaction separately checks for
    # ambiguity or recovers every original from the preservation ledger.
    history = {selection.modification_time(item): (item, False) for item in current.history}
    added = False
    for item in incoming.history:
        stamp = selection.modification_time(item)
        if stamp not in history and stamp != max(left_time, right_time):
            history[stamp] = (item, True)
            added = True
    if left_time != right_time:
        loser, imported = (current, False) if left_time < right_time else (incoming, True)
        stamp = min(left_time, right_time)
        if stamp not in history:
            history[stamp] = (loser, imported)
            added = True
    if not (added or moved or right_time > left_time):
        return False

    winner = transfer.translate(_snapshot(right)) if right_time > left_time else _snapshot(left)
    if moved and right_time <= left_time:
        _set(winner, 'PreviousParentGroup', left.getparent().findtext('UUID'))
        # The location update changes the original active record's signature.
        history[left_time] = (current, False)
    stamps = sorted(history)
    if history_limit >= 0:
        stamps = stamps[max(0, len(stamps) - history_limit):]
    kept = []
    size = 0
    for stamp in reversed(stamps):
        item, imported = history[stamp]
        node = _snapshot(item._element)
        if size_limit >= 0:
            size += _history_bytes(node, transfer.source_pool if imported else transfer.target_pool)
            if size > size_limit:
                break
        kept.append(transfer.translate(node) if imported else node)
    if kept:
        etree.SubElement(winner, 'History').extend(reversed(kept))
    if not moved and etree.tostring(winner, with_tail=False) == etree.tostring(left, with_tail=False):
        return False
    if moved:
        left.getparent().remove(left)
        parent.append(winner)
    else:
        left.getparent().replace(left, winner)
    return True


def _keyed(node, tag, key):
    result = {}
    if node is not None:
        for item in node.findall(tag):
            identity = item.findtext(key)
            if not identity or identity in result:
                raise ValueError('invalid metadata key')
            result[identity] = item
    return result


def _dictionary_time(items, vault):
    clock = items.get('_LAST_MODIFIED')
    if clock is None:
        return None
    text = clock.findtext('Value') or ''
    try:
        return selection.decode_time(text, vault.version)
    except selection.SelectionError:
        # KeePassXC also writes Qt TextDate, e.g. "Sun Jan 12 03:51:58 2020 GMT".
        try:
            date = parsedate_to_datetime(text)
            return date.astimezone(timezone.utc) if date.tzinfo else None
        except (ValueError, TypeError, OverflowError):
            return None


def _metadata(target, source, transfer):
    changed = False
    for collection, tag, key in [('CustomIcons', 'Icon', 'UUID'), ('CustomData', 'Item', 'Key')]:
        container = target.tree.find('./Meta/' + collection)
        existing = _keyed(container, tag, key)
        incoming = _keyed(source.tree.find('./Meta/' + collection), tag, key)
        source_clock = _dictionary_time(incoming, source) if tag == 'Item' else None
        target_clock = _dictionary_time(existing, target) if tag == 'Item' else None
        for identity, item in incoming.items():
            old = existing.get(identity)
            if old is not None:
                if tag == 'Icon':
                    continue
                ltime, rtime = old.findtext('LastModificationTime'), item.findtext('LastModificationTime')
                left = selection.decode_time(ltime, target.version) if ltime else target_clock
                right = selection.decode_time(rtime, source.version) if rtime else source_clock
                if left is None or right is None or right <= left or identity == 'KPXC_RANDOM_SLUG':
                    continue
            if container is None:
                container = etree.SubElement(target.tree.find('./Meta'), collection)
            node = transfer.translate(copy.deepcopy(item))
            if old is not None and etree.tostring(old, with_tail=False) == etree.tostring(node, with_tail=False):
                continue
            if old is None:
                container.append(node)
            else:
                container.replace(old, node)
            changed = True
    return changed


def merge(target, source):
    transfer = _Transfer(target, source)
    groups, changed = _groups(target, source, transfer)
    entries = {entry.uuid: entry for entry in target.entries}
    history_limit = int(target.tree.findtext('./Meta/HistoryMaxItems', '10'))
    size_limit = int(target.tree.findtext('./Meta/HistoryMaxSize', '6291456'))
    for incoming in source.entries:
        parent = groups[incoming.group.uuid]
        current = entries.get(incoming.uuid)
        if current is None:
            parent.append(transfer.translate(copy.deepcopy(incoming._element)))
            changed = True
        else:
            changed = _merge_entry(current, incoming, parent, transfer, history_limit, size_limit) or changed
    changed = _metadata(target, source, transfer) or changed
    if changed:
        requires_41 = target.tree.xpath(
            'boolean(//Group/Tags[string-length(text()) > 0] | //Entry/QualityCheck[text()="False"]'
            ' | //CustomIcons/Icon/Name[string-length(text()) > 0] | //CustomIcons/Icon/LastModificationTime'
            ' | //CustomData/Item/LastModificationTime)')
        if target.version[0] == 3 and requires_41:
            raise ValueError('merged data requires KDBX 4.1')
        if target.version[0] == 4:
            minor = source.version[1] if source.version[0] == 4 else 0
            target.kdbx.header.value.minor_version = max(target.version[1], minor, int(requires_41))
    return changed
