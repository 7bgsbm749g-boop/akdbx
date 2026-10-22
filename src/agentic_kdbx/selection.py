"""Private, semantic verification of KeePassXC 2.7 active entry selection.

This does not merge or modify records. Capsule-v1's identity/retention code is
deliberately separate. No projection, field name, value or identity leaves here.
"""
from __future__ import annotations

import base64
import copy
import re
import unicodedata
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone

from . import versions

VERIFICATION = 'semantic-v1'
DIAGNOSTICS = 'categories-v1'
CATEGORIES = frozenset({'missing_entry', 'unexpected_entry', 'duplicate_entry', 'deletion',
                        'modification_time', 'standard_fields', 'custom_fields', 'field_protection',
                        'attachments', 'times_metadata', 'location', 'entry_metadata', 'custom_data',
                        'unsupported_structure', 'unsupported_times', 'unsupported_metadata'})
STANDARD = ('Title', 'UserName', 'Password', 'URL', 'Notes')
TIME_FIELDS = {'LastModificationTime', 'CreationTime', 'LastAccessTime', 'ExpiryTime',
               'Expires', 'UsageCount', 'LocationChanged'}


class SelectionError(versions.PreservationError):
    def __init__(self, categories):
        super().__init__('active version verification failed; target not replaced')
        # These are per-entry categories, never per-field details or secret hashes.
        self.diagnostics = {key: min(count, 2**31 - 1) for key, count in sorted(Counter(categories).items())
                            if key in CATEGORIES and type(count) is int and count > 0}


def decode_time(text, version):
    try:
        value = datetime.fromisoformat(versions._time(text, version))
        return value.replace(tzinfo=value.tzinfo or timezone.utc).astimezone(timezone.utc).replace(microsecond=0)
    except Exception:
        raise SelectionError(['unsupported_times']) from None


def time_value(item, name):
    nodes = item._element.findall('Times/' + name)
    if len(nodes) != 1:
        raise SelectionError(['unsupported_times'])
    return decode_time(nodes[0].text, item._kp.version)


def modification_time(item):
    return time_value(item, 'LastModificationTime')


def _boolean(text):
    result = versions._bool(text or '')
    if result not in {'True', 'False'}:
        raise SelectionError(['unsupported_structure'])
    return result == 'True'


def _uuid(text):
    if not text:
        return None
    try:
        value = uuid.UUID(bytes=base64.b64decode(text, validate=True))
        return value if value.int else None
    except Exception:
        raise SelectionError(['unsupported_structure']) from None


def _leaf(node, attributes=()):
    if len(node) or set(node.attrib) - set(attributes):
        raise SelectionError(['unsupported_structure'])
    return node.text or ''


def _pairs(element, tag, allowed_value_attributes=()):
    result = {}
    for node in element.findall(tag):
        if node.attrib or len(node) != 2 or {c.tag for c in node} != {'Key', 'Value'}:
            raise SelectionError(['unsupported_structure'])
        key = _leaf(node.find('Key'))
        value_node = node.find('Value')
        value = _leaf(value_node, allowed_value_attributes)
        if key in result:
            raise SelectionError(['unsupported_structure'])
        result[key] = (value, value_node)
    return result


def _fields(entry):
    values = _pairs(entry._element, 'String', ('Protected', 'ProtectInMemory'))
    return {key: (value, any([_boolean(node.get(attr, 'False')) for attr in ('Protected', 'ProtectInMemory')]))
            for key, (value, node) in values.items()}


def _attachments(entry):
    values = _pairs(entry._element, 'Binary', ('Ref',))
    try:
        return {key: entry._kp.binaries[int(node.get('Ref'))] for key, (_, node) in values.items()}
    except Exception:
        raise SelectionError(['unsupported_structure']) from None


def _times(entry):
    nodes = entry._element.findall('Times')
    if len(nodes) != 1 or nodes[0].attrib:
        raise SelectionError(['unsupported_times'])
    seen = set()
    for node in nodes[0]:
        if not isinstance(node.tag, str):
            continue
        if node.tag not in TIME_FIELDS or node.tag in seen or node.attrib or len(node):
            raise SelectionError(['unsupported_times'])
        seen.add(node.tag)
    expires = _boolean(nodes[0].findtext('Expires', 'False'))
    # An unused expiry time has no active expiry semantics; its exact original
    # representation is still retained in the immutable capsule.
    return (time_value(entry, 'CreationTime'), expires,
            time_value(entry, 'ExpiryTime') if expires else None)


def _custom_data(entry):
    containers = entry._element.findall('CustomData')
    if len(containers) > 1:
        raise SelectionError(['unsupported_structure'])
    values = {}
    for container in containers:
        if container.attrib:
            raise SelectionError(['unsupported_structure'])
        for item in container:
            if not isinstance(item.tag, str):
                continue
            tags = [c.tag for c in item if isinstance(c.tag, str)]
            if (item.tag != 'Item' or item.attrib or tags.count('Key') != 1 or tags.count('Value') != 1
                    or tags.count('LastModificationTime') > 1
                    or set(tags) - {'Key', 'Value', 'LastModificationTime'}):
                raise SelectionError(['unsupported_structure'])
            clock = item.find('LastModificationTime')
            if clock is not None:
                decode_time(_leaf(clock), entry._kp.version)
            key, value = _leaf(item.find('Key')), _leaf(item.find('Value'))
            if key in values:
                raise SelectionError(['unsupported_structure'])
            values[key] = value
    # Native reader/writer regenerates its dictionary clock and upgrades the
    # legacy report flag. Neither exception applies to String custom fields.
    values.pop('_LAST_MODIFIED', None)
    values.pop('KnownBad', None)
    return values


def _tags(text):
    def space(character):
        return character in '\t\n\v\f\r' or unicodedata.category(character) in {'Zs', 'Zl', 'Zp'}
    def trim(value):
        while value and space(value[0]):
            value = value[1:]
        while value and space(value[-1]):
            value = value[:-1]
        return value
    return ';'.join(sorted({trim(part) for part in re.split('[,;\t]', text) if part},
                           key=lambda item: item.encode('utf-16be')))


def _metadata(entry):
    from lxml import etree
    node = copy.deepcopy(entry._element)
    known = {'UUID', 'String', 'Binary', 'Times', 'History', 'CustomData', 'PreviousParentGroup',
             'IconID', 'CustomIconUUID', 'ForegroundColor', 'BackgroundColor', 'OverrideURL', 'Tags',
             'AutoType', 'QualityCheck'}
    unknown = bool(node.attrib) or any(isinstance(c.tag, str) and c.tag not in known for c in node)
    quality = True
    for child in node:
        if child.tag == 'QualityCheck':
            quality = _boolean(_leaf(child))
        elif child.tag == 'CustomData':
            legacy = child.findtext('./Item[Key="KnownBad"]/Value')
            if legacy is not None:
                quality = legacy != 'true'
    for child in list(node):
        if child.tag in {'String', 'Binary', 'Times', 'History', 'CustomData', 'PreviousParentGroup', 'QualityCheck'}:
            node.remove(child)
        elif child.tag == 'Tags':
            child.text = _tags(_leaf(child))
        elif child.tag == 'IconID':
            try:
                child.text = str(int(_leaf(child)))
            except ValueError:
                raise SelectionError(['unsupported_structure']) from None
        elif child.tag == 'AutoType':
            for number in child.findall('DataTransferObfuscation'):
                try:
                    number.text = str(int(_leaf(number)))
                except ValueError:
                    raise SelectionError(['unsupported_structure']) from None
    custom_icon = node.find('CustomIconUUID')
    if custom_icon is not None:
        identity = _uuid(_leaf(custom_icon))
        if identity is None:
            node.remove(custom_icon)
        else:
            custom_icon.text = base64.b64encode(identity.bytes).decode('ascii')
            for icon in list(node.findall('IconID')):
                node.remove(icon)  # Native custom icon selects icon number zero.
    if not quality:
        etree.SubElement(node, 'QualityCheck').text = 'False'
    return versions._canonical(node, {}, entry._kp.version, times=False), unknown


@dataclass
class Expected:
    entry: object
    group: uuid.UUID
    previous: uuid.UUID | None


def _previous(entry):
    nodes = entry._element.findall('PreviousParentGroup')
    if len(nodes) > 1:
        raise SelectionError(['unsupported_structure'])
    return _uuid(_leaf(nodes[0])) if nodes else None


def _expected(originals):
    result = {}
    root = originals[0].root_group.uuid
    # Match the two native stages: location is resolved before whole active
    # record selection. A newer value and a newer location can come from
    # different inputs. History never promotes itself to active.
    for original in originals:
        for entry in versions.active_entries(original):
            group = root if entry.group.uuid == original.root_group.uuid else entry.group.uuid
            stamp = modification_time(entry)
            location = time_value(entry, 'LocationChanged')
            current = result.get(entry.uuid)
            if current is None:
                result[entry.uuid] = Expected(entry, group, _previous(entry))
                continue
            if location > time_value(current.entry, 'LocationChanged') and group != current.group:
                current.previous, current.group = current.group, group
            if stamp > modification_time(current.entry):
                current.entry, current.previous = entry, _previous(entry)
    return result


def verify(vault, originals):
    expected = _expected(originals)
    entries = list(versions.active_entries(vault))
    actual = {entry.uuid: entry for entry in entries}
    errors = Counter()
    if len(actual) != len(entries):
        errors['duplicate_entry'] += 1
    errors['unexpected_entry'] += len(actual.keys() - expected.keys())
    deleted = {r.findtext('UUID'): decode_time(r.findtext('DeletionTime'), vault.version)
               for r in vault.tree.findall('./Root/DeletedObjects/DeletedObject')}
    protection = originals[0].tree.find('./Meta/MemoryProtection')
    for identity, selected in expected.items():
        entry, chosen = selected.entry, actual.get(identity)
        categories = set()
        stamp = deleted.get(entry._element.findtext('UUID'))
        if stamp is not None and modification_time(entry) <= stamp:
            if chosen is not None:
                errors['deletion'] += 1
            continue
        if chosen is None:
            errors['missing_entry'] += 1
            continue
        try:
            if modification_time(chosen) != modification_time(entry):
                categories.add('modification_time')
            left, right = _fields(entry), _fields(chosen)
            if any(left.get(key, ('', False))[0] != right.get(key, ('', False))[0] for key in STANDARD):
                categories.add('standard_fields')
            if {k: v[0] for k, v in left.items() if k not in STANDARD} != {k: v[0] for k, v in right.items() if k not in STANDARD}:
                categories.add('custom_fields')
            for key in left.keys() | right.keys():
                before, after = left.get(key, ('', False))[1], right.get(key, ('', False))[1]
                policy = protection.findtext('Protect' + key, 'False') if protection is not None and key in STANDARD else 'False'
                if before and not after or not before and after and not _boolean(policy):
                    categories.add('field_protection')
            if _attachments(chosen) != _attachments(entry):
                categories.add('attachments')
            if _times(chosen) != _times(entry):
                categories.add('times_metadata')
            if (chosen.group.uuid != selected.group or _previous(chosen) != selected.previous
                    or time_value(chosen, 'LocationChanged') != time_value(entry, 'LocationChanged')):
                categories.add('location')
            if _custom_data(chosen) != _custom_data(entry):
                categories.add('custom_data')
            before, unknown_before = _metadata(entry)
            after, unknown_after = _metadata(chosen)
            if before != after:
                categories.add('unsupported_metadata' if unknown_before or unknown_after else 'entry_metadata')
        except SelectionError as exc:
            categories.update(exc.diagnostics)
        except Exception:
            categories.add('unsupported_structure')
        errors.update(categories)
    if any(errors.values()):
        raise SelectionError(errors)
