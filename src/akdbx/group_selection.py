"""Private native group selection, distinct from group-semantic-v1.

Models KeePassXC 2.7.10 Merger's current -> held -> incoming property and
location selection. Does not merge, mutate a database, run native code or
serialize a candidate. Unknown group schema refuses. Original full-precision
clocks/CustomData are checked before writer loss, never bucketed or erased.
"""
from __future__ import annotations

import base64
import copy
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from lxml import etree

from . import selection, versions

VERIFICATION = 'keepassxc-2.7.10-selection-v1'
CATEGORIES = frozenset({'group_membership', 'group_properties', 'group_times',
    'group_location', 'group_custom_data', 'group_tags', 'unsupported_group_metadata'})


class GroupSelectionError(versions.PreservationError):
    def __init__(self, categories):
        super().__init__('native group selection verification failed; target not replaced')
        self.diagnostics = {k: min(v, 2**31 - 1) for k, v in sorted(Counter(categories).items())
                            if k in CATEGORIES and type(v) is int and v > 0}


def _put(node, tag, text):
    child = node.find(tag)
    if child is None:
        child = etree.SubElement(node, tag)
    child.text = text


def _remove(node, tag):
    for child in node.findall(tag):
        node.remove(child)


@dataclass
class GroupState:
    node: object
    vault: object
    parent: object


def _clock(state, name):
    from .admission import _group_time
    return datetime.fromisoformat(_group_time(state.node.findtext('Times/' + name), state.vault))


def _read(group, vault):
    from .admission import GROUP_FIELDS, _group_defaults
    original = group._element
    if original.attrib or (original.text or '').strip():
        raise GroupSelectionError(['unsupported_group_metadata'])
    node = etree.Element('Group')
    seen = set()
    for child in original:
        if child.tag in {'Entry', 'Group'}:
            continue
        if child.tag not in GROUP_FIELDS or child.tag in seen:
            raise GroupSelectionError(['unsupported_group_metadata'])
        seen.add(child.tag)
        if child.tag not in {'Times', 'CustomData'}:
            selection._leaf(child)
        node.append(copy.deepcopy(child))
    _group_defaults(node, vault)
    # QDateTime and the native binary writer cannot preserve arbitrary ISO
    # fractions. Do not invent a finer native ordering or round an input.
    # The strict/tag-only profiles can still compare exact equal fractions.
    for name in ('CreationTime', 'LastModificationTime', 'ExpiryTime', 'LocationChanged'):
        if datetime.fromisoformat(node.findtext('Times/' + name)).microsecond:
            raise GroupSelectionError(['unsupported_group_metadata'])
    try:
        icon = int(node.findtext('IconID'))
        if str(icon) != node.findtext('IconID') or not 0 <= icon <= 68:
            raise ValueError
    except Exception:
        raise GroupSelectionError(['unsupported_group_metadata']) from None
    custom = selection._uuid(node.findtext('CustomIconUUID'))
    if custom is not None:
        # Native reader: custom icon sets built-in icon number to zero.
        _put(node, 'IconID', '0')
        _put(node, 'CustomIconUUID', base64.b64encode(custom.bytes).decode())
    return GroupState(node, vault, group.parentgroup.uuid if group.parentgroup else None)


def _parent(states, identity, parent):
    current = parent
    seen = {identity}
    while current is not None:
        if current in seen or current not in states:
            raise GroupSelectionError(['group_location'])
        seen.add(current)
        current = states[current].parent


def _fields(state):
    from .admission import _shape
    shape = _shape(state.node, state.vault, group=True, tag_equivalence=True)
    return {field[0]: field for field in shape[3]}


def _deletions(vaults):
    from .admission import _group_time
    deleted = {}
    for vault in vaults:
        for node in vault.tree.findall('./Root/DeletedObjects/DeletedObject'):
            identity = selection._uuid(node.findtext('UUID'))
            stamp = datetime.fromisoformat(_group_time(node.findtext('DeletionTime'), vault))
            # Entry selection's established tombstone protocol is whole seconds.
            # Refuse unsupported fractional tombstones, never silently round.
            if stamp.microsecond:
                raise GroupSelectionError(['unsupported_group_metadata'])
            deleted[identity] = min(stamp, deleted.get(identity, stamp))
    return deleted


def verify(incoming, originals):
    all_inputs = (*originals, incoming)
    root = originals[0].root_group.uuid
    if any(v.root_group.uuid != root for v in all_inputs):
        raise GroupSelectionError(['group_membership'])
    # A UUID cannot change between an entry and a group across input branches.
    group_ids = {g.uuid for v in all_inputs for g in v.groups}
    if any(e.uuid in group_ids for v in all_inputs for e in v.entries):
        raise GroupSelectionError(['group_membership'])
    states = {}
    for vault in all_inputs:
        # PyKeePass groups are document/preorder. Parents precede their children,
        # matching native Merger recursion. Newly cloned children have no parent
        # until moveGroup attaches them; existing groups resolve moves first.
        for group in vault.groups:
            source = _read(group, vault)
            current = states.get(group.uuid)
            if current is None:
                if source.parent is not None:
                    _parent(states, group.uuid, source.parent)
                states[group.uuid] = source
                continue
            if group.uuid == root:
                continue  # Native mergeGroup does not resolve root properties.
            if (_clock(source, 'LocationChanged') > _clock(current, 'LocationChanged')
                    and source.parent != current.parent):
                _parent(states, group.uuid, source.parent)
                _put(current.node, 'PreviousParentGroup', base64.b64encode(current.parent.bytes).decode())
                current.parent = source.parent
                _put(current.node.find('Times'), 'LocationChanged', source.node.findtext('Times/LocationChanged'))
            if _clock(source, 'LastModificationTime') > _clock(current, 'LastModificationTime'):
                # Native resolves ONLY these properties. Other settings, original
                # creation/expiry-enabled/CustomData and unknowns are not replaced.
                for tag in ('Name', 'Notes'):
                    _put(current.node, tag, source.node.findtext(tag))
                icon = source.node.findtext('IconID')
                custom = source.node.findtext('CustomIconUUID')
                if icon != '0':
                    _put(current.node, 'IconID', icon)
                    _remove(current.node, 'CustomIconUUID')
                elif custom is not None:
                    _put(current.node, 'IconID', '0')
                    _put(current.node, 'CustomIconUUID', custom)
                # setIcon(null UUID) is a no-op; never invent a built-in icon.
                for tag in ('ExpiryTime', 'LastModificationTime'):
                    _put(current.node.find('Times'), tag, source.node.findtext('Times/' + tag))
    for identity, state in states.items():
        _parent(states, identity, state.parent)
    deleted = _deletions(all_inputs)
    if root in deleted or versions.ARCHIVE_UUID in deleted:
        raise GroupSelectionError(['group_membership'])
    if _deletions((incoming,)) != deleted:
        raise GroupSelectionError(['group_membership'])
    # Conditional admission verifies entry containment independently below. Using
    # actual incoming occupancy here cannot excuse a missing required entry.
    occupied = {entry.group.uuid for entry in incoming.entries}
    pending = set(states)
    while pending:
        leaves = {identity for identity in pending if not any(
            child in pending and value.parent == identity for child, value in states.items())}
        if not leaves:
            raise GroupSelectionError(['group_location'])
        for identity in leaves:
            state = states[identity]
            if (identity in deleted and _clock(state, 'LastModificationTime') <= deleted[identity]
                    and identity not in occupied and not any(v.parent == identity for v in states.values())):
                del states[identity]
        pending -= leaves
    actual = {g.uuid: _read(g, incoming) for g in incoming.groups}
    errors = Counter()
    errors['group_membership'] += len(states.keys() ^ actual.keys())
    for identity in states.keys() & actual.keys():
        selected, chosen = states[identity], actual[identity]
        categories = set()
        if chosen.parent != selected.parent:
            categories.add('group_location')
        left, right = _fields(selected), _fields(chosen)
        for key in left.keys() | right.keys():
            if left.get(key) != right.get(key):
                categories.add({'Times': 'group_times', 'CustomData': 'group_custom_data',
                                'Tags': 'group_tags', 'PreviousParentGroup': 'group_location'}.get(key, 'group_properties'))
        errors.update(categories)
    if any(errors.values()):
        raise GroupSelectionError(errors)
