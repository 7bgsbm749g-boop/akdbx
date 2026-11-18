"""Small synthetic fixtures measure redundant copying without timing thresholds."""
from collections import Counter
import copy
from datetime import timedelta
import io
import sys

from lxml import etree
import pytest
from pykeepass import PyKeePass
from pykeepass.entry import Entry

from akdbx import admission, group_selection, selection, versions
from test_merge import BASE_TIME, MASTER, base


@pytest.mark.parametrize('padding', [128, 16384])
def test_tag_trimming_copies_only_linear_text(monkeypatch, padding):
    copied = 0

    class CountedText(str):
        def __getitem__(self, key):
            nonlocal copied
            value = super().__getitem__(key)
            if isinstance(key, slice):
                copied += len(value)
                return CountedText(value)
            return value

    split = selection.re.split

    def counted_split(pattern, text):
        return [CountedText(part) for part in split(pattern, text)]

    monkeypatch.setattr(selection.re, 'split', counted_split)
    text = ' ' * padding + 'tag' + '\u2003' * padding
    assert selection._tags(text) == 'tag'
    assert copied <= len(text) * 2, copied


@pytest.mark.parametrize('text,expected', [
    ('\u2003 Beta\u2028;Alpha\r\n;Alpha', 'Alpha;Beta'),
    (' ;tag;;', ';tag'),
    ('\u001ctag\u0085;\u200btag\u200b', '\u001ctag\u0085;\u200btag\u200b'),
    ('\ue000;\U00010000;a;A;a', 'A;a;\U00010000;\ue000'),
])
def test_tag_trimming_preserves_native_comparison_semantics(text, expected):
    assert selection._tags(text) == expected


def test_tag_padding_verification_preserves_xml_and_detects_changed_tag(base):
    source = PyKeePass(io.BytesIO(base.read_bytes()), password=MASTER)
    entry = source.add_entry(source.root_group, 'Tagged synthetic', 'synthetic-user', 'synthetic')
    tags = etree.SubElement(entry._element, 'Tags')
    tags.text = '\u2003 alpha\u2028;beta '
    candidate = copy.deepcopy(source)
    changed = candidate.find_entries(uuid=entry.uuid, first=True)._element.find('Tags')
    changed.text = 'beta;alpha'
    before = etree.tostring(source.tree), etree.tostring(candidate.tree)
    selection.verify(candidate, [source])
    assert (etree.tostring(source.tree), etree.tostring(candidate.tree)) == before
    changed.text = 'beta;different'
    with pytest.raises(selection.SelectionError) as exc:
        selection.verify(candidate, [source])
    assert exc.value.diagnostics.get('entry_metadata') == 1


def attached_vault(base, size, attachments=2):
    vault = PyKeePass(io.BytesIO(base.read_bytes()), password=MASTER)
    vault.add_binary(b'synthetic unrelated data' * 256)
    reference = vault.add_binary(b'synthetic attachment' * 64)
    for number in range(size):
        entry = vault.add_entry(vault.root_group, f'Synthetic {number}', 'synthetic-user', 'synthetic')
        for index in range(attachments):
            entry.add_attachment(reference, f'document-{index}.bin')
        entry.mtime = BASE_TIME
        for revision in range(2):
            entry.save_history()
            entry.password = f'synthetic revision {revision}'
            entry.mtime = BASE_TIME + timedelta(seconds=revision + 1)
    return vault


@pytest.fixture
def pool_reads(monkeypatch):
    getter = PyKeePass.binaries.fget
    calls = Counter()

    def counted(vault):
        calls[id(vault)] += 1
        return getter(vault)

    monkeypatch.setattr(PyKeePass, 'binaries', property(counted))
    return calls


@pytest.mark.parametrize('verifier', [selection.verify, admission.verify])
def test_active_attachment_pool_reads_are_bounded_per_input(base, pool_reads, verifier):
    counts, shared_counts = {}, {}
    for size in (2, 24):
        source = attached_vault(base, size)
        candidate = copy.deepcopy(source)
        pool_reads.clear()
        verifier(candidate, [source, candidate])
        counts[size] = pool_reads[id(source)], pool_reads[id(candidate)]
        pool_reads.clear()
        verifier(candidate, [candidate])
        shared_counts[size] = pool_reads[id(candidate)]
    assert counts[2] == counts[24], counts
    assert shared_counts[2] == shared_counts[24], shared_counts
    assert all(count <= 1 for values in counts.values() for count in values)
    assert all(count <= 1 for count in shared_counts.values())


@pytest.mark.parametrize('verifier', [selection.verify, admission.verify])
def test_attachment_free_selection_does_not_load_unreferenced_pool(base, pool_reads, verifier):
    source = attached_vault(base, 2, attachments=0)
    candidate = copy.deepcopy(source)
    pool_reads.clear()
    verifier(candidate, [source, candidate])
    assert not pool_reads


@pytest.mark.parametrize('verifier', [selection.verify, admission.verify])
def test_active_attachment_changes_are_detected_in_later_operations(base, verifier):
    source = attached_vault(base, 2)
    candidate = copy.deepcopy(source)
    verifier(candidate, [source])
    entry = candidate.find_entries(title='Synthetic 0', first=True)
    entry.attachments[0].id = candidate.add_binary(b'synthetic changed attachment')
    with pytest.raises(selection.SelectionError) as exc:
        verifier(candidate, [source])
    assert exc.value.diagnostics.get('attachments') == 1


def test_new_capsules_do_not_materialize_growing_pool_per_insert(base, pool_reads):
    counts = {}
    for size in (2, 24):
        source = attached_vault(base, size)
        candidate = copy.deepcopy(source)
        ledger = versions.collect([source], capture=True)
        before = [item.data for item in candidate.payload.inner_header.binary]
        pool_reads.clear()
        assert versions.ensure(candidate, ledger)
        counts[size] = pool_reads[id(candidate)]
        assert [item.data for item in candidate.payload.inner_header.binary[:len(before)]] == before
        assert all(item.data[:1] == b'\x01' for item in candidate.payload.inner_header.binary[len(before):])
        buffer = io.BytesIO()
        candidate.save(buffer)
        reopened = PyKeePass(io.BytesIO(buffer.getvalue()), password=MASTER)
        assert versions.archives(reopened) == ledger
    assert counts[2] == counts[24], counts


def test_capsule_repair_and_later_mutation_preserve_payloads(base):
    source = attached_vault(base, 2)
    candidate = copy.deepcopy(source)
    ledger = versions.collect([source], capture=True)
    assert versions.ensure(candidate, ledger)
    wrapper = next(entry for entry in candidate.entries if versions.is_archive_group(entry.group))
    wrapper.set_custom_property(versions.CHECKSUM, 'synthetic invalidated checksum', protect=True)
    assert versions.ensure(candidate, ledger)
    assert versions.archives(candidate) == ledger
    entry = source.find_entries(title='Synthetic 0', first=True)
    entry.password = 'synthetic new version'
    entry.mtime = BASE_TIME + timedelta(days=1)
    updated = versions.collect([candidate, source], capture=True)
    assert len(updated) > len(ledger) and versions.ensure(candidate, updated)
    buffer = io.BytesIO()
    candidate.save(buffer)
    reopened = PyKeePass(io.BytesIO(buffer.getvalue()), password=MASTER)
    assert versions.archives(reopened) == updated
    assert versions.ensure(reopened, updated) is False


@pytest.mark.parametrize('repair', [False, True])
def test_capsule_insertion_duplicate_lookup_work_is_bounded(base, monkeypatch, repair):
    """Managed UUID-addressed wrappers need no growing duplicate-label search."""
    constructor, find = Entry.__init__, PyKeePass.find_entries
    for size in (2, 24):
        candidate = attached_vault(base, size)
        ledger = versions.collect([candidate], capture=True)
        if repair:
            versions.ensure(candidate, ledger)
            for entry in candidate.entries:
                if versions.is_archive_group(entry.group):
                    entry.set_custom_property(versions.CHECKSUM, 'synthetic invalid checksum', protect=True)
        matching = False
        matches = 0

        def counted_constructor(entry, *args, **kwargs):
            nonlocal matches
            if matching and kwargs.get('element') is not None:
                matches += 1
            constructor(entry, *args, **kwargs)

        def counted_find(vault, *args, **kwargs):
            nonlocal matching
            previous = matching
            matching = kwargs.get('title') == 'Preserved original record' and kwargs.get('first') is True
            try:
                return find(vault, *args, **kwargs)
            finally:
                matching = previous

        with monkeypatch.context() as patch:
            patch.setattr(Entry, '__init__', counted_constructor)
            patch.setattr(PyKeePass, 'find_entries', counted_find)
            assert versions.ensure(candidate, ledger)
        assert matches <= len(ledger), (size, matches, len(ledger))
        buffer = io.BytesIO()
        candidate.save(buffer)
        reopened = PyKeePass(io.BytesIO(buffer.getvalue()), password=MASTER)
        assert versions.archives(reopened) == ledger
        assert versions.ensure(reopened, ledger) is False


@pytest.mark.parametrize('shape', ['flat', 'chain'])
@pytest.mark.parametrize('deleted', [False, True])
def test_native_group_deletion_traversal_work_is_bounded(base, monkeypatch, shape, deleted):
    """Topology validation stays intact while deletion traversal scales linearly."""
    counts = {}
    for size in (12, 48):
        source = PyKeePass(io.BytesIO(base.read_bytes()), password=MASTER)
        parent = source.root_group
        branch = []
        for index in range(size):
            group = source.add_group(parent, f'Synthetic resource group {index}')
            group.mtime = BASE_TIME
            branch.append(group)
            if shape == 'chain':
                parent = group
        candidate = copy.deepcopy(source)
        if deleted:
            for group in branch:
                node = etree.SubElement(candidate.tree.find('./Root/DeletedObjects'), 'DeletedObject')
                etree.SubElement(node, 'UUID').text = group._element.findtext('UUID')
                etree.SubElement(node, 'DeletionTime').text = candidate._encode_time(BASE_TIME + timedelta(days=1))
            for group in list(candidate.root_group.subgroups):
                if group.uuid in {item.uuid for item in branch}:
                    candidate.delete_group(group)
        before = etree.tostring(source.tree), etree.tostring(candidate.tree)
        reads = 0

        class CountedState:
            def __init__(self, node, vault, parent):
                self.node, self.vault, self._parent = node, vault, parent

            @property
            def parent(self):
                nonlocal reads
                # Ancestor/cycle validation is separate from deletion traversal.
                if sys._getframe(1).f_code.co_name != '_parent':
                    reads += 1
                return self._parent

            @parent.setter
            def parent(self, value):
                self._parent = value

        with monkeypatch.context() as patch:
            patch.setattr(group_selection, 'GroupState', CountedState)
            group_selection.verify(candidate, [source])
        counts[size] = reads
        assert (etree.tostring(source.tree), etree.tostring(candidate.tree)) == before
    assert counts[48] <= 5 * counts[12], counts


@pytest.mark.parametrize('retained', ['occupied', 'newer', 'not-deleted'])
def test_group_deletion_keeps_ancestors_of_retained_children(base, retained):
    """A processed child still prevents parent deletion until it is actually removed."""
    source = PyKeePass(io.BytesIO(base.read_bytes()), password=MASTER)
    parent = source.add_group(source.root_group, 'Synthetic retained ancestor')
    child = source.add_group(parent, 'Synthetic retained descendant')
    parent.mtime = child.mtime = BASE_TIME
    if retained == 'occupied':
        source.add_entry(child, 'Synthetic retained record', 'synthetic', 'synthetic')
    elif retained == 'newer':
        child.mtime = BASE_TIME + timedelta(days=2)
    candidate = copy.deepcopy(source)
    for group in (parent, child):
        if group is child and retained == 'not-deleted':
            continue
        node = etree.SubElement(candidate.tree.find('./Root/DeletedObjects'), 'DeletedObject')
        etree.SubElement(node, 'UUID').text = group._element.findtext('UUID')
        etree.SubElement(node, 'DeletionTime').text = candidate._encode_time(BASE_TIME + timedelta(days=1))
    before = etree.tostring(source.tree), etree.tostring(candidate.tree)
    group_selection.verify(candidate, [source])
    assert (etree.tostring(source.tree), etree.tostring(candidate.tree)) == before


@pytest.mark.parametrize('profile', [admission.GROUP_VERIFICATION, admission.TAG_GROUP_VERIFICATION])
def test_group_projections_do_not_copy_discarded_descendants(base, monkeypatch, profile):
    real_copy = copy.deepcopy
    for depth in (4, 12):
        source = PyKeePass(io.BytesIO(base.read_bytes()), password=MASTER)
        parent = source.root_group
        for index in range(depth):
            parent = source.add_group(parent, f'Synthetic nested {index}')
            entry = source.add_entry(parent, 'Synthetic entry', 'synthetic-user', 'synthetic')
            entry.save_history()
            entry.save_history()
        candidate = real_copy(source)
        before = etree.tostring(source.tree), etree.tostring(candidate.tree)
        entries_copied = []

        def counted(node, memo=None):
            if isinstance(node, etree._Element) and node.tag == 'Group':
                entries_copied.append(sum(1 for _ in node.iter('Entry')))
            return real_copy(node, memo)

        with monkeypatch.context() as patch:
            patch.setattr(copy, 'deepcopy', counted)
            details, archived = admission.verify(candidate, [source], group_verification=profile)
        assert details == {'retained_capsules': 0} and archived == {}
        assert (etree.tostring(source.tree), etree.tostring(candidate.tree)) == before
        assert sum(entries_copied) == 0, entries_copied
