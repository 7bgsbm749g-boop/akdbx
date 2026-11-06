"""Small synthetic fixtures measure redundant copying without timing thresholds."""
from collections import Counter
import copy
from datetime import timedelta
import io

from lxml import etree
import pytest
from pykeepass import PyKeePass

from akdbx import admission, selection, versions
from test_merge import BASE_TIME, MASTER, base


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
