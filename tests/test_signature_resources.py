"""Small synthetic pools prove scaling without host-dependent timing thresholds."""
from collections import Counter
import copy
from datetime import timedelta
import io

import pytest
from pykeepass import PyKeePass

from akdbx import merge, versions
from test_merge import BASE_TIME, MASTER, base


def test_signature_pool_copies_do_not_grow_with_record_count(base, monkeypatch):
    getter = PyKeePass.binaries.fget
    calls = Counter()

    def counted_pool(vault):
        calls[id(vault)] += 1
        return getter(vault)

    monkeypatch.setattr(PyKeePass, 'binaries', property(counted_pool))
    counts = {}
    for size in (2, 24):
        source = PyKeePass(io.BytesIO(base.read_bytes()), password=MASTER)
        reference = source.add_binary(b'synthetic attachment' * 1024)
        for number in range(size):
            entry = source.add_entry(source.root_group, f'Synthetic {number}', 'user', 'synthetic')
            entry.add_attachment(reference, 'document.bin')
            entry.mtime = BASE_TIME
            for revision in range(2):
                entry.save_history()
                entry.password = f'synthetic revision {revision}'
                entry.mtime = BASE_TIME + timedelta(seconds=revision + 1)
        other, candidate = copy.deepcopy(source), copy.deepcopy(source)
        calls.clear()
        merge._check_ambiguity(source, other)
        ambiguity = calls[id(source)], calls[id(other)]
        calls.clear()
        merge.verify_history(candidate, source, other)
        history = calls[id(candidate)], calls[id(source)], calls[id(other)]
        counts[size] = ambiguity, history
    assert counts[24] == counts[2], counts


def test_signature_checks_bind_attachment_bytes_and_refresh_between_operations(base):
    source = PyKeePass(io.BytesIO(base.read_bytes()), password=MASTER)
    entry = source.find_entries(title='Shared', first=True)
    entry.add_attachment(source.add_binary(b'synthetic original bytes'), 'document.bin')
    candidate = copy.deepcopy(source)
    original_signature = versions.entry_signature(entry)
    merge._check_ambiguity(source, candidate)
    merge.verify_history(candidate, source)

    source.add_binary(b'synthetic unreferenced bytes')
    assert versions.entry_signature(entry) == original_signature
    merge._check_ambiguity(source, candidate)
    entry.attachments[0].id = source.add_binary(b'synthetic changed bytes')
    assert versions.entry_signature(entry) != original_signature
    with pytest.raises(merge.MergeError, match='conflicting same-second records'):
        merge._check_ambiguity(source, candidate)
    with pytest.raises(merge.MergeError, match='discard entry history or fields'):
        merge.verify_history(candidate, source)
    merge.verify_history(copy.deepcopy(source), source)
