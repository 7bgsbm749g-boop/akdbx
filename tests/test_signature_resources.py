"""Small synthetic pools prove scaling without host-dependent timing thresholds."""
from collections import Counter
import copy
from datetime import timedelta
import io

import pytest
from pykeepass import PyKeePass

from akdbx import merge, versions
from test_merge import BASE_TIME, MASTER, base, pair


def test_preservation_preflight_does_not_build_unused_signatures(base, monkeypatch):
    """Preservation still checks UUIDs/archives without constructing conflict signatures."""
    getter, signature = PyKeePass.binaries.fget, merge._entry_signature
    calls = Counter()

    def pool(vault):
        calls['pool'] += 1
        return getter(vault)

    def record(*args, **kwargs):
        calls['signature'] += 1
        return signature(*args, **kwargs)

    for size in (2, 24):
        source = PyKeePass(io.BytesIO(base.read_bytes()), password=MASTER)
        source.add_binary(b'synthetic unreferenced pool' * 2048)
        for index in range(size):
            entry = source.add_entry(source.root_group, f'Synthetic {index}', 'synthetic', 'synthetic')
            entry.mtime = BASE_TIME
            entry.save_history()
        calls.clear()
        with monkeypatch.context() as patch:
            patch.setattr(PyKeePass, 'binaries', property(pool))
            patch.setattr(merge, '_entry_signature', record)
            merge._check_ambiguity(source, preserve=True)
        assert not calls, (size, calls)


@pytest.mark.parametrize('damage', ['timestamp', 'attachment'])
def test_preservation_capture_refuses_malformed_records_before_native_engine(pair, monkeypatch, damage):
    """Skipping unused signatures must retain capture's validation before native code."""
    broker, target, source = pair
    incoming = PyKeePass(source, password=MASTER)
    entry = incoming.find_entries(title='Shared', first=True)
    if damage == 'timestamp':
        entry._element.find('Times/LastModificationTime').text = 'synthetic invalid timestamp'
    else:
        entry.add_attachment(999, 'synthetic missing binary')
    incoming.save(source)
    before = target.read_bytes(), source.read_bytes()
    calls = []

    def forbidden_engine(*args, **kwargs):
        calls.append(True)
        raise AssertionError('malformed input reached the native engine')

    monkeypatch.setattr(merge, 'run_engine', forbidden_engine)
    import uuid
    result = broker.dispatch(dict(action='merge', source=str(source), check=True,
                                  preserve_conflicts=True, operation_id=uuid.uuid4().hex))
    assert not result['ok'] and result['state'] == 'failed', result
    assert not calls and (target.read_bytes(), source.read_bytes()) == before


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
