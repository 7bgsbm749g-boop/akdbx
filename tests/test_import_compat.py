"""Exercise both supported import names with private, synthetic encrypted vaults."""
from __future__ import annotations

import base64
import copy
import importlib
import io
import logging
from pathlib import Path
import subprocess
import sys
import threading

import pytest
import pykeepass
from pykeepass.kdbx_parsing.common import UnprotectedStream

MASTER = 'synthetic-mixed-import-master'


@pytest.fixture(scope='module')
def encrypted_files(tmp_path_factory):
    directory = tmp_path_factory.mktemp('mixed-import-vaults')
    vault = pykeepass.create_database(io.BytesIO(), password=MASTER)
    params = vault.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    params['I'].value = 1
    params['M'].value = 1024 * 1024
    vault.add_entry(vault.root_group, 'Synthetic', 'synthetic-user', 'synthetic-value')
    valid, invalid = directory / 'valid.kdbx', directory / 'invalid.kdbx'
    vault.save(valid)

    def corrupt_password(self, tree, context, path):
        tree = copy.deepcopy(tree)
        cipher = self.get_cipher(self.protected_stream_key(context))
        for element in tree.xpath(self.protected_xpath):
            if element.text is not None:
                value = (b'\xff' if element.getparent().findtext('Key') == 'Password'
                         else element.text.encode('utf-8'))
                element.text = base64.b64encode(cipher.encrypt(value)).decode('ascii')
        return tree

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(UnprotectedStream, '_encode', corrupt_password)
        vault.save(invalid)
    for path in (valid, invalid):
        path.chmod(0o600)
    return valid, invalid


def mixed_import_probe(first, invalid_name, valid_path, invalid_path):
    """Use fresh modules and real decoder results; control only the call schedule."""
    names = [first, 'agentic_kdbx' if first == 'akdbx' else 'akdbx']
    modules = {name: importlib.import_module(name + '.persistence') for name in names}
    openers = {name: importlib.import_module(name + '.broker').open_vault_with_password
               for name in names}
    valid, invalid = Path(valid_path), Path(invalid_path)

    def opened(name, path):
        try:
            vault = openers[name](path, MASTER)
        except modules[name].SaveError:
            return 'refused'
        assert vault._akdbx_store.verified_encrypted == path.read_bytes()
        return 'accepted'

    for name in names:
        assert opened(name, valid) == 'accepted'
        assert opened(name, invalid) == 'refused'
    logger = logging.getLogger('pykeepass.kdbx_parsing.common')
    previous = logger.handlers, logger.propagate, logger.disabled, logger.level
    invalid_entered, valid_entered = threading.Event(), threading.Event()
    attempted, release_invalid, invalid_finished = (threading.Event() for _ in range(3))
    blocked = []
    outcomes, failures = {}, []

    class ObservedGuard:
        """Preserve the actual lock while observing whether the second open blocks."""
        def __init__(self, lock):
            self.lock = lock

        def __enter__(self):
            acquired = self.lock.acquire(False)
            if threading.current_thread().name == 'valid-open':
                blocked.append(not acquired)
                attempted.set()
            if not acquired:
                self.lock.acquire()
            return self

        def __exit__(self, *args):
            self.lock.release()

    real_constructor = pykeepass.PyKeePass
    invalid_bytes = invalid.read_bytes()

    def scheduled_constructor(stream, *args, **kwargs):
        if stream.getvalue() == invalid_bytes:
            invalid_entered.set()
            assert release_invalid.wait(5)
        else:
            valid_entered.set()
            assert invalid_finished.wait(5)
        return real_constructor(stream, *args, **kwargs)

    def worker(name, path, label):
        try:
            outcomes[label] = opened(name, path)
        except BaseException as exc:
            failures.append(type(exc).__name__)
        finally:
            if label == 'invalid':
                invalid_finished.set()

    valid_name = next(name for name in names if name != invalid_name)
    bad = threading.Thread(target=worker, args=(invalid_name, invalid, 'invalid'), name='invalid-open')
    good = threading.Thread(target=worker, args=(valid_name, valid, 'valid'), name='valid-open')
    try:
        with pytest.MonkeyPatch.context() as patch:
            for module in modules.values():
                patch.setattr(module, '_OPEN_LOCK', ObservedGuard(module._OPEN_LOCK))
            patch.setattr(pykeepass, 'PyKeePass', scheduled_constructor)
            bad.start()
            assert invalid_entered.wait(5)
            good.start()
            assert attempted.wait(5)
            if not blocked[0]:
                assert valid_entered.wait(5)
            release_invalid.set()
            bad.join(6)
            good.join(6)
            assert not bad.is_alive() and not good.is_alive()
        assert not failures, failures
        assert outcomes == {'invalid': 'refused', 'valid': 'accepted'}, outcomes
        assert (logger.handlers, logger.propagate, logger.disabled, logger.level) == previous
    finally:
        release_invalid.set()
        for thread in (bad, good):
            if thread.ident is not None:
                thread.join(6)
        logger.handlers, logger.propagate, logger.disabled, level = previous
        logger.setLevel(level)


@pytest.mark.parametrize('first', ['akdbx', 'agentic_kdbx'])
@pytest.mark.parametrize('invalid_name', ['akdbx', 'agentic_kdbx'])
def test_mixed_import_opens_keep_protected_field_checks_isolated(encrypted_files, first, invalid_name):
    valid, invalid = encrypted_files
    result = subprocess.run([sys.executable, str(Path(__file__).resolve()), first,
                             invalid_name, str(valid), str(invalid)],
                            capture_output=True, text=True, timeout=40)
    assert result.returncode == 0, result.stderr


if __name__ == '__main__':
    mixed_import_probe(*sys.argv[1:])
