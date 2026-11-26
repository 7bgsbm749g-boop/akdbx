"""The Windows vault store with a key file and a hardware key response from the page."""
import io
import os

import pytest

if os.name != 'nt':
    pytest.skip('native Windows APIs required', allow_module_level=True)

from pykeepass import PyKeePass, create_database
from pykeepass.exceptions import CredentialsError

from akdbx import windows_security as security
from akdbx.persistence import SaveError, open_encrypted, serialize_encrypted
from akdbx.unlock_keys import ChallengeChanged, UnlockKeys, key_material, vault_challenge
from akdbx.windows_store import WindowsVaultStore
from test_unlock_keys import MASTER, YUBIKEY_PASSWORD, YUBIKEY_RESPONSE, YUBIKEY_SEED, YUBIKEY_VAULT
from test_windows_native import private_dir  # noqa: F401


def test_windows_store_opens_with_the_hardware_key_response(private_dir):
    path = private_dir / 'yubikey.kdbx'
    security.write_new(path, YUBIKEY_VAULT.read_bytes())
    response = bytes.fromhex(YUBIKEY_RESPONSE)
    with pytest.raises(ChallengeChanged):
        WindowsVaultStore(path).open(YUBIKEY_PASSWORD, None, UnlockKeys(challenge=b'\0' * 32, response=response))
    with pytest.raises(CredentialsError):
        WindowsVaultStore(path).open(YUBIKEY_PASSWORD, None, UnlockKeys(challenge=YUBIKEY_SEED, response=b'\0' * 20))
    vault = WindowsVaultStore(path).open(YUBIKEY_PASSWORD, None, UnlockKeys(challenge=YUBIKEY_SEED, response=response))
    assert [entry.title for entry in vault.entries] == ['Demo entry']
    saved = serialize_encrypted(vault)
    assert vault_challenge(saved) == YUBIKEY_SEED
    assert open_encrypted(saved, YUBIKEY_PASSWORD, key_material(None, response)).entries


def test_windows_store_opens_with_an_uploaded_key_file_only_when_it_has_none(private_dir):
    key = b'\x00synthetic key file\r\n' + bytes(range(256))
    vault = create_database(io.BytesIO(), password=MASTER, keyfile=io.BytesIO(key))
    params = vault.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    params['I'].value, params['M'].value = 1, 1024 * 1024
    buffer = io.BytesIO()
    vault.save(buffer)
    path, keyfile = private_dir / 'keyfile.kdbx', private_dir / 'synthetic.key'
    security.write_new(path, buffer.getvalue())
    security.write_new(keyfile, key)
    with pytest.raises(CredentialsError):
        WindowsVaultStore(path).open(MASTER, None, UnlockKeys(keyfile=b'another synthetic key'))
    opened = WindowsVaultStore(path).open(MASTER, None, UnlockKeys(keyfile=key))
    assert opened.root_group is not None
    with pytest.raises(SaveError):
        WindowsVaultStore(path).open(MASTER, keyfile, UnlockKeys(keyfile=key))
    assert PyKeePass(io.BytesIO(serialize_encrypted(opened)), password=MASTER, keyfile=io.BytesIO(key)).root_group


def test_windows_lists_hid_and_smart_card_keys_without_error():
    """hid.dll, setupapi.dll and winscard.dll through ctypes: no key on the runner, and no crash."""
    from akdbx import hardware_key
    assert hardware_key.available() in (True, False)
    assert isinstance(hardware_key._windows_devices(), list)
    with pytest.raises(hardware_key.HardwareKeyError):
        hardware_key.responses(b'\x01' * 32, timeout=1)
