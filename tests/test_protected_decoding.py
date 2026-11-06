"""Protected fixture bytes are synthetic; no real vault, target or account is used."""
import base64
import copy
import importlib
import io
import logging
from pathlib import Path
import subprocess

import pytest
from pykeepass import PyKeePass, create_database
from pykeepass.kdbx_parsing.common import UnprotectedStream

MASTER = 'synthetic-protected-decoding-master'
FAILURE = 'protected record fields could not be verified; merge refused'


@pytest.fixture(scope='module')
def protected_template():
    vault = create_database(io.BytesIO(), password=MASTER)
    params = vault.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    params['I'].value = 1
    params['M'].value = 1024 * 1024
    entry = vault.add_entry(vault.root_group, 'Synthetic', 'synthetic-user', 'safe-old',
                            url='https://example.test')
    entry.save_history()
    entry.password = 'safe-current'
    entry.set_custom_property('SyntheticProtectedField', 'safe-custom', protect=True)
    buffer = io.BytesIO()
    vault.save(buffer)
    return buffer.getvalue()


def protected_fixture(template, payload, placement):
    vault = PyKeePass(io.BytesIO(template), password=MASTER)

    def encode(adapter, tree, context, path):
        tree = copy.deepcopy(tree)
        cipher = adapter.get_cipher(adapter.protected_stream_key(context))
        for element in tree.xpath(adapter.protected_xpath):
            if element.text is None:
                continue
            key = element.getparent().findtext('Key')
            historical = element.getparent().getparent().getparent().tag == 'History'
            chosen = ((placement == 'custom' and key == 'SyntheticProtectedField')
                      or (key == 'Password' and ((placement == 'history' and historical)
                                                or (placement == 'active' and not historical))))
            value = payload if chosen else element.text.encode('utf-8')
            element.text = base64.b64encode(cipher.encrypt(value)).decode('ascii')
        return tree

    buffer = io.BytesIO()
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(UnprotectedStream, '_encode', encode)
        vault.save(buffer)
    return buffer.getvalue()


@pytest.mark.parametrize('package', ['akdbx', 'agentic_kdbx'])
@pytest.mark.parametrize('placement', ['active', 'history', 'custom'])
@pytest.mark.parametrize('value', ['\x00', '\x01', '\x0b', '\x0c', '\x1f', '\ufffe', '\uffff', b'\xff'])
def test_lossy_protected_fields_refused_before_adoption(
    protected_template, tmp_path, caplog, package, placement, value,
):
    payload = b'synthetic-left' + (value if isinstance(value, bytes) else value.encode()) + b'right'
    encrypted = protected_fixture(protected_template, payload, placement)
    path = tmp_path / 'synthetic.kdbx'
    path.write_bytes(encrypted)
    path.chmod(0o600)
    persistence = importlib.import_module(package + '.persistence')
    logger = logging.getLogger('pykeepass.kdbx_parsing.common')
    previous = logger.handlers, logger.propagate, logger.disabled, logger.level
    decoder = UnprotectedStream._decode
    with pytest.raises(persistence.SaveError, match=FAILURE):
        persistence.VaultStore(path).open(MASTER)
    assert path.read_bytes() == encrypted and list(tmp_path.iterdir()) == [path]
    assert UnprotectedStream._decode is decoder
    assert (logger.handlers, logger.propagate, logger.disabled, logger.level) == previous
    assert 'synthetic-left' not in caplog.text and MASTER not in caplog.text


@pytest.mark.parametrize('package', ['akdbx', 'agentic_kdbx'])
@pytest.mark.parametrize('value', ['synthetic-café-🗝️', 'synthetic\tvalue',
                                  'synthetic\nvalue', 'synthetic\rvalue'])
def test_xml_valid_protected_text_is_lossless(protected_template, package, value):
    persistence = importlib.import_module(package + '.persistence')
    decoder = UnprotectedStream._decode
    encrypted = protected_fixture(protected_template, value.encode(), 'active')
    opened = persistence.open_encrypted(encrypted, MASTER)
    assert opened.find_entries(title='Synthetic', first=True).password == value
    assert UnprotectedStream._decode is decoder


@pytest.mark.skipif(not Path('/usr/bin/keepassxc-cli').is_file(), reason='requires KeePassXC writer')
@pytest.mark.parametrize('package', ['akdbx', 'agentic_kdbx'])
def test_native_written_control_password_refused_unchanged(protected_template, tmp_path, package):
    path = tmp_path / 'native.kdbx'
    path.write_bytes(protected_template)
    path.chmod(0o600)
    value = b'synthetic-left\x0bright'
    edited = subprocess.run(['/usr/bin/keepassxc-cli', 'edit', '--quiet', '--password-prompt',
                             str(path), 'Synthetic'],
                            input=MASTER.encode() + b'\n' + value + b'\n' + value + b'\n',
                            capture_output=True, timeout=15, env={'LANG': 'C.UTF-8'})
    assert edited.returncode == 0
    shown = subprocess.run(['/usr/bin/keepassxc-cli', 'show', '--quiet', '--show-protected',
                            '--attributes', 'Password', str(path), 'Synthetic'],
                           input=(MASTER + '\n').encode(), capture_output=True,
                           timeout=15, env={'LANG': 'C.UTF-8'})
    assert shown.returncode == 0 and shown.stdout == value + b'\n'
    before = path.read_bytes()
    persistence = importlib.import_module(package + '.persistence')
    with pytest.raises(persistence.SaveError, match=FAILURE):
        persistence.VaultStore(path).open(MASTER)
    assert path.read_bytes() == before and list(tmp_path.iterdir()) == [path]
