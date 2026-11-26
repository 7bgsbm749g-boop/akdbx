"""Key file upload and hardware key (YubiKey challenge-response) unlock on the private page.

Only synthetic vaults and keys. ``fixtures/keepassxc-yubikey4.kdbx`` is a
KeePassXC KDBX 4 vault protected by the password ``demo`` and a YubiKey
HMAC-SHA1 challenge-response slot, from the kdbxweb test resources (MIT
licence, Copyright (C) 2021-2025 Antelle). kdbxweb's tests give the key's
response to that vault's challenge, so KeePassXC compatibility is checked
without a hardware key.
"""
from __future__ import annotations

import hashlib
import io
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest
from pykeepass import PyKeePass, create_database
from pykeepass.exceptions import CredentialsError

from akdbx import unlock_keys
from akdbx.broker import Broker
from akdbx.persistence import open_encrypted
from akdbx.unlock_keys import UnlockKeys, key_material, padded_challenge, read_challenge, vault_challenge
from akdbx.web_unlock import parse_multipart, start_unlock_server, unlock_credentials
from test_broker import RecordingTyper
from test_web_unlock import UnixHTTPConnection, call, route

FIXTURES = Path(__file__).parent / 'fixtures'
YUBIKEY_VAULT = FIXTURES / 'keepassxc-yubikey4.kdbx'
YUBIKEY_PASSWORD = 'demo'
YUBIKEY_SEED = bytes.fromhex('011ed85afa703341893596fba2da60b6cacabaa5468a0e9ea74698b901bc89ab')
YUBIKEY_RESPONSE = 'ae7244b336f3360e4669ec9eaf4ddc23785aef03'
MASTER = 'synthetic master'
BOUNDARY = '----akdbxSyntheticBoundary7MA4YWxkTrZu0gW'


def multipart(fields=(), files=(), boundary=BOUNDARY):
    body = b''
    for name, value in fields:
        body += (f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
                 + value.encode() + b'\r\n')
    for name, filename, data in files:
        body += (f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
                 'Content-Type: application/octet-stream\r\n\r\n'.encode() + data + b'\r\n')
    return body + f'--{boundary}--\r\n'.encode(), 'multipart/form-data; boundary=' + boundary


def post(socket_path, path, fields=(), files=()):
    body, content_type = multipart(fields, files)
    connection = UnixHTTPConnection(socket_path, timeout=30)
    connection.request('POST', path, body=body, headers={
        'Content-Type': content_type, 'Tailscale-User-Login': 'owner@example.test'})
    response = connection.getresponse()
    data = response.read()
    connection.close()
    return response.status, data


def private_copy(tmp_path, source, name='vault.kdbx'):
    folder = tmp_path / 'vault'
    folder.mkdir(mode=0o700)
    target = folder / name
    shutil.copyfile(source, target)
    target.chmod(0o600)
    return target


def serve(tmp_path, database, keyfile=None):
    broker = Broker(None, RecordingTyper())
    server, url = start_unlock_server(broker, database, keyfile, tmp_path / 'private' / 'unlock.sock',
                                      'https://node.example:9443')
    return broker, server, tmp_path / 'private' / 'unlock.sock', route(url)


def save_secret(broker, title='Synthetic service'):
    return broker.dispatch(dict(action='save-secret', secret_save_protocol=1, secret='synthetic-service-key',
                                metadata=dict(title=title, username='synthetic-user' if title == 'Synthetic service'
                                              else 'synthetic-user-2',
                                              url='https://service.example.test/', group='')))


def cheap_vault(path, password=MASTER, keyfile=None):
    vault = create_database(io.BytesIO(), password=password, keyfile=keyfile)
    params = vault.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    params['I'].value, params['M'].value = 1, 1024 * 1024
    vault.add_entry(vault.root_group, 'Synthetic site', 'synthetic-account', 'synthetic-site-secret')
    buffer = io.BytesIO()
    vault.save(buffer)
    path.write_bytes(buffer.getvalue())
    path.chmod(0o600)


# ----- form parsing ------------------------------------------------------------
def test_multipart_keeps_file_bytes_exact():
    data = b'\r\n--' + BOUNDARY[:-1].encode() + b'\r\n\x00\xff\r\r\n\n' + bytes(range(256))
    body, content_type = multipart([('password', 'synthetic é'), ('response', '')],
                                   [('keyfile', 'kéy.keyx', data)])
    values = parse_multipart(body, content_type)
    assert values == {'password': ['synthetic é'], 'response': [''], 'keyfile': [data]}


@pytest.mark.parametrize('mutate', [
    lambda body, ct: (body[:-4], ct),  # no closing delimiter
    lambda body, ct: (body + b'extra', ct),
    lambda body, ct: (body, 'multipart/form-data; boundary=other'),
    lambda body, ct: (body, 'multipart/form-data'),
    lambda body, ct: (body, 'multipart/form-data; boundary="bad boundaryé"'),
    lambda body, ct: (body.replace(b'Content-Disposition', b'Content-Transfer-Encoding: base64\r\nContent-Disposition', 1), ct),
    lambda body, ct: (body.replace(b'Content-Disposition: form-data; name="password"\r\n',
                                   b'Content-Disposition: form-data; name="password"\r\n'
                                   b'Content-Disposition: form-data; name="other"\r\n', 1), ct),
    lambda body, ct: (body.replace(b'form-data; name="password"', b'attachment; name="password"', 1), ct),
    lambda body, ct: (body.replace(b'"\r\n\r\n', b'"\r\n', 1), ct),
])
def test_malformed_multipart_is_rejected(mutate):
    body, content_type = mutate(*multipart([('password', MASTER)]))
    with pytest.raises(ValueError):
        parse_multipart(body, content_type)


def test_unlock_credentials_rules():
    seed = YUBIKEY_SEED.hex()
    assert unlock_credentials({'password': [MASTER]}, None) == (MASTER, None)
    # An empty file part means no key file was chosen.
    assert unlock_credentials({'password': [MASTER], 'keyfile': [b''], 'challenge': [seed],
                               'response': ['']}, None) == (MASTER, None)
    assert unlock_credentials({'password': [MASTER], 'keyfile': [b'key']}, None) == (MASTER, UnlockKeys(keyfile=b'key'))
    password, keys = unlock_credentials({'password': [MASTER], 'challenge': [seed],
                                         'response': [' AE7244B336F3360E4669EC9EAF4DDC23785AEF03 ']}, None)
    assert password == MASTER and keys == UnlockKeys(challenge=YUBIKEY_SEED, response=bytes.fromhex(YUBIKEY_RESPONSE))
    # Key material never shows in a repr, so a traceback or log cannot carry it.
    assert 'ae72' not in repr(keys) and 'synthetic-bytes' not in repr(UnlockKeys(keyfile=b'synthetic-bytes'))
    for values, keyfile in [
        # The master password is always required, also with a key file or hardware key.
        ({'password': ['']}, None),
        ({'password': ['']}, Path('/configured.key')),
        ({'password': [''], 'keyfile': [b'key']}, None),
        ({'password': [''], 'challenge': [seed], 'response': [YUBIKEY_RESPONSE]}, None),
        ({'password': [MASTER], 'keyfile': [b'key']}, Path('/configured.key')),
        ({'password': [MASTER], 'keyfile': ['text, not a file']}, None),
        ({'password': [MASTER, MASTER]}, None),
        ({}, None),
        ({'password': [MASTER], 'response': [YUBIKEY_RESPONSE]}, None),  # no challenge
        ({'password': [MASTER], 'challenge': [seed], 'response': [YUBIKEY_RESPONSE[:-2]]}, None),
        ({'password': [MASTER], 'challenge': [seed], 'response': ['zz' + YUBIKEY_RESPONSE[2:]]}, None),
        ({'password': [MASTER], 'challenge': [seed + '0'], 'response': [YUBIKEY_RESPONSE]}, None),
        ({'password': [MASTER], 'challenge': [seed, seed], 'response': [YUBIKEY_RESPONSE]}, None),
    ]:
        with pytest.raises(ValueError):
            unlock_credentials(values, keyfile)


# ----- KeePassXC compatibility ------------------------------------------------
def test_keepassxc_challenge_and_composite_key():
    assert vault_challenge(YUBIKEY_VAULT.read_bytes()) == YUBIKEY_SEED
    # KeePassXC pads the seed to 64 bytes with PKCS #7 before it sends it to the key.
    assert padded_challenge(YUBIKEY_SEED) == YUBIKEY_SEED + b'\x20' * 32
    material = key_material(None, bytes.fromhex(YUBIKEY_RESPONSE))
    assert unlock_keys.uses_hardware_key(material)
    vault = open_encrypted(YUBIKEY_VAULT.read_bytes(), YUBIKEY_PASSWORD, material)
    assert vault.root_group is not None and [e.title for e in vault.entries] == ['Demo entry']
    with pytest.raises(CredentialsError):
        open_encrypted(YUBIKEY_VAULT.read_bytes(), YUBIKEY_PASSWORD, key_material(None, b'\0' * 20))
    # A KDBX 3 vault has no supported challenge, and neither does a file that is no vault.
    assert vault_challenge((FIXTURES / 'empty-3.1.kdbx').read_bytes()) is None
    assert vault_challenge(b'not a vault') is None and read_challenge(None) is None


@pytest.mark.parametrize('keyfile', [
    b'\x01' * 32, b'ab' * 32, b'any file at all' * 9,
    b'<?xml version="1.0"?><KeyFile><Meta><Version>1.00</Version></Meta><Key><Data>'
    + __import__('base64').b64encode(b'\x07' * 32) + b'</Data></Key></KeyFile>',
])
def test_key_file_and_hardware_key_together_match_the_keepassxc_composite(keyfile):
    response = bytes.fromhex(YUBIKEY_RESPONSE)
    expected = hashlib.sha256(hashlib.sha256(MASTER.encode()).digest() + unlock_keys.keyfile_key(keyfile)
                              + hashlib.sha256(response).digest()).digest()
    from pykeepass.kdbx_parsing.common import compute_key_composite
    assert compute_key_composite(MASTER, key_material(keyfile, response)) == expected
    # Without a response the uploaded file is used as it is.
    assert compute_key_composite(MASTER, key_material(keyfile, None)) == compute_key_composite(MASTER, io.BytesIO(keyfile))


# ----- the unlock page ----------------------------------------------------------
def test_hardware_key_unlock_over_the_page_and_saves_keep_the_challenge(tmp_path):
    database = private_copy(tmp_path, YUBIKEY_VAULT)
    broker, server, socket_path, path = serve(tmp_path, database)
    try:
        status, _, page = call(socket_path, 'GET', path)
        command = 'ykman otp calculate 2 ' + padded_challenge(YUBIKEY_SEED).hex()
        assert status == 200 and command.encode() in page and b'enctype="multipart/form-data"' in page
        assert f'name="challenge" value="{YUBIKEY_SEED.hex()}"'.encode() in page
        assert b'name="response"' in page and b'name="keyfile"' in page
        assert b'<summary>Key file or hardware key</summary>' in page

        fields = [('password', YUBIKEY_PASSWORD), ('challenge', YUBIKEY_SEED.hex())]
        # A response to another challenge (the vault changed) is not a failed attempt.
        status, page = post(socket_path, path, [('password', YUBIKEY_PASSWORD), ('challenge', '00' * 32),
                                                ('response', YUBIKEY_RESPONSE)])
        assert status == 409 and b'did not count' in page and command.encode() in page
        assert broker.unlock_link.remaining() == 3
        status, page = post(socket_path, path, fields + [('response', '00' * 20)])
        assert status == 401 and b'hardware key response' in page and broker.locked
        assert broker.unlock_link.remaining() == 2 and b'00' * 20 not in page
        status, page = post(socket_path, path, fields + [('response', YUBIKEY_RESPONSE.upper())])
        assert status == 200 and b'Vault unlocked' in page and not broker.locked
        assert YUBIKEY_RESPONSE.encode() not in page
        before = database.read_bytes()
        assert save_secret(broker)['state'] == 'saved'
        after = database.read_bytes()
        # The vault the broker adopted after that save saves again with the same response.
        assert save_secret(broker, 'Second synthetic service')['state'] == 'saved'
        second = database.read_bytes()
    finally:
        server.shutdown()
        server.server_close()
    # The save keeps the challenge, so KeePassXC and the next unlock use the same key response,
    # and still rotates the master seed.
    assert vault_challenge(after) == YUBIKEY_SEED and after != before
    from pykeepass.kdbx_parsing.kdbx import KDBX
    seed = lambda data: KDBX.header.parse(data).value.dynamic_header.master_seed.data
    assert seed(after) != seed(before)
    reopened = open_encrypted(after, YUBIKEY_PASSWORD, key_material(None, bytes.fromhex(YUBIKEY_RESPONSE)))
    assert reopened.find_entries(title='Synthetic service', first=True).password == 'synthetic-service-key'
    assert vault_challenge(second) == YUBIKEY_SEED
    reopened = open_encrypted(second, YUBIKEY_PASSWORD, key_material(None, bytes.fromhex(YUBIKEY_RESPONSE)))
    assert {e.title for e in reopened.entries} >= {'Synthetic service', 'Second synthetic service'}


def keyfile_vault(tmp_path, password=MASTER):
    outside = tmp_path / 'outside'
    outside.mkdir(mode=0o700)
    keyfile = outside / 'synthetic.key'
    keyfile.write_bytes(b'\x00synthetic key file\r\n--' + bytes(range(256)))
    folder = tmp_path / 'vault'
    folder.mkdir(mode=0o700)
    database = folder / 'vault.kdbx'
    cheap_vault(database, password, str(keyfile))
    return database, keyfile


def test_uploaded_key_file_unlocks_saves_and_is_never_written(tmp_path):
    password = MASTER
    database, keyfile = keyfile_vault(tmp_path, password)
    key = keyfile.read_bytes()
    broker, server, socket_path, path = serve(tmp_path, database)
    try:
        status, _, page = call(socket_path, 'GET', path)
        assert status == 200 and b'name="keyfile" type="file"' in page
        # A KDBX 4 Argon2 vault may use a hardware key too, so that field is offered as well.
        assert b'<summary>Key file or hardware key</summary>' in page
        status, _, _ = call(socket_path, 'POST', path, urlencode({'password': password}))
        assert status == 401 and broker.locked
        # An empty password is a malformed form, even with a key file: no attempt is used.
        status, page = post(socket_path, path, [('password', '')], [('keyfile', 'synthetic.key', key)])
        assert status == 400 and broker.locked and broker.unlock_link.remaining() == 2
        status, page = post(socket_path, path, [('password', password)],
                            [('keyfile', 'wrong.key', b'another synthetic key')])
        assert status == 401 and broker.locked
        status, page = post(socket_path, path, [('password', password), ('challenge', 'aa' * 32),
                                                ('response', '')], [('keyfile', 'synthetic.key', key)])
        assert status == 200 and b'Vault unlocked' in page and not broker.locked
        assert save_secret(broker)['state'] == 'saved'
    finally:
        server.shutdown()
        server.server_close()
    reopened = PyKeePass(str(database), password=password, keyfile=str(keyfile))
    assert reopened.find_entries(title='Synthetic service', first=True).password == 'synthetic-service-key'
    # The uploaded key file exists only where the user keeps it, never next to the vault.
    holders = [p for p in tmp_path.rglob('*') if p.is_file() and key in p.read_bytes()]
    assert holders == [keyfile]


def test_broker_key_file_hides_the_upload_and_never_unlocks_without_a_password(tmp_path):
    database, keyfile = keyfile_vault(tmp_path)
    broker, server, socket_path, path = serve(tmp_path, database, keyfile)
    try:
        status, _, page = call(socket_path, 'GET', path)
        assert status == 200 and b'name="keyfile"' not in page and b'<summary>Hardware key</summary>' in page
        status, _ = post(socket_path, path, [('password', '')])
        assert status == 400 and broker.locked and broker.unlock_link.remaining() == 3
        status, _ = post(socket_path, path, [('password', MASTER)], [('keyfile', 'k.key', keyfile.read_bytes())])
        assert status == 400 and broker.locked
        status, page = post(socket_path, path, [('password', MASTER)])
        assert status == 200 and not broker.locked
    finally:
        server.shutdown()
        server.server_close()


def test_kdbx3_vault_page_offers_no_hardware_key(tmp_path):
    database = private_copy(tmp_path, FIXTURES / 'empty-3.1.kdbx')
    broker, server, socket_path, path = serve(tmp_path, database)
    try:
        status, _, page = call(socket_path, 'GET', path)
        assert status == 200 and b'<summary>Key file</summary>' in page and b'ykman' not in page
        status, page = post(socket_path, path, [('password', MASTER), ('challenge', '00' * 32),
                                                ('response', YUBIKEY_RESPONSE)])
        assert status == 409 and broker.unlock_link.remaining() == 3
    finally:
        server.shutdown()
        server.server_close()


def _keepassxc_cli():
    cli = Path('/usr/bin/keepassxc-cli')
    if not cli.is_file():
        pytest.skip('requires keepassxc-cli')
    return cli


def test_keepassxc_key_file_vault_unlocks_by_upload_and_stays_readable_by_keepassxc(tmp_path):
    cli = _keepassxc_cli()
    folder = tmp_path / 'vault'
    folder.mkdir(mode=0o700)
    outside = tmp_path / 'outside'
    outside.mkdir(mode=0o700)
    database, keyfile = folder / 'vault.kdbx', outside / 'vault.key'
    subprocess.run([cli, 'db-create', '-q', '-p', '-t', '100', '--set-key-file', keyfile, database],
                   input=f'{MASTER}\n{MASTER}\n'.encode(), check=True, timeout=120,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    database.chmod(0o600)
    broker, server, socket_path, path = serve(tmp_path, database)
    try:
        status, page = post(socket_path, path, [('password', MASTER)],
                            [('keyfile', 'vault.key', keyfile.read_bytes())])
        assert status == 200 and not broker.locked
        assert save_secret(broker)['state'] == 'saved'
    finally:
        server.shutdown()
        server.server_close()
    listed = subprocess.run([cli, 'show', '-q', '-a', 'UserName', '-k', keyfile, database, 'Synthetic service'],
                            input=f'{MASTER}\n'.encode(), capture_output=True, check=True, timeout=120)
    assert listed.stdout.strip() == b'synthetic-user'


# ----- the pairing page ---------------------------------------------------------
def test_locked_pairing_page_unlocks_with_an_uploaded_key_file():
    from test_extension_route import PageHandler, attach, make_broker
    from akdbx.extension_web import handle_pairing
    from akdbx.web_unlock import UnlockState
    vault = SimpleNamespace(entries=[], password=MASTER)
    broker = make_broker(locked=True)
    channel, _ = attach(broker, {}, paired=False)
    path = '/extension/pair?token=' + broker.extension._pairing_info(channel.digest)['url'].split('token=')[1]
    seen = []

    def opener(_database, password, _keyfile, keys=None):
        seen.append((password, keys))
        if keys is None or keys.keyfile != b'synthetic key':
            raise CredentialsError('synthetic failure')
        return vault
    state = UnlockState(broker, None, None, opener)
    page = PageHandler(path)
    handle_pairing(page, state)
    assert page.sent[0][0] == 200 and 'name="keyfile" type="file"' in page.sent[0][1]
    assert 'enctype="multipart/form-data"' in page.sent[0][1]
    body, content_type = multipart([('password', MASTER), ('confirmed', 'yes')], [('keyfile', 'k', b'synthetic key')])
    page = PageHandler(path, 'POST', body)
    page.headers['Content-Type'] = content_type
    assert handle_pairing(page, state) and page.sent[0][0] == 200
    assert seen == [(MASTER, UnlockKeys(keyfile=b'synthetic key'))]
    assert not broker.locked
