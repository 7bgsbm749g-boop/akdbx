"""Key file and hardware key unlock on the private page, with and without a master password.

Only synthetic vaults and keys, built in-house. ``fixtures/hardware-key-kdbx4.kdbx``
is a KDBX 4 vault from another KeePass app, protected by the password ``demo``
and a hardware key; its README names the source and the key's known response,
so the composite key format is checked against a vault akdbx did not write.
Hardware keys here are a replaced ``hardware_key.responses``, or the virtual
USB key of ``virtual_hardware_key`` on Linux.
"""
from __future__ import annotations

import base64
import sys
import hashlib
import hmac
import io
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest
from pykeepass import PyKeePass, create_database
from pykeepass.exceptions import CredentialsError

from akdbx import hardware_key, unlock_keys
from akdbx.broker import Broker
from akdbx.persistence import open_encrypted
from akdbx.unlock_keys import UnlockKeys, key_material, read_challenge, vault_challenge
from akdbx.web_unlock import parse_multipart, start_unlock_server, unlock_credentials
from test_broker import RecordingTyper
from test_web_unlock import UnixHTTPConnection, call, route
if sys.platform == 'linux':
    from test_hardware_key import virtual_key  # noqa: F401  (fixture)

FIXTURES = Path(__file__).parent / 'fixtures'
YUBIKEY_VAULT = FIXTURES / 'hardware-key-kdbx4.kdbx'
YUBIKEY_PASSWORD = 'demo'
YUBIKEY_SEED = bytes.fromhex('011ed85afa703341893596fba2da60b6cacabaa5468a0e9ea74698b901bc89ab')
YUBIKEY_RESPONSE = 'ae7244b336f3360e4669ec9eaf4ddc23785aef03'
MASTER = 'synthetic master'
SECRET = bytes(range(20))
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
    connection = UnixHTTPConnection(socket_path, timeout=40)
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
                                metadata=dict(title=title, username='synthetic-user-' + str(len(title)),
                                              url='https://service.example.test/', group='')))


def cheap(vault):
    params = vault.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    params['I'].value, params['M'].value = 1, 1024 * 1024
    vault.add_entry(vault.root_group, 'Synthetic site', 'synthetic-account', 'synthetic-site-secret')
    return params


def key_response(seed, secret=SECRET):
    """What a key in variable-input mode answers: HMAC-SHA1 of the challenge without its padding."""
    return hmac.new(secret, seed, hashlib.sha1).digest()


def hardware_vault(path, password=MASTER, keyfile=None, secret=SECRET):
    """A KDBX 4 vault protected by a hardware key with ``secret`` (and the password and key file)."""
    from pykeepass.kdbx_parsing.kdbx import KDBX
    vault = create_database(io.BytesIO(), password=password or 'unused')
    params = cheap(vault)
    material = key_material(keyfile, key_response(params['S'].value, secret))
    path.write_bytes(KDBX.build(vault.kdbx, password=password, keyfile=material, transformed_key=None,
                                decrypt=True))
    path.chmod(0o600)


def keyfile_vault(tmp_path, password=MASTER):
    outside = tmp_path / 'outside'
    outside.mkdir(mode=0o700)
    keyfile = outside / 'synthetic.key'
    keyfile.write_bytes(b'\x00synthetic key file\r\n--' + bytes(range(256)))
    folder = tmp_path / 'vault'
    folder.mkdir(mode=0o700)
    database = folder / 'vault.kdbx'
    vault = create_database(io.BytesIO(), password=password, keyfile=str(keyfile))
    cheap(vault)
    vault.save(database)
    database.chmod(0o600)
    return database, keyfile


@pytest.fixture
def broker_key(monkeypatch):
    """The broker's own computer has one key; ``state`` records what the page made it ask."""
    state = SimpleNamespace(asked=[], here=True, secret=SECRET, error=None, answers=None)

    def responses(seed, **_):
        state.asked.append(seed)
        if state.error is not None:
            raise state.error
        return list(state.answers) if state.answers is not None else [key_response(seed, state.secret)]
    monkeypatch.setattr(hardware_key, 'available', lambda: state.here)
    monkeypatch.setattr(hardware_key, 'responses', responses)
    return state


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
    answer = bytes.fromhex(YUBIKEY_RESPONSE)
    assert unlock_credentials({'password': [MASTER]}, None) == (MASTER, None)
    # An empty file part means no key file; a challenge without the hardware key is ignored.
    assert unlock_credentials({'password': [MASTER], 'keyfile': [b''], 'challenge': [seed]}, None) == (MASTER, None)
    assert unlock_credentials({'password': [MASTER], 'keyfile': [b'key']}, None) == (MASTER, UnlockKeys(keyfile=b'key'))
    # The hardware key without responses asks the broker's own key.
    assert unlock_credentials({'password': [MASTER], 'hardware': ['on'], 'challenge': [seed]}, None) == (
        MASTER, UnlockKeys(broker_key=True))
    # Responses from the browsing computer's key, with the challenge they answer.
    password, keys = unlock_credentials({'password': [MASTER], 'hardware': ['on'], 'challenge': [seed],
                                         'response': [' ' + YUBIKEY_RESPONSE.upper() + ' ', '00' * 20]}, None)
    assert password == MASTER and keys == UnlockKeys(challenge=YUBIKEY_SEED, responses=(answer, bytes(20)))
    # A vault with no master password: a key that the page brings.
    assert unlock_credentials({'password': [''], 'keyfile': [b'key']}, None) == (None, UnlockKeys(keyfile=b'key'))
    assert unlock_credentials({'password': [''], 'hardware': ['on'], 'challenge': [seed],
                               'response': [YUBIKEY_RESPONSE]}, Path('/configured.key')) == (
        None, UnlockKeys(challenge=YUBIKEY_SEED, responses=(answer,)))
    assert unlock_credentials({'password': [''], 'hardware': ['on'], 'keyfile': [b'key']}, None) == (
        None, UnlockKeys(keyfile=b'key', broker_key=True))
    # Key material never shows in a repr, so a traceback or log cannot carry it.
    assert YUBIKEY_RESPONSE not in repr(keys) and 'synthetic-bytes' not in repr(UnlockKeys(keyfile=b'synthetic-bytes'))
    for values, keyfile in [
        ({'password': ['']}, None),
        # Keys on the broker's computer never replace the password: the link alone opens nothing.
        ({'password': ['']}, Path('/configured.key')),
        ({'password': [''], 'hardware': ['on']}, None),
        ({'password': [''], 'hardware': ['on']}, Path('/configured.key')),
        ({'password': [MASTER], 'keyfile': [b'key']}, Path('/configured.key')),
        ({'password': [MASTER], 'keyfile': ['text, not a file']}, None),
        ({'password': [MASTER, MASTER]}, None),
        ({}, None),
        ({'password': [MASTER], 'hardware': ['yes']}, None),
        ({'password': [MASTER], 'challenge': [seed], 'response': [YUBIKEY_RESPONSE]}, None),  # no hardware field
        ({'password': [MASTER], 'hardware': ['on'], 'response': [YUBIKEY_RESPONSE]}, None),  # no challenge
        ({'password': [MASTER], 'hardware': ['on'], 'challenge': [seed], 'response': [YUBIKEY_RESPONSE[:-2]]}, None),
        ({'password': [MASTER], 'hardware': ['on'], 'challenge': [seed], 'response': ['zz' + YUBIKEY_RESPONSE[2:]]}, None),
        ({'password': [MASTER], 'hardware': ['on'], 'challenge': [seed + '0'], 'response': [YUBIKEY_RESPONSE]}, None),
        ({'password': [MASTER], 'hardware': ['on'], 'challenge': [seed], 'response': [YUBIKEY_RESPONSE] * 5}, None),
    ]:
        with pytest.raises(ValueError):
            unlock_credentials(values, keyfile)


# ----- the composite key ---------------------------------------------------------
def test_challenge_and_composite_key_match_a_vault_from_another_app():
    assert vault_challenge(YUBIKEY_VAULT.read_bytes()) == YUBIKEY_SEED
    # The key gets the seed with PKCS #7 padding to 64 bytes.
    assert hardware_key.padded(YUBIKEY_SEED) == YUBIKEY_SEED + b'\x20' * 32
    material = key_material(None, bytes.fromhex(YUBIKEY_RESPONSE))
    assert unlock_keys.uses_hardware_key(material)
    vault = open_encrypted(YUBIKEY_VAULT.read_bytes(), YUBIKEY_PASSWORD, material)
    assert [e.title for e in vault.entries] == ['Demo entry']
    with pytest.raises(CredentialsError):
        open_encrypted(YUBIKEY_VAULT.read_bytes(), YUBIKEY_PASSWORD, key_material(None, b'\0' * 20))
    # A KDBX 3 vault has no supported challenge, and neither does a file that is no vault.
    assert vault_challenge((FIXTURES / 'empty-3.1.kdbx').read_bytes()) is None
    assert vault_challenge(b'not a vault') is None and read_challenge(None) is None


@pytest.mark.parametrize('keyfile', [
    b'\x01' * 32, b'ab' * 32, b'any file at all' * 9,
    b'<?xml version="1.0"?><KeyFile><Meta><Version>1.00</Version></Meta><Key><Data>'
    + base64.b64encode(b'\x07' * 32) + b'</Data></Key></KeyFile>',
])
def test_key_file_and_hardware_key_together_give_the_standard_composite(keyfile):
    from pykeepass.kdbx_parsing.common import compute_key_composite
    response = bytes.fromhex(YUBIKEY_RESPONSE)
    expected = hashlib.sha256(hashlib.sha256(MASTER.encode()).digest() + unlock_keys.keyfile_key(keyfile)
                              + hashlib.sha256(response).digest()).digest()
    assert compute_key_composite(MASTER, key_material(keyfile, response)) == expected
    assert compute_key_composite(MASTER, key_material(keyfile, None)) == compute_key_composite(MASTER, io.BytesIO(keyfile))


@pytest.mark.parametrize('data', [
    b'a_b' + b'ab' * 30 + b'a',  # int(x, 16) accepts an underscore between digits
    b'ab' * 31 + b'a\n',  # and surrounding whitespace
    b' ' + b'ab' * 31 + b'a',
])
def test_a_64_byte_file_that_is_not_all_hex_digits_is_hashed(data):
    assert len(data) == 64 and unlock_keys.keyfile_key(data) == hashlib.sha256(data).digest()


def test_key_file_entities_are_never_resolved(tmp_path):
    """An uploaded key file is untrusted XML: no DTD, entity or network access."""
    secret = tmp_path / 'local-secret.txt'
    secret.write_text('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff')
    data = (f'<?xml version="1.0"?><!DOCTYPE KeyFile [<!ENTITY x SYSTEM "file://{secret}">]>'
            '<KeyFile><Meta><Version>1.0</Version></Meta><Key><Data>&x;</Data></Key></KeyFile>').encode()
    assert unlock_keys.keyfile_key(data) == hashlib.sha256(data).digest()
    material = key_material(data, None).getvalue()
    assert b'DOCTYPE' not in material and b'ENTITY' not in material


# ----- the unlock page: hardware key -----------------------------------------------
def test_page_wording_names_no_product_or_tool(tmp_path, broker_key):
    database = private_copy(tmp_path, YUBIKEY_VAULT)
    for here in (True, False):
        broker_key.here = here
        (tmp_path / str(here)).mkdir(mode=0o700)
        broker, server, socket_path, path = serve(tmp_path / str(here), database)
        try:
            status, _, page = call(socket_path, 'GET', path)
        finally:
            server.shutdown()
            server.server_close()
        text = page.decode()
        text = text[text.index('<section class="sheet"'):text.index('</section>')]  # what the user reads
        assert status == 200 and 'Use my hardware key' in text and 'enctype="multipart/form-data"' in text
        assert f'data-hardware-challenge="{YUBIKEY_SEED.hex()}"' in text
        assert f'data-hardware-route="{"broker" if here else "extension"}"' in text
        for word in ('KeePassXC', 'keepassxc', 'ykman', 'YubiKey', 'Yubico', 'command', 'Command'):
            assert word not in text
    assert broker_key.asked == []  # Rendering the page never talks to a key.


def test_broker_key_unlocks_saves_keep_the_challenge_and_reopen(tmp_path, broker_key):
    database = private_copy(tmp_path, YUBIKEY_VAULT)
    right = bytes.fromhex(YUBIKEY_RESPONSE)
    broker_key.answers = [bytes(20), right]  # slot 2 of one key, then the right one
    broker, server, socket_path, path = serve(tmp_path, database)
    try:
        status, page = post(socket_path, path, [('password', YUBIKEY_PASSWORD), ('hardware', 'on'),
                                                ('challenge', YUBIKEY_SEED.hex())])
        # The first response is wrong and the second right: one attempt, unlocked.
        assert status == 200 and b'Vault unlocked' in page and not broker.locked
        assert broker_key.asked == [YUBIKEY_SEED]
        before = database.read_bytes()
        assert save_secret(broker)['state'] == 'saved'
        after = database.read_bytes()
        assert save_secret(broker, 'Second synthetic service')['state'] == 'saved'
        second = database.read_bytes()
    finally:
        server.shutdown()
        server.server_close()
    from pykeepass.kdbx_parsing.kdbx import KDBX

    def seed(data):
        return KDBX.header.parse(data).value.dynamic_header.master_seed.data
    # The challenge stays, so the same key opens the vault in akdbx and other apps; the master seed changes.
    assert vault_challenge(after) == vault_challenge(second) == YUBIKEY_SEED and seed(after) != seed(before)
    reopened = open_encrypted(second, YUBIKEY_PASSWORD, key_material(None, right))
    assert {e.title for e in reopened.entries} >= {'Synthetic service', 'Second synthetic service'}


def test_broker_key_problems_never_use_an_attempt(tmp_path, broker_key):
    database = private_copy(tmp_path, YUBIKEY_VAULT)
    broker, server, socket_path, path = serve(tmp_path, database)
    fields = [('password', YUBIKEY_PASSWORD), ('hardware', 'on')]
    try:
        for error, text in [(hardware_key.NoHardwareKey(), b'found no hardware key on'),
                            (hardware_key.TouchTimeout(), b'was not touched in time'),
                            (hardware_key.HardwareKeyError('the hardware key has no challenge-response slot set up'),
                             b'did not answer')]:
            broker_key.error = error
            status, page = post(socket_path, path, fields)
            assert status == 409 and text in page and b'did not count' in page
            assert b'<details class="unlock-keys" open>' in page
        assert broker.unlock_link.remaining() == 3 and broker.locked
        broker_key.error = None
        broker_key.secret = b'\x02' * 20  # another key: a real failed attempt
        status, page = post(socket_path, path, fields)
        assert status == 401 and b'hardware key' in page and broker.unlock_link.remaining() == 2
    finally:
        server.shutdown()
        server.server_close()


def test_browsing_computer_responses_and_a_stale_challenge(tmp_path, broker_key):
    database = private_copy(tmp_path, YUBIKEY_VAULT)
    broker, server, socket_path, path = serve(tmp_path, database)
    try:
        status, page = post(socket_path, path, [('password', YUBIKEY_PASSWORD), ('hardware', 'on'),
                                                ('challenge', '00' * 32), ('response', YUBIKEY_RESPONSE)])
        assert status == 409 and b'did not count' in page and broker.unlock_link.remaining() == 3
        status, page = post(socket_path, path, [('password', YUBIKEY_PASSWORD), ('hardware', 'on'),
                                                ('challenge', YUBIKEY_SEED.hex()), ('response', '00' * 20),
                                                ('response', YUBIKEY_RESPONSE)])
        assert status == 200 and not broker.locked and YUBIKEY_RESPONSE.encode() not in page
        # Responses from the page: the broker's own key was never asked.
        assert broker_key.asked == []
    finally:
        server.shutdown()
        server.server_close()


def test_vault_without_master_password_needs_a_key_from_the_page(tmp_path, broker_key):
    """The broker's own key never replaces the master password; a key the page brings does."""
    folder = tmp_path / 'vault'
    folder.mkdir(mode=0o700)
    database = folder / 'vault.kdbx'
    hardware_vault(database, password=None)
    seed = vault_challenge(database.read_bytes())
    broker, server, socket_path, path = serve(tmp_path, database)
    try:
        # The link alone, with the key on the broker's computer: refused, no attempt used, key never asked.
        status, _ = post(socket_path, path, [('password', ''), ('hardware', 'on')])
        assert status == 400 and broker.locked and broker.unlock_link.remaining() == 3 and broker_key.asked == []
        # Responses from the browsing computer's key.
        status, page = post(socket_path, path, [('password', ''), ('hardware', 'on'), ('challenge', seed.hex()),
                                                ('response', key_response(seed).hex())])
        assert status == 200 and b'Vault unlocked' in page and not broker.locked
        assert save_secret(broker)['state'] == 'saved'
    finally:
        server.shutdown()
        server.server_close()
    data = database.read_bytes()
    reopened = open_encrypted(data, None, key_material(None, key_response(vault_challenge(data))))
    assert reopened.find_entries(title='Synthetic service', first=True) is not None


def test_vault_without_master_password_with_an_uploaded_key_file_may_use_the_broker_key(tmp_path, broker_key):
    folder = tmp_path / 'vault'
    folder.mkdir(mode=0o700)
    database = folder / 'vault.kdbx'
    key = b'synthetic key file'
    hardware_vault(database, password=None, keyfile=key)
    broker, server, socket_path, path = serve(tmp_path, database)
    try:
        status, page = post(socket_path, path, [('password', ''), ('hardware', 'on')], [('keyfile', 'k.key', key)])
        assert status == 200 and not broker.locked and len(broker_key.asked) == 1
    finally:
        server.shutdown()
        server.server_close()


def route_checked(page):
    import re
    match = re.search(rb'<input type="radio" name="hardware_route" value="(\w+)" data-route="\w+" checked>', page)
    return match.group(1).decode() if match else None


def test_both_routes_stay_selectable_and_only_a_missing_key_moves_the_choice(tmp_path, broker_key):
    database = private_copy(tmp_path, YUBIKEY_VAULT)
    broker, server, socket_path, path = serve(tmp_path, database)
    fields = [('password', YUBIKEY_PASSWORD), ('hardware', 'on'), ('hardware_route', 'broker')]
    try:
        status, _, page = call(socket_path, 'GET', path)
        assert b'data-hardware-route="broker"' in page and route_checked(page) == 'broker'
        assert b'Plugged into this computer (akdbx extension)' in page
        # A late touch or a wrong key/password keeps the broker's key first: the user retries there.
        broker_key.error = hardware_key.TouchTimeout()
        status, page = post(socket_path, path, fields)
        assert status == 409 and route_checked(page) == 'broker'
        broker_key.error, broker_key.secret = None, b'\x03' * 20
        status, page = post(socket_path, path, fields)
        assert status == 401 and route_checked(page) == 'broker'
        # No usable key on the broker's computer: this computer's key comes first, the broker's stays offered.
        broker_key.error = hardware_key.HardwareKeyError('the hardware key has no challenge-response slot set up')
        status, page = post(socket_path, path, fields)
        assert status == 409 and route_checked(page) == 'browser' and b'value="broker"' in page
    finally:
        server.shutdown()
        server.server_close()


def test_an_empty_key_file_does_not_replace_the_password(tmp_path, broker_key):
    """A key file that decodes to no key adds nothing: it cannot stand in for the user's key."""
    empty = (b'<?xml version="1.0"?><KeyFile><Meta><Version>2.0</Version></Meta><Key><Data Hash="'
             + hashlib.sha256(b'').digest()[:4].hex().upper().encode() + b'"> </Data></Key></KeyFile>')
    assert unlock_keys.keyfile_key(empty) == b''
    with pytest.raises(ValueError):
        unlock_credentials({'password': [''], 'hardware': ['on'], 'keyfile': [empty]}, None)
    with pytest.raises(ValueError):
        unlock_credentials({'password': [''], 'keyfile': [empty]}, None)
    # With a password it is only a (useless) extra key, as in other KeePass apps.
    assert unlock_credentials({'password': [MASTER], 'keyfile': [empty]}, None)[0] == MASTER


def test_page_carries_the_broker_identity_for_the_extension(tmp_path, broker_key):
    import json
    from akdbx import broker_identity
    database = private_copy(tmp_path, YUBIKEY_VAULT)
    broker, server, socket_path, path = serve(tmp_path, database)
    try:
        identity = broker_identity.IdentityStore(tmp_path / 'identity').announce('https://node.example:9443')
        broker.extension.set_identity(identity)
        broker_key.here = False
        status, _, page = call(socket_path, 'GET', path)
    finally:
        server.shutdown()
        server.server_close()
    import html as html_lib
    import re
    attribute = re.search(rb'data-hardware-identity="([^"]*)"', page).group(1).decode()
    assert json.loads(html_lib.unescape(attribute)) == identity.message()
    # A fresh signature by the same key for this page's challenge: a copied public statement proves nothing.
    proof = json.loads(html_lib.unescape(re.search(rb'data-hardware-proof="([^"]*)"', page).group(1).decode()))
    statement = proof['statement']
    assert statement['challenge'] == YUBIKEY_SEED.hex() and statement['key_id'] == identity.key_id
    assert statement['origin'] == identity.origin and statement['type'] == 'akdbx-hardware'
    import time
    assert abs(statement['issued'] - time.time()) < 60
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from akdbx.broker_identity import _unb64url, canonical_bytes
    raw = _unb64url(proof['signature'])
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), _unb64url(identity.public_key))
    key.verify(encode_dss_signature(int.from_bytes(raw[:32], 'big'), int.from_bytes(raw[32:], 'big')),
               canonical_bytes(statement), ec.ECDSA(hashes.SHA256()))


def test_kdbx3_vault_page_offers_no_hardware_key(tmp_path, broker_key):
    database = private_copy(tmp_path, FIXTURES / 'empty-3.1.kdbx')
    broker, server, socket_path, path = serve(tmp_path, database)
    try:
        status, _, page = call(socket_path, 'GET', path)
        assert status == 200 and b'<summary>Key file</summary>' in page and b'name="hardware"' not in page
        status, page = post(socket_path, path, [('password', MASTER), ('hardware', 'on')])
        assert status == 409 and broker.unlock_link.remaining() == 3
    finally:
        server.shutdown()
        server.server_close()


# ----- the unlock page: key file ---------------------------------------------------
@pytest.mark.parametrize('password', [MASTER, None])
def test_uploaded_key_file_unlocks_saves_and_is_never_written(tmp_path, password):
    database, keyfile = keyfile_vault(tmp_path, password)
    key = keyfile.read_bytes()
    broker, server, socket_path, path = serve(tmp_path, database)
    try:
        status, _, page = call(socket_path, 'GET', path)
        assert status == 200 and b'name="keyfile" type="file"' in page
        status, page = post(socket_path, path, [('password', password or '')],
                            [('keyfile', 'wrong.key', b'another synthetic key')])
        assert status == 401 and broker.locked
        status, page = post(socket_path, path, [('password', password or '')],
                            [('keyfile', 'synthetic.key', key)])
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


def test_broker_key_file_hides_the_upload_and_never_unlocks_without_a_password(tmp_path, broker_key):
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


def test_a_64_byte_non_hex_key_file_vault_unlocks_by_upload(tmp_path):
    folder = tmp_path / 'vault'
    folder.mkdir(mode=0o700)
    database = folder / 'vault.kdbx'
    key = b'a_b' + b'ab' * 30 + b'a'
    # Other KeePass apps hash such a file: the vault's key is its SHA-256.
    vault = create_database(io.BytesIO(), password=MASTER, keyfile=io.BytesIO(hashlib.sha256(key).digest()))
    cheap(vault)
    vault.save(database)
    database.chmod(0o600)
    broker, server, socket_path, path = serve(tmp_path, database)
    try:
        status, _ = post(socket_path, path, [('password', MASTER)], [('keyfile', 'vault.key', key)])
        assert status == 200 and not broker.locked
    finally:
        server.shutdown()
        server.server_close()


# ----- the pairing page ---------------------------------------------------------
def pairing(locked=True):
    from test_extension_route import attach, make_broker
    broker = make_broker(locked=locked)
    channel, _ = attach(broker, {}, paired=False)
    return broker, '/extension/pair?token=' + broker.extension._pairing_info(channel.digest)['url'].split('token=')[1]


def pair(path, state, fields, files=()):
    from test_extension_route import PageHandler
    from akdbx.extension_web import handle_pairing
    body, content_type = multipart(fields, files)
    page = PageHandler(path, 'POST', body)
    page.headers['Content-Type'] = content_type
    assert handle_pairing(page, state)
    return page.sent[0]


def test_locked_pairing_page_unlocks_with_an_uploaded_key_file_and_no_password():
    from test_extension_route import PageHandler
    from akdbx.extension_web import handle_pairing
    from akdbx.web_unlock import UnlockState
    broker, path = pairing()
    seen = []

    def opener(_database, password, _keyfile, keys=None):
        seen.append((password, keys))
        if keys is None or keys.keyfile != b'synthetic key':
            raise CredentialsError('synthetic failure')
        return SimpleNamespace(entries=[], password=None)
    state = UnlockState(broker, None, None, opener)
    page = PageHandler(path)
    handle_pairing(page, state)
    assert page.sent[0][0] == 200 and 'name="keyfile" type="file"' in page.sent[0][1]
    status, _ = pair(path, state, [('password', ''), ('confirmed', 'yes')], [('keyfile', 'k', b'synthetic key')])
    assert status == 200 and seen == [(None, UnlockKeys(keyfile=b'synthetic key'))] and not broker.locked


def test_pairing_page_hardware_key_branches_count_like_the_unlock_page(broker_key):
    from akdbx.web_unlock import UnlockState
    broker, path = pairing()

    def opener(_database, password, _keyfile, keys=None):
        return unlock_keys.open_with_keys(YUBIKEY_VAULT.read_bytes(), password, None, keys,
                                          lambda *_: (_ for _ in ()).throw(CredentialsError('synthetic')))
    state = UnlockState(broker, YUBIKEY_VAULT, None, opener)
    fields = [('password', MASTER), ('confirmed', 'yes'), ('hardware', 'on')]
    status, body = pair(path, state, fields + [('challenge', '00' * 32), ('response', YUBIKEY_RESPONSE)])
    assert status == 409 and 'did not count' in body and state.remaining() == 3
    broker_key.error = hardware_key.NoHardwareKey()
    status, body = pair(path, state, fields)
    assert status == 409 and 'found no hardware key' in body and state.remaining() == 3
    status, body = pair(path, state, fields + [('challenge', YUBIKEY_SEED.hex()), ('response', '00' * 20)])
    assert status == 401 and 'hardware key' in body and '<details class="unlock-keys" open>' in body
    assert state.remaining() == 2 and broker.locked


def test_unlocked_vault_without_master_password_pairs_with_its_own_keys():
    """The open vault's own key material decides: no read of the vault file, no new unlock."""
    from test_extension_route import PageHandler
    from akdbx.extension_web import handle_pairing
    from akdbx.web_unlock import UnlockState
    broker, path = pairing(locked=False)
    held = SimpleNamespace(entries=[], password=None, keyfile=key_material(b'synthetic key', None))
    broker.vault = held
    state = UnlockState(broker, None, None, lambda *_, **__: pytest.fail('the vault file was opened'))
    token = state.token
    page = PageHandler(path)
    handle_pairing(page, state)
    assert page.sent[0][0] == 200 and 'name="keyfile" type="file"' in page.sent[0][1]
    status, _ = pair(path, state, [('password', ''), ('confirmed', 'yes')], [('keyfile', 'k', b'other key')])
    assert status == 401 and state.remaining() == 2
    status, _ = pair(path, state, [('password', ''), ('confirmed', 'yes')], [('keyfile', 'k', b'synthetic key')])
    assert status == 200 and broker.vault is held and broker.extension.approved
    # The unlock link is not spent: only an unlock does that.
    assert state.token == token and state.remaining() == 2


def test_held_keys_match_password_key_file_and_hardware_response():
    response = bytes.fromhex(YUBIKEY_RESPONSE)
    vault = open_encrypted(YUBIKEY_VAULT.read_bytes(), YUBIKEY_PASSWORD, key_material(None, response))
    check = unlock_keys.held_keys_match
    keys = UnlockKeys(challenge=YUBIKEY_SEED, responses=(bytes(20), response))
    assert check(vault, YUBIKEY_PASSWORD, keys)
    assert not check(vault, 'other', keys) and not check(vault, None, keys)
    assert not check(vault, YUBIKEY_PASSWORD, UnlockKeys(challenge=YUBIKEY_SEED, responses=(bytes(20),)))
    assert not check(vault, YUBIKEY_PASSWORD, None)
    with pytest.raises(unlock_keys.ChallengeChanged):
        check(vault, YUBIKEY_PASSWORD, UnlockKeys(challenge=bytes(32), responses=(response,)))


def test_a_key_file_without_its_hash_is_a_malformed_form():
    data = b'<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data>AABB</Data></Key></KeyFile>'
    with pytest.raises(ValueError):
        unlock_keys.keyfile_key(data)
    with pytest.raises(ValueError):
        unlock_credentials({'password': [''], 'keyfile': [data]}, None)


def test_a_failed_try_with_this_computers_key_keeps_that_route(tmp_path, broker_key):
    database = private_copy(tmp_path, YUBIKEY_VAULT)
    broker, server, socket_path, path = serve(tmp_path, database)
    try:
        status, page = post(socket_path, path, [('password', 'wrong'), ('hardware', 'on'), ('hardware_route', 'browser'),
                                                ('challenge', YUBIKEY_SEED.hex()), ('response', YUBIKEY_RESPONSE)])
        assert status == 401 and route_checked(page) == 'browser'
    finally:
        server.shutdown()
        server.server_close()


# ----- the real kernel path ------------------------------------------------------
# Defined only on Linux: other systems have no /dev/uhid, and their CI jobs refuse skips.
if sys.platform == 'linux':
    def test_virtual_usb_key_on_the_broker_unlocks_with_the_password(tmp_path, request):
        """Linux: a virtual USB key through /dev/uhid; the broker finds and asks it like a real one."""
        from test_hardware_key import _virtual_key_available
        if not _virtual_key_available():
            pytest.skip('the virtual hardware key needs passwordless sudo and /dev/uhid')
        request.getfixturevalue('virtual_key')
        folder = tmp_path / 'vault'
        folder.mkdir(mode=0o700)
        database = folder / 'vault.kdbx'
        hardware_vault(database, password=MASTER)
        broker, server, socket_path, path = serve(tmp_path, database)
        try:
            status, _, page = call(socket_path, 'GET', path)
            assert b'data-hardware-route="broker"' in page
            status, page = post(socket_path, path, [('password', MASTER), ('hardware', 'on')])
            assert status == 200 and b'Vault unlocked' in page and not broker.locked
        finally:
            server.shutdown()
            server.server_close()
