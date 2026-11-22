"""Broker identity key and signed origin statements (broker_identity) for the browser extension.

Synthetic keys and origins only. tests/origin_statement_fixture.json holds
statements that this Python code signed; tests/test_fill_extension.js checks
them with the extension's own verifier.
"""
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from akdbx import broker_identity, cli
from akdbx.broker_identity import IdentityError, IdentityStore, canonical_bytes, verify_message

pytestmark = pytest.mark.skipif(os.name == 'nt', reason='Linux file modes; Windows: the same PrivateFolder checks')
FIXTURE = Path(__file__).with_name('origin_statement_fixture.json')
LOCAL = 'https://localhost:9443'
RELAY = 'https://abcdefghijkl.akdbx.link'


@pytest.fixture
def store(tmp_path):
    folder = tmp_path / 'state'
    folder.mkdir(mode=0o700)
    return IdentityStore(folder / 'broker-identity', 'identity-test.json')


def test_canonical_bytes_are_sorted_compact_ascii_json():
    statement = {'type': 'akdbx-origin', 'v': 1, 'origin': LOCAL, 'seq': 7, 'key_id': 'K' * 43}
    assert canonical_bytes(statement) == (
        b'{"key_id":"' + b'K' * 43 + b'","origin":"https://localhost:9443","seq":7,"type":"akdbx-origin","v":1}')


def test_a_new_key_starts_at_one_and_each_origin_change_adds_one(store):
    first = store.announce(LOCAL + '/')
    assert first.changed and (first.origin, first.seq) == (LOCAL, 1)
    again = store.announce(LOCAL)
    assert not again.changed and again.seq == 1 and again.key_id == first.key_id
    moved = store.announce(RELAY)
    assert moved.changed and moved.seq == 2 and moved.key_id == first.key_id
    back = store.announce(LOCAL)
    assert back.seq == 3 and back.key_id == first.key_id  # Never 1 again: an old statement stays older.
    assert verify_message(back.message(), first.public_key)['seq'] == 3
    saved = json.loads(store.path.read_text())
    assert set(saved) == {'version', 'private_key', 'origin', 'seq'} and saved['seq'] == 3 and saved['origin'] == LOCAL


def test_the_identity_file_is_private_and_the_key_is_never_shown(store):
    identity = store.announce(LOCAL)
    assert stat.S_IMODE(store.directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    assert sorted(p.name for p in store.directory.iterdir()) == ['identity-test.json']
    shown = repr(identity) + json.dumps(identity.message()) + json.dumps(identity.summary())
    assert 'PRIVATE KEY' in store.path.read_text() and 'PRIVATE' not in shown
    assert identity.summary() == {'key_id': identity.key_id, 'origin': LOCAL, 'seq': 1}


@pytest.mark.parametrize('damage', ['file-mode', 'folder-mode', 'symlink', 'malformed', 'bad-origin', 'zero-seq',
                                    'other-curve'])
def test_an_untrusted_or_malformed_identity_file_is_refused(store, tmp_path, damage):
    store.announce(LOCAL)
    saved = json.loads(store.path.read_text())
    if damage == 'file-mode':
        store.path.chmod(0o644)
    elif damage == 'folder-mode':
        store.directory.chmod(0o755)
    elif damage == 'symlink':
        target = tmp_path / 'elsewhere.json'
        target.write_text(store.path.read_text())
        target.chmod(0o600)
        store.path.unlink()
        store.path.symlink_to(target)
    else:
        if damage == 'malformed':
            data = b'{not json'
        else:
            if damage == 'bad-origin':
                saved['origin'] = LOCAL + '/path'
            elif damage == 'zero-seq':
                saved['seq'] = 0
            else:
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric import ec
                saved['private_key'] = ec.generate_private_key(ec.SECP384R1()).private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()).decode()
            data = json.dumps(saved).encode()
        store.path.write_bytes(data)
    with pytest.raises(IdentityError) as caught:
        store.announce(LOCAL)
    assert 'PRIVATE' not in str(caught.value) and 'BEGIN' not in str(caught.value)


@pytest.mark.parametrize('origin', ['http://localhost:9443', 'https://user:pw@localhost', 'ftp://example.test',
                                    'https://', 'https://exa mple.test', 'https://ÿ.example', 7, None])
def test_only_https_origins_are_signed(store, origin):
    with pytest.raises(IdentityError):
        store.announce(origin)
    assert not store.path.exists()


def test_origins_are_signed_in_the_browser_serialization(store):
    assert store.announce('https://localhost:443').origin == 'https://localhost'
    assert store.announce('https://[::1]:9443/').origin == 'https://[::1]:9443'


def test_identity_files_are_per_endpoint(tmp_path):
    first = broker_identity.file_name(tmp_path / 'a.sock')
    assert first == broker_identity.file_name(tmp_path / 'x' / '..' / 'a.sock')
    assert first != broker_identity.file_name(tmp_path / 'b.sock')
    assert first.startswith('identity-') and first.endswith('.json')
    with pytest.raises(ValueError):
        IdentityStore(tmp_path, '../escape.json')


def sign_raw(key, statement, public_key=None):
    """Sign any statement, also an invalid one, the way Identity signs; for refusal fixtures."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(key.sign(canonical_bytes(statement), ec.ECDSA(hashes.SHA256())))
    point = broker_identity.public_point(key.public_key())
    return {'public_key': public_key or broker_identity.b64url(point), 'statement': statement,
            'signature': broker_identity.b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}


def make_fixture():
    from cryptography.hazmat.primitives.asymmetric import ec
    key, other = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    first = broker_identity.Identity(key, LOCAL, 1)
    moved = broker_identity.Identity(key, RELAY, 2)
    bad_origin = sign_raw(key, dict(first.statement, origin=LOCAL + '/unlock', seq=3))
    return {
        'note': 'Signed by tests/test_broker_identity.py (make_fixture); synthetic keys only.',
        'canonical': canonical_bytes(first.statement).decode('ascii'),
        'first': first.message(),
        'moved': moved.message(),
        'same_seq_other_origin': broker_identity.Identity(key, 'https://other.example.test', 2).message(),
        'ipv6': broker_identity.Identity(key, 'https://[::1]:9443', 3).message(),
        'other_key': broker_identity.Identity(other, 'https://look-alike.example.test', 3).message(),
        'bad_origin': bad_origin,
        'wrong_key_id': sign_raw(key, dict(first.statement, key_id=broker_identity.Identity(other, LOCAL, 1).key_id)),
    }


def test_the_extension_fixture_is_signed_by_this_code():
    """Run once with AKDBX_UPDATE_ORIGIN_FIXTURE=1 after a change to the encoding."""
    if os.environ.get('AKDBX_UPDATE_ORIGIN_FIXTURE') == '1':
        FIXTURE.write_text(json.dumps(make_fixture(), indent=2) + '\n', encoding='utf-8')
    fixture = json.loads(FIXTURE.read_text(encoding='utf-8'))
    first = verify_message(fixture['first'])
    assert canonical_bytes(first).decode('ascii') == fixture['canonical']
    assert verify_message(fixture['moved'], fixture['first']['public_key'])['seq'] == 2
    assert verify_message(fixture['ipv6'], fixture['first']['public_key'])['origin'] == 'https://[::1]:9443'
    for name in ('bad_origin', 'wrong_key_id'):
        with pytest.raises(IdentityError):
            verify_message(fixture[name])
    with pytest.raises(IdentityError, match='another key'):
        verify_message(fixture['other_key'], fixture['first']['public_key'])


@pytest.mark.parametrize('change', [
    lambda m: m['statement'].update(origin=RELAY),
    lambda m: m['statement'].update(seq=99),
    lambda m: m['statement'].update(extra=1),
    lambda m: m.update(signature=m['signature'][:-2] + ('AA' if m['signature'][-2:] != 'AA' else 'BA')),
    lambda m: m['statement'].update(v=2),
    lambda m: m['statement'].update(seq=2 ** 53),
    lambda m: m['statement'].update(seq=True),
    lambda m: m.pop('signature'),
])
def test_a_changed_statement_fails_verification(store, change):
    message = store.announce(LOCAL).message()
    change(message)
    with pytest.raises(IdentityError):
        verify_message(message)


# ----- the broker sends the statement ----------------------------------------------
def test_the_hub_sends_the_statement_in_state_messages_and_status(store):
    from test_extension_route import attach, make_broker
    broker = make_broker()
    channel, _ = attach(broker, {}, paired=False)
    assert 'identity' not in broker.extension._state(channel) and 'extension_trust' not in broker.dispatch(
        dict(action='ping'))
    sent = []
    channel.send = sent.append
    identity = store.announce(broker.writes.public_base)
    broker.extension.set_identity(identity)
    assert sent and sent[-1]['identity'] == identity.message()  # Pushed to attached extensions at once.
    state = broker.extension.popup(channel, dict(type='request', id='p1', op='state'))
    assert verify_message(state['identity'], identity.public_key)['origin'] == 'https://unlock.example.test:9443'
    assert state['pairing']['url'].startswith('https://unlock.example.test:9443/extension/pair?token=')
    assert broker.dispatch(dict(action='ping'))['extension_trust'] == identity.summary()


def test_serve_announces_the_page_origin_and_warns_without_stopping(tmp_path, capsys):
    folder = tmp_path / 'identity'
    broker = SimpleNamespace(writes=SimpleNamespace(public_base=LOCAL), extension=SimpleNamespace(identity=None))
    broker.extension.set_identity = lambda identity: setattr(broker.extension, 'identity', identity)
    cli.announce_identity(broker, tmp_path / 'broker.sock', folder)
    assert broker.extension.identity.seq == 1
    assert 'signed its origin https://localhost:9443 (sequence 1)' in capsys.readouterr().err
    cli.announce_identity(broker, tmp_path / 'broker.sock', folder)
    assert broker.extension.identity.seq == 1 and capsys.readouterr().err == ''  # Same origin: nothing new.
    folder.chmod(0o755)
    broker.extension.identity = None
    cli.announce_identity(broker, tmp_path / 'broker.sock', folder)
    err = capsys.readouterr().err
    assert broker.extension.identity is None and 'cannot follow an origin change' in err and 'mode 0700' in err
