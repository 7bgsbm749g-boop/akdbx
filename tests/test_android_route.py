"""Android route: device configuration, site rules, pins and fills without a device.

A real emulator run is in the PR evidence; these tests drive the broker with a
fake adb (both an in-process fake and a fake adb executable) and a fake
DevTools connection.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from akdbx import android_cli, android_route
from akdbx.android_route import (AndroidError, AndroidTargets, CHROME_CODE_DELIVERY, DELIVERY, GOOGLE_SIGNER,
                                 ORIGIN_MISMATCH, asset_link_allows, load_devices)
from akdbx.broker import Broker

from test_broker import RecordingTyper

ROOT = Path(__file__).resolve().parents[1]
HELPER_SOURCES = ROOT / 'android' / 'helper' / 'src'
HELPER_RECORD = Path(__file__).with_name('android_helper_fingerprint.json')
SECRET = 'Synthetic-Android-Password-1'
OTHER_SIGNER = 'AB' * 32
GMS_SIGNER = '5F2391277B1DBD489000467E4C2FA6AF802430080457DCE2F618992E9DFB5402'
BOOT = 'e3ca56e3-b6ce-4760-80c6-89a1b43369ed'


@dataclass
class Entry:
    uuid: str
    title: str
    username: str
    password: str
    url: str
    path: tuple = ('Root', 'Synthetic')
    otp: str | None = None


@dataclass
class Vault:
    entries: list


# ----- the bundled helper -------------------------------------------------

def source_digest():
    digest = hashlib.sha256()
    for path in sorted(HELPER_SOURCES.rglob('*.java')):
        digest.update(path.relative_to(HELPER_SOURCES).as_posix().encode() + b'\0' + path.read_bytes() + b'\0')
    return digest.hexdigest()


def test_helper_dex_matches_the_recorded_build():
    """The bundled dex must be the build of the current Java source.

    After a source change, rebuild with android/helper/build.sh, set
    HELPER_SHA256 in android_route.py, then run this test once with
    AKDBX_UPDATE_ANDROID_HELPER=1 to record the new source hash.
    """
    dex = hashlib.sha256(android_route.helper_path().read_bytes()).hexdigest()
    assert dex == android_route.HELPER_SHA256, 'set HELPER_SHA256 in android_route.py to the bundled dex hash'
    current = {'source_sha256': source_digest(), 'dex_sha256': dex}
    if os.environ.get('AKDBX_UPDATE_ANDROID_HELPER') == '1':
        HELPER_RECORD.write_text(json.dumps(current, indent=2) + '\n', encoding='utf-8')
    recorded = json.loads(HELPER_RECORD.read_text(encoding='utf-8'))
    assert recorded == current, ('the helper source or dex changed: rebuild with android/helper/build.sh, '
                                 'then record it with AKDBX_UPDATE_ANDROID_HELPER=1')


@pytest.mark.skipif(not (os.environ.get('JAVA_HOME') and os.environ.get('ANDROID_SDK')),
                    reason='needs JAVA_HOME (JDK 17) and ANDROID_SDK (build-tools 35.0.0, platform 35)')
def test_helper_build_is_reproducible(tmp_path):
    output = tmp_path / 'helper.dex'
    subprocess.run([str(ROOT / 'android' / 'helper' / 'build.sh')], check=True, capture_output=True,
                   env={**os.environ, 'AKDBX_HELPER_OUTPUT': str(output)})
    assert hashlib.sha256(output.read_bytes()).hexdigest() == android_route.HELPER_SHA256


def test_helper_ships_in_the_wheel_data():
    pyproject = (ROOT / 'pyproject.toml').read_text(encoding='utf-8')
    assert '"android_assets/*"' in pyproject


# ----- operator configuration ---------------------------------------------

def write_config(path, devices, mode=0o600):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    path.write_text(json.dumps({'version': 1, 'devices': devices}), encoding='utf-8')
    os.chmod(path, mode)
    return path


DEVICE = {'adb': '/opt/android/platform-tools/adb', 'adb_server_port': 5043, 'serial': 'emulator-5584'}


def test_missing_configuration_means_no_devices(tmp_path):
    assert load_devices(tmp_path / 'none.json') == {}
    assert load_devices(None) == {}


def test_configuration_is_parsed(tmp_path):
    devices = load_devices(write_config(tmp_path / 'cfg' / 'android.json', {'phone': DEVICE}))
    assert devices['phone'] == android_route.Device('phone', DEVICE['adb'], 5043, 'emulator-5584')


@pytest.mark.skipif(os.name == 'nt', reason='POSIX permissions')
def test_configuration_others_may_change_is_refused(tmp_path):
    path = write_config(tmp_path / 'cfg' / 'android.json', {'phone': DEVICE}, mode=0o620)
    with pytest.raises(AndroidError, match='not writable by others'):
        load_devices(path)
    os.chmod(path, 0o600)
    os.chmod(path.parent, 0o777)
    with pytest.raises(AndroidError, match='folder is writable'):
        load_devices(path)


@pytest.mark.parametrize('device', [
    {**DEVICE, 'adb': 'adb'},
    {**DEVICE, 'adb': '/opt/../adb'},
    {**DEVICE, 'adb_server_port': 80},
    {**DEVICE, 'adb_server_port': True},
    {**DEVICE, 'serial': 'emulator 5584'},
    {**DEVICE, 'extra': 1},
])
def test_invalid_device_entries_are_refused(tmp_path, device):
    with pytest.raises(AndroidError):
        load_devices(write_config(tmp_path / 'cfg' / 'android.json', {'phone': device}))


# ----- Digital Asset Links --------------------------------------------------

def statements(package='com.example.app', signer=OTHER_SIGNER, relation='delegate_permission/common.get_login_creds'):
    return json.dumps([{'relation': [relation], 'target': {
        'namespace': 'android_app', 'package_name': package,
        'sha256_cert_fingerprints': [':'.join(signer[i:i + 2] for i in range(0, 64, 2))]}}]).encode()


SITE = ('https', 'example.com', 443)


def test_asset_links_name_the_app_and_signer():
    fetched = []
    fetch = lambda url: fetched.append(url) or statements()
    assert asset_link_allows(SITE, 'com.example.app', OTHER_SIGNER, fetch=fetch)
    assert fetched == ['https://example.com/.well-known/assetlinks.json']
    assert asset_link_allows(SITE, 'com.example.app', OTHER_SIGNER,
                             fetch=lambda url: statements(relation='delegate_permission/common.handle_all_urls'))


@pytest.mark.parametrize('fetch', [
    lambda url: statements(package='com.example.other'),
    lambda url: statements(signer='CD' * 32),
    lambda url: statements(relation='delegate_permission/common.use_as_origin'),
    lambda url: b'{}',
    lambda url: b'not json',
    lambda url: (_ for _ in ()).throw(OSError()),
])
def test_asset_links_refuse_other_apps(fetch):
    assert not asset_link_allows(SITE, 'com.example.app', OTHER_SIGNER, fetch=fetch)


# ----- a fake device ----------------------------------------------------------

def context(package='com.example.app', activity='com.example.app/.Login', lineage=(OTHER_SIGNER,), **extra):
    return {'address_bar': None, 'boot_id': BOOT, 'sdk': 35, 'speak_password': False, 'window_id': 7,
            'window_title': 'Sign in', 'package': package, 'activity': activity, 'signers': [lineage[-1]],
            'signer_lineage': list(lineage), 'debuggable': False, 'system_app': False, **extra}


def field(node_id, password=False, web=False, package='com.example.app', **extra):
    value = {'window_id': 7, 'node_id': node_id, 'class': 'android.widget.EditText', 'view_id': None,
             'package': package, 'hint': 'Password' if password else 'Email', 'label': None, 'password': password,
             'editable': True, 'enabled': True, 'visible': True, 'focused': False, 'has_text': False,
             'input_type': 129 if password else 33, 'bounds': [0, 0, 10, 10], 'web': web, **extra}
    if web:
        value.setdefault('in_frame', False)
    return value


GMS = dict(package='com.google.android.gms', activity=android_route.GMS_SIGN_IN_ACTIVITY,
           lineage=(GOOGLE_SIGNER, '7C' * 32, GMS_SIGNER))


class FakeAdb:
    """Answers helper requests from a scene; records every request."""

    requests = []

    def __init__(self, scene):
        self.scene = scene

    def helper(self, request, *, install):
        FakeAdb.requests.append(request)
        scene = self.scene
        op = request['op']
        if op == 'probe':
            return {'ok': True, 'boot_id': scene.get('boot', BOOT), 'sdk': 35,
                    'speak_password': scene['context']['speak_password'], 'protocol': 1}
        if op in {'context', 'inspect'}:
            return {'ok': True, 'context': scene['context'], 'fields': scene['fields'], 'protocol': 1}
        if op == 'check':
            by_id = {f['node_id']: f for f in scene['fields']}
            if not all(i in by_id for i in request['node_ids']):
                return {'ok': False, 'error': 'field not found in the focused window', 'protocol': 1}
            return {'ok': True, 'context': scene['context'], 'fields': [by_id[i] for i in request['node_ids']], 'protocol': 1}
        if op == 'fill':
            return scene.get('fill', {'ok': True, 'delivered': True,
                                      'results': [{'accepted': True, 'confirmed': True} for _ in request['fields']],
                                      'protocol': 1})
        raise AssertionError(op)


@pytest.fixture
def device_file(tmp_path):
    adb = tmp_path / 'bin' / 'adb'
    adb.parent.mkdir()
    adb.write_text('#!/bin/sh\nexit 1\n')
    adb.chmod(0o700)
    return write_config(tmp_path / 'cfg' / 'android.json',
                        {'phone': {'adb': str(adb), 'adb_server_port': 5043, 'serial': 'emulator-5584'}})


def make_broker(device_file, scene, entries=None, fetch=None):
    FakeAdb.requests = []
    entries = entries or [
        Entry('1', 'Google', 'synthetic@example.invalid', SECRET, 'https://accounts.google.com/'),
        Entry('2', 'Example', 'synthetic-user', SECRET, 'https://example.com/',
              otp='otpauth://totp/synthetic?secret=JBSWY3DPEHPK3PXP&issuer=akdbx'),
        Entry('3', 'Other', 'other-user', SECRET, 'https://other.example/'),
    ]
    # The start of a TOTP period: a code never refuses as near expiry.
    broker = Broker(Vault(entries), RecordingTyper(), android_devices_path=device_file,
                    wall_clock=lambda: 1_700_000_010.0)
    broker.android.adb_factory = lambda device: FakeAdb(scene)
    broker.android.fetch = fetch
    return broker


def handle(broker, query):
    return broker.dispatch({'action': 'search', 'query': query})['entries'][0]['handle']


def pin(broker, **request):
    return broker.dispatch({'action': 'android-pin', 'android_protocol': 1, 'device': 'phone', **request})


def fill(broker, query, target, mode='password'):
    request = {'action': 'fill', 'handle': handle(broker, query), 'target': target, 'target_protocol': 1, 'mode': mode}
    if mode == 'totp':
        request['action'] = 'fill-totp'
        del request['mode']
    return broker.dispatch(request)


def fill_requests():
    return [r for r in FakeAdb.requests if r['op'] == 'fill']


def test_status_reports_android_capabilities(device_file):
    broker = make_broker(device_file, {'context': context(), 'fields': []})
    status = broker.dispatch({'action': 'ping'})
    assert status['android_fill_protocol'] == 1 and status['android_devices_configured'] is True
    assert status['android_fill_delivery'] == DELIVERY and status['android_page_code_delivery'] == CHROME_CODE_DELIVERY


def test_google_sign_in_fills_the_google_entry_only(device_file):
    scene = {'context': context(**GMS), 'fields': [field('11', web=True, package='com.google.android.gms'),
                                                   field('12', password=True, web=True, package='com.google.android.gms')]}
    broker = make_broker(device_file, scene)
    inspected = broker.dispatch({'action': 'android-inspect', 'device': 'phone'})
    assert inspected['site'] == {'origin': 'https://accounts.google.com', 'source': 'google-sign-in'}
    assert [f['field'] for f in inspected['fields']] == ['11', '12']

    pinned = pin(broker, mode='password', field='12')
    assert pinned['ok'] and pinned['origin'] == 'https://accounts.google.com' and pinned['android_delivery'] == DELIVERY
    assert fill(broker, 'Other', pinned['target']) == {'ok': False, 'error': ORIGIN_MISMATCH, 'delivery': 'not-started'}
    assert fill_requests() == []

    pinned = pin(broker, mode='password', field='12')
    response = fill(broker, 'Google', pinned['target'])
    assert response == {'ok': True, 'filled': 'password', 'target_delivery': DELIVERY}
    assert SECRET not in json.dumps(response)
    [request] = fill_requests()
    assert [f['value'] for f in request['fields']] == [SECRET] and request['boot_id'] == BOOT
    # A pin is single use.
    assert fill(broker, 'Google', pinned['target'])['delivery'] == 'not-started'


def test_login_mode_fills_both_fields_in_order(device_file):
    scene = {'context': context(**GMS), 'fields': [field('11', web=True, package='com.google.android.gms'),
                                                   field('12', password=True, web=True, package='com.google.android.gms')]}
    broker = make_broker(device_file, scene)
    pinned = pin(broker, mode='login', field='12', username_field='11')
    assert fill(broker, 'Google', pinned['target'], mode='login')['ok']
    [request] = fill_requests()
    assert [(f['expect']['node_id'], f['value']) for f in request['fields']] == [
        ('11', 'synthetic@example.invalid'), ('12', SECRET)]


@pytest.mark.parametrize('change, error', [
    (dict(lineage=(OTHER_SIGNER,)), 'app not verified'),
    (dict(activity='com.google.android.gms/.Other'), 'app not verified'),
])
def test_google_sign_in_needs_google_signing_and_its_activity(device_file, change, error):
    scene = {'context': context(**{**GMS, **change}),
             'fields': [field('12', password=True, web=True, package='com.google.android.gms')]}
    assert error in pin(make_broker(device_file, scene), mode='password', field='12')['error']


@pytest.mark.parametrize('scene_change, request_change, error', [
    ({'speak_password': True}, {}, 'speak_password 0'),
    ({'debuggable': True}, {}, 'debuggable'),
    ({}, {'mode': 'password', 'field': '11'}, 'password value needs a password field'),
    ({}, {'mode': 'username', 'field': '12'}, 'not a password field'),
    ({}, {'mode': 'password', 'field': '99'}, 'field not found'),
    ({}, {'mode': 'password', 'field': '#password'}, 'field values from android inspect'),
    ({}, {'mode': 'login', 'field': '12'}, 'required in login mode'),
])
def test_unsafe_or_wrong_targets_are_refused(device_file, scene_change, request_change, error):
    scene = {'context': context(**GMS, **scene_change),
             'fields': [field('11', web=True, package='com.google.android.gms'),
                        field('12', password=True, web=True, package='com.google.android.gms')]}
    response = pin(make_broker(device_file, scene), **{'mode': 'password', 'field': '12', **request_change})
    assert response['ok'] is False and error in response['error']


def test_hidden_field_and_frames_are_refused(device_file):
    scene = {'context': context(**GMS), 'fields': [field('12', password=True, web=True, package='com.google.android.gms',
                                                         visible=False),
                                                   field('13', password=True, web=True, package='com.google.android.gms',
                                                         in_frame=True)]}
    broker = make_broker(device_file, scene)
    assert 'visible' in pin(broker, mode='password', field='12')['error']
    assert 'frame' in pin(broker, mode='password', field='13')['error']


def test_an_app_needs_asset_links_for_the_named_site(device_file):
    scene = {'context': context(), 'fields': [field('21'), field('22', password=True)]}
    broker = make_broker(device_file, scene, fetch=lambda url: statements())
    assert 'give --app-site' in pin(broker, mode='password', field='22')['error']
    assert 'exact HTTPS origin' in pin(broker, mode='password', field='22', app_site='http://example.com')['error']
    broker.android.fetch = lambda url: statements() if url.startswith('https://example.com/') else b'[]'
    assert 'do not name this app' in pin(broker, mode='password', field='22', app_site='https://other.example')['error']
    pinned = pin(broker, mode='login', field='22', username_field='21', app_site='https://example.com')
    assert pinned['ok'] and pinned['origin'] == 'https://example.com' and pinned['site_source'] == 'asset-links'
    assert fill(broker, 'synthetic-user', pinned['target'], mode='login')['ok']


def test_fill_stops_before_any_value_when_the_device_changed(device_file):
    scene = {'context': context(**GMS), 'fields': [field('12', password=True, web=True, package='com.google.android.gms')]}
    broker = make_broker(device_file, scene)
    pinned = pin(broker, mode='password', field='12')
    scene['boot'] = 'another-boot'
    assert fill(broker, 'Google', pinned['target'])['delivery'] == 'not-started'
    scene.pop('boot')
    scene['context'] = context(**GMS, speak_password=True)
    pinned = pin(broker, mode='password', field='12')
    assert pinned['ok'] is False
    assert fill_requests() == []


@pytest.mark.parametrize('answer, delivery', [
    ({'ok': False, 'error': 'field changed since the pin', 'protocol': 1}, 'not-started'),
    ({'ok': False, 'error': 'helper failed: RuntimeException', 'protocol': 1}, 'uncertain'),
    ({'ok': True, 'delivered': False, 'results': [{'accepted': False, 'confirmed': False}], 'protocol': 1}, 'not-started'),
    ({'ok': True, 'delivered': True, 'results': [{'accepted': False}], 'protocol': 1}, 'uncertain'),
])
def test_helper_failures_report_whether_delivery_started(device_file, answer, delivery):
    scene = {'context': context(**GMS), 'fields': [field('12', password=True, web=True, package='com.google.android.gms')],
             'fill': answer}
    broker = make_broker(device_file, scene)
    response = fill(broker, 'Google', pin(broker, mode='password', field='12')['target'])
    assert response['ok'] is False and response['delivery'] == delivery and SECRET not in json.dumps(response)


def test_authenticator_code_goes_to_an_app_field_of_the_entry_site(device_file):
    scene = {'context': context(), 'fields': [field('31')]}
    broker = make_broker(device_file, scene, fetch=lambda url: statements())
    pinned = pin(broker, mode='totp', field='31', app_site='https://example.com')
    response = fill(broker, 'synthetic-user', pinned['target'], mode='totp')
    assert response == {'ok': True, 'filled': 'totp', 'target_delivery': DELIVERY}
    [request] = fill_requests()
    code = request['fields'][0]['value']
    assert len(code) == 6 and code.isdigit() and code not in json.dumps(response)
    # The pin names the site; a caller-supplied target URL is refused.
    pinned = pin(broker, mode='totp', field='31', app_site='https://example.com')
    refused = broker.dispatch({'action': 'fill-totp', 'handle': handle(broker, 'synthetic-user'), 'target': pinned['target'],
                               'target_protocol': 1, 'target_url': 'https://example.com/'})
    assert refused['ok'] is False and refused['delivery'] == 'not-started'


def test_inspect_and_device_list_work_while_locked(device_file):
    scene = {'context': context(**GMS), 'fields': []}
    broker = Broker(None, RecordingTyper(), android_devices_path=device_file)
    broker.android.adb_factory = lambda device: FakeAdb(scene)
    assert broker.dispatch({'action': 'android-inspect', 'device': 'phone'})['ok']
    assert broker.dispatch({'action': 'android-devices'})['devices'][0]['reachable'] is True
    assert broker.dispatch({'action': 'android-pin', 'android_protocol': 1, 'device': 'phone',
                            'mode': 'password', 'field': '1'})['error'] == 'vault locked'


def test_unknown_device_is_refused(device_file):
    broker = make_broker(device_file, {'context': context(), 'fields': []})
    response = broker.dispatch({'action': 'android-inspect', 'device': 'tablet'})
    assert response == {'ok': False, 'error': 'unknown Android device; configured devices: phone'}


# ----- Chrome pages through DevTools ---------------------------------------

class FakeCDP:
    """A Chrome with one visible tab at URL and other frozen tabs."""

    def __init__(self, url, shown=True, focused_code=True):
        self.url, self.shown, self.focused_code = url, shown, focused_code
        self.calls = []
        self.closed = False

    def call(self, method, params=None, session=None, *, timeout=3):
        self.calls.append((method, params))
        if method == 'Target.getTargets':
            return {'targetInfos': [{'targetId': 'T1', 'type': 'page', 'url': self.url},
                                    {'targetId': 'T2', 'type': 'page', 'url': 'https://evil.example/'}]}
        if method == 'Target.attachToTarget':
            return {'sessionId': 'S-' + params['targetId']}
        if method == 'Target.getTargetInfo':
            return {'targetInfo': {'targetId': 'T1', 'type': 'page', 'url': self.url}}
        if method == 'Page.getFrameTree':
            return {'frameTree': {'frame': {'id': 'F1', 'url': self.url}}}
        if method == 'Page.createIsolatedWorld':
            return {'executionContextId': 5}
        if method == 'Runtime.evaluate':
            expression = params['expression']
            if expression == android_route.PAGE_STATE:
                return {'result': {'value': {'url': self.url, 'shown': self.shown, 'secure': True}}}
            if expression.startswith(android_route.OTP_CAPTURE):
                if not self.focused_code:
                    return {'exceptionDetails': {}}
                return {'result': {'type': 'object', 'objectId': 'OBJ'}}
            if expression == android_route.PAGE_FIELDS:
                return {'result': {'value': [{'selector': '#app_totp', 'type': 'text', 'focused': True}]}}
        if method == 'Runtime.callFunctionOn':
            if 'performance.now()' in params['functionDeclaration'] and 'arguments' not in params:
                return {'result': {'value': 1000.0}}
            if params['functionDeclaration'] == android_route.OTP_FILL:
                return {'result': {'value': True}}
            return {'result': {}}
        if method == 'Runtime.releaseObject':
            return {}
        raise AssertionError(method)

    def close(self):
        self.closed = True


CHROME = dict(package='com.android.chrome', activity=android_route.CHROME_ACTIVITIES[1], lineage=(GOOGLE_SIGNER,))


def chrome_broker(device_file, cdp, address_bar='example.com'):
    scene = {'context': context(**CHROME, address_bar=address_bar), 'fields': []}
    broker = make_broker(device_file, scene)
    broker.android.cdp_factory = lambda adb: cdp
    return broker


def test_chrome_page_code_fill_binds_the_page_origin(device_file):
    cdp = FakeCDP('https://example.com/sessions/two-factor/app')
    broker = chrome_broker(device_file, cdp)
    inspected = broker.dispatch({'action': 'android-inspect', 'device': 'phone'})
    assert inspected['site'] == {'origin': 'https://example.com', 'source': 'chrome'}
    assert inspected['fields'][0]['field'] == '#app_totp'
    # Only the tab with the address bar's host is asked: frozen tabs answer nothing.
    assert ('Target.attachToTarget', {'targetId': 'T2', 'flatten': True}) not in cdp.calls

    pinned = pin(broker, mode='totp', field='#app_totp')
    assert pinned['ok'] and pinned['android_delivery'] == CHROME_CODE_DELIVERY and pinned['origin'] == 'https://example.com'
    assert fill(broker, 'Other', pinned['target'], mode='totp')['error'] == ORIGIN_MISMATCH
    assert cdp.closed

    cdp.closed = False
    pinned = pin(broker, mode='totp', field='#app_totp')
    response = fill(broker, 'synthetic-user', pinned['target'], mode='totp')
    assert response == {'ok': True, 'filled': 'totp', 'target_delivery': CHROME_CODE_DELIVERY}
    [call] = [params for method, params in cdp.calls
              if method == 'Runtime.callFunctionOn' and params['functionDeclaration'] == android_route.OTP_FILL]
    code = call['arguments'][0]['value']
    assert len(code) == 6 and code not in json.dumps(response)
    assert cdp.closed


@pytest.mark.parametrize('kwargs, address_bar, error', [
    (dict(shown=False), 'example.com', 'no single visible'),
    (dict(), 'other.example', 'no single visible'),
    (dict(focused_code=False), 'example.com', 'code field refused'),
])
def test_chrome_page_refusals(device_file, kwargs, address_bar, error):
    broker = chrome_broker(device_file, FakeCDP('https://example.com/login', **kwargs), address_bar=address_bar)
    assert error in pin(broker, mode='totp', field='#app_totp')['error']


def test_chrome_http_page_is_refused(device_file):
    broker = chrome_broker(device_file, FakeCDP('http://example.com/login'), address_bar='example.com')
    assert 'no single visible' in pin(broker, mode='totp', field='#code')['error']


def test_chrome_login_uses_the_cdp_route_pin(device_file):
    broker = chrome_broker(device_file, FakeCDP('https://example.com/login'))
    seen = {}

    def pin_with(request, profile, slot=None):
        seen.update(request=request, profile=profile)
        return {'ok': True, 'target': 'f' * 64, 'expires_in': 30, 'target_delivery': 'chromium-password-dom-v1'}
    broker.passwords.pin_with = pin_with
    response = pin(broker, mode='login', field='#password', username_field='#login')
    assert response['ok'] and response['android_delivery'] == 'chromium-password-dom-v1'
    assert seen['request'] == {'action': 'pin-password-target', 'password_protocol': 1, 'page_id': 'T1', 'frame_id': 'F1',
                               'top_url': 'https://example.com/login', 'selector': '#password', 'mode': 'login',
                               'username_selector': '#login'}
    assert isinstance(seen['profile'], android_route.ChromeDevTools)


def test_chrome_outside_a_tab_is_refused(device_file):
    scene = {'context': context(package='com.android.chrome', activity='com.android.chrome/.Other',
                                lineage=(GOOGLE_SIGNER,)), 'fields': [field('1', password=True, package='com.android.chrome')]}
    assert 'not in a tab' in pin(make_broker(device_file, scene), mode='password', field='1')['error']


def test_forwarded_devtools_port_is_removed_once_connected():
    calls = []

    class Adb:
        def forward_devtools(self):
            calls.append('forward')
            return 40000

        def remove_forward(self, port):
            calls.append(('remove', port))
    endpoint = android_route.ChromeDevTools(Adb())
    assert endpoint.devtools_endpoint() == 'ws://127.0.0.1:40000/devtools/browser'
    endpoint.release_endpoint()
    endpoint.release_endpoint()
    assert calls == ['forward', ('remove', 40000)]


# ----- the adb process: values only on standard input ----------------------

FAKE_ADB = r'''#!PYTHON
import json, os, sys
log = os.environ['FAKE_ADB_LOG']
args = sys.argv[1:]
data = sys.stdin.buffer.read() if args[4:6] == ['shell', '-T'] else b''
with open(log, 'a') as out:
    out.write(json.dumps({'argv': args, 'stdin': data.decode()}) + '\n')
if args[4:6] == ['shell', '-T']:
    request = json.loads(data)
    if request['op'] == 'probe':
        answer = {'ok': True, 'boot_id': 'B', 'sdk': 35, 'speak_password': False}
    else:
        answer = {'ok': True, 'delivered': True, 'results': [{'accepted': True, 'confirmed': True}]}
    answer['protocol'] = 1
    print('noise from app_process')
    print('AKDBX-ANDROID-RESULT ' + json.dumps(answer))
'''


@pytest.mark.skipif(os.name == 'nt', reason='fake adb is a POSIX script')
def test_values_reach_adb_only_on_standard_input(tmp_path, monkeypatch):
    adb = tmp_path / 'adb'
    adb.write_text(FAKE_ADB.replace('PYTHON', sys.executable))
    adb.chmod(0o700)
    log = tmp_path / 'adb.log'
    monkeypatch.setenv('FAKE_ADB_LOG', str(log))
    monkeypatch.setenv('ANDROID_SERIAL', 'should-not-pass')
    device = android_route.Device('phone', str(adb), 5043, 'emulator-5584')
    runner = android_route.Adb(device)
    monkeypatch.setattr(runner, 'server_running', lambda: True)
    targets = AndroidTargets(None, adb_factory=lambda d: runner)
    pinned = android_route.AndroidPin(token='t', device=device, boot_id='B', context=context(**GMS),
                                      fields=[field('12', password=True, web=True, package='com.google.android.gms')],
                                      mode='password', origin=('https', 'accounts.google.com', 443),
                                      source='google-sign-in', expires_at=time.monotonic() + 30)
    targets.deliver(pinned, 'password', [SECRET], lambda: True, time.monotonic() + 4)
    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert [r['argv'][4:6] for r in records] == [['shell', '-T']] * 2
    for record in records:
        assert record['argv'][:4] == ['-P', '5043', '-s', 'emulator-5584']
        assert SECRET not in json.dumps(record['argv'])
        assert 'app_process' in record['argv'][-1] and android_route.HELPER_SHA256 in record['argv'][-1]
    assert SECRET not in records[0]['stdin'] and SECRET in records[1]['stdin']


# ----- CLI --------------------------------------------------------------------

def caps():
    return {'ok': True, 'android_fill_protocol': 1, 'android_fill_delivery': DELIVERY}


def run_cli(argv, responses, capsys):
    from akdbx.cli import parser
    args = parser().parse_args(argv)
    sent = []

    def request(payload):
        sent.append(payload)
        return caps() if payload['action'] == 'ping' else responses.pop(0)
    code = android_cli.run(args, request)
    return code, sent, capsys.readouterr()


def test_cli_fill_sends_no_value_and_prints_the_receipt(capsys):
    receipt = {'ok': True, 'filled': 'password', 'target_delivery': DELIVERY}
    code, sent, out = run_cli(['android', 'fill', 'a' * 64, '--target', 'b' * 64, '--mode', 'password'], [receipt], capsys)
    assert code == 0 and json.loads(out.out) == receipt
    assert set(sent[1]) == {'action', 'handle', 'target', 'target_protocol', 'start_deadline', 'mode'}


def test_cli_rejects_an_unexpected_fill_answer(capsys):
    code, _, out = run_cli(['android', 'fill-totp', 'a' * 64, '--target', 'b' * 64],
                           [{'ok': True, 'filled': 'totp', 'target_delivery': DELIVERY, 'code': '123456'}], capsys)
    assert code == 2 and '123456' not in out.out + out.err


def test_cli_pin_needs_the_username_field_only_in_login_mode(capsys):
    code, sent, out = run_cli(['android', 'pin', '--device', 'phone', '--mode', 'login', '--field', '1'], [], capsys)
    assert code == 1 and len(sent) == 1 and 'username-field' in out.out
    pinned = {'ok': True, 'target': 'c' * 64, 'expires_in': 30, 'android_delivery': DELIVERY, 'mode': 'password',
              'origin': 'https://accounts.google.com', 'site_source': 'google-sign-in', 'package': 'com.google.android.gms'}
    code, sent, out = run_cli(['android', 'pin', '--device', 'phone', '--mode', 'password', '--field', '1'], [pinned], capsys)
    assert code == 0 and sent[1] == {'action': 'android-pin', 'android_protocol': 1, 'device': 'phone',
                                     'mode': 'password', 'field': '1'}
