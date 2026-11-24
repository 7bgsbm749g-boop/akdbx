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
from dataclasses import dataclass
from pathlib import Path

import pytest

from akdbx import android_cli, android_route
from akdbx.android_route import (AndroidError, CHROME_DELIVERY, DELIVERY, GOOGLE_SIGNER,
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


@pytest.mark.parametrize('fetch', [
    # App Links let an app open the site's links; they do not share its credentials.
    lambda url: statements(relation='delegate_permission/common.handle_all_urls'),
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
            'window_title': 'Sign in', 'package': package, 'activity': activity, 'task_id': 12, 'user_id': 0,
            'signers': [lineage[-1]],
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

    def helper(self, request, *, install, timeout=None, answer=None):
        FakeAdb.requests.append(request)
        scene = self.scene
        op = request['op']
        if op == 'probe':
            return {'ok': True, 'boot_id': scene.get('boot', BOOT), 'sdk': 35,
                    'speak_password': scene['context']['speak_password'], 'protocol': 1}
        if op in {'context', 'inspect'}:
            return {'ok': True, 'context': scene['context'], 'fields': scene['fields'], 'protocol': 1}
        if op == 'google_sign_in':
            steps = ['email', 'password']
            if request.get('code') is True:
                # The helper asks for the code only when Google's code field is ready.
                reply = json.loads(answer('code'))
                FakeAdb.requests.append({'op': 'code-answer', **reply})
                steps.append('code')
            return scene.get('sign_in', {'ok': True, 'steps': steps, 'protocol': 1})
        if op == 'type':
            scene.setdefault('typed', []).append(request['value'])
            return scene.get('type', {'ok': True, 'complete': True, 'started': True, 'protocol': 1})
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
    assert status['android_fill_delivery'] == DELIVERY and status['android_chrome_delivery'] == CHROME_DELIVERY


APP = [field('21'), field('22', password=True)]


def app_broker(device_file, scene_change=None, fields=None, fill=None):
    scene = {'context': context(**(scene_change or {})), 'fields': fields or APP}
    if fill is not None:
        scene['fill'] = fill
    broker = make_broker(device_file, scene,
                         fetch=lambda url: statements() if url.startswith('https://example.com/') else b'[]')
    return broker, scene


def test_an_app_fills_only_the_entry_of_the_site_its_asset_links_name(device_file):
    broker, _ = app_broker(device_file)
    inspected = broker.dispatch({'action': 'android-inspect', 'device': 'phone'})
    assert inspected['site'] is None and 'give --app-site' in inspected['site_note']
    assert [f['field'] for f in inspected['fields']] == ['21', '22']
    assert 'give --app-site' in pin(broker, mode='password', field='22')['error']
    assert 'exact HTTPS origin' in pin(broker, mode='password', field='22', app_site='http://example.com')['error']
    assert 'do not name this app' in pin(broker, mode='password', field='22', app_site='https://other.example')['error']

    pinned = pin(broker, mode='password', field='22', app_site='https://example.com')
    assert pinned['ok'] and pinned['origin'] == 'https://example.com' and pinned['site_source'] == 'asset-links'
    assert pinned['android_delivery'] == DELIVERY
    assert fill(broker, 'Other', pinned['target']) == {'ok': False, 'error': ORIGIN_MISMATCH, 'delivery': 'not-started'}
    assert fill_requests() == []

    pinned = pin(broker, mode='password', field='22', app_site='https://example.com')
    response = fill(broker, 'synthetic-user', pinned['target'])
    assert response == {'ok': True, 'filled': 'password', 'target_delivery': DELIVERY}
    assert SECRET not in json.dumps(response)
    [request] = fill_requests()
    assert [f['value'] for f in request['fields']] == [SECRET] and request['boot_id'] == BOOT
    # A pin is single use.
    assert fill(broker, 'synthetic-user', pinned['target'])['delivery'] == 'not-started'


def test_login_mode_fills_both_fields_in_order(device_file):
    broker, _ = app_broker(device_file)
    pinned = pin(broker, mode='login', field='22', username_field='21', app_site='https://example.com')
    assert fill(broker, 'synthetic-user', pinned['target'], mode='login')['ok']
    [request] = fill_requests()
    assert [(f['expect']['node_id'], f['value']) for f in request['fields']] == [('21', 'synthetic-user'), ('22', SECRET)]


def test_a_web_field_inside_an_app_is_refused(device_file):
    # An app's web view shows no page URL; asset links name the app, not the page it shows.
    broker, _ = app_broker(device_file, fields=[field('22', password=True, web=True)])
    assert 'web field inside an app' in pin(broker, mode='password', field='22', app_site='https://example.com')['error']


@pytest.mark.parametrize('scene_change, request_change, error', [
    ({'speak_password': True}, {}, 'speak_password 0'),
    ({'debuggable': True}, {}, 'debuggable'),
    ({}, {'mode': 'password', 'field': '21'}, 'password value needs a password field'),
    ({}, {'mode': 'username', 'field': '22'}, 'not a password field'),
    ({}, {'mode': 'password', 'field': '99'}, 'field not found'),
    ({}, {'mode': 'password', 'field': '#password'}, 'field values from android inspect'),
    ({}, {'mode': 'login', 'field': '22'}, 'required in login mode'),
])
def test_unsafe_or_wrong_targets_are_refused(device_file, scene_change, request_change, error):
    broker, _ = app_broker(device_file, scene_change)
    response = pin(broker, **{'mode': 'password', 'field': '22', 'app_site': 'https://example.com', **request_change})
    assert response['ok'] is False and error in response['error']


def test_hidden_field_is_refused(device_file):
    broker, _ = app_broker(device_file, fields=[field('22', password=True, visible=False)])
    assert 'visible' in pin(broker, mode='password', field='22', app_site='https://example.com')['error']


def test_fill_stops_before_any_value_when_the_device_changed(device_file):
    broker, scene = app_broker(device_file)
    pinned = pin(broker, mode='password', field='22', app_site='https://example.com')
    scene['boot'] = 'another-boot'
    assert fill(broker, 'synthetic-user', pinned['target'])['delivery'] == 'not-started'
    assert fill_requests() == []


@pytest.mark.parametrize('answer, delivery', [
    ({'ok': False, 'error': 'field changed since the pin', 'protocol': 1}, 'not-started'),
    ({'ok': False, 'error': 'helper failed: RuntimeException', 'protocol': 1}, 'uncertain'),
    ({'ok': True, 'delivered': False, 'results': [{'accepted': False, 'confirmed': False}], 'protocol': 1}, 'not-started'),
    ({'ok': True, 'delivered': True, 'results': [{'accepted': False}], 'protocol': 1}, 'uncertain'),
    # The field took the write but does not hold the value (for example, a maximum length cut it).
    ({'ok': True, 'delivered': True, 'results': [{'accepted': True, 'confirmed': False}], 'protocol': 1}, 'uncertain'),
])
def test_helper_failures_report_whether_delivery_started(device_file, answer, delivery):
    broker, _ = app_broker(device_file, fill=answer)
    response = fill(broker, 'synthetic-user', pin(broker, mode='password', field='22', app_site='https://example.com')['target'])
    assert response['ok'] is False and response['delivery'] == delivery and SECRET not in json.dumps(response)


def test_authenticator_code_goes_to_an_app_field_of_the_entry_site(device_file):
    broker, _ = app_broker(device_file, fields=[field('31')])
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


# ----- Google account sign-in -------------------------------------------------

GMS_FIELDS = [field('11', web=True, package='com.google.android.gms'),
              field('12', password=True, web=True, package='com.google.android.gms')]


def google_sign_in(broker, query='Google', code=False):
    return broker.dispatch({'action': 'android-google-sign-in', 'android_protocol': 1, 'device': 'phone',
                            'handle': handle(broker, query), 'code': code})


def sign_in_requests():
    return [r for r in FakeAdb.requests if r['op'] == 'google_sign_in']


def test_google_sign_in_pins_only_the_email(device_file):
    broker = make_broker(device_file, {'context': context(**GMS), 'fields': GMS_FIELDS})
    inspected = broker.dispatch({'action': 'android-inspect', 'device': 'phone'})
    assert inspected['site'] == {'origin': 'https://accounts.google.com', 'source': 'google-sign-in'}
    assert 'google-sign-in' in inspected['site_note']
    # The sign-in web view shows no page URL: a work account can move it to
    # another site, so a separate password or code pin is refused.
    for mode in ('password', 'totp'):
        assert 'android google-sign-in' in pin(broker, mode=mode, field='12' if mode == 'password' else '11')['error']
    assert 'android google-sign-in' in pin(broker, mode='login', field='12', username_field='11')['error']
    pinned = pin(broker, mode='username', field='11')
    assert pinned['ok'] and pinned['origin'] == 'https://accounts.google.com'
    assert fill(broker, 'Google', pinned['target'], mode='username')['ok']


GMAIL = [Entry('1', 'Google', 'synthetic@gmail.com', SECRET, 'https://accounts.google.com/',
               otp='otpauth://totp/s?secret=JBSWY3DPEHPK3PXP&issuer=akdbx'),
         Entry('2', 'Work', 'synthetic@example.invalid', SECRET, 'https://accounts.google.com/'),
         Entry('3', 'Other', 'other@gmail.com', SECRET, 'https://other.example/')]


def test_google_sign_in_runs_email_password_and_code_in_one_helper_run(device_file):
    broker = make_broker(device_file, {'context': context(**GMS), 'fields': GMS_FIELDS}, entries=GMAIL)
    response = google_sign_in(broker, query='synthetic@gmail', code=False)
    assert response == {'ok': True, 'filled': ['email', 'password'], 'target_delivery': DELIVERY}
    [request] = sign_in_requests()
    assert request['email'] == 'synthetic@gmail.com' and request['password'] == SECRET and 'code' not in request
    assert SECRET not in json.dumps(response)
    FakeAdb.requests = []
    response = google_sign_in(broker, query='synthetic@gmail', code=True)
    assert response['filled'] == ['email', 'password', 'code']
    [request] = sign_in_requests()
    # The code is not in the request: the broker makes it when the helper asks.
    assert request['code'] is True
    [answer] = [r for r in FakeAdb.requests if r['op'] == 'code-answer']
    assert len(answer['code']) == 6 and answer['code'] not in json.dumps(response)


def test_google_sign_in_is_only_for_consumer_accounts(device_file):
    # Another domain can send the sign-in to its own company page, whose site akdbx cannot read.
    broker = make_broker(device_file, {'context': context(**GMS), 'fields': GMS_FIELDS}, entries=GMAIL)
    response = google_sign_in(broker, query='Work')
    assert response['ok'] is False and response['delivery'] == 'not-started' and '@gmail.com' in response['error']
    assert sign_in_requests() == []


def test_google_sign_in_refusals(device_file):
    broker = make_broker(device_file, {'context': context(**GMS), 'fields': GMS_FIELDS}, entries=GMAIL)
    assert google_sign_in(broker, query='other@gmail') == {'ok': False, 'error': ORIGIN_MISMATCH, 'delivery': 'not-started'}
    speaking = make_broker(device_file, {'context': context(**GMS, speak_password=True), 'fields': []}, entries=GMAIL)
    assert 'speak_password 0' in google_sign_in(speaking, query='synthetic@gmail')['error']
    assert sign_in_requests() == []


@pytest.mark.parametrize('answer, expected', [
    ({'ok': True, 'steps': ['email'], 'stopped_at': 'password', 'protocol': 1},
     {'ok': True, 'filled': ['email'], 'stopped_at': 'password', 'target_delivery': DELIVERY}),
    ({'ok': True, 'steps': ['email'], 'stopped_at': 'password', 'uncertain': True, 'protocol': 1},
     {'ok': False, 'delivery': 'uncertain'}),
    ({'ok': False, 'error': 'Google sign-in screen changed', 'protocol': 1}, {'ok': False, 'delivery': 'not-started'}),
    ({'ok': False, 'error': 'helper failed: IllegalStateException', 'protocol': 1}, {'ok': False, 'delivery': 'uncertain'}),
])
def test_google_sign_in_reports_where_it_stopped(device_file, answer, expected):
    broker = make_broker(device_file, {'context': context(**GMS), 'fields': GMS_FIELDS, 'sign_in': answer}, entries=GMAIL)
    response = google_sign_in(broker, query='synthetic@gmail')
    assert {k: response[k] for k in expected} == expected


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
    """A Chrome with one visible tab at URL and a frozen tab on another site."""

    def __init__(self, url, shown=True, focused=True, holds=None):
        self.url, self.shown, self.focused, self.holds = url, shown, focused, holds
        self.calls = []
        self.closed = False
        self.objects = {}

    def call(self, method, params=None, session=None, *, timeout=3):
        self.calls.append((method, params))
        if method == 'Target.getTargets':
            return {'targetInfos': [{'targetId': 'T1', 'type': 'page', 'url': self.url},
                                    {'targetId': 'T2', 'type': 'page', 'url': 'https://evil.example/'}]}
        if method == 'Target.attachToTarget':
            return {'sessionId': 'S-' + params['targetId']}
        if method == 'Page.getFrameTree':
            return {'frameTree': {'frame': {'id': 'F1', 'url': self.url}}}
        if method == 'Page.createIsolatedWorld':
            return {'executionContextId': 5}
        if method == 'Runtime.evaluate':
            expression = params['expression']
            if expression == android_route.PAGE_STATE:
                return {'result': {'value': {'url': self.url, 'shown': self.shown, 'secure': True}}}
            if expression == 'performance.now()':
                return {'result': {'value': 1000.0}}
            if expression.startswith(android_route.PAGE_FIELD):
                selector = json.loads('[' + expression[len(android_route.PAGE_FIELD) + 1:-1] + ']')[0]
                if selector == '#missing':
                    return {'exceptionDetails': {}}
                object_id = 'OBJ%d' % len(self.objects)
                self.objects[object_id] = selector
                return {'result': {'type': 'object', 'objectId': object_id}}
            if expression == android_route.PAGE_FIELDS:
                return {'result': {'value': [{'selector': '#app_totp', 'type': 'text', 'focused': True}]}}
        if method == 'Runtime.callFunctionOn':
            declaration = params['functionDeclaration']
            if 'this.focused' in declaration:
                return {'result': {'value': self.focused}}
            if 'this.prepare' in declaration:
                return {'result': {'value': True}}
            if 'this.length' in declaration:
                return {'result': {'value': self.holds}}
            return {'result': {}}
        raise AssertionError(method)

    def close(self):
        self.closed = True


CHROME = dict(package='com.android.chrome', activity=android_route.CHROME_ACTIVITIES[1], lineage=(GOOGLE_SIGNER,))


def chrome_broker(device_file, cdp, address_bar='example.com', type_answer=None):
    scene = {'context': context(**CHROME, address_bar=address_bar), 'fields': []}
    if type_answer is not None:
        scene['type'] = type_answer
    broker = make_broker(device_file, scene)
    broker.android.cdp_factory = lambda adb: cdp
    return broker, scene


def test_chrome_page_fill_types_values_that_devtools_never_carries(device_file):
    cdp = FakeCDP('https://example.com/sessions/two-factor/app')
    broker, scene = chrome_broker(device_file, cdp)
    inspected = broker.dispatch({'action': 'android-inspect', 'device': 'phone'})
    assert inspected['site'] == {'origin': 'https://example.com', 'source': 'chrome'}
    assert inspected['fields'][0]['field'] == '#app_totp'
    # Only the tab with the address bar's host is asked: frozen tabs answer nothing.
    assert ('Target.attachToTarget', {'targetId': 'T2', 'flatten': True}) not in cdp.calls

    pinned = pin(broker, mode='totp', field='#app_totp')
    assert pinned['ok'] and pinned['android_delivery'] == CHROME_DELIVERY and pinned['origin'] == 'https://example.com'
    assert fill(broker, 'Other', pinned['target'], mode='totp')['error'] == ORIGIN_MISMATCH
    assert cdp.closed and 'typed' not in scene

    cdp.closed, cdp.holds = False, 6
    pinned = pin(broker, mode='totp', field='#app_totp')
    response = fill(broker, 'synthetic-user', pinned['target'], mode='totp')
    assert response == {'ok': True, 'filled': 'totp', 'target_delivery': CHROME_DELIVERY}
    [code] = scene['typed']
    [request] = [r for r in FakeAdb.requests if r['op'] == 'type']
    assert request['address_bar'] == 'example.com' and request['task_id'] == 12
    assert code not in json.dumps(cdp.calls) and cdp.closed


def test_chrome_login_types_both_values_and_devtools_never_sees_them(device_file):
    cdp = FakeCDP('https://example.com/login', holds=None)
    broker, scene = chrome_broker(device_file, cdp)
    pinned = pin(broker, mode='login', field='#password', username_field='#login')
    assert pinned['ok'] and list(cdp.objects.values()) == ['#login', '#password']
    lengths = iter([len('synthetic-user'), len(SECRET)])
    cdp.holds = None
    original = cdp.call

    def call(method, params=None, session=None, *, timeout=3):
        if method == 'Runtime.callFunctionOn' and 'this.length' in params['functionDeclaration']:
            return {'result': {'value': next(lengths)}}
        return original(method, params, session, timeout=timeout)
    cdp.call = call
    assert fill(broker, 'synthetic-user', pinned['target'], mode='login')['ok']
    assert scene['typed'] == ['synthetic-user', SECRET]
    assert SECRET not in json.dumps(cdp.calls)


@pytest.mark.parametrize('holds, type_answer, delivery', [
    # The page cleared or cut the typed value: it may have seen part of it.
    (3, None, 'uncertain'),
    (None, {'ok': True, 'complete': False, 'started': False, 'protocol': 1}, 'not-started'),
    (None, {'ok': True, 'complete': False, 'started': True, 'protocol': 1}, 'uncertain'),
    (None, {'ok': False, 'error': 'Chrome is not the focused app in the pinned task', 'protocol': 1}, 'not-started'),
])
def test_chrome_typing_failures_report_whether_delivery_started(device_file, holds, type_answer, delivery):
    cdp = FakeCDP('https://example.com/login', holds=holds)
    broker, _ = chrome_broker(device_file, cdp, type_answer=type_answer)
    response = fill(broker, 'synthetic-user', pin(broker, mode='password', field='#password')['target'])
    assert response['ok'] is False and response['delivery'] == delivery


@pytest.mark.parametrize('kwargs, address_bar, field, error', [
    (dict(shown=False), 'example.com', '#code', 'no single visible'),
    (dict(), 'other.example', '#code', 'no single visible'),
    (dict(focused=False), 'example.com', '#code', 'tap the field first'),
    (dict(), 'example.com', '#missing', 'page code field refused'),
    (dict(), None, '#code', 'address bar is not shown'),
])
def test_chrome_page_refusals(device_file, kwargs, address_bar, field, error):
    broker, _ = chrome_broker(device_file, FakeCDP('https://example.com/login', **kwargs), address_bar=address_bar)
    assert error in pin(broker, mode='totp', field=field)['error']


def test_chrome_address_bar_hides_www_and_shows_unicode_hosts(device_file):
    broker, _ = chrome_broker(device_file, FakeCDP('https://www.example.com/login'), address_bar='example.com')
    assert pin(broker, mode='totp', field='#code')['origin'] == 'https://www.example.com'
    assert android_route._authority_matches('example.com', ('https', 'www.example.com', 443))
    assert not android_route._authority_matches('www.example.com', ('https', 'example.com', 443))
    assert not android_route._authority_matches('example.com', ('https', 'wwwexample.com', 443))
    assert android_route._authority_matches('bücher.de', ('https', 'xn--bcher-kva.de', 443))
    assert not android_route._authority_matches('bucher.de', ('https', 'xn--bcher-kva.de', 443))


def test_chrome_http_page_is_refused(device_file):
    broker, _ = chrome_broker(device_file, FakeCDP('http://example.com/login'), address_bar='example.com')
    assert 'no single visible' in pin(broker, mode='totp', field='#code')['error']


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

class FakeAdbServer:
    """An adb server on loopback that speaks the host protocol and shell v2; it records what it receives."""

    def __init__(self, answer):
        import socket as socket_module
        import threading
        self.answer = answer
        self.services, self.stdin = [], []
        self.listener = socket_module.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(4)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while True:
            try:
                connection, _ = self.listener.accept()
            except OSError:
                return
            with connection:
                try:
                    self.session(connection)
                except Exception:
                    pass

    def session(self, connection):
        read = lambda n: android_route._read_exact(connection, n)
        for _ in range(2):
            service = read(int(read(4), 16)).decode()
            self.services.append(service)
            connection.sendall(b'OKAY')
        data = b''
        while True:
            kind, payload = android_route._read_packet(connection)
            if kind == android_route.SHELL_STDIN:
                data += payload
            if kind == android_route.SHELL_CLOSE_STDIN:
                break
        self.stdin.append(data)
        output = ('AKDBX-ANDROID-RESULT ' + json.dumps({**self.answer, 'protocol': 1}) + '\n').encode()
        android_route._send_packet(connection, android_route.SHELL_STDOUT, b'noise\n' + output)
        android_route._send_packet(connection, android_route.SHELL_EXIT, b'\x00')

    def close(self):
        self.listener.close()


@pytest.mark.skipif(os.name == 'nt', reason='Linux peer check')
def test_values_reach_the_device_only_in_stdin_packets_of_the_verified_connection(tmp_path):
    server = FakeAdbServer({'ok': True, 'delivered': True, 'results': [{'accepted': True, 'confirmed': True}]})
    adb = tmp_path / 'adb'
    adb.write_text('#!/bin/sh\nexit 1\n')
    adb.chmod(0o700)
    try:
        device = android_route.Device('phone', str(adb), server.port, 'emulator-5584')
        runner = android_route.Adb(device)
        answer = runner.helper({'op': 'fill', 'fields': [{'value': SECRET}]}, install=False)
        assert answer['ok'] is True
        assert server.services[0] == 'host:transport:emulator-5584'
        assert server.services[1].startswith('shell,v2,raw:p=/data/local/tmp/akdbx/helper-')
        assert android_route.HELPER_SHA256 in server.services[1] and SECRET not in ''.join(server.services)
        assert SECRET.encode() in server.stdin[0]
    finally:
        server.close()


@pytest.mark.skipif(os.name == 'nt', reason='Linux peer check')
def test_a_helper_run_refuses_an_adb_port_of_another_account(tmp_path, monkeypatch):
    server = FakeAdbServer({'ok': True})
    try:
        runner = android_route.Adb(android_route.Device('phone', '/bin/true', server.port, 'emulator-5584'))

        def other_owner(connection):
            raise android_route.TargetError()
        monkeypatch.setattr('akdbx.browser_password.verify_peer', other_owner)
        with pytest.raises(AndroidError, match='another account'):
            runner.helper({'op': 'fill', 'fields': [{'value': SECRET}]}, install=False)
        assert server.stdin == []
    finally:
        server.close()


# ----- CLI --------------------------------------------------------------------

def caps():
    return {'ok': True, 'android_fill_protocol': 1, 'android_fill_delivery': DELIVERY}


def run_cli(argv, responses, capsys):
    from akdbx.cli import parser
    args = parser().parse_args(argv)
    sent = []

    def request(payload, timeout=None):
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


def test_cli_reports_a_used_handle_as_not_started(capsys):
    refusal = {'ok': False, 'error': 'unknown or expired handle; search again'}
    code, _, out = run_cli(['android', 'fill', 'a' * 64, '--target', 'b' * 64, '--mode', 'password'], [refusal], capsys)
    assert code == 1 and json.loads(out.out) == refusal and 'unconfirmed' not in out.err


def test_cli_google_sign_in_sends_no_value(capsys):
    receipt = {'ok': True, 'filled': ['email'], 'stopped_at': 'password', 'target_delivery': DELIVERY}
    code, sent, out = run_cli(['android', 'google-sign-in', 'a' * 64, '--device', 'phone', '--code'], [receipt], capsys)
    assert code == 0 and json.loads(out.out) == receipt
    assert set(sent[1]) == {'action', 'android_protocol', 'device', 'handle', 'code', 'start_deadline'} and sent[1]['code'] is True
