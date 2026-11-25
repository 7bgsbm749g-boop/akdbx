"""Real signed/sandboxed Swift IPC and Xcode app builds on a disposable Mac.

Opt in with AKDBX_REQUIRE_SAFARI_NATIVE=1. This gate refuses an existing akdbx
default directory, so it cannot replace an installed broker's runtime state.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import plistlib
import select
import shutil
import subprocess
import sys
import threading
import time

import pytest

if sys.platform != 'darwin' or os.environ.get('AKDBX_REQUIRE_SAFARI_NATIVE') != '1':
    pytest.skip('requires an explicitly selected disposable native Safari Mac', allow_module_level=True)

from akdbx import extension_host, macos, safari
from akdbx.broker import Broker, serve
from akdbx.extension_route import b64url


def checked(argv, *, timeout=120):
    result = subprocess.run(argv, capture_output=True, timeout=timeout)
    assert result.returncode == 0, (result.stdout + result.stderr)[-8192:].decode(errors='replace')
    return result


@pytest.fixture(scope='module')
def helper(tmp_path_factory):
    folder = tmp_path_factory.mktemp('swift')
    source = folder / 'BrokerBridge.swift'
    # Instrument only this disposable source copy. The shipped handler keeps
    # generic errors; CI needs the rejected operation and errno to diagnose
    # actual sandbox failures without removing any trust checks.
    instrumented = safari.assets().joinpath('BrokerBridge.swift').read_text()
    for kind in ('refused', 'unavailable'):
        instrumented = instrumented.replace('throw BridgeError.' + kind,
                                            'throw NativeProbeFailure(line: #line, code: errno)')
    instrumented = instrumented.replace('"error": "local broker unavailable"',
                                        '"error": "local broker unavailable (\\(error))"')
    source.write_text(instrumented)
    entitlement = folder / 'native.entitlements'
    entitlement.write_bytes(safari.assets().joinpath('Extension.entitlements').read_bytes())
    app = folder / 'NativeLab.app'
    executable = app / 'Contents/MacOS'
    executable.mkdir(parents=True)
    binary = executable / 'akdbx-safari-native-test'
    (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({
        'CFBundleIdentifier': 'org.akdbx.safari.native-test',
        'CFBundleExecutable': binary.name, 'CFBundleName': 'NativeLab',
        'CFBundlePackageType': 'APPL', 'CFBundleVersion': '1',
        'LSMinimumSystemVersion': '14.0', 'LSBackgroundOnly': True,
    }))
    checked(['xcrun', 'swiftc', '-parse-as-library', str(source),
             str(Path(__file__).with_name('safari_bridge_main.swift')), '-framework', 'Foundation',
             '-framework', 'Security', '-o', str(binary)])
    checked(['codesign', '--force', '--sign', '-', '--identifier', 'org.akdbx.safari.native-test',
             '--entitlements', str(entitlement), str(app)])
    checked(['codesign', '--verify', '--strict', str(app)])
    return binary


@contextmanager
def running_helper(binary):
    process = subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        def call(message, *, profile='normal'):
            data = json.dumps(dict(message=message, profile=profile)).encode() + b'\n'
            process.stdin.write(data)
            process.stdin.flush()
            result, deadline = bytearray(), time.monotonic() + 10
            while b'\n' not in result:
                left = deadline - time.monotonic()
                assert left > 0 and select.select([process.stdout], [], [], left)[0], 'native bridge timed out'
                chunk = os.read(process.stdout.fileno(), 66049)
                assert chunk, 'native bridge exited before its response'
                result.extend(chunk)
                assert len(result) <= 66049, 'native bridge response exceeds limit'
            return json.loads(result)
        yield call
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()


@pytest.fixture
def local_broker():
    from pwd import getpwuid
    app = Path(getpwuid(os.getuid()).pw_dir) / 'Library/Application Support/akdbx'
    if app.exists() or app.is_symlink():
        raise RuntimeError('native Safari CI requires a clean default akdbx directory; refusing existing state')
    endpoint = app / 'run/s'
    macos.prepare_runtime(endpoint, create_ancestors=True)
    broker = Broker(None, macos.NoWindowDelivery())
    stop = threading.Event()
    errors = []

    def run():
        try:
            serve(endpoint, broker, stop)
        except Exception as error:
            errors.append(type(error).__name__)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    try:
        deadline = time.monotonic() + 5
        while not endpoint.exists() and time.monotonic() < deadline and not errors:
            time.sleep(0.02)
        assert endpoint.exists() and not errors
        yield broker
    finally:
        broker.extension.close()
        stop.set()
        worker.join(5)
        broker.unlock_notifications.close()
        assert not worker.is_alive() and not errors
        shutil.rmtree(app)


def hello():
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    point = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return dict(type='hello', protocol=1, public_key=b64url(point), version=extension_host.built_version())


def test_sandboxed_native_bridge_attaches_and_preserves_profile_isolation(helper, local_broker):
    with running_helper(helper) as call:
        initial_fds = call(dict(op='test-fd-count'))['count']
        for _ in range(8):
            opened = call(dict(op='open', hello=hello()), profile='profile-a')
            if not opened['ok']:
                opened['test_runtime_probe'] = call(dict(op='test-runtime-probe'))
                print(json.dumps(opened, sort_keys=True))
            assert opened['ok'], opened
            token = opened['session']
            assert call(dict(op='read', session=token), profile='profile-b')['ok'] is False
            attached = call(dict(op='read', session=token), profile='profile-a')
            assert attached['ok'] and attached['message']['type'] == 'attached'
            assert call(dict(op='write', session=token, message=dict(type='request', id='s', op='state')),
                        profile='profile-a')['ok']
            response = call(dict(op='read', session=token), profile='profile-a')
            assert response['ok'] and response['message']['type'] == 'response'
            assert response['message']['id'] == 's'
            assert call(dict(op='close', session=token), profile='profile-a')['ok']
            assert call(dict(op='read', session=token), profile='profile-a')['ok'] is False
        assert call(dict(op='test-fd-count'))['count'] <= initial_fds + 1


def test_native_helper_is_actually_sandboxed(helper, tmp_path):
    forbidden = tmp_path / 'synthetic-outside-runtime.txt'
    forbidden.write_text('synthetic sandbox probe, no secret')
    assert checked([str(helper), '--probe-denied', str(forbidden)]).stdout.strip() == b'denied'


@pytest.fixture(scope='module')
def xpc_helper(tmp_path_factory):
    folder = tmp_path_factory.mktemp('xpc')
    app = folder / 'XPCLab.app'
    client = app / 'Contents/MacOS/xpc-client'
    service = app / 'Contents/XPCServices/org.akdbx.safari.bridge-probe.xpc'
    server = service / 'Contents/MacOS/xpc-service'
    for path in (client, server):
        path.parent.mkdir(parents=True)
    for bundle, binary, identifier, kind in (
        (app, client, 'org.akdbx.safari.xpc-test', 'APPL'),
        (service, server, 'org.akdbx.safari.bridge-probe', 'XPC!'),
    ):
        info = dict(CFBundleIdentifier=identifier, CFBundleExecutable=binary.name,
                    CFBundleName=binary.name, CFBundlePackageType=kind, CFBundleVersion='1',
                    LSMinimumSystemVersion='14.0', LSBackgroundOnly=True)
        if kind == 'XPC!':
            info['XPCService'] = dict(ServiceType='Application')
        (bundle / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
    protocol = Path(__file__).with_name('safari_xpc_protocol.swift')
    core = folder / 'BrokerBridge.swift'
    core.write_bytes(safari.assets().joinpath('BrokerBridge.swift').read_bytes())
    checked(['xcrun', 'swiftc', '-parse-as-library', str(protocol), str(core),
             str(Path(__file__).with_name('safari_xpc_service.swift')), '-framework', 'Security', '-o', str(server)])
    checked(['xcrun', 'swiftc', '-parse-as-library', str(protocol),
             str(Path(__file__).with_name('safari_xpc_client.swift')), '-o', str(client)])
    checked(['codesign', '--force', '--sign', '-', str(service)])
    entitlements = folder / 'client.entitlements'
    entitlements.write_bytes(plistlib.dumps({'com.apple.security.app-sandbox': True}))
    checked(['codesign', '--force', '--sign', '-', '--entitlements', str(entitlements), str(app)])
    checked(['codesign', '--verify', '--strict', '--deep', str(app)])
    return client


def test_sandboxed_client_reaches_local_broker_through_its_embedded_xpc_service(xpc_helper, local_broker):
    with running_helper(xpc_helper) as call:
        opened = call(dict(op='open', hello=hello()), profile='xpc-profile')
        assert opened['ok'], opened
        token = opened['session']
        attached = call(dict(op='read', session=token), profile='xpc-profile')
        assert attached['ok'] and attached['message']['type'] == 'attached'
        assert call(dict(op='close', session=token), profile='xpc-profile')['ok']


@pytest.mark.parametrize('grant', ['public-mode', 'ancestor-acl'])
def test_native_bridge_refuses_runtime_permission_grants(helper, local_broker, grant):
    from pwd import getpwuid
    app = Path(getpwuid(os.getuid()).pw_dir) / 'Library/Application Support/akdbx'
    runtime = app / 'run'
    try:
        if grant == 'public-mode':
            runtime.chmod(0o755)
        else:
            checked(['chmod', '+a', 'everyone allow read', str(app)])
        with running_helper(helper) as call:
            assert call(dict(op='open', hello=hello()))['ok'] is False
    finally:
        runtime.chmod(0o700)
        if grant == 'ancestor-acl':
            checked(['chmod', '-N', str(app)])


def test_native_bridge_refuses_a_symlinked_runtime_ancestor(helper, local_broker):
    from pwd import getpwuid
    app = Path(getpwuid(os.getuid()).pw_dir) / 'Library/Application Support/akdbx'
    moved = app.with_name('akdbx-safari-native-test')
    assert not moved.exists() and not moved.is_symlink()
    app.rename(moved)
    try:
        app.symlink_to(moved, target_is_directory=True)
        with running_helper(helper) as call:
            assert call(dict(op='open', hello=hello()))['ok'] is False
    finally:
        app.unlink()
        moved.rename(app)


def test_xcode_builds_the_native_safari_app(tmp_path):
    app = safari.build_app(tmp_path / 'Safari.app', unlock_origin='https://localhost:9443')
    checked(['codesign', '--verify', '--strict', '--deep', str(app)])
    appex, = (app / 'Contents/PlugIns').glob('*.appex')
    info = plistlib.loads((appex / 'Contents/Info.plist').read_bytes())
    assert info['NSExtension']['NSExtensionPointIdentifier'] == 'com.apple.Safari.web-extension'
    resource = appex / 'Contents/Resources/manifest.json'
    assert json.loads(resource.read_text())['browser_specific_settings']['safari']['strict_min_version'] == '26.0'
