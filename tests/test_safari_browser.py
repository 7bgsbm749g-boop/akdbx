"""Actual Safari automation of the built native extension on a disposable Mac.

This first gate verifies native attachment through Safari, beyond the separate
sandboxed app/XPC and packaging tests. It never uses a real vault or account.
"""
import json
import os
from pathlib import Path
import platform
import plistlib
import secrets
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

if sys.platform != 'darwin' or os.environ.get('AKDBX_REQUIRE_SAFARI_BROWSER') != '1':
    pytest.skip('requires the disposable actual Safari CI job', allow_module_level=True)

from akdbx import safari
from test_safari_native import local_broker  # noqa: F401


def prepare_disposable_ci_password():
    """Set a throwaway password only on GitHub's disposable hosted Mac.

    Safari's unsigned-extension authorization needs the logged-in account's
    password. Never read the image's existing password or its credential store.
    """
    from pwd import getpwuid
    assert os.environ.get('GITHUB_ACTIONS') == 'true'
    assert os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted', 'refusing a persistent or self-hosted Mac'
    account = getpwuid(os.getuid()).pw_name
    assert account == 'runner', 'refusing to alter an ordinary user account'
    password = secrets.token_hex(24)
    result = subprocess.run(['sudo', '-n', '/usr/bin/dscl', '.', '-passwd', '/Users/' + account, password],
                            capture_output=True, timeout=30)
    assert result.returncode == 0, f'disposable CI account password setup failed (exit {result.returncode})'
    return password


def redact_log(path, password):
    if path.exists():
        content = path.read_text(errors='replace')
        for value in sorted({password, *(value for value in os.environ.values() if len(value) >= 12)},
                            key=len, reverse=True):
            content = content.replace(value, '<CI value>')
        path.write_text(content)


def retain_ui_attachments(folder):
    """Keep only our named UI captures, not XCTest's synthesized input events."""
    manifest = folder / 'manifest.json'
    if not manifest.exists():
        # Fail closed if the exporter did not provide an attachment index.
        import shutil
        shutil.rmtree(folder, ignore_errors=True)
        return
    records = json.loads(manifest.read_text())
    keep = set()
    for record in records:
        for attachment in record.get('attachments', []):
            name = attachment.get('suggestedHumanReadableName', '')
            filename = attachment.get('exportedFileName', '')
            if name.startswith('safari-ui-') and Path(filename).name == filename and Path(filename).suffix in ('.txt', '.png'):
                keep.add(filename)
    for path in folder.iterdir():
        if path.is_file() and path.name not in keep:
            path.unlink()


def startup_diagnostics(folder):
    """Bounded diagnostics from this disposable, account-free browser test."""
    screenshot = folder / 'safari-startup.png'
    capture = subprocess.run(['/usr/sbin/screencapture', '-x', str(screenshot)],
                             capture_output=True, timeout=10)
    processes = subprocess.run(['pgrep', '-l', '-x', 'Safari'], capture_output=True, text=True, timeout=10)
    (folder / 'safari-startup.json').write_text(json.dumps(dict(
        macos=platform.mac_ver()[0], architecture=platform.machine(), safari_processes=processes.stdout[:2048],
        screenshot_status=capture.returncode), indent=2))


def test_actual_safari_loads_the_native_app_and_attaches_to_its_local_broker(tmp_path, local_broker):
    # SafariDriver's temporary-resource installation cannot associate the
    # native app handler. Exercise the packaged extension in normal Safari.
    from safari_ui_project import create_project

    ci_password = prepare_disposable_ci_password()
    observed = threading.Event()

    class Observer(BaseHTTPRequestHandler):
        def do_GET(self):
            attached = self.path == '/attached' and any(
                channel.browser == 'safari' for channel in list(local_broker.extension.channels.values()))
            if attached:
                observed.set()
            data = b'attached' if attached else b'waiting'
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    observer = ThreadingHTTPServer(('127.0.0.1', 0), Observer)
    worker = threading.Thread(target=observer.serve_forever, daemon=True)
    worker.start()
    try:
        info = plistlib.loads(Path('/Applications/Safari.app/Contents/Info.plist').read_bytes())
        print('Native Safari UI runtime: ' + json.dumps(dict(macos=platform.mac_ver()[0],
              architecture=platform.machine(), safari=info.get('CFBundleShortVersionString'))))
        app = safari.build_app(tmp_path / 'Safari.app', unlock_origin='https://localhost:9443')
        subprocess.run(['open', '-g', str(app)], check=True, timeout=30)
        project = create_project(tmp_path / 'safari-ui',
                                 f'http://127.0.0.1:{observer.server_port}/attached',
                                 authorization_password=ci_password)
        log = tmp_path / 'safari-ui-xcode.log'
        with log.open('wb') as stream:
            result = subprocess.run(['xcodebuild', '-project', str(project), '-scheme', 'SafariUI',
                '-destination', 'platform=macOS', '-derivedDataPath', str(tmp_path / 'ui-derived'),
                '-resultBundlePath', str(tmp_path / 'safari-ui.xcresult'),
                '-parallel-testing-enabled', 'NO', '-maximum-test-execution-time-allowance', '180',
                'test'], stdout=stream, stderr=subprocess.STDOUT, timeout=600)
        redact_log(log, ci_password)
        assert result.returncode == 0, log.read_text(errors='replace')[-20000:]
        assert observed.is_set(), 'Xcode UI test did not observe a real Safari native broker channel'
    finally:
        observer.shutdown()
        observer.server_close()
        worker.join(5)
        bundle = tmp_path / 'safari-ui.xcresult'
        if bundle.exists():
            exported = subprocess.run(['xcrun', 'xcresulttool', 'export', 'attachments',
                '--path', str(bundle), '--output-path', str(tmp_path / 'safari-ui-attachments')],
                capture_output=True, timeout=30)
            if exported.returncode:
                print('UI attachment export failed: ' + exported.stderr.decode(errors='replace')[-2048:])
            retain_ui_attachments(tmp_path / 'safari-ui-attachments')
        log = tmp_path / 'safari-ui-xcode.log'
        redact_log(log, ci_password)
        startup_diagnostics(tmp_path)
