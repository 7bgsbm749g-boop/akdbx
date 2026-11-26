"""Actual Safari automation of the built native extension on a disposable Mac.

This first gate verifies native attachment through Safari, beyond the separate
sandboxed app/XPC and packaging tests. It never uses a real vault or account.
"""
import json
import os
from pathlib import Path
import platform
import plistlib
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

if sys.platform != 'darwin' or os.environ.get('AKDBX_REQUIRE_SAFARI_BROWSER') != '1':
    pytest.skip('requires the disposable actual Safari CI job', allow_module_level=True)

from akdbx import safari
from test_safari_native import local_broker  # noqa: F401


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
                                 f'http://127.0.0.1:{observer.server_port}/attached')
        log = tmp_path / 'safari-ui-xcode.log'
        with log.open('wb') as stream:
            result = subprocess.run(['xcodebuild', '-project', str(project), '-scheme', 'SafariUI',
                '-destination', 'platform=macOS', '-derivedDataPath', str(tmp_path / 'ui-derived'),
                '-parallel-testing-enabled', 'NO', '-maximum-test-execution-time-allowance', '180',
                'test'], stdout=stream, stderr=subprocess.STDOUT, timeout=600)
        assert result.returncode == 0, log.read_text(errors='replace')[-20000:]
        assert observed.is_set(), 'Xcode UI test did not observe a real Safari native broker channel'
    finally:
        observer.shutdown()
        observer.server_close()
        worker.join(5)
        log = tmp_path / 'safari-ui-xcode.log'
        if log.exists():
            content = log.read_text(errors='replace')
            for value in sorted({value for value in os.environ.values() if len(value) >= 12}, key=len, reverse=True):
                content = content.replace(value, '<CI value>')
            log.write_text(content)
        startup_diagnostics(tmp_path)
