"""Actual Safari automation of the built native extension on a disposable Mac.

This first gate verifies native attachment through Safari, beyond the separate
sandboxed app/XPC and packaging tests. It never uses a real vault or account.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.parse import quote

import pytest

if sys.platform != 'darwin' or os.environ.get('AKDBX_REQUIRE_SAFARI_BROWSER') != '1':
    pytest.skip('requires the disposable actual Safari CI job', allow_module_level=True)

from selenium import webdriver
from selenium.webdriver.safari.service import Service

from akdbx import safari
from test_safari_native import local_broker  # noqa: F401


def test_actual_safari_loads_the_native_app_and_attaches_to_its_local_broker(tmp_path, local_broker):
    app = safari.build_app(tmp_path / 'Safari.app', unlock_origin='https://localhost:9443')
    subprocess.run(['open', '-g', str(app)], check=True, timeout=30)
    service = Service(executable_path='/usr/bin/safaridriver', log_output=str(tmp_path / 'safaridriver.log'))
    driver = None
    attempts = []
    try:
        driver = webdriver.Safari(service=service)
        driver.set_page_load_timeout(20)
        driver.set_script_timeout(10)
        print('Safari automation capabilities: ' + json.dumps(driver.capabilities, sort_keys=True))
        driver.command_executor.add_command('installWebExtension', 'POST', '/session/$sessionId/webextension')
        driver.command_executor.add_command('uninstallWebExtension', 'DELETE',
                                            '/session/$sessionId/webextension/$extensionId')
        driver.get('about:blank')
        appex, = (app / 'Contents/PlugIns').glob('*.appex')
        # Verify which official install form preserves the native app handler.
        # A resource-only load counts only if Safari really attaches to the broker.
        for candidate in (app, appex, appex / 'Contents/Resources'):
            installed = None
            try:
                installed = driver.execute('installWebExtension', {'type': 'path', 'path': str(candidate)})['value']
                attempts.append(dict(path=candidate.name, installed=installed))
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    if any(channel.browser == 'safari' for channel in list(local_broker.extension.channels.values())):
                        driver.save_screenshot(str(tmp_path / 'actual-safari-native.png'))
                        return
                    time.sleep(.1)
                attempts[-1]['native_attached'] = False
            except Exception as error:
                attempts.append(dict(path=candidate.name, error=type(error).__name__, detail=str(error)[:1200]))
            finally:
                if installed:
                    driver.execute('uninstallWebExtension', {'extensionId': quote(installed, safe='')})
        print('Native installation attempts: ' + json.dumps(attempts, sort_keys=True))
        pytest.fail('Safari did not attach its native extension to the synthetic local broker')
    finally:
        if driver:
            driver.quit()
        service.stop()
