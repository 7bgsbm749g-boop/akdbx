"""Exercise real per-user path and registry writes using a disposable host name."""
import argparse
import json
import os
from pathlib import Path
import sys
import uuid

import pytest

from akdbx import extension_host as host


@pytest.fixture
def home(tmp_path, monkeypatch):
    for name in ('HOME', 'USERPROFILE', 'LOCALAPPDATA', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME'):
        monkeypatch.setenv(name, str(tmp_path / name))
    monkeypatch.delenv('CHROME_CONFIG_HOME', raising=False)
    monkeypatch.setattr(host, 'HOST_NAME', 'org.akdbx.test_' + uuid.uuid4().hex)
    return tmp_path


@pytest.mark.parametrize(('browser', 'linux', 'mac', 'windows'), [
    ('chromium', 'chromium', 'Chromium', r'Software\Chromium'),
    ('brave', 'BraveSoftware/Brave-Browser', 'Google/Chrome', r'Software\Google\Chrome'),
])
@pytest.mark.parametrize('custom', [False, True])
def test_install_reinstall_and_remove(home, browser, linux, mac, windows, custom):
    parser = argparse.ArgumentParser()
    host.add_parser(parser.add_subparsers())
    args = ['extension', 'install', '--browser', browser]
    directory = home / 'custom location' if custom else None
    if custom:
        args += ['--manifest-dir', str(directory)]
    assert parser.parse_args(args).manifest_dir == directory
    where = host.install(browser, manifest_dir=directory)
    try:
        manifest = Path(where['manifest'])
        launcher = Path(where['launcher'])
        descriptor = json.loads(manifest.read_bytes())
        assert descriptor['name'] == host.HOST_NAME
        assert descriptor['allowed_origins'] == [host.EXTENSION_ORIGIN]
        assert Path(descriptor['path']) == launcher and launcher.is_file()
        if os.name == 'nt':
            import winreg
            key = windows + '\\NativeMessagingHosts\\' + host.HOST_NAME
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as handle:
                assert winreg.QueryValueEx(handle, '') == (str(manifest), winreg.REG_SZ)
            expected_dir = directory or home / 'LOCALAPPDATA/akdbx/extension-host'
            if custom:
                from unittest.mock import Mock
                from akdbx.setup_cli import Setup
                setup = Mock(windows=True, socket_explicit=False, executable=sys.executable)
                assert Setup._install_host(setup, browser) == 'done'
                # An owned manifest may need its launcher restored after an upgrade.
                launcher.unlink()
                setup.akdbx_argv.side_effect = lambda *args: list(args)
                setup.change.side_effect = lambda stage, detail, display, apply, **options: apply()
                Setup._install_host(setup, browser)
                setup._akdbx_ok.assert_called_once_with(
                    ['extension', 'install', '--browser', browser, '--manifest-dir', str(directory)])
                extended = Path('\\\\?\\' + str(directory))
                assert host.uninstall(browser, manifest_dir=directory)
                host.install(browser, manifest_dir=extended)
                assert Setup._install_host(setup, browser) == 'done'
                assert host.uninstall(browser, manifest_dir=extended)
                alternate = directory.with_name(directory.name.upper())
                assert Path(host.install(browser, manifest_dir=alternate)['manifest']).samefile(manifest)
                assert not host.uninstall(browser)
                with pytest.raises(ValueError, match='registered'):
                    host.install(browser)
                assert launcher.is_file()
        else:
            default = (Path.home() / 'Library/Application Support' / mac if sys.platform == 'darwin'
                       else home / 'XDG_CONFIG_HOME' / linux)
            expected_dir = directory or default / 'NativeMessagingHosts'
        assert expected_dir == manifest.parent
        assert host.install(browser, manifest_dir=directory) == where
        if browser != where['registration_browser']:
            assert host.install(where['registration_browser'], manifest_dir=directory) == where
        assert host.launcher_state(browser) == 'current'
        assert len(host.refresh()) == 1
    finally:
        host.uninstall(browser, manifest_dir=(directory.with_name(directory.name.upper())
                                              if custom and os.name == 'nt' else directory))
    assert not manifest.exists() and not launcher.exists()
    if os.name == 'nt':
        with pytest.raises(FileNotFoundError):
            winreg.OpenKey(winreg.HKEY_CURRENT_USER, key)


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux desktop session')
def test_confined_firefox_without_bridge_writes_nothing(home, monkeypatch):
    monkeypatch.setenv('PATH', str(home))
    for package in ('snap', 'flatpak'):
        with pytest.raises(ValueError, match=f'Firefox {package} requires'):
            host.install('firefox', firefox_package=package)
    assert not host.paths('firefox')['launcher'].exists()
    assert not host.paths('firefox')['manifest'].exists()


def test_setup_detects_each_supported_browser(home):
    from types import SimpleNamespace
    from akdbx import setup_cli

    setup = SimpleNamespace(home=home, windows=os.name == 'nt', env={'LOCALAPPDATA': str(home)},
                            which=lambda name: None)
    if os.name == 'nt':
        executables = ['Mozilla Firefox/firefox.exe', 'imput/Helium/Application/chrome.exe',
                       'Google/Chrome/Application/chrome.exe', 'Microsoft/Edge/Application/msedge.exe',
                       'Chromium/Application/chrome.exe', 'BraveSoftware/Brave-Browser/Application/brave.exe']
        setup.env['ProgramFiles'] = str(home)
    elif sys.platform == 'darwin':
        executables = [f'Applications/{bundle}.app/Contents/MacOS/{exe}' for bundle, exe in (
            ('Firefox', 'firefox'), ('Helium', 'Helium'), ('Google Chrome', 'Google Chrome'),
            ('Microsoft Edge', 'Microsoft Edge'), ('Chromium', 'Chromium'), ('Brave Browser', 'Brave Browser'))]
    else:
        executables = ['firefox', 'helium', 'google-chrome', 'microsoft-edge', 'chromium', 'brave-browser']
        setup.which = lambda name: str(home / name) if (home / name).is_file() else None
    for relative in executables:
        exe = home / relative
        exe.parent.mkdir(parents=True, exist_ok=True)
        exe.touch()
    assert set(setup_cli.Setup._browsers(setup)) == set(host.BROWSERS)


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux desktop session')
@pytest.mark.parametrize(('bus', 'interface', 'package'), [
    ('org.freedesktop.NativeMessagingProxy', 'org.freedesktop.NativeMessagingProxy', 'flatpak'),
    ('org.freedesktop.portal.Desktop', 'org.freedesktop.portal.WebExtensions', 'snap'),
])
def test_confined_firefox_installs_with_bridge(home, monkeypatch, bus, interface, package):
    probe = home / 'gdbus'
    probe.write_text(f'''#!/bin/sh
[ "$4" = "{bus}" ] || exit 1
echo '<node><interface name="{interface}"></interface></node>'
''')
    probe.chmod(0o700)
    monkeypatch.setenv('PATH', str(home))
    where = host.install('firefox', firefox_package=package)
    manifest = json.loads(Path(where['manifest']).read_bytes())
    assert manifest['allowed_extensions'] == [host.FIREFOX_EXTENSION_ID]
    assert Path(manifest['path']).is_file()
