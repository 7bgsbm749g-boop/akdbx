"""Darwin proof with an isolated LaunchAgent, sockets and synthetic vault."""
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import uuid

import pytest

from akdbx import cli, launch_agent
from akdbx.broker import Broker
from akdbx.desktop_lock import watch_locks
from test_broker import Entry, RecordingTyper, Vault
from test_local_https import certificates, free_port, private_pair  # noqa: F401
from test_web_unlock import wait_for


pytestmark = pytest.mark.skipif(sys.platform != 'darwin', reason='requires macOS')


@pytest.mark.skipif(os.environ.get('AKDBX_MACOS_RUNNER') != '1', reason='disposable macOS GUI session only')
def test_distributed_screen_lock_closes_vault():
    from Foundation import NSDistributedNotificationCenter
    broker = Broker(Vault([Entry()]), RecordingTyper())
    with watch_locks(broker):
        wait_for(lambda: broker.lock_events == {'macos': 'listening'}, timeout=15)
        NSDistributedNotificationCenter.defaultCenter().postNotificationName_object_userInfo_deliverImmediately_(
            'com.apple.screenIsLocked', None, None, True)
        wait_for(lambda: broker.locked, timeout=10)


def test_launchagent_refuses_unowned_content_and_link(tmp_path):
    folder = tmp_path / 'LaunchAgents'
    folder.mkdir()
    plist = folder / 'org.akdbx.broker.plist'
    plist.write_bytes(plistlib.dumps({'Label': launch_agent.LABEL}))
    with pytest.raises(ValueError, match='not written by'):
        launch_agent.read(plist)
    plist.unlink()
    other = tmp_path / 'other'
    other.write_bytes(b'keep')
    plist.symlink_to(other)
    with pytest.raises(OSError):
        launch_agent.install(plist, b'bad', None)
    assert other.read_bytes() == b'keep'


def test_guided_setup_cdp_refusal_names_the_manual_route(tmp_path, monkeypatch, capsys):
    # CDP works on macOS from 0.50.1; only guided setup does not configure it.
    home = tmp_path / 'home'
    (home / 'Library').mkdir(parents=True)
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('XDG_CONFIG_HOME', str(home / 'config'))
    args = ['--socket', str(tmp_path / 'run' / 's'), 'setup', '--dry-run', '--json', '--skip', 'system',
            '--vault', str(tmp_path / 'vault.kdbx'), '--cdp-profile', str(tmp_path / 'cdp')]
    assert cli.main(args) == 2
    error = json.loads(capsys.readouterr().out)['error']
    assert error.startswith('guided setup does not configure the CDP route on macOS; omit --cdp-profile')
    assert '--password-browser-profile' in error and 'requires the extension route' not in error
    assert not (tmp_path / 'cdp').exists()


@pytest.mark.skipif(os.environ.get('AKDBX_MACOS_RUNNER') != '1', reason='disposable macOS GUI session only')
def test_guided_setup_launches_locked_broker_and_installs_hosts(tmp_path, monkeypatch, private_pair, capsys):
    from pykeepass import create_database
    from akdbx import browser_import, extension_host
    home = tmp_path / 'home'
    (home / 'Library').mkdir(parents=True)
    monkeypatch.setenv('AKDBX_LOCK_TIMEOUT', '30')
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('XDG_DATA_HOME', str(home / 'data'))
    monkeypatch.setenv('XDG_CONFIG_HOME', str(home / 'config'))
    label = 'org.akdbx.test.' + uuid.uuid4().hex
    monkeypatch.setattr(launch_agent, 'LABEL', label)
    vault = tmp_path / 'test vault.kdbx'
    create_database(str(vault), password='synthetic-only')
    vault.chmod(0o600)
    socket = tmp_path / 'run' / 's'
    origin = f'https://localhost:{free_port()}'
    options = ['--socket', str(socket), '--unlock-origin', origin]
    args = [*options, 'setup', '--yes', '--json', '--vault', str(vault),
            '--tls-cert', str(private_pair[0]), '--tls-key', str(private_pair[1]),
            '--start-at-login', '--browser', 'chrome', '--capture-host', '--capture-extension-id', 'a'*32]
    job = f'gui/{os.getuid()}/{label}'
    plist = home / 'Library' / 'LaunchAgents' / (label + '.plist')
    try:
        assert cli.main([*args, '--dry-run']) == 0
        capsys.readouterr()
        assert not plist.exists()
        code = cli.main(args)
        result = json.loads(capsys.readouterr().out)
        assert code == 0, {s: v.get('errors', v.get('error')) for s, v in result['stages'].items()}
        assert result['broker']['running'] is True and result['broker']['locked'] is True
        assert result['stages']['system']['platform'] == 'macos'
        arguments = plistlib.loads(plist.read_bytes())['ProgramArguments']
        assert '--no-print-unlock-link' in arguments
        assert arguments[arguments.index('--lock-timeout') + 1] == '30'
        directory = home / 'Library/Application Support/Google/Chrome/NativeMessagingHosts'
        assert (directory / (extension_host.HOST_NAME + '.json')).is_file()
        manifest = json.loads((directory / (browser_import.HOST_NAME + '.json')).read_text())
        launcher = Path(manifest['path'])
        assert launcher.is_file()
        assert launcher.read_text().startswith('#!/bin/sh')
        assert browser_import.load_config(browser_import.config_path())['socket'] == str(socket.with_name('u'))
        assert cli.main(args) == 0
        assert json.loads(capsys.readouterr().out)['stages']['login']['state'] == 'done'
        # A second Chromium browser that has run once reuses the configuration and launcher.
        (home / 'Library/Application Support/Microsoft Edge').mkdir(mode=0o700)
        assert cli.main([*args, '--capture-browser', 'edge']) == 0
        assert json.loads(capsys.readouterr().out)['stages']['features']['state'] == 'changed'
        edge = home / 'Library/Application Support/Microsoft Edge/NativeMessagingHosts'
        assert json.loads((edge / (browser_import.HOST_NAME + '.json')).read_text()) == manifest
        # An existing configuration for the original origin cannot count as ready for another origin.
        stale = [f'https://localhost:{free_port()}' if arg == origin else arg for arg in args]
        assert cli.main(stale) != 0
        assert json.loads(capsys.readouterr().out)['stages']['features']['state'] == 'failed'
    finally:
        subprocess.run(['/bin/launchctl', 'bootout', job], capture_output=True, timeout=15)

