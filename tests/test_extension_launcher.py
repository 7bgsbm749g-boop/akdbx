"""The host launcher runs the akdbx that installed it, also beside another akdbx (wrapper deployments).

On the VPS the CLI is a wrapper that puts a release folder first on ``sys.path`` and runs a virtual
environment's Python, whose own site-packages hold an older akdbx without ``extension_host``. A launcher
that ran ``python -I -m akdbx.extension_host`` imported that older akdbx and failed. Every interpreter and
akdbx here is synthetic: a new virtual environment without pip, a fake old ``akdbx`` package, and temporary
data and config folders. Nothing touches a real browser, broker or vault.
"""
import io
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import sys
import threading
import venv

import pytest

from akdbx import cli, extension_host
from akdbx.extension_route import EXTENSION_ORIGIN

pytestmark = pytest.mark.skipif(os.name == 'nt', reason='the Windows launcher runs the akdbx of its own Python')
KEY = 'A' * 87


@pytest.fixture
def homes(tmp_path, monkeypatch):
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path / 'config'))
    monkeypatch.delenv('CHROME_CONFIG_HOME', raising=False)
    return tmp_path


def dependency_folders():
    """The folders that hold this test interpreter's third-party packages (not akdbx itself)."""
    import cryptography
    import idna
    import pykeepass
    return sorted({str(Path(m.__file__).parent.parent) for m in (cryptography, idna, pykeepass)})


def wrapper_python(root, *, dependencies=True, old_host=False):
    """A new virtual environment whose site-packages hold a fake old akdbx before the dependencies.

    ``dependencies`` is True (all of them), False (none) or a tuple of top-level package names to link.
    """
    env = root / 'venv'
    venv.EnvBuilder(with_pip=False, symlinks=True).create(env)
    old = root / 'old-checkout'
    (old / 'akdbx').mkdir(parents=True)
    (old / 'akdbx' / '__init__.py').write_text('__version__ = "0.14.1"\n')
    if old_host:
        (old / 'akdbx' / 'extension_host.py').write_text('OLD = True\n')
        (old / 'akdbx' / 'cli.py').write_text('OLD = True\n')
    python = env / 'bin' / 'python'
    purelib = subprocess.run([str(python), '-I', '-c', 'import sysconfig;print(sysconfig.get_path("purelib"))'],
                             capture_output=True, text=True, timeout=60, check=True).stdout.strip()
    if isinstance(dependencies, tuple):
        chosen = root / 'some-deps'
        chosen.mkdir()
        for name in dependencies:
            (chosen / name).symlink_to(Path(__import__(name).__file__).parent)
        folders = [str(chosen)]
    else:
        folders = dependency_folders() if dependencies else []
    lines = [str(old)] + folders
    Path(purelib, '00-synthetic.pth').write_text('\n'.join(lines) + '\n')
    return str(python)


def run_launcher(launcher, socket_path):
    """Start the launcher as Chrome does (origin argument, hello frame on stdin); return its frames."""
    hello = io.BytesIO()
    extension_host.write_frame(hello, dict(type='hello', protocol=1, public_key=KEY))
    result = subprocess.run([str(launcher), EXTENSION_ORIGIN], input=hello.getvalue(), capture_output=True,
                            timeout=60, cwd=launcher.parent)
    frames, stream = [], io.BytesIO(result.stdout)
    while (item := extension_host.read_frame(stream)) is not None:
        frames.append(item)
    return result.returncode, frames, result.stderr.decode('utf-8', 'replace')


def test_the_old_launcher_imported_the_interpreters_own_akdbx(homes):
    # The reported defect, reproduced: the released format runs whatever akdbx the interpreter finds first.
    python = wrapper_python(homes)
    launcher = homes / 'old.sh'
    launcher.write_text(extension_host._launcher_text('chrome', python, str(homes / 'none.sock')))
    launcher.chmod(0o700)
    status, frames, error = run_launcher(launcher, homes / 'none.sock')
    assert status != 0 and frames == [] and "No module named akdbx.extension_host" in error


def fake_broker(socket_path):
    """A Unix socket with the broker's permissions that records the host's first message, then closes."""
    from akdbx.protocol import receive_message
    socket_path.parent.mkdir(mode=0o700)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    os.chmod(socket_path, 0o600)
    server.listen()
    received = []

    def run():
        try:
            server.settimeout(60)
            connection, _ = server.accept()
            with connection:
                received.append(receive_message(connection))
        finally:
            server.close()
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, received


def test_install_pins_this_akdbx_and_the_host_reaches_the_broker(homes):
    python = wrapper_python(homes)
    socket_path = str(homes / 'run' / 'akdbx.sock')
    where = extension_host.install('chrome', socket_path=socket_path, python=python,
                                   manifest_dir=homes / 'profiles' / 'slot1' / 'NativeMessagingHosts')
    launcher = Path(where['launcher'])
    words = shlex.split(launcher.read_text().split('\n')[1])
    assert words[:6] == ['exec', python, '-I', '-c', extension_host.BOOTSTRAP, extension_host.package_root()]
    assert extension_host.launcher_state('chrome') == 'current'
    thread, received = fake_broker(Path(socket_path))
    status, frames, error = run_launcher(launcher, socket_path)
    thread.join(60)
    # This akdbx's host connected with the CLI's peer checks and sent its attach message.
    assert status == 0 and received and received[0]['action'] == 'extension-attach', (frames, error)
    assert received[0]['browser'] == 'chrome' and received[0]['public_key'] == KEY
    manifest = json.loads(Path(where['manifest']).read_text())
    assert manifest['path'] == str(launcher)
    # A second slot profile shares the one launcher; uninstall still takes only its own files.
    second = extension_host.install('chrome', socket_path=socket_path, python=python,
                                    manifest_dir=homes / 'profiles' / 'slot2' / 'NativeMessagingHosts')
    assert second['launcher'] == where['launcher'] and second['manifest'] != where['manifest']
    assert set(extension_host.uninstall('chrome', manifest_dir=homes / 'profiles' / 'slot2' / 'NativeMessagingHosts')) \
        == {'manifest', 'launcher'}


def test_install_refuses_an_interpreter_that_cannot_run_this_akdbx(homes):
    python = wrapper_python(homes, dependencies=False)
    with pytest.raises(ValueError, match="cannot run the akdbx extension host .*No module named 'idna'"):
        extension_host.install('chrome', python=python)
    where = extension_host.paths('chrome')
    assert not where['launcher'].exists() and not where['manifest'].exists()
    with pytest.raises(ValueError, match='cannot start'):
        extension_host.install('chrome', python=str(homes / 'missing' / 'python'))
    assert not where['launcher'].exists()


def test_install_refuses_an_interpreter_without_the_broker_client_dependencies(homes):
    # The host itself imports only idna; the broker connection imports akdbx.cli (pykeepass, lxml, ...).
    python = wrapper_python(homes, dependencies=('idna',))
    with pytest.raises(ValueError, match='cannot run the akdbx extension host .*No module named'):
        extension_host.install('chrome', python=python)
    assert not extension_host.paths('chrome')['launcher'].exists()
    launcher = extension_host.paths('chrome')['launcher']
    launcher.parent.mkdir(parents=True)
    launcher.write_text(extension_host._launcher_text('chrome', python, None, extension_host.package_root()))
    assert extension_host.launcher_state('chrome') == 'stale'


def test_the_check_finds_another_akdbx_without_the_pin(homes):
    python = wrapper_python(homes, old_host=True)
    with pytest.raises(ValueError, match='runs another akdbx'):
        extension_host.check_python(python, None)
    extension_host.check_python(python, extension_host.package_root())


def test_only_the_exact_pinned_launcher_is_owned(tmp_path):
    launcher = tmp_path / 'chrome.sh'
    python, source = str(tmp_path / "py dir 'q'" / 'python3'), str(tmp_path / 'release 1' / 'src')
    for sock in (None, str(tmp_path / 'run dir' / 'akdbx.sock')):
        ours = extension_host._launcher_text('chrome', python, sock, source)
        launcher.write_text(ours)
        assert extension_host._parse_launcher(launcher, 'chrome') == dict(python=python, socket=sock, source=source)
        assert not extension_host._owned_launcher(launcher, 'edge')
    for text in (ours.replace('sys.path.insert(0,', 'sys.path.append('), ours.replace(' --browser', ' -X dev --browser'),
                 ours + 'touch /tmp/owned\n', ours.replace('exec ', 'exec env A=1 '), ours.replace('-I -c', '-c')):
        launcher.write_text(text)
        assert not extension_host._owned_launcher(launcher, 'chrome'), text


def test_refresh_points_every_launcher_at_this_akdbx_and_keeps_manifests(homes):
    old_source = str(homes / 'releases' / '0.31.0' / 'src')
    socket_path = str(homes / 'run' / 'akdbx.sock')
    chrome, helium = extension_host.paths('chrome')['launcher'], extension_host.paths('helium')['launcher']
    chrome.parent.mkdir(parents=True)
    chrome.write_text(extension_host._launcher_text('chrome', sys.executable, socket_path, old_source))
    helium.write_text(extension_host._launcher_text('helium', sys.executable, None))  # A 0.21-0.31.0 launcher.
    manifest = homes / 'profiles' / 'slot1' / 'NativeMessagingHosts' / 'org.akdbx.extension.json'
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps(extension_host._manifest(chrome)))
    before = manifest.read_bytes()
    assert extension_host.launcher_state('chrome') == 'stale' and extension_host.launcher_state('helium') == 'stale'
    assert extension_host.launcher_state('edge') == 'missing'
    refreshed = extension_host.refresh()
    assert refreshed == [dict(browser='helium', launcher=str(helium)), dict(browser='chrome', launcher=str(chrome))]
    assert extension_host._parse_launcher(chrome, 'chrome') == dict(
        python=str(Path(sys.executable).absolute()), socket=socket_path, source=extension_host.package_root())
    assert extension_host._parse_launcher(helium, 'helium')['socket'] is None
    assert {extension_host.launcher_state(b) for b in ('chrome', 'helium')} == {'current'}
    assert manifest.read_bytes() == before and not extension_host.paths('edge')['launcher'].exists()
    assert extension_host.refresh() == refreshed  # Nothing left to change.


def test_refresh_changes_nothing_when_a_launcher_is_not_ours(homes):
    chrome, edge = extension_host.paths('chrome')['launcher'], extension_host.paths('edge')['launcher']
    chrome.parent.mkdir(parents=True)
    stale = extension_host._launcher_text('chrome', sys.executable, None, str(homes / 'old'))
    chrome.write_text(stale)
    edge.write_text('#!/bin/sh\necho my own helper\n')
    with pytest.raises(ValueError, match='not written by akdbx'):
        extension_host.refresh()
    assert chrome.read_text() == stale and edge.read_text() == '#!/bin/sh\necho my own helper\n'
    assert extension_host.launcher_state('edge') == 'foreign'
    edge.unlink()
    edge.symlink_to(chrome)
    with pytest.raises(ValueError, match='not written by akdbx'):
        extension_host.refresh()
    assert chrome.read_text() == stale
    edge.unlink()
    assert [item['browser'] for item in extension_host.refresh()] == ['chrome']


def test_refresh_never_replaces_a_launcher_that_changed_after_its_check(homes, monkeypatch):
    chrome = extension_host.paths('chrome')['launcher']
    chrome.parent.mkdir(parents=True)
    stale = extension_host._launcher_text('chrome', sys.executable, None, str(homes / 'old'))
    chrome.write_text(stale)
    real = extension_host.check_python

    def check_then_replace(python, source):
        real(python, source)
        chrome.write_text('#!/bin/sh\necho another program\n')
    monkeypatch.setattr(extension_host, 'check_python', check_then_replace)
    with pytest.raises(ValueError, match='changed during the refresh'):
        extension_host.refresh()
    assert chrome.read_text() == '#!/bin/sh\necho another program\n'


def test_cli_install_python_refresh_and_info(homes, capsys):
    python = wrapper_python(homes)
    manifest_dir = homes / 'profiles' / 'slot1' / 'NativeMessagingHosts'
    assert cli.main(['extension', 'install', '--browser', 'chrome', '--manifest-dir', str(manifest_dir),
                     '--python', python]) == 0
    installed = json.loads(capsys.readouterr().out)
    assert installed['akdbx_source'] == extension_host.package_root()
    assert extension_host._parse_launcher(Path(installed['launcher']), 'chrome')['python'] == python
    assert cli.main(['extension', 'refresh']) == 0  # Back to this CLI's own interpreter.
    refreshed = json.loads(capsys.readouterr().out)
    assert refreshed['refreshed'] == [dict(browser='chrome', launcher=installed['launcher'])]
    assert cli.main(['extension', 'info']) == 0
    info = json.loads(capsys.readouterr().out)
    assert info['browsers']['chrome']['launcher_state'] == 'current'
    assert info['browsers']['edge']['launcher_state'] == 'missing'
    assert cli.main(['extension', 'install', '--browser', 'chrome', '--python', str(homes / 'nope')]) == 1
    assert 'cannot start' in json.loads(capsys.readouterr().err)['error']
