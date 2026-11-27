"""Firefox packaging and the native host's exact caller contract; no real vault."""
import io
import json
import os
from pathlib import Path
import sys

import pytest

from akdbx import extension_host as host
from akdbx.extension_route import EXTENSION_ORIGIN, FIREFOX_EXTENSION_ID


def test_firefox_build_has_native_document_targeting_and_event_page(tmp_path):
    folder = host.build(tmp_path / 'firefox', browser='firefox')
    manifest = json.loads((folder / 'manifest.json').read_text())
    assert manifest['browser_specific_settings']['gecko']['id'] == FIREFOX_EXTENSION_ID
    assert manifest['browser_specific_settings']['gecko']['strict_min_version'] == '153.0'
    assert 'key' not in manifest and 'minimum_chrome_version' not in manifest
    assert manifest['background'] == {'scripts': ['api.js', 'config.js', 'trust.js', 'background.js']}
    assert 'nativeMessaging' in manifest['permissions'] and 'scripting' in manifest['permissions']
    assert 'menus' in manifest['permissions']
    assert manifest['version'] == host.built_version()
    for script in manifest['background']['scripts']:
        assert (folder / script).is_file()
    # Rebuilds keep the supported format, and never overwrite another browser's build.
    host.build(folder, browser='firefox')
    with pytest.raises(ValueError, match='does not hold'):
        host.build(folder, browser='chrome')
    chrome = host.build(tmp_path / 'chrome')
    with pytest.raises(ValueError, match='does not hold'):
        host.build(chrome, browser='firefox')


def test_firefox_host_manifest_allows_only_the_fixed_addon_id():
    manifest = host._manifest(Path('/synthetic/host'), browser='firefox')
    assert manifest['allowed_extensions'] == [FIREFOX_EXTENSION_ID]
    assert 'allowed_origins' not in manifest
    assert host._manifest(Path('/synthetic/host'))['allowed_origins'] == [EXTENSION_ORIGIN]


@pytest.mark.skipif(os.name == 'nt', reason='Linux per-user native manifest location')
def test_firefox_host_is_installed_in_mozilla_folder(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    monkeypatch.setattr(host, 'check_python', lambda *args: None)
    where = host.install('firefox')
    expected = (tmp_path / 'Library/Application Support/Mozilla/NativeMessagingHosts'
                if sys.platform == 'darwin' else tmp_path / '.mozilla/native-messaging-hosts')
    assert Path(where['manifest']) == expected / 'org.akdbx.extension.json'
    assert json.loads(Path(where['manifest']).read_text())['allowed_extensions'] == [FIREFOX_EXTENSION_ID]
    assert host._owned_launcher(Path(where['launcher']), 'firefox')
    assert host.uninstall('firefox') == ['manifest', 'launcher']


@pytest.mark.parametrize('caller', ['', EXTENSION_ORIGIN, 'other@example.org'])
def test_firefox_host_rejects_another_extension_before_reading_input(caller):
    def forbidden():
        pytest.fail('must not connect for another caller')
    assert host.relay(io.BytesIO(b'not a frame'), io.BytesIO(), caller, 'firefox', forbidden) == 1


def test_firefox_command_uses_second_browser_argument(monkeypatch):
    monkeypatch.setattr(host, '_binary_stdio', lambda: (io.BytesIO(), io.BytesIO()))
    seen = []
    monkeypatch.setattr(host, 'relay', lambda incoming, outgoing, origin, browser, *args, **kwargs:
                        seen.append((origin, browser)) or 0)
    assert host.main(['--browser', 'firefox', '/synthetic/manifest.json', FIREFOX_EXTENSION_ID]) == 0
    assert seen == [(FIREFOX_EXTENSION_ID, 'firefox')]


def test_firefox_native_document_ids_support_discovery_and_pinning():
    from test_extension_route import make_broker, attach, Document, LOGIN
    from akdbx import extension_route as route
    broker = make_broker()
    document_id = 'e607bd18-76b3-416f-bf73-fcae49ec5cc2'
    channel, _ = attach(broker, {3: [Document(document_id, LOGIN)]})
    listing = broker.dispatch(dict(action='list-password-frames', password_protocol=1,
                                   frame_protocol=1, top_url=LOGIN, route='extension'))
    assert listing['ok'] and listing['main_frame_id'] == document_id
    pin = broker.dispatch(dict(action='pin-password-target', password_protocol=1,
                               page_id=listing['page_id'], frame_id=document_id, top_url=LOGIN,
                               selector='#password', mode='password', route='extension'))
    assert pin['ok'] and pin['target_delivery'] == route.DELIVERY
