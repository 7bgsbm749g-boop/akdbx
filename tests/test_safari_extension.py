"""Safari resource format. Native app and real browser proofs run on macOS."""
import json

import pytest

from akdbx import extension_host as host
from akdbx.extension_route import BROWSERS, HOST_BROWSERS


def test_safari_resources_use_the_native_adapter_and_document_guards(tmp_path):
    folder = host.build(tmp_path / 'safari', browser='safari', unlock_origin='https://localhost:9443')
    manifest = json.loads((folder / 'manifest.json').read_text())
    assert manifest['browser_specific_settings'] == {'safari': {'strict_min_version': '26.0'}}
    assert 'key' not in manifest and 'minimum_chrome_version' not in manifest
    assert manifest['background'] == {'scripts': [
        'api.js', 'config.js', 'trust.js', 'safari-port.js', 'background.js']}
    assert 'scripting' in manifest['permissions'] and 'nativeMessaging' in manifest['permissions']
    assert manifest['version'] == host.built_version()
    for script in manifest['background']['scripts']:
        assert (folder / script).is_file()
    host.build(folder, browser='safari')
    for other in ('chrome', 'firefox'):
        with pytest.raises(ValueError, match='does not hold'):
            host.build(folder, browser=other)
        other_folder = host.build(tmp_path / other, browser=other)
        with pytest.raises(ValueError, match='does not hold'):
            host.build(other_folder, browser='safari')


def test_safari_uses_an_apple_native_app_instead_of_a_host_manifest():
    assert 'safari' in BROWSERS and 'safari' not in HOST_BROWSERS
