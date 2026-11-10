"""The caller cannot select a debugging endpoint or weaken profile checks."""
import os
from pathlib import Path

import pytest

from akdbx.browser_password import BrowserPasswords, endpoint
from akdbx.target import TargetError


@pytest.fixture
def profile(tmp_path):
    profile = tmp_path / 'profile'
    profile.mkdir(mode=0o700)
    # The fixture's parent directories must be private/owned, as in production.
    for path in [tmp_path, tmp_path.parent]:
        if path.stat().st_uid == os.getuid():
            path.chmod(0o700)
    return profile


@pytest.mark.parametrize('data', ['0\n/devtools/browser/id', '65536\n/devtools/browser/id',
                                 '1234\nws://remote.invalid/', '1234\n/devtools/page/id',
                                 '1234\n/devtools/browser/id\nextra', 'a' * 257])
def test_untrusted_endpoint_file_fails(profile, data):
    (profile / 'DevToolsActivePort').write_text(data)
    with pytest.raises(TargetError):
        endpoint(profile)


def test_exact_endpoint_and_symlink_permissions(profile, tmp_path):
    port = profile / 'DevToolsActivePort'
    port.write_text('12345\n/devtools/browser/synthetic-id')
    port.chmod(0o600)
    assert endpoint(profile) == 'ws://127.0.0.1:12345/devtools/browser/synthetic-id'
    port.chmod(0o666)
    with pytest.raises(TargetError):
        endpoint(profile)
    port.chmod(0o600)
    other = tmp_path / 'other'
    port.rename(other)
    port.symlink_to(other)
    with pytest.raises(OSError):
        endpoint(profile)
    link = tmp_path / 'link'
    link.symlink_to(profile)
    with pytest.raises(TargetError):
        endpoint(link)


def test_expiry_capacity_consumption_and_close(monkeypatch):
    from akdbx.browser_password import MAX_PINS
    class Pin:
        closed = False
        def close(self):
            self.closed = True
    now = [0]
    targets = BrowserPasswords(clock=lambda: now[0])
    pins = [Pin() for _ in range(MAX_PINS)]
    targets.pins = {str(i): (30, pin) for i, pin in enumerate(pins)}
    assert targets.consume('0') is pins[0]
    assert '0' not in targets.pins
    with pytest.raises(TargetError):
        targets.consume('0')
    now[0] = 30
    targets.prune()
    assert not targets.pins and all(pin.closed for pin in pins[1:])
    targets.pins = {'next': (60, pins[0])}
    targets.close()
    assert pins[0].closed and not targets.pins


def test_pin_capacity_refuses_before_connect(monkeypatch):
    from akdbx import browser_password
    targets = BrowserPasswords(clock=lambda: 0)
    targets.pins = {str(i): (30, object()) for i in range(browser_password.MAX_PINS)}
    def forbidden(*args, **kwargs):
        pytest.fail('capacity overflow opened a browser connection')
    monkeypatch.setattr(browser_password, 'CDP', forbidden)
    with pytest.raises(TargetError):
        targets.pin(dict(action='pin-password-target', password_protocol=1, page_id='synthetic-page',
                         frame_id='synthetic-frame', top_url='https://example.test/login', selector='#password', mode='password'))
