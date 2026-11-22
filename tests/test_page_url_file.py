"""--top-url-file / --frame-url-file: exact page URLs that hold a token stay out of argv and output."""
import json
import os

import pytest

from akdbx import cli
from akdbx.browser_card import DELIVERY as CARD_DELIVERY
from akdbx.browser_identity import DELIVERY as IDENTITY_DELIVERY

# Synthetic only: a fake activation page with a fake one-time token.
TOKEN = 'SYNTHETIC-ONE-TIME-TOKEN-4f9c2e7a'
TOP_URL = f'https://forge.example.test/user/activate?code={TOKEN}#step-2'
FRAME_URL = f'https://forge.example.test/frame/reset?token={TOKEN}'

pytestmark = pytest.mark.skipif(os.name == 'nt', reason='POSIX file-mode checks')

PASSWORD_CAPS = dict(ok=True, password_fill_protocol=1, password_fill_delivery='chromium-password-dom-v1',
                     password_frame_protocol=1, password_frame_policy='same-site-chain-v1')
IDENTITY_CAPS = dict(ok=True, identity_protocol=1, identity_delivery=IDENTITY_DELIVERY,
                     identity_browser_configured=True, locked=False)
CARD_CAPS = dict(ok=True, cards_supported=True, card_protocol=1, card_delivery=CARD_DELIVERY)
PIN = ['--page-id', 'page', '--frame-id', 'frame', '--selector', '#field']

COMMANDS = {
    'pin-password-target': (PASSWORD_CAPS, [*PIN],
                            dict(ok=True, target='a' * 64, expires_in=30, target_delivery='chromium-password-dom-v1')),
    'list-password-frames': (PASSWORD_CAPS, [],
                             dict(ok=True, page_id='page', main_frame_id='frame', frame_policy='same-site-chain-v1',
                                  frames=[], truncated=False)),
    'pin-identity-target': (IDENTITY_CAPS, [*PIN, '--field', 'postal-code'],
                            dict(ok=True, field='postal-code', target='b' * 64, expires_in=30,
                                 identity_delivery=IDENTITY_DELIVERY)),
    'pin-card-target': (CARD_CAPS, [*PIN, '--field', 'cc-number'],
                        dict(ok=True, target='c' * 64, expires_in=30, field='cc-number', card_delivery=CARD_DELIVERY)),
}
FRAME_COMMANDS = ('pin-identity-target', 'pin-card-target')


def private_file(tmp_path, name, text, mode=0o600):
    path = tmp_path / name
    path.write_text(text)
    path.chmod(mode)
    return path


@pytest.fixture
def broker(monkeypatch):
    calls = []

    def install(command):
        caps, _, receipt = COMMANDS[command]

        def request(path, payload, **kwargs):
            calls.append(payload)
            return caps if payload['action'] == 'ping' else receipt
        monkeypatch.setattr(cli, 'request', request)
        return calls
    return install


def no_token(captured):
    assert TOKEN not in captured.out and TOKEN not in captured.err


@pytest.mark.parametrize('command', COMMANDS)
def test_top_url_file_reaches_broker_unchanged_and_is_never_printed(command, broker, tmp_path, capsys):
    calls = broker(command)
    top = private_file(tmp_path, 'top-url', TOP_URL + '\n')
    argv = [command, *COMMANDS[command][1], '--top-url-file', str(top)]
    if command in FRAME_COMMANDS:
        argv += ['--frame-url-file', str(private_file(tmp_path, 'frame-url', FRAME_URL))]
    assert cli.main(argv) == 0
    sent = [call for call in calls if call['action'] == command]
    assert len(sent) == 1 and sent[0]['top_url'] == TOP_URL
    assert 'top_url_file' not in sent[0] and 'frame_url_file' not in sent[0]
    if command in FRAME_COMMANDS:
        assert sent[0]['frame_url'] == FRAME_URL
    no_token(capsys.readouterr())


@pytest.mark.parametrize('command', COMMANDS)
def test_file_form_sends_the_same_request_as_the_plain_flag(command, broker, tmp_path, capsys):
    calls = broker(command)
    plain = [command, *COMMANDS[command][1], '--top-url', TOP_URL]
    filed = [command, *COMMANDS[command][1], '--top-url-file', str(private_file(tmp_path, 'top', TOP_URL))]
    if command in FRAME_COMMANDS:
        plain += ['--frame-url', FRAME_URL]
        filed += ['--frame-url-file', str(private_file(tmp_path, 'frame', FRAME_URL + '\r\n'))]
    assert cli.main(plain) == 0
    first = list(calls)
    calls.clear()
    assert cli.main(filed) == 0
    assert calls == first


@pytest.mark.parametrize('command', COMMANDS)
def test_plain_and_file_flags_are_mutually_exclusive(command, broker, tmp_path, capsys):
    calls = broker(command)
    top = private_file(tmp_path, 'top', TOP_URL)
    with pytest.raises(SystemExit) as exit_info:
        cli.main([command, *COMMANDS[command][1], '--top-url', 'https://forge.example.test/',
                  '--top-url-file', str(top)])
    assert exit_info.value.code == 2 and calls == []
    captured = capsys.readouterr()
    assert 'not allowed with argument' in captured.err
    no_token(captured)


@pytest.mark.parametrize('command', FRAME_COMMANDS)
def test_frame_url_flags_are_mutually_exclusive(command, broker, tmp_path, capsys):
    calls = broker(command)
    with pytest.raises(SystemExit) as exit_info:
        cli.main([command, *COMMANDS[command][1], '--top-url', 'https://forge.example.test/',
                  '--frame-url', 'https://forge.example.test/', '--frame-url-file',
                  str(private_file(tmp_path, 'frame', FRAME_URL))])
    assert exit_info.value.code == 2 and calls == []
    no_token(capsys.readouterr())


@pytest.mark.parametrize('command', COMMANDS)
def test_one_top_url_form_is_still_required(command, broker, capsys):
    calls = broker(command)
    with pytest.raises(SystemExit) as exit_info:
        cli.main([command, *COMMANDS[command][1]])
    assert exit_info.value.code == 2 and calls == []
    assert '--top-url' in capsys.readouterr().err


def _bad_files(tmp_path):
    missing = tmp_path / 'missing'
    group_readable = private_file(tmp_path, 'group', TOP_URL, 0o640)
    world_readable = private_file(tmp_path, 'world', TOP_URL, 0o644)
    unreadable = private_file(tmp_path, 'unreadable', TOP_URL, 0o000)
    target = private_file(tmp_path, 'real', TOP_URL)
    link = tmp_path / 'link'
    link.symlink_to(target)
    two_lines = private_file(tmp_path, 'two-lines', TOP_URL + '\nhttps://other.example.test/\n')
    spaced = private_file(tmp_path, 'spaced', ' ' + TOP_URL)
    empty = private_file(tmp_path, 'empty', '')
    large = private_file(tmp_path, 'large', 'https://forge.example.test/?' + TOKEN + 'x' * 5000)
    binary = tmp_path / 'binary'
    binary.write_bytes(b'https://forge.example.test/\xff' + TOKEN.encode())
    binary.chmod(0o600)
    directory = tmp_path / 'directory'
    directory.mkdir(mode=0o700)
    return dict(missing=(missing, 'could not open'), group=(group_readable, 'other users'),
                world=(world_readable, 'other users'), unreadable=(unreadable, 'could not open'),
                symlink=(link, 'could not open'), two_lines=(two_lines, 'one line'), spaced=(spaced, 'one line'),
                empty=(empty, '1 to 4096 bytes'), large=(large, '1 to 4096 bytes'),
                binary=(binary, 'not UTF-8'), directory=(directory, 'regular file'))


@pytest.mark.parametrize('case', ['missing', 'group', 'world', 'unreadable', 'symlink', 'two_lines',
                                  'spaced', 'empty', 'large', 'binary', 'directory'])
@pytest.mark.parametrize('command', COMMANDS)
def test_bad_url_file_refuses_before_any_broker_request_without_echoing_it(command, case, broker, tmp_path, capsys):
    if case == 'unreadable' and os.geteuid() == 0:
        pytest.skip('root reads mode-0000 files')
    calls = broker(command)
    path, reason = _bad_files(tmp_path)[case]
    assert cli.main([command, *COMMANDS[command][1], '--top-url-file', str(path)]) == 2
    assert calls == []
    captured = capsys.readouterr()
    assert captured.out == ''
    assert captured.err.startswith('--top-url-file: ') and reason in captured.err
    assert captured.err.endswith('; request not sent\n')
    no_token(captured)


@pytest.mark.parametrize('command', FRAME_COMMANDS)
def test_bad_frame_url_file_names_its_own_flag(command, broker, tmp_path, capsys):
    calls = broker(command)
    frame = private_file(tmp_path, 'frame', FRAME_URL, 0o644)
    assert cli.main([command, *COMMANDS[command][1], '--top-url-file', str(private_file(tmp_path, 'top', TOP_URL)),
                     '--frame-url-file', str(frame)]) == 2
    assert calls == []
    captured = capsys.readouterr()
    assert captured.err.startswith('--frame-url-file: other users')
    no_token(captured)


def test_broker_refusal_after_a_file_pin_does_not_print_the_url(monkeypatch, tmp_path, capsys):
    def request(path, payload, **kwargs):
        if payload['action'] == 'ping':
            return PASSWORD_CAPS
        return dict(ok=False, error='target refused; no field pinned')
    monkeypatch.setattr(cli, 'request', request)
    cli.main(['pin-password-target', *PIN, '--top-url-file', str(private_file(tmp_path, 'top', TOP_URL))])
    no_token(capsys.readouterr())


def test_help_names_the_file_flags(capsys):
    for command in COMMANDS:
        with pytest.raises(SystemExit):
            cli.main([command, '--help'])
        out = capsys.readouterr().out
        assert '--top-url-file PATH' in out
        assert ('--frame-url-file PATH' in out) == (command in FRAME_COMMANDS)
