from __future__ import annotations

import json
import os
import socket
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode, urlsplit

import pytest
from pykeepass import PyKeePass, create_database

from akdbx import cli
from akdbx.broker import Broker
from akdbx.protocol import ProtocolError, receive_message, send_message
from test_broker import target_capabilities, Entry, RecordingTyper, target_request, SECRET, running_broker, expected_merge_capabilities, expected_sso_capabilities, expected_passwordless_capabilities, expected_extension_capabilities
from test_web_unlock import call


MASTER = "synthetic-web-unlock-master"


@pytest.mark.parametrize('arguments, field', [
    (['write-status', '--', '-legacy-handle'], 'write_handle'),
    (['cancel-write', '--', '-legacy-handle'], 'write_handle'),
    (['commit-password', '--site-accepted', '--', '-legacy-handle'], 'write_handle'),
    (['fill-generated', '--target-url', 'https://example.test/reset',
      '--target', 'synthetic-pin', '--', '-legacy-handle'], 'handle'),
])
def test_documented_end_of_options_accepts_legacy_handles(arguments, field):
    """A new CLI must still accept opaque handles from a running old broker."""
    assert getattr(cli.parser().parse_args(arguments), field) == '-legacy-handle'


@pytest.mark.parametrize('raw_uid', ['', 'not-a-uid'])
@pytest.mark.parametrize('command', ['override', 'default', 'help', 'version', 'subcommand-help'])
def test_unused_invalid_uid_environment_does_not_block_cli(monkeypatch, tmp_path, capsys, raw_uid, command):
    """Only the effective UID needs conversion; local help needs no broker configuration."""
    monkeypatch.setenv('AKDBX_BROKER_UID', raw_uid)
    if command == 'override':
        endpoint = tmp_path / 'private' / 'broker.sock'
        broker = Broker(SimpleNamespace(entries=[]), RecordingTyper())
        with running_broker(endpoint, broker):
            assert cli.main(['--socket', str(endpoint), '--broker-uid', str(os.getuid()), 'status']) == 0
        assert json.loads(capsys.readouterr().out)['ok'] is True
    else:
        arguments = {'default': ['status'], 'help': ['--help'], 'version': ['--version'],
                     'subcommand-help': ['status', '--help']}[command]
        with pytest.raises(SystemExit) as exc:
            cli.main(arguments)
        assert exc.value.code == (2 if command == 'default' else 0)
        captured = capsys.readouterr()
        if command == 'default':
            assert not captured.out and '--broker-uid' in captured.err
        else:
            assert captured.out and not captured.err
        assert 'Traceback' not in captured.err


def test_valid_uid_environment_selects_authenticated_broker(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv('AKDBX_BROKER_UID', str(os.getuid()))
    endpoint = tmp_path / 'private' / 'broker.sock'
    with running_broker(endpoint, Broker(SimpleNamespace(entries=[]), RecordingTyper())):
        assert cli.main(['--socket', str(endpoint), 'status']) == 0
    assert json.loads(capsys.readouterr().out)['ok'] is True


def test_eof_after_completed_fill_requires_uncertainty_without_retry(tmp_path, capsys):
    """A completed delivery with a lost receipt cannot be classified as safe to repeat."""
    typer = RecordingTyper()
    broker = Broker(SimpleNamespace(entries=[Entry()]), typer)
    handle = broker.dispatch({'action': 'search'})['entries'][0]['handle']
    pin = target_request(broker, 'password')['target']
    endpoint = tmp_path / 'private' / 'broker.sock'
    endpoint.parent.mkdir(mode=0o700)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(endpoint))
    endpoint.chmod(0o600)
    listener.listen(2)
    listener.settimeout(2)
    actions, errors = [], []

    def lose_reply():
        try:
            for _ in range(2):
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(2)
                    payload = receive_message(connection)
                    actions.append(payload['action'])
                    response = broker.dispatch(payload)
                    if payload['action'] == 'ping':
                        send_message(connection, response)
                    else:
                        assert response['ok'] is True
        except Exception as exc:
            errors.append(exc)

    worker = threading.Thread(target=lose_reply)
    worker.start()
    try:
        assert cli.main(['--socket', str(endpoint), '--broker-uid', str(os.getuid()),
                         'fill', handle, '--mode', 'password', '--target', pin]) == 2
        worker.join(3)
        assert not worker.is_alive() and not errors
        assert actions == ['ping', 'fill']
        assert typer.events == [('type', SECRET)] and handle not in broker._handles
        captured = capsys.readouterr()
        assert not captured.out and SECRET not in captured.err
        assert 'outcome unconfirmed' in captured.err and 'do not retry automatically' in captured.err
    finally:
        listener.close()
        worker.join(3)
        broker.unlock_notifications.close()


@pytest.mark.parametrize('action, preflight', [
    ('fill-generated', False), ('fill-totp', False), ('commit-password', False),
    ('fill-generated', True), ('fill-totp', True),
])
def test_lost_mutation_reply_has_safe_recovery_guidance(monkeypatch, capsys, action, preflight):
    calls = []

    def lost_reply(endpoint, payload, **kwargs):
        calls.append(payload['action'])
        if payload['action'] == 'ping' and not preflight:
            return {'ok': True, **target_capabilities(), 'totp_supported': True, 'totp_protocol': 1}
        if payload['action'] != 'ping' and kwargs.get('before_send') is not None:
            kwargs['before_send']()
        raise ProtocolError('connection closed')

    monkeypatch.setattr(cli, 'request', lost_reply)
    arguments = [action, 'synthetic-reference']
    arguments += (['--site-accepted'] if action == 'commit-password' else
                  ['--target-url', 'https://example.test', '--target', 'synthetic-pin'])
    assert cli.main(arguments) == 2
    captured = capsys.readouterr()
    assert not captured.out
    if preflight:
        assert 'request not sent' in captured.err and 'not started' in captured.err
        assert 'outcome unconfirmed' not in captured.err
    else:
        assert 'outcome unconfirmed' in captured.err
        assert ('write-status' if action == 'commit-password' else 'do not retry automatically') in captured.err
    assert 'after request' not in captured.err
    assert calls == (['ping'] if preflight else
                     ['ping', 'ping', action] if action == 'fill-totp' else
                     ['ping', action] if action == 'fill-generated' else [action])


@pytest.mark.parametrize('action', ['fill', 'commit-password'])
@pytest.mark.parametrize('fault', ['socket-mode', 'peer-uid'])
def test_mutation_transport_refusal_is_known_not_sent(tmp_path, monkeypatch, capsys, action, fault):
    endpoint = tmp_path / 'private' / 'broker.sock'
    endpoint.parent.mkdir(mode=0o700)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(endpoint))
    listener.listen(1)
    endpoint.chmod(0o666 if fault == 'socket-mode' else 0o600)
    if fault == 'peer-uid':
        monkeypatch.setattr(cli, '_peer_credentials', lambda client: (os.getpid(), os.getuid() + 1, os.getgid()))
    arguments = ['--socket', str(endpoint), action, 'synthetic-reference']
    arguments += ['--site-accepted'] if action == 'commit-password' else ['--target', 'synthetic-pin']
    try:
        assert cli.main(arguments) == 2
        captured = capsys.readouterr()
        assert not captured.out and 'socket or peer identity' in captured.err
        assert 'request not sent' in captured.err and 'outcome unconfirmed' not in captured.err
        if action == 'commit-password':
            assert 'write-status' in captured.err and 'do not reset the site again' in captured.err
        if fault == 'peer-uid':
            listener.settimeout(1)
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(1)
                assert connection.recv(1) == b''
        else:
            listener.setblocking(False)
            with pytest.raises(BlockingIOError):
                listener.accept()
    finally:
        listener.close()


def test_rejected_capability_reply_is_not_a_fill_attempt(tmp_path, monkeypatch, capsys):
    actions = []
    broker = Broker(SimpleNamespace(entries=[]), RecordingTyper())

    def rejected(payload, **kwargs):
        actions.append(payload['action'])
        return {'ok': 'synthetic private diagnostic'}

    monkeypatch.setattr(broker, 'dispatch', rejected)
    endpoint = tmp_path / 'private' / 'broker.sock'
    with running_broker(endpoint, broker):
        assert cli.main(['--socket', str(endpoint), 'fill', 'synthetic-reference',
                         '--target', 'synthetic-pin']) == 2
    captured = capsys.readouterr()
    assert not captured.out and 'request not sent' in captured.err
    assert 'capability' in captured.err and 'synthetic private diagnostic' not in captured.err
    assert actions == ['ping'] and not broker.typer.events


@pytest.fixture(scope="module")
def synthetic_database(tmp_path_factory):
    database = tmp_path_factory.mktemp("synthetic") / "vault.kdbx"
    create_database(str(database), password=MASTER)
    vault = PyKeePass(str(database), password=MASTER)
    vault.add_entry(vault.root_group, Entry.title, Entry.username, SECRET, url=Entry.url)
    vault.save()
    return database


@pytest.mark.parametrize("options, is_tty", [
    ([], False),
    (["--web-unlock"], False),
    (["--web-unlock"], True),
    (["--web-unlock", "--yes-on-fill"], False),
    (["--yes-on-fill"], True),
])
def test_serve_web_unlock_and_explicit_fill_without_approval(
    options, is_tty, synthetic_database, tmp_path, monkeypatch, capsys, caplog,
):
    typer = RecordingTyper()
    monkeypatch.setattr(cli, "X11Typer", lambda: typer)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: is_tty)
    start_unlock_server = cli.start_unlock_server
    servers = []

    def isolated_unlock_server(*args):
        server, url = start_unlock_server(*args)
        servers.append(server)
        return server, url

    monkeypatch.setattr(cli, "start_unlock_server", isolated_unlock_server)

    def exercise_broker(socket_path, broker):
        assert broker.locked
        prefix = [
            "--socket", str(socket_path),
            "--unlock-origin", "https://node.example:9443",
        ]

        def command(*args, expected_exit=0):
            if args[0] == 'fill':
                mode = args[args.index('--mode') + 1] if '--mode' in args else 'login'
                pin = 'synthetic-locked-pin' if broker.locked else target_request(broker, mode)['target']
                args = (*args, '--target', pin)
            assert cli.main([*prefix, *args]) == expected_exit
            captured = capsys.readouterr()
            assert not captured.err
            assert SECRET not in captured.out
            assert MASTER not in captured.out
            return json.loads(captured.out)

        with running_broker(socket_path, broker):
            startup = capsys.readouterr()
            assert startup.out == ""
            assert SECRET not in startup.err and MASTER not in startup.err
            assert ("deprecated" in startup.err) == ("--yes-on-fill" in options)

            status = command("status")
            assert status["locked"] is True
            assert command("search", "example", expected_exit=1)["error"] == "vault locked"
            assert command("fill", "invalid", expected_exit=1)["error"] == "vault locked"
            assert typer.events == []

            # This POST is only for a newly created synthetic test vault/server.
            parts = urlsplit(status["unlock_url"])
            path = parts.path + "?" + parts.query
            # Real KDBX key derivation can exceed two seconds on a busy host.
            code, _, page = call(servers[0].server_address, "POST", path, urlencode({"password": MASTER}), timeout=30)
            assert code == 200
            assert MASTER.encode() not in page and SECRET.encode() not in page
            status = command("status")
            # serve signs its page origin for the browser extension (broker_identity).
            assert status["lock_event_sources"].get("logind") in {"starting", "listening", "signals-only", "unavailable"}
            status["lock_event_sources"] = {}
            trust = status.pop("extension_trust")
            assert set(trust) == {"key_id", "origin", "seq"} and trust["seq"] == 1
            assert status == {"ok": True, "locked": False, "version": "0.54.1", "lock_timeout_seconds": 3600, "lock_event_sources": {}, "unlock_notifications_supported": True, "unlock_notifications_protocol": 1, "unlock_notifications_until_unlock": True, "unlock_notifications_blocked_event": True, "unlock_link_protocol": 1, "unlock_link_max_failures": 3, "card_save_notifications_supported": True, "card_save_notifications_protocol": 1, "card_save_notifications_until_result": True, "write_notifications_supported": True, "write_notifications_protocol": 1, "write_notifications_until_result": True, "write_notification_kinds": ["password", "totp", "identity", "card"], "pairing_notifications_supported": True, "pairing_notifications_protocol": 1, "pairing_notifications_until_paired": True, "writes_available": True, "recovery_required": False, **expected_merge_capabilities(available=True), **expected_sso_capabilities(), **expected_passwordless_capabilities(), "cards_supported": True, "card_protocol": 1, "card_delivery": "cdp-card-element-v1", "card_browser_configured": False, "card_processor_frames_protocol": 1, "card_processors": ["adyen", "computop", "stripe"], "stripe_card_element": True, "card_field_purpose_protocol": 1, "generated_entry_protocol": 1, "generated_single_field": True, "generated_additional_urls": True, "totp_supported": True, "totp_protocol": 1, "totp_import_supported": True, "totp_import_protocol": 1, **target_capabilities(), **expected_extension_capabilities(),
                              # serve gives the broker its folder for AMO-signed Firefox add-ons.
                              "firefox_signing_configured": True}
            search = command("search", "example")
            assert typer.events == []  # Unlock/search must not trigger a fill.
            handle = search["entries"][0]["handle"]
            assert command("fill", handle, "--mode", "login") == {"ok": True, "filled": "login", "target_delivery": "chromium-password-dom-v1"}
            expected = [("type", Entry.username), ("key", "tab"), ("type", SECRET)]
            assert typer.events == expected
            assert command("fill", handle, expected_exit=1)["error"] == "unknown or expired handle; search again"
            assert typer.events == expected

            if not options:
                previous = command("search", "example")["entries"][0]["handle"]
                assert command("lock") == {"ok": True, "locked": True}
                locked = command("status")
                assert locked["locked"] and urlsplit(locked["unlock_url"]).query != parts.query
                assert command("search", "example", expected_exit=1)["error"] == "vault locked"
                assert call(servers[0].server_address, "GET", path)[0] == 404
                fresh = urlsplit(locked["unlock_url"])
                assert call(servers[0].server_address, "POST", fresh.path + "?" + fresh.query,
                            urlencode({"password": MASTER}), timeout=30)[0] == 200
                assert command("fill", previous, expected_exit=1)["error"] == "unknown or expired handle; search again"
                assert command("search", "example")["entries"]

    monkeypatch.setattr(cli, "serve", exercise_broker)
    assert cli.main([
        "--socket", str(tmp_path / "private" / "broker.sock"),
        "serve", str(synthetic_database),
        "--unlock-url", "https://node.example:9443", *options,
    ]) == 0
    assert servers[0].fileno() == -1  # The test's unlock listener is closed.
    assert capsys.readouterr() == ("", "")
    assert not caplog.records


@pytest.mark.parametrize(("environment", "global_options", "serve_options", "expected"), [
    ("https://configured.example:9443", [], [], "https://configured.example:9443"),
    ("https://configured.example:9443", ["--unlock-origin", "https://override.example:8443"], [], "https://override.example:8443"),
    ("https://configured.example:9443", [], ["--unlock-url", "https://legacy.example:9443"], "https://legacy.example:9443"),
])
def test_serve_uses_private_configuration_for_origin_and_runtime(
    environment, global_options, serve_options, expected, monkeypatch, tmp_path,
):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    if environment is None:
        monkeypatch.delenv("AKDBX_UNLOCK_ORIGIN", raising=False)
    else:
        monkeypatch.setenv("AKDBX_UNLOCK_ORIGIN", environment)
    calls = []
    lifecycle = []
    listener = SimpleNamespace(
        shutdown=lambda: lifecycle.append("shutdown"),
        server_close=lambda: lifecycle.append("close"),
    )

    def start_unlock(_broker, _database, _keyfile, socket_path, origin):
        calls.append((socket_path, origin))
        return listener, origin + "/?token=synthetic"

    monkeypatch.setattr(cli, "X11Typer", RecordingTyper)
    monkeypatch.setattr(cli, "start_unlock_server", start_unlock)
    monkeypatch.setattr(cli, "serve", lambda *_: None)
    assert cli.main([*global_options, "serve", "synthetic.kdbx", *serve_options]) == 0
    assert calls == [(tmp_path / "akdbx" / "akdbx-unlock.sock", expected)]
    assert lifecycle == ["shutdown", "close"]


def test_request_default_refuses_unconfigured_deployment_link(tmp_path):
    socket_path = tmp_path / "private" / "broker.sock"
    thread = _fake_server(socket_path, {
        "ok": True, "locked": True,
        "unlock_url": "https://configured.example:9443/?token=synthetic",
    })
    try:
        with pytest.raises(ProtocolError, match="untrusted unlock URL"):
            cli.request(socket_path, {"action": "ping"})
    finally:
        thread.join(timeout=1)


def _fake_server(socket_path, response):
    socket_path.parent.mkdir(mode=0o700)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    os.chmod(socket_path, 0o600)
    server.listen()

    def run():
        try:
            connection, _ = server.accept()
            with connection:
                if connection.recv(4096):
                    send_message(connection, response)
        finally:
            server.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def test_request_rejects_untrusted_runtime_directory(tmp_path):
    socket_path = tmp_path / "shared" / "broker.sock"
    socket_path.parent.mkdir(mode=0o700)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    os.chmod(socket_path, 0o600)
    os.chmod(socket_path.parent, 0o777)
    try:
        with pytest.raises(PermissionError, match="mode 0700"):
            cli.request(socket_path, {"action": "ping"})
    finally:
        server.close()


def test_request_rejects_symlinked_runtime_path(tmp_path):
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "runtime"
    link.symlink_to(real, target_is_directory=True)
    socket_path = real / "broker.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    os.chmod(socket_path, 0o600)
    try:
        with pytest.raises(PermissionError, match="symlinked"):
            cli.request(link / "broker.sock", {"action": "ping"})
    finally:
        server.close()


def test_rpc_server_and_client_reject_same_replaceable_ancestor(tmp_path):
    replaceable = tmp_path / "replaceable"
    replaceable.mkdir(mode=0o777)
    replaceable.chmod(0o777)
    private = replaceable / "private"
    private.mkdir(mode=0o700)
    socket_path = private / "broker.sock"

    with pytest.raises(RuntimeError, match="replaceable"):
        cli.serve(
            socket_path, cli.Broker(None, RecordingTyper()), threading.Event(),
        )

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    os.chmod(socket_path, 0o600)
    try:
        with pytest.raises(PermissionError, match="replaceable"):
            cli.request(socket_path, {"action": "ping"})
    finally:
        listener.close()


def test_request_rejects_peer_with_wrong_uid(tmp_path, monkeypatch):
    socket_path = tmp_path / "private" / "broker.sock"
    thread = _fake_server(socket_path, {"ok": True, "locked": False})
    monkeypatch.setattr(cli, "_peer_credentials", lambda client: (123, os.getuid() + 1, 456))

    with pytest.raises(PermissionError, match="peer UID"):
        cli.request(socket_path, {"action": "ping"})

    thread.join(timeout=1)


@pytest.mark.parametrize("unlock_url", [
    "http://node.example:9443/?token=opaque",
    "https://phishing.example.invalid/?token=opaque",
    "https://node.example:9443/?token=",
    "https://node.example:9443/?token=opaque&next=phishing",
    "https://user@node.example:9443/?token=opaque",
])
def test_request_rejects_untrusted_unlock_url(tmp_path, unlock_url):
    socket_path = tmp_path / "private" / "broker.sock"
    thread = _fake_server(socket_path, {"ok": True, "locked": True, "unlock_url": unlock_url})

    with pytest.raises(ProtocolError, match="unlock URL"):
        cli.request(
            socket_path, {"action": "ping"},
            expected_unlock_origin="https://node.example:9443",
        )

    thread.join(timeout=1)


@pytest.mark.parametrize(("unlock_url", "expected_origin"), [
    ("https://node.example/?token=opaque", "https://node.example"),
    ("https://node.example:443/?token=opaque", "https://node.example"),
    ("https://node.example/?token=opaque", "https://node.example:443"),
])
def test_unlock_url_treats_only_omitted_https_port_as_443(unlock_url, expected_origin):
    cli._validate_unlock_url(unlock_url, expected_origin)


@pytest.mark.parametrize(("unlock_url", "expected_origin"), [
    ("https://node.example:0/?token=opaque", "https://node.example"),
    ("https://node.example/?token=opaque", "https://node.example:0"),
    ("https://node.example:9443/?token=opaque", "https://node.example:8443"),
])
def test_unlock_url_rejects_zero_and_distinct_explicit_ports(unlock_url, expected_origin):
    with pytest.raises(ProtocolError, match="untrusted unlock URL"):
        cli._validate_unlock_url(unlock_url, expected_origin)


def test_request_accepts_authenticated_peer_and_configured_unlock_origin(tmp_path):
    socket_path = tmp_path / "private" / "broker.sock"
    response = {
        "ok": True,
        "locked": True,
        "unlock_url": "https://node.example:9443/?token=opaque",
    }
    thread = _fake_server(socket_path, response)

    assert cli.request(
        socket_path, {"action": "ping"},
        expected_unlock_origin="https://node.example:9443",
    ) == response

    thread.join(timeout=1)


def test_generate_entry_refuses_old_broker_without_sending_write(monkeypatch, capsys):
    calls = []
    def request(socket, payload, **kwargs):
        calls.append(payload)
        return {'ok': True}
    monkeypatch.setattr(cli, 'request', request)
    assert cli.main(['generate-entry', '--title', 'Example', '--username', 'user',
                     '--url', 'https://example.test', '--group', 'Web']) == 1
    assert [p['action'] for p in calls] == ['ping']
    assert 'lacks generated entry protocol' in capsys.readouterr().out


def test_fill_connection_timeout_is_reported_as_uncertain_without_retry(monkeypatch, capsys):
    calls = []

    def timed_out(_socket_path, payload, **_kwargs):
        calls.append(payload)
        if payload["action"] == "ping":
            return {"ok": True, **target_capabilities(), **expected_extension_capabilities()}
        _kwargs['before_send']()
        raise TimeoutError

    monkeypatch.setattr(cli, "request", timed_out)
    monkeypatch.setattr(cli.time, "monotonic", lambda: 100.0)

    assert cli.main(["fill", "opaque-handle", "--mode", "password", "--target", "synthetic-pin"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "outcome uncertain" in captured.err
    assert "do not retry automatically" in captured.err
    assert calls[0] == {"action": "ping"}
    assert calls[1:] == [{
        "action": "fill", "target": "synthetic-pin", "target_protocol": 1,
        "handle": "opaque-handle",
        "mode": "password",
        "start_deadline": 100.0 + cli.FILL_START_TIMEOUT,
    }]


def test_default_socket_uses_dedicated_xdg_runtime_subdirectory(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    assert cli.default_socket() == tmp_path / "akdbx" / "akdbx.sock"


@pytest.mark.parametrize('command', ['explicit', 'default', 'help', 'version', 'subcommand-help'])
def test_unused_inaccessible_runtime_does_not_block_cli(monkeypatch, tmp_path, capsys, command):
    """An explicit endpoint and local diagnostics do not need the default runtime."""
    if os.geteuid() == 0:
        pytest.skip('root can traverse a mode-000 directory')
    runtime = tmp_path / 'unavailable'
    runtime.mkdir(mode=0o700)
    monkeypatch.setenv('XDG_RUNTIME_DIR', str(runtime))
    runtime.chmod(0)
    try:
        if command == 'explicit':
            endpoint = tmp_path / 'private' / 'broker.sock'
            with running_broker(endpoint, Broker(SimpleNamespace(entries=[]), RecordingTyper())):
                assert cli.main(['--socket', str(endpoint), 'status']) == 0
            assert json.loads(capsys.readouterr().out)['ok'] is True
        elif command == 'default':
            assert cli.main(['status']) == 2
            captured = capsys.readouterr()
            assert not captured.out and 'default broker socket' in captured.err
            assert 'Traceback' not in captured.err
        else:
            arguments = {'help': ['--help'], 'version': ['--version'],
                         'subcommand-help': ['status', '--help']}[command]
            with pytest.raises(SystemExit) as exc:
                cli.main(arguments)
            assert exc.value.code == 0
            captured = capsys.readouterr()
            assert captured.out and not captured.err
    finally:
        runtime.chmod(0o700)


def test_rebrand_client_uses_existing_broker_without_restart(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    legacy = tmp_path / "agentic-kdbx" / "agentic-kdbx.sock"
    broker = Broker(SimpleNamespace(entries=[]), RecordingTyper())
    with running_broker(legacy, broker):
        assert cli.default_socket() == legacy
        assert cli.main(["status"]) == 0
        assert json.loads(capsys.readouterr().out)["locked"] is False


def test_rebrand_prefers_canonical_broker_when_both_exist(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    canonical = tmp_path / "akdbx" / "akdbx.sock"
    legacy = tmp_path / "agentic-kdbx" / "agentic-kdbx.sock"
    with running_broker(legacy, Broker(SimpleNamespace(entries=[]), RecordingTyper())):
        with running_broker(canonical, Broker(SimpleNamespace(entries=[]), RecordingTyper())):
            assert cli.default_socket() == canonical


def _fake_system_runtime(monkeypatch, tmp_path, mode=0o700):
    """Point the logind root at a fake /run/user and drop XDG_RUNTIME_DIR."""
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    root = tmp_path / "run-user"
    root.mkdir(mode=0o755)
    runtime = root / str(os.getuid())
    runtime.mkdir(mode=0o700)
    runtime.chmod(mode)
    monkeypatch.setattr(cli, "SYSTEM_RUNTIME_ROOT", root)
    return runtime


def _tmp_fallback() -> Path:
    base = Path(f"/tmp/akdbx-{os.getuid()}")
    if base.exists():
        pytest.skip("a real /tmp broker directory exists on this host")
    return base / "akdbx.sock"


@pytest.mark.parametrize("names", [("akdbx", "akdbx.sock"), ("agentic-kdbx", "agentic-kdbx.sock")])
def test_default_socket_without_xdg_finds_broker_in_system_runtime(monkeypatch, tmp_path, capsys, names):
    runtime = _fake_system_runtime(monkeypatch, tmp_path)
    endpoint = runtime / names[0] / names[1]
    with running_broker(endpoint, Broker(SimpleNamespace(entries=[]), RecordingTyper())):
        assert cli.default_socket() == endpoint
        assert cli.main(["status"]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_set_xdg_runtime_takes_precedence_over_system_runtime(monkeypatch, tmp_path):
    runtime = _fake_system_runtime(monkeypatch, tmp_path)
    xdg = tmp_path / "xdg"
    xdg.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(xdg))
    with running_broker(runtime / "akdbx" / "akdbx.sock", Broker(SimpleNamespace(entries=[]), RecordingTyper())):
        assert cli.default_socket() == xdg / "akdbx" / "akdbx.sock"


def test_explicit_socket_takes_precedence_over_system_runtime(monkeypatch, tmp_path, capsys):
    runtime = _fake_system_runtime(monkeypatch, tmp_path)
    missing = tmp_path / "explicit" / "akdbx.sock"
    (tmp_path / "explicit").mkdir(mode=0o700)
    with running_broker(runtime / "akdbx" / "akdbx.sock", Broker(SimpleNamespace(entries=[]), RecordingTyper())):
        assert cli.main(["--socket", str(missing), "status"]) != 0
    captured = capsys.readouterr()
    assert not captured.out and "broker is not running" in captured.err


def test_default_socket_without_xdg_or_system_broker_uses_tmp(monkeypatch, tmp_path):
    _fake_system_runtime(monkeypatch, tmp_path)
    assert cli.default_socket() == _tmp_fallback()
    monkeypatch.setattr(cli, "SYSTEM_RUNTIME_ROOT", tmp_path / "absent")
    assert cli.default_socket() == _tmp_fallback()


def _bind_socket(path):
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.close()
    path.chmod(0o600)


def test_default_socket_falls_back_when_system_runtime_entry_is_not_a_directory(monkeypatch, tmp_path):
    runtime = _fake_system_runtime(monkeypatch, tmp_path)
    (runtime / "akdbx").touch()
    (runtime / "agentic-kdbx").touch()
    assert cli.default_socket() == _tmp_fallback()


@pytest.mark.parametrize("blocker", ["file-at-socket", "file-at-directory"])
def test_system_runtime_non_socket_does_not_hide_legacy_broker(monkeypatch, tmp_path, blocker):
    runtime = _fake_system_runtime(monkeypatch, tmp_path)
    if blocker == "file-at-socket":
        (runtime / "akdbx").mkdir(mode=0o700)
        (runtime / "akdbx" / "akdbx.sock").touch()
    else:
        (runtime / "akdbx").touch()
    legacy = runtime / "agentic-kdbx" / "agentic-kdbx.sock"
    legacy.parent.mkdir(mode=0o700)
    _bind_socket(legacy)
    assert cli.default_socket() == legacy


@pytest.mark.parametrize("unsafe", ["group-writable", "symlink"])
def test_default_socket_ignores_untrusted_system_runtime(monkeypatch, tmp_path, unsafe):
    if unsafe == "group-writable":
        runtime = _fake_system_runtime(monkeypatch, tmp_path, mode=0o770)
        endpoint = runtime / "akdbx" / "akdbx.sock"
        endpoint.parent.mkdir(mode=0o700)
        _bind_socket(endpoint)
    else:
        monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
        root = tmp_path / "run-user"
        root.mkdir()
        real = tmp_path / "real"
        (real / "akdbx").mkdir(parents=True, mode=0o700)
        real.chmod(0o700)
        _bind_socket(real / "akdbx" / "akdbx.sock")
        (root / str(os.getuid())).symlink_to(real, target_is_directory=True)
        monkeypatch.setattr(cli, "SYSTEM_RUNTIME_ROOT", root)
    assert cli.default_socket() == _tmp_fallback()


def test_rebrand_fallback_does_not_bypass_symlink_checks(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    real_socket = tmp_path / "real" / "broker.sock"
    legacy = tmp_path / "agentic-kdbx"
    legacy.symlink_to(real_socket.parent, target_is_directory=True)
    with running_broker(real_socket, Broker(SimpleNamespace(entries=[]), RecordingTyper())):
        (real_socket.parent / "agentic-kdbx.sock").symlink_to(real_socket)
        assert cli.main(["status"]) == 2
        captured = capsys.readouterr()
        assert not captured.out
        assert "symlink" in captured.err.lower()


@pytest.mark.parametrize('capabilities', [
    {}, {'password_fill_protocol': True, 'password_fill_delivery': 'chromium-password-dom-v1'},
    {'password_fill_protocol': 1, 'password_fill_delivery': 'x11-send-event-v1'},
])
def test_password_commands_do_not_downgrade_to_window_only_broker(monkeypatch, capsys, capabilities):
    calls = []
    def request(path, payload, **kwargs):
        calls.append(payload)
        return dict(ok=True, **capabilities)
    monkeypatch.setattr(cli, 'request', request)
    assert cli.main(['fill', 'synthetic', '--mode', 'password', '--target', 'synthetic']) == 1
    assert calls == [{'action': 'ping'}]
    assert 'not sent' in capsys.readouterr().out


def test_password_pin_cli_passes_only_explicit_dom_metadata(monkeypatch, capsys):
    calls = []
    def request(path, payload, **kwargs):
        calls.append(payload)
        if payload['action'] == 'ping':
            return dict(ok=True, password_fill_protocol=1, password_fill_delivery='chromium-password-dom-v1')
        return dict(ok=True, target='a' * 64, expires_in=30, target_delivery='chromium-password-dom-v1')
    monkeypatch.setattr(cli, 'request', request)
    assert cli.main(['pin-password-target', '--page-id', 'page', '--frame-id', 'frame',
                     '--top-url', 'https://example.test/login', '--selector', '#password']) == 0
    assert calls == [dict(action='ping'), dict(action='pin-password-target', password_protocol=1,
                    page_id='page', frame_id='frame', top_url='https://example.test/login',
                    selector='#password', mode='password')]
    assert json.loads(capsys.readouterr().out)['target_delivery'] == 'chromium-password-dom-v1'


@pytest.mark.parametrize('options, error', [
    (['--mode', 'login'], '--mode login requires --username-selector'),
    (['--mode', 'login', '--username-selector', ''], '--mode login requires --username-selector'),
    (['--username-selector', '#username'], '--username-selector is only valid with --mode login'),
    (['--mode', 'username', '--username-selector', '#username'], '--username-selector is only valid with --mode login'),
])
def test_password_pin_selector_errors_are_local(monkeypatch, capsys, options, error):
    def forbidden(*args, **kwargs):
        pytest.fail('invalid selector combination reached broker RPC')
    monkeypatch.setattr(cli, 'request', forbidden)
    assert cli.main(['pin-password-target', '--page-id', 'page', '--frame-id', 'frame',
                     '--top-url', 'https://example.test/login', '--selector', '#password', *options]) == 2
    assert capsys.readouterr() == ('', error + '\n')


@pytest.mark.parametrize('command, options, field', [
    ('fill-generated', ['--target-url', 'https://example.test/reset', '--target', 'synthetic-pin'], 'handle'),
    ('commit-password', ['--site-accepted'], 'write_handle'),
    ('write-status', [], 'write_handle'),
    ('cancel-write', [], 'write_handle'),
])
def test_generated_handles_starting_with_hyphen_use_positional_separator(command, options, field):
    args = cli.parser().parse_args([command, *options, '--', '-synthetic-opaque-handle'])
    assert getattr(args, field) == '-synthetic-opaque-handle'


@pytest.mark.parametrize('global_options, options', [
    ([], []),  # the default origin is https://localhost:9443
    (['--unlock-origin', 'https://localhost:9443'], []),
    (['--unlock-origin', 'https://node.example:9443'], ['--local-port', '9444']),
    (['--unlock-origin', 'https://node.example:9443'], ['--unlock-url', 'https://127.0.0.1:9443']),
    (['--unlock-origin', 'https://localhost:9443'], ['--tls-cert', 'unused.pem', '--tls-key', 'unused.pem',
                                                     '--unlock-url', 'https://localhost:9443']),
])
def test_linux_serve_refuses_a_loopback_route_without_tls_cleanly(global_options, options, tmp_path,
                                                                 capsys, monkeypatch):
    monkeypatch.delenv('AKDBX_UNLOCK_ORIGIN', raising=False)
    monkeypatch.setattr(cli, 'start_unlock_server', lambda *_: pytest.fail('socket route started'))
    monkeypatch.setattr(cli, 'start_local_unlock_server', lambda *_a, **_k: pytest.fail('HTTPS route started'))
    assert cli.main(['--socket', str(tmp_path / 'unused.sock'), *global_options, 'serve',
                     str(tmp_path / 'unused.kdbx'), *options]) == 2
    captured = capsys.readouterr()
    assert not captured.out and ('needs --tls-cert and --tls-key' in captured.err
                                 or 'belongs to the Tailscale Serve socket route' in captured.err)
    assert 'Traceback' not in captured.err


@pytest.mark.parametrize('failure', [ValueError('synthetic private detail'), OSError('synthetic private detail')])
def test_linux_https_startup_errors_are_clean_and_private(failure, tmp_path, capsys, monkeypatch):
    def fail(*_args, **_kwargs):
        raise failure
    monkeypatch.setattr(cli, 'X11Typer', RecordingTyper)
    monkeypatch.setattr(cli, 'start_local_unlock_server', fail)
    assert cli.main(['--socket', str(tmp_path / 'private' / 'unused.sock'), '--unlock-origin', 'https://localhost:9443',
                     'serve', str(tmp_path / 'unused.kdbx'), '--tls-cert', 'c.pem', '--tls-key', 'k.pem']) == 2
    captured = capsys.readouterr()
    assert not captured.out and 'could not start HTTPS unlock' in captured.err
    assert 'synthetic private detail' not in captured.err and 'Traceback' not in captured.err


def _serve_capturing_brokers(monkeypatch, *, restore_link=False):
    """Run `serve` without listeners; return the brokers it builds."""
    from akdbx import web_unlock
    brokers = []
    listener = SimpleNamespace(shutdown=lambda: None, server_close=lambda: None)

    def start_unlock(broker, database, keyfile, _socket_path, origin):
        brokers.append(broker)
        if restore_link:
            # What start_unlock_server does, without a socket.
            broker.unlock_link = web_unlock.UnlockState(broker, database, keyfile, public_base=origin)
            broker.unlock_url = broker.unlock_link.url
            return listener, broker.unlock_url
        return listener, origin + "/?token=synthetic"

    monkeypatch.setattr(cli, "X11Typer", RecordingTyper)
    monkeypatch.setattr(cli, "start_unlock_server", start_unlock)
    monkeypatch.setattr(cli, "serve", lambda *_: None)
    return brokers


def test_linux_default_unlock_block_survives_a_cleared_runtime_folder(monkeypatch, tmp_path, capsys):
    # F2: XDG_RUNTIME_DIR is cleared on reboot or logout; the block must not be.
    import shutil
    runtime, state_home = tmp_path / "run", tmp_path / "state"
    runtime.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    monkeypatch.setenv("XDG_STATE_HOME", str(state_home))
    brokers = _serve_capturing_brokers(monkeypatch)
    serve = ["--unlock-origin", "https://node.example:9443", "serve", "synthetic.kdbx"]

    assert cli.main(serve) == 0
    brokers[-1].unlock_notifications.save_unlock_blocked(True)
    flag = cli.default_unlock_block_state(runtime / "akdbx" / "akdbx.sock")
    assert flag.parent == state_home / "akdbx" and json.loads(flag.read_text()) == {"blocked": True}
    assert flag.stat().st_mode & 0o777 == 0o600 and flag.parent.stat().st_mode & 0o777 == 0o700
    assert not [path for path in runtime.rglob("*") if "blocked" in path.name]

    shutil.rmtree(runtime)  # a reboot or logout
    runtime.mkdir(mode=0o700)
    assert cli.main(serve) == 0
    assert brokers[-1].unlock_notifications.load_unlock_blocked() is True

    # Another broker endpoint has its own flag.
    other = runtime / "other" / "broker.sock"
    assert cli.default_unlock_block_state(other) != flag
    assert cli.main(["--socket", str(other), *serve]) == 0
    assert brokers[-1].unlock_notifications.load_unlock_blocked() is False

    # The same trust checks apply: a flag another user could write refuses
    # start (H6); it neither starts blocked nor silently unblocks.
    flag.chmod(0o644)
    count = len(brokers)
    capsys.readouterr()
    assert cli.main(serve) == 2 and len(brokers) == count
    err = capsys.readouterr().err
    assert f"refusing to start: the saved unlock-link block {flag} cannot be trusted" in err
    assert "mode 0600" in err and "token=" not in err
    assert json.loads(flag.read_text()) == {"blocked": True}
    flag.chmod(0o600)

    # An explicit --notification-state keeps the block beside it.
    explicit = tmp_path / "explicit" / "notifications.json"
    assert cli.main([*serve, "--notification-state", str(explicit)]) == 0
    brokers[-1].unlock_notifications.save_unlock_blocked(True)
    assert json.loads(explicit.with_name("notifications.json.unlock-blocked").read_text()) == {"blocked": True}
    capsys.readouterr()


def test_serve_with_a_restored_block_prints_no_unlock_url(monkeypatch, tmp_path, capsys):
    # H2: a blocked link answers 403, so serve must not offer it.
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    brokers = _serve_capturing_brokers(monkeypatch, restore_link=True)
    state = tmp_path / "state" / "notifications.json"
    serve = ["--unlock-origin", "https://node.example:9443", "serve", "synthetic.kdbx",
             "--notification-state", str(state)]
    assert cli.main(serve) == 0
    assert "Open the private HTTPS page: https://node.example:9443/?token=" in capsys.readouterr().err
    brokers[-1].unlock_notifications.save_unlock_blocked(True)

    assert cli.main(serve) == 0
    err = capsys.readouterr().err
    assert brokers[-1].unlock_blocked
    assert "token=" not in err and "https://" not in err
    assert "unlock link is blocked" in err and "akdbx new-unlock-link --user-confirmed" in err
    assert "only after the user confirms" in err


def test_serve_can_keep_the_unlock_link_out_of_a_service_log(monkeypatch, tmp_path, capsys):
    # M1: a systemd journal or task output must not keep the link's token; interactive use still prints it.
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    _serve_capturing_brokers(monkeypatch)
    serve = ["--unlock-origin", "https://node.example:9443", "serve", "synthetic.kdbx",
             "--notification-state", str(tmp_path / "state" / "notifications.json")]
    assert cli.main([*serve, "--no-print-unlock-link"]) == 0
    err = capsys.readouterr().err
    assert "token=" not in err and "https://" not in err
    assert "Vault locked" in err and "akdbx status" in err
    assert cli.main(serve) == 0
    assert "Open the private HTTPS page: https://node.example:9443/?token=synthetic" in capsys.readouterr().err


def test_refusal_message_survives_a_failed_notifier_close(monkeypatch, tmp_path, capsys):
    # A state write that fails while the notifiers close must not hide which
    # permissions to fix: the diagnostic is printed first.
    from akdbx import notifications
    runtime, state_home = tmp_path / "run", tmp_path / "state"
    runtime.mkdir(mode=0o700)
    state_home.mkdir()
    state_home.chmod(0o775)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    monkeypatch.setenv("XDG_STATE_HOME", str(state_home))
    def failing_close(self):
        raise OSError(28, "synthetic ENOSPC")
    for name in dir(notifications):
        cls = getattr(notifications, name)
        if isinstance(cls, type) and hasattr(cls, "close"):
            monkeypatch.setattr(cls, "close", failing_close)
    brokers = _serve_capturing_brokers(monkeypatch, restore_link=True)
    serve = ["--unlock-origin", "https://node.example:9443", "serve", "synthetic.kdbx"]
    assert cli.main(serve) == 2 and brokers == []
    err = capsys.readouterr().err
    assert "refusing to start" in err and f"chmod 700 {state_home / 'akdbx'}" in err


def test_serve_refuses_a_group_writable_unlock_block_folder(monkeypatch, tmp_path, capsys):
    # H6: a common mode-0775 state folder must not start a broker that is
    # blocked with no way out: serve refuses and says how to fix it.
    runtime, state_home = tmp_path / "run", tmp_path / "state"
    runtime.mkdir(mode=0o700)
    state_home.mkdir()
    state_home.chmod(0o775)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    monkeypatch.setenv("XDG_STATE_HOME", str(state_home))
    brokers = _serve_capturing_brokers(monkeypatch, restore_link=True)
    serve = ["--unlock-origin", "https://node.example:9443", "serve", "synthetic.kdbx"]

    assert cli.main(serve) == 2 and brokers == []
    err = capsys.readouterr().err
    assert "refusing to start" in err and f"replaceable by another user: {state_home}" in err
    assert f"chmod 700 {state_home / 'akdbx'}" in err and "--notification-state FILE" in err
    assert "Broker ready" not in err and "https://" not in err

    # A private folder starts; a missing akdbx folder is made 0700, and the
    # block survives a restart.
    state_home.chmod(0o700)
    assert cli.main(serve) == 0 and not brokers[-1].unlock_blocked
    assert (state_home / "akdbx").stat().st_mode & 0o777 == 0o700
    brokers[-1].unlock_notifications.save_unlock_blocked(True)
    assert cli.main(serve) == 0 and brokers[-1].unlock_blocked
    assert "unlock link is blocked" in capsys.readouterr().err
    assert brokers[-1].unlock_link.new_link().startswith("https://node.example:9443/?token=")
    assert cli.main(serve) == 0 and not brokers[-1].unlock_blocked
