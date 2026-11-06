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
from test_broker import target_capabilities, Entry, RecordingTyper, target_request, SECRET, running_broker, expected_merge_capabilities, expected_sso_capabilities, expected_passwordless_capabilities
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
    pin = target_request(broker)['target']
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
        except BaseException as exc:
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
        raise ProtocolError('connection closed')

    monkeypatch.setattr(cli, 'request', lost_reply)
    arguments = [action, 'synthetic-reference']
    arguments += (['--site-accepted'] if action == 'commit-password' else
                  ['--target-url', 'https://example.test', '--target', 'synthetic-pin'])
    assert cli.main(arguments) == 2
    captured = capsys.readouterr()
    assert not captured.out and 'outcome unconfirmed' in captured.err
    assert ('write-status' if action == 'commit-password' else 'do not retry automatically') in captured.err
    assert 'after request' not in captured.err
    assert calls == (['ping'] if preflight else
                     ['ping', 'ping', action] if action == 'fill-totp' else
                     ['ping', action] if action == 'fill-generated' else [action])


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
                args = (*args, '--target', ('synthetic-locked-pin' if broker.locked else target_request(broker)['target']))
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
            assert command("status") == {"ok": True, "locked": False, "version": "0.11.0", "unlock_notifications_supported": True, "unlock_notifications_protocol": 1, "writes_available": True, "recovery_required": False, **expected_merge_capabilities(available=True), **expected_sso_capabilities(), **expected_passwordless_capabilities(), "generated_entry_protocol": 1, "totp_supported": True, "totp_protocol": 1, **target_capabilities()}
            search = command("search", "example")
            assert typer.events == []  # Unlock/search must not trigger a fill.
            handle = search["entries"][0]["handle"]
            assert command("fill", handle, "--mode", "login") == {"ok": True, "filled": "login", "target_delivery": "x11-send-event-v1"}
            expected = [("type", Entry.username), ("key", "tab"), ("type", SECRET)]
            assert typer.events == expected
            assert command("fill", handle, expected_exit=1)["error"] == "unknown or expired handle; search again"
            assert typer.events == expected

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
    (None, [], [], "https://unlock.example.invalid:9443"),
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
            return {"ok": True, **target_capabilities()}
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
