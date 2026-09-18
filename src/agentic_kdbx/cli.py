from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from pathlib import Path

from .broker import Broker, PynputTyper, serve
from .protocol import receive_message, send_message
from .web_unlock import start_unlock_server


def default_socket() -> Path:
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    base = Path(runtime) if runtime else Path(f"/tmp/akdbx-{os.getuid()}")
    return base / "agentic-kdbx.sock"


def request(socket_path: Path, payload: dict) -> dict:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(5)
    try:
        client.connect(str(socket_path))
        send_message(client, payload)
        return receive_message(client)
    finally:
        client.close()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="akdbx", description="Secret-withholding KeePass autofill broker")
    result.add_argument("--socket", type=Path, default=default_socket())
    commands = result.add_subparsers(dest="command", required=True)
    start = commands.add_parser("serve", help="unlock a KDBX and run the local broker")
    start.add_argument("database", type=Path)
    start.add_argument("--keyfile", type=Path)
    start.add_argument("--yes-on-fill", action="store_true", help="deprecated no-op: fills no longer require terminal approval")
    start.add_argument("--web-unlock", action="store_true", help="compatibility flag: private web unlock is always enabled")
    start.add_argument("--unlock-port", type=int, default=43128, help=argparse.SUPPRESS)
    start.add_argument("--unlock-url", default="https://vps-3857965a.tailb80cc4.ts.net:9443", help=argparse.SUPPRESS)
    search = commands.add_parser("search", help="return matching non-secret login metadata")
    search.add_argument("query", nargs="?", default="")
    fill = commands.add_parser("fill", help="autofill using a handle returned by search")
    fill.add_argument("handle")
    fill.add_argument("--mode", choices=("login", "username", "password"), default="login")
    commands.add_parser("status", help="check broker status")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "serve":
        database = args.database.expanduser()
        keyfile = args.keyfile.expanduser() if args.keyfile else None
        if args.yes_on_fill:
            print("Warning: --yes-on-fill is deprecated and has no effect; fills no longer require terminal approval.", file=sys.stderr)
        broker = Broker(None, PynputTyper())
        unlock_server, unlock_url = start_unlock_server(broker, database, keyfile, "127.0.0.1", args.unlock_port, args.unlock_url)
        print(f"Vault locked. Open over Tailscale: {unlock_url}", file=sys.stderr)
        print(f"Broker ready at {args.socket}; Ctrl-C locks it.", file=sys.stderr)
        try:
            serve(args.socket, broker)
        except KeyboardInterrupt:
            print("\nBroker locked.", file=sys.stderr)
        finally:
            unlock_server.shutdown()
            unlock_server.server_close()
        return 0
    payload = {"action": "ping" if args.command == "status" else args.command}
    if args.command == "search":
        payload["query"] = args.query
    elif args.command == "fill":
        payload.update(handle=args.handle, mode=args.mode)
    try:
        response = request(args.socket, payload)
    except (FileNotFoundError, ConnectionRefusedError):
        print("broker is not running", file=sys.stderr)
        return 2
    print(json.dumps(response, indent=2))
    return 0 if response.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
