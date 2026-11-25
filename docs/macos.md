# macOS broker (0.43.0)

The macOS broker runs locally as your normal user with Python 3.11 or newer.
It uses the shared encrypted KeePass vault, metadata search, private HTTPS
pages, password writes, paired extension protocol and non-secret receipts.
The native host supports Chrome and Edge on macOS. Safari packaging and its
Apple native-messaging adapter are a separate change; this release alone does
not install or enable a Safari extension.

## Install and run

Install the same release wheel as Linux and Windows. The platform dependency
markers omit both python-xlib and pywin32 on macOS. Use a virtual environment:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install /path/to/akdbx-VERSION-py3-none-any.whl
```

Use an existing local KDBX file in a directory owned by your user, without
symlink components or writable ancestors owned by other users. Vaults and
private keys must be regular private files (mode 0600); the vault must have
one hard link. Extended allow ACLs on private files or their trusted path components are refused, including inherited grants; deny-only ACLs are accepted. Keep other editors and sync writers away during saves, as on
Linux. The broker never changes permissions on an existing vault for you.
Do not use a path through `/tmp` or `/var`, which are symlinks on macOS; use
the actual home directory or the physical path returned by `pwd -P`.

Configure a browser-trusted HTTPS certificate for `localhost` and its private
key as [Private HTTPS pages](private-pages.md) describes. Installing a local
certificate authority is a separate setup decision. Then start the broker:

```sh
.venv/bin/akdbx --unlock-origin https://localhost:9443 serve /absolute/path/to/vault.kdbx \
  --tls-cert /absolute/path/to/localhost.pem --tls-key /absolute/path/to/localhost-key.pem \
  --default-fill-route extension
```

The first launch creates and verifies missing default runtime parents with mode 0700. The default socket is `~/Library/Application Support/akdbx/run/s`, with mode
0600 in an owned mode-0700 runtime directory. `akdbx status` discovers that
same socket without XDG environment variables. An explicit global `--socket`
selects another private endpoint; macOS socket paths must be shorter than
104 bytes. Each accepted RPC is checked before reading a request. Every client connection checks the actual peer's effective user through
Darwin `getpeereid` and its kernel-reported PID. Socket path resolution uses
`F_GETPATH` on the validated directory descriptor and checks its ancestry and
identity again. Same-user compromise remains outside the broker's boundary.

Open the private unlock link and enter the master password there. It never
passes through the CLI, shell or agent. Chrome or Edge can use the existing
extension route:

```sh
.venv/bin/akdbx extension install --browser chrome
.venv/bin/akdbx --unlock-origin https://localhost:9443 extension build --output /absolute/path/to/extension
```

Load the built extension and pair it as [Extension route](../skills/akdbx/references/extension.md)
describes. Chrome's host manifest is under
`~/Library/Application Support/Google/Chrome/NativeMessagingHosts`; Edge's is
under `~/Library/Application Support/Microsoft Edge/NativeMessagingHosts`.
Pairing and sealed values use the same protocol as Linux and Windows.

Firefox 153+ is supported from 0.44.0 with its own native host and extension
build. See [Firefox setup](firefox.md); its macOS host manifest goes under
`~/Library/Application Support/Mozilla/NativeMessagingHosts`.

## Limits

- The broker supports the extension route only. CDP profile options are
  refused before startup; this release does not claim macOS CDP peer verification.
- Native application/window fills are unavailable. Status reports
  `target_fill_delivery: "unavailable"` and an empty `target_fill_modes` list;
  there is no keyboard or clipboard fallback.
- From 0.46.0, `merge`, `admit` and `merge-status` use the built-in
  engine and the same encrypted snapshot and recovery protocol as Linux.
- The guided `akdbx setup` command and login-service installation are not yet
  implemented on macOS. Use the explicit commands above; no system service,
  browser setting or trust setting is changed by installing the wheel.
- iOS and iPadOS cannot run this Python broker. This is macOS support only.

## Validation

The `Native macOS broker` CI job uses a real Darwin runner for Unix peer
credentials, private socket RPC, encrypted save/reopen, checked TLS loading
and unlock, and the extension protocol tests. It installs the same wheel in
the release workflow. Linux simulations are not evidence of native macOS
behavior. Safari application signing, installation and live browser behavior
belong to the separate Safari extension delivery.
