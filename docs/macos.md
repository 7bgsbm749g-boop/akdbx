# macOS broker (0.43.0)

The macOS broker runs locally as your normal user with Python 3.11 or newer.
It uses the shared encrypted KeePass vault, metadata search, private HTTPS
pages, password writes, paired extension protocol and non-secret receipts.
The native host supports Chrome, Edge, Helium and Firefox 153+. From 0.49.0,
use `--browser chromium` for Chromium or `--browser brave` for Brave. Brave
reads Chrome’s host folder, so both use one launcher and registration.

Safari requires a containing app, a Safari native-messaging adapter and
signatures for the app and extension. Direct macOS distribution also requires
Developer ID signing and notarization. See Apple’s [packaging guide](https://developer.apple.com/documentation/safariservices/packaging-a-web-extension-for-safari)
and [distribution guide](https://developer.apple.com/documentation/safariservices/distributing-your-safari-web-extension).

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

Firefox 153+ is supported from 0.47.0 with its own native host and extension
build. See [Firefox setup](firefox.md); its macOS host manifest goes under
`~/Library/Application Support/Mozilla/NativeMessagingHosts`.

For user-started authenticator QR import, use the separate 1.1.0+ importer.
The default capture socket is `~/Library/Application Support/akdbx/run/u`.
From 0.49.0 the importer also accepts `--browser chromium|brave` and uses the
fill extension host's folders. Brave reads Chrome's folder, so Chrome's importer
registration already serves Brave.
See [private import](../skills/akdbx/references/private-import.md) for browser builds and registration.

## Guided setup and login

From 0.49.0, run `akdbx setup` in your macOS login session. For example:

```sh
akdbx setup --yes --vault /absolute/path/to/vault.kdbx \
  --tls-cert /absolute/path/to/localhost.pem --tls-key /absolute/path/to/localhost-key.pem \
  --browser chrome --start-at-login
```

Use `--dry-run --json` to check the plan. The login stage installs
`~/Library/LaunchAgents/org.akdbx.broker.plist`. It uses the selected Python and
vault, starts locked, and suppresses the unlock link in service output. Setup
checks the selected RPC socket before starting a broker. If the vault already has a
broker, use its socket and origin. The LaunchAgent preserves `AKDBX_LOCK_TIMEOUT`
as an explicit timeout in seconds. Changes to a loaded job apply at next login.
Use `akdbx status` to get the private link and check that
`lock_event_sources.macos` is `listening`. The broker listens for screen lock,
sleep and wake in the GUI login session. Losing a listening helper locks the vault.

## Private pages and phone codes

- For the relay, select `--access relay` in setup. Check `relay.connected` in
  broker status. TLS terminates at the broker. CI exercises a local test relay.
- For Tailscale Serve, setup prints the verified HTTPS loopback mapping. The
  broker also accepts a Serve backend on its private Unix socket. With the
  default RPC path the backend is `~/Library/Application Support/akdbx/run/u`.
  Use the root-run open-source Tailscale daemon for a filesystem socket. See
  [private pages](private-pages.md#tailscale-serve-unix-socket-linux-and-macos).
- One-shot unlock webhooks use `unlock_notifications_protocol: 1`. SMS ingest
  uses `sms_protocol: 1`; the phone or SMS provider needs access to the
  configured HTTPS origin. See [SMS sources](../skills/akdbx/references/sms.md).
- SMS codes fill web pages through the paired extension (fill extension
  0.13.0+, `extension_code_protocol: 1`): `pin-code-target --route extension`,
  then `fill-sms-code`. Status reports `sms_fill_routes: ["extension"]` and
  `code_browser_configured: false`. The extension applies the CDP code pin's
  field, focus, origin, single-use and expiry checks, and the code never
  reaches the agent. CI proves this route on macOS in Firefox.
- For a Chromium QR capture host, select `--capture-host --capture-browser
  chrome|edge|helium|chromium|brave` and supply `--capture-extension-id ID` after
  loading the capture extension. Setup runs the importer's `install-host
  --browser BROWSER` with the default capture socket. The importer uses that
  browser's `NativeMessagingHosts` folder and creates it when it is missing;
  Brave uses Chrome's folder. For Firefox, run `install-host --browser firefox`
  yourself. The host requires `totp_import_protocol: 1`. A
  capture still needs confirmation on the private page before a save.

## Limits

- The broker supports the extension route only. CDP profile options are
  refused before startup; this release does not claim macOS CDP peer verification.
- Native application/window fills are unavailable. Status reports
  `target_fill_delivery: "unavailable"` and an empty `target_fill_modes` list;
  there is no keyboard or clipboard fallback.
- From 0.46.0, `merge`, `admit` and `merge-status` use the built-in
  engine and the same encrypted snapshot and recovery protocol as Linux.
- Screen lock and the LaunchAgent need the user's GUI login session. There is
  no sleep-delay inhibitor. CI tests delivery of the lock notification in that
  session; a physical sleep/wake cycle and a live tailnet are outside this test.
- Safari needs a signed Apple browser wrapper. The fill extension and the
  separate QR capture extension use Chromium or Firefox native messaging, so
  neither runs in Safari. SMS codes fill only web pages (through the paired
  extension); a native app or window has no SMS route on macOS.
- The managed Android emulator requires a Linux host with KVM. The Linux
  privileged secret-sink helper requires Linux peer credentials and systemd.
- iOS and iPadOS cannot run this Python broker. This is macOS support only.

## Validation

The `Native macOS broker` CI job uses a real Darwin runner for Unix peer
credentials, private socket RPC, encrypted save/reopen, checked TLS loading
and unlock, and the extension protocol tests. It also installs and removes the
native host for each supported browser, and runs guided setup with the
LaunchAgent, the capture host and lock notifications in the runner's GUI
session. It installs the same wheel in the release workflow. Linux simulations are not evidence of native macOS
behavior. Safari application signing, installation and live browser behavior
belong to the separate Safari extension delivery.
