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
markers select the PyObjC ApplicationServices bridge on macOS. This single
framework package supplies managed Accessibility and Core Foundation references. Use a virtual environment:

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

## Chromium CDP

Versions from 0.50.1 support CDP on macOS. The extension remains the default. Before enabling CDP, verify that only trusted
clients can reach the browser’s loopback TCP listener. For example, run Chrome
and the broker inside a dedicated VM that only you can access, with no port
forwarding. On a shared Mac, keep using the extension unless you have verified
equivalent isolation. Any local process that can reach the debugger can read
filled fields. A private profile and the broker’s socket UID check do not
restrict incoming connections to Chrome.

Once client isolation is in place, start Chromium with a dedicated
mode-0700 user-data directory and `--remote-debugging-port=0` under `umask 077`.
Give the broker that physical path with `--password-browser-profile` for
credentials and read pins and `--card-browser-profile` for cards. Identities
and SMS codes use the password profile when set, otherwise the card profile. Use `--browser-profile-root` to select a named slot at pin time.
Select `--route cdp` or configure `serve --default-fill-route cdp`. Check
`fill_routes` and the relevant `*_browser_configured` fields in `status`.

Before sending a WebSocket handshake, the broker checks the exact reciprocal
established IPv4 loopback connection in Darwin's kernel TCP table. The socket
owner must match the broker UID. The broker checks the profile ancestry,
directory and port file for extended allow ACLs. An unverifiable peer or path
refuses delivery. See [browser pins](../skills/akdbx/references/target-fill.md).

## Android devices (after 0.50.1)

A macOS broker drives an attached Android device or emulator with the same
checks as Linux. You run the device and its adb server; akdbx never starts or
stops them. Register it with:

```sh
akdbx android setup --attach SERIAL --adb-port 5037
```

`--adb` defaults to `adb` on `PATH`, then `platform-tools/adb` in `--sdk`,
`ANDROID_HOME`, `ANDROID_SDK_ROOT` or `~/Library/Android/sdk`. Setup stores
that path as given, without following links, so Homebrew's
`/opt/homebrew/bin/adb` keeps working after an upgrade. Setup checks
that the device is online on that server and turns off spoken passwords. It
writes `~/.config/akdbx/android-devices.json` (or `AKDBX_ANDROID_DEVICES`) as a
mode-0600 file in a folder that only you can write. On macOS that file must
have one hard link, and neither the file nor its folder may have an allow ACL
entry; deny-only entries are accepted. The broker reads the file at each
request, so it needs no restart.

Before it sends a byte to the adb server, or a WebSocket handshake to Chrome's
forwarded DevTools port, the broker finds that exact loopback connection in
Darwin's kernel TCP table and requires your UID as the owner of the server
side. The same Chrome typed check, site rules and single-use pins apply as on
Linux. See [Android devices](../skills/akdbx/references/android.md).

adb's loopback server accepts a client from any local account, and adb gives
that client full control of the device. akdbx checks the server's owner, not
its other clients. On a Mac with other user accounts, protect the adb port as
you would a browser debugging port.

The managed emulator (`android setup --create` or `--manage-avd`, `android
wake`) needs Linux with systemd and KVM. On macOS these commands refuse, and
`akdbx status` reports `android_managed_emulators: false`. To use an
emulator, start it yourself (for example from Android Studio) and attach it.

## Limits

- Native field protocol 1 (0.50.1+) supports retained Accessibility text
  controls in the frontmost native app. In System Settings → Privacy & Security →
  Accessibility, grant access to the process macOS identifies for the broker.
  Check `native_field_accessibility_granted: true` in `akdbx status`. The broker
  checks permission without prompting. It can operate only on fields that
  pass the [native field checks](../skills/akdbx/references/native-fields.md).
- Numeric window pins remain unavailable. `CGEventPostToPid` directs input to a
  process and cannot bind a keyboard event to a field. Secure Event Input also
  restricts synthesized keyboard input. Status reports
  `target_fill_delivery: "unavailable"` and an empty `target_fill_modes` list.
- From 0.46.0, `merge`, `admit` and `merge-status` use the built-in
  engine and the same encrypted snapshot and recovery protocol as Linux.
- Screen lock and the LaunchAgent need the user's GUI login session. There is
  no sleep-delay inhibitor. CI tests delivery of the lock notification in that
  session; a physical sleep/wake cycle and a live tailnet are outside this test.
- Safari needs a signed Apple browser wrapper. The fill extension and the
  separate QR capture extension use Chromium or Firefox native messaging, so
  neither runs in Safari.
- SMS ingest is available. SMS codes fill web pages through the paired extension,
  or through a CDP code pin once a browser profile is configured (`sms_fill_routes`
  then lists `cdp`). From 0.50.1 they also fill native app fields with
  `pin-native-target --mode code`, so status lists `native` too. A window pin has no SMS route on macOS.
- Android: attached devices only. The managed emulator requires a Linux host
  with systemd and KVM. CI has no Android device or emulator on macOS:
  GitHub's arm64 macOS runners have no nested virtualization, so the emulator
  cannot start there. The macOS proof covers the host side (see Validation).
- The Linux privileged secret-sink helper requires Linux peer credentials and
  systemd.
- iOS and iPadOS cannot run this Python broker. This is macOS support only.

## Validation

The `Native macOS broker` CI job uses a real Darwin runner for Unix peer
credentials, private socket RPC, encrypted save/reopen, checked TLS loading
and unlock, the extension protocol tests, and native field tests against a
separate AppKit application. The native field tests require the runner’s existing
Accessibility grant and fail if it is missing. It also installs and removes the
native host for each supported browser, runs guided setup with the
LaunchAgent, the capture host and lock notifications in the runner's GUI
session, and runs peer checks and DOM fills in Chrome. It runs the Android
route suite with a fake device. A real loopback adb server stand-in and a
DevTools forward owned by the runner user pass the kernel owner check.
`android setup --attach` runs the real check and a stand-in adb, then writes
the private device file. A stand-in owned by `_www` receives zero bytes from
setup, probes, helper runs and the DevTools handshake. It installs the same wheel in the release workflow. Linux simulations are not evidence of native macOS
behavior. Safari application signing, installation and live browser behavior
belong to the separate Safari extension delivery.
