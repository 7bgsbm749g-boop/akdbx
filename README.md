# akdbx

`akdbx` is a local KeePass (`.kdbx`) autofill broker for AI agents. The broker
holds the unlocked vault. Agents search non-secret metadata, choose an opaque,
short-lived handle, and tell the broker which exact field to fill. The broker
puts the password, card number, code or address straight into that field and
returns only a receipt. The agent never receives the secret.

It covers logins (including SSO and emailed-code accounts), authenticator
codes, payment cards, addresses, password changes and generated passwords,
secrets that a site shows once, and merging encrypted vaults.

Source and issue tracker: [7bgsbm749g-boop/akdbx](https://github.com/7bgsbm749g-boop/akdbx).
Releases are on [GitHub Releases](https://github.com/7bgsbm749g-boop/akdbx/releases):
one wheel per version for Linux and Windows, with `SHA256SUMS` and a
build-provenance attestation. See [Releasing akdbx](docs/releasing.md) to cut a
release or upgrade a broker.

## Quick start: akdbx setup

Install akdbx (a release wheel or `pip install -e .` in a checkout), then run
one guided command (0.27.0+; the same on Linux and Windows):

```sh
akdbx setup
```

It asks a few questions with defaults and takes you from install to a working
broker. The broker is the only required part; every other stage is optional
and can be skipped (`--skip STAGE`):

1. **System check**: Python, the desktop (Linux X11 or Windows), and optional
   tools (KeePassXC CLI for merge, mkcert, Tailscale, Chromium browsers). It
   reports gaps and installs no system software.
2. **Vault**: your existing `.kdbx` file and key file, checked with the
   broker's own path and permission rules. Setup never creates, copies, opens
   or reads the vault, and never asks for the master password.
3. **Local page**: the certificate for the private HTTPS page. Setup checks an
   existing pair, or issues one with mkcert after you ran `mkcert -install`
   yourself (that command changes which certificates your computer trusts).
4. **Access**: local only; a private proxy such as Tailscale Serve
   (recommended for remote use; setup prints the `tailscale serve` command
   and never inspects or changes Tailscale); the akdbx relay (`akdbx relay enable`);
   another public tunnel that does not decrypt (instructions only); or a proxy
   that decrypts HTTPS, which setup warns about and does not configure. See
   [Unlock from the internet](#unlock-from-the-internet).
5. **Start at login**: a systemd user service on Linux, a logon task for your
   user on Windows. Setup never starts a second broker. The service runs
   `akdbx serve --no-print-unlock-link`, so the journal or task output never
   keeps the unlock link: run `akdbx status` to get it.
6. **Fill route**: the browser extension (`akdbx extension install` and
   `build`) and/or the CDP route.
7. **Optional features**: the authenticator capture host, unlock notifications
   and merge.
8. **Agent skill**: links `~/.claude/skills/akdbx` and `~/.codex/skills/akdbx`
   to the installed skill (a junction on Windows). It never replaces an
   existing folder or a different link.
9. **Final check**: `status`, the private unlock link if the vault is locked,
   and what remains for you.

Each stage detects what is already done and shows each change before it makes
it, so you can run setup again at any time. Every answer is also a flag.
`--yes` never asks, and only the flags of that run select a change: start at
login, the relay, browsers, a CDP profile, the capture host and the skill link.
Your earlier answers give only values such as paths and ports. `--dry-run` changes nothing, and `--json` prints a summary for
scripts and agents:

```sh
akdbx setup --yes --json --vault ~/vaults/passwords.kdbx --create-cert \
  --access tailscale --start-at-login --browser chrome --link-skill
```

Setup saves its answers (paths and choices, never a secret) in a private file:
`~/.config/akdbx/setup.json` on Linux, `%LOCALAPPDATA%\akdbx\setup.json` on
Windows. `akdbx setup --help` lists every flag.

## How it works

1. The broker starts **locked**. The user unlocks it on a private HTTPS page,
   on the broker's computer or from another tailnet device through Tailscale
   Serve; see [Private HTTPS pages](docs/private-pages.md). The master password
   never passes through chat, the CLI, arguments or the environment.
2. The agent runs `akdbx search`, `search-cards` or `search-identities` and gets
   metadata plus a single-use handle that expires after five minutes.
3. The agent verifies the page and field, then asks the broker to **pin** that
   exact element. A pin is bound to the tab, frame, origin and element and lives
   30 seconds.
4. `akdbx fill` (or `fill-card`, `fill-identity`, `fill-totp`) delivers the value
   to the pinned element. The response is a receipt with no value in it.

There is no reveal, export, clipboard or arbitrary-field command.

## Fill routes

Web fills reach the page through one of two routes. Both use the same search,
pin, fill and receipt model. Agents choose with `--route extension|cdp`, and
`status` reports `fill_routes` and `default_fill_route`.

| | Extension route (0.21.0+) | CDP route |
| --- | --- | --- |
| Browser | The user's everyday Helium, Chrome or Edge, with the akdbx extension | A Chromium profile started with `--remote-debugging-port` |
| Connection | Native-messaging host; values sealed to the extension (AES-256-GCM) | Chrome DevTools Protocol over loopback |
| Setup | Install the host, load the extension, pair once per browser session | Configure the profile at broker start |
| Sites see | The user's normal browser | A browser with a debugging port, which anti-bot checks often flag |
| Also | The user can click the extension to fill a login, card or address | The only route for capturing shown-once secrets |

**Prefer the extension route.** A debugging port gives every process of the same
OS user full control of that browser profile, and anti-bot and anti-fraud checks
often treat such a browser as a bot. In practice, Cloudflare's sign-in check
failed and Stripe declined a valid card (`generic_decline`) on the CDP route.
The same sign-in and card save worked first time through the extension in the
user's own browser. The CDP route stays for setups without the extension and for
secret capture.

Native applications (username and TOTP fields outside a browser) use window
pins: X11 on Linux, HWND on Windows. A window pin never receives a password.

## Platforms

- **Linux** (X11 desktop): the original platform. The setup notes in this
  README and the [VPS setup reference](skills/akdbx/references/vps-setup.md)
  describe it. The unlock page is the same loopback HTTPS page as on Windows
  (0.23.0+), optionally reached from other tailnet devices through Tailscale
  Serve or from any device through the akdbx relay (0.26.0+), or the earlier
  Tailscale Serve Unix-socket route.
- **Windows** (0.17.0+): the same features. It uses local named pipes, Windows
  access checks, a loopback HTTPS page (from 0.22.0 also reachable from other
  tailnet devices through Tailscale Serve, from 0.26.0 from any device through
  the akdbx relay) and directed Unicode window messages for
  native-app username and TOTP fills. See [Windows setup and validation](docs/windows.md)
  for browser and engine requirements, limits and pending checks. The Linux
  broker-socket and Unix-socket unlock notes below do not describe the Windows
  transport. [Private HTTPS pages](docs/private-pages.md) describes the unlock
  page for both platforms.

## Security model

- The unlocked database and plaintext secrets stay in the foreground broker process.
- The API has no reveal, clipboard, export, or arbitrary-field operation.
- Search returns only title, username, URL, group, a random authenticated handle,
  auth-method/passwordless flags, and TOTP-presence flags.
- Handles expire after five minutes and are consumed on the first fill attempt.
- The Unix socket and its directory are mode `0600` and `0700`. The CLI rejects
  symlinked or incorrectly owned runtime paths and verifies the server's Unix
  peer UID before sending a request.
- The broker starts locked. The user enters the master password only on the private HTTPS unlock page, never in chat, terminal input, arguments, or environment variables. The page is HTTPS on `127.0.0.1` with the broker's own certificate, or (Linux only) a Unix socket behind Tailscale Serve; it never binds the LAN or tailnet and never serves plain HTTP over TCP. Through the optional akdbx relay, TLS still ends in the broker: the relay forwards only encrypted bytes, and the broker trusts no name, certificate or header from it without checking.
- After unlock, password fills go to a retained DOM password input, through the extension route or an explicitly configured Chromium CDP connection. They never send password keys or Tab. Unsupported targets refuse delivery without terminal approval.
- Errors are deliberately generic after the typing boundary.

This prevents accidental disclosure into chat, command output, logs, process arguments, and agent RPC responses. It does **not** protect against a malicious process running as your OS user, a compromised target application, screen/key logging, or an agent that can redirect focus or inspect a filled web page. Password fills require a short-lived DOM target pin; see [the target contract](skills/akdbx/references/target-fill.md). The broker verifies the exact HTTPS page, main frame and retained editable password input. X11 window pins refuse password/login delivery. Application acceptance remains a caller check; malicious pages and compromised local processes are outside this boundary. Python cannot guarantee memory zeroization.

## Browser extension route (0.21.0)

The broker can also fill through the akdbx browser extension in the user's
everyday Helium, Chrome or Edge, reached through a native-messaging host. The
browser then needs no remote-debugging port, which would give every process
of the same user full control of that profile. Agents add `--route extension`
to `list-password-frames`, `pin-password-target`, `pin-card-target` and
`pin-identity-target`; the list, single-use pin, fresh handle and receipt model
of the CDP route is unchanged, with `extension-dom-v1` receipts. The user can
also click the extension (toolbar button, context menu or Alt+Shift+K) and
pick a saved login, card or address for the focused field; the popup shows
metadata only. `status` advertises `extension_protocol: 1`, `fill_routes`,
`default_fill_route` (`serve --default-fill-route`), `extension_connected`,
`extension_paired`, and `extension_version_expected`. Each `extension_browsers`
item shows the `version` that browser loaded and a `version_status`
(`current`, `outdated` or `newer`).

The extension has its own semantic version, starting at 0.1.0, separate from
the akdbx version; the popup shows it in its footer. After an akdbx update,
`version_status: "outdated"` means the unpacked copy is stale: run
`extension build` into the same folder again, then click reload on the akdbx
card in `chrome://extensions`. An extension built by akdbx 0.21.2 or earlier
reports no version; it still works and shows as outdated.

```bash
akdbx extension install --browser helium   # or chrome, edge; Windows and Linux; --python PATH (0.31.1+)
akdbx extension refresh                    # 0.31.1+: after an update moves akdbx to another folder
akdbx --unlock-origin "$AKDBX_UNLOCK_ORIGIN" extension build --output /path/to/akdbx-extension   # then Load unpacked
```

The extension pairs its ECDH public key with the broker once per browser
session: the popup shows a code computed from that key, and the broker's
private page shows the same code and asks for the master password. Every value
is sealed with AES-256-GCM to the extension, so the native host relays only
ciphertext. This adds `cryptography` as a runtime dependency. Origin
and frame identity come from the browser, never from page content; cards go
only to merchant frames or to the supported processor frames below them. On
Linux the host manifest goes in `~/.config/net.imput.helium`,
`~/.config/google-chrome` or `~/.config/microsoft-edge` under
`NativeMessagingHosts`. From 0.31.1 the Linux and macOS launcher names the folder
of the akdbx that installed it, so the host runs that akdbx even when the
interpreter has another one; see [host launcher](skills/akdbx/references/extension.md#host-launcher-0311).
See [the extension route](skills/akdbx/references/extension.md)
and [Windows setup](docs/windows.md#browser-extension-route). The Linux host is
covered by unit tests; the real-browser checks run on Windows.

Install steps for Windows and Helium are in
[Windows setup](docs/windows.md#browser-extension-route). Pairing lasts until the
browser or the broker restarts; the popup then shows a new code.

From extension 0.3.0 (akdbx 0.29.0), an origin change needs no rebuild, no
reload and no approval. The broker keeps a persistent identity key and signs
its current origin with a sequence number at each start. The extension learns
the key at its first pairing from the broker's HTTPS page on the built origin
(`/.well-known/akdbx-identity`), never from the native host alone, then follows only
origin changes that key signed with a higher sequence number. A changed broker
key is refused until the user clicks **Reset broker trust…** in the popup; the
reset keeps the trusted origin, and the new key must again come from that
origin's HTTPS page. There is no trust on first use: only a local
`akdbx extension build` sets the first origin. See
[Browser extension trust](docs/private-pages.md#browser-extension-trust).

## CDP route: install and run (Linux)

Linux desktop with X11, X-Resource 1.2 local PID support and EWMH window-manager metadata. Set `AKDBX_UNLOCK_ORIGIN` in your private local environment to the private page's HTTPS origin before starting the broker or using the CLI, and create its certificate as [Private HTTPS pages](docs/private-pages.md) describes. `https://localhost:9443` is the default:

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/akdbx --unlock-origin "$AKDBX_UNLOCK_ORIGIN" \
  serve /absolute/path/to/passwords.kdbx \
  --tls-cert ~/.config/akdbx/tls/localhost.pem --tls-key ~/.config/akdbx/tls/localhost-key.pem \
  --password-browser-profile /absolute/path/to/chrome-user-data
```

Keep the broker process running. Open its private unlock page (on this computer for a loopback origin, or from a tailnet device for a Tailscale origin) and enter the master password there. The broker needs no terminal input and can run in a persistent agent PTY that the user cannot access. After unlocking, use another shell—or an agent—to search, focus the destination, and explicitly fill:

```bash
.venv/bin/akdbx search github.com
.venv/bin/akdbx pin-password-target --page-id PAGE_ID --frame-id MAIN_FRAME_ID \
  --top-url VERIFIED_EXACT_HTTPS_URL --selector '#password' --mode password
.venv/bin/akdbx fill HANDLE_FROM_SEARCH --mode password --target TARGET_FROM_PIN
```

Before starting the broker, choose the private Chrome user data directory shown above (or set `AKDBX_PASSWORD_BROWSER_PROFILE`). Configure that browser's startup with `--user-data-dir=/absolute/path/to/chrome-user-data --remote-debugging-port=0` so Chrome writes its selected port and browser endpoint to `DevToolsActivePort`. [Chrome 136 and later require a non-default user data directory](https://developer.chrome.com/blog/remote-debugging-port); explicitly naming Chrome's default directory with `--user-data-dir` does not enable remote debugging there. This concerns the user-data root, not a profile name such as `Default`. A fixed debugging port does not provide `DevToolsActivePort` for this transport. The broker does not start or change Chrome. The profile must be owned, mode 0700, without symlink components; launch Chrome with `umask 077` so `DevToolsActivePort` is not writable by other users. On Linux, the broker also verifies the kernel UID of the connected TCP peer before the WebSocket handshake. An unavailable or ambiguous ownership check refuses; redirects and reconnection are forbidden. No profile means password fills refuse. Treat CDP as a privileged local interface.

### Several agent desktops: one Chrome per slot

A host can run several agent desktops at the same time. Each desktop is a *slot* (`slot1`, `slot2`, …) with its own display and its own Chrome. Start the broker with a profile root instead of a single profile:

```bash
.venv/bin/akdbx serve /absolute/path/to/passwords.kdbx --browser-profile-root /absolute/path/to/profiles
# or: AKDBX_BROWSER_PROFILE_ROOT=/absolute/path/to/profiles
```

Each slot `ROOT/slotN` is one Chrome user data directory, started as above (`--user-data-dir=ROOT/slotN --remote-debugging-port=0 --remote-debugging-address=127.0.0.1`, `umask 077`). Slot names match `slot[1-9][0-9]?`. The root replaces `--password-browser-profile` and `--card-browser-profile` for password, card and identity fills; the broker refuses to start with both. The single-profile options work as before when no root is set.

With a root, every CDP pin names its slot: `pin-password-target`, `list-password-frames`, `pin-card-target` and `pin-identity-target` take `--browser-slot SLOT`, and default to the `AGENT_DESKTOP_SLOT` environment variable (sent only to a broker that reports a root, so a single-profile broker keeps working in an agent desktop shell). The request field is `browser_slot`; the broker advertises `browser_slot_protocol: 1` (0.30.0+).

```bash
.venv/bin/akdbx pin-password-target --browser-slot slot2 --page-id PAGE_ID --frame-id MAIN_FRAME_ID \
  --top-url VERIFIED_EXACT_HTTPS_URL --selector '#password' --mode password
```

The broker takes only the slot name, never a path, and applies every profile check above to that exact directory `ROOT/SLOT`. It refuses an invalid name (including any path), an unknown slot, a slot request when no root is configured, and a pin with no slot when a root is configured; that refusal names the slots that exist. A pin keeps the browser connection it was made with, so a pin made in one slot never fills another slot's Chrome. The extension route takes no slot. `akdbx status` shows `browser_profile_root`, `browser_slots` (slot folders) and `browser_slots_live` (slots with a valid `DevToolsActivePort`; status does not connect, so a Chrome that stopped and left its file still shows here, and a pin then refuses).

`--top-url` is the exact observed URL, query and fragment included. When that URL contains a private token (a reset or activation code), give it with `--top-url-file FILE` instead: a mode-0600 file that holds only the URL. The CLI reads it, sends the URL unchanged and never prints it. `list-password-frames`, `pin-identity-target` and `pin-card-target` accept the same file form, plus `--frame-url-file` where `--frame-url` applies. See [exact URL with a private token](skills/akdbx/references/target-fill.md#exact-url-with-a-private-token).

Focus the password input before pinning. For `login`, pin with `--mode login --selector PASSWORD_SELECTOR --username-selector USERNAME_SELECTOR` and focus the username first. Username inputs require autocomplete field token `username`; password inputs require `current-password` or `new-password`. Valid ordered lists such as `current-password webauthn` and optional section/address prefixes are supported; malformed or conflicting tokens refuse. Delivery never rewrites the page's autocomplete attributes. Login fills both retained nodes with native DOM setters, without Tab or focus changes. Both saved and generated passwords require this path; a legacy X11 pin refuses them. HTTPS main-frame standard inputs are supported. Shadow DOM, custom controls, and ambiguous or changed fields refuse.

Broker 0.16.0 adds child-frame (iframe) delivery with integer `password_frame_protocol: 1` and `password_frame_policy: "same-site-chain-v1"`. The read-only `akdbx list-password-frames --top-url EXACT_HTTPS_URL` returns the tab's `page_id`, frame IDs, exact frame origins and visible field counts, without URLs or values, so callers need no raw CDP. Pin with `--frame-id CHILD_FRAME_ID --frame-origin https://login.example.com` added to `pin-password-target`; `--top-url` stays the exact top-level URL. The broker resolves the frame chain itself (in-process and out-of-process iframes) and requires every document from the top page to the field frame to be HTTPS, non-opaque and on one registrable domain as Chrome computes it. The field frame's origin must equal `--frame-origin` and the saved credential's origin. Each iframe owner is retained and must stay connected, visible and unchanged, without `srcdoc` or a script-less sandbox. A hostile page around a real login frame, a hostile frame in a real page, and any navigation refuse. See [child frames](skills/akdbx/references/target-fill.md#child-frames-iframes). The broker sends no submit key and does not use the clipboard.

Broker 0.18.0 adds KeePassXC/KeePass2Android additional URLs (`additional_urls_protocol: 1`, `additional_urls_policy: "kp2a-exact-origin-v1"`). Custom string fields `KP2A_URL`, `KP2A_URL_1`, … each add one exact HTTPS origin where the credential may fill, besides the main URL's origin; search shows them as `additional_urls`. The field document's origin must still equal one of these origins exactly, and every frame-chain and DOM check is unchanged. The metadata-only `akdbx add-url --url https://secure.example.com/ -- HANDLE` and `akdbx remove-url --url ORIGIN -- HANDLE` change one such field through the normal verified encrypted save without reading out or changing the password; `add-url` accepts only origins on the saved URL's site (same registrable domain under the vendored Public Suffix List). See [additional URLs](skills/akdbx/references/password-writes.md#additional-urls-0180).

Broker 0.19.0 adds `save-secret` (`secret_save_protocol: 1`, `secret_save_field: "password"`) to store a secret that already exists in a file, such as a service key, without anyone seeing it: `sudo cat KEYFILE | akdbx save-secret --stdin --title T --username U --url URL --group G` (or `--file PATH`; add `-- HANDLE` to replace a selected entry's password). The CLI checks the capability, lock state and write availability before it reads input, removes exactly one trailing line ending, and sends the value only over the private broker socket. The broker stores it in the protected Password field through the normal verified encrypted save; receipts and errors never contain it. See [secret save](skills/akdbx/references/password-writes.md#save-an-existing-secret-from-a-file-or-stdin-0190).

Some login forms omit semantic autofill hints or use `autocomplete="on"`.
When `status` advertises integer `password_purpose_protocol: 1`, callers who
independently verified a password-only field can pin it with
`--password-purpose current-password` (or `new-password` for an authorized
creation/change). The default remains strict. The option does not support
username/login modes or override `off`, malformed hints or a conflicting
password purpose; exact page, origin, retained input, focus and expiry checks
remain mandatory. It never edits site attributes or enables keyboard passwords.
See [the field-purpose contract](skills/akdbx/references/target-fill.md#password-inputs-without-semantic-autofill-hints).

Broker 0.14.1 adds integer `password_autocomplete_off_protocol: 1`. A verified
password-only input with `autocomplete="off"` additionally requires explicit
`--allow-autocomplete-off` together with `--password-purpose`. Neither default
pins nor purpose declarations alone accept `off`. Unknown or conflicting hints
still refuse; the page's attributes are retained unchanged and all normal DOM
target and focus checks apply to saved and generated passwords.

There are no per-fill approval prompts. `--yes-on-fill` is a deprecated compatibility no-op; it emits a deprecation warning. All fill commands now require `--target`. Omit `--yes-on-fill` from new commands. `--web-unlock` remains accepted for clarity; private web unlock is now the default and only unlock method, even when the flag is omitted. The former hidden terminal master-password prompt has been removed.

## Private unlock page

Start the broker without entering the master password locally, as above. The
broker starts locked. `status` and `search` responses provide a one-time
unlock link under your configured HTTPS origin. Open it, enter the KDBX master
password, and then use the broker normally. The page and URL are
non-cacheable, request logging is disabled, and the URL token is replaced
after a successful unlock.

Each link allows three failed master-password attempts in total (0.25.0+).
The third failure blocks the link at once, and time never expires it. While
it is blocked, `status` reports `unlock_blocked: true` without a link, and
waiting unlock notifications that opted in get an `akdbx.unlock-blocked`
event. A broker restart keeps the block. Only
`akdbx new-unlock-link --user-confirmed` replaces a blocked link, after the
user confirms that the failures were theirs; see
[Failed attempts block the link](docs/private-pages.md#failed-attempts-block-the-link).

Linux and Windows serve the same page. [Private HTTPS pages](docs/private-pages.md)
describes its setups:

- **Loopback HTTPS page** (`--tls-cert`, `--tls-key`): the broker serves HTTPS
  on `127.0.0.1` with your certificate. Open the link on the broker's
  computer. No Tailscale or other proxy is needed.
- **Unlock from another device** (add a Tailscale origin and `--local-port`):
  Tailscale Serve proxies the tailnet name to the loopback listener through a
  verified `https://127.0.0.1:PORT` target.
- **The akdbx relay** (`akdbx relay enable`, 0.26.0+): the page opens on any
  device at a random `https://<id>.akdbx.link` name (from 0.28.0 with no port
  in the address; brokers registered earlier used `:8443` and move by
  themselves at their next start). The relay forwards the encrypted connection
  and cannot read it; see [Unlock from the internet](#unlock-from-the-internet).
- **Tailscale Serve Unix socket** (Linux only, no TLS options): the earlier
  Linux route. The backend listens only on a Unix-domain socket in the
  broker's private runtime directory, and Tailscale Serve supplies HTTPS and
  the authenticated identity header. Windows has no such route, because
  Tailscale Serve proxies to Unix sockets only on Linux, macOS and BSD.

The CLI independently trusts that HTTPS origin; it rejects broker responses
containing an HTTP, malformed, credential-bearing, or different-origin unlock
link. Every deployment must configure the client with the intended origin
using global `--unlock-origin HTTPS_ORIGIN` (or `AKDBX_UNLOCK_ORIGIN`) before the
subcommand. With neither, the CLI uses the origin of an enabled akdbx relay
(0.26.0+), then `https://localhost:9443`. The same setting configures the broker's private-page origin at startup; the built-in default is `https://localhost:9443` on both platforms (before 0.23.0, Linux used a non-routable example). Existing deployments must set their current trusted origin before updating the CLI or restarting the broker. Keep real hostnames and deployment paths in private configuration, outside Git. A broker running under a separately configured account likewise
requires global `--broker-uid UID` (or `AKDBX_BROKER_UID`).

The master password travels inside the HTTPS connection directly to the local broker. It is never returned to the CLI or agent. Unlock remains valid for the lifetime of the broker process.

Key-file databases are supported with `serve DB --keyfile KEY`. Stop the broker with Ctrl-C to lock it and remove its socket. Explicit password writes and merges can modify the database; ordinary unlock, search and fill remain read-only.

## Unlock from the internet

Linux and Windows have the same choices. In order of recommendation:

1. **Local only**: the loopback HTTPS page on the broker's computer.
2. **A private proxy** such as Tailscale Serve: only your tailnet can reach the
   page. This is the most secure remote option; use it first.
3. **The akdbx relay** (0.26.0+): one command and no open port, router change
   or VPN. The relay forwards the encrypted connection; TLS ends in the broker
   with a key that never leaves it, so the relay cannot read the master
   password. Trust point: the relay operator controls the `akdbx.link` DNS
   and could get a second certificate for your broker's name, which the
   public Certificate Transparency logs would show.
4. **Another public tunnel that does not decrypt traffic**, such as Tailscale
   Funnel: available, but not recommended. On Linux it needs the loopback
   HTTPS page, not the Unix-socket route.
5. **A proxy that decrypts HTTPS**, such as Cloudflare Tunnel: STRONGLY
   DISCOURAGED. The proxy operator can read the master password.

The relay setup:

```sh
akdbx relay enable                     # register, get the certificate, save it privately
akdbx serve /absolute/path/to/passwords.kdbx   # no --unlock-origin, --tls-cert, --tls-key or --local-port
akdbx relay status                     # name, origin, certificate expiry, connected; never the secret
akdbx relay rotate                     # 0.29.0: a new name and certificate; stop the broker first
akdbx relay disable [--forget]         # stop using it (keep the files, or delete them)
```

`serve` then opens the private pages at the broker's relay origin, keeps one
connection to the relay, renews the certificate, and loads the new one without
a restart. Every akdbx command uses the relay origin by itself; an explicit
`--unlock-origin` or `AKDBX_UNLOCK_ORIGIN` still wins, except for
`serve --relay`, which ignores `AKDBX_UNLOCK_ORIGIN` and refuses another
`--unlock-origin`.

On a public route (3, 4 or 5), anyone on the internet can reach the page: the
secret link and the three-attempt block are the only protections.
[Unlock from the internet](docs/private-pages.md#unlock-from-the-internet) has
the details and the relay's files and checks.

## Shown-once secrets and service sinks (0.20.0)

`pin-password-target --mode read` pins one focused element that
shows a secret, with the same exact HTTPS URL, page, frame and same-site frame
checks as password fills. `capture-secret` makes the broker read that element
itself over its CDP connection and save it as a protected custom field of a
new or explicitly selected entry, through the verified encrypted save. The
pin refuses hidden, duplicated, editable, empty, spaced or multi-line targets,
and capture refuses if the element, focus, frame or URL changed. Pins accept
focus only, because X11 Chromium publishes selected text to PRIMARY.
`deliver-secret --sink NAME` writes such a field only to an operator-defined
`KEY=VALUE` file sink (`serve --secret-sinks PATH`), atomically and with an
optional fixed restart command. Files of another account go through a
root-owned, socket-activated helper with its own root-owned allowlist; see
[docs/secret-sinks.md](docs/secret-sinks.md). Status advertises
`secret_capture_protocol: 1`, `secret_sink_protocol: 1` and `secret_sinks`.
Responses are receipts only.

## Identity and address records (0.18.2)

`create-identity --title LABEL --group EXISTING_GROUP` returns a private HTTPS
save page for contact and postal details. The personal fields are protected
custom strings on a standard KDBX entry. `--fields tel,email` (0.28.2) limits
the page, and the stored fields, to the listed fields; without it the page
shows all fields. `update-identity HANDLE --title --group --fields` (0.28.3)
adds or changes the chosen fields of one existing identity, selected with a
fresh `search-identities` handle; its page never shows the saved values, and
the previous version stays in the entry history. `search-identities LABEL` returns
only labels, group paths and single-use handles. Login search excludes these
records. `pin-identity-target` and `fill-identity` deliver one field to a
verified and focused Chromium DOM element without using keys or submitting
the form. See [identity workflows](skills/akdbx/references/identities.md) for
supported fields, target discovery and example commands.

## Payment cards (0.14.0)

Cards use ordinary KDBX entries with custom fields; no format extension is
needed. `akdbx.card=v1` identifies a card. Cardholder name, number, expiry month,
expiry year and optional security code use protected custom strings named
`akdbx.card.name`, `.number`, `.month`, `.year` and `.csc`. These field names are
akdbx conventions; other clients can display them as custom fields.

`create-card --title LABEL --group EXISTING_GROUP` opens a private card-save
workflow. Enter card values only on the returned private HTTPS page. Never
put them in command arguments, agent messages or notes. `update-card HANDLE
--title EXACT_TITLE --group EXACT_GROUP` prepares an update. Updates preserve
the previous entry in KDBX History. `write-status` and `cancel-write` apply to
these saves. Persistence reopens and verifies every protected field before
replacing the encrypted vault. A private page expires after five minutes.

The page prefills `--title` and `--group`. The user can change the title, and
on a new card can choose another existing group (the KeePass folder) from a
list. The page does not create groups, and an update keeps the card's group.
Before saving, the page checks the number (Luhn checksum and length for the
detected Visa, Mastercard or American Express brand), the expiry (month 01 to
12, not in the past) and the security-code length for the brand. It shows the
detected brand and an error under each wrong field. The broker repeats the
same checks, so a request that bypasses the page is refused; a refused form
stays open for correction. The save button shows a busy state, then `Saved`,
or `Page expired`, `Vault changed`, `Cancelled` or `Not confirmed`. A saved
`write-status` includes the final non-secret `title` and `group`.

`search-cards QUERY` returns only title, group, brand, last four digits and a
single-use handle. Ordinary login search excludes card entries; password
operations refuse card records. Expired cards cannot be filled.

Card delivery uses a retained DOM element in a private isolated JavaScript world
through Chrome DevTools Protocol. It never sends keyboard events, Tab or submit,
and cannot direct input into the browser address bar through keyboard focus.
The broker checks the exact HTTPS page/frame URLs, unique selector, matching
`autocomplete` card token, element identity, editability, visibility and
occlusion. It repeats input identity and local DOM checks in the same JavaScript
task as the native value setter. Separate browser-native hit tests include
pointer-transparent covers before and after dispatch and require the exact
retained input/iframe owner at the point. A focus change cannot select a different destination. Replacement,
navigation, expiry or unsupported markup refuses the fill. An interrupted
delivery is reported as uncertain and must not be retried automatically.

Configure the broker with `serve DB --card-browser-profile /absolute/USER_DATA_DIR`
or `AKDBX_CARD_BROWSER_PROFILE`. This must be the existing, owned, mode-0700
Chrome **user-data directory**, containing an owned, non-symlink,
non-group/world-writable `DevToolsActivePort` file from a loopback debugging
port. The broker does not launch/restart Chrome, enable debugging, change
profiles or fall back to X11. Keep this directory and the debugging connection
private. An unconfigured/unsupported browser refuses fills; storage and search
remain available.

Before sending any WebSocket bytes, the broker verifies that its UID owns the
server side of the connected loopback TCP socket using Linux's bounded
/proc/self/net/tcp table. It keeps that exact socket and refuses redirects.
Missing or ambiguous ownership data refuses the connection, including stale
port files that point to another user's listener.

Chrome's debugging port grants browser control. Loopback binding alone does
not restrict it to one OS user. Use a host environment that restricts access
to trusted clients; the private profile-directory checks do not provide network
authentication for CDP. Do not enable a debugging port as an automatic workaround
for a refused fill.

After independently verifying the merchant and payment form, obtain the page
and frame IDs through your browser's DOM inspection tools, bring the intended
field into view, and pin its exact selector and autocomplete field type:

```bash
akdbx search-cards 'Personal Visa'
akdbx pin-card-target --page-id PAGE_ID --frame-id FRAME_ID \
  --top-url https://merchant.example/checkout \
  --frame-url https://merchant.example/checkout \
  --selector '#card-number' --field cc-number
akdbx fill-card CARD_HANDLE --target CARD_TARGET --field cc-number
```

Pins have a maximum lifetime of 30 seconds and are consumed on the first fill attempt. Use a fresh
search handle and pin for each field. Supported types are `cc-name`, `cc-number`,
`cc-exp-month`, `cc-exp-year`, `cc-exp` and `cc-csc`. Combined expiry requires
`--format MM/YY` or `MM/YYYY`; expiry year requires `--format YY` or `YYYY`.
Month/year selects are supported when the value matches an unambiguous option.
Main frames and same-origin iframes are supported. Version 0.14.0 adds the
explicit `--processor adyen` pin option, gated by integer
`card_processor_frames_protocol: 1` and `adyen` in `card_processors`.
Only production HTTPS `checkoutshopper-live.adyen.com` secured-field iframes
attested by Chrome to the selected merchant tab are accepted. All intermediate
merchant frames must be same-origin with the top page. The broker retains
the input and iframe-owner elements in isolated worlds, refuses unsupported CSS
transforms, motion paths, filters and masks (including Chromium mask-box images), and checks exact URLs,
frame ancestry, identity and occlusion before and after dispatch, and preserves
the single-use pin, deadline and receipt-only contract. Child input checks run
in the write task; cross-process ancestor checks run separately. A changed or
lost post-dispatch guard is uncertain and must not be retried automatically.
Version 0.14.2 also supports explicit `--processor computop` when `computop`
is advertised in `card_processors`. Only `https://www.computop-paygate.com/payssl.aspx`
with no query/fragment and its four exact hosted card id/name pairs are accepted.
Those fields use `autocomplete=off`; this does not allow off on default or Adyen
routes. Computop expiry requires MM/YY. Every existing processor ancestry,
retained-node, visibility, native hit-test and receipt guard remains. POST-loaded
blank frames additionally require the retained unique merchant POST form, exact
processor action and matching target name.
Version 0.18.1 supports `--processor stripe` for the Stripe Payment Element
iframe used by Cloudflare. It accepts only the Stripe card-entry endpoint and
its exact card number, combined expiry (MM/YY) and security code inputs.
Version 0.24.0 also accepts Stripe's classic Card Element iframe
(`js.stripe.com/v3/elements-inner-card-<hash>.html`) under the same
`--processor stripe`, advertised as `stripe_card_element: true`. The frame path
selects the input set: only the `cardnumber`, `exp-date` (MM/YY) and `cvc`
inputs with no id and the matching autocomplete token; decoy inputs refuse.
The Card Element fills only through `pin-card-target --processor stripe`; the
extension popup refuses that frame.
Other cross-origin frames, shadow DOM, unrecognised fields and native
applications remain unsupported. Merchant verification uses part of the pin's
lifetime, while the four-second fill deadline starts with the fill request.
An already expired pin is not issued. See the skill's card guide for the exact
processor pin command and independent merchant verification requirements.

The success receipt contains only the field type and transport, never a card
value. It confirms the element accepted the value at dispatch; it does not
prove merchant acceptance or authorize a purchase. The intended page receives
the card values. A malicious page, compromised browser or process with the same
OS-user privileges remains outside this boundary. Do not read filled card values
back through browser tools or capture unmasked fields in screenshots.

## Card-save notifications

Private card forms can resume the same agent task through a one-shot HTTPS
webhook, with the same bounded sender and private persistent storage used by
unlock notifications. Register before sharing the form; no completion message
or polling schedule is needed:

```bash
.venv/bin/akdbx subscribe-card-save WRITE_HANDLE --webhook-url-file /private/url-file
.venv/bin/akdbx card-save-subscription-status SUBSCRIPTION_ID
.venv/bin/akdbx unsubscribe-card-save SUBSCRIPTION_ID
```

Require `card_save_notifications_protocol: 1` and
`card_save_notifications_until_result: true` from the running broker. Waits have
no subscription TTL. The existing form deadline emits `expired`; cancellation,
invalidation and persistence failure also emit terminal results. A validation
typo leaves the form pending. Callbacks contain only `akdbx.card-save`, a result
state and opaque event/subscription IDs. Card values, metadata, form tokens and
write handles are excluded. Pending callbacks survive restart in the configured
notification-state file plus `.card-saves`; an unfinished form reports
`interrupted` because private form contents are never restored. See the
[card-save notification workflow](skills/akdbx/references/card-save-notifications.md)
for host registration, verification, duplicate handling and cleanup.

## Unlock notifications (0.11.0)

Agents can subscribe to a one-shot unlock webhook and end their turn. In T3,
create a webhook task bound to the current thread, register its returned URL,
and let T3 resume the thread when the broker posts the unlock event. No “unlocked”
chat reply, active agent wait or polling schedule is needed. Other agent hosts
can use their own incoming webhook/event adapters.

```bash
.venv/bin/akdbx subscribe-unlock --webhook-url-file /private/url-file
.venv/bin/akdbx unlock-subscription-status SUBSCRIPTION_ID
.venv/bin/akdbx unsubscribe-unlock SUBSCRIPTION_ID
```

The URL file must be an owned mode-0600 regular file. The URL is private and is
never echoed in receipts. Events contain only `event: "akdbx.unlocked"`,
`locked: false` and opaque subscription/event IDs. Registration cannot miss a
racing unlock; an already-unlocked broker queues the event immediately. Delivery
runs outside the unlock request, uses verified HTTPS without redirects, and
retries at most three times with the same event ID. Subscriptions wait until
unlock or explicit cancellation by default. Pending
callbacks survive restarts through the configured private notification-state
file; choose persistent storage outside `/run` for host reboot survival. Only an
explicitly requested time-limited wait uses `--ttl 60..3600`. Delivery attempts
and the number of stored subscriptions remain bounded. The agent must remove
the host trigger and recheck broker readiness before continuing.

Require the running broker's `unlock_notifications_supported: true` and integer
`unlock_notifications_protocol: 1`; source/CLI updates alone do not activate a
running broker. See [the notification workflow](skills/akdbx/references/unlock-notifications.md)
for exact T3 registration, cleanup and recovery.

From 0.25.0, a subscription can opt in with `blocked_events: true` (the CLI
sends it with `subscribe-unlock --blocked-events` when the broker advertises
`unlock_notifications_blocked_event: true`). When the unlock link is blocked after three failed attempts, each such
waiting subscription also gets `{"event": "akdbx.unlock-blocked", "locked":
true, "unlock_blocked": true, ...}` with a new event ID. The subscription stays
`subscribed` and later sends the normal `akdbx.unlocked` event to the same URL.
Subscriptions without the opt-in get only `akdbx.unlocked`. The block itself
is saved, so a restarted or rebooted broker stays blocked and sends the blocked
event again to waiting opted-in subscriptions.

## Authenticator codes (0.10.0)

`akdbx` can import TOTP authenticator keys and directly fill the current code
without returning the key or code to the agent. It supports RFC 6238 SHA-1,
SHA-256 and SHA-512, six or eight digits, and periods from 15 to 120 seconds.
The default for a manual Base32 key is SHA-1, six digits and 30 seconds.
Other settings require an `otpauth://totp/` URI. HOTP and Steam codes are not
supported. There is no code-reveal or key-export command.

Version 0.12.0 adds [private QR/Google transfer import and Chrome native capture](skills/akdbx/references/private-import.md).
The private setup page can decode QR images on the user's device, review a
complete Google export batch, and save one explicitly selected account to an
existing entry. It copies the existing key without removing phone accounts or
changing website 2FA. An optional Linux Chrome extension sends one selected
site's setup QR directly to a local native host/broker; private confirmation is
still required before any save. The agent receives only receipts, never keys,
codes or QR images. Authy/Microsoft export restrictions are not bypassed.
Require `totp_import_supported: true` and integer `totp_import_protocol: 1` in
the running broker. Installation does not activate an already-running broker.

Check that `status` advertises `totp_supported: true`, integer `totp_protocol: 1`,
and the existing target-fill protocol. New CLI commands refuse old brokers.
Updating source or pushing a commit does not update a running broker: install
the tested version and coordinate its normal restart/private unlock first.

For one-time import, select an existing account entry with `search`, then pass
its fresh handle and all four exact metadata fields:

```bash
akdbx setup-totp HANDLE --title 'Example' --username 'alice@example.com' \
  --url 'https://example.com/login' --group 'Web'
```

This returns a private `/totp?token=...` page. The user enters the site's setup
key or otpauth URI there and confirms the displayed account. Never put keys,
URIs or generated codes in CLI arguments, environment variables, chat, logs,
screenshots or notes. The page uses the existing Tailscale private-write
transport; it accepts no secrets through agent RPC. Check
`write-status -- WRITE_HANDLE` for `state: saved`. A cancelled, expired or stale request cannot
save; an existing OTP field requires explicit `setup-totp ... --replace`.
Private imports save to KeePass only: they do not enable or change site 2FA.
This version attaches authenticators to existing entries, including managed
passwordless identities; it does not create standalone TOTP-only records.

The key is stored in the standard protected KDBX `otp` field. The broker
reopens the encrypted candidate and verifies the exact protected field before
replacing the vault. Existing passwords, notes and other fields are preserved;
replacing a key keeps the previous entry in encrypted history. No existing key
is exposed on the import page. Keep recovery methods under your own control.
Storing passwords and TOTP keys on the same host reduces their independence;
the broker does not protect against a malicious process sharing its OS account.

After import, search returns `totp_configured: true` for that entry. Confirm the
site and account, focus the code field in the verified foreground window, then
pin and fill using fresh single-use references:

```bash
akdbx search example.com
akdbx pin-target --pid VERIFIED_PID --window VERIFIED_X11_CLIENT_WINDOW
akdbx fill-totp FRESH_SEARCH_HANDLE --target-url 'https://example.com/challenge' \
  --target FRESH_TARGET_PIN
```

The asserted target URL and the entry URL must use ASCII HTTPS spelling
(punycode for internationalized hosts) and match in origin; X11 does
not attest the DOM field, browser tab or origin. The caller must verify them.
The receipt contains only `ok`, `filled: totp` and `target_delivery`.
The broker refuses a code with less than eight seconds remaining, returning
a non-secret `retry_after` delay. Wait for the next period, then search and pin
again. Keep the host clock synchronized. Never retry an uncertain/partial
dispatch automatically or read back a filled code; verify the site's outcome.
This handles standard authenticator challenges, not push approvals, SMS,
passkeys, recovery checks or organization-specific device requirements.

Algorithm references: [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) and
[Google's Key URI format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format).

## Encrypted vault merge (0.8.0)

```bash
akdbx status
akdbx merge /absolute/path/to/other.kdbx --check
akdbx merge /absolute/path/to/other.kdbx
akdbx merge /absolute/path/to/other.kdbx --refresh-target
akdbx merge /absolute/path/to/other.kdbx --refresh-target --preserve-conflicts --check
akdbx merge /absolute/path/to/other.kdbx --refresh-target --preserve-conflicts
akdbx merge-status OPERATION_ID
```

Require broker 0.8.0 or newer, `merge_protocol: 1`, `merge_available: true` and no recovery
block. The broker privately reuses its held password and key file. Locked
operation returns the existing private HTTPS unlock link and a clear command
continuation. Different source credentials are not supported in this release.

The native dependency is root-owned `/usr/bin/keepassxc-cli` >=2.7.10,<2.8
(tested: 2.7.10). Its UUID-aware merge keeps newer entry versions and combines
history. A broker deletion pass applies timestamped UUID tombstones; newer edits
survive. Default mode refuses genuine equal-second conflicts and loss of surviving
history/fields. Explicit `--preserve-conflicts` retains every distinct original
active/history entry version in opaque preservation attachments inside the encrypted
KDBX, including original timestamps, fields, attachment bytes and referenced icons.
Newest active values win; equal-time active ties prefer the current disk target,
then broker image, then source. No original timestamp is changed. Native History
can still collapse or prune versions; the verified preservation records retain
them across repeats, reconciliation and history limits. These managed records are
excluded from broker search/fill and password destinations. There is no capsule
restore/view/export command in this release. See the workflow for the documented
format and limits. Destination database settings remain authoritative;
source custom icons/CustomData follow native engine rules. See the workflow for
metadata conflict details and unsupported credential types.

The default still refuses externally changed targets. Explicit
`--refresh-target` requires `merge_refresh_target_supported: true` and combines
the last verified encrypted broker image, the current disk target and the
incoming source. It privately reuses held credentials, retains all three inputs,
checks both native merge stages, then applies all deletion records. Broker-only,
external-only and incoming-only entries survive according to the conflict and
deletion rules. `--check` also works with this option and adopts no state.
Successful reconciliation refreshes the broker and invalidates handles even if
the disk file already held the full result. Bad current keys, incomplete receipts
and races remain failures. This is not a plain reload or a security override.
For the preservation option require `merge_preserve_conflicts_supported: true`
and `merge_preservation_policy: "capsule-v1"`. Use both options for explicit authorized
reconciliation. A transformed merge does not satisfy an unmodified KeePassium
consecutive-save byte contract. The CLI checks the exact policy before sending
the request; raw RPC integrations must do the same. Version 0.6.0 also requires
`merge_active_verification: "semantic-v1"`. It verifies active values separately
from native serialization and independent entry location changes, while keeping
the capsule-v1 format and exact original payloads unchanged. Standard/custom
values, protection against downgrade, attachments, active times/expiry and
native location selection remain checked. Known tag/default/protection/settings
and CustomData clock transformations are documented in the workflow. Refusals
add only fixed aggregate `verification_diagnostics` categories; they expose no
record identities, field names/values or secret digests. Status advertises
`merge_diagnostics: "categories-v1"`. Raw callers must require these capabilities
and verify `active_verification: "semantic-v1"` in saved/check receipts.
PyKeePass is pinned to the
tested 4.2.0; another version disables this policy. `--check` supports both options.
The basic command remains compatible with 0.3.0; the new CLI rejects unsupported
brokers before sending an opt-in. Activating 0.8.0 in place of an older running
process still requires a coordinated restart/private unlock with its latest
encrypted state retained; future external saves need no additional unlock.

Both encrypted originals and a reopened encrypted candidate are retained in a
private recovery directory beside the target. The source stays unchanged.
Replacement uses the existing advisory lock, change checks, restrictive
permissions, fsync and atomic rename. Success refreshes the active broker and
invalidates old selection/write handles. Responses contain only status, counts,
encrypted checksums and durable receipt paths. No plaintext password or raw engine output
is returned or written to disk. A lost response must be resolved with
`merge-status`, not an automatic retry. Incomplete receipts block use after
restart until authorized recovery. Keep competing editors/sync writers away
from the inputs during merge; filesystem advisory locks cannot constrain them.

Read [the supported merge workflow](skills/akdbx/references/merge.md)
for the normal command path, exact semantics, recovery and activation. A source
update does not replace a running broker. Development uses synthetic vaults and
isolated sockets only; it does not access or restart the production broker.

## Passwordless email-code identity records (0.9.1)

`create-passwordless-entry --title TITLE --username ACCOUNT --url SITE --group GROUP
--auth-method email_code` saves an authorized account verified through the site's
native emailed-code sign-in. It saves an empty Password field, not the one-time
code. It neither labels the account as SSO nor creates/copies a password.
Require CLI/broker 0.9.1 or newer, `passwordless_identity_supported: true`, integer
`passwordless_identity_protocol: 1`, and `email_code` in
`passwordless_auth_methods`. The CLI checks these capabilities before dispatch;
an older running broker is refused even if new CLI help is present.

This separate action reuses SSO's metadata validation, duplicate checks,
verified encrypted persistence, backups and recovery rules. The entry has
`akdbx.passwordless: "v1"` and `akdbx.auth-method: "email_code"`; search returns
`passwordless: true` and `auth_method: "email_code"`. Password/login fills and
password updates/generation refuse it. Username-only fill still requires the
existing fresh target pin. Empty or incomplete managed markers fail closed.
Google/GitHub remain on the unchanged SSO protocol 1 and `create-sso-entry`.
See [email-code save and parent activation](skills/akdbx/references/password-writes.md#passwordless-email-code-identity-records-091).

## Passwordless SSO identity records (0.8.1)

`create-sso-entry --title TITLE --username ACCOUNT --url SITE --group GROUP
--auth-method google` saves an explicitly authorized Google SSO account with
an empty Password field and clear provider/no-separate-password markers.
`--auth-method github` is also supported. It never generates, copies, accepts
or exports a password, opens a password form, or types credentials. Require
CLI/broker 0.8.1 or newer, `sso_identity_supported: true`, integer
`sso_identity_protocol: 1` and the selected provider in `sso_auth_methods`.
The CLI checks the running broker before dispatch. Existing group selection,
same-origin/account duplicate checks, write safety, conflicts, recovery refusal,
verified encrypted persistence and backups are reused. Search reports provider
and passwordless flags; login/password fills and password writes refuse these
records, while username-only fill remains available. The ordinary chosen-
password workflow below still requires private confirmation and a nonempty
password. Read [the exact SSO workflow and activation requirements](skills/akdbx/references/password-writes.md#passwordless-sso-identity-records-081).

## Password writes (0.2.0)

`akdbx --version` reports the CLI version. Broker `status` reports its own
`version`, `writes_available` and `recovery_required`; require an unlocked,
write-capable broker version 0.12.0 or newer before changing a website password.
Password fills also require integer `password_fill_protocol: 1`,
`password_fill_delivery: "chromium-password-dom-v1"`, and
`password_browser_configured: true` in the running broker's status.

- `create-entry --title TITLE --username ACCOUNT --url SITE --group GROUP`
- `update-password SEARCH_HANDLE --title TITLE --username ACCOUNT --url SITE --group GROUP`
- `generate-password SEARCH_HANDLE --title TITLE --username ACCOUNT --url SITE --group GROUP [--length 24] [--symbols '!@#$%*-_+=?'] [--single-field]`
- `fill-generated --target-url VERIFIED_RESET_URL --target TARGET_FROM_FRESH_PIN -- SINGLE_USE_FILL_HANDLE`
- `commit-password --site-accepted -- WRITE_HANDLE`
- `write-status -- WRITE_HANDLE`
- `cancel-write -- WRITE_HANDLE`

Put options before `--` and the returned handle after it. This also accepts
opaque handles from older running brokers that start with `-`.

Update/generation requires all exact search metadata and consumes the fresh
search handle. Creation checks the destination group and rejects duplicate
site/accounts. Create/update returns a private confirmation page where the user
reviews metadata and enters/repeats a chosen password; secrets never pass
through the CLI. Generated reset passwords remain in broker memory: two
single-use references fill password and confirmation fields on the verified
broker desktop, then explicit site acceptance permits saving the same secret.
With `--single-field` (0.31.0+, status `generated_single_field: true`), a form
with one new-password field and no confirmation field gets one `password`
reference, and the commit needs that one fill plus site acceptance.
Generated resets require the entry and asserted target URLs to use ASCII HTTPS
spelling (punycode for internationalized hosts) and to match in origin.
No operation exports, shows, logs or copies passwords.

Writes expire after five minutes and vanish on restart. Site rejection requires
cancellation, not a vault overwrite. Saves serialize against fills/searches,
check on-disk conflicts, preserve history and unrelated vault data, verify the
encrypted candidate, retain mode-0600 encrypted backups and replace atomically.
Failed or uncertain saves never return success. Successful writes become
immediately searchable/fillable and invalidate previous selection handles.
The advisory disk lock does not constrain uncooperative external editors;
arrange exclusive vault editing during saves.

See [password workflows and recovery](skills/akdbx/references/password-writes.md)
for reset coordination, policy constraints, focus/origin checks, cancellation,
conflicts, backup recovery and activation. Installing new code does not replace
a running broker: coordinate restart and private re-unlock with its owner after
any live interaction ends.

## Agent contract

The agent skill is [skills/akdbx/SKILL.md](skills/akdbx/SKILL.md). Install it by
linking your agent's skills directory to that folder, so it stays in sync with
the checkout (`akdbx setup --link-skill` does this; a wheel install also ships
the skill); agents can then invoke it as `$akdbx`. It explains route choice,
unlock, account selection, pinning, fills, writes and recovery, and links a
reference file for each workflow. The [setup reference](skills/akdbx/references/vps-setup.md)
covers the Linux desktop, socket discovery, startup and Tailscale configuration
with portable examples.

An agent should:

1. Run `akdbx status`, then `akdbx search <site-or-app>`, and pick the right
   account from the non-secret results.
2. Verify the destination, pin the exact field (preferably through the extension
   route), and fill it once with a fresh handle. The user has authorized fills,
   so no per-fill approval is needed.
3. Never ask for the master password, and never read, log, copy or inspect a
   filled field.
4. Search again if a handle expires. `autofill not started` means nothing was
   sent. A timeout or lost connection can mean the value was already delivered,
   so check the page and never retry automatically.

A running broker keeps its loaded code until it restarts. The workflow that owns
it stops the old broker, starts the new version with the same database, key
file, socket and desktop environment, and asks the user for a fresh private
unlock. Old handles do not survive a restart. See the
[VPS setup reference](skills/akdbx/references/vps-setup.md) for the deployment
command.

Remote unlock requires Tailscale Serve to proxy HTTPS either to the broker's
Unix socket (Linux) or to the broker's own HTTPS listener through a verified
`https://127.0.0.1:PORT` target (Linux and Windows). Never map it to plain
HTTP on a loopback TCP port or to an `https+insecure://` target: another local
user could take that port while the broker is stopped. Root must install a
Unix-socket mapping with Tailscale 1.98.9 or newer (older versions had a
Unix-socket Serve authorization flaw). Starting an updated broker does not
migrate an existing Serve mapping; follow the setup reference when deployment
changes are authorized.

## Development

```bash
.venv/bin/pip install -e '.[test]'
.venv/bin/pytest -q
```

Card browser tests skip locally if Chrome/Chromium, Xvfb or openssl is missing.
The foreign-UID listener test requires an explicit opt-in and passwordless
`sudo -n -u nobody`. To require both native checks locally, install those
dependencies and run:

```bash
AKDBX_REQUIRE_CARD_CHROMIUM=1 AKDBX_TEST_FOREIGN_UID=1 \
  .venv/bin/pytest tests/test_cards.py tests/test_card_target.py tests/test_card_chromium.py -q
```

Card CI enables both requirements and rejects any skipped case.

Merge integration tests require the native KeePassXC CLI dependency above.
Tests generate synthetic KDBXs under pytest's temporary directory, with isolated
RPC and HTTP Unix sockets. Keep temporary fixtures outside every synced vault;
store retained evidence in the project's gitignored `evidence/` directory, outside
synced vaults.
Most fixtures use a reduced KDF cost. `test_full_argon2d_41_profile` separately
uses KDBX 4.1/AES-256/Argon2d with I=119, M=67108864, P=2, V=19. The suite
includes the installed CLI, broker, native engine, encrypted replacement, reopen,
private HTTP form handling, restart receipts and regression boundaries. Its
test-only identity headers do not test the deployed Tailscale HTTPS proxy,
native browser input, real vaults, synchronization services, or mobile editors.

## Exact-byte snapshot admission (0.8.0 review prototype)

**NEEDS PARENT POLICY REVIEW before activation.** Existing capsule-v1 merge
defaults remain unchanged. The separate `admit` operation saves exact incoming
encrypted bytes only after proving the required active state and existing
capsules survive. Complete encrypted originals are retained outside canonical;
new per-upload capsules are not required. Ordinary-history versions can remain
only in those encrypted backups. Conservative group/settings conflicts refuse.

```bash
akdbx admit /absolute/private-staging/upload.kdbx --policy snapshot-admission-v1 \
  --snapshot-dir /absolute/private-backups/one-vault-admission --check
```

Read the [full admission contract](skills/akdbx/references/snapshot-admission.md)
before use, including capability/result checks, retention differences, real
conflict recovery, deadline limits, and coordinated restart/private unlock.
Synthetic transport evidence does not establish native iPhone compatibility.
Version 0.8.0 adds explicit `--group-verification group-tag-sequence-v1` and
`--group-verification native-group-selection-v1` profiles. Read the
[group contract and remaining limits](skills/akdbx/references/group-selection.md)
before selecting either. The old default `group-semantic-v1` remains narrower.
New CLI requires group protocol 2 and checks the exact requested profile in
capabilities and durable results; old 0.7.0/0.7.1 processes are rejected before
dispatch. Recovery locators/old receipts need no migration and gain no new
certification. Noncanonical tag separators can be admitted when the ordered
case-sensitive sequence, including duplicates, is unchanged. Native group
selection admits only already-complete selected properties/locations. Pure
entry moves/recycle deletes and root modification propagation remain conflicts;
this patch does not prove unrestricted native phone sync. No production or
native iPhone test is claimed.

## Password destination regression checks

`tests/test_browser_password.py` uses synthetic credentials, temporary Chrome
profiles, loopback HTTPS pages and separate Xvfb desktops (never the shared
desktop). It reproduces the former X11 omnibox delivery and checks direct DOM
saved/generated fills, login without Tab, wrong-field/selector/type changes,
replacement, focus restoration, tab changes, navigation and commit refusal.
`tests/test_password_endpoint.py` checks endpoint configuration and pin cleanup.
Existing native X11 tests cover the remaining username/TOTP transport.
Optional browser tests require Xvfb, Chromium, OpenSSL, xdotool and ImageMagick;
record skips explicitly. Store test output and temporary files outside project
checkouts, for example with pytest `--basetemp` in a private evidence directory.
Run heavy batches through the configured resource-manager queue.

## Rename from agentic-kdbx (0.9.2)

The project, Python distribution, Python package and agent skill are named
`akdbx`. The command remains `akdbx`; new integrations import `akdbx` and invoke
`$akdbx`. The old `agentic_kdbx` import remains a compatibility alias.

New brokers use `akdbx/akdbx.sock` under `XDG_RUNTIME_DIR`, or
`/tmp/akdbx-UID/akdbx.sock` without it. Without `XDG_RUNTIME_DIR` (for example
over non-interactive SSH), the CLI first uses an existing broker socket under
the user's own private `/run/user/UID` directory. When the new socket is absent, the CLI
can connect to an existing `agentic-kdbx.sock` using the same path, ownership
and peer checks. This lets an unlocked broker finish its session without a
restart. Explicit `--socket` remains supported. Existing encrypted vaults,
recovery directories, admission locators and receipts must retain their paths;
the rebrand does not migrate or rewrite private vault data.

## License

akdbx's own code is MIT licensed. See [LICENSE](LICENSE).

The package also bundles third-party files under their own licenses:

- jsQR, Apache-2.0: [src/akdbx/import_assets/jsQR.LICENSE](src/akdbx/import_assets/jsQR.LICENSE) and [VENDOR.txt](src/akdbx/import_assets/VENDOR.txt).
- The Public Suffix List, MPL-2.0: the notice at the top of [src/akdbx/public_suffix_assets/public_suffix_list.dat](src/akdbx/public_suffix_assets/public_suffix_list.dat), see [VENDOR.txt](src/akdbx/public_suffix_assets/VENDOR.txt).
