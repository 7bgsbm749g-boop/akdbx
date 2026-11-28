# Private HTTPS pages

The broker starts locked. The user unlocks it on a private HTTPS page, and
uses the same page to save passwords, authenticators, cards and identities.
The master password and other secrets go only into that page, never into chat,
the CLI, arguments or the environment.

Linux, macOS and Windows serve this page the same way: the broker terminates HTTPS
itself on `127.0.0.1`. Linux also keeps its earlier Tailscale Serve
Unix-socket route for existing deployments.

| Route | Platforms | Where the page opens | Setup |
| --- | --- | --- | --- |
| [Loopback HTTPS page](#loopback-https-page) | macOS, Linux (0.23.0+), Windows | The broker's computer | A certificate and private key |
| [Unlock from another device](#unlock-from-another-device) | macOS, Linux (0.23.0+), Windows (0.22.0+) | Any device in your tailnet, including the broker's computer | The loopback page, plus Tailscale Serve to a verified `https://127.0.0.1:PORT` target |
| [Tailscale Serve Unix socket](#tailscale-serve-unix-socket-linux-and-macos) | Linux and macOS | Any device in your tailnet | Tailscale Serve to the broker's Unix socket; no certificate |
| [The akdbx relay](#the-akdbx-relay) | Linux, macOS, Windows | Any device | `akdbx relay enable`; no certificate, port or proxy to set up |
| [Unlock from the internet](#unlock-from-the-internet) | Linux, macOS, Windows | Any device | The loopback page, plus a public route; read the section before you choose one |

Every route has the same limit on failed attempts: see
[Failed attempts block the link](#failed-attempts-block-the-link).
Every route also takes a key file and a hardware key on the page: see
[Key file and hardware key](#key-file-and-hardware-key).

`akdbx setup` (0.27.0+) sets up the loopback page and one access route in
the order of [Unlock from the internet](#unlock-from-the-internet). It checks
the certificate with the broker's own load and requires the host name that
the route needs (`localhost` or `127.0.0.1` for a loopback origin, `127.0.0.1`
behind Tailscale). It issues a certificate with mkcert only after you ran
`mkcert -install`, runs `akdbx relay enable` for the relay, and does not
configure a proxy that decrypts HTTPS. It never inspects or changes
Tailscale: from the tailnet name and port (or an explicit origin) it prints
the exact `tailscale serve --bg --https=PORT https://127.0.0.1:LOCALPORT`
command (or the Funnel commands) for you to run, and the check:
`tailscale serve status` must show that mapping, marked tailnet only, and no
Funnel. The access stage stays `todo`; the broker itself works on loopback,
so the login stage still runs.

For a broker that runs as a service (a systemd unit, a logon task, any
supervisor that keeps its output in a log), start it with
`akdbx serve --no-print-unlock-link`. It then prints only that the vault is
locked; get the private link with `akdbx status`. This is the recommended
setting for every service: a log such as the systemd journal keeps the link's
secret token. The units and tasks that `akdbx setup` writes use it.

`--tls-cert` and `--tls-key` select the loopback HTTPS page. An enabled
[akdbx relay](#the-akdbx-relay) selects the same page with the relay's
certificate. Without either, Linux uses the Unix-socket route and Windows
refuses to start.

## Loopback HTTPS page

The broker listens on `127.0.0.1` only, never on the LAN or tailnet, and
serves only HTTPS (TLS 1.2 or newer). It needs a certificate that the browser
trusts for `localhost` or `127.0.0.1`, and the unencrypted PEM private key of
that certificate. A local development CA such as
[mkcert](https://github.com/FiloSottile/mkcert) can issue it. mkcert is a setup
tool, not a runtime dependency; a certificate from your own trusted CA also
works.

Linux:

```bash
mkcert -install
umask 077
mkdir -p ~/.config/akdbx/tls
mkcert -cert-file ~/.config/akdbx/tls/localhost.pem \
  -key-file ~/.config/akdbx/tls/localhost-key.pem localhost 127.0.0.1

export AKDBX_UNLOCK_ORIGIN=https://localhost:9443
.venv/bin/akdbx serve /absolute/path/to/passwords.kdbx \
  --tls-cert ~/.config/akdbx/tls/localhost.pem \
  --tls-key ~/.config/akdbx/tls/localhost-key.pem
```

Windows (PowerShell, in the private folder from
[Install and prepare private files](windows.md#install-and-prepare-private-files)):

```powershell
mkcert -install
mkcert -cert-file "$private\localhost.pem" -key-file "$private\localhost-key.pem" localhost 127.0.0.1

$env:AKDBX_UNLOCK_ORIGIN = 'https://localhost:9443'
.\.venv\Scripts\akdbx.exe serve "$private\synthetic.kdbx" `
  --tls-cert "$private\localhost.pem" --tls-key "$private\localhost-key.pem"
```

`mkcert -install` changes which certificates the browser and the computer
trust. It is a user setup step. Keep the CA private key (`rootCA-key.pem` in
`mkcert -CAROOT`) private. On Linux, Chrome and Firefox read the CA from their
own NSS store, which mkcert fills only when `certutil` (package `libnss3-tools`
or `nss-tools`) is installed.

Rules for both platforms:

- The origin is `https://localhost:PORT` or `https://127.0.0.1:PORT`, with a
  port from 1024 to 65535. `https://localhost:9443` is the default. The
  certificate must match its host name. The same origin must be set for every
  CLI command (global `--unlock-origin` or `AKDBX_UNLOCK_ORIGIN`). The browser
  extension (0.19.0+) holds no origin: confirm this one in its popup on first
  use.
- The private key must be readable by the broker's user only. Linux requires a
  regular file that this user owns with mode `0600` or stricter, opened
  without following a symbolic link. Windows requires a restrictive DACL on a
  trusted local NTFS path. An encrypted key is refused rather than prompting.
- The page accepts a request only when its `Host` header is the configured
  origin's host and port, and its `Origin` header, if present, is the
  configured origin. It trusts no proxy identity header such as
  `Tailscale-User-Login`, because any local process can send headers to a
  loopback port. The one-time URL token protects the page. It allows three
  failed attempts in total and is replaced after a successful unlock.
- No other process can share the port while the broker runs. When the broker
  stops, another local user can take the port, but cannot show a page that the
  browser trusts without the private key. Do not bypass certificate warnings
  or use HTTP.

The broker prints the private link when it starts, and `status` returns it
while the vault is locked. Open it in a browser on the broker's computer.

The browser native host that captures an authenticator setup QR does not use
this listener. On Windows it uses a capture pipe. On Linux the broker also
opens its private Unix unlock socket (`akdbx-unlock.sock` beside the broker
socket, `agentic-kdbx-unlock.sock` beside a legacy `agentic-kdbx.sock`, or
`--unlock-socket`), which on this route answers only the native
host's capture request from the same user. It serves no page and cannot
unlock the vault. Register the native host with that socket on both Linux
routes. On macOS register the capture socket `~/Library/Application Support/akdbx/run/u`
for the default broker. See [private import](../skills/akdbx/references/private-import.md).

## Unlock from another device

Tailscale Serve on the broker's computer can proxy its tailnet HTTPS name to
the loopback listener. The page then opens on any device in your tailnet. The
listener still binds `127.0.0.1` only.

1. Install Tailscale and enable HTTPS certificates for the tailnet. Find the
   computer's name, for example `node.tailnet.ts.net`.
2. Make the Tailscale service trust the CA that issued the broker's
   certificate. Tailscale checks the backend certificate against the
   computer's trusted roots, not the browser's.
   - **Linux:** `mkcert -install` already adds the CA to the system trust
     store. `tailscaled` reads that store once when it starts, so restart it:
     `sudo systemctl restart tailscaled`. The restart briefly drops tailnet
     connections, including an SSH session over Tailscale. Without mkcert,
     add the CA to the system store (on Debian and Ubuntu, copy it to
     `/usr/local/share/ca-certificates/NAME.crt` and run
     `sudo update-ca-certificates`) and then restart `tailscaled`.
   - **Windows:** Tailscale runs as SYSTEM and does not read your user
     certificate store. Import the CA into the computer's trusted roots as
     [docs/windows.md](windows.md#unlock-from-another-device) describes.
3. Pick a free loopback port for the broker, for example `9444`. Proxy a
   tailnet HTTPS port to it with a **verified** `https://` target:

   ```sh
   tailscale serve --bg --https=9443 https://127.0.0.1:9444
   ```

   On Linux, run this as root or as the Tailscale operator user. Tailscale
   Serve then checks the broker's certificate for `127.0.0.1` on every
   connection. Never use an `https+insecure://` or `http://` target. The Serve
   proxy stays configured when the broker stops, and another local user can
   then take the free port. With a verified target, Serve refuses that
   listener, because it has no certificate from your CA. With an unverified
   target, Serve would show that user's fake unlock page at your trusted
   tailnet name, and could collect the master password.
4. Start the broker with the Tailscale origin and the loopback port. Use the
   same origin for every CLI command, and confirm it in the extension popup
   on first use:

   ```bash
   export AKDBX_UNLOCK_ORIGIN=https://node.tailnet.ts.net:9443
   .venv/bin/akdbx serve /absolute/path/to/passwords.kdbx --local-port 9444 \
     --tls-cert ~/.config/akdbx/tls/localhost.pem \
     --tls-key ~/.config/akdbx/tls/localhost-key.pem
   ```

   On Windows, use the same options with `akdbx.exe`.

The broker then gives links on the Tailscale origin. Tailscale Serve keeps the
browser's `Host` and `Origin`, and the page accepts only the configured
origin. A remote origin must be a DNS name, not an IP address, and needs
`--local-port` from 1024 to 65535. A loopback origin keeps its own port and
needs no `--local-port`. Limit access to the Serve port with tailnet access
controls. `tailscale funnel` publishes the page to the internet instead: read
[Unlock from the internet](#unlock-from-the-internet) before you use it.
To stop remote unlock, remove the proxy with `tailscale serve --https=9443 off`.

## Unlock from the internet

Choose the route that exposes the page to the fewest people. Linux, macOS and
Windows have the same choices, in this order of recommendation:

1. **Local only** (most secure). Use the [loopback HTTPS page](#loopback-https-page)
   and open the link on the broker's computer. Nothing outside that computer
   can reach the page.
2. **A private proxy** such as [Tailscale Serve](#unlock-from-another-device)
   (the most secure remote option; recommended first). Only devices in your
   tailnet can reach the page, and tailnet access controls can limit them
   further. TLS ends on the broker's computer, so no third party sees the
   password.
3. **The akdbx relay** (0.26.0+): one command, no open port, no router change
   and no VPN. The relay forwards the encrypted connection; TLS ends in the
   broker, with a key that never leaves the broker's computer, so the relay
   cannot read the master password. Anyone on the internet can reach the page.
   See [The akdbx relay](#the-akdbx-relay) for the setup and its one trust
   point.
4. **Another public tunnel that does not decrypt the traffic** (available, not
   recommended), such as Tailscale Funnel. Funnel publishes the page at the
   computer's tailnet name to the whole internet. The Funnel relays pass the
   TLS connection through without decrypting it; TLS still ends on the
   broker's computer. Use the loopback page with a verified target, the same
   way as Serve. Funnel accepts only ports 443, 8443 and 10000:

   ```sh
   tailscale funnel --bg --https=8443 https://127.0.0.1:9444
   export AKDBX_UNLOCK_ORIGIN=https://node.tailnet.ts.net:8443
   ```

   Then start the broker with `--local-port 9444` and the TLS options, as in
   [Unlock from another device](#unlock-from-another-device). The Linux
   [Unix-socket route](#tailscale-serve-unix-socket-linux-and-macos) does not work
   through Funnel: Funnel sends no tailnet identity header, so the page
   refuses every request. Remove the route with
   `tailscale funnel --https=8443 off`.
5. **Proxies that decrypt HTTPS** (STRONGLY DISCOURAGED). Services such as
   Cloudflare Tunnel end TLS on the provider's servers and open a new
   connection to your computer. The proxy operator, and anyone who controls
   that proxy, can read the master password and every secret you enter on the
   page. Do not use them for akdbx.

On a public route (3, 4 or 5), anyone on the internet can reach the page.
Only two things protect the vault there: the secret token in the link, and
the [three-attempt block](#failed-attempts-block-the-link). Keep the link
private, and use a strong master password. Stop the public route when you do
not need it. Private save pages (passwords, authenticators, cards, identities)
and the extension pairing page are reachable on the same route and are
protected by their own secret links.

### The akdbx relay

The relay at `relay.akdbx.link` gives the broker a random public name such as
`https://k3x7q2mbn5vd.akdbx.link`. A browser that opens that name connects
to the relay, and the relay passes the connection, still encrypted, to the
broker through a WebSocket that the broker opened. The broker answers with its
own certificate for that name, from a key that only the broker has. The relay
sees the name and encrypted bytes, never the page or the password.

```
phone --TLS for <id>.akdbx.link--> relay :443 (reads the name only)
      --encrypted bytes over the broker's WebSocket--> broker
      --> the broker's own HTTPS page on 127.0.0.1 (TLS ends here)
```

Set it up once (Linux, macOS and Windows, the same commands):

```sh
akdbx relay enable
akdbx serve /absolute/path/to/passwords.kdbx
```

`relay enable` registers the broker, creates an ECDSA P-256 key and a
certificate request for the broker's name only, gets the certificate from
Let's Encrypt through the relay, and saves everything in a private folder. It
prints the broker's public origin and what to do next. Run it again to finish
an interrupted setup; it keeps the same name. `--relay URL` selects another
relay (default `https://relay.akdbx.link`). A broker registered with the old
default, `https://relay.akdbx.link:8443`, is registered with the same relay:
`relay enable` accepts either URL for it.

#### The relay moved from port 8443 to 443

Until 0.28.0 the relay served the pages at `https://<id>.akdbx.link:8443` and
its control API at `https://relay.akdbx.link:8443`. It now uses port 443, so
the address has no port, and it still accepts port 8443 for a while for older
brokers. A broker saves the relay URL and its public port in `relay.json`, so a
broker that registered earlier keeps the `:8443` origin until it learns the
new port. From 0.28.0 the broker learns it by itself: at each `serve` start
with the relay, and in `relay enable`, it asks the relay for this broker's
current public port and control URL (an authenticated `GET /api/v1/broker`,
with the same TLS checks, redirect refusal, size limit and timeout as the other
relay calls). It accepts the answer only when it names exactly this broker,
the port is 1 to 65535, and a control URL is HTTPS on the same host as the
saved one (only the port may differ). It then saves the change in
`relay.json` and prints it, for example `akdbx relay: relay moved the public
port from 8443 to 443`; `relay enable` shows it in `moved`, and `relay status`
in `public_port` and `broker.moved`. An older relay (HTTP 404), no network or
an answer that fails a check keeps the saved values, with one warning; the
broker still starts.

If the saved URL cannot be reached (the relay already closed the old port),
the broker asks once more at the default relay URL on the same host, and
`relay enable --relay URL` asks at that URL; the same checks apply.

After the move the origin changes, so links of the old origin stop working at
the broker's first start on the new port. A paired browser extension at version
0.3.0 or later follows the new origin by itself (see
[Browser extension trust](#browser-extension-trust)); an older extension needs
`akdbx extension build` again and a reload. Unset or update an
`AKDBX_UNLOCK_ORIGIN` or `--unlock-origin` that names the old origin.

`serve` then uses the relay by itself: the relay origin, the relay certificate
for the loopback page, and a free loopback port. Do not give `--tls-cert`,
`--tls-key` or `--local-port` with the relay; `serve` refuses them. `serve
--relay` requires the relay and refuses to start without it. The broker opens
one control WebSocket to the relay, reconnects after a failure (1 s, doubling
to 60 s, with jitter), and opens one WebSocket per browser connection. It
renews the certificate when less than a third of its lifetime is left, and
loads the new certificate without a restart; open connections are not
dropped. Only one broker can use a relay registration at a time: it holds the
lock file `.relay.lock` in the relay folder open while it runs (Linux: an
exclusive `flock`; Windows: share mode 0, which every logon session sees).

Every akdbx command finds the relay origin by itself, so you do not copy it.
The CLI and `serve` choose the trusted origin in this order:

1. `--unlock-origin` (before the subcommand);
2. `AKDBX_UNLOCK_ORIGIN`;
3. the origin of an enabled relay (`akdbx relay enable`) whose files pass the
   private-file checks;
4. `https://localhost:9443`.

So an `AKDBX_UNLOCK_ORIGIN` that you set for Tailscale keeps the broker on
Tailscale even with the relay enabled; `relay enable` and `relay status` warn
about it. Unset it to use the relay. `serve --relay` is the exception: it
always uses the relay origin, ignores `AKDBX_UNLOCK_ORIGIN`, and refuses an
`--unlock-origin` (or `--unlock-url`) that names another origin. The units and
tasks that `akdbx setup` writes for the relay use `serve --relay`, so an
inherited variable cannot change them; setup warns when the variable names
another origin, because the other commands still use it.

```sh
akdbx relay status            # name, origin, certificate expiry, running broker's relay state; no secret
akdbx relay disable           # use no relay from the next broker start; files are kept
akdbx relay enable            # use it again, with the same name
akdbx relay rotate            # register a new name and certificate (stop the broker first)
akdbx relay disable --forget  # also delete the name, secret, key and certificate
```

Restart a running broker after `disable` to stop using the relay. A running
broker's `status` has a `relay` object with `connected`, `name`, `origin`,
the certificate dates and, after a [port move](#the-relay-moved-from-port-8443-to-443)
at its start, `moved`. `relay status` asks the running broker for its relay
state and the origin of its private page with a separate, peer-checked
request that holds no private URL, so it also works after `disable`, when the
CLI already expects another origin. Its `broker.running` is `true`, `false`
(no broker listens) or `"unknown"` (a socket, peer or answer check failed;
the broker may still run). After you enable or disable the relay, a paired
browser extension at version 0.3.0 or later follows the new origin at its next
connection; an older extension needs `akdbx extension build` again and a reload.

The relay folder holds `relay.json` (relay URL, name, port, origin and the
bearer secret that authorizes this broker at the relay) and `tls.pem` (the
private key, then the certificate chain). akdbx never prints or logs the
secret or the key.

- **Linux:** `${XDG_STATE_HOME:-~/.local/state}/akdbx/relay/`, folder mode
  `0700`, files mode `0600`, below folders owned by you or root that group and
  others cannot write. Files are opened without following symbolic links.
- **Windows:** `%LOCALAPPDATA%\akdbx\relay\`, a folder and files that only this
  user and SYSTEM can open, on a local NTFS path.

If the folder or a file fails these checks, `serve` refuses to start and names
what to fix, and the CLI does not use the relay origin. akdbx never repairs the
permissions itself. `relay disable --forget` is the repair for untrusted or
malformed files: it checks only the folder, never reads the files, and deletes
`relay.json`, `tls.pem`, `rotate.json` and the lock file by name.

The broker trusts nothing that the relay sends. It checks the name, the port
and the certificate the relay returns (exactly the broker's name, and the
broker's own key), and the page keeps every check: the one-time token,
`Host` and `Origin` equal to the relay origin, and the three-attempt block. No
header from the relay counts as an identity. The WebSocket upgrades follow no
redirect (a redirect would resend the bearer secret to another address) and
accept only HTTP 101; anything else is a failed attempt with the normal
backoff. The broker reads each WebSocket frame header first and aborts the
connection before it reads a message over the protocol limits: 4 KiB on the
control connection, 256 KiB and 256 fragments on a stream.

**Trust point.** The relay operator controls the `akdbx.link` DNS zone. With
it, the operator could get a second certificate for your broker's name and
serve a fake page there. Every publicly trusted certificate is written to the
public Certificate Transparency logs, so such a certificate would be visible,
for example on [crt.sh](https://crt.sh/?q=%25.akdbx.link). Tailscale Serve
(option 2) has no such point outside your tailnet. The relay's source and
protocol are public: [akdbx-relay](https://github.com/7bgsbm749g-boop/akdbx-relay)
(`docs/PROTOCOL.md`).

Limits: the relay accepts a few registrations per network address each day
and a few certificates per broker each week. When a limit is reached,
`relay enable` and `relay rotate` wait for a short `retry_after` (up to five
minutes in total) and otherwise say when to try again. A failed renewal keeps the current
certificate and tries again later; `relay status` shows the error.

#### Rotate the relay name

`akdbx relay rotate` gives the broker a new public name, for example when the
old name was shared too widely. Stop the broker first: `rotate` refuses while a
broker holds `.relay.lock`, because a running broker keeps the name it started
with.

```sh
# stop the broker, then:
akdbx relay rotate
akdbx serve /absolute/path/to/passwords.kdbx   # unlock the vault on the new origin
```

`rotate` registers a new name with the saved relay (`POST /api/v1/register`),
creates a new key and gets a certificate for the new name only (the same code
and checks as `relay enable`), and then replaces `tls.pem` and `relay.json`.
It prints the new `origin`, the `previous_origin` and the certificate dates,
never the secret or the key. It keeps the enabled or disabled state. The old
name is no longer used; the relay has no call to delete it, and it expires
unused.

The new registration is saved in `rotate.json` in the relay folder before the
certificate request. If the request fails or the relay limits it, the current
name stays in use and `rotate` says when to try again; run `rotate` again to
finish, without another registration. Until then `relay enable` refuses and
`relay status` shows `rotation_pending`. Each write is a private temporary file
and a rename; after an interruption between the two writes, the next `rotate`
only finishes the switch. `relay disable --forget` also deletes `rotate.json`.

Costs of one rotation:

- one new registration and one new certificate, which count toward the
  relay's daily registration and weekly certificate limits (see Limits above);
- a new entry in the public Certificate Transparency logs, which shows the new
  name to anyone who reads the logs;
- a broker restart, which locks the vault: unlock it again on the new origin;
- links of the old origin stop working. A paired extension at 0.3.0 or later
  follows the new origin by itself; an older extension needs a rebuild and a
  reload.

## Browser extension trust

The browser extension opens pairing and unlock links only on one trusted
origin, so a replaced native host cannot send you to a look-alike
master-password page. From extension version 0.3.0 (akdbx 0.29.0), an origin
change needs no rebuild, no reload and no approval. From fill extension 0.19.0
(akdbx 0.55.0) the extension is one generic build, the same for every
user and every release asset: `config.js` holds only its version, with no
broker address and no build ID.

1. **First use: you confirm the origin.** With no saved trust, the extension
   takes the origin that the native host's signed statement names only as a
   proposal. The popup shows that exact origin, says that this extension does
   not trust a broker address yet, and offers **Trust this address**. It opens
   no pairing or unlock page, reads nothing from that origin and seals no
   captured secret to any broker key until you click it. Confirm only your
   broker's address: `akdbx status` on the computer with the broker shows it
   as `extension_trust.origin`, and `akdbx setup` and `akdbx extension build`
   (`confirm_origin`) print it. The service worker saves the origin only if
   the native host, at that moment, still names exactly the origin you saw in
   a statement that verifies; then it binds the key (step 2). A script in the
   popup cannot confirm: the click must be a real one. A broker older than
   0.29.0 sends no statement and gets no proposal.
2. **First key, bound to HTTPS.** Each broker has a persistent identity key
   (ECDSA P-256). At each start it signs a statement with its current origin
   and a sequence number. When the extension has no stored key, it does not
   take the key from the native host alone. For a trusted origin with no key
   (just confirmed, or kept by a reset), when the native host sends the
   statement (at the connection, not only when the popup opens), the
   extension's service worker reads
   `GET <trusted origin>/.well-known/akdbx-identity` over HTTPS (no
   redirects, no cookies, no cache, a three-second limit). It stores the
   broker's public key, origin and sequence number in `chrome.storage.local`
   only when that statement verifies, names the trusted origin, and has the
   same key as the statement from the native host. If the read fails, the
   extension stores nothing new, keeps the trusted origin, and tries again at
   the next statement or popup. The popup shows the origin next to the
   pairing code: check it before you open the page.
3. **Signed changes.** When the origin changes (a relay port move, `relay
   rotate`, `relay enable` or `disable`, another `--unlock-origin`), the broker
   adds 1 to the sequence number and signs the new origin. The extension
   accepts it only when the stored key verified the signature, the key id
   matches, the sequence number is higher than the stored one, and the origin
   is an HTTPS origin with no path, query or credentials. The extension
   checks each statement when it arrives and saves the new sequence number at
   once; an older statement never replaces a newer saved one. The popup then
   says that the broker moved from the old origin to the new one, also when
   the move arrived while the popup was closed. Anything else keeps the
   stored origin and shows why.
4. **Reset.** The extension never accepts another broker key by itself, and
   it opens no pairing or unlock page while the key differs. If the broker's
   key changed (a new computer, or deleted akdbx state) and it names the
   trusted origin, the popup shows **Reset broker trust…**. Click it, read the
   note, and click **Reset and pair again**. The extension forgets the stored
   key and sequence number, keeps the trusted origin, and makes a new pairing
   key. It then accepts a new key only when
   `GET <trusted origin>/.well-known/akdbx-identity` over HTTPS returns a valid
   statement for that origin with that key. If you did not set up this broker
   again yourself, do not reset and do not enter your master password.
5. **Forget.** A broker that names another origin than the trusted one, with
   no signature by the stored key (moved by hand to a new address, or set up
   again elsewhere), gets no reset. The popup says which origin the broker
   names and which one the extension trusts, and offers **Forget this
   broker…**. Its second click (**Forget and confirm again**) deletes the
   saved trust and the pairing; the next popup asks you to confirm the
   origin that the broker names now (step 1). The service worker forgets only
   while the broker still names another origin without the trusted key's
   signature. This replaces the rebuild of earlier builds: they started over
   from a new `config.js`. If you did not move the broker yourself, do not
   forget it and do not enter your master password.
6. **Update from a per-deployment build.** Fill extension 0.18.x and earlier
   wrote the CLI's origin and a random build ID into `config.js` and saved
   the build ID with the stored trust. When such an extension is rebuilt with
   this akdbx (or replaced by a release asset with the same extension ID) and
   reloads, the generic build trusts none of that stored trust: the popup
   asks once for the first-use confirmation (step 1), and the confirmation
   binds the key through the confirmed origin's HTTPS page again. Such a
   build ignored the record of an earlier build but left it in storage until
   it bound a new key, so a stored record may belong to a broker that a later
   rebuild replaced, and the generic build cannot see which build was
   installed last. A broker statement cannot settle it: statements are
   public and carry no freshness, so a replaced native host could replay an
   old broker's. Firefox removes a temporary add-on's storage when Firefox
   quits, so a temporary add-on asks at each first use.

The broker sends the statement in the `identity` field of its `attached` and
`state` messages to the extension. Its private HTTPS page server (the
loopback listener, the relay route to it, and the legacy Tailscale socket)
also serves it at `GET /.well-known/akdbx-identity` as `application/json`
(`public_key`, `statement`, `signature`; `Cache-Control: no-store`). This
route needs no token because it holds only public data. It keeps the `Host`
check (and, on the Tailscale socket, the Tailscale login header) and accepts
no `Origin` other than the page's own or the akdbx extension's, so a web page
on another origin cannot read it. It answers `404` when the broker has no
identity and `405` for a method other than `GET`. The exact encoding is in
`src/akdbx/broker_identity.py`. `akdbx status` shows `extension_trust` (`key_id`,
`origin`, `seq`; no key). The identity file is per broker endpoint:
`${XDG_STATE_HOME:-~/.local/state}/akdbx/broker-identity/identity-<hash>.json`
on Linux (folder `0700`, file `0600`, the relay folder's checks) and
`%LOCALAPPDATA%\akdbx\broker-identity\` on Windows (this user and SYSTEM only).
akdbx never prints the private key. If the file fails a check, `serve` warns
and starts without a statement; extensions then keep the origin they trust.
Deleting the file makes a new key, which every paired extension refuses until
the user resets it. On Windows the default broker pipe name contains the logon
session id, which changes at each sign-in; the default broker therefore keeps
one file, `identity-default.json`, and every other `--socket` pipe has its own
`identity-<hash>.json`.

**Trust point.** Every key, also the one after a reset, must come from the
broker's HTTPS page on the trusted origin, which the browser checks with TLS
and the broker checks with `Host`. A replaced native host can send its own key
for the trusted origin, but the extension refuses it when the page has another
key, so the host cannot sign a move off the trusted origin. After the first
key, a replaced host can no longer change the trusted origin or key; the popup
shows a key change or an unsigned move as a warning and opens no link. The
native host cannot click in the popup, so it can neither confirm an origin nor
forget a broker.

**What the generic build changes.** Earlier builds took the first trusted
origin from a local `akdbx extension build`, so the native host never chose
it. In the generic build the native host proposes the first origin and you
confirm it. A same-user process that replaced the native host *before* your
first confirmation (also the one after the update from a per-deployment
build, or after you chose Forget) can therefore propose an origin
it controls and serve a matching statement there; your check of the shown
origin against `akdbx status` is the only guard at that point. This is the
trust on first use that earlier builds did not have, limited to the moment you
confirm. akdbx does not protect against a malicious process of your own OS
user in general (see [Security model](../README.md#security-model)); such a
process could also have rewritten an unpacked extension folder before. Every
check after the confirmation is unchanged.


## Key file and hardware key

The unlock page (and the extension pairing page while the vault is locked)
has a **Key file or hardware key** section under the master password. The
master password is always required.

- **Key file.** Choose the vault's key file. The browser sends it in the
  same form as the password, over the page's HTTPS connection. On the relay
  route, TLS ends at the broker, so the relay sees only encrypted bytes. The
  broker keeps the file in memory for later saves and never writes it to
  disk. The field is not shown when the broker was started with
  `--keyfile`: that key file stays on the broker's computer, and an uploaded
  one is refused. Upload limit: 1 MiB.
- **Hardware key.** KeePassXC's YubiKey HMAC-SHA1 challenge-response, for a
  KDBX 4 vault with an Argon2 KDF. A browser cannot reach that function of
  the key, so the page shows the vault's challenge as a command:

  ```sh
  ykman otp calculate 2 <128 hex digits>
  ```

  Run it on any computer with the key (change `2` to `1` for slot 1), touch
  the key, and enter the 40-character response on the page. The command
  sends the same 64 bytes that KeePassXC sends, so both fixed and variable
  input slots answer as they do in KeePassXC. The response is a key secret:
  treat it like the password. The broker keeps it in memory only.

A vault unlocked with a hardware key keeps its KDF seed (the challenge) when
the broker saves it; the master seed and IVs still change on every save.
Otherwise every save would need a new touch of the key, and the broker holds
only the response. KeePassXC then opens the saved vault with the same key. A
merge source must open with the same keys, so merges from a vault with
another challenge are refused.

If the vault file changed after the page opened (for example a save in
KeePassXC made a new challenge), the page shows the new command and the
attempt does not count. A KDBX 3 vault or an AES-KDF vault shows no hardware
key field: KeePassXC mixes the response into those in another way.

## Failed attempts block the link

Each unlock link allows three failed master-password attempts in total. Time
does not reset the count, and a link never expires because of time. The third
failure blocks the link at once: its token stops working, even with the right
password, and the page says that the link is blocked and that you must ask
your agent for a new one. Failed attempts on the extension pairing page count
toward the same three, and a block or a new link invalidates every pairing
link made before it. Parallel requests cannot exceed the limit: the broker
reserves each attempt before it starts the key derivation. Only a wrong
password, key file or hardware key response counts: an empty or malformed
form gets `400`, a response to an old challenge gets `409` with the new
command, and a vault file or store error gets a "could not open the vault"
page; none of these uses an attempt.

The block is saved in a private file, so a broker restart, a logout or a
reboot keeps it. On Linux the file is in
`${XDG_STATE_HOME:-~/.local/state}/akdbx/` (folder mode `0700`, file mode
`0600`), one file per broker socket; with `--notification-state FILE` it is
next to that file instead. On Windows it is next to the notification state in
`%LOCALAPPDATA%\akdbx` (this user and SYSTEM only). If that folder (or a
folder above it, such as a group-writable `~/.local/state`) or the file fails
these checks, `serve` refuses to start and names the folder and the
permissions it needs; fix them, or use `--notification-state FILE` in a
private folder. If the broker cannot save the block, the block still holds
until the broker stops: the broker logs it and `status` adds
`unlock_block_saved: false`. If it cannot save the cleared block,
`new-unlock-link` refuses and the link stays blocked. A broker that starts
blocked prints no unlock link, only how to get a new one.

While the link is blocked, `status` and locked responses report
`unlock_blocked: true` and contain no unlock link; `status` names only the
link's origin (`unlock_origin`), which the CLI checks before it asks for a new
link. The broker sends an `akdbx.unlock-blocked` event to each waiting
[unlock notification](../skills/akdbx/references/unlock-notifications.md)
subscription that opted in; the subscription keeps waiting and later sends
the normal unlock event.

Only an explicit command makes a new link, and only while the current link is
blocked:

```sh
akdbx new-unlock-link --user-confirmed
```

It creates a fresh token with three new attempts and prints the new private
link after the same origin check as every unlock link. The broker cannot check
who asks for it. An agent must first ask you whether the three failures were
yours and whether you want a new link. If they were not yours, someone else
has the link: do not create a new one until you know how it leaked. A broker
restart does not replace a blocked link.

## Tailscale Serve Unix socket (Linux and macOS)

Before 0.23.0 this was the only Linux route, and existing deployments can keep
it. Start the broker with a tailnet origin and without `--tls-cert`,
`--tls-key` or `--local-port`:

```bash
export AKDBX_UNLOCK_ORIGIN=https://node.tailnet.ts.net:9443
.venv/bin/akdbx serve /absolute/path/to/passwords.kdbx
```

The broker serves plain HTTP on a Unix socket, `akdbx-unlock.sock`, in its
private runtime directory (mode `0700`; the socket is mode `0600`). It opens no
TCP port. Root maps a tailnet HTTPS port to that socket with Tailscale 1.98.9
or newer (older versions had a Unix-socket Serve authorization flaw):

```bash
sudo tailscale serve --bg --https=9443 "unix:${XDG_RUNTIME_DIR}/akdbx/akdbx-unlock.sock"
```

For macOS with the open-source `tailscaled`, substitute
`"unix:${HOME}/Library/Application Support/akdbx/run/u"` for the Linux target.
Use the HTTPS loopback target when the daemon cannot access the socket.

Tailscale Serve supplies HTTPS and the `Tailscale-User-Login` header. The page
requires that header and the one-time token. Only `tailscaled`, which runs as
root, can reach the socket, so the header cannot come from another local
process. The filesystem permissions stop another local user from replacing a
stopped backend, so this route needs no certificate.

The page on this route opens only through Tailscale, not on a plain loopback
origin: a loopback origin on Linux requires `--tls-cert` and `--tls-key`.
Windows has no such route, because Tailscale Serve on Windows cannot proxy to a
Unix socket. See the [setup reference](../skills/akdbx/references/vps-setup.md#tailscale-web-page)
for checks and migration.
