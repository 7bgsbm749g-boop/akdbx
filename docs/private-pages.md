# Private HTTPS pages

The broker starts locked. The user unlocks it on a private HTTPS page, and
uses the same page to save passwords, authenticators, cards and identities.
The master password and other secrets go only into that page, never into chat,
the CLI, arguments or the environment.

Linux and Windows serve this page the same way: the broker terminates HTTPS
itself on `127.0.0.1`. Linux also keeps its earlier Tailscale Serve
Unix-socket route for existing deployments.

| Route | Platforms | Where the page opens | Setup |
| --- | --- | --- | --- |
| [Loopback HTTPS page](#loopback-https-page) | Linux (0.23.0+), Windows | The broker's computer | A certificate and private key |
| [Unlock from another device](#unlock-from-another-device) | Linux (0.23.0+), Windows (0.22.0+) | Any device in your tailnet, including the broker's computer | The loopback page, plus Tailscale Serve to a verified `https://127.0.0.1:PORT` target |
| [Tailscale Serve Unix socket](#tailscale-serve-unix-socket-linux-only) | Linux only | Any device in your tailnet | Tailscale Serve to the broker's Unix socket; no certificate |
| [The akdbx relay](#the-akdbx-relay) | Linux, Windows (0.26.0+) | Any device | `akdbx relay enable`; no certificate, port or proxy to set up |
| [Unlock from the internet](#unlock-from-the-internet) | Linux, Windows | Any device | The loopback page, plus a public route; read the section before you choose one |

Every route has the same limit on failed attempts: see
[Failed attempts block the link](#failed-attempts-block-the-link).

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
  CLI command and for `akdbx extension build` (global `--unlock-origin` or
  `AKDBX_UNLOCK_ORIGIN`).
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
routes; see the skill's private import reference.

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
   same origin for every CLI command and for `akdbx extension build`:

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

Choose the route that exposes the page to the fewest people. Linux and
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
   [Unix-socket route](#tailscale-serve-unix-socket-linux-only) does not work
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
`https://k3x7q2mbn5vd.akdbx.link:8443`. A browser that opens that name connects
to the relay, and the relay passes the connection, still encrypted, to the
broker through a WebSocket that the broker opened. The broker answers with its
own certificate for that name, from a key that only the broker has. The relay
sees the name and encrypted bytes, never the page or the password.

```
phone --TLS for <id>.akdbx.link--> relay :8443 (reads the name only)
      --encrypted bytes over the broker's WebSocket--> broker
      --> the broker's own HTTPS page on 127.0.0.1 (TLS ends here)
```

Set it up once (Linux and Windows, the same commands):

```sh
akdbx relay enable
akdbx serve /absolute/path/to/passwords.kdbx
```

`relay enable` registers the broker, creates an ECDSA P-256 key and a
certificate request for the broker's name only, gets the certificate from
Let's Encrypt through the relay, and saves everything in a private folder. It
prints the broker's public origin and what to do next. Run it again to finish
an interrupted setup; it keeps the same name. `--relay URL` selects another
relay (default `https://relay.akdbx.link:8443`).

`serve` then uses the relay by itself: the relay origin, the relay certificate
for the loopback page, and a free loopback port. Do not give `--tls-cert`,
`--tls-key` or `--local-port` with the relay; `serve` refuses them. `serve
--relay` requires the relay and refuses to start without it. The broker opens
one control WebSocket to the relay, reconnects after a failure (1 s, doubling
to 60 s, with jitter), and opens one WebSocket per browser connection. It
renews the certificate when less than a third of its lifetime is left, and
loads the new certificate without a restart; open connections are not
dropped. Only one broker can use a relay registration at a time.

Every akdbx command finds the relay origin by itself, so you do not copy it.
The CLI and `serve` choose the trusted origin in this order:

1. `--unlock-origin` (before the subcommand);
2. `AKDBX_UNLOCK_ORIGIN`;
3. the origin of an enabled relay (`akdbx relay enable`) whose files pass the
   private-file checks;
4. `https://localhost:9443`.

So an `AKDBX_UNLOCK_ORIGIN` that you set for Tailscale keeps the broker on
Tailscale even with the relay enabled; `relay enable` and `relay status` warn
about it. Unset it to use the relay.

```sh
akdbx relay status            # name, origin, certificate expiry, broker connected or not; no secret
akdbx relay disable           # use no relay from the next broker start; files are kept
akdbx relay enable            # use it again, with the same name
akdbx relay disable --forget  # also delete the name, secret, key and certificate
```

Restart a running broker after `disable` to stop using the relay. A running
broker's `status` has a `relay` object with `connected`, `name`, `origin` and
the certificate dates.

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
permissions itself.

The broker trusts nothing that the relay sends. It checks the name, the port
and the certificate the relay returns (exactly the broker's name, and the
broker's own key), and the page keeps every check: the one-time token,
`Host` and `Origin` equal to the relay origin, and the three-attempt block. No
header from the relay counts as an identity.

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
`relay enable` waits for a short `retry_after` (up to five minutes in total)
and otherwise says when to try again. A failed renewal keeps the current
certificate and tries again later; `relay status` shows the error.

## Failed attempts block the link

Each unlock link allows three failed master-password attempts in total. Time
does not reset the count, and a link never expires because of time. The third
failure blocks the link at once: its token stops working, even with the right
password, and the page says that the link is blocked and that you must ask
your agent for a new one. Failed attempts on the extension pairing page count
toward the same three, and a block or a new link invalidates every pairing
link made before it. Parallel requests cannot exceed the limit: the broker
reserves each attempt before it starts the key derivation. Only a wrong
password or key file counts: an empty or malformed form gets `400`, and a
vault file or store error gets a "could not open the vault" page; neither
uses an attempt.

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

## Tailscale Serve Unix socket (Linux only)

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
