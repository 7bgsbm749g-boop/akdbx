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

`--tls-cert` and `--tls-key` select the loopback HTTPS page. Without them,
Linux uses the Unix-socket route and Windows refuses to start.

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
  loopback port. The one-time URL token protects the page. It is rate-limited
  and replaced after a successful unlock.
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
controls. Do not use `tailscale funnel`: it publishes the page to the internet.
To stop remote unlock, remove the proxy with `tailscale serve --https=9443 off`.

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
