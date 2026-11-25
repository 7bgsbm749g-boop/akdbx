akdbx {{VERSION}} is one release for every platform. Install the same wheel on Linux, Windows and macOS; pip selects platform dependencies automatically.

| Platform | Status | Fills | Not available |
| --- | --- | --- | --- |
| macOS | Local extension-only broker from 0.42.0; native Darwin IPC, TLS and encrypted save checks | The shared paired-extension protocol; Chrome and Edge native hosts | Native window delivery, CDP, guided setup and the Safari wrapper (separate delivery); native merge engine |
| Linux (X11 + Chromium) | Established; the loopback HTTPS unlock page, with or without Tailscale Serve, from 0.23.0; the akdbx relay from 0.26.0 | Passwords and logins to verified Chromium DOM inputs; usernames and TOTP to pinned X11 windows; cards and identity fields in Chromium; the browser extension route | — |
| Windows 10/11 | Same feature set from 0.17.0; unlock from another device and authenticator capture from 0.22.0; the akdbx relay from 0.26.0 | Passwords and logins to verified Chromium DOM inputs; usernames and TOTP to pinned windows; cards and identity fields in Chromium; the browser extension route (Helium, Chrome, Edge); authenticator capture through the browser native host | — |

Verify a download before installing it:

```sh
sha256sum --check SHA256SUMS
gh attestation verify akdbx-{{VERSION}}-py3-none-any.whl --repo 7bgsbm749g-boop/akdbx
```

Merge and snapshot admission need KeePassXC CLI 2.7.10 or newer, below 2.8, on both platforms; on Windows it must be installed for all users.

Both platforms serve the same private HTTPS page: HTTPS on `127.0.0.1` with your own certificate (`--tls-cert`, `--tls-key`), opened on the broker's computer or, through Tailscale Serve to a verified `https://127.0.0.1:PORT` target (`--local-port`), on any tailnet device. Linux also keeps its Tailscale Serve Unix-socket route; Tailscale Serve on Windows cannot proxy to a Unix socket. From 0.26.0, `akdbx relay enable` opens the same page on any device through the akdbx relay, with no open port: the relay forwards encrypted traffic and TLS ends in the broker. The default `--unlock-origin` is `https://localhost:9443` on both platforms, or the origin of an enabled relay. See `docs/private-pages.md`.

Restarting a broker on a new version locks its vault until the private unlock page is used. See `docs/releasing.md` for upgrade steps and `docs/windows.md` for Windows setup, limits and pending checks.
