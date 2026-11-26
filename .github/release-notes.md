akdbx {{VERSION}} is one release for every platform. Install the same wheel on Linux, Windows and macOS; pip selects platform dependencies automatically.

| Platform | Status | Fills | Not available |
| --- | --- | --- | --- |
| macOS | Local broker from 0.43.0; native Darwin IPC, TLS and encrypted save checks; guided setup, login LaunchAgent and desktop lock notifications (0.49.0) | The paired extension in Chrome, Edge and Helium (0.43.0), Firefox 153+ (0.47.0), Chromium and Brave (0.49.0); TOTP from the extension popup (0.49.0); Chromium CDP with private profiles and slots, set up by hand (0.50.1); Accessibility native field pins for usernames, TOTP, SMS codes, cards, addresses and reads (0.50.1); SMS codes through the extension and authenticator QR capture from setup pages (0.50.1); the private authenticator QR importer for Chromium and Firefox (0.48.0) | Numeric window pins; native password, login and generated-password pins (AppKit secure fields report no length); CDP in guided setup; Android devices; Safari (needs a signed Apple app wrapper) |
| Linux | Established; loopback HTTPS unlock from 0.23.0; relay from 0.26.0; native field pins on X11 and Wayland from 0.44.0 | Passwords and logins to verified DOM inputs (CDP and the extension) and to native AT-SPI fields; usernames, TOTP and SMS codes to pinned X11 or XWayland windows; cards and identity fields; SMS codes to native AT-SPI fields and TOTP from the extension popup (0.49.0); SMS codes through the extension and authenticator QR capture from setup pages (0.50.1); the extension route in Helium, Chrome, Edge, Chromium, Brave (0.49.0) and Firefox 153+ (0.47.0); Android devices and the managed emulator | Numeric window pins for native Wayland surfaces (use native field pins) |
| Windows 10/11 | Same feature set from 0.17.0; unlock from another device and authenticator capture from 0.22.0; the akdbx relay from 0.26.0 | Passwords and logins to verified DOM inputs (CDP and the extension) and to native Win32 Edit fields; usernames, TOTP and SMS codes to pinned windows; cards and identity fields; SMS codes to native Edit controls and TOTP from the extension popup (0.49.0); WinForms and WPF native fields, SMS codes through the extension and authenticator QR capture from setup pages (0.50.1); the extension route (Helium, Chrome, Edge, Firefox 153+ from 0.47.0; Chromium and Brave from 0.49.0); authenticator capture through the Chromium and Firefox (0.48.0) native hosts; secret sinks over a private named pipe (0.48.0) | Agent desktop slot window pins; UWP, WinUI and Qt native controls (not proven); the managed Android emulator |

Every operation, per route and platform, with the CI job that proves it and the reason for each gap: [support matrix](https://github.com/7bgsbm749g-boop/akdbx/blob/v{{VERSION}}/docs/support-matrix.md).

Verify a download before installing it:

```sh
sha256sum --check SHA256SUMS
gh attestation verify akdbx-{{VERSION}}-py3-none-any.whl --repo 7bgsbm749g-boop/akdbx
```

Merge and snapshot admission run inside akdbx on Linux, macOS and Windows. No KeePass or KeePassXC installation is required.

From 0.50.1 the private unlock page also takes a key file, or a KeePassXC YubiKey challenge-response for a KDBX 4 Argon2 vault; Linux CI tests the whole page flow, Windows CI the vault store, and macOS has no CI for it yet. All three platforms serve the same private HTTPS page: HTTPS on `127.0.0.1` with your own certificate (`--tls-cert`, `--tls-key`), opened on the broker's computer or, through Tailscale Serve to a verified `https://127.0.0.1:PORT` target (`--local-port`), on any tailnet device. Linux and macOS also support the Tailscale Serve Unix-socket route; Tailscale Serve on Windows cannot proxy to a Unix socket. From 0.26.0, `akdbx relay enable` opens the same page on any device through the akdbx relay, with no open port: the relay forwards encrypted traffic and TLS ends in the broker. The default `--unlock-origin` is `https://localhost:9443` on every platform, or the origin of an enabled relay. See `docs/private-pages.md`.

Restarting a broker on a new version locks its vault until the private unlock page is used. See `docs/releasing.md` for upgrade steps and `docs/windows.md` for Windows setup, limits and pending checks.
