akdbx {{VERSION}} is one release for every platform. Install the same wheel on Linux, Windows and macOS; pip selects platform dependencies automatically.

| Platform | Status | Fills | Not available |
| --- | --- | --- | --- |
| macOS | Local broker from 0.43.0; native Darwin IPC, TLS and encrypted save checks; guided setup, login LaunchAgent and desktop lock notifications (0.49.0) | The paired extension in Chrome, Edge and Helium (0.43.0), Firefox 153+ (0.47.0), Chromium and Brave (0.49.0); TOTP from the extension popup (0.49.0), and addresses with the agent's field checks and texted codes from it (0.52.0+); Chromium CDP with private profiles and slots, set up by hand (0.50.1); Accessibility native field pins for usernames, TOTP, SMS codes, cards, addresses and reads (0.50.1), and for passwords, logins and generated passwords (0.52.0+); SMS codes through the extension and authenticator QR capture from setup pages (0.50.1); the private authenticator QR importer for Chromium and Firefox (0.48.0); attached Android devices (after 0.50.1) | Numeric window pins; CDP in guided setup; the managed Android emulator; Safari (needs a signed Apple app wrapper) |
| Linux | Established; loopback HTTPS unlock from 0.23.0; relay from 0.26.0; native field pins on X11 and Wayland from 0.44.0 | Passwords and logins to verified DOM inputs (CDP and the extension) and to native AT-SPI fields; usernames, TOTP and SMS codes to pinned X11 or XWayland windows; cards and identity fields; SMS codes to native AT-SPI fields and TOTP from the extension popup (0.49.0), and addresses with the agent's field checks and texted codes from it (0.52.0+); SMS codes through the extension and authenticator QR capture from setup pages (0.50.1); the extension route in Helium, Chrome, Edge, Chromium, Brave (0.49.0) and Firefox 153+ (0.47.0); Android devices and the managed emulator | Numeric window pins for native Wayland surfaces (use native field pins) |
| Windows 10/11 | Same feature set from 0.17.0; unlock from another device and authenticator capture from 0.22.0; the akdbx relay from 0.26.0 | Passwords and logins to verified DOM inputs (CDP and the extension) and to native Win32 Edit fields; usernames, TOTP and SMS codes to pinned windows; cards and identity fields; SMS codes to native Edit controls and TOTP from the extension popup (0.49.0), and addresses with the agent's field checks and texted codes from it (0.52.0+); WinForms and WPF native fields, SMS codes through the extension and authenticator QR capture from setup pages (0.50.1); the extension route (Helium, Chrome, Edge, Firefox 153+ from 0.47.0; Chromium and Brave from 0.49.0); authenticator capture through the Chromium and Firefox (0.48.0) native hosts; secret sinks over a private named pipe (0.48.0) | Agent desktop slot window pins; UWP, WinUI and Qt native controls (not proven); the managed Android emulator |

Every operation, per route and platform, with the CI job that proves it and the reason for each gap: [support matrix](https://github.com/7bgsbm749g-boop/akdbx/blob/v{{VERSION}}/docs/support-matrix.md).

From 0.50.1, the private unlock page also accepts a vault key file or a KeePassXC YubiKey challenge-response (KDBX 4, Argon2). Linux and macOS CI test the whole page flow, and Windows CI the vault store. Version 0.50.0 was tagged but not published; its changes ship in 0.50.1.

From 0.50.3, `docs/support-matrix.md` lists every fill and capture operation by route and platform, with the release and CI job that prove each one or the reason for the gap.

From 0.52.0: macOS native fields fill passwords, logins and generated passwords (checked by masked length); Firefox captures authenticator QR codes; the toolbar popup fills address fields with the agent pin checks and offers texted codes; QR capture refuses any image that loads with CORS from another origin on every route; Android fills wait for a cold-booted device instead of reporting a lost connection.

From 0.53.0 (fill extension 0.16.0): the extension's experimental Enhanced security pixel check, its settings page and its `<all_urls>` permission request are removed. A page could beat the check, and the page that gets a value can read it anyway. The checks that stop hidden and invisible fields stay on both routes, and the CDP route still refuses a click-through cover. An extension that had the setting on keeps working. See the README section "Visibility checks: what they stop".

From 0.53.0, the akdbx relay no longer closes a connection before the phone receives its HTTP response (concurrent TLS calls are serialized), and a saved identity page ends on a short saved screen where the user can rename the entry.

From 0.53.0: every private save page (password, authenticator key and import, identity, card) sends a one-shot `akdbx.write-result` webhook when it is saved, fails, is cancelled or expires (`subscribe-write`), and `subscribe-sms --any-text` wakes when an SMS setup or test page receives its test text. Agents resume on the event instead of polling.

From 0.53.0 (fill extension 0.17.0): `akdbx extension sign --output DIR HANDLE` has Mozilla sign the broker's own Firefox build (AMO, unlisted channel) for a permanent install, with the AMO API key from a vault entry that stays inside the broker. Only the AMO account that owns the add-on ID `akdbx@akdbx.org` can sign. Each signed build has its own version; `status` reports it as current. See `docs/firefox.md`. (Removed after 0.54.1: the release signs one generic build instead.)

From 0.54.0 (fill extension 0.18.0): `pin-card-target --field-purpose cc-number|cc-csc|cc-name|cc-exp-month|cc-exp-year` fills a main-frame card field that has no autocomplete hint after the agent checks its purpose, and an expiry month or year that is an ARIA dropdown (a button with a listbox) is chosen by the broker itself, refusing on no match or an ambiguous match. This covers Microsoft's own card form (Azure sign-up).

From 0.54.1 (fill extension 0.18.1): a card expiry dropdown may be a `role=combobox` button with `aria-haspopup="true"` (Microsoft's card form) as long as the list it owns is a listbox; a menu still refuses.

After 0.54.1 (fill extension 0.19.0): the browser extension is one generic build for everyone, with no broker address and no per-user ID, so this release attaches it: `akdbx-extension-chrome-*.zip` (unzip, then Load unpacked), `akdbx-extension-firefox-*.zip` (unsigned, a temporary add-on) and, when the release could sign it, `akdbx-extension-firefox-*.xpi`, the same Firefox build signed by Mozilla for a permanent install. On first use the popup shows the broker address that the native host names and opens no pairing or unlock page until you confirm it; check it against `extension_trust.origin` in `akdbx status`. Broker trust that an earlier extension saved carries over once the broker signs with that key. `akdbx extension sign` and the `firefox_signing_*` status fields are removed. See `docs/private-pages.md` (Browser extension trust) and `docs/firefox.md`.

Verify a download before installing it:

```sh
sha256sum --check SHA256SUMS
gh attestation verify akdbx-{{VERSION}}-py3-none-any.whl --repo 7bgsbm749g-boop/akdbx
gh attestation verify akdbx-extension-chrome-*.zip --repo 7bgsbm749g-boop/akdbx   # and each other extension file
```

Merge and snapshot admission run inside akdbx on Linux, macOS and Windows. No KeePass or KeePassXC installation is required.

All three platforms serve the same private HTTPS page: HTTPS on `127.0.0.1` with your own certificate (`--tls-cert`, `--tls-key`), opened on the broker's computer or, through Tailscale Serve to a verified `https://127.0.0.1:PORT` target (`--local-port`), on any tailnet device. Linux and macOS also support the Tailscale Serve Unix-socket route; Tailscale Serve on Windows cannot proxy to a Unix socket. From 0.26.0, `akdbx relay enable` opens the same page on any device through the akdbx relay, with no open port: the relay forwards encrypted traffic and TLS ends in the broker. The default `--unlock-origin` is `https://localhost:9443` on every platform, or the origin of an enabled relay. See `docs/private-pages.md`.

Restarting a broker on a new version locks its vault until the private unlock page is used. See `docs/releasing.md` for upgrade steps and `docs/windows.md` for Windows setup, limits and pending checks.
