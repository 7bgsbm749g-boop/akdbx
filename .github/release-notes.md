akdbx {{VERSION}} is one release for every platform. Install the same wheel on Linux and Windows; pip selects `python-xlib` or `pywin32` automatically.

| Platform | Status | Fills | Not available |
| --- | --- | --- | --- |
| Linux (X11 + Chromium) | Established | Passwords and logins to verified Chromium DOM inputs; usernames and TOTP to pinned X11 windows; cards and identity fields in Chromium; the browser extension route | — |
| Windows 10/11 | Same feature set from 0.17.0; unlock from another device and authenticator capture from 0.22.0 | Passwords and logins to verified Chromium DOM inputs; usernames and TOTP to pinned windows; cards and identity fields in Chromium; the browser extension route (Helium, Chrome, Edge); authenticator capture through the browser native host | — |

Verify a download before installing it:

```sh
sha256sum --check SHA256SUMS
gh attestation verify akdbx-{{VERSION}}-py3-none-any.whl --repo 7bgsbm749g-boop/akdbx
```

Merge and snapshot admission need KeePassXC CLI 2.7.10 or newer, below 2.8, on both platforms; on Windows it must be installed for all users.

Restarting a broker on a new version locks its vault until the private unlock page is used. See `docs/releasing.md` for upgrade steps and `docs/windows.md` for Windows setup, limits and pending checks.
