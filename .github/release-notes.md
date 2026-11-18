akdbx {{VERSION}} is one release for every platform. Install the same wheel on Linux and Windows; pip selects `python-xlib` or `pywin32` automatically.

| Platform | Status | Fills | Not available |
| --- | --- | --- | --- |
| Linux (X11 + Chromium) | Established | Passwords and logins to verified Chromium DOM inputs; usernames and TOTP to pinned X11 windows; cards | — |
| Windows 10/11 | Experimental | Usernames and TOTP to pinned windows; password imports and saves through the private HTTPS page | Password, login and generated-password fills; merge, snapshot admission, cards |

Verify a download before installing it:

```sh
sha256sum --check SHA256SUMS
gh attestation verify akdbx-{{VERSION}}-py3-none-any.whl --repo 7bgsbm749g-boop/akdbx
```

Restarting a broker on a new version locks its vault until the private unlock page is used. See `docs/releasing.md` for upgrade steps and `docs/windows.md` for Windows limits.
