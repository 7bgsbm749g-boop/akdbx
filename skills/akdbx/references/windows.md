# Native Windows operation

Use the installed Windows executable, typically
`CHECKOUT\.venv\Scripts\akdbx.exe`, in the broker's Windows desktop session. Keep
the existing signed-in app when it satisfies the task. From 0.17.0 the Windows
backend has the same workflows as Linux: DOM password, login and
generated-password fills, the full password-write workflow, cards, merge,
snapshot admission and durable unlock notifications. The repository's
`docs/windows.md` contains setup, the browser and engine requirements, and the
validation record; this reference covers operation of an already configured
broker.

Every instruction in `SKILL.md` and the other references applies on Windows,
with these replacements:

| Linux | Windows |
| --- | --- |
| Tailscale HTTPS page, opened on any tailnet device | Loopback HTTPS page, opened on the **Windows machine** |
| Unix socket, `--broker-uid` | Local named pipe of this user and session; `--broker-uid` is refused |
| `pin-target` X11 window, `x11-send-event-v1` | `pin-target` top-level HWND, `win32-char-v1` |
| `/absolute/path/to/akdbx/.venv/bin/akdbx` | `CHECKOUT\.venv\Scripts\akdbx.exe` |
| `/usr/bin/keepassxc-cli`, root-owned | `%ProgramFiles%\KeePassXC\keepassxc-cli.exe`, installed for all users |

## Before a fill

- Use the independently configured `AKDBX_UNLOCK_ORIGIN` (normally
  `https://localhost:9443`), not a hostname learned from a broker response.
- Run `status`. Require an unlocked broker with `recovery_required: false`.
  For password, login and generated-password fills also require integer
  `password_fill_protocol: 1`, `password_fill_delivery:
  "chromium-password-dom-v1"` and `password_browser_configured: true`. For
  window pins require `target_fill_delivery: "win32-char-v1"` and target
  protocol 1. `target_fill_modes: ["username"]` describes window pins only.
- When locked, give the exact returned private HTTPS link to the user. It opens
  on the **Windows machine**, not a separate Tailscale device. The user enters the
  master password privately. Never bypass a TLS certificate warning, read the
  master password, submit it for the user, or replace HTTPS with HTTP. Register
  an unlock notification as `SKILL.md` describes and resume on that event. The
  broker needs a trusted local certificate and private key; do not start a
  duplicate broker or change trust/permissions merely because a command fails.
- `password_browser_configured: false` means the operator did not start the
  broker with `--password-browser-profile`. The CLI then refuses password,
  login and generated-password requests before dispatch. Report this exact
  blocker. Do not restart the broker, change a browser profile or look for
  another way to type a password.

## Password, login and username fills on a web page

Use the DOM route exactly as [password field delivery](target-fill.md)
describes. The page must be open in the browser profile that the broker was
started with.

1. Verify the site, account and field with the authorized browser tool.
2. `list-password-frames --top-url EXACT_HTTPS_URL` returns `page_id` and
   `main_frame_id`, and each child frame's `frame_id` and `origin`. No raw CDP
   call is needed.
3. Focus the field. As on Linux, the browser window must be the active window,
   the page must be the visible tab and the field must be the focused element.
   Do not move focus or navigate while a pin is pending.
4. `pin-password-target --page-id PAGE_ID --frame-id MAIN_FRAME_ID --top-url
   EXACT_HTTPS_URL --selector SELECTOR --mode password` (or `--mode login
   --username-selector USERNAME_SELECTOR` with the username focused, or
   `--mode username`).
5. `fill HANDLE --mode MODE --target PIN` with a fresh search handle, or
   `fill-generated FILL_HANDLE --target-url URL --target PIN`.
6. Verify the application's nonsecret outcome. Never read back a filled field.

Account creation and password resets use
[the password-write workflow](password-writes.md) without change:
`generate-entry`, one fresh pin and `fill-generated` for the new-password
field, another for the confirmation field, the site's acceptance, then
`commit-password --site-accepted -- WRITE_HANDLE`.

## Username and TOTP fills in a native application

- Independently verify the application's PID and top-level HWND. Focus the
  intended field. Call `pin-target --pid VERIFIED_PID --window VERIFIED_HWND`.
  HWND values can be decimal or `0x` hex.
- Use a fresh search handle and target pin for each
  `fill HANDLE --mode username --target PIN` or `fill-totp`. A window pin
  refuses `--mode password`, `--mode login` and `fill-generated`: a browser's
  address bar shares its page's HWND, so only a DOM pin may receive a
  password.
- A success receipt confirms directed message dispatch, not application
  acceptance. Some apps ignore synthetic `WM_CHAR` messages. Stop on uncertain
  or partial delivery; do not retry or fall back to global input/clipboard.

## Saves, cards, merge and notifications

- Private password, authenticator and card saves use the local HTTPS page.
  Shared metadata, site acceptance, exact-receipt and handle-consumption rules
  apply. Files need restrictive Windows DACLs on a trusted local NTFS path. Do
  not copy a real vault into a test or change file permissions without
  authorization. Keep encrypted recovery files if a save is uncertain.
- Card fills follow [card workflows](cards.md). Require
  `card_browser_configured: true`.
- Merge and admission follow [the merge workflow](merge.md) and
  [the admission contract](snapshot-admission.md). Require `merge_available:
  true` and read `merge_engine`. `merge_available: false` with `merge_engine:
  null` means that no trusted KeePassXC CLI 2.7.10 or newer, below 2.8, is
  installed for all users. Report it; do not point the broker at another copy.
- `subscribe-unlock` and `subscribe-card-save` read the callback from a file
  that only this user, SYSTEM and administrators can open. Until-unlock
  subscriptions survive a broker restart.
- The browser native host for authenticator capture (`akdbx-browser-import`)
  is Linux-only. Use the private HTTPS import page of `setup-totp`.

The broker, browser and target must have the same Windows user and desktop
session. Do not elevate the broker to fill UAC, secure-desktop, service-session
or other unsupported targets. Python/Windows cannot protect from a malicious
process running as the same user or an administrator.
