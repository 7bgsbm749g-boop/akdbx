# Target-pinned X11 fill (0.9.0)

All saved and generated fills require a fresh target token. There is no legacy
or global-input option. This is a breaking fill-API change; passwordless SSO
protocol 1, writes, merges and unlock behavior are unchanged.

## Supported workflow

1. Check CLI `--version` and broker `status`. Require 0.9.0 or newer,
   `target_fill_required: true`, integer `target_fill_protocol: 1`, and exact
   `target_fill_delivery: "x11-send-event-v1"`. CLI checks these before dispatch.
2. Search for a fresh entry handle. Independently verify the correct local app,
   process PID and X11 client window ID with the supported desktop tool. For
   Chrome, verify the canonical profile process, intended window and HTTPS URL.
   Do not treat a title match or current active PID as sufficient verification.
3. Bring the verified window to the foreground and focus the intended field.
   Release held keyboard/mouse keys and use neutral modifier/lock state. The
   broker refuses active modifiers, lock masks or buttons; it never changes
   another client's keyboard state. Do not inspect a password field value.
4. Run `akdbx pin-target --pid VERIFIED_PID --window VERIFIED_X11_CLIENT_WINDOW`.
   Window IDs accept decimal or `0x` hexadecimal. Retain the returned `target`
   privately, like a credential handle. Pinning never types.
5. Run `akdbx fill ENTRY_HANDLE --mode password --target TARGET_TOKEN` within
   30 seconds. Obtain new search and target handles for a separate fill.
   `login` uses directed username, Tab, password; verify Tab order first.
6. Require `ok: true`, the expected `filled` mode and
   `target_delivery: "x11-send-event-v1"`. Then submit and verify authenticated
   application state. The receipt proves dispatch, not field adoption or login.

For a reset, each `fill-generated REF --target-url VERIFIED_URL --target TOKEN`
needs its own fresh pin after independently focusing that field. A failed or
partial generated fill does not count toward the two successful fills needed
for `commit-password --site-accepted`. Do not commit until the site accepts it.

The broker consumes the credential handle on the first fill attempt. A resolved
target pin is consumed even if later mode, deadline, text or delivery checks
fail. Pins expire after 30 seconds and disappear on restart. Missing, malformed,
unknown, expired and incompatible targets fail closed. Unknown fill/pin RPC
fields are refused. New CLI refuses an old broker before sending the fill;
old clients cannot fill through a new broker without the required protocol.

## Delivery design and limits

The pin captures the foreground EWMH client window, exact X input-focus window
(which must belong to its tree), local `_NET_WM_PID` corroborated by X-Resource 1.2 local owner PID for both the
client and focus windows, same-UID Linux process
start time and executable inode, nonempty WM_CLASS, and local WM_CLIENT_MACHINE.
A fill opens its own X connection and subscribes before final validation. It
checks process/window/focus identity, visibility, held keys/buttons and relevant
focus, property, destruction, unmap, reparent and keyboard-map events before
and after every key pair, including Tab and the final key. A transient focus
loss followed by restoration still interrupts delivery.

Every press/release uses core X11 SendEvent to the *fixed pinned focus XID*,
with propagation disabled and event mask zero (the window owner's connection).
It never uses the special InputFocus/PointerWindow destinations or XTest global
input. A switch in the check/send gap cannot redirect that pair to the newly
foreground app. The broker stops remaining pairs on detected changes. A pair
already dispatched can still reach the original window after it loses focus;
there is no atomic cancellation of events already queued in the destination.

The backend preflights all characters against the existing first core keyboard
layout group, with explicit shift state. Unmapped Unicode/layout characters
are refused before any key. It never modifies a keymap or falls back to global
input. Synthetic-event acceptance depends on the application. A successful
receipt does not establish that an application accepted or rendered the keys.
A three-second delivery budget stops unusually long fills with partial
uncertainty. Native widget regressions use synthetic windows on a separate temporary
Xvfb server. A separate browser regression on Chrome 153.0.8010.47 proved six
individual username/password fills and one username–Tab–password fill using
only synthetic values, a new Xvfb desktop and a temporary profile. CDP prepared
and observed that test form; production X11Typer delivered every nonempty
value. This proves that browser/version accepted the tested input, not a real
site sign-in or every browser configuration. The parent must verify its actual
authorized sign-in after activation.

No X server/keyboard grabs are used. There is no check-then-unrestricted-global
input path and no second pynput connection that can deadlock under a server
grab. Owner PID verification uses [X-Resource 1.2](https://xorg.freedesktop.org/archive/current/doc/resourceproto/resproto.txt).
The delivery design follows [X11 SendEvent destination and event-mask semantics](https://xorg.freedesktop.org/archive/X11R7.6/doc/xproto/x11protocol.html#SendEvent).
The former [pynput Xorg text path](https://github.com/moses-palmer/pynput/blob/master/lib/pynput/keyboard/_xorg.py)
also uses SendEvent, but resolves the current focus for each event and uses
XTest for special keys. This release removes that unrestricted destination.

X11 metadata and events are not authenticated. A hostile same-display/account
process can spoof properties, intercept input or manipulate resources. This
is not atomic or hostile-process isolation. Browser tabs, DOM focus, URL/origin,
same-window content changes, and renderer acceptance cannot be proved from X11
window identity. Caller GUI checks remain required. Missing X-Resource 1.2 ownership support or unknown EWMH/PID/host/focus
metadata or unsupported desktop backends are refused; do not weaken validation.

`delivery: "not-started"` / `autofill not started: ...` means no key was sent for
that request. Recheck the app and focus before a deliberate fresh attempt.
`delivery: "uncertain"` / `autofill outcome uncertain: ...` means at least one
pair may have been dispatched. Stop, check non-secret application state and
broker health, and do not automatically retry. Clear/prepare the destination
only through the authorized GUI workflow; never read back a password.

## Parent-owned activation

The source repair thread must not activate the patch. The original workflow
must first read the repair's actual final result and complete test/push evidence.
Keep the latest verified encrypted vault state and resolve pending writes/fills
and stop the owned broker before changing its source checkout. Select the
reviewed commit in the established live checkout without overwriting unrelated
edits. Install there with
`.venv/bin/pip install -e .` (the direct dependency is now python-xlib >=0.33,<1).
Do not change permissions, service policy, desktop/profile or vault configuration.

Check `.venv/bin/akdbx --version` reports 0.9.0. Perform one coordinated normal
restart of the existing owned broker using its unchanged DB/key/socket/unlock
and desktop environment. Share its new private unlock link; let the user unlock.
Require the running broker's version/capabilities above, `locked: false`, and
`recovery_required: false`. Confirm passwordless SSO protocol 1 remains advertised.
Reread the skill, obtain fresh handles and pin, then resume the original login.
Real browser acceptance and the authorized login result belong to that workflow.
