# Native desktop fields (0.44.0)

Native field protocol 1 adds password, combined login, generated-password,
username, TOTP, SMS code, card and address fills, and read-only secret capture outside a
browser. Check `native_field_supported: true`, integer `native_field_protocol: 1`
and `native_field_delivery: "native-field-v1"` in `status`.

Supported controls:

- Linux: AT-SPI text/entry controls, including password text, in the active
  native window. The `libatspi` runtime and the app's accessibility bridge must
  be available. X11 and Wayland use the same accessibility transport. Tests use
  real GTK delivery and Qt read-only capture on X11 and native Wayland under a nested Weston compositor;
  this is not certification of every toolkit or compositor.
- Windows 10/11: visible, enabled Win32 Edit controls, WinForms TextBox controls
  and WPF TextBox and PasswordBox controls in the active native window.
  Check `native_field_windows_uia: true` for the Windows backend (0.50.0+).
  The broker requires its own user and session, the Default input desktop
  and a target at or below its integrity level. Browser controls are refused.
- macOS (0.50.0+) uses Accessibility in the frontmost native window. Check
  `native_field_accessibility_granted: true`. Each control must be visible at
  its center and support a character count. Username, TOTP, SMS code, card and
  identity fills require an unmasked writable field. Password and combined login modes
  are unavailable because stock AppKit secure fields omit the count. Read pins require selectable,
  read-only, unmasked text with a bounded accessible range. Browser windows
  and embedded web areas are refused. A window that contains a WebKit view
  (`WKWebView`) is refused from the moment the view is added. This is also true
  before its page loads and while WebKit hides its content.
  See [macOS setup](../../../docs/macos.md).

This is directed **control** delivery: Linux uses the retained AT-SPI editable
text object, and Windows uses `WM_SETTEXT` to the exact Edit HWND or UI Automation
ValuePattern on a retained WPF element. For a WPF PasswordBox, TextPattern
checks the UTF-16 length without reading back the password. For an unmasked
WPF TextBox, the broker reads the Value back and compares it exactly with the
written text; it never returns the value. UI Automation string conditions are
not used, because they accept canonically equivalent text. WPF supports single-line values
because UI Automation does not expose the TextBox AcceptsReturn setting.
Qt, WinUI, UWP, Java, Flutter, RichEdit and VCL controls are outside the
verified set. The broker refuses other UI Automation providers. There are
no global keys, Tab, clipboard or automatic submit actions. Legacy numeric
`pin-target` pins accept usernames, TOTP and SMS codes on X11, XWayland or Windows.
Native Wayland windows have no XID; use AT-SPI field pins there. Window pins
cannot authorize passwords or the other native field operations.

## Verify the destination

Independently verify the app, process, intended account and field through the
GUI tools. Native apps have no DOM, browser tab or browser origin. The required
`--service-url` is the caller's assertion of the service used in that app,
not a URL discovered or attested by the OS. Login, generated-password and TOTP
fills and secret capture require that assertion to match the selected entry's
allowed HTTPS origins. Cards and addresses use an explicitly asserted field
purpose, as these controls have no browser autocomplete semantics.

Do not use native pins to fill browser pages, browser chrome, terminals, custom
web views or unsupported controls. Known browser processes and accessible web
documents are refused. Use the browser CDP or Extension route for pages; those
routes retain their tab, URL, document, frame and DOM-field checks.

The process, window, controls, field roles, editability, mask and focus must
remain unchanged. Native UI visibility flags are checked; this is not a browser
occlusion or native screenshot-attestation claim. A trusted app can change its
own behavior or server connection; same-user compromise and a malicious target
app are outside this boundary, as on the browser routes.

## Discover and pin

Focus the intended native field, then discover that verified process:

```sh
akdbx list-native-fields --pid VERIFIED_PID
```

The response contains only opaque window tokens and control indices with
password/read-only flags and exactly one `focused` flag. It reads no values,
labels or titles. Select the field through the GUI first and use its `focused`
index; never infer purpose from an index alone. Tokens expire after 30 seconds.

Pin the selected control:

```sh
akdbx pin-native-target --window OPAQUE_WINDOW --control PASSWORD_INDEX \
  --mode password --service-url https://example.com/
```

Password mode requires a still-masked password control. For combined login,
first focus the username field through the GUI, then discover. Save its
`focused` index as `USERNAME_INDEX`. Next focus the password field through the
GUI, and pin the same discovery token with `--mode login
--username-control USERNAME_INDEX --control PASSWORD_INDEX`. The username must
have held focus during discovery and the password must hold focus at pinning
and through delivery. Both controls are pinned explicitly; Tab order is irrelevant. Username mode requires an editable, unmasked text control.

Use the returned target with the existing commands:

```sh
akdbx fill FRESH_SEARCH_HANDLE --mode password --target NATIVE_TARGET
akdbx fill FRESH_SEARCH_HANDLE --mode login --target NATIVE_LOGIN_TARGET
akdbx fill-generated GENERATED_REF --target-url https://example.com/ --target NATIVE_PASSWORD_TARGET
```

Generate and commit passwords through the normal staged write flow. Each
password and confirmation fill needs a fresh discovery and pin. Commit only
after independently confirming that the intended app accepted the password.

For a card, pin `--mode card --field cc-number` (or another supported card
field), then use `fill-card --target NATIVE_TARGET --field cc-number`. For an
address, pin `--mode identity --field address-line1`, then use `fill-identity`
with the same field. The existing expiry/year and telephone formats still
apply. Multiline street addresses require a multiline native control.
`--notify-page` is unavailable for native controls.

For a texted verification code, require `code` in `native_field_modes`. Pin
the focused unmasked input with `--mode code` and the app's verified service
URL. Use `fill-sms-code MESSAGE_ID --target NATIVE_TARGET`. The receipt
reports `code_delivery: native-field-v1`. See [SMS](sms.md).

For TOTP, pin `--mode totp`, then use the normal `fill-totp` command with its
matching `--target-url`. Clock/expiry checks remain active through delivery.

## Capture a displayed native secret

Use `--mode read` only on an independently verified, visible, read-only,
unmasked text control. Editable fields and password controls are refused.
Focus that control before discovery, obtain a fresh native read target, then
use `capture-secret` as usual. The broker reads only that pinned control and
saves its value into the verified encrypted vault; it never returns the value.
The receipt identifies `capture_delivery: "native-field-read-v1"`. Existing
single-line secret validation and configured sink rules are unchanged.

A native read pin cannot authorize `capture-totp`. The caller supplies
`--service-url`, and the OS cannot verify that a website at that origin
displayed the setup key. The broker consumes the pin and returns a fixed
refusal before reading the control.

All pins and entry handles are single-use. A changed destination refuses before
dispatch, or reports an uncertain result if a write may already have started.
Do not retry an uncertain fill automatically. A length check detects truncation;
it does not prove authentication or server-side acceptance. Check the app's
non-secret result, and never read a filled real password back with GUI tools.
On Windows, each Win32 discovery, focus and read message waits at most 100 ms.
`WM_SETTEXT` and its length check wait up to 1 s for a busy app, never past
the pin expiry or the fill deadline; a hung window fails at once. A timeout
after the write starts is uncertain.
