# Android devices (0.36.0+)

`akdbx android` fills a login, username, password or authenticator code
(0.36.0), and from 0.50.1 a generated password, SMS code, card or identity
field, into one verified field of the focused app on an Android device or
emulator that the operator configured. From 0.50.1 it also reads shown-once
values in Chrome ([additional operations](#additional-android-operations-0501)).
It covers Google account sign-in (for example Google
Play), pages in Chrome and Chrome Custom Tabs (for example GitHub Mobile's
sign-in, which opens github.com in a Custom Tab), and native app fields whose
app a site names in its Digital Asset Links.

The value never passes through the agent. It is never an adb or shell
argument, never on the clipboard, and never in a response or log.

## Broker hosts

| Broker host | `akdbx android setup` | Attached device or emulator | Managed emulator (`android_managed_emulators`) | Host proof |
| --- | --- | --- | --- | --- |
| Linux | `--attach`, `--create`, `--manage-avd` | Yes | Yes: x86-64, KVM and a systemd 254+ user manager | CI, and a real Android 15 Google Play emulator |
| macOS (after 0.50.1) | `--attach` only | Yes, with the same owner checks as Linux | No: setup and `android wake` refuse (`false`) | CI on a macOS runner; no device or emulator (see [Limits](#limits)) |
| Windows | Refused: write the device file by hand | Yes, but no end-to-end host proof | No (`false`) | None |

On every host the broker checks the kernel's owner of its own loopback
connection to the adb server, and of its connection to Chrome's forwarded
DevTools port, before it sends a byte: `/proc/self/net/tcp` on Linux, the TCP
owner table on Windows, and `net.inet.tcp.pcblist64` on macOS.

## How a value reaches the device

The broker checks the operating-system owner of its adb connection. A managed
emulator (Linux) has a Unix socket in a private runtime directory. An attached
device uses its operator's loopback adb server, whose owner must be the broker
user.
It starts a small akdbx helper on the device (`app_process`, adb shell user)
and sends the request on that connection's standard input.

- **App fields and Google sign-in**: the helper finds the exact field through
  Android's accessibility API, checks it again, empties it, sets the value
  (`ACTION_SET_TEXT`) and confirms that the field holds it.
- **Chrome pages**: the broker reads the page through Chrome's DevTools
  socket (which tab is visible, which field is focused). On managed devices
  this is a stream inside the private adb connection. Any app could hold
  that socket's name, so before a value moves the broker proves the
  connection is Chrome's: it empties and focuses the pinned field, the helper
  types a random check string as key events that Android delivers only to
  windows of Chrome's own app user (after it checks that Chrome is focused in
  the pinned task and that Chrome's own address bar shows the pinned host),
  and the broker reads the pinned element's text back and compares it with
  that string itself (the connection is never told what to expect). Only
  Chrome received the keys, and only the focused element shows them. The
  broker then sets the value on that element over the same connection.

## On-demand emulator (0.37.0+)

On the broker host, choose one setup command. Without arguments,
`akdbx android setup` prompts at a terminal. The default device name is
`android`; use `--device NAME` to select another. `--create` and
`--manage-avd` need Linux; on macOS use `--attach` (after 0.50.1).

- `akdbx android setup --create` provisions a persistent Android 35 Google Play
  x86-64 virtual device. It uses Google's Linux command-line tools, downloads
  the SDK packages if needed and lets sdkmanager present its license. Allow
  several GiB for the SDK and device data. The host needs Java, read/write
  access to `/dev/kvm`, and systemd 254+ with a working user manager. Run it
  as the user who runs the broker. Setup leaves the emulator off.
- `akdbx android setup --attach SERIAL --adb-port 5037` registers an online
  device on a running adb server and disables spoken passwords. Its operator
  controls its power and adb server. It works on Linux and, after 0.50.1, on
  macOS. `--adb` defaults to `adb` on `PATH`, then `platform-tools/adb` in the
  SDK (`~/Library/Android/sdk` on macOS).
- `akdbx android setup --manage-avd NAME --sdk /path/to/sdk --avd-home /path/to/avd`
  adopts an existing stopped emulator. The registry directory must contain
  `NAME.ini`. Use its original SDK, device name, adb and emulator ports when
  converting an attached entry. Stop that device and its dedicated adb
  server first. Adoption keeps the virtual disk and signed-in accounts.

The managed adb server accepts clients on a private Unix socket. It disables
USB, mDNS and emulator discovery. The worker registers its own emulator,
which uses a pair of ports (5584 and 5585), and reserves its legacy adb
notification port (5043) on 127.0.0.1 and [::1] without accepting TCP clients. For another device, choose unused ports
with `--adb-port` and `--emulator-port`. `--sdk` defaults to `ANDROID_HOME`,
then `ANDROID_SDK_ROOT`, then `~/Android/Sdk`. New AVDs live under
`$XDG_DATA_HOME/akdbx/android/avd` (default `~/.local/share/akdbx/android/avd`).
Use the same `AKDBX_ANDROID_DEVICES` setting in the CLI and the broker when
you choose a custom registration file.

`akdbx status` and `akdbx android devices` report the managed device's power
state without starting it. Inspect, pin and Google sign-in wake it before
contacting the device. For several app steps or a long-running tool, wrap the
command with `akdbx android run --device android -- PROGRAM ARGS`. For example,
`akdbx android run --device android -- adb shell getprop ro.build.version.sdk`
reads the Android version. The command gets the correct adb path, endpoint and
serial. Concurrent commands share one emulator. After the last command exits,
the emulator and its adb server stop after the idle interval (default 180
seconds; set `--idle-seconds` at setup). The AVD data stays on disk.

### Mobile confirmation

1. Sign in to the service's mobile app on this device and enable notifications.
2. When the active login offers mobile confirmation, wake the device with
   `akdbx android wake --device NAME` before requesting the notification. For
   a flow that may take longer than the idle interval, hold the whole flow
   with `android run`.
3. Open the matching request in the app. Check its account, service and the
   challenge from the login you started. Confirm that request and check that
   the service accepts it. If the prompt cannot be matched, leave it pending.
   Support for mobile confirmation depends on the provider and app.

A push notification cannot boot a stopped emulator. An ordinary browser fill
or vault TOTP does not power up Android. The stock Google Play image and its
signed-in app data belong to the Android SDK installation and AVD. The
broker delivers credentials through its existing verified helper.

## Manual setup for an externally managed device

1. Run the adb server that already serves the device, on a fixed port.
2. Create the broker's device file, owned by the broker user, mode 0600, in a
   folder others cannot write. The default path is
   `~/.config/akdbx/android-devices.json` (`$XDG_CONFIG_HOME/akdbx/`); `serve
   --android-devices PATH` or `AKDBX_ANDROID_DEVICES` changes it. On macOS the
   file must have one hard link, and neither the file nor its folder may have
   an allow ACL entry (deny-only entries are fine). The broker reads it at
   each request, so no restart (and no unlock) is needed:

   ```json
   {"version": 1, "devices": {
     "github-mobile": {"adb": "/abs/path/platform-tools/adb", "adb_server_port": 5043, "serial": "emulator-5584"}
   }}
   ```

   The broker never starts an adb server: if none listens on that port it
   refuses.
3. On the device, stop accessibility from reading password text (Android
   emulator images often have it on):

   ```sh
   adb -P 5043 -s emulator-5584 shell settings put secure speak_password 0
   ```

   The broker refuses until it is 0.
4. Recommended: in Chrome on the device, turn off Settings > Password Manager >
   "Offer to save passwords", so Chrome does not keep a second copy.

`akdbx android devices` lists each device, whether the broker reaches it, its
Android SDK level and `speak_password`.

## Procedure

1. Bring the sign-in screen to the front (adb input or screenshots are fine;
   they never see a value). For a page field, tap the field so it has focus;
   in login mode, tap the username field.
2. Inspect (read-only, works while the vault is locked):

   ```sh
   akdbx android inspect --device github-mobile
   ```

   The answer names the focused app (`package`, `activity`, `signer_sha256`),
   the verified `site` (origin and `source`) and the text fields. Each field
   has a `field` value: a node id for app fields (`kind: "app"`), a CSS
   selector for page fields (`kind: "page"`). It never holds field text.
3. Search the entry as usual (`akdbx search`). Its URL or an additional URL
   must be the exact verified site origin. For Google account sign-in, use
   `akdbx android google-sign-in` instead of steps 4 and 5 (see below).
4. Pin within 30 seconds:

   ```sh
   akdbx android pin --device github-mobile --mode password --field FIELD
   akdbx android pin --device github-mobile --mode login --username-field FIELD --field FIELD
   akdbx android pin --device github-mobile --mode totp --field FIELD
   ```

   For these sign-in commands use `login` (username then password), `username`, `password` or `totp`.
5. Fill once with the pin's token:

   ```sh
   akdbx android fill HANDLE --target TOKEN --mode password
   akdbx android fill-totp HANDLE --target TOKEN
   ```

   The receipt is `{"ok": true, "filled": MODE, "target_delivery": ...}`.
   Then submit with a tap or Enter and check the result on screen. Do not
   retry a fill whose `delivery` is `uncertain`; inspect first.

<a id="additional-android-operations-0500"></a>

## Additional Android operations (0.50.1+)

Use a fresh `akdbx android pin --device NAME --field FIELD` for each command.
Check `android_fill_modes` for the required mode. For a native app also supply
the verified `--app-site` when pinning.

| Operation | Pin options | Command |
| --- | --- | --- |
| Generated password | `--mode password` | `fill-generated --target-url RESET_URL --target TOKEN -- FILL_HANDLE` (requires `android_generated_password: true`) |
| SMS code | `--mode sms` | `fill-sms-code MESSAGE --target TOKEN --target-url CHALLENGE_URL` (the HTTPS origin must match the pin) |
| Card field | `--mode card --purpose cc-number` | `fill-card HANDLE --field cc-number --target TOKEN` |
| Identity field | `--mode identity --purpose email` | `fill-identity HANDLE --field email --target TOKEN` |
| Shown-once secret or authenticator setup key | `--mode read` | Use the token with `capture-secret` or `capture-totp` and the usual entry metadata. Chrome only. Check `android_read_delivery` for `android-chrome-verified-read-v1`. |

For a card or identity pin, use the field name for the selected value as its
purpose. On Chrome, focus the field and use the matching HTML autocomplete
token. The browser guard checks that the field is visible, exposed and still
the same element. On a Chrome page, `fill-identity --notify-page` sends
bubbling `input` and `change` events after the value is set; without it the
fill sends no event. An app field has no page to notify: after 0.51.0 the
broker refuses `--notify-page` there before any value, with `identity fill
not started: --notify-page needs a web page, and an app field has none`. The
pin is used up; pin again and fill without the option.
For a read pin, focus a visible read-only text input or a focusable text leaf.
Supply a simple selector for that element. Read pins accept up to 16 rendered text rectangles. A leaf may need a selector from
the page because `android inspect` lists input fields. The read pin checks
that the shown value, focus and document stay the same. Capture keeps the
value inside the broker. After `capture-totp`, use a fresh `--mode totp` pin
and `akdbx android fill-totp --pending HANDLE --target TOKEN` for the site's
confirmation step (requires `android_pending_totp: true`). Then run
`commit-totp` with the site's result. In-app web views and frames remain unsupported.

**Reply time and cold boots.** Before each value the helper runs its typed
check (below), which takes under a second on a warm device and 5 to 10
seconds right after a cold boot. A managed emulator always starts from a
cold boot.

- Login, username, password, generated-password and TOTP pins: the 4-second
  start deadline bounds the first key of the check, so a fill right after a
  cold boot still fills. When the broker has Android devices configured,
  `fill`, `fill-generated`, `fill-totp`, `fill-card`, `fill-identity` and
  `fill-sms-code` wait up to 60 seconds for the broker's answer, as `akdbx
  android fill` does (after 0.51.0). Before, they waited 5 seconds, and a
  fill right after a cold boot ended with `autofill outcome uncertain:
  connection lost after request`.
- Card, identity, SMS-code and read pins: the whole typed check must end
  within the 4-second start deadline. Right after a cold boot these fills,
  `capture-secret` and `capture-totp` are refused with delivery
  `not-started` and nothing filled or read. Search and pin again a few
  seconds later: in the lab, the next pin 10 seconds later filled every time,
  about a minute after the emulator started. To avoid the wait, wake the
  device first (`akdbx android wake`, or hold it with `akdbx android run`).

For these new Chrome read, SMS, card and identity pins, the helper sends
random key events only to Chrome. The retained focused element must receive
the whole sequence before the broker reads or writes. The check cancels the
keys' normal editing action so it can verify a read-only or short field.
A page with a capturing keyboard handler on its window is refused.
For generated passwords the existing password field check applies.

## Which site a pin may fill

| Focused app | Delivery | Verified site |
| --- | --- | --- |
| Chrome tab or Custom Tab (`com.android.chrome`, Google signing key) | Set on the element after the typed check proves the connection is Chrome's (`android-chrome-verified-dom-v1`) | The exact origin of the one visible, focused tab; its host must match Chrome's address bar (which hides `www.` and shows Unicode hosts) |
| Google account sign-in (`com.google.android.gms`, Google signing lineage) | Accessibility helper (`android-accessibility-set-text-v1`) | `https://accounts.google.com`: the email pin, and `android google-sign-in` |
| Any other app | Accessibility helper | The site named with `--app-site https://...`, only if that site's `/.well-known/assetlinks.json` shares its credentials with the app's package and current signing certificate (`delegate_permission/common.get_login_creds`; App Links alone are not enough). Native fields only: a web view inside an app is refused, because its page's site cannot be read |

The fill refuses before any value moves when the entry's URL and additional
URLs do not include that site, when the pinned app, activity, task, signer,
field or device boot changed, when the field is hidden (for example behind
the keyboard) or in a frame, when a password would go into a field that is
not a password field, or when the app is debuggable. A fill whose value the
field does not hold afterwards (for example a page cleared or cut it) is
reported as `uncertain`.

## Google Play and GitHub Mobile

- **Google Play sign-in** (a `@gmail.com` or `@googlemail.com` account):

  ```sh
  akdbx android google-sign-in HANDLE --device github-mobile [--code]
  ```

  The helper closes any open Google sign-in, opens a new one in a new task
  (Settings > Add account > Google, which Google Play uses too), skips the
  phone-number offer, fills the entry's email on Google's first page and
  submits it. It then fills the password, and with `--code` the code on
  Google's authenticator-app page (`totpPin`), only on the pages that
  Google's flow shows next in that task, with no other step in between. The
  broker makes the code only when that page is ready. The receipt lists what
  was filled (`"filled": ["email", "password"]`) and `stopped_at` when a page
  did not come (for example Google asked for another sign-in method or could
  not find the account); nothing after that point is filled.

  Google's sign-in web view shows no page URL, and a work or school account
  can move it to its own company page. So this runs only for consumer Google
  accounts, and a separate password or code pin in Google sign-in is refused;
  only the email may be pinned alone. The entry's URL (or an additional URL)
  must be `https://accounts.google.com`; `akdbx add-url` can add it.
- **GitHub Mobile**: "Sign in" opens github.com in a Chrome Custom Tab.
  Tap the username field, inspect (`site_source: "chrome"`), pin in login
  mode, fill, tap "Sign in". On the two-factor page, tap the code field,
  inspect, pin `--mode totp`, `fill-totp`.

## Limits

- Tested on an Android 15 (API 35) Google Play emulator with Chrome 124 and
  Google Play services 26.45. A physical device over USB uses the same path but
  was not tested; the device must have USB debugging on.
- `tests/test_android_emulator.py` (after 0.51.0) runs on a real emulator
  through the real broker, CLI and helper: on a Chrome page, a login, a
  generated password from pin through commit, `capture-secret` from pin
  through save, a text-key `capture-totp` through the pending code and
  `commit-totp`, a card field, an identity with and without `--notify-page`,
  an SMS code, and their refusals (another site, a used pin, a value or key
  that changes after the pin, covered text, an editable field, prose). With
  `AKDBX_TEST_ANDROID_COLD_BOOTS=N` it cold-boots a managed emulator N times
  and fills a generated password at once each time. It needs KVM, so it runs
  on a Linux host by hand, not in CI:

  ```sh
  AKDBX_TEST_ANDROID_DEVICES=/path/devices.json AKDBX_TEST_ANDROID_DEVICE=NAME \
    python -m pytest -rs tests/test_android_emulator.py
  ```

  The device file is the broker's format. Chrome must have finished its
  first-run screens, and the device needs network access to
  `https://example.com`, whose document the tests replace with synthetic forms.
- Managed emulators need Linux: their worker runs as a systemd user unit
  with a private runtime directory, and the stock image is x86-64 for KVM.
  On macOS and Windows the broker refuses a managed entry with that reason.
- macOS (after 0.50.1): CI on a GitHub macOS runner proves the host side. A
  real loopback adb server stand-in and a DevTools forward of the runner user
  pass the owner check. `android setup --attach` runs that check, then a
  stand-in adb, then writes the private file. One owned by another account
  (`_www`) receives zero bytes. No device or emulator runs in that CI. This is
  an inherent limit: GitHub's arm64 macOS runners have no nested
  virtualization, so the emulator cannot start there. A macOS broker with a
  real device or emulator was not tested.
- Windows device operation has no end-to-end host proof. A Windows broker
  that reads a manual device registry requires a private file DACL and
  trusted parent directories.
- adb gives every process of the broker's operating-system user full control
  of the device, as a DevTools port does for a desktop browser. The broker
  checks the helper file's hash immediately before it starts it, but a
  process of the same user that races the device files could interfere. An externally managed adb
  loopback server port accepts any local client: on a host with other OS
  accounts, protect it as you would a browser's debugging port.
- The Google sign-in password and code steps were not tested end to end: a
  synthetic account cannot pass Google's email page. The run was checked up to
  that point (a new task, the email filled and submitted, and a stop with no
  password when Google did not find the account).
- Chrome pages: the field must accept the check string, which is 6 to 16
  letters and digits (up to the field's maximum length). In a code field it
  is 5 characters with a letter (5 digits in a number field), fewer than any
  code, so a page that submits a complete code never submits it. A code
  field that drops letters, a code field limited to fewer than 6 characters,
  or another field limited to fewer than 6 is refused. An authenticator code
  is visible on screen after it is filled, until the page submits it.
- A site with so many open tabs that Chrome's DevTools cannot list them
  within 30 seconds is refused; close some tabs.
- Chrome on Android sometimes stops giving its page to accessibility, so
  Chrome pages are read through DevTools. For other apps' web views the helper
  may briefly open and close the system volume panel to make the app rebuild
  its accessibility tree; it presses Back only while that panel is focused.
- Not supported: fields in frames, split one-character code boxes,
  passkeys, Android Autofill and Credential Manager prompts.
