# Android devices (0.36.0+)

`akdbx android` fills a login, username, password or authenticator code into
one verified field of the focused app on an Android device or emulator that
the operator configured. It covers Google account sign-in (for example Google
Play), pages in Chrome and Chrome Custom Tabs (for example GitHub Mobile's
sign-in, which opens github.com in a Custom Tab), and native app fields whose
app a site names in its Digital Asset Links.

The value never passes through the agent. It is never an adb or shell
argument, never on the clipboard, never sent over Chrome's DevTools
connection, and never in a response or log.

## How a value reaches the device

The broker talks to the operator's adb server itself, over a loopback
connection whose owner it checks (another OS account's listener is refused).
It starts a small akdbx helper on the device (`app_process`, adb shell user)
and sends the request on that connection's standard input.

- **App fields and Google sign-in**: the helper finds the exact field through
  Android's accessibility API, checks it again, empties it, sets the value
  (`ACTION_SET_TEXT`) and confirms that the field holds it.
- **Chrome pages**: the broker uses Chrome's DevTools socket only to read the
  page: which tab is visible, which field is focused, and how many characters
  it holds. The helper types the value as key events that Android delivers
  only to windows of Chrome's own app user, after it checks that Chrome is the
  focused app in the pinned task and that Chrome's address bar shows the
  pinned host. Another app that held the DevTools socket name could lie about
  a page, but it never receives a value.

## Operator setup

1. Run the adb server that already serves the device, on a fixed port.
2. Create the broker's device file, owned by the broker user, mode 0600, in a
   folder others cannot write. The default path is
   `~/.config/akdbx/android-devices.json` (`$XDG_CONFIG_HOME/akdbx/`); `serve
   --android-devices PATH` or `AKDBX_ANDROID_DEVICES` changes it. The broker
   reads it at each request, so no restart (and no unlock) is needed:

   ```json
   {"version": 1, "devices": {
     "github-mobile": {"adb": "/abs/path/platform-tools/adb", "adb_server_port": 5043, "serial": "emulator-5584"}
   }}
   ```

   The broker never starts an adb server: if none listens on that port it
   refuses.
3. On the device, stop accessibility from reading password text, and stop
   Android from showing each typed password character (emulator images often
   have both on):

   ```sh
   adb -P 5043 -s emulator-5584 shell settings put secure speak_password 0
   adb -P 5043 -s emulator-5584 shell settings put system show_password 0
   ```

   The broker refuses until both are 0.
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

   Modes: `login` (username then password), `username`, `password`, `totp`.
5. Fill once with the pin's token:

   ```sh
   akdbx android fill HANDLE --target TOKEN --mode password
   akdbx android fill-totp HANDLE --target TOKEN
   ```

   The receipt is `{"ok": true, "filled": MODE, "target_delivery": ...}`.
   Then submit with a tap or Enter and check the result on screen. Do not
   retry a fill whose `delivery` is `uncertain`; inspect first.

## Which site a pin may fill

| Focused app | Delivery | Verified site |
| --- | --- | --- |
| Chrome tab or Custom Tab (`com.android.chrome`, Google signing key) | Key events to Chrome only (`android-chrome-keys-v1`) | The exact origin of the one visible, focused tab; its host must match Chrome's address bar (which hides `www.` and shows Unicode hosts) |
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
- Linux broker only was tested. The Windows broker has the same code path.
- adb gives every process of the broker's operating-system user full control
  of the device, as a DevTools port does for a desktop browser. The broker
  checks the helper file's hash immediately before it starts it, but a
  process of the same user that races the device files could interfere.
- The Google sign-in password and code steps were not tested end to end: a
  synthetic account cannot pass Google's email page. The run was checked up to
  that point (a new task, the email filled and submitted, and a stop with no
  password when Google did not find the account).
- Chrome pages: only printable ASCII values can be typed; a value with other
  characters is refused before any key. An authenticator code is visible on
  screen after it is filled, until the page submits it.
- Chrome on Android sometimes stops giving its page to accessibility, so
  Chrome pages are read through DevTools. For other apps' web views the helper
  may briefly open and close the system volume panel to make the app rebuild
  its accessibility tree; it presses Back only while that panel is focused.
- Not supported: fields in frames, split one-character code boxes,
  passkeys, Android Autofill and Credential Manager prompts.
