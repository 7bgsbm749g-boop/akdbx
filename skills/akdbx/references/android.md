# Android devices (0.36.0+)

`akdbx android` fills a login, username, password or authenticator code into
one verified field of the focused app on an Android device or emulator that
the operator configured. It covers Google account sign-in (for example Google
Play), pages in Chrome and Chrome Custom Tabs (for example GitHub Mobile's
sign-in, which opens github.com in a Custom Tab), and app fields whose app a
site names in its Digital Asset Links.

The value never passes through the agent. It is never an adb or shell
argument, never on the clipboard, never typed as key events, and never in a
response or log.

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
3. On the device, stop accessibility from reading password text (Android
   emulator images often have it on):

   ```sh
   adb -P 5043 -s emulator-5584 shell settings put secure speak_password 0
   ```

   The broker refuses app and Google sign-in password fields until it is 0.
4. Recommended: in Chrome on the device, turn off Settings > Password Manager >
   "Offer to save passwords", so Chrome does not keep a second copy.

`akdbx android devices` lists each device, whether the broker reaches it, its
Android SDK level and `speak_password`.

## Procedure

1. Bring the sign-in screen to the front (adb input or screenshots are fine;
   they never see a value). For a page field, tap the field so it has focus.
2. Inspect (read-only, works while the vault is locked):

   ```sh
   akdbx android inspect --device github-mobile
   ```

   The answer names the focused app (`package`, `activity`, `signer_sha256`),
   the verified `site` (origin and `source`) and the text fields. Each field
   has a `field` value: a node id for app fields (`kind: "app"`), a CSS
   selector for page fields (`kind: "page"`). It never holds field text.
3. Search the entry as usual (`akdbx search`). Its URL or an additional URL
   must be the exact verified site origin.
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
   Then submit with a tap and check the result on screen. Do not retry a fill
   whose `delivery` is `uncertain`; inspect first.

## Which site a pin may fill

| Focused app | Delivery | Verified site |
| --- | --- | --- |
| Chrome tab or Custom Tab (`com.android.chrome`, Google signing key) | Chrome DevTools socket (`chromium-password-dom-v1` for logins, `android-chrome-dom-code-v1` for codes) | The exact origin of the one visible, focused tab; its host must also match Chrome's address bar when the bar shows |
| Google account sign-in (`com.google.android.gms`, sign-in activity, Google signing lineage) | Accessibility helper (`android-accessibility-set-text-v1`) | `https://accounts.google.com` |
| Any other app | Accessibility helper | The site named with `--app-site https://...`, only if that site's `/.well-known/assetlinks.json` names the app's package and current signing certificate (`get_login_creds` or `handle_all_urls`) |

The fill refuses before any value moves when the entry's URL and additional
URLs do not include that site, when the pinned app, activity, signer, field
or device boot changed, when the field is hidden (for example behind the
keyboard), in a frame, or not a password field for a password, or when the
app is debuggable.

Page pins use the CDP route's own checks: the field must be focused, unique
for its selector, visible, and (for passwords) marked `autocomplete`
`username`/`current-password`. For a password field without that hint, add
`--password-purpose current-password` after you verified the field's purpose.

## Google Play and GitHub Mobile

- **Google Play sign-in**: open Play Store or Settings > Accounts > Add
  account > Google. Inspect shows `site_source: "google-sign-in"`. Fill the
  email (`--mode username`), tap Next, inspect again, fill the password
  (`--mode password`), tap Next. A Google 2-Step code field on the same
  screens takes `--mode totp`. The Google entry's URL (or an additional URL)
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
  of the device, as a DevTools port does for a desktop browser. akdbx checks
  the helper file's hash immediately before it starts it, but a process of the
  same user that races the device files could interfere.
- In Google Play services, the page URL is not visible to accessibility.
  akdbx trusts Google's signed sign-in activity to show Google's sign-in. A
  work account that redirects to a third-party identity provider (SAML) inside
  that screen is not detected: do not fill a Google password there.
- An authenticator code is visible on screen after it is filled, until the
  page submits it.
- Chrome on Android sometimes stops giving its page to accessibility. Chrome
  pages therefore use Chrome's DevTools socket. For other apps' web views the
  helper may briefly open and close the system volume panel to make the app
  rebuild its accessibility tree; it presses Back only while that panel is
  focused.
- Not supported: fields in frames, split one-character code boxes,
  passkeys, Android Autofill and Credential Manager prompts.
