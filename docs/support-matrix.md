# Support matrix (0.50.1)

This page is the one list of what each fill route does on each platform. It
comes from the code for 0.50.1: the `status` capability fields, the broker's
refusals and platform checks, and the CI jobs that prove each cell. Where
another page disagrees with this one, this page is correct; please report the
other page. A change that adds, removes or proves a cell updates this page in
the same pull request.

Check the running broker, not this page, before you act: `akdbx status` lists
the routes and modes that this broker offers now (`fill_routes`,
`target_fill_modes`, `native_field_modes`, `sms_fill_routes`,
`android_fill_modes` and the `*_protocol` fields).

## How to read a cell

| Mark | Meaning |
| --- | --- |
| ✅ `0.x.0` · `job` | Supported from release `0.x.0`. `job` is the CI job that runs a real browser or app test of this operation on this platform. |
| ✅ `0.x.0` · contract test (`job`) | Supported, but `job` tests it only with a simulated control, window or device, not a real app. |
| ✅ `0.x.0` · real emulator test | Supported. `tests/test_android_emulator.py` proves it on a real Android emulator through the real broker and CLI. That test needs KVM, so it runs by hand on a Linux host, not in CI (note X). |
| ✅ `0.x.0` · no CI | Supported by the same code as the other platforms, but no CI job tests it on this platform. Treat it as unproven there. |
| ⛔ by design | The broker refuses it on purpose. The note gives the reason. |
| ◼ inherent | The platform or route cannot do it safely. The note gives the reason. |
| ✗ not built | Nobody has built or proved it yet. The note says what is missing. |
| — | The operation does not exist on this route. |

`<0.16` means the feature shipped before the first release tag (`v0.16.0`).
`after 0.50.1` and `from 0.52.0` mean merged on `main` for the next release after that version.
`v0.50.0` was tagged but never published (its release checks failed), so the
features of PRs #81–#96 first ship in 0.50.1, together with key-file and
hardware-key unlock (#98).
Letters such as (A) point to the [notes](#notes). `ext 0.x.y` is the fill extension version that the operation needs.

CI jobs (all in `.github/workflows/`):

| Job | Workflow | What it runs |
| --- | --- | --- |
| `linux` | `tests.yml` | Unit and contract suites on Ubuntu, including Android with a simulated device |
| `linux-native-fields` | `tests.yml` | Real GTK and Qt apps on X11, XWayland and native Wayland (Weston) |
| `linux-extension-browser` | `tests.yml` | Chrome for Testing 153 with the built extension: fills, TOTP, QR capture, hidden-field and cover refusals |
| `firefox-extension-browser` | `tests.yml` | Firefox 161 on Ubuntu, Windows and macOS 15, and Firefox 153 on Ubuntu, with the built extension: fills, TOTP, secret reads, QR capture (also with `<all_urls>`), SMS codes |
| `windows` | `tests.yml` | Named pipe, real Win32, WinForms and WPF apps, Chrome and Edge CDP, the extension in Edge, QR capture |
| `macos-broker` | `tests.yml` | macOS 15: AppKit fields, Darwin IPC and TLS, Chrome CDP with a foreign-user listener, guided setup and LaunchAgent, Android attach host checks with a simulated device |
| `card-safety` | `card-safety.yml` | Real Chrome CDP: cards, processor frames, identities, SMS codes, agent desktop slots |
| `synthetic-password-fields` | `password-fields.yml` | Real Chrome CDP: passwords, child frames, secret capture, TOTP, QR capture, slot window pins |
| `synthetic-import` | `private-import.yml` | The private authenticator QR importer |

## Overview

| Route | Linux X11 | Linux Wayland | Windows 10/11 | macOS |
| --- | --- | --- | --- | --- |
| [Window pin](#window-pin-pin-target) (`pin-target`) | ✅ 0.9.0: usernames, TOTP, SMS codes | ✅ XWayland windows only (0.49.0); ◼ native Wayland surfaces (D) | ✅ 0.17.0, HWND: usernames, TOTP, SMS codes | ◼ unavailable (E) |
| [Native field](#native-field-pin-native-target) (`pin-native-target`) | ✅ 0.44.0, AT-SPI | ✅ 0.44.0, AT-SPI | ✅ 0.44.0 Win32 Edit; 0.50.1 WinForms, WPF | ✅ 0.50.1, Accessibility; passwords from 0.52.0 (F) |
| [CDP](#cdp-route) (`--route cdp`) | ✅ <0.16 | ✅ <0.16 | ✅ 0.17.0 | ✅ 0.50.1 |
| [Extension, Chromium family](#extension-route-chromium-family) | ✅ 0.21.0 | ✅ 0.21.0 | ✅ 0.21.0 | ✅ 0.43.0, no real-browser CI (P) |
| [Extension, Firefox 153+](#extension-route-firefox) | ✅ 0.47.0 | ✅ 0.47.0 | ✅ 0.47.0 | ✅ 0.47.0 |
| [Android](#android-route-akdbx-android) (`akdbx android`) | ✅ 0.36.0 | ✅ 0.36.0 | ✅ 0.50.1 · no CI (T) | ✅ after 0.50.1, attached devices only (AE) |
| Safari | — | — | — | ✗ not built (W) |

The CDP and extension routes talk to the browser, not to the display server,
so their Linux cells are the same on X11 and Wayland. CI runs those browsers
under Xvfb (X11).

## Window pin (`pin-target`)

A window pin sends key events to one verified, focused window
(`x11-send-event-v1` on Linux, `win32-char-v1` on Windows). It carries no
DOM, tab or origin proof.

| Operation | Linux X11 | Linux Wayland | Windows | macOS |
| --- | --- | --- | --- | --- |
| Username | ✅ 0.9.0 · `linux-native-fields` | ✅ XWayland (fixed 0.49.0) · `linux-native-fields`; ◼ native (D) | ✅ 0.17.0 · contract test (`windows`) (G) | ◼ (E) |
| Password, login, generated password | ⛔ (A) | ⛔ (A) | ⛔ (A) | ◼ (E) |
| TOTP | ✅ 0.10.0 · `synthetic-password-fields` | ✅ XWayland (0.49.0); ◼ native (D) | ✅ 0.17.0 · contract test (`windows`) (G) | ◼ (E) |
| Card, identity | ⛔ (B) | ⛔ (B) | ⛔ (B) | ◼ (E) |
| Card processor iframes, child-frame login, notify-page, popup | — | — | — | — |
| Secret read, `capture-totp` (text or QR) | ◼ (C) | ◼ (C) | ◼ (C) | ◼ (E) |
| SMS code (split boxes) | ✅ 0.40.0 · contract test (`linux`) (H) | ✅ XWayland (0.49.0); ◼ native (D) | ✅ 0.49.0 · `windows` | ◼ (E) |
| Agent desktop slot window | ✅ 0.35.3 · `synthetic-password-fields` | ✅ 0.35.3 (the slot has its own X display) | ✗ (I) | ◼ (E) |

## Native field (`pin-native-target`)

A native field pin retains one exact control of a native app: AT-SPI on
Linux, Win32 messages and UI Automation on Windows, Accessibility on macOS.
Native apps have no browser origin, so `--service-url` is the caller's
assertion. Check `native_field_modes` in `status`.

| Operation | Linux X11 | Linux Wayland | Windows | macOS |
| --- | --- | --- | --- | --- |
| Username | ✅ 0.44.0 · `linux-native-fields` | ✅ 0.44.0 · `linux-native-fields` | ✅ 0.44.0 Edit, 0.50.1 WinForms and WPF · `windows` (J) | ✅ 0.50.1 · `macos-broker` |
| Password, login | ✅ 0.44.0 · `linux-native-fields` | ✅ 0.44.0 · `linux-native-fields` | ✅ 0.44.0 Edit, 0.50.1 WinForms TextBox and WPF PasswordBox · `windows` (J) | ✅ from 0.52.0 · `macos-broker` (F) |
| Generated password | ✅ 0.44.0 · `linux-native-fields` | ✅ 0.44.0 · `linux-native-fields` | ✅ 0.44.0 · no CI | ✅ from 0.52.0 · `macos-broker` (F) |
| TOTP | ✅ 0.44.0 · contract test (`linux-native-fields`) | ✅ 0.44.0 · contract test (`linux-native-fields`) | ✅ 0.44.0 · contract test (`windows`) | ✅ 0.50.1 · `macos-broker` |
| Card | ✅ 0.44.0 · `linux-native-fields` | ✅ 0.44.0 · `linux-native-fields` | ✅ 0.44.0 · contract test (`windows`) | ✅ 0.50.1 · `macos-broker` |
| Identity | ✅ 0.44.0 · `linux-native-fields` | ✅ 0.44.0 · `linux-native-fields` | ✅ 0.44.0 · contract test (`windows`) | ✅ 0.50.1 · `macos-broker` |
| Card processor iframes, child-frame login, popup, slots | — | — | — | — |
| notify-page | ⛔ (K) | ⛔ (K) | ⛔ (K) | ⛔ (K) |
| Secret read (`capture-secret`) | ✅ 0.44.0 · `linux-native-fields` (GTK, Qt) | ✅ 0.44.0 · `linux-native-fields` | ✅ 0.44.0 Edit, 0.50.1 WinForms and WPF · `windows` | ✅ 0.50.1 · `macos-broker` |
| `capture-totp` (text or QR) | ⛔ (L) | ⛔ (L) | ⛔ (L) | ⛔ (L) |
| SMS code | ✅ 0.49.0 · `linux-native-fields` | ✅ 0.49.0 · `linux-native-fields` | ✅ 0.49.0 Win32 Edit · `windows`; WinForms and WPF: no test (M) | ✅ 0.50.1 · `macos-broker` |

## CDP route

The broker drives a Chromium profile that the operator started with
`--remote-debugging-port=0`. Every platform checks the owner of the
connection before the WebSocket handshake.

| Operation | Linux (X11 or Wayland) | Windows | macOS |
| --- | --- | --- | --- |
| Username, password, login | ✅ <0.16 · `synthetic-password-fields` | ✅ 0.17.0 · `windows` | ✅ 0.50.1 · `macos-broker` |
| Generated password | ✅ <0.16 · `synthetic-password-fields` | ✅ 0.17.0 · `windows` | ✅ 0.50.1 · `macos-broker` |
| TOTP | ✅ 0.45.0 · `synthetic-password-fields` | ✅ 0.45.0 · `windows` | ✅ 0.50.1 · `macos-broker` |
| Card | ✅ 0.14.0 · `card-safety` | ✅ 0.17.0 · `windows` | ✅ 0.50.1 · no CI for merchant-page fields (N) |
| Card processor iframes | ✅ Adyen 0.14.0, Computop 0.14.2, Stripe 0.18.1, Stripe Card Element 0.24.0 · `card-safety` | ✅ 0.17.0 Adyen and Computop, 0.18.1 Stripe · `windows` (Edge) | ✅ 0.50.1 Stripe Card Element · `macos-broker`; Adyen and Computop: no CI |
| Identity | ✅ 0.18.2 · `card-safety` | ✅ 0.18.2 · `windows` | ✅ 0.50.1 · `macos-broker` |
| Child-frame login | ✅ 0.16.0 · `synthetic-password-fields` | ✅ 0.17.0 · `windows` | ✅ 0.50.1 · `macos-broker` |
| notify-page (identity) | ✅ 0.41.0 · `card-safety` | ✅ 0.41.0 · `windows` | ✅ 0.50.1 · `macos-broker` |
| Secret read (`capture-secret`), also in child frames | ✅ 0.20.0 · `synthetic-password-fields` | ✅ 0.20.0 · `windows` | ✅ 0.50.1 · `macos-broker` |
| `capture-totp`, text key | ✅ 0.35.0 · `synthetic-password-fields` | ✅ 0.35.0 · `windows` | ✅ 0.50.1 · `macos-broker` |
| `capture-totp`, QR code | ✅ 0.50.1 · `synthetic-password-fields` | ✅ 0.50.1 · `windows` | ✅ 0.50.1 · no CI |
| SMS code | ✅ 0.40.0 · `card-safety` | ✅ 0.40.0 · `windows` (Edge) | ✅ 0.50.1 · `macos-broker` |
| Refuses a click-through cover over a card, address or code field (AG) | ✅ 0.16.0 · `card-safety` | ✅ 0.17.0 · no CI | ✅ 0.50.1 · no CI |
| Popup human click | — | — | — |
| Agent desktop slots (`--browser-slot`) | ✅ 0.30.0 · `card-safety` | ✅ 0.30.0 · no CI | ✅ 0.50.1 · `macos-broker` |

## Extension route, Chromium family

The paired akdbx extension in Helium, Chrome, Edge, Chromium or Brave
(installer names in `extension_host_browsers`). Chromium and Brave hosts
install from 0.49.0.

| Operation | Linux (X11 or Wayland) | Windows | macOS |
| --- | --- | --- | --- |
| Username, password, login | ✅ 0.21.0 · `linux-extension-browser` | ✅ 0.21.0 · `windows` (Edge) | ✅ 0.43.0 · no CI (P) |
| Generated password | ✅ 0.21.0 · no CI (Q) | ✅ 0.21.0 · no CI (Q) | ✅ 0.43.0 · no CI (P) |
| TOTP | ✅ 0.45.0 (ext 0.10.0) · `linux-extension-browser` | ✅ 0.45.0 · `windows` | ✅ 0.45.0 · no CI (P) |
| Card | ✅ 0.21.0 · `linux-extension-browser` | ✅ 0.21.0 · `windows` | ✅ 0.43.0 · no CI (P) |
| Card processor iframes | ✅ 0.21.0 (Card Element: ext 0.2.0) · `linux-extension-browser` | ✅ 0.21.0 Stripe · `windows` | ✅ 0.43.0 · no CI (P) |
| Identity | ✅ 0.21.0 · `linux-extension-browser` | ✅ 0.21.0 · `windows` | ✅ 0.43.0 · no CI (P) |
| Child-frame login | ✅ 0.32.0 (ext 0.4.0) · `linux-extension-browser` | ✅ 0.32.0 · `windows` | ✅ 0.43.0 · no CI (P) |
| notify-page (identity) | ✅ 0.41.0 (ext 0.9.0) · `linux-extension-browser` | ✅ 0.41.0 · `windows` | ✅ 0.43.0 · no CI (P) |
| Secret read, top document | ✅ 0.32.0 (ext 0.4.0) · `linux-extension-browser` | ✅ 0.32.0 · `windows` | ✅ 0.43.0 · no CI (P) |
| Secret read, child frame | ⛔ (O) | ⛔ (O) | ⛔ (O) |
| `capture-totp`, text key (top document) | ✅ 0.35.0 (ext 0.6.0 for grouped keys) · `linux-extension-browser` | ✅ 0.35.0 · `windows` | ✅ 0.43.0 · no CI (P) |
| `capture-totp`, QR code (top document) | ✅ 0.50.1 (ext 0.14.0) · `linux-extension-browser` | ✅ 0.50.1 · `windows` | ✅ 0.50.1 · no CI (P) |
| SMS code | ✅ 0.50.1 (ext 0.13.0) · `linux-extension-browser` | ✅ 0.50.1 · `windows` | ✅ 0.50.1 · no CI (P) |
| Refuses a click-through cover over a field | ◼ (AG) | ◼ (AG) | ◼ (AG) |
| Popup human click | ✅ login and card 0.21.0, TOTP 0.49.0 (ext 0.12.0); address with the identity pin's checks and texted (SMS) code from 0.52.0 (ext 0.15.0) · `linux-extension-browser` (R) | ✅ same · `windows` (S) | ✅ 0.43.0; address and texted code from 0.52.0 · no CI (P) |
| Agent desktop slots | — (U) | — (U) | — (U) |

## Extension route, Firefox

Firefox 153 or newer, with its own host and build (`--browser firefox`). It
runs as a temporary add-on; see [Firefox setup](firefox.md).

| Operation | Linux (Firefox 153 and 161) | Windows (Firefox 161) | macOS (Firefox 161) |
| --- | --- | --- | --- |
| Username, password, login | ✅ 0.47.0 · `firefox-extension-browser` | ✅ 0.47.0 · `firefox-extension-browser` | ✅ 0.47.0 · `firefox-extension-browser` |
| Generated password | ✅ 0.47.0 · `firefox-extension-browser` | ✅ 0.47.0 · `firefox-extension-browser` | ✅ 0.47.0 · `firefox-extension-browser` |
| TOTP (main and child frame) | ✅ 0.47.0 · `firefox-extension-browser` | ✅ 0.47.0 · `firefox-extension-browser` | ✅ 0.47.0 · `firefox-extension-browser` |
| Card (clipped drawers: ext 0.11.1) | ✅ 0.47.0 · `firefox-extension-browser` | ✅ 0.47.0 · `firefox-extension-browser` | ✅ 0.47.0 · `firefox-extension-browser` |
| Card processor iframes (Adyen, Computop, Stripe, Stripe Card Element) | ✅ 0.47.0 · `firefox-extension-browser` | ✅ 0.47.0 · `firefox-extension-browser` | ✅ 0.47.0 · `firefox-extension-browser` |
| Identity, notify-page | ✅ 0.47.0 · `firefox-extension-browser` | ✅ 0.47.0 · `firefox-extension-browser` | ✅ 0.47.0 · `firefox-extension-browser` |
| Child-frame login | ✅ 0.47.0 · `firefox-extension-browser` | ✅ 0.47.0 · `firefox-extension-browser` | ✅ 0.47.0 · `firefox-extension-browser` |
| Secret read, top document | ✅ 0.47.0 · `firefox-extension-browser` | ✅ 0.47.0 · `firefox-extension-browser` | ✅ 0.47.0 · `firefox-extension-browser` |
| Secret read, child frame | ⛔ (O) | ⛔ (O) | ⛔ (O) |
| `capture-totp`, text key | ✅ 0.47.0 · `firefox-extension-browser` | ✅ 0.47.0 · `firefox-extension-browser` | ✅ 0.47.0 · `firefox-extension-browser` |
| `capture-totp`, QR code (top document) | ✅ from 0.52.0 (ext 0.14.2) · `firefox-extension-browser` (V) | ✅ from 0.52.0 · `firefox-extension-browser` (V) | ✅ from 0.52.0 · `firefox-extension-browser` (V) |
| SMS code | ✅ 0.50.1 (ext 0.13.0) · `firefox-extension-browser` | ✅ 0.50.1 · `firefox-extension-browser` | ✅ 0.50.1 · `firefox-extension-browser` |
| Refuses a click-through cover over a field | ◼ (AG) | ◼ (AG) | ◼ (AG) |
| Popup human click | ✅ login 0.47.0; address and texted (SMS) code from 0.52.0 (ext 0.15.0) · `firefox-extension-browser`; TOTP, card: no Firefox test (R) | ✅ login, address, texted code · `firefox-extension-browser` | ✅ login, address, texted code · `firefox-extension-browser` |
| Agent desktop slots | — (U) | — (U) | — (U) |

## Android route (`akdbx android`)

The columns are the computer that runs the broker. The device is an Android
device or emulator reached through adb. Chrome pages use Chrome's DevTools
socket; app fields use the akdbx accessibility helper. Check
`android_fill_modes` and `android_managed_emulators` in `status`. A macOS
broker takes attached devices only (after 0.50.1).

| Operation | Linux host (X11 or Wayland) | Windows host | macOS host |
| --- | --- | --- | --- |
| Username, password, login | ✅ 0.36.0 · contract test (`linux`); Chrome pages: real emulator test (X) | ✅ 0.50.1 · no CI (T) | ✅ after 0.50.1 · contract test (`macos-broker`) (AE) |
| Generated password | ✅ 0.50.1 · contract test (`linux`); Chrome pages: real emulator test, also right after a cold boot (X) (Y) | ✅ 0.50.1 · no CI (T) | ✅ after 0.50.1 · no CI (AE) |
| TOTP | ✅ 0.36.0 · contract test (`linux`); Chrome pages: real emulator test (X) | ✅ 0.50.1 · no CI (T) | ✅ after 0.50.1 · contract test (`macos-broker`) (AE) |
| Card, identity | ✅ 0.50.1 · contract test (`linux`); Chrome pages: real emulator test (X) | ✅ 0.50.1 · no CI (T) | ✅ after 0.50.1 · contract test (`macos-broker`) (AE) |
| Card processor iframes, child-frame login | ✗ (Z) | ✗ (Z) | ✗ (Z) |
| notify-page (identity) | ✅ 0.50.1 Chrome pages · real emulator test (X); ⛔ app fields (K) | ✅ 0.50.1 · no CI (T); ⛔ app fields (K) | ✅ after 0.50.1 Chrome pages · no CI (AE); ⛔ app fields (K) |
| Secret read, `capture-totp` text key | ✅ 0.50.1 Chrome pages · real emulator test (X) (AF) | ✅ 0.50.1 Chrome pages · no CI (T) | ✅ after 0.50.1 Chrome pages · no CI (AE) (AF) |
| `capture-totp`, QR code | ✗ not built | ✗ not built | ✗ not built |
| SMS code | ✅ 0.50.1 · contract test (`linux`); Chrome pages: real emulator test (X) | ✅ 0.50.1 · no CI (T) | ✅ after 0.50.1 · contract test (`macos-broker`) (AE) |
| Fields in an app's own web view | ◼ (AB) | ◼ (AB) | ◼ (AB) |
| Managed on-demand emulator (`android setup --create`) | ✅ 0.37.0 (x86-64, KVM, systemd 254+) | ✗ Linux only (AA) | ✗ Linux only (AA) |
| Popup human click, agent desktop slots | — | — | — |

## Platform services

| Feature | Linux | Windows | macOS |
| --- | --- | --- | --- |
| Guided setup (`akdbx setup`) | ✅ 0.27.0 | ✅ 0.27.0 | ✅ 0.49.0 · `macos-broker`; it does not set up the CDP route (AC) |
| Start at login | systemd user unit | logon task | LaunchAgent, 0.49.0 |
| Desktop lock locks the vault | logind; Hyprland | session lock and suspend | screen lock and sleep, 0.49.0 |
| Loopback HTTPS private page | ✅ 0.23.0 | ✅ 0.17.0 | ✅ 0.43.0 |
| Unlock with a key file chosen on the page, or a YubiKey challenge-response (AD) | ✅ 0.50.1 · `linux` | ✅ 0.50.1 · `windows` (vault store only) | ✅ 0.50.1 · no CI |
| Tailscale Serve to a Unix socket | ✅ | ◼ Tailscale Serve cannot proxy to a Unix socket on Windows | ✅ 0.43.0 |
| akdbx relay | ✅ 0.26.0 | ✅ 0.26.0 | ✅ 0.43.0 · `macos-broker` |
| Secret sinks (`deliver-secret`) | ✅ 0.20.0 files; root helper for other accounts | ✅ 0.48.0 private named pipe | ✅ same-user files · no CI; ◼ no root helper (needs systemd and Linux peer credentials) |
| Private authenticator QR importer | ✅ 0.12.0 Chromium, 0.48.0 Firefox · `linux-extension-browser`, `firefox-extension-browser` | ✅ 0.22.0 Chromium, 0.48.0 Firefox · `windows` (registration and pipe) | ✅ 0.48.0 · `macos-broker` (registration and socket) |
| Merge and snapshot admission | ✅ 0.8.0 | ✅ 0.17.0 | ✅ 0.46.0 |

## Notes

- **A** Refused by design: a browser's address bar shares its page's window,
  so a window pin cannot prove that a password field has focus. Saved and
  generated passwords need a DOM pin, a native field pin or an Android pin.
- **B** Refused by design: card and address values go only to a verified DOM,
  native or Android field, never to key events.
- **C** Inherent: a window pin sends key events; it has nothing to read.
- **D** Inherent: a native Wayland surface has no X window ID, and Wayland has
  no window-directed keyboard input. Use a native field pin for native Wayland
  apps. The broker refuses with a message that says so.
- **E** Inherent: `CGEventPostToPid` directs input to a process, not a field,
  and Secure Event Input blocks synthesized keys. `status` reports
  `target_fill_delivery: "unavailable"` and empty `target_fill_modes`.
- **F** A stock AppKit secure field (`NSSecureTextField`) has no character
  count, visible range or text for a range. Its Accessibility value has one
  mask character (U+F79A, or U+200B when the field shows no bullets) for each
  UTF-16 unit. The broker accepts only a wholly masked value and compares its
  length with the written text; a stock field never gives the password back.
  A field that cuts or rejects the text gives an uncertain result. A secure
  field that already shows text is refused before the write; an empty one that
  shows text after the write gives an uncertain result. On real macOS 15.8 and
  26.7 runners, the masked length matched in every random write (300 of 300 on
  each), with Secure Event Input on. From 0.50.1 to 0.51.0 the broker refused
  these pins.
- **G** `windows` sends a window-pin SMS code to a real Win32 Edit control over
  the same `win32-char-v1` transport. Usernames and TOTP have contract tests
  with simulated windows only; a real-app check is the manual
  [desktop acceptance check](windows.md#desktop-acceptance-check-for-window-pins).
- **H** No test sends an SMS code to a real X11 window. `tests/test_sms.py`
  tests the window route with a simulated window, and no CI job runs that
  test. The `linux` job fills through a simulated window token in the
  cross-route test of `tests/test_android_route.py`.
- **I** Not built: slot window pins find the slot Chrome's X display, and
  Windows has none. The broker refuses with `browser slot window pins need
  Linux X11`.
- **J** Win32 Edit and WinForms TextBox use Win32 messages; WPF TextBox and
  PasswordBox use UI Automation (`native_field_windows_uia: true`). UWP, WinUI
  and Qt on Windows are not proven, and the broker refuses other UI
  Automation providers.
- **K** Refused: a native control or an Android app field has no page to
  notify; `--notify-page` refuses before delivery. From 0.52.0 the refusal
  names the option (`--notify-page needs a web page, and an app field has
  none`); before, it was the generic `target unavailable` refusal.
- **L** Refused by design: the caller asserts the service URL, and the OS
  cannot verify that a website at that origin showed the setup key. The
  broker consumes the pin and saves nothing.
- **M** The broker accepts code pins on WinForms and WPF controls, but no test
  sends an SMS code to them.
- **N** The `macos-broker` CDP tests fill identities (also with `--notify-page`), a Stripe Card Element
  frame and every login mode. No macOS test fills a card field on the
  merchant page itself; it uses the same transport as the Stripe frame.
- **O** Refused by design: the extension cannot map a child frame's text
  position exactly through every parent document (padding, transforms). Use
  the CDP route for a secret or setup key in a same-site child frame.
- **P** The `macos-broker` job runs the extension protocol tests
  (`test_extension_route.py`) but no real Chromium browser with the built
  extension. Google Chrome 137 and later ignore `--load-extension`. On macOS,
  real-browser extension fills are proven in Firefox only.
- **Q** The real-browser generated-password test runs in Firefox. In Chromium,
  `fill-generated` uses the same password pin that the login tests prove.
- **R** From fill extension 0.15.0 the popup fills an address with the agent
  identity pin's checks on each field (autocomplete grammar, input types,
  style guard, hit test through same-origin frames, one section and address
  part) and the events of `--notify-page`; it has no `--field-purpose` and no
  phone `--format`. It also lists the SMS inbox's texts for a focused
  top-page one-time-code field and fills the chosen code with the agent code
  pin's checks, once. akdbx cannot tell which site sent a text, so the user
  picks it by its sender and masked preview.
  Real-browser tests: Chrome for Testing and headless Edge
  (`test_extension_browser.py`), Firefox 153 and 161 on Linux, Windows and
  macOS (`test_firefox_browser.py`).
- **S** Fill extension 0.14.1 fixed a race in which a popup TOTP code reached
  the page before the closing popup gave the focus back to the field. The
  Linux job forces that order and proves the fix. The Windows job runs
  headless Edge, where the page keeps its focus while the popup is open, so
  the race cannot happen there: the fix is not proven in a headed Windows
  browser. If a popup TOTP fill reports `field changed or hidden; nothing
  filled`, focus the field and choose the account again.
- **T** `akdbx android setup` refuses on Windows, so the operator writes the
  device file by hand (private DACL and trusted folders required; 0.50.1 added
  that check). A real Windows host refused an unsafe device file, but no test
  fills a device from a Windows broker.
- **U** The extension runs in the user's own browser. `--browser-slot` applies
  only to the CDP route, and the broker refuses it with `--route extension`.
- **V** A Firefox content script with `<all_urls>` host access (fill extension
  0.5.0 to 0.15.x could ask for it, and Firefox keeps the grant through an
  update) reads another origin's pixels from a tainted canvas,
  also for an `<img>` whose URL on the page's origin redirects to another
  origin. Fill extension 0.14.2 decodes only a canvas that passes
  `convertToBlob`'s origin-clean check, which that access does not skip
  (`extension_qr_capture_firefox_min_version`). The broker refuses a QR read
  pin from an older Firefox build with `target unavailable`. Real Firefox
  tests capture a same-origin `<img>`, `<canvas>` and inline `<svg>` through
  `commit-totp`. They also show that the pin refuses another origin's image
  (with or without CORS), the redirect and a tainted canvas, with and without
  `<all_urls>`. Two codes or a changed element refuse, and so does a code that
  is not TOTP. From fill extension 0.15.1 (and on the CDP route from 0.52.0),
  an `<img>` that is not a `data:` URL and loads in CORS mode refuses on every
  route. After a redirect to another origin that allows the read, its canvas
  stays origin-clean. A canvas
  tainted after the pin refuses even with identical pixels.
- **W** Safari needs a containing Apple app, a Safari native-messaging adapter
  and Apple signing. A permanently installed (signed) Firefox add-on also
  needs the owner's Mozilla AMO credentials; until then Firefox uses a
  temporary add-on.
- **X** CI checks the Android route with a simulated device. From 0.52.0,
  `tests/test_android_emulator.py` also proves every Chrome-page operation
  on a real Android 15 Google Play emulator (Chrome 124) through the real
  broker, CLI and helper: login, generated password through commit, TOTP,
  card, identity with and without `--notify-page`, SMS code, `capture-secret`
  through save, text-key `capture-totp` through `commit-totp`, and their
  refusals. It needs KVM, so it runs by hand on a Linux host and is not in
  CI. App fields have no real-device test.
- **Y** Fixed from 0.52.0. Right after a cold boot, the helper's typed check
  takes 5 to 10 seconds (about 1 second warm), and `fill-generated` waited
  only 5 seconds for the broker's answer. Each fill then ended with
  `autofill outcome uncertain: connection lost after request` (6 of 6 cold
  boots before the fix), and the broker stopped before the value because
  its caller had left. With Android devices configured, the fill commands
  now wait up to 60 seconds, as `android fill` does; 10 of 10 cold boots
  filled and saved. Login, password, generated-password and TOTP pins fill
  right after a cold boot because the start deadline bounds only the first
  key. Card, identity, SMS-code and read pins must finish the whole check
  within the 4-second start deadline, so right after a cold boot they may
  be refused `not-started` with nothing filled or read (3 of 5 identity
  fills in the lab); a new pin 10 seconds later filled each time.
- **Z** Not built: Android fields in frames are refused.
- **AA** Not built: the managed emulator uses systemd user units and KVM.
  On macOS and Windows, setup and `android wake` refuse it, and `status`
  reports `android_managed_emulators: false`.
- **AB** Inherent: the site of a page inside an app's web view cannot be read,
  so the broker refuses those fields. Chrome tabs and Custom Tabs work.
- **AC** `akdbx setup --cdp-profile` refuses on macOS. To use CDP there, start
  the broker yourself with `--password-browser-profile` as
  [macOS Chromium CDP](macos.md#chromium-cdp) describes.
- **AD** The unlock page and, while the vault is locked, the extension pairing
  page take a key file or a hardware key response on every access route
  (loopback, Tailscale, relay). The master password is still required. The
  key file field is hidden when the broker runs with `--keyfile`. The
  hardware key is KeePassXC's YubiKey HMAC-SHA1 challenge-response for a
  KDBX 4 vault with an Argon2 KDF; the page shows a `ykman otp calculate`
  command, and the user enters its response. The `linux` job tests the whole
  page flow; the `windows` job tests only the Windows vault store with both
  keys. See [Key file and hardware key](private-pages.md#key-file-and-hardware-key).
- **AE** Attach mode only (`android setup --attach`, or a device file written
  by hand). The `macos-broker` job proves the host side on macOS: the kernel
  owner check of the loopback adb server and of the DevTools forward,
  `android setup --attach` against a stand-in adb, the route suite with a
  simulated device, and a stand-in owned by another account (`_www`) that
  receives zero bytes. Inherent: no device or emulator runs in that CI,
  because GitHub's arm64 macOS runners have no nested virtualization. A macOS
  broker with a real device or emulator was not tested.
- **AF** The `linux` and `macos-broker` jobs test the Android read pin and
  its refusals (an unverified DevTools peer, a QR capture, covered text)
  with a simulated device. From 0.52.0 the real emulator test (X) completes
  `capture-secret` from pin through save and a text-key `capture-totp`
  through the pending code and `commit-totp`, with the CDP route's refusals:
  another site, a used pin, a changed value or key, covered text, an
  editable field, prose. The broker refuses a read pin on an app field, so
  reads work on Chrome pages only.
- **AG** The CDP and extension routes refuse a hidden, transparent,
  zero-size, off-screen, inert or clipped field and a cover that takes pointer
  events (`linux-extension-browser`, `card-safety`). A
  click-through cover (`pointer-events: none`, `inert`, a popover
  `::backdrop`) is not seen by the DOM hit test. The CDP route's native hit
  test (`DOM.getNodeForLocation`) refuses one at the field centre for card,
  address and code fields; `card-safety` tests all three kinds of cover on a
  card field and `pointer-events: none` on a code field. An extension has no
  browser-native hit test, so the extension route cannot see one. Fill
  extension 0.5.0 to 0.15.x had an opt-in pixel check for covers; after 0.52.0
  it is removed, because a page could beat it and the page gets the value
  anyway. A read pin uses the DOM hit test on both routes. See
  [Visibility checks](../README.md#visibility-checks-what-they-stop).
