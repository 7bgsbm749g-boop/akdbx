"""Shared private portal presentation. No remote assets or secret-reading scripts."""
from __future__ import annotations

import base64
import hashlib
import html


STYLE = r"""
:root {
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  color: #fff; background: #030303; color-scheme: dark;
  font-synthesis: none; -webkit-font-smoothing: antialiased;
  --ease: cubic-bezier(.22, 1, .36, 1);
}
* { box-sizing: border-box; }
body { margin: 0; min-width: 280px; }
button, input, select, textarea { font: inherit; }
button { -webkit-tap-highlight-color: transparent; touch-action: manipulation; }
::selection { background: #ffffff30; color: #fff; }
.atmosphere { position: fixed; inset: 0; overflow: hidden; pointer-events: none; isolation: isolate; }
.grain { position: absolute; inset: 0; width: 100%; height: 100%; opacity: .13; }
.light { position: absolute; border-radius: 50%; filter: blur(60px); }
.light-one { width: 700px; height: 700px; left: calc(50% - 620px); top: -330px; background: radial-gradient(ellipse, #ffffff24 0%, #ffffff0a 40%, transparent 68%); }
.light-two { width: 720px; height: 900px; right: calc(50% - 690px); bottom: -470px; background: radial-gradient(ellipse, #ffffff1c, transparent 68%); }
.light-line { position: absolute; width: 1px; height: 85vh; top: -200px; left: calc(50% - 110px); transform: rotate(38deg); background: linear-gradient(transparent, #ffffff12 45%, transparent); box-shadow: 0 0 80px 18px #ffffff04; }
main {
  position: relative; z-index: 1; width: min(100%, 484px); min-height: 100svh;
  margin: auto; padding: 60px 24px 32px;
  padding-top: max(60px, env(safe-area-inset-top));
  padding-bottom: calc(32px + env(safe-area-inset-bottom));
  display: flex; flex-direction: column; justify-content: center;
}
.sheet {
  position: relative; width: 100%; padding: 24px; border-radius: 26px;
  border: 1px solid #ffffff18; border-top-color: #ffffff32;
  background: linear-gradient(145deg, #ffffff0a, #ffffff01 38%, #ffffff04), #080808a8;
  -webkit-backdrop-filter: blur(30px); backdrop-filter: blur(30px);
  box-shadow: 0 36px 80px #0008, 0 4px 16px #0007, inset 0 1px 0 #ffffff07;
}
.sheet::before { content: ""; position: absolute; height: 1px; top: -1px; left: 18%; right: 18%; background: linear-gradient(90deg, transparent, #ffffff36, transparent); }
h1 { margin: 0 0 18px; font-size: 18px; line-height: 1.4; font-weight: 450; letter-spacing: -.4px; overflow-wrap: anywhere; }
p { color: #ffffffb3; font-size: 13px; line-height: 1.65; margin: 0 0 18px; overflow-wrap: anywhere; }
p:last-child { margin-bottom: 0; }
strong { color: #fff; font-weight: 500; }
form { display: grid; grid-template-columns: minmax(0, 1fr); gap: 12px; }
.sheet > form + p { margin-top: 18px; }
.field, label:has(> input[type=file]), label:has(> #manual) {
  position: relative; min-width: 0; padding: 13px 16px 12px;
  border: 1px solid #ffffff1a; border-top-color: #ffffff20; border-radius: 14px;
  background: linear-gradient(135deg, #ffffff04, transparent 55%), #00000038;
  box-shadow: inset 0 1px 0 #ffffff03;
}
label { display: block; color: #ffffffb3; font-size: 11px; line-height: 1.5; letter-spacing: .12px; overflow-wrap: anywhere; }
.field label { margin-bottom: 5px; }
.field:focus-within, label:has(> input:focus-visible) { border-color: #ffffff5c; background-color: #ffffff04; box-shadow: 0 0 0 3px #ffffff04, inset 0 1px 0 #ffffff06; }
.field:focus-within label { color: #fff; }
input:not([type=checkbox]):not([type=radio]):not([type=file]):not([type=hidden]), select, textarea {
  width: 100%; min-width: 0; padding: 0; border: 0; outline: 0; border-radius: 0;
  background: transparent; color: #fff; font-size: 16px; line-height: 1.5; letter-spacing: -.2px;
}
input::placeholder, textarea::placeholder { color: #ffffff80; opacity: 1; }
input:disabled, select:disabled, textarea:disabled { opacity: .5; }
input:-webkit-autofill { -webkit-text-fill-color: #fff; -webkit-box-shadow: 0 0 0 1000px #111 inset; caret-color: #fff; border-radius: 3px; }
input[type=file] { display: block; width: 100%; min-width: 0; margin-top: 8px; color: #ffffffa6; font-size: 12px; }
input[type=file]::file-selector-button { font: inherit; color: #fff; background: #ffffff08; border: 1px solid #ffffff24; border-radius: 6px; padding: 6px 9px; margin-right: 10px; }
label:has(> #manual) input { display: block; margin-top: 5px; }
label:has(> input[type=checkbox]), label:has(> input[type=radio]) {
  display: flex; align-items: flex-start; gap: 10px; color: #ffffffb3; font-size: 12px; line-height: 1.6; padding: 4px 1px; cursor: pointer;
}
input[type=checkbox], input[type=radio] { flex-shrink: 0; width: 17px; height: 17px; margin: 1px 0 0; accent-color: #fff; cursor: pointer; }
.secret-control { position: relative; padding-right: 40px; }
button.password-toggle {
  position: absolute; right: -8px; top: 50%; transform: translateY(-50%);
  width: 40px; height: 40px; min-height: 40px; padding: 10px; border: 0; border-radius: 8px;
  background: transparent; color: #ffffffb3; box-shadow: none; justify-content: center;
}
button.password-toggle:active { transform: translateY(-50%); }
button.password-toggle::before, button.password-toggle::after { display: none; }
button.password-toggle:hover { color: #fff; background: #ffffff10; }
.password-toggle svg { width: 20px; height: 20px; fill: none; stroke: currentColor; stroke-width: 1.5; }
.password-toggle .eye-slash { display: none; }
.password-toggle[aria-pressed=true] .eye-slash { display: block; }
input:focus-visible, a:focus-visible { outline: 1px solid #fff; outline-offset: 4px; }
.field input:focus-visible { outline: 0; }
button {
  position: relative; overflow: hidden; width: 100%; display: flex; justify-content: space-between; align-items: center; gap: 12px;
  color: #fff; padding: 16px 18px; min-height: 56px; border-radius: 13px; font-size: 13px; font-weight: 500; letter-spacing: -.1px; cursor: pointer;
  border: 1px solid #ffffff32; border-top-color: #ffffff52;
  background: linear-gradient(165deg, #ffffff16, #ffffff06 52%, #ffffff0a), #08080880;
  box-shadow: inset 0 1px 0 #ffffff07, 0 6px 16px #0005;
}
button::before { content: ""; position: absolute; inset: 0; background: linear-gradient(110deg, transparent 20%, #ffffff0c 46%, transparent 70%); transform: translateX(-110%); pointer-events: none; }
button::after { content: ""; flex-shrink: 0; width: 8px; height: 8px; border-top: 1px solid currentColor; border-right: 1px solid currentColor; transform: rotate(45deg); }
button:hover { border-color: #ffffff63; background-color: #ffffff05; box-shadow: 0 0 30px #ffffff05, inset 0 1px 0 #ffffff16; }
button:active { transform: scale(.985); }
button:focus-visible { outline: 1px solid #fff; outline-offset: 4px; }
button[type=button] { border-color: #ffffff20; background: #ffffff03; box-shadow: none; color: #ffffffb3; }
button:disabled { cursor: default; opacity: .4; }
.unlock-submit { isolation: isolate; }
.unlock-submit .button-label { position: relative; z-index: 1; }
.unlock-submit.is-pending, .unlock-submit.is-pending:active {
  transform: translateY(1px); opacity: 1; cursor: wait; border-color: #ffffff70;
  background-color: #ffffff12; box-shadow: inset 0 3px 9px #000a, inset 0 1px 0 #ffffff08;
}
.unlock-submit.is-pending::before, .unlock-submit.is-pending::after { display: none; }
.unlock-progress { position: absolute; inset: 0; pointer-events: none; background: #ffffff0b; }
.unlock-progress::before {
  content: ""; position: absolute; inset: 0; width: 40%;
  background: linear-gradient(90deg, transparent, #ffffff38, transparent);
}
[hidden] { display: none !important; }
.unlock-status.is-error {
  position: static; width: auto; height: auto; margin: 18px 0 0 !important;
  overflow: visible; clip-path: none; white-space: normal;
}
.unlock-status {
  position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px !important;
  overflow: hidden; clip-path: inset(50%); white-space: nowrap;
}
a { color: #ffffffd9; text-underline-offset: 4px; text-decoration-color: #ffffff52; overflow-wrap: anywhere; }
a:hover { color: #fff; text-decoration-color: #fff; }
dl { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: 6px 14px; margin: 0 0 20px; padding: 0 0 18px; border-bottom: 1px solid #ffffff18; font-size: 12px; line-height: 1.6; }
dt { color: #ffffffa6; text-transform: capitalize; }
dd { color: #fff; margin: 0; overflow-wrap: anywhere; }
.error { color: #fff; border-left: 1px solid #ffffff70; padding-left: 12px; }
#message:empty { display: none; }
@media (min-width: 700px) { main { padding-top: 80px; padding-bottom: 56px; } .sheet { padding: 30px; } }
@media (max-width: 360px) { main { padding-left: 16px; padding-right: 16px; } .sheet { padding: 20px; } .field { padding-left: 13px; padding-right: 13px; } dl { grid-template-columns: minmax(0, 1fr); gap: 2px; } dd { margin-bottom: 6px; } }
@media (prefers-reduced-motion: no-preference) {
  .light-one { animation: drift-one 24s ease-in-out infinite alternate; }
  .light-two { animation: drift-two 30s ease-in-out infinite alternate; }
  .sheet { animation: enter .8s var(--ease) both; }
  .field { animation: reveal .7s var(--ease) both; }
  .field:nth-of-type(1) { animation-delay: .08s; } .field:nth-of-type(2) { animation-delay: .12s; }
  .field:nth-of-type(3) { animation-delay: .16s; } .field:nth-of-type(4) { animation-delay: .20s; }
  .field:nth-of-type(5) { animation-delay: .24s; }
  .field, label, button, a { transition: border-color .3s, color .3s, background-color .3s, box-shadow .3s, transform .35s var(--ease), opacity .25s; }
  button:not([type=button])::before { animation: glint 9s ease-in-out 2s infinite; }
  .unlock-submit.is-pending { animation: unlock-press .16s ease-out; }
  .unlock-submit.is-pending .unlock-progress::before { animation: unlock-loading 1.3s ease-in-out infinite; }
  @keyframes unlock-press { from { transform: translateY(0); } to { transform: translateY(1px); } }
  @keyframes unlock-loading { from { transform: translateX(-100%); } to { transform: translateX(350%); } }
  @keyframes enter { from { opacity: 0; transform: translateY(16px) scale(.985); } to { opacity: 1; transform: none; } }
  @keyframes reveal { from { opacity: 0; transform: translateY(9px); } to { opacity: 1; transform: none; } }
  @keyframes drift-one { from { transform: translate3d(-50px, 0, 0); opacity: .7; } to { transform: translate3d(100px, 140px, 0); opacity: 1; } }
  @keyframes drift-two { from { transform: translate3d(0, 20px, 0); } to { transform: translate3d(-100px, -150px, 0); } }
  @keyframes glint { 0%, 70%, 100% { transform: translateX(-110%); } 87% { transform: translateX(110%); } }
}
"""


SCRIPT = r""""use strict";
(() => {
  function concealPasswords() {
    document.querySelectorAll("[data-password-toggle]").forEach(button => {
      const input = document.getElementById(button.getAttribute("aria-controls"));
      input.type = "password";
      button.setAttribute("aria-pressed", "false");
    });
  }
  document.addEventListener("click", event => {
    const button = event.target.closest("[data-password-toggle]");
    if (!button) return;
    const input = document.getElementById(button.getAttribute("aria-controls"));
    const visible = input.type === "password";
    input.type = visible ? "text" : "password";
    button.setAttribute("aria-pressed", String(visible));
  });
  function resetUnlock(form) {
    form.removeAttribute("aria-busy");
    const button = form.querySelector(".unlock-submit");
    button.disabled = false;
    button.classList.remove("is-pending");
    button.querySelector(".button-label").textContent = "Unlock AKDBX";
    button.querySelector(".unlock-progress").hidden = true;
  }
  document.addEventListener("submit", async event => {
    const form = event.target;
    concealPasswords();
    if (!form.matches("[data-unlock-form]")) return;
    event.preventDefault();
    if (form.getAttribute("aria-busy") === "true") return;
    form.closest(".sheet").querySelector("[role=alert]")?.remove();
    form.setAttribute("aria-busy", "true");
    const button = form.querySelector(".unlock-submit");
    button.disabled = true;
    button.classList.add("is-pending");
    button.querySelector(".button-label").textContent = "Unlocking AKDBX…";
    button.querySelector(".unlock-progress").hidden = false;
    const status = document.getElementById("unlock-status");
    status.classList.remove("is-error");
    status.textContent = "Unlocking AKDBX. Please wait.";
    try {
      // Standard form encoding is used only for the authorized POST. No field
      // is inspected, copied to status text, logged, or persisted by this UI.
      const response = await fetch(form.action, {
        method: "POST", body: new URLSearchParams(new FormData(form)),
        credentials: "same-origin", cache: "no-store", redirect: "error"
      });
      if (!response.headers.get("Content-Type")?.startsWith("text/html")) throw new Error();
      const page = new DOMParser().parseFromString(await response.text(), "text/html");
      const sheet = page.querySelector("main > .sheet");
      if (!sheet || !sheet.querySelector("#portal-title")) throw new Error();
      // The same-origin server provides the real success or error page. Scripts
      // stay outside the sheet; only the already escaped presentation is moved.
      document.querySelector("main > .sheet").replaceWith(sheet);
      document.title = page.title;
      const focus = sheet.querySelector("[role=alert]") || sheet.querySelector("#portal-title");
      focus.setAttribute("tabindex", "-1");
      focus.focus();
    } catch {
      status.classList.add("is-error");
      status.textContent = "AKDBX unlock result not confirmed. Check its status before trying again.";
    } finally {
      form.reset();
      resetUnlock(form);
    }
  });
  window.addEventListener("pageshow", () => {
    // A history restore must never resume a previous attempt or infer success.
    concealPasswords();
    document.querySelectorAll("[data-unlock-form]").forEach(form => {
      resetUnlock(form);
      const status = document.getElementById("unlock-status");
      status.classList.remove("is-error");
      status.textContent = "";
    });
  });
})();
"""
SCRIPT_HASH = "'sha256-" + base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode() + "'"


def content_security_policy(*, import_page: bool = False) -> str:
    # Only this exact presentation script is allowed on normal portals. The QR
    # importer additionally uses its existing same-origin vendored scripts.
    scripts = ("'self' " if import_page else "") + SCRIPT_HASH
    policy = ("default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; connect-src 'self'; "
              "frame-ancestors 'none'; base-uri 'none'; script-src " + scripts)
    if import_page:
        policy += "; img-src 'self' blob:"
    return policy


def field(label: str, name: str, *, kind: str = "password",
          autocomplete: str = "off", maxlength: int | None = None,
          required: bool = True, autofocus: bool = False,
          submitted: bool = True) -> str:
    """Keep labels associated with inputs without changing submitted field names."""
    escaped = html.escape(name, quote=True)
    attrs = f' id="{escaped}"'
    if submitted:
        attrs += f' name="{escaped}"'
    attrs += (f' type="{html.escape(kind, quote=True)}"'
              f' autocomplete="{html.escape(autocomplete, quote=True)}"')
    if maxlength is not None:
        attrs += f' maxlength="{maxlength}"'
    if required:
        attrs += ' required'
    if autofocus:
        attrs += ' autofocus'
    control = f'<input{attrs}>'
    if kind == "password":
        # The accessible toggle name stays stable; pressed means visible.
        toggle_name = html.escape('Show ' + label.lower(), quote=True)
        control = (f'<div class="secret-control">{control}'
                   f'<button type="button" class="password-toggle" data-password-toggle'
                   f' aria-controls="{escaped}" aria-label="{toggle_name}" aria-pressed="false">'
                   '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">'
                   '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/>'
                   '<circle cx="12" cy="12" r="3"/>'
                   '<path class="eye-slash" d="m3 3 18 18"/></svg></button></div>')
    return (f'<div class="field"><label for="{escaped}">{html.escape(label)}</label>'
            f'{control}</div>')


def render(title: str, body: str) -> bytes:
    """Wrap server-generated, already escaped form markup in the shared shell."""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="referrer" content="same-origin"><meta name="color-scheme" content="dark">
<title>{html.escape('AKDBX: ' + title)}</title><style>{STYLE}</style></head>
<body><div class="atmosphere" aria-hidden="true"><div class="light light-one"></div>
<div class="light light-two"></div><div class="light-line"></div>
<svg class="grain" xmlns="http://www.w3.org/2000/svg"><filter id="portal-grain">
<feTurbulence type="fractalNoise" baseFrequency=".95" numOctaves="3" stitchTiles="stitch"/>
</filter><rect width="100%" height="100%" filter="url(#portal-grain)" opacity=".16"/></svg></div>
<main><section class="sheet" aria-labelledby="portal-title"><h1 id="portal-title">{html.escape(title)}</h1>
{body}</section></main><script>{SCRIPT}</script></body></html>""".encode("utf-8")
