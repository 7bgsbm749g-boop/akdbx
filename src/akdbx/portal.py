"""Shared private portal presentation. No remote assets or secret-reading scripts."""
from __future__ import annotations

import base64
import hashlib
import html
import json

from .cards import CSC_LENGTHS, LENGTHS, MESSAGES


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
/* Windows and Linux draw the open list with system colours; white option text
   on a white list hides every option except the highlighted one. */
select { color-scheme: dark; }
select option { background-color: #161616; color: #fff; }
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
.portal-submit { isolation: isolate; }
.portal-submit .button-label { position: relative; z-index: 1; }
.portal-submit.is-pending, .portal-submit.is-pending:active {
  transform: translateY(1px); opacity: 1; cursor: wait; border-color: #ffffff70;
  background-color: #ffffff12; box-shadow: inset 0 3px 9px #000a, inset 0 1px 0 #ffffff08;
}
.portal-submit.is-pending::before, .portal-submit.is-pending::after { display: none; }
.portal-submit.is-done, .portal-submit.is-error { opacity: 1; cursor: default; box-shadow: none; }
.portal-submit.is-done { border-color: #ffffff70; background-color: #ffffff12; }
.portal-submit.is-done::after { width: 5px; height: 10px; border-top: 0; border-bottom: 1px solid currentColor; transform: translateY(-2px) rotate(45deg); }
.portal-submit.is-error { border-style: dashed; border-color: #ffffff52; background: #ffffff03; }
.portal-submit.is-error::after, .portal-submit.is-done::before, .portal-submit.is-error::before { display: none; }
.portal-progress { position: absolute; inset: 0; pointer-events: none; background: #ffffff0b; }
.portal-progress::before {
  content: ""; position: absolute; inset: 0; width: 40%;
  background: linear-gradient(90deg, transparent, #ffffff38, transparent);
}
[hidden] { display: none !important; }
.setup-steps { padding-left: 22px; margin: 0 0 18px; }
.setup-steps li + li { margin-top: 14px; }
.wizard-count { margin: 0 0 8px !important; color: #fff; font-size: 20px; font-weight: 500; letter-spacing: -.4px; line-height: 1.3; }
.wizard-count.is-label { margin-bottom: 10px !important; font-size: 14px; letter-spacing: -.1px; }
.wizard.is-wizard .setup-steps { list-style: none; padding: 0; margin: 0; }
.wizard.is-wizard .setup-steps li { color: #ffffffd9; font-size: 16px; line-height: 1.6; }
.wizard.is-wizard .setup-steps li + li { margin-top: 0; }
.wizard.is-wizard .copy-field { margin-top: 18px; }
.variant-field { margin-top: 0; }
/* The step heading already names the list; the label stays for screen readers. */
.wizard.is-wizard .variant-field label { position: absolute; width: 1px; height: 1px; margin: 0; overflow: hidden; clip-path: inset(50%); white-space: nowrap; }
.variant-field .field-hint { margin: 6px 0 0; }
.wizard-nav { display: flex; gap: 10px; margin-top: 22px; }
.wizard-nav button { flex: 1; min-height: 52px; }
.wizard-nav button.wizard-back { flex-direction: row-reverse; justify-content: flex-end; }
.wizard-nav button.wizard-back::after { transform: rotate(-135deg); }
.wizard-nav button.wizard-next, .wizard-done button.wizard-next {
  color: #fff; border-color: #ffffff32; border-top-color: #ffffff52;
  background: linear-gradient(165deg, #ffffff16, #ffffff06 52%, #ffffff0a), #08080880;
  box-shadow: inset 0 1px 0 #ffffff07, 0 6px 16px #0005;
}
.wizard-nav button.wizard-skip { flex-direction: row; }
.sms-test {
  display: flex; align-items: flex-start; gap: 12px; margin-top: 18px; padding: 14px 16px;
  border: 1px solid #ffffff1a; border-radius: 14px; background: #00000038;
}
.sms-test[hidden] { display: none; }
.sms-test-dot { flex-shrink: 0; width: 8px; height: 8px; margin-top: 7px; border-radius: 50%; background: #fff; }
.sms-test-text { margin: 0 !important; color: #ffffffd9; font-size: 14px; line-height: 1.55; }
.sms-test.is-warning { border-color: #ffffff3d; }
.sms-test.is-warning .sms-test-dot { background: transparent; border: 1px solid #fff; }
.wizard.is-done > :not(.wizard-done) { display: none !important; }
.wizard-done { padding: 6px 0 2px; text-align: center; }
.done-mark { width: 64px; height: 64px; fill: none; stroke: #fff; stroke-width: 1.4; stroke-linecap: round; stroke-linejoin: round; }
.wizard.is-skipped .done-mark { display: none; }
.wizard.is-passed .done-mark circle, .wizard.is-passed .done-mark path { stroke-dasharray: 1; stroke-dashoffset: 1; animation: copy-draw .8s cubic-bezier(.65, 0, .35, 1) .1s forwards; }
.wizard-done-title { margin: 14px 0 8px; font-size: 22px; font-weight: 500; letter-spacing: -.4px; outline: 0; }
.wizard-done-text { margin: 0 0 22px !important; font-size: 15px; }
.wizard-done.is-closed .wizard-done-text { margin-bottom: 0 !important; }
.wizard.is-skipped .wizard-done-title, .wizard-done.is-closed .wizard-done-title { margin-top: 0; }
.wizard-done.is-closing .done-mark, .wizard-done.is-closing button.wizard-next { opacity: 0; transition: opacity .2s ease; }
.wizard-done.is-closed .done-mark { display: none; }
.wizard-done-close { margin: 16px 0 0 !important; color: #ffffff8c; font-size: 14px; }
.wizard-done button.wizard-next { min-height: 52px; }
@media (prefers-reduced-motion: no-preference) {
  .sms-test:not(.is-warning) .sms-test-dot { animation: test-pulse 1.4s ease-in-out infinite; }
  @keyframes test-pulse { 50% { opacity: .25; transform: scale(.7); } }
  .wizard-done-close:not([hidden]) { animation: done-fade .35s ease .2s both; }
  @keyframes done-fade { from { opacity: 0; } }
}
@media (prefers-reduced-motion: reduce) {
  .wizard.is-passed .done-mark circle, .wizard.is-passed .done-mark path { animation: none; stroke-dashoffset: 0; }
}
.setup-note { margin: 10px 0 0 !important; color: #ffffff8c; font-size: 12px; line-height: 1.55; }
button.copy-field {
  display: block; text-align: left; min-height: 0; padding: 13px 16px 12px; border: 1px solid #ffffff1a;
  border-top-color: #ffffff20; border-radius: 14px; background: linear-gradient(135deg, #ffffff04, transparent 55%), #00000038;
  box-shadow: inset 0 1px 0 #ffffff03; font-weight: 400; -webkit-user-select: none; user-select: none;
  -webkit-tap-highlight-color: transparent;
}
button.copy-field::before, button.copy-field::after { display: none; }
button.copy-field:active { transform: none; border-color: #ffffff5c; }
.copy-field .copy-label { display: block; margin-bottom: 5px; color: #ffffffb3; font-size: 11px; line-height: 1.5; }
.copy-field .copy-text { -webkit-user-select: text; user-select: text; display: block; color: #fff; font-size: 15px; line-height: 1.5; overflow-wrap: anywhere; }
.copy-done {
  position: absolute; inset: 0; display: none; align-items: center; justify-content: center; gap: 9px;
  border-radius: inherit; background: #0b0b0b; color: #fff; font-size: 17px; font-weight: 500; letter-spacing: -.2px;
}
.copy-done svg { flex-shrink: 0; width: 1.25em; height: 1.25em; fill: none; stroke: #fff; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round; }
.copy-done circle, .copy-done path { stroke-dasharray: 1; stroke-dashoffset: 1; }
.copy-field.is-copied { border-color: #ffffff52; }
.copy-field.is-copied .copy-label, .copy-field.is-copied .copy-text { visibility: hidden; }
/* Drawn once: showing the box again on a later step does not replay it. */
.copy-field.is-drawn .copy-done, .copy-field.is-drawn .copy-done circle, .copy-field.is-drawn .copy-done path { animation: none; stroke-dashoffset: 0; }
.copy-field.is-copied .copy-done { display: flex; animation: copy-fade .18s ease-out; }
.copy-field.is-copied .copy-done circle, .copy-field.is-copied .copy-done path { animation: copy-draw .65s cubic-bezier(.65, 0, .35, 1) .08s forwards; }
@keyframes copy-draw { to { stroke-dashoffset: 0; } }
@keyframes copy-fade { from { opacity: 0; } }
@media (prefers-reduced-motion: reduce) {
  .copy-field.is-copied .copy-done, .copy-field.is-copied .copy-done circle, .copy-field.is-copied .copy-done path { animation: none; stroke-dashoffset: 0; }
}
.portal-status.is-error, .portal-status.is-shown {
  position: static; width: auto; height: auto; margin: 18px 0 0 !important;
  overflow: visible; clip-path: none; white-space: normal;
}
.portal-status.is-error { border-left: 1px solid #ffffff70; padding-left: 12px; color: #fff; }
.portal-status {
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
.field-hint, .field-error { margin: 6px 0 0; font-size: 12px; line-height: 1.5; }
.field-hint { color: #ffffffa6; }
.field-error { color: #fff; }
.field-error::before { content: "! "; }
.field:has([aria-invalid=true]) { border-color: #ffffff8c; border-style: dashed; }
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
  /* Call-to-action buttons share the unlock button's shimmer. */
  button:not([type=button])::before, button.wizard-next::before { animation: glint 9s ease-in-out 2s infinite; }
  .portal-submit.is-pending { animation: unlock-press .16s ease-out; }
  .portal-submit.is-pending .portal-progress::before { animation: unlock-loading 1.3s ease-in-out infinite; }
  @keyframes unlock-press { from { transform: translateY(0); } to { transform: translateY(1px); } }
  @keyframes unlock-loading { from { transform: translateX(-100%); } to { transform: translateX(350%); } }
  @keyframes enter { from { opacity: 0; transform: translateY(16px) scale(.985); } to { opacity: 1; transform: none; } }
  @keyframes reveal { from { opacity: 0; transform: translateY(9px); } to { opacity: 1; transform: none; } }
  @keyframes drift-one { from { transform: translate3d(-50px, 0, 0); opacity: .7; } to { transform: translate3d(100px, 140px, 0); opacity: 1; } }
  @keyframes drift-two { from { transform: translate3d(0, 20px, 0); } to { transform: translate3d(-100px, -150px, 0); } }
  @keyframes glint { 0%, 70%, 100% { transform: translateX(-110%); } 87% { transform: translateX(110%); } }
}
"""


CARD_CHECK = r"""function cardBrand(n) {
    if (/^3[47]/.test(n)) return "amex";
    if (n[0] === "4") return "visa";
    const two = Number(n.slice(0, 2)), four = Number(n.slice(0, 4));
    if (n.length >= 2 && two >= 51 && two <= 55 || n.length >= 4 && four >= 2221 && four <= 2720) return "mastercard";
    return "other";
  }
  function luhn(n) {
    let sum = 0;
    for (let i = 0; i < n.length; i++) {
      let d = Number(n[n.length - 1 - i]);
      if (i % 2) { d *= 2; if (d > 9) d -= 9; }
      sum += d;
    }
    return sum % 10 === 0;
  }
  // The same rules and messages as cards.problems() in the broker.
  function checkCard(card, today) {
    const M = __MESSAGES__, LENGTHS = __LENGTHS__, CSC = __CSC__;
    const errors = {};
    const number = card.number.replace(/[ -]/g, "");
    const digits = /^[0-9]+$/.test(number);
    const brand = digits ? cardBrand(number) : null;
    if (/\p{C}/u.test(card.name + card.number + card.month + card.year + card.csc)) errors.name = M.unsupported;
    else if (!card.name.trim()) errors.name = M.name;
    if (!number) errors.number = M.number_empty;
    else if (!digits) errors.number = M.number_digits;
    else if (!LENGTHS[brand].includes(number.length)) errors.number = M["number_" + brand];
    else if (!luhn(number)) errors.number = M.number_checksum;
    const month = /^(0[1-9]|1[0-2])$/.test(card.month), year = /^20[0-9]{2}$/.test(card.year);
    if (!month) errors.month = M.month;
    if (!year) errors.year = M.year;
    if (month && year && (Number(card.year) < today[0] || Number(card.year) === today[0] && Number(card.month) < today[1])) errors.month = M.expiry;
    if (card.csc && !(/^[0-9]+$/.test(card.csc) && CSC[brand || "other"].includes(card.csc.length))) errors.csc = M["csc_" + (brand || "other")];
    return {brand, errors};
  }""".replace("__MESSAGES__", json.dumps(MESSAGES, sort_keys=True)).replace(
    "__LENGTHS__", json.dumps({k: list(v) for k, v in LENGTHS.items()}, sort_keys=True)).replace(
    "__CSC__", json.dumps({k: list(v) for k, v in CSC_LENGTHS.items()}, sort_keys=True))


SCRIPT = r""""use strict";
(() => {
  """ + CARD_CHECK + r"""
  const CARD_FIELDS = ["name", "number", "month", "year", "csc"];
  const BRAND_NAMES = {visa: "Visa", mastercard: "Mastercard", amex: "American Express", other: "another brand"};
  // Final button state for each save result from the broker.
  const SAVE_RESULTS = {saved: ["Saved", "is-done"], expired: ["Page expired", "is-error"],
    stale: ["Vault changed", "is-error"], cancelled: ["Cancelled", "is-error"], failed: ["Not confirmed", "is-error"]};
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
  // A wizard shows one step of its visible step list at a time: a step
  // count, the step and the URL box on its steps. A page with a version list
  // starts on a step 0 that shows the introduction and that list.
  // Without this script every step stays visible.
  function showStep(wizard, index) {
    const steps = Array.from(wizard.querySelectorAll("ol.setup-steps:not([hidden]) > li"));
    const first = wizard.querySelector("[data-variant-select]") ? -1 : 0;
    const last = steps.length - 1;
    index = Math.max(first, Math.min(index, last));
    wizard.setAttribute("data-step", String(index));
    steps.forEach((step, i) => { step.hidden = i !== index; });
    document.querySelectorAll("[data-wizard-first]").forEach(part => { part.hidden = index !== first; });
    // The page title shows on the first screen only; the step heading replaces it.
    const title = document.getElementById("portal-title");
    if (title) title.hidden = index !== first;
    wizard.querySelectorAll("[data-wizard-url]").forEach(part => { part.hidden = index < 0 || !steps[index].hasAttribute("data-url"); });
    const count = wizard.querySelector(".wizard-count");
    count.textContent = index < 0 ? "Choose your iOS version" : "Step " + (index + 1) + " of " + steps.length;
    count.classList.toggle("is-label", index < 0);
    wizard.querySelector("[data-wizard-back]").hidden = index === first;
    const next = wizard.querySelector("[data-wizard-next]");
    next.hidden = index === last;
    next.querySelector("span").textContent = index < 0 ? "Start" : "Next";
    // The test step waits for the test text and offers to skip the test.
    const testing = index >= 0 && steps[index].hasAttribute("data-test");
    wizard.querySelector("[data-wizard-skip]").hidden = !testing;
    const panel = wizard.querySelector("[data-wizard-test]");
    if (panel) {
      panel.hidden = !testing;
      if (testing) watchTest(wizard, panel); else testRun += 1;
    }
  }
  // The live test asks the broker for the next text (an 8-second wait per
  // request). The answer has only a count and a result, never the text.
  const TEST_RESULTS = {
    "empty": "A text arrived, but it was empty. Check that the text field in the automation uses Message.",
    "no-code-word": "A text arrived, but it has no word such as code. Send: Your test code is 482913",
    "no-code": "A text arrived, but it has no code of 4 to 8 digits. Send: Your test code is 482913",
    "several-codes": "A text arrived, but it has more than one number. Send: Your test code is 482913",
    "expired": "This page has expired. Ask your agent for a new one."
  };
  let testRun = 0;
  async function watchTest(wizard, panel) {
    const run = ++testRun;
    let count = Number(panel.getAttribute("data-count"));
    while (run === testRun) {
      let reply = null;
      try {
        const response = await fetch(panel.getAttribute("data-wait") + "&after=" + count,
          {credentials: "same-origin", cache: "no-store", redirect: "error"});
        if (response.status === 404) reply = {result: "expired"};
        else if (response.ok) reply = await response.json();
      } catch {
        reply = null;
      }
      if (run !== testRun) return;
      if (reply === null) {
        // The phone may pause the page in the background; try again soon.
        await new Promise(resume => setTimeout(resume, 1500));
        continue;
      }
      if (reply.result === "expired") {
        panel.classList.add("is-warning");
        panel.querySelector(".sms-test-text").textContent = TEST_RESULTS.expired;
        return;
      }
      if (reply.count > count) {
        count = reply.count;
        if (reply.result === "code") {
          finish(wizard, true);
          return;
        }
        panel.classList.add("is-warning");
        panel.querySelector(".sms-test-text").textContent = TEST_RESULTS[reply.result] || TEST_RESULTS["no-code"];
      }
    }
  }
  function finish(wizard, passed) {
    testRun += 1;
    const done = wizard.querySelector(".wizard-done");
    wizard.classList.add("is-done", passed ? "is-passed" : "is-skipped");
    done.hidden = false;
    const title = done.querySelector(".wizard-done-title");
    title.textContent = passed ? "Code received" : "Setup finished";
    const text = done.querySelector(".wizard-done-text");
    text.textContent = text.getAttribute(passed ? "data-passed" : "data-skipped");
    title.focus();
    window.scrollTo({top: 0});
  }
  document.addEventListener("click", event => {
    const skip = event.target.closest("[data-wizard-skip]");
    if (skip) finish(skip.closest("[data-wizard]"), false);
    const close = event.target.closest("[data-wizard-close]");
    if (!close) return;
    window.close();
    // A page the user opened from a link cannot close itself: fade out the
    // tick and the button, then ease the card to its new height.
    setTimeout(() => {
      const done = close.closest(".wizard-done");
      const sheet = done.closest(".sheet");
      const calm = matchMedia("(prefers-reduced-motion: reduce)").matches;
      const swap = () => {
        const start = sheet.offsetHeight;
        done.classList.add("is-closed");
        close.hidden = true;
        done.querySelector(".wizard-done-close").hidden = false;
        if (calm) return;
        const end = sheet.offsetHeight;
        sheet.style.height = start + "px";
        void sheet.offsetHeight;
        sheet.style.transition = "height .45s cubic-bezier(.65, 0, .35, 1)";
        sheet.style.height = end + "px";
        const reset = event => {
          if (event.target !== sheet || event.propertyName !== "height") return;
          sheet.removeEventListener("transitionend", reset);
          sheet.style.height = sheet.style.transition = "";
        };
        sheet.addEventListener("transitionend", reset);
      };
      if (calm) return swap();
      done.classList.add("is-closing");
      setTimeout(swap, 200);
    }, 300);
  });
  document.querySelectorAll("[data-wizard]").forEach(wizard => {
    wizard.classList.add("is-wizard");
    wizard.querySelector(".wizard-count").hidden = false;
    wizard.querySelector(".wizard-nav").hidden = false;
    showStep(wizard, -1);
  });
  document.addEventListener("click", event => {
    const button = event.target.closest("[data-wizard-next], [data-wizard-back]");
    if (!button) return;
    const wizard = button.closest("[data-wizard]");
    const step = Number(wizard.getAttribute("data-step"));
    showStep(wizard, button.hasAttribute("data-wizard-next") ? step + 1 : step - 1);
    window.scrollTo({top: 0});
  });
  // A version list shows only the step list of the chosen option. It reads
  // the option's data-show attribute, never an input.
  document.addEventListener("change", event => {
    const list = event.target.closest("[data-variant-select]");
    if (!list) return;
    const chosen = list.selectedOptions[0]?.getAttribute("data-show");
    document.querySelectorAll('[data-variant-group="' + list.getAttribute("data-variant-select") + '"]')
      .forEach(steps => { steps.hidden = steps.getAttribute("data-variant") !== chosen; });
    document.querySelectorAll("[data-wizard]").forEach(wizard => showStep(wizard, -1));
  });
  // A copy box carries its text in data-copy (the SMS webhook URL on its
  // private setup page). No input is read.
  document.addEventListener("click", async event => {
    const box = event.target.closest("[data-copy]");
    if (!box) return;
    const label = box.querySelector(".copy-label");
    let copied = false;
    try {
      await navigator.clipboard.writeText(box.getAttribute("data-copy"));
      copied = true;
    } catch {
      const range = document.createRange();
      range.selectNodeContents(box.querySelector(".copy-text"));
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      try { copied = document.execCommand("copy"); } catch { copied = false; }
    }
    if (copied) {
      // The copied cover stays; another tap copies again and replays it.
      box.classList.remove("is-copied", "is-drawn");
      void box.offsetWidth;
      box.classList.add("is-copied");
      clearTimeout(box.drawTimer);
      box.drawTimer = setTimeout(() => box.classList.add("is-drawn"), 900);
      label.textContent = "Link copied to clipboard";
    } else {
      label.textContent = "Copy failed. Press and hold the link, then tap Copy.";
    }
  });
  function setBusy(form, busy) {
    const button = form.querySelector(".portal-submit");
    if (busy) form.setAttribute("aria-busy", "true");
    else form.removeAttribute("aria-busy");
    button.disabled = busy;
    button.classList.toggle("is-pending", busy);
    button.querySelector(".button-label").textContent = button.getAttribute(busy ? "data-busy-label" : "data-idle-label");
    button.querySelector(".portal-progress").hidden = !busy;
  }
  function setStatus(status, text, kind) {
    status.classList.remove("is-error", "is-shown");
    if (kind) status.classList.add(kind);
    status.textContent = text;
  }
  async function post(form) {
    // Standard form encoding is used only for the authorized same-origin POST.
    const response = await fetch(form.action, {
      method: "POST", body: new URLSearchParams(new FormData(form)),
      credentials: "same-origin", cache: "no-store", redirect: "error"
    });
    if (!response.headers.get("Content-Type")?.startsWith("text/html")) throw new Error();
    return new DOMParser().parseFromString(await response.text(), "text/html");
  }
  function today() {
    const now = new Date();
    return [now.getFullYear(), now.getMonth() + 1];
  }
  function cardFields(form) {
    // The only place card values are read: local checks before the POST.
    // They are never shown, copied to status text, logged or stored.
    const card = {};
    CARD_FIELDS.forEach(name => { card[name] = form.elements.namedItem(name).value; });
    return card;
  }
  function showCardErrors(form, errors, onlyMarked) {
    CARD_FIELDS.forEach(name => {
      const input = form.elements.namedItem(name), note = document.getElementById(name + "-error");
      if (onlyMarked && input.getAttribute("aria-invalid") !== "true") return;
      const message = errors[name] || "";
      note.textContent = message;
      note.hidden = !message;
      if (message) input.setAttribute("aria-invalid", "true");
      else input.removeAttribute("aria-invalid");
    });
  }
  document.addEventListener("input", event => {
    const form = event.target.closest("[data-card-form]");
    if (!form) return;
    const result = checkCard(cardFields(form), today());
    const digits = form.elements.namedItem("number").value.replace(/[ -]/g, "").length;
    document.getElementById("card-brand").textContent =
      result.brand && digits >= 4 ? "Detected brand: " + BRAND_NAMES[result.brand] + "." : "";
    showCardErrors(form, result.errors, true);
  });
  async function save(form) {
    const status = document.getElementById("save-status");
    const card = form.matches("[data-card-form]");
    if (card) {
      const errors = checkCard(cardFields(form), today()).errors;
      showCardErrors(form, errors, false);
      const first = CARD_FIELDS.find(name => errors[name]);
      if (first) {
        setStatus(status, "Check the marked card details.", "is-error");
        form.elements.namedItem(first).focus();
        return;
      }
    }
    // Keep the destination that is sent, even if the user edits it while saving.
    const chosen = ["title", "group"].map(name => form.elements.namedItem(name)).filter(Boolean)
      .map(control => [control, control.value]);
    setBusy(form, true);
    setStatus(status, "Saving. Please wait.", "");
    let result = "", message = "", title = "";
    try {
      const page = await post(form);
      const note = page.querySelector("[data-save-result]");
      if (!note) throw new Error();
      result = note.getAttribute("data-save-result");
      message = Array.from(note.querySelectorAll("p"), line => line.textContent).join(" ");
      title = page.querySelector("#portal-title")?.textContent || "";
    } catch {
      result = "";
    }
    setBusy(form, false);
    concealPasswords();
    if (result === "rejected") {
      setStatus(status, message, "is-error");
      return;
    }
    const final = SAVE_RESULTS[result];
    if (!final) {
      setStatus(status, "Save result not confirmed. Ask for the save status before you try again.", "is-error");
      return;
    }
    // A final result: clear the entered values and stop further submissions.
    // The non-secret title and group keep what was sent.
    form.reset();
    chosen.forEach(([control, text]) => { control.value = text; });
    if (card) {
      showCardErrors(form, {}, false);
      document.getElementById("card-brand").textContent = "";
    }
    form.querySelectorAll("input, select, button").forEach(control => { control.disabled = true; });
    const button = form.querySelector(".portal-submit");
    button.classList.add(final[1]);
    button.querySelector(".button-label").textContent = final[0];
    // The heading and tab title show the result page's Success or Failure.
    if (title) {
      document.getElementById("portal-title").textContent = title;
      document.title = "AKDBX: " + title;
    }
    setStatus(status, message, final[1] === "is-done" ? "is-shown" : "is-error");
  }
  async function unlock(form) {
    form.closest(".sheet").querySelector("[role=alert]")?.remove();
    setBusy(form, true);
    const status = document.getElementById("unlock-status");
    // The pairing page reuses this form and names its own status lines.
    setStatus(status, form.getAttribute("data-wait-text") || "Unlocking AKDBX. Please wait.", "");
    try {
      const page = await post(form);
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
      setStatus(status, form.getAttribute("data-unconfirmed-text") ||
        "AKDBX unlock result not confirmed. Check its status before trying again.", "is-error");
    } finally {
      form.reset();
      setBusy(form, false);
    }
  }
  document.addEventListener("submit", event => {
    const form = event.target;
    concealPasswords();
    const saving = form.matches("[data-save-form]");
    if (!saving && !form.matches("[data-unlock-form]")) return;
    event.preventDefault();
    if (form.getAttribute("aria-busy") === "true") return;
    (saving ? save : unlock)(form);
  });
  window.addEventListener("pageshow", () => {
    // A history restore must never resume a previous attempt or infer success.
    concealPasswords();
    document.querySelectorAll("[data-unlock-form]").forEach(form => {
      setBusy(form, false);
      setStatus(document.getElementById("unlock-status"), "", "");
    });
    document.querySelectorAll("[data-save-form][aria-busy=true]").forEach(form => {
      setBusy(form, false);
      setStatus(document.getElementById("save-status"), "", "");
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
          submitted: bool = True, value: str | None = None,
          inputmode: str | None = None, note: str = "",
          describedby: str | None = None) -> str:
    """Keep labels associated with inputs without changing submitted field names.

    ``value`` prefills non-secret text only. ``note`` is already escaped markup
    placed under the control; ``describedby`` names the ids that describe it.
    """
    escaped = html.escape(name, quote=True)
    attrs = f' id="{escaped}"'
    if submitted:
        attrs += f' name="{escaped}"'
    attrs += (f' type="{html.escape(kind, quote=True)}"'
              f' autocomplete="{html.escape(autocomplete, quote=True)}"')
    if maxlength is not None:
        attrs += f' maxlength="{maxlength}"'
    if value is not None:
        if kind == "password":
            raise ValueError("password fields are never prefilled")
        attrs += f' value="{html.escape(value, quote=True)}"'
    if inputmode is not None:
        attrs += f' inputmode="{html.escape(inputmode, quote=True)}"'
    if describedby is not None:
        attrs += f' aria-describedby="{html.escape(describedby, quote=True)}"'
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
            f'{control}{note}</div>')


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
