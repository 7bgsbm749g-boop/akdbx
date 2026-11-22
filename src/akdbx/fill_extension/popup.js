/* akdbx popup: the user picks one entry; only a real click in this popup fills. */
"use strict";

// A fill starts only from a trusted click with transient user activation.
function userGesture(event, activation) {
  return Boolean(event && event.isTrusted === true && activation && activation.isActive === true);
}

// Links arrive through the native host, so they open only on the origin that the
// service worker trusts (trust.js): the built origin or one the broker's key signed.
const trust = globalThis.akdbxTrust || (typeof require === "function" ? require("./trust.js") : null);
const privateLink = trust.privateLink;

// The extension's own version, so a user can see a stale unpacked copy.
function versionText(manifest) {
  const version = manifest && typeof manifest.version === "string" ? manifest.version : "";
  return /^\d{1,5}\.\d{1,5}\.\d{1,5}$/.test(version) ? "akdbx extension " + version : "akdbx extension";
}

function label(kind, entry) {
  if (kind === "card") return [entry.title, `${entry.brand} •••• ${entry.last_four}`];
  if (kind === "login") return [entry.title, entry.username + (entry.passwordless ? " (no password)" : "")];
  return [entry.title, "address and contact details"];
}

// The trust message, and the reset that only a real click in this popup starts.
function showTrust(state, send) {
  const note = document.getElementById("trust");
  const text = state.trust_error || (state.origin_changed && trust.validOrigin(state.origin) &&
    trust.validOrigin(state.moved_from) ? "The broker signed a move from " + state.moved_from + " to " +
    state.origin + "; this extension now trusts " + state.origin + "." : "");
  note.textContent = typeof text === "string" ? text : "";
  note.hidden = !note.textContent;
  note.className = state.trust_error ? "warning" : "detail";
  if (state.trust_reset !== true) return;
  const reset = document.getElementById("reset");
  reset.hidden = false;
  document.getElementById("reset-start").onclick = event => {
    if (!userGesture(event, navigator.userActivation)) return;
    document.getElementById("reset-confirm").hidden = false;
  };
  document.getElementById("reset-yes").onclick = async event => {
    if (!userGesture(event, navigator.userActivation)) return;
    event.target.disabled = true;
    const done = await send({op: "reset-trust"});
    note.textContent = done && done.ok ? "Broker trust reset. Open akdbx again to pair this browser." : "Reset failed.";
    note.className = "detail";
    reset.hidden = true;
  };
}

async function main() {
  const status = document.getElementById("status");
  const list = document.getElementById("entries");
  const send = message => chrome.runtime.sendMessage(message);
  document.getElementById("version").textContent = versionText(chrome.runtime.getManifest());
  const state = await send({op: "state"});
  if (!state || !state.connected) {
    status.textContent = "The akdbx broker is not reachable. Start the broker, then run “akdbx extension install” for this browser.";
    return;
  }
  showTrust(state, send);
  if (!state.paired) {
    const link = state.pairing_url && privateLink(state.pairing_url, "/extension/pair", state.origin);
    status.textContent = "This browser is not paired with akdbx yet.";
    // The code comes from this browser's own key, never from the host.
    if (link && /^[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(state.code)) {
      document.getElementById("code").textContent = state.code;
      document.getElementById("origin").textContent = "Pairing page: " + new URL(link).origin;
      document.getElementById("pairing").hidden = false;
      document.getElementById("pair").onclick = () => chrome.tabs.create({url: link});
    }
    return;
  }
  if (state.locked) {
    const link = state.unlock_url && privateLink(state.unlock_url, "/", state.origin);
    status.textContent = "The akdbx vault is locked.";
    if (link) {
      const unlock = document.getElementById("unlock");
      unlock.hidden = false;
      unlock.onclick = () => chrome.tabs.create({url: link});
      const origin = document.getElementById("unlock-origin");
      origin.textContent = "Unlock page: " + new URL(link).origin;
      origin.hidden = false;
    }
    return;
  }
  const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
  if (!tab) return;
  const found = await send({op: "probe", tab_id: tab.id});
  if (!found || !found.ok) {
    status.textContent = (found && found.error) || "Click into a login, card or address field first.";
    return;
  }
  if (!found.entries.length) {
    status.textContent = `No saved ${found.kind === "login" ? "login" : found.kind} matches ${found.origin}.`;
    return;
  }
  status.textContent = `Choose what to fill on ${found.origin}:`;
  for (const entry of found.entries) {
    const item = document.createElement("li");
    const button = document.createElement("button");
    const [title, detail] = label(found.kind, entry);
    button.textContent = title;
    const small = document.createElement("span");
    small.className = "detail";
    small.textContent = detail;
    button.append(small);
    button.addEventListener("click", async event => {
      if (!userGesture(event, navigator.userActivation)) return;
      for (const other of list.querySelectorAll("button")) other.disabled = true;
      const result = await send({op: "fill", session: found.session, index: entry.index});
      status.textContent = result && result.ok ? "Filled." : (result && result.error) || "Nothing filled.";
      if (result && result.ok) setTimeout(() => window.close(), 400);
    });
    item.append(button);
    list.append(item);
  }
}

if (typeof document !== "undefined" && typeof chrome !== "undefined" && chrome.runtime) {
  main().catch(() => {
    document.getElementById("status").textContent = "akdbx request failed.";
  });
}
if (typeof module !== "undefined") module.exports = {userGesture, privateLink, label, versionText};
