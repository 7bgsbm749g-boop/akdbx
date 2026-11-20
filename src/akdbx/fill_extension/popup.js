/* akdbx popup: the user picks one entry; only a real click in this popup fills. */
"use strict";

// A fill starts only from a trusted click with transient user activation.
function userGesture(event, activation) {
  return Boolean(event && event.isTrusted === true && activation && activation.isActive === true);
}

// Links arrive through the native host, so they open only on the broker origin
// that `akdbx extension build` wrote into this extension.
function privateLink(value, path, trusted = globalThis.AKDBX_TRUSTED_ORIGIN) {
  try {
    const url = new URL(value);
    return typeof trusted === "string" && url.origin === trusted && url.protocol === "https:" &&
      url.pathname === path && !url.username && !url.password ? url.href : null;
  } catch {
    return null;
  }
}

function label(kind, entry) {
  if (kind === "card") return [entry.title, `${entry.brand} •••• ${entry.last_four}`];
  if (kind === "login") return [entry.title, entry.username + (entry.passwordless ? " (no password)" : "")];
  return [entry.title, "address and contact details"];
}

async function main() {
  const status = document.getElementById("status");
  const list = document.getElementById("entries");
  const send = message => chrome.runtime.sendMessage(message);
  const state = await send({op: "state"});
  if (!state || !state.connected) {
    status.textContent = "The akdbx broker is not reachable. Start the broker, then run “akdbx extension install” for this browser.";
    return;
  }
  if (!state.paired) {
    const link = state.pairing && privateLink(state.pairing.url, "/extension/pair");
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
    const link = state.unlock_url && privateLink(state.unlock_url, "/");
    status.textContent = "The akdbx vault is locked.";
    if (link) {
      const unlock = document.getElementById("unlock");
      unlock.hidden = false;
      unlock.onclick = () => chrome.tabs.create({url: link});
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
if (typeof module !== "undefined") module.exports = {userGesture, privateLink, label};
