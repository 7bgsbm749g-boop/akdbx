/* akdbx extension service worker.
 *
 * It keeps one native-messaging port to the akdbx host, answers the broker's
 * frame, pin and fill requests with facts from the browser itself (tabs,
 * webNavigation, injection results), and serves the popup. Values from the
 * broker go only to the retained element in the exact document; they are never
 * stored, logged or put on the clipboard.
 */
"use strict";
const HOST = "org.akdbx.extension";
const PROTOCOL = 1;
const RECONNECT_MINUTES = [0.5, 1, 2, 5, 10];
const MAX_FRAMES = 64, MAX_TABS = 4, MAX_SESSIONS = 4, SESSION_MS = 60000;
let port = null;
let state = {connected: false};
let sequence = 0;
let reconnects = 0;
const waiting = new Map();
const sessions = new Map();
const processorGuards = new Map();

// Only extension pages may read session storage; content scripts may not.
chrome.storage.session.setAccessLevel?.({accessLevel: "TRUSTED_CONTEXTS"});

function randomText(bytes) {
  const data = crypto.getRandomValues(new Uint8Array(bytes));
  return btoa(String.fromCharCode(...data)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function pairingKey() {
  // Memory-only for this browser session: a restart needs a new pairing.
  const stored = await chrome.storage.session.get("pairingKey");
  if (typeof stored.pairingKey === "string" && /^[A-Za-z0-9_-]{43}$/.test(stored.pairingKey)) return stored.pairingKey;
  const pairingKey = randomText(32);
  await chrome.storage.session.set({pairingKey});
  return pairingKey;
}

async function connect() {
  if (port) return;
  const key = await pairingKey();
  if (port) return;
  let current;
  try {
    current = chrome.runtime.connectNative(HOST);
  } catch {
    scheduleReconnect();
    return;
  }
  port = current;
  current.onMessage.addListener(message => onHost(current, message));
  current.onDisconnect.addListener(() => {
    void chrome.runtime.lastError;
    if (port !== current) return;
    port = null;
    state = {connected: false};
    for (const resolve of waiting.values()) resolve(null);
    waiting.clear();
    scheduleReconnect();
  });
  current.postMessage({type: "hello", protocol: PROTOCOL, pairing_key: key});
}

function scheduleReconnect() {
  const delay = RECONNECT_MINUTES[Math.min(reconnects, RECONNECT_MINUTES.length - 1)];
  reconnects += 1;
  chrome.alarms.create("akdbx-reconnect", {delayInMinutes: delay});
}

chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === "akdbx-reconnect") connect();
});
chrome.runtime.onStartup.addListener(() => connect());
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({id: "akdbx-fill", title: "Fill with akdbx…", contexts: ["editable"]}, () => {
    void chrome.runtime.lastError;
  });
  connect();
});
chrome.contextMenus.onClicked.addListener(info => {
  // The popup is the only place where an entry is chosen.
  if (info.menuItemId === "akdbx-fill") chrome.action.openPopup().catch(() => {});
});

function onHost(current, message) {
  if (!message || typeof message !== "object") return;
  if (message.type === "attached" || message.type === "state") {
    if (message.connected === false) {
      state = {connected: false, error: "broker unavailable"};
      return;
    }
    reconnects = 0;
    chrome.alarms.clear("akdbx-reconnect");
    state = {connected: true, paired: message.paired === true, locked: message.locked === true,
      pairing: message.pairing || null, unlock_url: message.unlock_url || null};
  } else if (message.type === "call") {
    handleCall(message).catch(() => ({ok: false})).then(result => {
      if (port === current) current.postMessage({type: "reply", id: message.id, result});
    });
  } else if (message.type === "response") {
    const resolve = waiting.get(message.id);
    if (resolve) resolve(message.result);
  } else if (message.type === "error") {
    state = {connected: false, error: "attach refused"};
  }
}

function brokerRequest(op, payload = {}, timeout = 10000) {
  return new Promise(resolve => {
    if (!port) {
      resolve(null);
      return;
    }
    const id = "p" + (++sequence);
    const timer = setTimeout(() => {
      waiting.delete(id);
      resolve(null);
    }, timeout);
    waiting.set(id, result => {
      clearTimeout(timer);
      waiting.delete(id);
      resolve(result);
    });
    port.postMessage({type: "request", id, op, ...payload});
  });
}

// ----- browser facts ---------------------------------------------------
async function chainFor(tabId, documentId) {
  const frames = await chrome.webNavigation.getAllFrames({tabId});
  if (!frames) return null;
  const byDocument = new Map(frames.filter(f => f.documentId).map(f => [f.documentId, f]));
  let frame = byDocument.get(documentId);
  const chain = [];
  while (frame) {
    if (frame.documentLifecycle && frame.documentLifecycle !== "active") return null;
    chain.unshift({document_id: frame.documentId, url: frame.url});
    if (chain.length > 9) return null;
    if (frame.frameId === 0) return chain;
    frame = frame.parentDocumentId ? byDocument.get(frame.parentDocumentId) : null;
  }
  return null;
}

const sameChain = (a, b) => JSON.stringify(a) === JSON.stringify(b);

async function inject(tabId, documentId) {
  await chrome.scripting.executeScript({target: {tabId, documentIds: [documentId]}, files: ["content.js"]});
}

async function run(tabId, documentId, func, args = []) {
  const [result] = await chrome.scripting.executeScript({target: {tabId, documentIds: [documentId]}, func, args});
  return result ? result.result : undefined;
}

// ----- broker requests (agent route) -------------------------------------
async function handleCall(message) {
  if (message.op === "frames") return frames(message);
  if (message.op === "pin") return pin(message);
  if (message.op === "fill") return fill(message);
  if (message.op === "release") return release(message);
  return {ok: false};
}

async function frames(message) {
  const tabs = (await chrome.tabs.query({})).filter(tab => tab.url === message.top_url &&
    (message.tab_id === null || message.tab_id === undefined || tab.id === message.tab_id));
  if (tabs.length > MAX_TABS) return {ok: false};
  const result = [];
  for (const tab of tabs) {
    const all = (await chrome.webNavigation.getAllFrames({tabId: tab.id})) || [];
    const listed = [];
    for (const frame of all.filter(f => f.documentId && (!f.documentLifecycle || f.documentLifecycle === "active"))
      .slice(0, MAX_FRAMES + 1)) {
      let visible = null;
      if (frame.url.startsWith("https://")) {
        try {
          await inject(tab.id, frame.documentId);
          visible = await run(tab.id, frame.documentId, () => globalThis.__akdbxContent.count());
        } catch {
          visible = null;
        }
      }
      listed.push({document_id: frame.documentId, parent_document_id: frame.frameId === 0 ? null : (frame.parentDocumentId || null),
        url: frame.url, visible_fields: visible || null});
    }
    result.push({tab_id: tab.id, frames: listed});
  }
  return {ok: true, tabs: result};
}

async function processorCheck(tabId, chain, pinId, guardId) {
  const point = await run(tabId, chain[chain.length - 1].document_id, id => globalThis.__akdbxContent.geometry(id), [pinId]);
  if (!point) return false;
  return (await run(tabId, chain[chain.length - 2].document_id,
    (id, p) => globalThis.__akdbxContent.guardCheck(id, p), [guardId, point])) === true;
}

async function pin(message) {
  const tab = await chrome.tabs.get(message.tab_id);
  if (!tab || tab.url !== message.top_url) return {ok: false};
  const chain = await chainFor(message.tab_id, message.document_id);
  if (!chain || chain[0].url !== message.top_url) return {ok: false};
  const frameURL = chain[chain.length - 1].url;
  if (message.frame_url !== null && message.frame_url !== undefined && message.frame_url !== frameURL) return {ok: false};
  if (!frameURL.startsWith("https://")) return {ok: false};
  const spec = {...message.spec};
  if (message.kind === "password") {
    const origin = new URL(frameURL).origin;
    if (spec.frame_origin === null || spec.frame_origin === undefined) spec.frame_origin = origin;
    else if (spec.frame_origin !== origin) return {ok: false};
  }
  await inject(message.tab_id, message.document_id);
  const pinId = await run(message.tab_id, message.document_id,
    (kind, value, url, top) => globalThis.__akdbxContent.pin(kind, value, url, top),
    [message.kind, spec, frameURL, message.top_url]);
  if (typeof pinId !== "string") return {ok: false};
  if (message.kind === "card" && spec.processor) {
    let guardId = null;
    try {
      if (chain.length < 2) throw new Error();
      const parent = chain[chain.length - 2].document_id;
      await inject(message.tab_id, parent);
      guardId = await run(message.tab_id, parent, (url, top, processor) => globalThis.__akdbxContent.guard(url, top, processor),
        [frameURL, message.top_url, spec.processor]);
      if (typeof guardId !== "string" || !(await processorCheck(message.tab_id, chain, pinId, guardId))) throw new Error();
    } catch {
      await release({tab_id: message.tab_id, document_id: message.document_id, pin_id: pinId, chain});
      return {ok: false};
    }
    processorGuards.set(pinId, guardId);
  }
  return {ok: true, pin_id: pinId, chain};
}

async function fill(message) {
  const values = message.values || {};
  try {
    const tab = await chrome.tabs.get(message.tab_id);
    const chain = await chainFor(message.tab_id, message.document_id);
    if (!tab || tab.url !== message.top_url || !chain || !sameChain(chain, message.chain)) {
      await release(message);
      return {state: "refused"};
    }
    const guardId = processorGuards.get(message.pin_id);
    if (message.kind === "card" && guardId && !(await processorCheck(message.tab_id, chain, message.pin_id, guardId))) {
      await release(message);
      return {state: "refused"};
    }
    let result;
    try {
      result = await run(message.tab_id, message.document_id,
        (id, kind, value, maxAge, remaining) => globalThis.__akdbxContent.fill(id, kind, value, maxAge, remaining),
        [message.pin_id, message.kind, values, message.max_age_ms, message.remaining_ms]);
    } catch {
      return {state: "uncertain"};
    }
    return {state: result === "filled" || result === "refused" ? result : "uncertain"};
  } finally {
    for (const key of Object.keys(values)) values[key] = "";
    processorGuards.delete(message.pin_id);
  }
}

async function release(message) {
  try {
    await run(message.tab_id, message.document_id, id => globalThis.__akdbxContent.release(id), [message.pin_id]);
  } catch {
    // The document is gone; its isolated world went with it.
  }
  processorGuards.delete(message.pin_id);
  return {ok: true};
}

// ----- popup (user-click route) ------------------------------------------
function fromPopup(sender) {
  // Web pages cannot reach this listener, and content scripts carry a tab.
  return sender.id === chrome.runtime.id && !sender.tab && sender.url === chrome.runtime.getURL("popup.html");
}

async function popupState() {
  await connect();
  const fresh = port ? await brokerRequest("state", {}, 5000) : null;
  if (fresh && fresh.ok) {
    state = {connected: true, paired: fresh.paired === true, locked: fresh.locked === true,
      pairing: fresh.pairing || null, unlock_url: fresh.unlock_url || null};
  }
  return {ok: true, ...state};
}

async function popupProbe(message) {
  const tab = await chrome.tabs.get(message.tab_id);
  if (!tab || typeof tab.url !== "string" || !tab.url.startsWith("https://")) return {ok: false, error: "open an HTTPS page first"};
  await chrome.scripting.executeScript({target: {tabId: tab.id, allFrames: true}, files: ["content.js"]}).catch(() => {});
  const results = await chrome.scripting.executeScript({target: {tabId: tab.id, allFrames: true},
    func: () => globalThis.__akdbxContent ? globalThis.__akdbxContent.probe() : null});
  const best = results.filter(r => r.result && r.documentId).sort((a, b) => b.result.t - a.result.t)[0];
  if (!best) return {ok: false, error: "click into a login, card or address field first"};
  const chain = await chainFor(tab.id, best.documentId);
  if (!chain || chain[0].url !== tab.url) return {ok: false, error: "page changed; try again"};
  const match = await brokerRequest("match", {tab_id: tab.id, document_id: best.documentId, top_url: tab.url, chain,
    kind: best.result.kind});
  if (!match || match.ok !== true) return {ok: false, error: (match && match.error) || "akdbx refused this field"};
  const id = randomText(16);
  while (sessions.size >= MAX_SESSIONS) sessions.delete(sessions.keys().next().value);
  sessions.set(id, {tabId: tab.id, documentId: best.documentId, topUrl: tab.url, chain, probe: best.result.id,
    roles: best.result.roles, formats: best.result.formats, handles: match.entries.map(e => e.handle),
    created: Date.now()});
  return {ok: true, session: id, kind: match.kind, origin: new URL(chain[chain.length - 1].url).origin,
    entries: match.entries.map(({handle, ...metadata}, index) => ({index, ...metadata}))};
}

async function popupFill(message) {
  const session = sessions.get(message.session);
  sessions.delete(message.session);
  if (!session || Date.now() - session.created >= SESSION_MS || !Number.isInteger(message.index) ||
      !session.handles[message.index]) return {ok: false, error: "selection expired; open akdbx again"};
  const tab = await chrome.tabs.get(session.tabId);
  const chain = await chainFor(session.tabId, session.documentId);
  if (!tab || tab.url !== session.topUrl || !chain || !sameChain(chain, session.chain)) {
    return {ok: false, error: "page changed; nothing filled"};
  }
  const released = await brokerRequest("release", {handle: session.handles[message.index], tab_id: session.tabId,
    document_id: session.documentId, top_url: session.topUrl, chain, roles: session.roles, formats: session.formats});
  if (!released || released.ok !== true || typeof released.values !== "object") {
    return {ok: false, error: (released && released.error) || "akdbx refused this fill"};
  }
  const values = released.values;
  try {
    const result = await run(session.tabId, session.documentId, (id, v) => globalThis.__akdbxContent.probeFill(id, v),
      [session.probe, values]);
    return result === "filled" ? {ok: true} : {ok: false, error: result === "uncertain"
      ? "fill incomplete; check the page" : "field changed or hidden; nothing filled"};
  } catch {
    return {ok: false, error: "fill not confirmed; check the page"};
  } finally {
    for (const key of Object.keys(values)) values[key] = "";
  }
}

chrome.runtime.onMessage.addListener((message, sender, respond) => {
  if (!fromPopup(sender) || !message || typeof message !== "object") return false;
  const handler = {state: popupState, probe: popupProbe, fill: popupFill}[message.op];
  if (!handler) return false;
  handler(message).then(respond, () => respond({ok: false, error: "akdbx request failed"}));
  return true;
});

connect();
if (typeof module !== "undefined") module.exports = {fromPopup, chainFor, sameChain, onHost, state: () => state};
