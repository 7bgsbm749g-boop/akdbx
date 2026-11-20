/* akdbx extension service worker.
 *
 * It keeps one native-messaging port to the akdbx host, answers the broker's
 * frame, pin and fill requests with facts from the browser itself (tabs,
 * webNavigation, injection results), and serves the popup. Values arrive
 * sealed (AES-GCM) to this extension's ECDH key, so the host relays only
 * ciphertext. After decryption they go only to the retained element in the
 * exact document; they are never stored, logged or put on the clipboard.
 */
"use strict";
importScripts("config.js");
const HOST = "org.akdbx.extension";
const PROTOCOL = 1;
const RECONNECT_MINUTES = [0.5, 1, 2, 5, 10];
const MAX_FRAMES = 64, MAX_TABS = 4, MAX_SESSIONS = 4, SESSION_MS = 60000;
let port = null;
let state = {connected: false};
let sequence = 0;
let reconnects = 0;
let sealKey = null;   // Promise of the AES-GCM key agreed with the broker for the current port.
const waiting = new Map();
const sessions = new Map();
const processorGuards = new Map();

// Only extension pages may read session storage; content scripts may not.
chrome.storage.session.setAccessLevel?.({accessLevel: "TRUSTED_CONTEXTS"});

const encoder = new TextEncoder();
const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

function base64url(data) {
  return btoa(String.fromCharCode(...new Uint8Array(data))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function unbase64url(text) {
  const plain = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(plain, c => c.charCodeAt(0));
}

function randomText(bytes) {
  return base64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

let keysPromise = null;

function pairingKeys() {
  // One shared promise: concurrent callers must never create two key pairs.
  if (!keysPromise) keysPromise = loadPairingKeys().catch(error => {
    keysPromise = null;
    throw error;
  });
  return keysPromise;
}

async function loadPairingKeys() {
  // An ECDH P-256 key pair, in memory only for this browser session: a
  // restart needs a new pairing. Only the public key ever leaves the worker.
  const stored = (await chrome.storage.session.get("pairing")).pairing;
  if (stored && stored.jwk && typeof stored.publicKey === "string") {
    const privateKey = await crypto.subtle.importKey("jwk", stored.jwk, {name: "ECDH", namedCurve: "P-256"}, false,
      ["deriveBits"]);
    return {privateKey, publicKey: stored.publicKey};
  }
  const pair = await crypto.subtle.generateKey({name: "ECDH", namedCurve: "P-256"}, true, ["deriveBits"]);
  const publicKey = base64url(await crypto.subtle.exportKey("raw", pair.publicKey));
  const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  await chrome.storage.session.set({pairing: {jwk, publicKey}});
  return {privateKey: pair.privateKey, publicKey};
}

async function localCode(publicKey) {
  // The same code the broker's pairing page shows for the key it received.
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", unbase64url(publicKey)));
  const mac = new Uint8Array(await crypto.subtle.digest("SHA-256",
    concat(encoder.encode("akdbx-pairing-code\0"), digest)));
  const letters = Array.from(mac.slice(0, 8), b => CODE_ALPHABET[b % CODE_ALPHABET.length]).join("");
  return letters.slice(0, 4) + "-" + letters.slice(4);
}

async function agreeKey(brokerPublicKey) {
  const keys = await pairingKeys();
  const brokerRaw = unbase64url(brokerPublicKey);
  const broker = await crypto.subtle.importKey("raw", brokerRaw, {name: "ECDH", namedCurve: "P-256"}, false, []);
  const shared = await crypto.subtle.deriveBits({name: "ECDH", public: broker}, keys.privateKey, 256);
  const base = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32),
    info: concat(encoder.encode("akdbx-extension-v1"), unbase64url(keys.publicKey), brokerRaw)},
  base, {name: "AES-GCM", length: 256}, false, ["decrypt"]);
}

async function unseal(sealed, context) {
  // A value sealed for another pin, selection or key fails authentication.
  const key = sealKey && await sealKey;
  if (!key || !sealed || typeof sealed.iv !== "string" || typeof sealed.data !== "string") throw new Error();
  const plain = await crypto.subtle.decrypt({name: "AES-GCM", iv: unbase64url(sealed.iv),
    additionalData: encoder.encode(context)}, key, unbase64url(sealed.data));
  const payload = JSON.parse(new TextDecoder().decode(plain));
  new Uint8Array(plain).fill(0);
  if (!payload || typeof payload.values !== "object" || payload.values === null ||
      typeof payload.facts !== "object" || payload.facts === null) throw new Error();
  return payload;
}

async function connect() {
  if (port) return;
  const key = (await pairingKeys()).publicKey;
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
    sealKey = null;
    state = {connected: false};
    for (const resolve of waiting.values()) resolve(null);
    waiting.clear();
    scheduleReconnect();
  });
  current.postMessage({type: "hello", protocol: PROTOCOL, public_key: key});
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
    if (message.type === "attached" && typeof message.broker_public_key === "string") {
      if (port === current) sealKey = agreeKey(message.broker_public_key).catch(() => null);
    }
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
      // Only origins matter below the top document; this also bounds the reply.
      const url = frame.frameId === 0 ? frame.url
        : frame.url.startsWith("https://") ? new URL(frame.url).origin + "/" : frame.url.split(":")[0] + ":";
      listed.push({document_id: frame.documentId, parent_document_id: frame.frameId === 0 ? null : (frame.parentDocumentId || null),
        url, visible_fields: visible || null});
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
  let values = {};
  try {
    let facts;
    try {
      ({values, facts} = await unseal(message.sealed, "fill:" + message.pin_id));
    } catch {
      await release(message);
      return {state: "refused"};
    }
    // Only the facts the broker authorized and sealed count, never the
    // relayed message: they must equal what this browser reports now.
    const tab = await chrome.tabs.get(facts.tab_id);
    const chain = await chainFor(facts.tab_id, facts.document_id);
    if (facts.pin_id !== message.pin_id || !Array.isArray(facts.chain) || !facts.chain.length || !tab ||
        tab.url !== facts.chain[0].url || !chain || !sameChain(chain, facts.chain)) {
      await release({...message, tab_id: facts.tab_id, document_id: facts.document_id});
      return {state: "refused"};
    }
    const guardId = processorGuards.get(facts.pin_id);
    if (facts.kind === "card" && guardId && !(await processorCheck(facts.tab_id, chain, facts.pin_id, guardId))) {
      await release({...message, tab_id: facts.tab_id, document_id: facts.document_id});
      return {state: "refused"};
    }
    let result;
    try {
      result = await run(facts.tab_id, facts.document_id,
        (id, kind, value, maxAge) => globalThis.__akdbxContent.fill(id, kind, value, maxAge),
        [facts.pin_id, facts.kind, values, message.max_age_ms]);
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
  // The popup shows the code of this browser's own key, never one from the host.
  return {ok: true, ...state, code: await localCode((await pairingKeys()).publicKey)};
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
    kind: best.result.kind,
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
  if (!released || released.ok !== true) {
    return {ok: false, error: (released && released.error) || "akdbx refused this fill"};
  }
  let values = {};
  try {
    const sealed = await unseal(released.sealed, "release:" + session.handles[message.index]);
    const facts = sealed.facts;
    // The broker authorized exactly this tab, document, chain, kind and fields.
    if (facts.tab_id !== session.tabId || facts.document_id !== session.documentId || facts.kind !== session.kind ||
        !sameChain(facts.chain, session.chain) || !sameChain(facts.roles, session.roles)) throw new Error();
    values = sealed.values;
  } catch {
    return {ok: false, error: "akdbx answer could not be verified; nothing filled"};
  }
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
if (typeof module !== "undefined") {
  module.exports = {fromPopup, chainFor, sameChain, onHost, localCode, unseal, agreeKey, pairingKeys, fill,
    setSealKey: key => { sealKey = Promise.resolve(key); }, state: () => state};
}
