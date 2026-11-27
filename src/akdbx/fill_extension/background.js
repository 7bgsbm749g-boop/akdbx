/* akdbx extension service worker.
 *
 * It keeps one native-messaging port to the akdbx host, answers the broker's
 * frame, pin and fill requests with facts from the browser itself (tabs,
 * webNavigation, injection results), and serves the popup. Values arrive
 * sealed (AES-GCM) to this extension's ECDH key, so the host relays only
 * ciphertext. After decryption they go only to the retained element in the
 * exact document; they are never stored, logged or put on the clipboard.
 * A secret that a read pin captures goes the other way, sealed to the broker
 * under a second key (akdbx-extension-capture-v1) and bound to that pin.
 *
 * Pairing and unlock links open only on the origin that trust.js decides:
 * the origin the user confirmed in the popup on first use (or the trust an
 * earlier build saved), then the broker identity read over HTTPS from that
 * origin, and the origin changes that identity signed. Every identity the host
 * sends is checked when it arrives, one at a time. This build is the same for
 * every user: config.js holds only its version.
 */
"use strict";
if (typeof importScripts === "function") importScripts("api.js", "config.js", "trust.js");
const HOST = "org.akdbx.extension";
const PROTOCOL = 1;
const RECONNECT_MINUTES = [0.5, 1, 2, 5, 10];
const MAX_FRAMES = 64, MAX_TABS = 4, MAX_SESSIONS = 4, SESSION_MS = 60000;
let port = null;
let state = {connected: false};
let sequence = 0;
let reconnects = 0;
let sealKey = null;   // Promise of the AES-GCM key agreed with the broker for the current port.
let captureKey = null;  // Promise of the AES-GCM key that seals captured secrets to the broker.
// The broker key of the current port, the keys agreed with it and the broker's signature over it
// (see channelTrusted). A port gets one broker key: its first `attached` message sets it.
let channel = {brokerKey: null, signature: null, sealKey: null, captureKey: null};
const waiting = new Map();
const sessions = new Map();
const processorGuards = new Map();

/* The build this worker runs. Chrome keeps a registered worker, with the
 * scripts it imported, until the manifest version changes or the extension
 * reloads; content scripts and injected files come from disk. So after
 * `akdbx extension build` rewrites the folder, an old worker can run beside
 * new content scripts, and getManifest() can already describe the new build.
 * config.js is cached with this worker, so its version names the code that
 * runs here; manifest.json on disk names the newest build. */
const VERSION = typeof globalThis.AKDBX_EXTENSION_VERSION === "string" ? globalThis.AKDBX_EXTENSION_VERSION
  : akdbxBrowser.runtime.getManifest().version;
const RELOAD_KEY = "stale_reload";  // The disk version that this extension last reloaded for.

// The version of the build on disk, or null when it cannot be read.
async function diskVersion() {
  try {
    const response = await fetch(akdbxBrowser.runtime.getURL("manifest.json"), {cache: "no-store"});
    const version = (await response.json()).version;
    return typeof version === "string" ? version : null;
  } catch {
    return null;
  }
}

// The disk version when this worker is older than the build on disk, else null.
async function staleBuild() {
  const disk = await diskVersion();
  return disk !== null && disk !== VERSION ? disk : null;
}

// Reload once for each build on disk, so the new worker runs. A reload ends the
// pairing (the pairing key lives in session storage). If that worker still runs
// old code, there is no second reload: it reports itself stale.
async function reloadFor(disk) {
  if ((await akdbxBrowser.storage.local.get(RELOAD_KEY))[RELOAD_KEY] === disk) return false;
  await akdbxBrowser.storage.local.set({[RELOAD_KEY]: disk});
  akdbxBrowser.runtime.reload();
  return true;
}

// Only extension pages may read session storage; content scripts may not.
// Chromium148+ also exposes browser: the manifest format, not the namespace, selects the signature.
const storageAccess = akdbxBrowser.runtime.getManifest().browser_specific_settings?.gecko
  ? "TRUSTED_CONTEXTS" : {accessLevel: "TRUSTED_CONTEXTS"};
Promise.resolve(akdbxBrowser.storage.session.setAccessLevel?.(storageAccess)).catch(() => {});
// The broker trust lives in local storage: keep content scripts out of it too where the browser allows it.
try {
  Promise.resolve(akdbxBrowser.storage.local.setAccessLevel?.(storageAccess)).catch(() => {});
} catch {
  // Older browsers keep local storage open to content scripts; this extension's content script never reads it.
}

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
  const stored = (await akdbxBrowser.storage.session.get("pairing")).pairing;
  if (stored && stored.jwk && typeof stored.publicKey === "string") {
    const privateKey = await crypto.subtle.importKey("jwk", stored.jwk, {name: "ECDH", namedCurve: "P-256"}, false,
      ["deriveBits"]);
    return {privateKey, publicKey: stored.publicKey};
  }
  const pair = await crypto.subtle.generateKey({name: "ECDH", namedCurve: "P-256"}, true, ["deriveBits"]);
  const publicKey = base64url(await crypto.subtle.exportKey("raw", pair.publicKey));
  const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  await akdbxBrowser.storage.session.set({pairing: {jwk, publicKey}});
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

// From fill extension 0.4.0 the keys also bind this extension's own version: a
// host that reports another version to the broker makes every sealed message fail.
function keyInfo(label) {
  return label + "/" + VERSION;
}

async function agreeKey(brokerPublicKey, info = keyInfo("akdbx-extension-v1"), usages = ["decrypt"]) {
  const keys = await pairingKeys();
  const brokerRaw = unbase64url(brokerPublicKey);
  const broker = await crypto.subtle.importKey("raw", brokerRaw, {name: "ECDH", namedCurve: "P-256"}, false, []);
  const shared = await crypto.subtle.deriveBits({name: "ECDH", public: broker}, keys.privateKey, 256);
  const base = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32),
    info: concat(encoder.encode(info), unbase64url(keys.publicKey), brokerRaw)},
  base, {name: "AES-GCM", length: 256}, false, usages);
}

// The native host relays the broker's per-connection key, so it could offer its
// own. A captured secret goes only to a key that the broker's identity key
// signed for this extension's key; the identity key is the one this extension
// learned over HTTPS from its trusted origin (trust.js).
// Returns the verified channel (one object with its own keys), or null.
async function channelTrusted() {
  try {
    const current = channel;
    if (!current.brokerKey || !current.signature || !current.sealKey || !current.captureKey) return null;
    const trusted = akdbxTrust.trustedKey(await storedTrust());
    if (!trusted) return null;
    const valid = await akdbxTrust.verifyChannel(trusted, current.brokerKey, (await pairingKeys()).publicKey,
      current.signature);
    return valid && channel === current ? current : null;
  } catch {
    return null;
  }
}

async function sealCapture(value, facts, context, keyPromise = captureKey) {
  // Only the broker can open this: the host relays ciphertext bound to one read pin.
  const key = keyPromise && await keyPromise;
  if (!key) throw new Error();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({name: "AES-GCM", iv, additionalData: encoder.encode(context)}, key,
    encoder.encode(JSON.stringify({value, facts})));
  return {iv: base64url(iv), data: base64url(data)};
}

async function unseal(sealed, context, keyPromise = sealKey) {
  // A value sealed for another pin, selection or key fails authentication.
  const key = keyPromise && await keyPromise;
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
  const disk = await staleBuild();
  if (disk && await reloadFor(disk).catch(() => false)) return;
  if (!disk) await akdbxBrowser.storage.local.remove(RELOAD_KEY).catch(() => {});
  const key = (await pairingKeys()).publicKey;
  if (port) return;
  let current;
  try {
    current = akdbxBrowser.runtime.connectNative(HOST);
  } catch {
    scheduleReconnect();
    return;
  }
  port = current;
  current.onMessage.addListener(message => onHost(current, message));
  current.onDisconnect.addListener(() => {
    void akdbxBrowser.runtime.lastError;
    if (port !== current) return;
    port = null;
    sealKey = null;
    captureKey = null;
    channel = {brokerKey: null, signature: null, sealKey: null, captureKey: null};
    state = {connected: false};
    for (const resolve of waiting.values()) resolve(null);
    waiting.clear();
    scheduleReconnect();
  });
  // The version lets `akdbx status` show an outdated or stale unpacked extension after an update.
  current.postMessage({type: "hello", protocol: PROTOCOL, public_key: key, version: VERSION,
    ...(disk ? {stale: true} : {})});
}

function scheduleReconnect() {
  const delay = RECONNECT_MINUTES[Math.min(reconnects, RECONNECT_MINUTES.length - 1)];
  reconnects += 1;
  akdbxBrowser.alarms.create("akdbx-reconnect", {delayInMinutes: delay});
}

akdbxBrowser.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === "akdbx-reconnect") connect();
});
akdbxBrowser.runtime.onStartup.addListener(() => connect());
akdbxBrowser.runtime.onInstalled.addListener(() => {
  (akdbxBrowser.menus || akdbxBrowser.contextMenus).create({id: "akdbx-fill", title: "Fill with akdbx…", contexts: ["editable"]}, () => {
    void akdbxBrowser.runtime.lastError;
  });
  connect();
});
(akdbxBrowser.menus || akdbxBrowser.contextMenus).onClicked.addListener(info => {
  // The popup is the only place where an entry is chosen.
  if (info.menuItemId === "akdbx-fill") akdbxBrowser.action.openPopup().catch(() => {});
});

function onHost(current, message) {
  if (!message || typeof message !== "object") return;
  if (message.type === "attached" || message.type === "state") {
    if (message.connected === false) {
      state = {connected: false, error: "broker unavailable"};
      return;
    }
    reconnects = 0;
    akdbxBrowser.alarms.clear("akdbx-reconnect");
    // One broker key per port: a host cannot swap keys under a running read or fill.
    if (message.type === "attached" && typeof message.broker_public_key === "string" && port === current &&
        !channel.brokerKey) {
      sealKey = agreeKey(message.broker_public_key).catch(() => null);
      captureKey = agreeKey(message.broker_public_key, keyInfo("akdbx-extension-capture-v1"), ["encrypt"])
        .catch(() => null);
      channel = {brokerKey: message.broker_public_key, signature: null, sealKey, captureKey};
    }
    // The signature comes with every state message (a new identity re-signs the same key).
    if (port === current && typeof message.channel_signature === "string" &&
        message.broker_public_key === channel.brokerKey) {
      channel = {...channel, signature: message.channel_signature};
    }
    state = brokerState(message);
    // Bind a first key or follow a signed move now, not only when the popup opens.
    if (port === current) observeTrust(state);
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

// What the popup needs from a broker state message. The identity is checked later, against stored trust.
function brokerState(message) {
  return {connected: true, paired: message.paired === true, locked: message.locked === true,
    pairing: message.pairing || null, unlock_url: message.unlock_url || null,
    identity_received: Object.prototype.hasOwnProperty.call(message, "identity"), identity: message.identity ?? null};
}

// One trust decision at a time, so two popups never save records out of order.
let trustQueue = Promise.resolve();

function withTrust(task) {
  const next = trustQueue.then(task, task);
  trustQueue = next.catch(() => {});
  return next;
}

// A verified signed move (old origin -> new origin), kept until a popup shows it once.
const MOVE_KEY = "broker_trust_moved";

async function storedTrust() {
  return (await akdbxBrowser.storage.local.get(akdbxTrust.STORAGE_KEY))[akdbxTrust.STORAGE_KEY] ?? null;
}

// Run only inside withTrust: decide against the saved record as it is now, so an older
// statement can never replace a newer saved sequence number.
async function trustNow(current) {
  const stored = await storedTrust();
  const verified = current.identity_received ? await akdbxTrust.verifyIdentity(current.identity) : null;
  const received = current.identity_received === true;
  let decision = akdbxTrust.decide(stored, verified, received);
  if (decision.fetch) {
    // A first key: read the statement over HTTPS from the trusted origin.
    decision = akdbxTrust.decide(stored, verified, received, await akdbxTrust.fetchIdentity(decision.fetch));
  }
  if (decision.store) {
    const items = {[akdbxTrust.STORAGE_KEY]: decision.store};
    if (decision.changed) items[MOVE_KEY] = {from: decision.from, to: decision.origin};
    await akdbxBrowser.storage.local.set(items);
  }
  return decision;
}

// The move notice to show now, or null. While the decision has an error, the popup shows only that warning
// and the notice waits; the next decision with no error clears it, and shows it if it names the trusted origin.
async function takeMove(trust) {
  if (trust.error) return null;
  const notice = (await akdbxBrowser.storage.local.get(MOVE_KEY))[MOVE_KEY];
  if (!notice) return null;
  await akdbxBrowser.storage.local.remove(MOVE_KEY);
  return akdbxTrust.validOrigin(notice.from) && notice.to === trust.origin ? notice : null;
}

function observeTrust(current) {
  if (current.identity_received) withTrust(() => trustNow(current)).catch(() => {});
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
  const frames = await akdbxBrowser.webNavigation.getAllFrames({tabId});
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

// Key-order independent JSON, to compare broker-sealed facts with local ones.
function canonical(value) {
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value && typeof value === "object") {
    return "{" + Object.keys(value).sort().map(k => JSON.stringify(k) + ":" + canonical(value[k])).join(",") + "}";
  }
  return JSON.stringify(value === undefined ? null : value);
}
const pinSpecs = new Map();

async function inject(tabId, documentId) {
  await akdbxBrowser.scripting.executeScript({target: {tabId, documentIds: [documentId]}, files: ["content.js"]});
}

// The vendored QR decoder, only into the isolated world of a document that gets a QR read pin.
async function injectDecoder(tabId, documentId) {
  await akdbxBrowser.scripting.executeScript({target: {tabId, documentIds: [documentId]}, files: ["jsQR.js"]});
}

async function run(tabId, documentId, func, args = []) {
  const [result] = await akdbxBrowser.scripting.executeScript({target: {tabId, documentIds: [documentId]}, func, args});
  return result ? result.result : undefined;
}

// ----- broker requests (agent route) -------------------------------------
async function handleCall(message) {
  if (message.op === "frames" || message.op === "pin") {
    // A newer build on disk: this worker's code may not match the content script it would inject.
    const disk = await staleBuild();
    if (disk) {
      setTimeout(() => reloadFor(disk).catch(() => {}), 200);  // After the reply has gone out.
      if (message.op === "pin") return {ok: false, error: "stale"};
      // The broker still counts this browser's tabs with the URL: a URL open in two browsers stays ambiguous.
      return {ok: false, error: "stale", tabs: (await akdbxBrowser.tabs.query({})).filter(tab => tab.url === message.top_url &&
        (message.tab_id === null || message.tab_id === undefined || tab.id === message.tab_id)).length};
    }
  }
  if (message.op === "frames") return frames(message);
  if (message.op === "pin") return pin(message);
  if (message.op === "check-totp") {
    // Public field-format preflight only; fill still verifies sealed facts and owners.
    try {
      const chain = await chainFor(message.tab_id, message.document_id);
      if (!chain || !sameChain(chain, message.chain)) return {ok: false};
      const ok = await run(message.tab_id, message.document_id,
        (id, digits) => globalThis.__akdbxContent.checkTotp(id, digits), [message.pin_id, message.digits]);
      return {ok: ok === true};
    } catch { return {ok: false}; }
  }
  if (message.op === "fill") return fill(message);
  if (message.op === "read") return read(message);
  if (message.op === "release") return release(message);
  return {ok: false};
}

async function frames(message) {
  const tabs = (await akdbxBrowser.tabs.query({})).filter(tab => tab.url === message.top_url &&
    (message.tab_id === null || message.tab_id === undefined || tab.id === message.tab_id));
  if (tabs.length > MAX_TABS) return {ok: false};
  const result = [];
  for (const tab of tabs) {
    const all = (await akdbxBrowser.webNavigation.getAllFrames({tabId: tab.id})) || [];
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

// A bounded wait for a renderer call: a page that stops answering cannot hold the worker.
function bounded(promise, ms) {
  let timer;
  return Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("timeout")), ms); })])
    .finally(() => clearTimeout(timer));
}

// ----- child-frame owners --------------------------------------------------
const ownerGuards = new Map();
const OWNER_SETTLE_MS = 50, OWNER_WAIT_MS = 1500;
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

// For each hop, find the parent's <iframe> element that holds the child document
// and retain the CDP route's owner guard on it (see content.js ownerListen).
async function holdOwners(tabId, chain) {
  const held = [];
  try {
    for (let i = 1; i < chain.length; ++i) {
      const parent = chain[i - 1].document_id, child = chain[i].document_id;
      const parentOrigin = new URL(chain[i - 1].url).origin, childOrigin = new URL(chain[i].url).origin;
      if (parentOrigin === "null" || childOrigin === "null") throw new Error();
      await inject(tabId, child);
      await inject(tabId, parent);
      const listen = await run(tabId, child, origin => globalThis.__akdbxContent.ownerListen(origin), [parentOrigin]);
      if (typeof listen !== "string") throw new Error();
      let heard = [];
      try {
        const probe = await run(tabId, parent, origin => globalThis.__akdbxContent.ownerProbe(origin), [childOrigin]);
        if (typeof probe !== "string") throw new Error();
        const until = Date.now() + OWNER_WAIT_MS;
        while (Date.now() < until) {
          heard = await run(tabId, child, id => globalThis.__akdbxContent.ownerHeard(id), [listen]);
          if (!Array.isArray(heard) || heard.length) break;
          await pause(10);
        }
        // A page that repeats a nonce it saw adds a second one: wait a moment for it.
        await pause(OWNER_SETTLE_MS);
        heard = await run(tabId, child, id => globalThis.__akdbxContent.ownerHeard(id), [listen]);
        if (!Array.isArray(heard) || heard.length !== 1) throw new Error();
        const guard = await run(tabId, parent, (id, nonce) => globalThis.__akdbxContent.ownerGuard(id, nonce),
          [probe, heard[0]]);
        if (typeof guard !== "string") throw new Error();
        held.push({documentId: parent, guard});
      } finally {
        await run(tabId, child, id => globalThis.__akdbxContent.ownerDone(id), [listen]).catch(() => {});
      }
    }
  } catch {
    await releaseOwners(tabId, held);
    return null;
  }
  return held;
}

async function ownersHold(tabId, held) {
  for (const item of held || []) {
    if ((await run(tabId, item.documentId, id => globalThis.__akdbxContent.ownerCheck(id), [item.guard])) !== true) {
      return false;
    }
  }
  return true;
}

async function releaseOwners(tabId, held) {
  for (const item of held || []) {
    await run(tabId, item.documentId, id => globalThis.__akdbxContent.ownerRelease(id), [item.guard]).catch(() => {});
  }
}

async function pin(message) {
  // What this browser pinned, before any local completion of the spec.
  const pinned = canonical({kind: message.kind, spec: message.spec});
  const tab = await akdbxBrowser.tabs.get(message.tab_id);
  if (!tab || tab.url !== message.top_url) return {ok: false};
  const chain = await chainFor(message.tab_id, message.document_id);
  if (!chain || chain[0].url !== message.top_url) return {ok: false};
  const frameURL = chain[chain.length - 1].url;
  if (message.frame_url !== null && message.frame_url !== undefined && message.frame_url !== frameURL) return {ok: false};
  if (!frameURL.startsWith("https://")) return {ok: false};
  const spec = {...message.spec};
  if (message.kind === "password" || message.kind === "read") {
    const origin = new URL(frameURL).origin;
    if (spec.frame_origin === null || spec.frame_origin === undefined) spec.frame_origin = origin;
    else if (spec.frame_origin !== origin) return {ok: false};
  }
  // The extension reads secrets only in the top document.
  if (message.kind === "read" && chain.length !== 1) return {ok: false};
  const qr = message.kind === "read" && spec.read_kind === "qr";
  if (message.kind === "read" && spec.read_kind !== undefined && !qr) return {ok: false};
  // Password pins in a child frame need the frame owners, as on the CDP route.
  let owners = [];
  if (message.kind === "password" && chain.length > 1) {
    owners = await holdOwners(message.tab_id, chain);
    let held = false;
    try {
      held = Boolean(owners) && await ownersHold(message.tab_id, owners);
    } catch {
      held = false;
    }
    if (!held) {
      await releaseOwners(message.tab_id, owners);
      return {ok: false};
    }
  }
  let pinId = null;
  try {
    await inject(message.tab_id, message.document_id);
    if (qr) await injectDecoder(message.tab_id, message.document_id);
    pinId = await run(message.tab_id, message.document_id,
      (kind, value, url, top) => globalThis.__akdbxContent.pin(kind, value, url, top),
      [message.kind, spec, frameURL, message.top_url]);
  } catch {
    pinId = null;
  }
  if (typeof pinId !== "string") {
    await releaseOwners(message.tab_id, owners);
    return {ok: false};
  }
  if (message.kind === "card" && spec.processor) {
    let guardId = null;
    try {
      if (chain.length < 2) throw new Error();
      const parent = chain[chain.length - 2].document_id;
      await inject(message.tab_id, parent);
      guardId = await run(message.tab_id, parent, (url, top, processor) => globalThis.__akdbxContent.guard(url, top, processor),
        [frameURL, message.top_url, spec.processor]);
      if (typeof guardId !== "string" || !(await processorCheck(message.tab_id, chain, pinId, guardId))) {
        throw new Error();
      }
    } catch {
      await release({tab_id: message.tab_id, document_id: message.document_id, pin_id: pinId, chain});
      return {ok: false};
    }
    processorGuards.set(pinId, guardId);
  }
  while (pinSpecs.size >= 32) pinSpecs.delete(pinSpecs.keys().next().value);
  pinSpecs.set(pinId, pinned);
  if (owners.length) ownerGuards.set(pinId, {tabId: message.tab_id, held: owners});
  return {ok: true, pin_id: pinId, chain};
}

// The facts the broker sealed must equal what this browser reports now.
async function currentFacts(message, facts) {
  const tab = await akdbxBrowser.tabs.get(facts.tab_id);
  const chain = await chainFor(facts.tab_id, facts.document_id);
  const pinned = pinSpecs.get(facts.pin_id);
  pinSpecs.delete(facts.pin_id);
  if (facts.pin_id !== message.pin_id || pinned !== canonical({kind: facts.kind, spec: facts.spec}) ||
      !Number.isFinite(facts.max_age_ms) || !Array.isArray(facts.chain) || !facts.chain.length || !tab ||
      tab.url !== facts.chain[0].url || !chain || !sameChain(chain, facts.chain)) return null;
  const owners = ownerGuards.get(facts.pin_id);
  if (facts.chain.length > 1 && (facts.kind === "password" || facts.kind === "read") &&
      (!owners || owners.tabId !== facts.tab_id || !(await ownersHold(facts.tab_id, owners.held)))) return null;
  return chain;
}

async function read(message) {
  // Only to a broker key that the trusted broker identity signed, with that channel's own keys throughout.
  const session = await channelTrusted();
  if (!session) {
    await release(message);
    return {state: "refused"};
  }
  let facts;
  try {
    ({facts} = await unseal(message.sealed, "read:" + message.pin_id, session.sealKey));
  } catch {
    await release(message);
    return {state: "refused"};
  }
  try {
    const chain = facts.kind === "read" ? await currentFacts(message, facts) : null;
    if (!chain) return {state: "refused"};
    let value = null;
    try {
      // The extension reads only in the top document; the pin's own deadline bounds the read.
      if (chain.length === 1) {
        value = await run(facts.tab_id, facts.document_id,
          (id, maxAge) => globalThis.__akdbxContent.read(id, maxAge), [facts.pin_id, facts.max_age_ms]);
      }
    } catch {
      value = null;
    }
    // The port, and so the channel, must not have changed while the page was read.
    if (typeof value !== "string" || channel.brokerKey !== session.brokerKey || channel.captureKey !== session.captureKey) {
      return {state: "refused"};
    }
    const bound = {tab_id: facts.tab_id, document_id: facts.document_id, chain: facts.chain, pin_id: facts.pin_id};
    return {state: "read", sealed: await sealCapture(value, bound, "capture:" + facts.pin_id, session.captureKey)};
  } finally {
    await release({...message, tab_id: facts.tab_id, document_id: facts.document_id});
  }
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
    const chain = facts.kind !== "read" ? await currentFacts(message, facts) : null;
    if (!chain) {
      await release({...message, tab_id: facts.tab_id, document_id: facts.document_id});
      return {state: "refused"};
    }
    const guardId = processorGuards.get(facts.pin_id);
    let result = "refused";
    // A processor field: the retained merchant <iframe> must still hold it at its point.
    const held = facts.kind !== "card" || !guardId ||
      await processorCheck(facts.tab_id, chain, facts.pin_id, guardId).catch(() => false);
    if (held) {
      try {
        // Before this call nothing reached the field; an error after it is uncertain.
        result = await run(facts.tab_id, facts.document_id,
          (id, kind, value, maxAge) => globalThis.__akdbxContent.fill(id, kind, value, maxAge),
          [facts.pin_id, facts.kind, values, facts.max_age_ms]);
      } catch {
        result = "uncertain";
      }
    }
    if (result === "refused") await release({...message, tab_id: facts.tab_id, document_id: facts.document_id});
    return {state: result === "filled" || result === "refused" ? result : "uncertain"};
  } finally {
    for (const key of Object.keys(values)) values[key] = "";
    processorGuards.delete(message.pin_id);
    const owners = ownerGuards.get(message.pin_id);
    ownerGuards.delete(message.pin_id);
    if (owners) await releaseOwners(owners.tabId, owners.held);
  }
}

async function release(message) {
  try {
    await run(message.tab_id, message.document_id, id => globalThis.__akdbxContent.release(id), [message.pin_id]);
  } catch {
    // The document is gone; its isolated world went with it.
  }
  processorGuards.delete(message.pin_id);
  pinSpecs.delete(message.pin_id);
  const owners = ownerGuards.get(message.pin_id);
  ownerGuards.delete(message.pin_id);
  if (owners) await releaseOwners(owners.tabId, owners.held);
  return {ok: true};
}

// ----- popup (user-click route) ------------------------------------------
function fromPopup(sender) {
  // Web pages cannot reach this listener, and content scripts carry a tab.
  return sender.id === akdbxBrowser.runtime.id && !sender.tab && sender.url === akdbxBrowser.runtime.getURL("popup.html");
}

async function popupState() {
  await freshState();
  // The popup shows the code of this browser's own key, never one from the host.
  const code = await localCode((await pairingKeys()).publicKey);
  // After the identity work queued before it, on the newest broker state.
  const {current, trust, moved} = await withTrust(async () => {
    const latest = state;
    if (!latest.connected) return {current: latest, trust: null, moved: null};
    const decision = await trustNow(latest);
    return {current: latest, trust: decision, moved: await takeMove(decision)};
  });
  if (!current.connected) return {ok: true, connected: false, code};
  // Links open only on the trusted origin; the popup checks them again.
  const pairing = !current.paired && current.pairing && akdbxTrust.privateLink(current.pairing.url, "/extension/pair", trust.origin);
  const unlock = current.locked && current.unlock_url && akdbxTrust.privateLink(current.unlock_url, "/", trust.origin);
  return {ok: true, connected: true, paired: current.paired, locked: current.locked, code, origin: trust.origin,
    pairing_url: pairing || null, unlock_url: unlock || null, trust_error: trust.error, trust_reset: trust.reset,
    trust_forget: trust.forget, propose_origin: trust.propose,
    origin_changed: moved !== null, moved_from: moved ? moved.from : null, origin_learned: trust.learned};
}

// The newest broker state, asked over the port when one is open.
async function freshState() {
  await connect();
  const fresh = port ? await brokerRequest("state", {}, 5000) : null;
  if (fresh && fresh.ok) state = brokerState(fresh);
  return state;
}

async function popupConfirm(message) {
  /* The user clicked "Trust this address" in the popup for the exact origin it showed (first use). Save it only
   * while this extension trusts no origin yet and the native host, now, names that same origin in a statement
   * that verifies. Then bind the broker key through that origin's HTTPS page at once, as for any trusted origin. */
  const origin = message && message.origin;
  if (!akdbxTrust.validOrigin(origin)) return {ok: false, error: "invalid broker address; nothing saved"};
  await freshState();
  return withTrust(async () => {
    const latest = state;
    if (!latest.connected) return {ok: false, error: "The akdbx broker is not reachable; nothing saved."};
    if (akdbxTrust.trustedOrigin(await storedTrust())) {
      return {ok: false, error: "This extension already trusts a broker address; nothing saved."};
    }
    const verified = latest.identity_received ? await akdbxTrust.verifyIdentity(latest.identity) : null;
    if (!verified || verified.origin !== origin) {
      return {ok: false, error: "The broker's address changed; nothing saved. Open akdbx again."};
    }
    await akdbxBrowser.storage.local.set({[akdbxTrust.STORAGE_KEY]: akdbxTrust.originRecord(origin)});
    const decision = await trustNow(latest);
    return {ok: true, origin: decision.origin, origin_learned: decision.learned};
  });
}

// A new browser key and no open port: the next connection pairs again, as after a reset.
async function dropPairing() {
  keysPromise = null;
  await akdbxBrowser.storage.session.remove("pairing");
  const current = port;
  if (current) {
    port = null;
    sealKey = null;
    captureKey = null;
    channel = {brokerKey: null, signature: null, sealKey: null, captureKey: null};
    state = {connected: false};
    for (const resolve of waiting.values()) resolve(null);
    waiting.clear();
    try {
      current.disconnect();
    } catch {
      // Already closed.
    }
  }
}

async function popupReset() {
  // The user clicked "Reset broker trust": forget the key and its sequence number, keep the trusted origin,
  // and pair again with a new browser key. The next key is bound only through that origin's HTTPS page.
  await withTrust(async () => {
    const origin = akdbxTrust.trustedOrigin(await storedTrust());
    if (origin) await akdbxBrowser.storage.local.set({[akdbxTrust.STORAGE_KEY]: akdbxTrust.originRecord(origin)});
    else await akdbxBrowser.storage.local.remove(akdbxTrust.STORAGE_KEY);
  });
  await dropPairing();
  return {ok: true};
}

async function popupForget() {
  /* The user clicked "Forget this broker": the broker names another origin than the trusted one, and the stored
   * key did not sign that move. Delete the saved trust only while that is still the case; the next origin then
   * needs the user's confirmation again (first use), and the browser pairs again with a new key. */
  await freshState();
  const forgotten = await withTrust(async () => {
    const latest = state;
    if (!latest.connected || !(await trustNow(latest)).forget) return false;
    await akdbxBrowser.storage.local.remove([akdbxTrust.STORAGE_KEY, MOVE_KEY]);
    return true;
  });
  if (!forgotten) return {ok: false, error: "The broker names the trusted address again; nothing forgotten."};
  await dropPairing();
  return {ok: true};
}

async function popupProbe(message) {
  const tab = await akdbxBrowser.tabs.get(message.tab_id);
  if (!tab || typeof tab.url !== "string" || !tab.url.startsWith("https://")) return {ok: false, error: "open an HTTPS page first"};
  await akdbxBrowser.scripting.executeScript({target: {tabId: tab.id, allFrames: true}, files: ["content.js"]}).catch(() => {});
  const results = await akdbxBrowser.scripting.executeScript({target: {tabId: tab.id, allFrames: true},
    func: () => globalThis.__akdbxContent ? globalThis.__akdbxContent.probe() : null});
  const best = results.filter(r => r.result && r.documentId).sort((a, b) => b.result.t - a.result.t)[0];
  if (!best) return {ok: false, error: "click into a login, authenticator code, card or address field first"};
  const chain = await chainFor(tab.id, best.documentId);
  if (!chain || chain[0].url !== tab.url) return {ok: false, error: "page changed; try again"};
  const match = await brokerRequest("match", {tab_id: tab.id, document_id: best.documentId, top_url: tab.url, chain,
    kind: best.result.kind, ...(best.result.kind === "totp" ? {probe_id: best.result.id} : {})});
  if (!match || match.ok !== true) return {ok: false, error: (match && match.error) || "akdbx refused this field"};
  let entries;
  try {
    const sealed = await unseal(match.sealed, "match");
    const facts = sealed.facts;
    if (facts.tab_id !== tab.id || facts.document_id !== best.documentId || facts.kind !== best.result.kind ||
        (best.result.kind === "totp" && facts.probe_id !== best.result.id) ||
        !sameChain(facts.chain, chain) || !Array.isArray(sealed.values.entries)) throw new Error();
    entries = sealed.values.entries;
  } catch {
    return {ok: false, error: "akdbx answer could not be verified"};
  }
  const id = randomText(16);
  while (sessions.size >= MAX_SESSIONS) sessions.delete(sessions.keys().next().value);
  // A one-time-code field also lists the inbox's texts (fill extension 0.15.0): each entry keeps its own kind.
  const kinds = entries.map(e => best.result.kind === "totp" && e.kind === "sms" ? "sms" : best.result.kind);
  sessions.set(id, {tabId: tab.id, documentId: best.documentId, topUrl: tab.url, chain, probe: best.result.id,
    kind: best.result.kind, kinds, lengths: entries.map(e => e.code_length),
    roles: best.result.roles, formats: best.result.formats, handles: entries.map(e => e.handle),
    created: Date.now()});
  return {ok: true, session: id, kind: best.result.kind, origin: new URL(chain[chain.length - 1].url).origin,
    entries: entries.map(({handle, ...metadata}, index) => ({index, ...metadata}))};
}

async function popupFill(message) {
  const deadline = performance.timeOrigin + performance.now() + 4000;
  const session = sessions.get(message.session);
  sessions.delete(message.session);
  if (!session || Date.now() - session.created >= SESSION_MS || !Number.isInteger(message.index) ||
      !session.handles[message.index]) return {ok: false, error: "selection expired; open akdbx again"};
  const tab = await akdbxBrowser.tabs.get(session.tabId);
  const chain = await chainFor(session.tabId, session.documentId);
  if (!tab || tab.url !== session.topUrl || !chain || !sameChain(chain, session.chain)) {
    return {ok: false, error: "page changed; nothing filled"};
  }
  if (session.kinds[message.index] === "sms") return popupText(session, message, deadline);
  const liveOtp = (digits = null) => run(session.tabId, session.documentId, (id, size) => globalThis.__akdbxContent.liveOtp(id, size),
    [session.probe, digits]).catch(() => false);
  const expired = {ok: false, error: "code field changed or expired; open akdbx again"};
  if (session.kind === "totp" && !(await liveOtp())) return expired;
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
        !sameChain(facts.chain, session.chain) || !sameChain(facts.roles, session.roles) ||
        canonical(facts.formats) !== canonical(session.formats)) throw new Error();
    values = sealed.values;
    // The page may have navigated while the broker answered.
    const [liveTab, liveChain] = await Promise.all([akdbxBrowser.tabs.get(session.tabId), chainFor(session.tabId, session.documentId)]);
    if (!liveTab || liveTab.url !== session.topUrl || !liveChain || !sameChain(liveChain, session.chain)) throw new Error();
  } catch {
    return {ok: false, error: "akdbx answer could not be verified; nothing filled"};
  }
  try {
    if (session.kind === "totp") {
      if (!/^(?:[0-9]{6}|[0-9]{8})$/.test(values.totp) || !(await liveOtp(values.totp.length))) {
        return {ok: false, error: "code field changed or cannot accept this code; check the field"};
      }
      if (performance.timeOrigin + performance.now() >= deadline) return expired;
      await akdbxBrowser.runtime.sendMessage({op: "return-focus", session: message.session}).catch(() => {});
    }
    const result = session.kind === "totp"
      ? await run(session.tabId, session.documentId, (id, v, end) => globalThis.__akdbxContent.popupTotp(id, v, end),
          [session.probe, values, deadline])
      : await run(session.tabId, session.documentId, (id, v) => globalThis.__akdbxContent.probeFill(id, v),
          [session.probe, values]);
    return result === "filled" ? {ok: true} : {ok: false, error: result === "uncertain"
      ? "fill incomplete; check the page" : "field changed or hidden; nothing filled"};
  } catch {
    return {ok: false, error: "fill not confirmed; check the page"};
  } finally {
    for (const key of Object.keys(values)) values[key] = "";
  }
}

// A texted code chosen in the popup (fill extension 0.15.0). The popup closes first,
// so the page gets the focus back; then the agent code pin's checks pin the field
// (content.js popupCodePin). Only then does the broker spend the text, once. When
// nothing reached the field, the token sealed in that release puts the text back in the inbox.
const TEXT_FILL_MS = 10000;

async function popupText(session, message, deadline) {
  const {tabId, documentId, chain} = session;
  const handle = session.handles[message.index];
  // While the popup is still open to show it: the field can take a code of the length the broker listed.
  const length = session.lengths[message.index];
  const live = await run(tabId, documentId, (id, size) => globalThis.__akdbxContent.liveCode(id, size),
    [session.probe, length]).catch(() => false);
  if (live !== true) {
    return {ok: false, error: `code field changed or cannot take a ${Number(length) || ""}-digit code; check the field`};
  }
  await akdbxBrowser.runtime.sendMessage({op: "return-focus", session: message.session}).catch(() => {});
  let pinId = null;
  try {
    pinId = await run(tabId, documentId, (id, end) => globalThis.__akdbxContent.popupCodePin(id, end),
      [session.probe, deadline]);
  } catch {
    pinId = null;
  }
  if (typeof pinId !== "string") return {ok: false, error: "field changed or hidden; nothing filled"};
  let values = {}, restore = null;
  try {
    const released = await brokerRequest("release", {handle, tab_id: tabId, document_id: documentId,
      top_url: session.topUrl, chain, roles: session.roles, formats: session.formats});
    if (!released || released.ok !== true) return {ok: false, error: (released && released.error) || "akdbx refused this fill"};
    try {
      const sealed = await unseal(released.sealed, "release:" + handle);
      const facts = sealed.facts;
      values = sealed.values;
      restore = typeof values.restore === "string" ? values.restore : null;
      if (facts.tab_id !== tabId || facts.document_id !== documentId || facts.kind !== "sms" ||
          !sameChain(facts.chain, chain) || !sameChain(facts.roles, session.roles) ||
          canonical(facts.formats) !== canonical(session.formats) || !/^[0-9]{4,8}$/.test(values.code)) throw new Error();
      const [liveTab, liveChain] = await Promise.all([akdbxBrowser.tabs.get(tabId), chainFor(tabId, documentId)]);
      if (!liveTab || liveTab.url !== session.topUrl || !liveChain || !sameChain(liveChain, chain)) throw new Error();
    } catch {
      return {ok: false, error: "akdbx answer could not be verified; nothing filled"};
    }
    let result;
    try {
      // Before this call nothing reached the field; a timeout after it is uncertain.
      result = await bounded(run(tabId, documentId,
        (id, kind, value, maxAge) => globalThis.__akdbxContent.fill(id, kind, value, maxAge),
        [pinId, "code", {value: values.code}, TEXT_FILL_MS]), 9000);
    } catch {
      result = "uncertain";
    }
    if (result === "filled") {
      restore = null;
      return {ok: true};
    }
    if (result !== "refused") restore = null;  // It may have reached the field: the text stays spent.
    return {ok: false, error: result === "refused" ? "field changed or hidden; nothing filled" : "fill incomplete; check the page"};
  } finally {
    for (const key of Object.keys(values)) values[key] = "";
    await run(tabId, documentId, id => globalThis.__akdbxContent.release(id), [pinId]).catch(() => {});
    if (restore) await brokerRequest("restore", {token: restore}, 5000);
  }
}

akdbxBrowser.runtime.onMessage.addListener((message, sender, respond) => {
  if (!fromPopup(sender) || !message || typeof message !== "object") return false;
  const handler = {state: popupState, probe: popupProbe, fill: popupFill, "reset-trust": popupReset,
    "confirm-origin": popupConfirm, "forget-trust": popupForget}[message.op];
  if (!handler) return false;
  handler(message).then(respond, () => respond({ok: false, error: "akdbx request failed"}));
  return true;
});

connect();
if (typeof module !== "undefined") {
  module.exports = {fromPopup, chainFor, sameChain, onHost, localCode, unseal, agreeKey, pairingKeys, fill, pin, release, read,
    sealCapture, holdOwners, channelTrusted, setCaptureKey: key => { captureKey = Promise.resolve(key); },
    setChannel: value => { channel = {sealKey, captureKey, ...value}; }, channel: () => channel,
    popupState, popupReset, popupConfirm, popupForget, popupText, trustIdle: () => trustQueue, setSealKey: key => { sealKey = Promise.resolve(key); }, state: () => state};
}
