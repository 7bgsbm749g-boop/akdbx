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
 * the built origin, then the broker identity read over HTTPS from that origin
 * when the host first sends it, and the origin changes that identity signed.
 * Every identity the host sends is checked when it arrives, one at a time.
 */
"use strict";
importScripts("config.js", "trust.js");
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

// Only extension pages may read session storage; content scripts may not.
chrome.storage.session.setAccessLevel?.({accessLevel: "TRUSTED_CONTEXTS"});
// The broker trust lives in local storage: keep content scripts out of it too where the browser allows it.
try {
  Promise.resolve(chrome.storage.local.setAccessLevel?.({accessLevel: "TRUSTED_CONTEXTS"})).catch(() => {});
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

// From fill extension 0.4.0 the keys also bind this extension's own version: a
// host that reports another version to the broker makes every sealed message fail.
function keyInfo(label) {
  return label + "/" + chrome.runtime.getManifest().version;
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
    const trusted = akdbxTrust.trustedKey(await storedTrust(), builtConfig());
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
    captureKey = null;
    channel = {brokerKey: null, signature: null, sealKey: null, captureKey: null};
    state = {connected: false};
    for (const resolve of waiting.values()) resolve(null);
    waiting.clear();
    scheduleReconnect();
  });
  // The version lets `akdbx status` show a stale unpacked extension after an update.
  current.postMessage({type: "hello", protocol: PROTOCOL, public_key: key, version: chrome.runtime.getManifest().version});
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

// What `akdbx extension build` wrote into config.js: the first trusted origin and this build's random ID.
function builtConfig() {
  return {origin: globalThis.AKDBX_TRUSTED_ORIGIN ?? null, build: globalThis.AKDBX_BUILD_ID ?? null};
}

// A verified signed move (old origin -> new origin), kept until a popup shows it once.
const MOVE_KEY = "broker_trust_moved";

async function storedTrust() {
  return (await chrome.storage.local.get(akdbxTrust.STORAGE_KEY))[akdbxTrust.STORAGE_KEY] ?? null;
}

// Run only inside withTrust: decide against the saved record as it is now, so an older
// statement can never replace a newer saved sequence number.
async function trustNow(current) {
  const stored = await storedTrust();
  const verified = current.identity_received ? await akdbxTrust.verifyIdentity(current.identity) : null;
  const built = builtConfig();
  const received = current.identity_received === true;
  let decision = akdbxTrust.decide(stored, built, verified, received);
  if (decision.fetch) {
    // A first key: read the statement over HTTPS from the trusted origin.
    decision = akdbxTrust.decide(stored, built, verified, received, await akdbxTrust.fetchIdentity(decision.fetch));
  }
  if (decision.store) {
    const items = {[akdbxTrust.STORAGE_KEY]: decision.store};
    if (decision.changed) items[MOVE_KEY] = {from: decision.from, to: decision.origin};
    await chrome.storage.local.set(items);
  }
  return decision;
}

// The move notice to show now, or null. While the decision has an error, the popup shows only that warning
// and the notice waits; the next decision with no error clears it, and shows it if it names the trusted origin.
async function takeMove(trust) {
  if (trust.error) return null;
  const notice = (await chrome.storage.local.get(MOVE_KEY))[MOVE_KEY];
  if (!notice) return null;
  await chrome.storage.local.remove(MOVE_KEY);
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
  if (message.op === "read") return read(message);
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

// ----- settings -------------------------------------------------------------
// The options page writes them to local storage, which content scripts cannot reach (see above).
const SETTINGS_KEY = "settings";

// Enhanced security (experimental, off by default): the cover checks below. An
// unreadable setting counts as on: the check then runs, and refuses where the
// browser did not grant the screenshot access.
async function enhancedSecurity() {
  try {
    const settings = (await chrome.storage.local.get(SETTINGS_KEY))[SETTINGS_KEY];
    return Boolean(settings && settings.enhanced_security === true);
  } catch {
    return true;
  }
}

// ----- covers: the browser's occlusion test, then a pixel challenge ------------
// With enhanced security on, a card, address or read pin needs proof that nothing is painted over the field
// or the secret. content.js clear() asks the browser itself (IntersectionObserver
// v2: the occlusion hit test that CDP uses, over the whole element, through every
// parent frame). That test is all-or-nothing, so a floating label or the
// transparent backdrop of a popover elsewhere also fails it. Then one pixel
// challenge decides: a user-origin rule (it beats every author rule) paints only
// the pinned element in a random colour for a moment, and a screenshot of the tab
// must show that colour at the checked points. Whatever covers a point, in any
// document, in the top layer or in a parent frame, changes its pixels. The
// screenshot needs the optional <all_urls> host access, which the options page
// requests when the user turns the setting on.
const STEP_MS = 3000, CAPTURE_GAP_MS = 550, COLOUR_TOLERANCE = 2, MAX_CHALLENGE_POINTS = 600;
// The screenshot API allows two calls each second: one challenge at a time, spaced.
let challengeQueue = Promise.resolve();
let lastCapture = 0;

function bounded(promise, ms) {
  let timer;
  return Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("timeout")), ms); })])
    .finally(() => clearTimeout(timer));
}

// "pixels": the checked points show the element, though something overlaps its
// box. "both": the occlusion test is also clear. null: covered, or no proof.
// Every card, address and read check takes the pixels: the occlusion test misses
// paint that the element's own ancestors draw over it (a negative-offset outline,
// also over a processor iframe), and text hidden under its own element's
// ::before or ::after is not occluded for any hit test, CDP's too.
async function seen(tabId, chain, pinId, guardId) {
  const documentId = chain[chain.length - 1].document_id;
  try {
    const clear = (await bounded(run(tabId, documentId, id => globalThis.__akdbxContent.clear(id), [pinId]), STEP_MS)) === true;
    // A page that stops answering cannot hold the queue for other tabs.
    const next = challengeQueue.then(() => bounded(challenge(tabId, chain, pinId, guardId), 8 * STEP_MS));
    challengeQueue = next.catch(() => {});
    if ((await next) !== true) return null;
    return clear ? "both" : "pixels";
  } catch {
    return null;
  }
}

// Mid-range channels: no page default, and far from the white and black ends.
function randomColour() {
  return Array.from(crypto.getRandomValues(new Uint8Array(3)), b => 40 + b % 176);
}

// Paint the whole padding box and the text in one colour, at once, whatever the page says.
function challengeCSS(path, colour, outlineColour) {
  const paint = `color:${colour}!important;-webkit-text-fill-color:${colour}!important;-webkit-text-stroke-color:${colour}!important;` +
    `text-decoration-color:${colour}!important;text-shadow:none!important;`;
  // An outline paints over the content: give it another colour, so one over a checked point refuses.
  return `${path}{box-shadow:inset 0 0 0 9999px ${colour}!important;caret-color:${colour}!important;` + paint +
    `outline-color:${outlineColour}!important;` +
    `transition:none!important;forced-color-adjust:none!important}` +
    `${path}::placeholder{${paint}opacity:1!important}${path}::selection{${paint}background-color:${colour}!important}`;
}

async function challenge(tabId, chain, pinId, guardId) {
  const documentId = chain[chain.length - 1].document_id;
  // Where the element is now, in the top viewport; a processor frame's point is
  // mapped by the merchant-side guard.
  const locate = async () => {
    const spec = await bounded(run(tabId, documentId, id => globalThis.__akdbxContent.challengeSpec(id), [pinId]), STEP_MS);
    if (!spec || typeof spec.path !== "string" || !/^:root(?:>:nth-child\([0-9]{1,6}\)){1,64}$/.test(spec.path)) return null;
    if (!spec.local) return {spec, placed: spec};
    if (!guardId || chain.length < 2) return null;
    const placed = await bounded(run(tabId, chain[chain.length - 2].document_id,
      (id, point) => globalThis.__akdbxContent.guardPoint(id, point), [guardId, spec.local]), STEP_MS);
    return {spec, placed};
  };
  const found = await locate();
  if (!found) return false;
  const {spec, placed} = found;
  const finite = value => typeof value === "number" && Number.isFinite(value);
  if (!placed || !Array.isArray(placed.points) || !placed.points.length || placed.points.length > MAX_CHALLENGE_POINTS ||
      !placed.points.every(point => Array.isArray(point) && point.length === 2 && point.every(finite)) ||
      !Array.isArray(placed.view) || placed.view.length !== 2 || !placed.view.every(value => finite(value) && value > 0)) {
    return false;
  }
  const tab = await bounded(chrome.tabs.get(tabId), STEP_MS);
  if (!tab || !tab.active) return false;
  const rgb = randomColour();
  const colour = `rgb(${rgb.join(", ")})`;
  // The outline colour is 128 levels away from the challenge colour in every channel.
  const css = challengeCSS(spec.path, colour, `rgb(${rgb.map(c => (c + 128) % 256).join(", ")})`);
  const target = {tabId, documentIds: [documentId]};
  try {
    await bounded(chrome.scripting.insertCSS({target, css, origin: "USER"}), STEP_MS);
    // A screenshot can be one frame behind the page: look twice before refusing.
    for (let attempt = 0; attempt < 2; ++attempt) {
      if ((await bounded(run(tabId, documentId, () => globalThis.__akdbxContent.painted()), STEP_MS)) !== true) return false;
      const wait = lastCapture + CAPTURE_GAP_MS - Date.now();
      if (wait > 0) await pause(wait);
      lastCapture = Date.now();
      const image = await bounded(chrome.tabs.captureVisibleTab(tab.windowId, {format: "png"}), STEP_MS);
      // The colour in the screenshot counts only if the rule was on the pinned element, still valid, at that time.
      const held = await bounded(run(tabId, documentId,
        (id, path, value) => globalThis.__akdbxContent.challengeHeld(id, path, value), [pinId, spec.path, colour]), STEP_MS);
      if (held !== true) return false;
      // The points must still be where the element is: a layout shift while the
      // screenshot was taken makes the old points meaningless.
      const again = await locate();
      if (!again || again.spec.path !== spec.path ||
          JSON.stringify([again.placed.points, again.placed.view]) !== JSON.stringify([placed.points, placed.view])) return false;
      if (await shows(image, placed.points, placed.view, rgb)) return true;
    }
    return false;
  } finally {
    await bounded(chrome.scripting.removeCSS({target, css, origin: "USER"}), STEP_MS).catch(() => {});
  }
}

// True when every point of the screenshot, with its neighbours, has the challenge colour.
// The image stays in this worker and is dropped here; no pixel is stored or sent.
async function shows(image, points, view, rgb) {
  if (typeof image !== "string" || !image.startsWith("data:image/png;base64,")) return false;
  const bytes = Uint8Array.from(atob(image.slice(image.indexOf(",") + 1)), c => c.charCodeAt(0));
  const bitmap = await createImageBitmap(new Blob([bytes], {type: "image/png"}));
  try {
    // Device pixels for each CSS pixel of the top viewport; both axes must agree.
    const scale = bitmap.width / view[0];
    if (!(scale >= 0.25 && scale <= 8) || Math.abs(bitmap.height / view[1] - scale) > 0.05 * scale) return false;
    const context = new OffscreenCanvas(bitmap.width, bitmap.height).getContext("2d", {willReadFrequently: true});
    context.drawImage(bitmap, 0, 0);
    const reach = Math.max(1, Math.round(scale));
    return points.every(([x, y]) => {
      const left = Math.round(x * scale) - reach, top = Math.round(y * scale) - reach, size = 2 * reach + 1;
      if (left < 0 || top < 0 || left + size > bitmap.width || top + size > bitmap.height) return false;
      const data = context.getImageData(left, top, size, size).data;
      for (let i = 0; i < data.length; i += 4) {
        if (data[i + 3] !== 255 || Math.abs(data[i] - rgb[0]) > COLOUR_TOLERANCE ||
            Math.abs(data[i + 1] - rgb[1]) > COLOUR_TOLERANCE || Math.abs(data[i + 2] - rgb[2]) > COLOUR_TOLERANCE) return false;
      }
      return true;
    });
  } finally {
    bitmap.close();
  }
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
  const tab = await chrome.tabs.get(message.tab_id);
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
  const hit = message.kind !== "password" && await enhancedSecurity();
  let pinId = null;
  try {
    await inject(message.tab_id, message.document_id);
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
  // With enhanced security, nothing may be painted over the field or the secret (see seen()).
  if (hit && !(await seen(message.tab_id, chain, pinId, processorGuards.get(pinId)))) {
    await release({tab_id: message.tab_id, document_id: message.document_id, pin_id: pinId, chain});
    await releaseOwners(message.tab_id, owners);
    return {ok: false};
  }
  while (pinSpecs.size >= 32) pinSpecs.delete(pinSpecs.keys().next().value);
  pinSpecs.set(pinId, pinned);
  if (owners.length) ownerGuards.set(pinId, {tabId: message.tab_id, held: owners});
  return {ok: true, pin_id: pinId, chain};
}

// The facts the broker sealed must equal what this browser reports now.
async function currentFacts(message, facts) {
  const tab = await chrome.tabs.get(facts.tab_id);
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
    let value;
    try {
      // With "both", content.js still runs its own fresh occlusion test in the task of the read.
      const cover = chain.length !== 1 ? null : await enhancedSecurity() ? await seen(facts.tab_id, chain, facts.pin_id, null) : "off";
      value = !cover ? null : await bounded(run(facts.tab_id, facts.document_id,
        (id, maxAge, how) => globalThis.__akdbxContent.read(id, maxAge, how),
        [facts.pin_id, facts.max_age_ms, cover]), STEP_MS);
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
    const hit = (facts.kind === "card" || facts.kind === "identity") && await enhancedSecurity();
    let result = "refused";
    // "off": no cover check; "pixels" or "both": see seen(); null: covered.
    let cover = "off";
    if (facts.kind === "card" && guardId && !(await processorCheck(facts.tab_id, chain, facts.pin_id, guardId).catch(() => false))) {
      cover = null;
    } else if (hit) {
      cover = await seen(facts.tab_id, chain, facts.pin_id, guardId);
    }
    if (cover) {
      try {
        // Before this call nothing reached the field; a timeout after it is uncertain.
        result = await bounded(run(facts.tab_id, facts.document_id,
          (id, kind, value, maxAge, how) => globalThis.__akdbxContent.fill(id, kind, value, maxAge, how),
          [facts.pin_id, facts.kind, values, facts.max_age_ms, cover]), 9000);
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
  return sender.id === chrome.runtime.id && !sender.tab && sender.url === chrome.runtime.getURL("popup.html");
}

async function popupState() {
  await connect();
  const fresh = port ? await brokerRequest("state", {}, 5000) : null;
  if (fresh && fresh.ok) state = brokerState(fresh);
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
    origin_changed: moved !== null, moved_from: moved ? moved.from : null, origin_learned: trust.learned};
}

async function popupReset() {
  // The user clicked "Reset broker trust": forget the key and its sequence number, keep the trusted origin,
  // and pair again with a new browser key. The next key is bound only through that origin's HTTPS page.
  await withTrust(async () => {
    const origin = akdbxTrust.trustedOrigin(await storedTrust(), builtConfig());
    if (origin) await chrome.storage.local.set({[akdbxTrust.STORAGE_KEY]: akdbxTrust.saveRecord({reset: true, origin}, builtConfig())});
    else await chrome.storage.local.remove(akdbxTrust.STORAGE_KEY);
  });
  keysPromise = null;
  await chrome.storage.session.remove("pairing");
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
  return {ok: true};
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
  let entries;
  try {
    const sealed = await unseal(match.sealed, "match");
    const facts = sealed.facts;
    if (facts.tab_id !== tab.id || facts.document_id !== best.documentId || facts.kind !== best.result.kind ||
        !sameChain(facts.chain, chain) || !Array.isArray(sealed.values.entries)) throw new Error();
    entries = sealed.values.entries;
  } catch {
    return {ok: false, error: "akdbx answer could not be verified"};
  }
  const id = randomText(16);
  while (sessions.size >= MAX_SESSIONS) sessions.delete(sessions.keys().next().value);
  sessions.set(id, {tabId: tab.id, documentId: best.documentId, topUrl: tab.url, chain, probe: best.result.id,
    kind: best.result.kind,
    roles: best.result.roles, formats: best.result.formats, handles: entries.map(e => e.handle),
    created: Date.now()});
  return {ok: true, session: id, kind: best.result.kind, origin: new URL(chain[chain.length - 1].url).origin,
    entries: entries.map(({handle, ...metadata}, index) => ({index, ...metadata}))};
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
        !sameChain(facts.chain, session.chain) || !sameChain(facts.roles, session.roles) ||
        canonical(facts.formats) !== canonical(session.formats)) throw new Error();
    values = sealed.values;
    // The page may have navigated while the broker answered.
    const [liveTab, liveChain] = await Promise.all([chrome.tabs.get(session.tabId), chainFor(session.tabId, session.documentId)]);
    if (!liveTab || liveTab.url !== session.topUrl || !liveChain || !sameChain(liveChain, session.chain)) throw new Error();
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
  const handler = {state: popupState, probe: popupProbe, fill: popupFill, "reset-trust": popupReset}[message.op];
  if (!handler) return false;
  handler(message).then(respond, () => respond({ok: false, error: "akdbx request failed"}));
  return true;
});

connect();
if (typeof module !== "undefined") {
  module.exports = {fromPopup, chainFor, sameChain, onHost, localCode, unseal, agreeKey, pairingKeys, fill, pin, release, read,
    sealCapture, holdOwners, channelTrusted, setCaptureKey: key => { captureKey = Promise.resolve(key); },
    setChannel: value => { channel = {sealKey, captureKey, ...value}; }, channel: () => channel,
    popupState, popupReset, trustIdle: () => trustQueue, setSealKey: key => { sealKey = Promise.resolve(key); }, state: () => state};
}
