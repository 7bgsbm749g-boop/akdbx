/* Node tests for the akdbx fill extension's gesture and sender checks.
 * Mocked Chrome APIs only; no browser, broker or value is involved. */
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");
const root = path.join(__dirname, "../src/akdbx/fill_extension");
const {userGesture, privateLink} = require(path.join(root, "popup.js"));

function loadBackground() {
  const posted = [];
  const listeners = {};
  const event = name => ({addListener: fn => { listeners[name] = fn; }});
  const port = {postMessage: m => posted.push(m), onMessage: event("port.message"), onDisconnect: event("port.disconnect")};
  const chrome = {
    runtime: {id: "jjoamaejjkldcjcpgncoomoaagdfimhg", getURL: p => "chrome-extension://jjoamaejjkldcjcpgncoomoaagdfimhg/" + p,
      connectNative: () => port, onStartup: event("startup"), onInstalled: event("installed"),
      onMessage: event("message"), lastError: undefined},
    storage: {session: {setAccessLevel: () => {}, get: async () => ({}), set: async () => {}}},
    alarms: {create: () => {}, clear: () => {}, onAlarm: event("alarm")},
    contextMenus: {create: () => {}, onClicked: event("menu")},
    action: {openPopup: async () => {}},
    tabs: {get: async () => null, query: async () => []},
    webNavigation: {getAllFrames: async () => []},
    scripting: {executeScript: async () => []},
  };
  const sandbox = {chrome, importScripts: () => {}, crypto: globalThis.crypto, btoa, atob, setTimeout, clearTimeout, URL, TextEncoder,
    TextDecoder, Uint8Array, module: {exports: {}}};
  vm.runInNewContext(fs.readFileSync(path.join(root, "background.js"), "utf8"), sandbox);
  return {exports: sandbox.module.exports, listeners, posted, chrome};
}

test("popup fills only from a trusted click with user activation", () => {
  assert.equal(userGesture({isTrusted: true}, {isActive: true}), true);
  assert.equal(userGesture({isTrusted: false}, {isActive: true}), false);  // Synthetic click.
  assert.equal(userGesture({isTrusted: true}, {isActive: false}), false);  // No activation.
  assert.equal(userGesture(null, {isActive: true}), false);
});

test("popup opens private links only on the configured broker origin", () => {
  const trusted = "https://localhost:9443";
  assert.equal(privateLink("https://localhost:9443/extension/pair?token=x", "/extension/pair", trusted),
    "https://localhost:9443/extension/pair?token=x");
  assert.equal(privateLink("https://look-alike.example/extension/pair?token=x", "/extension/pair", trusted), null);
  assert.equal(privateLink("https://localhost:9443/extension/pair?token=x", "/extension/pair", null), null);
  assert.equal(privateLink("http://localhost:9443/extension/pair?token=x", "/extension/pair", "http://localhost:9443"), null);
  assert.equal(privateLink("https://u:p@localhost:9443/extension/pair", "/extension/pair", trusted), null);
  assert.equal(privateLink("javascript:alert(1)", "/extension/pair", trusted), null);
});

test("agent fill trusts only the sealed facts and refuses a forged destination", async () => {
  const {exports, chrome} = loadBackground();
  const key = await crypto.subtle.generateKey({name: "AES-GCM", length: 256}, false, ["encrypt", "decrypt"]);
  exports.setSealKey(key);
  // The broker authorized a bank page; the browser's tab 7 shows another site.
  const facts = {tab_id: 7, document_id: "DOC", chain: [{document_id: "DOC", url: "https://bank.example/login"}],
    kind: "password", pin_id: "p".repeat(32)};
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({name: "AES-GCM", iv, additionalData: new TextEncoder().encode("fill:" + facts.pin_id)},
    key, new TextEncoder().encode(JSON.stringify({values: {mode: "password", password: "synthetic"}, facts})));
  const b64 = bytes => Buffer.from(bytes).toString("base64url");
  chrome.tabs.get = async () => ({id: 7, url: "https://evil.example/login"});
  chrome.webNavigation.getAllFrames = async () => [{frameId: 0, documentId: "DOC", url: "https://evil.example/login"}];
  const scripts = [];
  chrome.scripting.executeScript = async details => { scripts.push(details); return [{result: true}]; };
  // A host in the middle claims the evil page is the authorized one.
  const result = await exports.fill({pin_id: facts.pin_id, tab_id: 7, document_id: "DOC", kind: "password",
    top_url: "https://evil.example/login", chain: [{document_id: "DOC", url: "https://evil.example/login"}],
    sealed: {iv: b64(iv), data: b64(data)}, max_age_ms: 1000});
  assert.equal(result.state, "refused");
  assert.ok(scripts.every(s => !String(s.func).includes("__akdbxContent.fill(")));
});

test("service worker accepts popup requests only from its own popup page", async () => {
  const {exports, listeners} = loadBackground();
  const popup = {id: "jjoamaejjkldcjcpgncoomoaagdfimhg", url: "chrome-extension://jjoamaejjkldcjcpgncoomoaagdfimhg/popup.html"};
  assert.equal(exports.fromPopup(popup), true);
  assert.equal(exports.fromPopup({...popup, tab: {id: 1}}), false);            // A content script.
  assert.equal(exports.fromPopup({...popup, url: "https://example.com/"}), false);
  assert.equal(exports.fromPopup({...popup, id: "a".repeat(32)}), false);       // Another extension.
  let answered = false;
  const kept = listeners.message({op: "fill", session: "s", index: 0}, {...popup, tab: {id: 1}}, () => { answered = true; });
  assert.equal(kept, false);
  assert.equal(answered, false);
});

test("service worker sends only its public key, and refuses unsealed or foreign values", async () => {
  const {exports, posted} = loadBackground();
  for (let i = 0; i < 50 && !posted.length; i++) await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(posted.length, 1);
  assert.deepEqual(Object.keys(posted[0]).sort(), ["protocol", "public_key", "type"]);
  assert.match(posted[0].public_key, /^[A-Za-z0-9_-]{87}$/);
  assert.match(await exports.localCode(posted[0].public_key), /^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
  // No agreed key yet: nothing can be unsealed.
  await assert.rejects(exports.unseal({iv: "AAAAAAAAAAAAAAAA", data: "AAAA"}, "fill:x"));
  // A key agreed with another party fails AES-GCM authentication.
  const other = await crypto.subtle.generateKey({name: "AES-GCM", length: 256}, false, ["encrypt", "decrypt"]);
  exports.setSealKey(other);
  await assert.rejects(exports.unseal({iv: "AAAAAAAAAAAAAAAA", data: "AAAAAAAAAAAAAAAAAAAAAAAA"}, "fill:x"));
});

test("frame chains compare exactly", () => {
  const {exports} = loadBackground();
  const a = [{document_id: "A", url: "https://example.com/"}];
  assert.equal(exports.sameChain(a, [{document_id: "A", url: "https://example.com/"}]), true);
  assert.equal(exports.sameChain(a, [{document_id: "B", url: "https://example.com/"}]), false);
});

test("agent fill refuses a pin whose field spec differs from the sealed one", async () => {
  const {exports, chrome} = loadBackground();
  const key = await crypto.subtle.generateKey({name: "AES-GCM", length: 256}, false, ["encrypt", "decrypt"]);
  exports.setSealKey(key);
  const chain = [{document_id: "DOC", url: "https://shop.example/checkout"}];
  chrome.tabs.get = async () => ({id: 7, url: chain[0].url});
  chrome.webNavigation.getAllFrames = async () => [{frameId: 0, documentId: "DOC", url: chain[0].url}];
  const scripts = [];
  chrome.scripting.executeScript = async details => {
    scripts.push(details);
    return [{result: details.files ? undefined : "q".repeat(32)}];
  };
  // The relay asked the browser to pin the name field...
  const pinned = await exports.pin({tab_id: 7, document_id: "DOC", top_url: chain[0].url, frame_url: null, kind: "card",
    spec: {selector: "#name", field: "cc-name", processor: null}});
  assert.equal(pinned.ok, true);
  // ...but the broker authorized and sealed a number fill for "#number".
  const facts = {tab_id: 7, document_id: "DOC", chain, kind: "card", pin_id: pinned.pin_id, max_age_ms: 1000,
    spec: {selector: "#number", field: "cc-number", processor: null}};
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({name: "AES-GCM", iv, additionalData: new TextEncoder().encode("fill:" + pinned.pin_id)},
    key, new TextEncoder().encode(JSON.stringify({values: {value: "4111111111111111"}, facts})));
  const b64 = bytes => Buffer.from(bytes).toString("base64url");
  const count = scripts.length;
  const result = await exports.fill({pin_id: pinned.pin_id, sealed: {iv: b64(iv), data: b64(data)}});
  assert.equal(result.state, "refused");
  assert.ok(scripts.slice(count).every(s => !String(s.func).includes("__akdbxContent.fill(")));
});

test("popup compares origins as the browser serializes them", () => {
  assert.equal(privateLink("https://localhost/extension/pair?token=x", "/extension/pair", "https://localhost:443"),
    "https://localhost/extension/pair?token=x");
});

test("released pins do not evict a live pin's spec record", async () => {
  const {exports, chrome} = loadBackground();
  const key = await crypto.subtle.generateKey({name: "AES-GCM", length: 256}, false, ["encrypt", "decrypt"]);
  exports.setSealKey(key);
  const chain = [{document_id: "DOC", url: "https://shop.example/checkout"}];
  chrome.tabs.get = async () => ({id: 7, url: chain[0].url});
  chrome.webNavigation.getAllFrames = async () => [{frameId: 0, documentId: "DOC", url: chain[0].url}];
  let next = 0;
  chrome.scripting.executeScript = async details => {
    if (details.files) return [{}];
    const source = String(details.func);
    if (source.includes(".pin(")) return [{result: String(next++).padStart(32, "0")}];
    return [{result: source.includes(".fill(") ? "filled" : true}];
  };
  const spec = {selector: "#number", field: "cc-number", processor: null};
  const request = {tab_id: 7, document_id: "DOC", top_url: chain[0].url, frame_url: null, kind: "card", spec};
  const live = await exports.pin(request);
  for (let i = 0; i < 33; i++) {
    const other = await exports.pin(request);
    await exports.release({tab_id: 7, document_id: "DOC", pin_id: other.pin_id});
  }
  const facts = {tab_id: 7, document_id: "DOC", chain, kind: "card", pin_id: live.pin_id, max_age_ms: 1000, spec};
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({name: "AES-GCM", iv, additionalData: new TextEncoder().encode("fill:" + live.pin_id)},
    key, new TextEncoder().encode(JSON.stringify({values: {value: "4111111111111111"}, facts})));
  const b64 = bytes => Buffer.from(bytes).toString("base64url");
  const result = await exports.fill({pin_id: live.pin_id, sealed: {iv: b64(iv), data: b64(data)}});
  assert.equal(result.state, "filled");
});
