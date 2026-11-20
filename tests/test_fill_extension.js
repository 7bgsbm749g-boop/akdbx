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
  const sandbox = {chrome, crypto: globalThis.crypto, btoa, atob, setTimeout, clearTimeout, URL, TextEncoder,
    TextDecoder, Uint8Array, module: {exports: {}}};
  vm.runInNewContext(fs.readFileSync(path.join(root, "background.js"), "utf8"), sandbox);
  return {exports: sandbox.module.exports, listeners, posted};
}

test("popup fills only from a trusted click with user activation", () => {
  assert.equal(userGesture({isTrusted: true}, {isActive: true}), true);
  assert.equal(userGesture({isTrusted: false}, {isActive: true}), false);  // Synthetic click.
  assert.equal(userGesture({isTrusted: true}, {isActive: false}), false);  // No activation.
  assert.equal(userGesture(null, {isActive: true}), false);
});

test("popup opens only HTTPS private links on the expected path", () => {
  assert.equal(privateLink("https://localhost:9443/extension/pair?token=x", "/extension/pair"),
    "https://localhost:9443/extension/pair?token=x");
  assert.equal(privateLink("http://localhost:9443/extension/pair?token=x", "/extension/pair"), null);
  assert.equal(privateLink("https://u:p@localhost/extension/pair", "/extension/pair"), null);
  assert.equal(privateLink("javascript:alert(1)", "/extension/pair"), null);
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
