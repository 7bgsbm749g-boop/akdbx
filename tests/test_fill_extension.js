/* Node tests for the akdbx fill extension's gesture and sender checks.
 * Mocked Chrome APIs only; no browser, broker or value is involved. */
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");
const root = path.join(__dirname, "../src/akdbx/fill_extension");
const {userGesture, privateLink, versionText} = require(path.join(root, "popup.js"));
const trust = require(path.join(root, "trust.js"));
const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));
// Origin statements that src/akdbx/broker_identity.py signed (tests/test_broker_identity.py).
const signed = JSON.parse(fs.readFileSync(path.join(__dirname, "origin_statement_fixture.json"), "utf8"));
const copy = value => JSON.parse(JSON.stringify(value));

function loadBackground({builtOrigin, local = {}, answer} = {}) {
  const posted = [];
  const listeners = {};
  const event = name => ({addListener: fn => { listeners[name] = fn; }});
  const area = store => ({get: async key => (key in store ? {[key]: copy(store[key])} : {}),
    set: async items => { Object.assign(store, copy(items)); }, remove: async key => { delete store[key]; },
    setAccessLevel: async () => {}});
  const session = {pairing: undefined};
  delete session.pairing;
  const port = {postMessage: m => {
    posted.push(m);
    // A scripted broker answers the popup's state request through the port.
    if (answer && m.type === "request") setTimeout(() => listeners["port.message"]({type: "response", id: m.id, result: answer(m)}));
  }, onMessage: event("port.message"), onDisconnect: event("port.disconnect"), disconnect: () => { port.disconnected = true; }};
  const chrome = {
    runtime: {id: "jjoamaejjkldcjcpgncoomoaagdfimhg", getURL: p => "chrome-extension://jjoamaejjkldcjcpgncoomoaagdfimhg/" + p,
      getManifest: () => manifest, connectNative: () => port, onStartup: event("startup"), onInstalled: event("installed"),
      onMessage: event("message"), lastError: undefined},
    storage: {session: area(session), local: area(local)},
    alarms: {create: () => {}, clear: () => {}, onAlarm: event("alarm")},
    contextMenus: {create: () => {}, onClicked: event("menu")},
    action: {openPopup: async () => {}},
    tabs: {get: async () => null, query: async () => []},
    webNavigation: {getAllFrames: async () => []},
    scripting: {executeScript: async () => []},
  };
  const sandbox = {chrome, crypto: globalThis.crypto, btoa, atob, setTimeout, clearTimeout, URL, TextEncoder,
    TextDecoder, Uint8Array, module: {exports: {}}, AKDBX_TRUSTED_ORIGIN: builtOrigin ?? null};
  vm.createContext(sandbox);
  sandbox.importScripts = (...names) => {
    for (const name of names.filter(n => n !== "config.js")) {
      vm.runInContext(fs.readFileSync(path.join(root, name), "utf8"), sandbox);
    }
  };
  vm.runInContext(fs.readFileSync(path.join(root, "background.js"), "utf8"), sandbox);
  return {exports: sandbox.module.exports, listeners, posted, chrome, local, session, port};
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

test("service worker sends only its public key and version, and refuses unsealed or foreign values", async () => {
  const {exports, posted} = loadBackground();
  for (let i = 0; i < 50 && !posted.length; i++) await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(posted.length, 1);
  assert.deepEqual(Object.keys(posted[0]).sort(), ["protocol", "public_key", "type", "version"]);
  assert.equal(posted[0].version, manifest.version);
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

test("popup footer shows the extension's own version", () => {
  assert.match(manifest.version, /^\d+\.\d+\.\d+$/);
  assert.equal(versionText(manifest), "akdbx extension " + manifest.version);
  assert.equal(versionText({version: "<b>1</b>"}), "akdbx extension");
  assert.equal(versionText(null), "akdbx extension");
});

// ----- broker trust: signed origin statements ---------------------------------------
const LOCAL = "https://localhost:9443";
const RELAY = "https://abcdefghijkl.akdbx.link";
const recordOf = message => ({v: 1, public_key: message.public_key, key_id: message.statement.key_id,
  origin: message.statement.origin, seq: message.statement.seq});

test("the canonical statement bytes equal the ones Python signs", () => {
  assert.equal(trust.canonical(signed.first.statement), signed.canonical);
  // Key order in the message does not matter; the bytes are always sorted.
  const reordered = {v: 1, seq: 1, origin: LOCAL, key_id: signed.first.statement.key_id, type: "akdbx-origin"};
  assert.equal(trust.canonical(reordered), signed.canonical);
});

test("a statement signed by the Python broker verifies", async () => {
  const {v, ...facts} = recordOf(signed.first);
  assert.deepEqual(await trust.verifyIdentity(signed.first), facts);
  assert.equal((await trust.verifyIdentity(signed.moved)).origin, RELAY);
  assert.equal((await trust.verifyIdentity(signed.ipv6)).origin, "https://[::1]:9443");
});

test("a changed, malformed or misnamed statement does not verify", async () => {
  const changes = [
    m => { m.statement.origin = RELAY; },                         // Origin changed after signing.
    m => { m.statement.seq = 9; },                                // Sequence changed after signing.
    m => { m.statement.extra = true; },
    m => { delete m.signature; },
    m => { m.signature = m.signature.slice(0, 80); },
    m => { m.public_key = signed.other_key.public_key; },        // Another key: the key id no longer matches.
    m => { m.statement.seq = 2 ** 53; },
    m => { m.statement.seq = "1"; },
    m => { m.statement.v = 2; },
  ];
  for (const change of changes) {
    const message = copy(signed.first);
    change(message);
    assert.equal(await trust.verifyIdentity(message), null);
  }
  assert.equal(await trust.verifyIdentity(signed.bad_origin), null);    // Signed, but the origin has a path.
  assert.equal(await trust.verifyIdentity(signed.wrong_key_id), null);  // Signed, but names another key.
  for (const value of [null, [], "x", {statement: signed.first.statement}]) assert.equal(await trust.verifyIdentity(value), null);
});

test("only exact HTTPS origins are valid", () => {
  for (const good of [LOCAL, RELAY, "https://localhost", "https://[::1]:9443", "https://127.0.0.1:9443"]) {
    assert.equal(trust.validOrigin(good), true, good);
  }
  for (const bad of ["http://localhost:9443", LOCAL + "/", LOCAL + "/x", LOCAL + "?a", "https://u:p@localhost",
    "https://localhost:443", "https://LOCALHOST", "https://exa mple.test", "https://xn--", "javascript:alert(1)", null, 7]) {
    assert.equal(trust.validOrigin(bad), false, String(bad));
  }
});

test("first pairing learns the key, also for the built origin, and never against it", async () => {
  const first = await trust.verifyIdentity(signed.first);
  const learned = trust.decide(null, null, first, true);
  assert.equal(learned.learned, true);
  assert.equal(learned.origin, LOCAL);
  assert.deepEqual(learned.store, recordOf(signed.first));
  assert.deepEqual(trust.decide(null, LOCAL, first, true).store, recordOf(signed.first));
  // Built for one origin, the broker names another: keep the built origin, learn nothing, offer the reset.
  const moved = await trust.verifyIdentity(signed.moved);
  const refused = trust.decide(null, LOCAL, moved, true);
  assert.equal(refused.origin, LOCAL);
  assert.equal(refused.store, undefined);
  assert.equal(refused.reset, true);
  assert.match(refused.error, /built for https:\/\/localhost:9443/);
  // After the user's reset, the built origin no longer binds the first pairing.
  assert.equal(trust.decide({v: 1, reset: true}, LOCAL, moved, true).origin, RELAY);
  // An older broker sends no statement: the built origin works as before; no origin without one.
  assert.equal(trust.decide(null, LOCAL, null, false).origin, LOCAL);
  assert.equal(trust.decide(null, null, null, false).origin, null);
  // A statement that does not verify is not learned.
  const invalid = trust.decide(null, null, null, true);
  assert.equal(invalid.origin, null);
  assert.equal(invalid.store, undefined);
  assert.ok(invalid.error);
});

test("a signed origin change with a higher sequence replaces the stored origin", async () => {
  const decision = trust.decide(recordOf(signed.first), LOCAL, await trust.verifyIdentity(signed.moved), true);
  assert.equal(decision.origin, RELAY);
  assert.equal(decision.changed, true);
  assert.deepEqual(decision.store, recordOf(signed.moved));
  assert.equal(decision.error, null);
  const same = trust.decide(recordOf(signed.moved), LOCAL, await trust.verifyIdentity(signed.moved), true);
  assert.equal(same.origin, RELAY);
  assert.equal(same.store, undefined);
  assert.equal(same.error, null);
});

test("a rollback, a conflicting statement, a bad statement or another key keeps the stored origin", async () => {
  const stored = recordOf(signed.moved);
  const rollback = trust.decide(stored, LOCAL, await trust.verifyIdentity(signed.first), true);
  assert.equal(rollback.origin, RELAY);
  assert.equal(rollback.store, undefined);
  assert.match(rollback.error, /older origin statement/);
  const conflict = trust.decide(stored, null, await trust.verifyIdentity(signed.same_seq_other_origin), true);
  assert.equal(conflict.origin, RELAY);
  assert.equal(conflict.store, undefined);
  assert.ok(conflict.error);
  const invalid = trust.decide(stored, null, null, true);
  assert.equal(invalid.origin, RELAY);
  assert.match(invalid.error, /could not be verified/);
  const otherKey = trust.decide(stored, null, await trust.verifyIdentity(signed.other_key), true);
  assert.equal(otherKey.origin, RELAY);
  assert.equal(otherKey.store, undefined);
  assert.equal(otherKey.reset, true);
  assert.match(otherKey.error, /another identity key/);
  // A host that drops the statement changes nothing.
  assert.equal(trust.decide(stored, LOCAL, null, false).origin, RELAY);
});

function brokerAnswer(fields) {
  return () => ({ok: true, channel: "c0ffee00", protocol: 1, broker_public_key: "x", ...copy(fields)});
}

test("the popup state learns the key at pairing, follows a signed move, and refuses a rollback", async () => {
  let fields = {paired: false, locked: true, pairing: {code: "AAAA-AAAA", url: LOCAL + "/extension/pair?token=t1"},
    identity: signed.first};
  const local = {};
  const {exports} = loadBackground({builtOrigin: LOCAL, local, answer: () => brokerAnswer(fields)()});
  let state = await exports.popupState();
  assert.equal(state.origin, LOCAL);
  assert.equal(state.pairing_url, LOCAL + "/extension/pair?token=t1");
  assert.equal(state.origin_learned, true);
  assert.deepEqual(local[trust.STORAGE_KEY], recordOf(signed.first));
  // The broker restarted on the relay origin and signed it with the stored key: no rebuild, no reload.
  fields = {paired: true, locked: true, unlock_url: RELAY + "/?token=u1", identity: signed.moved};
  state = await exports.popupState();
  assert.equal(state.origin, RELAY);
  assert.equal(state.unlock_url, RELAY + "/?token=u1");
  assert.equal(state.origin_changed, true);
  assert.equal(local[trust.STORAGE_KEY].seq, 2);
  // A replaced host replays the first statement and a link to the old origin.
  fields = {paired: true, locked: true, unlock_url: LOCAL + "/?token=u2", identity: signed.first};
  state = await exports.popupState();
  assert.equal(state.origin, RELAY);
  assert.equal(state.unlock_url, null);
  assert.match(state.trust_error, /older origin statement/);
  // Or claims another key and a look-alike page.
  fields = {paired: false, locked: true, pairing: {code: "AAAA-AAAA", url: "https://look-alike.example.test/extension/pair?token=t"},
    identity: signed.other_key};
  state = await exports.popupState();
  assert.equal(state.pairing_url, null);
  assert.equal(state.trust_reset, true);
  assert.deepEqual(local[trust.STORAGE_KEY], recordOf(signed.moved));
});

test("an unsigned link off the built origin never opens, and the reset needs a new pairing", async () => {
  const local = {};
  const {exports, session, port} = loadBackground({builtOrigin: LOCAL, local, answer: brokerAnswer({paired: false,
    locked: true, pairing: {code: "AAAA-AAAA", url: "https://look-alike.example.test/extension/pair?token=t"}})});
  const state = await exports.popupState();
  assert.equal(state.origin, LOCAL);
  assert.equal(state.pairing_url, null);
  assert.ok(session.pairing);
  const keyBefore = session.pairing.publicKey;
  assert.equal((await exports.popupReset()).ok, true);
  assert.deepEqual(local[trust.STORAGE_KEY], {v: 1, reset: true});
  assert.equal(session.pairing, undefined);
  assert.equal(port.disconnected, true);
  assert.notEqual((await exports.pairingKeys()).publicKey, keyBefore);
});

test("the popup and its reset are reachable only from the popup page", () => {
  const html = fs.readFileSync(path.join(root, "popup.html"), "utf8");
  assert.ok(html.indexOf('src="trust.js"') < html.indexOf('src="popup.js"'));
  assert.match(html, /id="reset-yes"/);
  const source = fs.readFileSync(path.join(root, "background.js"), "utf8");
  assert.match(source, /importScripts\("config.js", "trust.js"\)/);
  assert.match(source, /"reset-trust": popupReset/);
});
