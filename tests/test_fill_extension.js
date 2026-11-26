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
// Build IDs that `akdbx extension build` writes into config.js: one per build.
const BUILD = "build-one-AAAAAAAAAAAA", REBUILD = "build-two-BBBBBBBBBBBB";
// What config.js says: the built origin and the build ID.
const at = (origin, build = BUILD) => ({origin, build});
// A saved record, made under `build` (null: a record with no build ID, from an unreleased 0.3.0 build).
const recordOf = (message, build = BUILD) => ({v: 1, public_key: message.public_key, key_id: message.statement.key_id,
  origin: message.statement.origin, seq: message.statement.seq, ...(build === null ? {} : {build})});

// `disk`: the version in manifest.json on disk (default: what this worker runs); `version`: what config.js says.
function loadBackground({builtOrigin, build = BUILD, local = {}, answer, fetch, session, version, disk,
  browserNamespace = false} = {}) {
  const posted = [];
  const listeners = {};
  // `listeners[name]` is the last listener; `listeners[name + "[]"]` keeps them all.
  const event = name => ({addListener: fn => { listeners[name] = fn; (listeners[name + "[]"] ??= []).push(fn); }});
  const area = store => ({get: async key => (key in store ? {[key]: copy(store[key])} : {}),
    set: async items => { Object.assign(store, copy(items)); }, remove: async key => { delete store[key]; },
    setAccessLevel: options => {
      assert.deepEqual(copy(options), {accessLevel: "TRUSTED_CONTEXTS"});
      return Promise.resolve();
    }});
  // Session storage outlives one service worker: pass the same object to model a restart.
  session = session ?? {};
  const port = {postMessage: m => {
    posted.push(m);
    // A scripted broker answers the popup's state request through the port.
    if (answer && m.type === "request") setTimeout(() => listeners["port.message"]({type: "response", id: m.id, result: answer(m)}));
  }, onMessage: event("port.message"), onDisconnect: event("port.disconnect"), disconnect: () => { port.disconnected = true; }};
  const chrome = {
    runtime: {id: "jjoamaejjkldcjcpgncoomoaagdfimhg", getURL: p => "chrome-extension://jjoamaejjkldcjcpgncoomoaagdfimhg/" + p,
      getManifest: () => manifest, connectNative: () => port, onStartup: event("startup"), onInstalled: event("installed"),
      onMessage: event("message"), lastError: undefined, reloads: 0, reload() { this.reloads += 1; }},
    storage: {session: area(session), local: area(local)},
    alarms: {create: () => {}, clear: () => {}, onAlarm: event("alarm")},
    contextMenus: {create: () => {}, onClicked: event("menu")},
    action: {openPopup: async () => {}},
    windows: {opened: [], removed: [], onRemoved: event("windows.removed"),
      create: async details => { chrome.windows.opened.push(details); return {id: 40 + chrome.windows.opened.length}; },
      remove: async id => { chrome.windows.removed.push(id); }},
    tabs: {get: async () => null, query: async () => []},
    webNavigation: {getAllFrames: async () => []},
    scripting: {executeScript: async () => []},
  };
  // The worker takes no screenshot and adds no style sheet (the pixel check of fill
  // extension 0.5.0 to 0.15.x did both): any such call is recorded here.
  const screen = {css: [], captures: 0};
  chrome.scripting.insertCSS = async details => { screen.css.push(details); };
  chrome.tabs.captureVisibleTab = async () => { screen.captures += 1; return "data:image/png;base64,AAAA"; };
  const sandbox = {chrome, crypto: globalThis.crypto, btoa, atob, setTimeout, clearTimeout, URL, URLSearchParams, TextEncoder,
    TextDecoder, Uint8Array, AbortController, module: {exports: {}}, AKDBX_TRUSTED_ORIGIN: builtOrigin ?? null,
    AKDBX_BUILD_ID: build};
  if (browserNamespace) sandbox.browser = chrome;  // Chromium148+ exposes both as the same API objects.
  if (version !== undefined) sandbox.AKDBX_EXTENSION_VERSION = version;
  // No network in these tests: the broker's HTTPS statement comes only from a scripted fetch,
  // and the worker's own manifest.json from `disk`.
  const own = chrome.runtime.getURL("manifest.json");
  const onDisk = disk === undefined ? (version ?? manifest.version) : disk;
  sandbox.fetch = async (url, options) => {
    if (url === own) {
      assert.equal(options.cache, "no-store");
      if (onDisk === null) throw new TypeError("missing");
      return {json: async () => ({...manifest, version: onDisk})};
    }
    if (!fetch) throw new TypeError("no network in tests");
    return fetch(url, options);
  };
  vm.createContext(sandbox);
  sandbox.importScripts = (...names) => {
    for (const name of names.filter(n => n !== "config.js")) {
      vm.runInContext(fs.readFileSync(path.join(root, name), "utf8"), sandbox);
    }
  };
  vm.runInContext(fs.readFileSync(path.join(root, "background.js"), "utf8"), sandbox);
  return {exports: sandbox.module.exports, listeners, posted, chrome, local, session, port, screen};
}

test("a Chromium worker starts when browser and chrome namespaces are both present", () => {
  const {listeners} = loadBackground({browserNamespace: true});
  assert.equal(typeof listeners.message, "function");
});

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

const settle = async (until, rounds = 50) => {
  for (let i = 0; i < rounds && !until(); i++) await new Promise(resolve => setTimeout(resolve, 10));
};

test("the hello reports the version of config.js, which Chrome caches with the worker", async () => {
  const local = {stale_reload: "0.6.0.1"};
  const {posted, chrome} = loadBackground({version: "0.6.0.7", local});
  await settle(() => posted.length);
  assert.deepEqual(Object.keys(posted[0]).sort(), ["protocol", "public_key", "type", "version"]);
  assert.equal(posted[0].version, "0.6.0.7");
  assert.equal(chrome.runtime.reloads, 0);
  assert.equal("stale_reload" in local, false);  // Running the build on disk: the reload record goes.
});

test("a worker older than the build on disk reloads once; if that does not help it says it is stale", async () => {
  // Chrome kept the worker of build 0.6.0.1; the folder now holds 0.6.0.2.
  const local = {};
  const first = loadBackground({version: "0.6.0.1", disk: "0.6.0.2", local});
  await settle(() => first.chrome.runtime.reloads);
  assert.equal(first.chrome.runtime.reloads, 1);
  assert.equal(first.posted.length, 0);  // No hello: the reload ends this worker.
  assert.equal(local.stale_reload, "0.6.0.2");
  // The worker after the reload still runs 0.6.0.1: no second reload, and the broker hears it.
  const second = loadBackground({version: "0.6.0.1", disk: "0.6.0.2", local});
  await settle(() => second.posted.length);
  assert.equal(second.chrome.runtime.reloads, 0);
  assert.deepEqual([second.posted[0].version, second.posted[0].stale], ["0.6.0.1", true]);
  // A manifest that cannot be read is not a newer build.
  const unread = loadBackground({version: "0.6.0.1", disk: null});
  await settle(() => unread.posted.length);
  assert.equal(unread.posted[0].stale, undefined);
  assert.equal(unread.chrome.runtime.reloads, 0);
});

test("a frame list or pin call to a worker older than the build on disk answers stale, then reloads", async () => {
  const local = {stale_reload: "0.6.0.2"};  // Already reloaded for this build: the hello says stale.
  const {posted, listeners, chrome, port} = loadBackground({version: "0.6.0.1", disk: "0.6.0.2", local});
  await settle(() => posted.length);
  delete local.stale_reload;  // The folder changed again under the running worker.
  const scripts = [];
  chrome.scripting.executeScript = async details => { scripts.push(details); return []; };
  // Two tabs show the URL, one another page: the stale frame answer counts the two, so a URL that
  // another browser also shows stays ambiguous for the broker.
  chrome.tabs.query = async () => [{id: 1, url: "https://example.com/"}, {id: 2, url: "https://example.com/"},
    {id: 3, url: "https://other.example/"}];
  for (const [id, op] of [[1, "frames"], [2, "pin"]]) {
    listeners["port.message"]({type: "call", id, op, top_url: "https://example.com/", tab_id: null});
  }
  await settle(() => posted.length === 3);
  assert.deepEqual(copy(posted.slice(1).map(m => [m.id, m.result]).sort((a, b) => a[0] - b[0])),
    [[1, {ok: false, error: "stale", tabs: 2}], [2, {ok: false, error: "stale"}]]);
  assert.deepEqual(scripts, []);  // Nothing injected from the newer files.
  await settle(() => chrome.runtime.reloads, 60);
  assert.equal(chrome.runtime.reloads, 1);
  assert.equal(port.disconnected, undefined);
});

test("a restarted service worker keeps its pairing key, so its code and pending link stay the same", async () => {
  const hello = async posted => {
    for (let i = 0; i < 50 && !posted.length; i++) await new Promise(resolve => setTimeout(resolve, 10));
    return posted[0];
  };
  const session = {};
  const first = loadBackground({session});
  const before = await hello(first.posted);
  assert.ok(session.pairing && session.pairing.publicKey === before.public_key);
  // Chrome stopped the idle worker; the next event starts a new one with the same session storage.
  const second = loadBackground({session});
  const after = await hello(second.posted);
  assert.equal(after.public_key, before.public_key);
  assert.equal(await second.exports.localCode(after.public_key), await first.exports.localCode(before.public_key));
  // A browser restart clears session storage: a new key, so a new code and a new pairing.
  const restarted = await hello(loadBackground({session: {}}).posted);
  assert.notEqual(restarted.public_key, before.public_key);
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
  chrome.tabs.get = async () => ({id: 7, url: chain[0].url, active: true, windowId: 1});
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

// A broker identity key, its saved trust record (made under BUILD) and a signature over one connection.
async function signedChannel(extensionKey) {
  const identity = await crypto.subtle.generateKey({name: "ECDSA", namedCurve: "P-256"}, false, ["sign"]);
  const point = new Uint8Array(await crypto.subtle.exportKey("raw", identity.publicKey));
  const b64 = bytes => Buffer.from(bytes).toString("base64url");
  const keyId = b64(new Uint8Array(await crypto.subtle.digest("SHA-256", point)));
  const ecdh = await crypto.subtle.generateKey({name: "ECDH", namedCurve: "P-256"}, true, ["deriveBits"]);
  const brokerKey = b64(new Uint8Array(await crypto.subtle.exportKey("raw", ecdh.publicKey)));
  const statement = {broker_key: brokerKey, extension_key: extensionKey, key_id: keyId, type: "akdbx-channel", v: 1};
  const signature = b64(new Uint8Array(await crypto.subtle.sign({name: "ECDSA", hash: "SHA-256"}, identity.privateKey,
    new TextEncoder().encode(trust.canonical(statement)))));
  const record = {v: 1, public_key: b64(point), key_id: keyId, origin: "https://localhost:9443", seq: 1, build: BUILD};
  return {record, brokerKey, signature};
}

test("a read answers only a signed broker connection and facts sealed for that pin, sealed to the broker", async () => {
  const local = {};
  const {exports, chrome} = loadBackground({builtOrigin: "https://localhost:9443", local});
  const key = await crypto.subtle.generateKey({name: "AES-GCM", length: 256}, false, ["encrypt", "decrypt"]);
  exports.setSealKey(key);
  exports.setCaptureKey(key);
  const chain = [{document_id: "DOC", url: "https://keys.example/new"}];
  chrome.tabs.get = async () => ({id: 7, url: chain[0].url, active: true, windowId: 1});
  chrome.webNavigation.getAllFrames = async () => [{frameId: 0, documentId: "DOC", url: chain[0].url}];
  const scripts = [];
  chrome.scripting.executeScript = async details => {
    scripts.push(details);
    const source = String(details.func);
    if (details.files) return [{}];
    if (source.includes(".pin(")) return [{result: "r".repeat(32)}];
    if (source.includes(".read(")) return [{result: "sk_synthetic_value"}];
    return [{result: true}];
  };
  const spec = {selector: "#secret", frame_origin: null};
  const b64 = bytes => Buffer.from(bytes).toString("base64url");
  const sealFor = async (context, facts) => {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = await crypto.subtle.encrypt({name: "AES-GCM", iv, additionalData: new TextEncoder().encode(context)}, key,
      new TextEncoder().encode(JSON.stringify({values: {}, facts})));
    return {iv: b64(iv), data: b64(data)};
  };
  const readOnce = async () => {
    const pinned = await exports.pin({tab_id: 7, document_id: "DOC", top_url: chain[0].url, frame_url: null, kind: "read", spec});
    assert.equal(pinned.ok, true);
    const facts = {tab_id: 7, document_id: "DOC", chain, kind: "read", pin_id: pinned.pin_id, max_age_ms: 1000, spec};
    return [pinned.pin_id, await exports.read({pin_id: pinned.pin_id, sealed: await sealFor("read:" + pinned.pin_id, facts)})];
  };
  const extensionKey = (await exports.pairingKeys()).publicKey;
  const {record, brokerKey, signature} = await signedChannel(extensionKey);
  // No trusted identity yet, then a signature for another extension key: nothing is read.
  exports.setChannel({brokerKey, signature});
  assert.equal((await readOnce())[1].state, "refused");
  local.broker_trust = record;
  exports.setChannel({brokerKey, signature: (await signedChannel("A".repeat(87))).signature});
  assert.equal((await readOnce())[1].state, "refused");
  assert.ok(scripts.every(s => !String(s.func).includes("__akdbxContent.read(")));
  exports.setChannel({brokerKey, signature});
  // A fill-sealed message is not a read request.
  const pinned = await exports.pin({tab_id: 7, document_id: "DOC", top_url: chain[0].url, frame_url: null, kind: "read", spec});
  const facts = {tab_id: 7, document_id: "DOC", chain, kind: "read", pin_id: pinned.pin_id, max_age_ms: 1000, spec};
  const asFill = await exports.read({pin_id: pinned.pin_id, sealed: await sealFor("fill:" + pinned.pin_id, facts)});
  assert.equal(asFill.state, "refused");
  assert.ok(scripts.every(s => !String(s.func).includes("__akdbxContent.read(")));
  const [pinId, good] = await readOnce();
  assert.equal(good.state, "read");
  assert.ok(!JSON.stringify(good).includes("sk_synthetic_value"));
  const iv = Buffer.from(good.sealed.iv, "base64url"), data = Buffer.from(good.sealed.data, "base64url");
  const plain = JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({name: "AES-GCM", iv,
    additionalData: new TextEncoder().encode("capture:" + pinId)}, key, data)));
  assert.equal(plain.value, "sk_synthetic_value");
  assert.equal(JSON.stringify(plain.facts), JSON.stringify({tab_id: 7, document_id: "DOC", chain, pin_id: pinId}));
});

test("a port keeps its first broker key: a second attached message cannot swap the keys", async () => {
  const {exports, port, posted} = loadBackground();
  for (let i = 0; i < 50 && !posted.length; i++) await new Promise(resolve => setTimeout(resolve, 10));
  const b64 = bytes => Buffer.from(bytes).toString("base64url");
  const brokerKey = async () => {
    const pair = await crypto.subtle.generateKey({name: "ECDH", namedCurve: "P-256"}, true, ["deriveBits"]);
    return b64(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  };
  const first = await brokerKey(), second = await brokerKey();
  exports.onHost(port, {type: "attached", connected: true, broker_public_key: first});
  const kept = exports.channel();
  assert.equal(kept.brokerKey, first);
  exports.onHost(port, {type: "attached", connected: true, broker_public_key: second, channel_signature: "A".repeat(86)});
  const after = exports.channel();
  assert.equal(after.brokerKey, first);
  assert.equal(after.captureKey, kept.captureKey);
  assert.equal(after.sealKey, kept.sealKey);
  assert.equal(after.signature, null);  // A signature for another key never attaches to this one.
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
  chrome.tabs.get = async () => ({id: 7, url: chain[0].url, active: true, windowId: 1});
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

// A card pin and its fill with a scripted content script. `local` is the extension's
// local storage: fill extension 0.5.0 to 0.15.x stored Enhanced security there.
async function pinAndFill(local) {
  const {exports, chrome, screen} = loadBackground({local});
  const key = await crypto.subtle.generateKey({name: "AES-GCM", length: 256}, false, ["encrypt", "decrypt"]);
  exports.setSealKey(key);
  const chain = [{document_id: "DOC", url: "https://shop.example/checkout"}];
  chrome.tabs.get = async () => ({id: 7, url: chain[0].url, active: true, windowId: 1});
  chrome.webNavigation.getAllFrames = async () => [{frameId: 0, documentId: "DOC", url: chain[0].url}];
  const calls = [];
  chrome.scripting.executeScript = async details => {
    if (details.files) return [{}];
    const source = String(details.func);
    calls.push([source, details.args]);
    if (source.includes(".pin(")) return [{result: "c".repeat(32)}];
    return [{result: source.includes(".fill(") ? "filled" : true}];
  };
  const spec = {selector: "#number", field: "cc-number", processor: null};
  const pinned = await exports.pin({tab_id: 7, document_id: "DOC", top_url: chain[0].url, frame_url: null, kind: "card", spec});
  const facts = {tab_id: 7, document_id: "DOC", chain, kind: "card", pin_id: pinned.pin_id, max_age_ms: 1000, spec};
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({name: "AES-GCM", iv, additionalData: new TextEncoder().encode("fill:" + pinned.pin_id)},
    key, new TextEncoder().encode(JSON.stringify({values: {value: "4111111111111111"}, facts})));
  const b64 = bytes => Buffer.from(bytes).toString("base64url");
  const result = await exports.fill({pin_id: pinned.pin_id, sealed: {iv: b64(iv), data: b64(data)}});
  return {pinned, result, screen, calls};
}

test("a stored Enhanced security setting is ignored: the pin and fill run the DOM checks only", async () => {
  // Fill extension 0.5.0 to 0.15.x stored this when the user turned the setting on; 0.16.0 keeps filling.
  for (const local of [{}, {settings: {enhanced_security: true}}, {settings: {enhanced_security: false}}]) {
    const {pinned, result, screen, calls} = await pinAndFill(copy(local));
    assert.equal(pinned.ok, true, JSON.stringify(local));
    assert.equal(result.state, "filled");
    // No screenshot, no style sheet, and no call to a cover check that content.js no longer has.
    assert.equal(screen.captures, 0);
    assert.equal(screen.css.length, 0);
    assert.ok(calls.every(([source]) => !/\.(clear|challengeSpec|challengeHeld|painted|guardPoint)\(/.test(source)));
    // The fill gets the pin, kind, values and deadline only.
    const fills = calls.filter(([source]) => source.includes(".fill("));
    assert.equal(fills.length, 1);
    assert.equal(fills[0][1].length, 4);
  }
});

test("the manifest asks for https pages only and has no settings page", () => {
  assert.deepEqual(manifest.host_permissions, ["https://*/*"]);
  assert.equal(manifest.optional_host_permissions, undefined);
  assert.equal(manifest.options_ui, undefined);
  for (const name of ["options.html", "options.js", "options.css"]) assert.equal(fs.existsSync(path.join(root, name)), false);
  // The worker, the content script and the popup take no screenshot, add no style sheet and open no settings page.
  for (const name of ["background.js", "content.js", "popup.js"]) {
    const source = fs.readFileSync(path.join(root, name), "utf8");
    assert.ok(!/captureVisibleTab|insertCSS|removeCSS|trackVisibility|openOptionsPage/.test(source), name);
  }
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

test("the canonical statement bytes equal the ones Python signs", () => {
  assert.equal(trust.canonical(signed.first.statement), signed.canonical);
  // Key order in the message does not matter; the bytes are always sorted.
  const reordered = {v: 1, seq: 1, origin: LOCAL, key_id: signed.first.statement.key_id, type: "akdbx-origin"};
  assert.equal(trust.canonical(reordered), signed.canonical);
});

test("a statement signed by the Python broker verifies", async () => {
  const {v, ...facts} = recordOf(signed.first, null);
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

// A statement that a fresh key signs in the test: the key a replaced native host could make itself.
async function hostKeyStatement(origin, seq = 1) {
  const pair = await crypto.subtle.generateKey({name: "ECDSA", namedCurve: "P-256"}, false, ["sign", "verify"]);
  const point = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const b64 = bytes => Buffer.from(bytes).toString("base64url");
  const statement = {type: "akdbx-origin", v: 1, origin, seq,
    key_id: b64(new Uint8Array(await crypto.subtle.digest("SHA-256", point)))};
  const signature = await crypto.subtle.sign({name: "ECDSA", hash: "SHA-256"}, pair.privateKey,
    new TextEncoder().encode(trust.canonical(statement)));
  return {public_key: b64(point), statement, signature: b64(new Uint8Array(signature))};
}

// A scripted HTTPS answer for the broker's identity page.
function identityFetch(body, {status = 200, type = "application/json", calls = []} = {}) {
  return async (url, options) => {
    calls.push({url, options});
    if (body instanceof Error) throw body;
    const text = typeof body === "string" ? body : JSON.stringify(body);
    return {status, redirected: false, url, headers: {get: name => (name.toLowerCase() === "content-type" ? type : null)},
      text: async () => text};
  };
}

test("a first key is stored only after the trusted origin's HTTPS page confirms it", async () => {
  const first = await trust.verifyIdentity(signed.first);
  // The host's statement alone stores nothing: read the built origin's page first.
  const pending = trust.decide(null, at(LOCAL), first, true);
  assert.equal(pending.fetch, LOCAL);
  assert.equal(pending.origin, LOCAL);
  assert.equal(pending.store, undefined);
  assert.equal(pending.learned, false);
  const learned = trust.decide(null, at(LOCAL), first, true, first);
  assert.equal(learned.learned, true);
  assert.equal(learned.origin, LOCAL);
  assert.deepEqual(learned.store, recordOf(signed.first));
  // A replaced host sends its own key for the built origin; the broker's page has the real one.
  const forged = await trust.verifyIdentity(await hostKeyStatement(LOCAL));
  assert.equal(forged.origin, LOCAL);
  const mismatch = trust.decide(null, at(LOCAL), forged, true, first);
  assert.equal(mismatch.origin, LOCAL);
  assert.equal(mismatch.store, undefined);
  assert.equal(mismatch.reset, false);
  assert.match(mismatch.error, /another identity than the native host sent/);
  // The page answers with a statement for another origin: refused.
  const offOrigin = trust.decide(null, at(LOCAL), first, true, await trust.verifyIdentity(signed.moved));
  assert.equal(offOrigin.origin, LOCAL);
  assert.equal(offOrigin.store, undefined);
  assert.ok(offOrigin.error);
  // The read failed: keep the built origin, store nothing, no warning; the next popup tries again.
  const failed = trust.decide(null, at(LOCAL), first, true, null);
  assert.deepEqual([failed.origin, failed.store, failed.error, failed.fetch], [LOCAL, undefined, null, undefined]);
});

test("built for one origin, a broker that names another is never learned and offers no reset", async () => {
  const moved = await trust.verifyIdentity(signed.moved);
  const refused = trust.decide(null, at(LOCAL), moved, true);
  assert.equal(refused.origin, LOCAL);
  assert.equal(refused.store, undefined);
  assert.equal(refused.fetch, undefined);
  assert.equal(refused.reset, false);
  assert.match(refused.error, /built for https:\/\/localhost:9443/);
  assert.match(refused.error, /akdbx extension build/);
  // An older broker sends no statement: the built origin works as before.
  assert.equal(trust.decide(null, at(LOCAL), null, false).origin, LOCAL);
  // A statement that does not verify is not learned and not read.
  const invalid = trust.decide(null, at(LOCAL), null, true);
  assert.equal(invalid.origin, LOCAL);
  assert.equal(invalid.store, undefined);
  assert.equal(invalid.fetch, undefined);
  assert.ok(invalid.error);
});

test("with no built origin and nothing stored, no origin is ever trusted", async () => {
  for (const [verified, received] of [[await trust.verifyIdentity(signed.first), true], [null, true], [null, false]]) {
    for (const fetched of [undefined, null, verified]) {
      const decision = trust.decide(null, at(null), verified, received, fetched);
      assert.equal(decision.origin, null);
      assert.equal(decision.store, undefined);
      assert.equal(decision.fetch, undefined);
      assert.equal(decision.reset, false);
      assert.match(decision.error, /akdbx extension build/);
    }
  }
  // An old reset record without an origin gives no origin either; the built one still counts.
  assert.equal(trust.decide({v: 1, reset: true}, at(null), null, false).origin, null);
  assert.equal(trust.decide({v: 1, reset: true}, at(LOCAL), null, false).origin, LOCAL);
});

test("after a reset, the kept origin's HTTPS page alone binds the next key", async () => {
  const afterReset = {v: 1, reset: true, origin: RELAY, build: BUILD};
  const fresh = await trust.verifyIdentity(await hostKeyStatement(RELAY));
  // The kept origin wins over the built one, and the page is read there.
  const pending = trust.decide(afterReset, at(LOCAL), fresh, true);
  assert.deepEqual([pending.origin, pending.fetch, pending.store], [RELAY, RELAY, undefined]);
  const learned = trust.decide(afterReset, at(LOCAL), fresh, true, fresh);
  assert.equal(learned.learned, true);
  assert.deepEqual(learned.store, {v: 1, ...fresh, build: BUILD});
  // The read failed: nothing is stored, and there is no trust on first use.
  const failed = trust.decide(afterReset, at(LOCAL), fresh, true, null);
  assert.deepEqual([failed.origin, failed.store, failed.learned], [RELAY, undefined, false]);
  // The page has another key than the host sent: nothing is stored.
  const forged = await trust.verifyIdentity(await hostKeyStatement(RELAY));
  const refused = trust.decide(afterReset, at(LOCAL), forged, true, fresh);
  assert.equal(refused.store, undefined);
  assert.match(refused.error, /another identity/);
  // The host names another origin: no reset can help; only a rebuild changes the first origin.
  const off = trust.decide(afterReset, at(LOCAL), await trust.verifyIdentity(signed.first), true);
  assert.deepEqual([off.origin, off.fetch, off.store, off.reset], [RELAY, undefined, undefined, false]);
  assert.match(off.error, /akdbx extension build/);
});

test("the identity page is read with no redirect, no credentials and no cache, and only a valid answer counts", async () => {
  const calls = [];
  const facts = await trust.fetchIdentity(LOCAL, identityFetch(signed.first, {calls}));
  assert.deepEqual(facts, await trust.verifyIdentity(signed.first));
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, LOCAL + "/.well-known/akdbx-identity");
  const {redirect, credentials, cache, method} = calls[0].options;
  assert.deepEqual({redirect, credentials, cache, method}, {redirect: "error", credentials: "omit", cache: "no-store", method: "GET"});
  assert.ok(calls[0].options.signal);
  assert.equal(await trust.fetchIdentity(LOCAL, identityFetch(signed.first, {status: 404})), null);
  assert.equal(await trust.fetchIdentity(LOCAL, identityFetch(signed.first, {type: "text/html"})), null);
  assert.equal(await trust.fetchIdentity(LOCAL, identityFetch("{not json")), null);
  assert.equal(await trust.fetchIdentity(LOCAL, identityFetch(signed.wrong_key_id)), null);
  assert.equal(await trust.fetchIdentity(LOCAL, identityFetch("x".repeat(5000))), null);
  assert.equal(await trust.fetchIdentity(LOCAL, identityFetch(new TypeError("network"))), null);
  assert.equal(await trust.fetchIdentity(LOCAL + "/x", identityFetch(signed.first)), null);
  const redirected = async url => ({status: 200, redirected: true, url, headers: {get: () => "application/json"},
    text: async () => JSON.stringify(signed.first)});
  assert.equal(await trust.fetchIdentity(LOCAL, redirected), null);
  // A page that never answers ends at the timeout.
  const hang = (url, options) => new Promise((resolve, reject) => options.signal.addEventListener("abort", () => reject(new Error("aborted"))));
  assert.equal(await trust.fetchIdentity(LOCAL, hang, 20), null);
});

test("a signed origin change with a higher sequence replaces the stored origin", async () => {
  const decision = trust.decide(recordOf(signed.first), at(LOCAL), await trust.verifyIdentity(signed.moved), true);
  assert.equal(decision.origin, RELAY);
  assert.equal(decision.changed, true);
  assert.deepEqual(decision.store, recordOf(signed.moved));
  assert.equal(decision.error, null);
  const same = trust.decide(recordOf(signed.moved), at(LOCAL), await trust.verifyIdentity(signed.moved), true);
  assert.equal(same.origin, RELAY);
  assert.equal(same.store, undefined);
  assert.equal(same.error, null);
});

test("a rollback, a conflicting statement, a bad statement or another key keeps the stored origin", async () => {
  const stored = recordOf(signed.moved);
  const rollback = trust.decide(stored, at(LOCAL), await trust.verifyIdentity(signed.first), true);
  assert.equal(rollback.origin, RELAY);
  assert.equal(rollback.store, undefined);
  assert.match(rollback.error, /older origin statement/);
  const conflict = trust.decide(stored, at(null), await trust.verifyIdentity(signed.same_seq_other_origin), true);
  assert.equal(conflict.origin, RELAY);
  assert.equal(conflict.store, undefined);
  assert.ok(conflict.error);
  const invalid = trust.decide(stored, at(null), null, true);
  assert.equal(invalid.origin, RELAY);
  assert.match(invalid.error, /could not be verified/);
  // A host that drops the statement changes nothing.
  assert.equal(trust.decide(stored, at(LOCAL), null, false).origin, RELAY);
});

test("another broker key keeps the saved record but leaves no origin for links", async () => {
  const stored = recordOf(signed.moved);
  // The same origin with another key: a reset is offered, and no link opens meanwhile.
  const sameOrigin = trust.decide(stored, at(LOCAL), await trust.verifyIdentity(await hostKeyStatement(RELAY, 9)), true);
  assert.deepEqual([sameOrigin.origin, sameOrigin.store, sameOrigin.reset], [null, undefined, true]);
  assert.match(sameOrigin.error, /another identity key/);
  assert.match(sameOrigin.error, /did not set up this broker again yourself, do not reset and do not enter your master password/);
  // Another key and another origin: no reset (it could not bind there); a rebuild is the only way.
  const otherKey = trust.decide(stored, at(null), await trust.verifyIdentity(signed.other_key), true);
  assert.deepEqual([otherKey.origin, otherKey.store, otherKey.reset], [null, undefined, false]);
  assert.match(otherKey.error, /akdbx extension build/);
});

function brokerAnswer(fields) {
  return () => ({ok: true, channel: "c0ffee00", protocol: 1, broker_public_key: "x", ...copy(fields)});
}

test("the popup state learns the key at pairing, follows a signed move, and refuses a rollback", async () => {
  let fields = {paired: false, locked: true, pairing: {code: "AAAA-AAAA", url: LOCAL + "/extension/pair?token=t1"},
    identity: signed.first};
  const local = {};
  const calls = [];
  const {exports} = loadBackground({builtOrigin: LOCAL, local, answer: () => brokerAnswer(fields)(),
    fetch: identityFetch(signed.first, {calls})});
  let state = await exports.popupState();
  assert.deepEqual(calls.map(c => c.url), [LOCAL + "/.well-known/akdbx-identity"]);
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
  assert.equal(calls.length, 1);  // A signed change needs no read.
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
  assert.equal(state.origin, null);
  assert.equal(state.trust_reset, false);
  assert.deepEqual(local[trust.STORAGE_KEY], recordOf(signed.moved));
});

test("the popup state stores no host-only key: a failed read keeps the built origin and retries", async () => {
  const fields = {paired: false, locked: true, pairing: {code: "AAAA-AAAA", url: LOCAL + "/extension/pair?token=t1"},
    identity: signed.first};
  const local = {};
  let page = new TypeError("connection refused");
  const calls = [];
  const fetch = (url, options) => identityFetch(page, {calls})(url, options);
  const {exports} = loadBackground({builtOrigin: LOCAL, local, answer: brokerAnswer(fields), fetch});
  let state = await exports.popupState();
  assert.equal(state.origin, LOCAL);
  assert.equal(state.pairing_url, LOCAL + "/extension/pair?token=t1");  // The built origin works as before.
  assert.equal(state.origin_learned, false);
  assert.equal(state.trust_error, null);
  assert.equal(local[trust.STORAGE_KEY], undefined);
  assert.equal(calls.length, 1);
  // The next popup reads the page again and then learns the key.
  page = signed.first;
  state = await exports.popupState();
  assert.equal(calls.length, 2);
  assert.equal(state.origin_learned, true);
  assert.deepEqual(local[trust.STORAGE_KEY], recordOf(signed.first));
});

test("a replaced host's own key for the built origin is refused when the HTTPS page has another", async () => {
  const forged = await hostKeyStatement(LOCAL);
  const local = {};
  const {exports} = loadBackground({builtOrigin: LOCAL, local, fetch: identityFetch(signed.first),
    answer: brokerAnswer({paired: false, locked: true, pairing: {code: "AAAA-AAAA", url: LOCAL + "/extension/pair?token=t"},
      identity: forged})});
  const state = await exports.popupState();
  assert.equal(state.origin, LOCAL);
  assert.match(state.trust_error, /another identity than the native host sent/);
  assert.equal(local[trust.STORAGE_KEY], undefined);
  // Without a stored key, the forged key can never sign a move away from the built origin.
  const moved = await hostKeyStatement(RELAY, 2);
  const again = loadBackground({builtOrigin: LOCAL, local, fetch: identityFetch(signed.first),
    answer: brokerAnswer({paired: true, locked: true, unlock_url: RELAY + "/?token=u", identity: moved})});
  const next = await again.exports.popupState();
  assert.equal(next.origin, LOCAL);
  assert.equal(next.unlock_url, null);
  assert.equal(local[trust.STORAGE_KEY], undefined);
});

test("a rebuild replaces the saved trust; a reload of the same build does not", async () => {
  // Broker A at the built origin: the extension binds key A through A's HTTPS page.
  const local = {};
  const first = loadBackground({builtOrigin: LOCAL, local, fetch: identityFetch(signed.first),
    answer: brokerAnswer({paired: false, locked: true, pairing: {code: "AAAA-AAAA", url: LOCAL + "/extension/pair?token=a"},
      identity: signed.first})});
  assert.equal((await first.exports.popupState()).origin_learned, true);
  const saved = copy(local[trust.STORAGE_KEY]);
  assert.deepEqual(saved, recordOf(signed.first));
  // Broker B was set up at another address with a new key, and its HTTPS page serves key B.
  const keyB = await hostKeyStatement(RELAY);
  const brokerB = brokerAnswer({paired: false, locked: true, pairing: {code: "BBBB-BBBB", url: RELAY + "/extension/pair?token=b"},
    identity: keyB});
  // A reload of the same build (same build ID) keeps refusing B.
  const calls = [];
  const reloaded = loadBackground({builtOrigin: LOCAL, local, fetch: identityFetch(keyB, {calls}), answer: brokerB});
  const refused = await reloaded.exports.popupState();
  assert.deepEqual([refused.origin, refused.pairing_url, refused.trust_reset], [null, null, false]);
  assert.match(refused.trust_error, /akdbx extension build/);
  assert.deepEqual(local[trust.STORAGE_KEY], saved);
  assert.equal(calls.length, 0);
  // The user runs akdbx extension build for B and reloads: B's key is bound through B's HTTPS page.
  const rebuilt = loadBackground({builtOrigin: RELAY, build: REBUILD, local, fetch: identityFetch(keyB, {calls}),
    answer: brokerB});
  const state = await rebuilt.exports.popupState();
  assert.deepEqual(calls.map(c => c.url), [RELAY + "/.well-known/akdbx-identity"]);
  assert.deepEqual([state.origin, state.origin_learned, state.trust_error], [RELAY, true, null]);
  assert.equal(state.pairing_url, RELAY + "/extension/pair?token=b");
  assert.deepEqual(local[trust.STORAGE_KEY], {v: 1, public_key: keyB.public_key, key_id: keyB.statement.key_id,
    origin: RELAY, seq: 1, build: REBUILD});
});

test("after a signed move away, a rebuild for the same address binds a replacement broker there", async () => {
  // Built for A; key A is bound, then the broker signs a move to B with key A.
  const local = {};
  let fields = {paired: false, locked: true, pairing: {code: "AAAA-AAAA", url: LOCAL + "/extension/pair?token=a"},
    identity: signed.first};
  const first = loadBackground({builtOrigin: LOCAL, local, fetch: identityFetch(signed.first), answer: () => brokerAnswer(fields)()});
  assert.equal((await first.exports.popupState()).origin_learned, true);
  fields = {paired: true, locked: true, unlock_url: RELAY + "/?token=b", identity: signed.moved};
  assert.equal((await first.exports.popupState()).origin, RELAY);
  const saved = copy(local[trust.STORAGE_KEY]);
  assert.deepEqual([saved.origin, saved.key_id, saved.seq], [RELAY, signed.first.statement.key_id, 2]);
  // A replacement broker with a new key now runs at A, and A's HTTPS page serves the new key.
  const replacement = await hostKeyStatement(LOCAL);
  const brokerA = brokerAnswer({paired: false, locked: true, unlock_url: LOCAL + "/?token=u",
    pairing: {code: "CCCC-CCCC", url: LOCAL + "/extension/pair?token=c"}, identity: replacement});
  // A reload of the same build refuses it with no reset, and says to rebuild.
  const calls = [];
  const reloaded = loadBackground({builtOrigin: LOCAL, local, fetch: identityFetch(replacement, {calls}), answer: brokerA});
  const refused = await reloaded.exports.popupState();
  assert.deepEqual([refused.origin, refused.pairing_url, refused.unlock_url, refused.trust_reset], [null, null, null, false]);
  assert.match(refused.trust_error, /trusts https:\/\/abcdefghijkl\.akdbx\.link/);
  assert.match(refused.trust_error, /akdbx extension build/);
  assert.deepEqual(local[trust.STORAGE_KEY], saved);
  assert.equal(calls.length, 0);
  // The user rebuilds for A (the same origin, a new build ID) and reloads: the new key is bound from A's page.
  const rebuilt = loadBackground({builtOrigin: LOCAL, build: REBUILD, local, fetch: identityFetch(replacement, {calls}),
    answer: brokerA});
  const state = await rebuilt.exports.popupState();
  assert.deepEqual(calls.map(c => c.url), [LOCAL + "/.well-known/akdbx-identity"]);
  assert.deepEqual([state.origin, state.origin_learned, state.trust_error, state.trust_reset], [LOCAL, true, null, false]);
  assert.equal(state.pairing_url, LOCAL + "/extension/pair?token=c");
  assert.equal(state.unlock_url, LOCAL + "/?token=u");
  assert.deepEqual(local[trust.STORAGE_KEY], {v: 1, public_key: replacement.public_key,
    key_id: replacement.statement.key_id, origin: LOCAL, seq: 1, build: REBUILD});
});

test("a saved record counts only under the build that made it", async () => {
  const moved = await trust.verifyIdentity(signed.moved);
  assert.equal(trust.trustedOrigin(recordOf(signed.moved), at(LOCAL)), RELAY);
  assert.equal(trust.trustedOrigin({v: 1, reset: true, origin: RELAY, build: BUILD}, at(LOCAL)), RELAY);
  // Another build, also for the same address: the record, or a reset that kept an origin, no longer counts.
  assert.equal(trust.trustedOrigin(recordOf(signed.moved), at(LOCAL, REBUILD)), LOCAL);
  assert.equal(trust.trustedOrigin({v: 1, reset: true, origin: RELAY, build: BUILD}, at(LOCAL, REBUILD)), LOCAL);
  // A record with no build ID (an unreleased 0.3.0 build), or a malformed one, matches no build.
  assert.equal(trust.trustedOrigin(recordOf(signed.moved, null), at(LOCAL)), LOCAL);
  assert.equal(trust.trustedOrigin({...recordOf(signed.moved), build: 7}, at(LOCAL)), LOCAL);
  // A config.js with no valid build ID counts as not built, whatever is saved.
  for (const build of [null, undefined, "short", 7]) {
    assert.equal(trust.trustedOrigin(recordOf(signed.moved), {origin: LOCAL, build}), null);
    assert.match(trust.decide(recordOf(signed.moved), {origin: LOCAL, build}, moved, true).error, /akdbx extension build/);
  }
  // The same build: the signed move is followed as before and keeps the build ID in the record.
  assert.deepEqual(trust.decide(recordOf(signed.first), at(LOCAL), moved, true).store, recordOf(signed.moved));
});

test("a signed move that arrives while the popup is closed is shown once in the next popup", async () => {
  const local = {[trust.STORAGE_KEY]: recordOf(signed.first)};
  const fields = {paired: true, locked: true, unlock_url: RELAY + "/?token=u", identity: signed.moved};
  const {exports, listeners} = loadBackground({builtOrigin: LOCAL, local, answer: brokerAnswer(fields)});
  for (let i = 0; i < 200 && !listeners["port.message"]; i++) await new Promise(resolve => setTimeout(resolve, 5));
  listeners["port.message"]({type: "attached", ...fields});
  await exports.trustIdle();
  assert.deepEqual(local[trust.STORAGE_KEY], recordOf(signed.moved));
  // The popup opens later; the broker's state now repeats the same (already saved) statement.
  let state = await exports.popupState();
  assert.deepEqual([state.origin, state.origin_changed, state.moved_from], [RELAY, true, LOCAL]);
  assert.equal(state.unlock_url, RELAY + "/?token=u");
  state = await exports.popupState();
  assert.deepEqual([state.origin, state.origin_changed, state.moved_from], [RELAY, false, null]);
});

test("a move notice waits while the popup shows a trust warning", async () => {
  const local = {[trust.STORAGE_KEY]: recordOf(signed.first)};
  let fields = {paired: true, locked: true, unlock_url: RELAY + "/?token=u", identity: signed.moved};
  const {exports, listeners} = loadBackground({builtOrigin: LOCAL, local, answer: () => brokerAnswer(fields)()});
  for (let i = 0; i < 200 && !listeners["port.message"]; i++) await new Promise(resolve => setTimeout(resolve, 5));
  listeners["port.message"]({type: "attached", ...fields});
  await exports.trustIdle();
  assert.deepEqual(local[trust.STORAGE_KEY], recordOf(signed.moved));
  // The popup opens while the broker sends another key for a moment: only the key warning shows.
  fields = {...fields, identity: await hostKeyStatement(RELAY, 9)};
  let state = await exports.popupState();
  assert.deepEqual([state.origin, state.origin_changed, state.trust_reset], [null, false, true]);
  assert.match(state.trust_error, /another identity key/);
  // The broker is back with the trusted key: the move is shown once, then no more.
  fields = {...fields, identity: signed.moved};
  state = await exports.popupState();
  assert.deepEqual([state.origin, state.origin_changed, state.moved_from, state.trust_error], [RELAY, true, LOCAL, null]);
  state = await exports.popupState();
  assert.deepEqual([state.origin_changed, state.moved_from], [false, null]);
});

test("with no built origin, the host's statement opens nothing and reads nothing", async () => {
  const local = {};
  const calls = [];
  const {exports} = loadBackground({local, fetch: identityFetch(signed.first, {calls}),
    answer: brokerAnswer({paired: false, locked: true, pairing: {code: "AAAA-AAAA", url: LOCAL + "/extension/pair?token=t"},
      identity: signed.first})});
  const state = await exports.popupState();
  assert.equal(state.origin, null);
  assert.equal(state.pairing_url, null);
  assert.equal(state.origin_learned, false);
  assert.equal(state.trust_reset, false);
  assert.match(state.trust_error, /akdbx extension build/);
  assert.equal(calls.length, 0);
  assert.equal(local[trust.STORAGE_KEY], undefined);
});

test("a key change on the saved origin opens no link there until a reset and a new HTTPS binding", async () => {
  const local = {[trust.STORAGE_KEY]: recordOf(signed.first)};
  const replaced = await hostKeyStatement(LOCAL, 1);
  let page = new TypeError("connection refused");
  const calls = [];
  const fetch = (url, options) => identityFetch(page, {calls})(url, options);
  const {exports} = loadBackground({builtOrigin: LOCAL, local, fetch,
    answer: brokerAnswer({paired: true, locked: true, unlock_url: LOCAL + "/?token=u", identity: replaced})});
  let state = await exports.popupState();
  assert.equal(state.origin, null);
  assert.equal(state.unlock_url, null);
  assert.equal(state.trust_reset, true);
  assert.deepEqual(local[trust.STORAGE_KEY], recordOf(signed.first));
  assert.equal(calls.length, 0);
  // The reset keeps the origin; the new key is not trusted while its page cannot be read.
  await exports.popupReset();
  assert.deepEqual(local[trust.STORAGE_KEY], {v: 1, reset: true, origin: LOCAL, build: BUILD});
  state = await exports.popupState();
  assert.equal(state.origin_learned, false);
  assert.deepEqual(local[trust.STORAGE_KEY], {v: 1, reset: true, origin: LOCAL, build: BUILD});
  assert.ok(calls.every(c => c.url === LOCAL + "/.well-known/akdbx-identity") && calls.length >= 1);
  // The page at the kept origin has the new key: now it is bound, and the link opens.
  page = replaced;
  state = await exports.popupState();
  assert.equal(state.origin_learned, true);
  assert.equal(state.origin, LOCAL);
  assert.equal(state.unlock_url, LOCAL + "/?token=u");
  assert.equal(local[trust.STORAGE_KEY].key_id, replaced.statement.key_id);
});

test("identities are checked when they arrive: a first key on attach, a signed move on a state message", async () => {
  const local = {};
  const calls = [];
  const {exports, listeners} = loadBackground({builtOrigin: LOCAL, local, fetch: identityFetch(signed.first, {calls})});
  // connect() opens the port once the browser key exists.
  for (let i = 0; i < 200 && !listeners["port.message"]; i++) await new Promise(resolve => setTimeout(resolve, 5));
  const send = message => listeners["port.message"](message);
  send({type: "attached", paired: true, locked: true, identity: signed.first});
  await exports.trustIdle();
  assert.deepEqual(calls.map(c => c.url), [LOCAL + "/.well-known/akdbx-identity"]);
  assert.deepEqual(local[trust.STORAGE_KEY], recordOf(signed.first));
  send({type: "state", paired: true, locked: true, identity: signed.moved});
  await exports.trustIdle();
  assert.deepEqual(local[trust.STORAGE_KEY], recordOf(signed.moved));
  // A later, older statement in memory never replaces the saved sequence number.
  send({type: "state", paired: true, locked: true, identity: signed.first});
  await exports.trustIdle();
  assert.deepEqual(local[trust.STORAGE_KEY], recordOf(signed.moved));
  assert.equal(calls.length, 1);
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
  // The reset keeps the built origin as the trusted one.
  assert.deepEqual(local[trust.STORAGE_KEY], {v: 1, reset: true, origin: LOCAL, build: BUILD});
  assert.equal(session.pairing, undefined);
  assert.equal(port.disconnected, true);
  assert.notEqual((await exports.pairingKeys()).publicKey, keyBefore);
});

test("the popup and its reset are reachable only from the popup page", () => {
  const html = fs.readFileSync(path.join(root, "popup.html"), "utf8");
  assert.ok(html.indexOf('src="trust.js"') < html.indexOf('src="popup.js"'));
  assert.match(html, /id="reset-yes"/);
  const source = fs.readFileSync(path.join(root, "background.js"), "utf8");
  assert.match(source, /importScripts\("api.js", "config.js", "trust.js"\)/);
  assert.match(source, /"reset-trust": popupReset/);
});

// ----- hardware key for unlock pages ---------------------------------------
const HARDWARE_ANSWER = "ab".repeat(20);

// A broker identity for `origin` and a signer for its per-page hardware statements (broker_identity.sign_hardware).
async function hardwareBroker(origin) {
  const pair = await crypto.subtle.generateKey({name: "ECDSA", namedCurve: "P-256"}, false, ["sign", "verify"]);
  const point = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const b64 = bytes => Buffer.from(bytes).toString("base64url");
  const sign = async statement => b64(new Uint8Array(await crypto.subtle.sign({name: "ECDSA", hash: "SHA-256"},
    pair.privateKey, new TextEncoder().encode(trust.canonical(statement)))));
  const keyId = b64(new Uint8Array(await crypto.subtle.digest("SHA-256", point)));
  const statement = {type: "akdbx-origin", v: 1, origin, seq: 1, key_id: keyId};
  const identity = JSON.stringify({public_key: b64(point), statement, signature: await sign(statement)});
  const proof = async (challenge, issued = Math.floor(Date.now() / 1000)) => {
    const hardware = {type: "akdbx-hardware", v: 1, origin, key_id: keyId, challenge, issued};
    return JSON.stringify({statement: hardware, signature: await sign(hardware)});
  };
  return {identity, proof, keyId};
}
const pageSender = (origin, extra = {}) =>
  ({id: "jjoamaejjkldcjcpgncoomoaagdfimhg", tab: {id: 3}, frameId: 0, url: origin + "/?token=synthetic", ...extra});

// The host's reply goes to every port listener, as the browser does for one port; the
// worker's main port ignores "hardware-key" messages, the request's own port takes them.
function fromHost(listeners, message) {
  for (const listener of listeners["port.message[]"]) listener(message);
}

function askHardware(listeners, message, sender) {
  // Objects from the worker's sandbox: compare plain JSON copies.
  return new Promise(resolve => {
    const kept = listeners["message[]"].map(listener => listener(message, sender, reply => resolve(copy(reply ?? null))));
    if (!kept.includes(true)) resolve("ignored");
  });
}

// Wait until `ready()` (the worker verifies signatures and reads storage asynchronously).
async function settleHardware(ready = () => true) {
  for (let i = 0; i < 400 && !ready(); i += 1) await new Promise(resolve => setTimeout(resolve, 5));
  for (let i = 0; i < 20; i += 1) await new Promise(resolve => setTimeout(resolve, 0));
}

test("the trusted broker origin gets the hardware key's answer from its own host connection", async () => {
  const {listeners, posted, chrome} = loadBackground({builtOrigin: LOCAL});
  assert.deepEqual(await askHardware(listeners, {op: "hardware-key-allowed"}, pageSender(LOCAL)), {ok: true});
  const reply = askHardware(listeners, {op: "hardware-key", challenge: "01".repeat(32)}, pageSender(LOCAL));
  await settleHardware(() => posted.some(message => message.type === "hardware-key"));
  const request = posted.find(message => message.type === "hardware-key");
  assert.deepEqual(copy(request), {type: "hardware-key", id: request.id, challenge: "01".repeat(32)});
  fromHost(listeners, {type: "hardware-key", id: request.id, responses: [HARDWARE_ANSWER, "not hex"]});
  assert.deepEqual(await reply, {responses: [HARDWARE_ANSWER]});
  assert.equal(chrome.windows.opened.length, 0);  // no consent window for the trusted origin
  // A host error comes back as a fixed code only; a closed host connection is "unavailable".
  const failing = askHardware(listeners, {op: "hardware-key", challenge: "01".repeat(32)}, pageSender(LOCAL));
  await settleHardware(() => posted.filter(message => message.type === "hardware-key").length === 2);
  const second = posted.filter(message => message.type === "hardware-key").at(-1);
  fromHost(listeners, {type: "hardware-key", id: second.id, error: "no-key"});
  assert.deepEqual(await failing, {error: "no-key"});
  const closed = askHardware(listeners, {op: "hardware-key", challenge: "01".repeat(32)}, pageSender(LOCAL));
  await settleHardware(() => posted.filter(message => message.type === "hardware-key").length === 3);
  for (const listener of listeners["port.disconnect[]"]) listener();
  assert.deepEqual(await closed, {error: "unavailable"});
});

test("only a content script in a top HTTPS document may ask, and a page without a fresh signed identity gets nothing", async () => {
  const calls = [];
  const {listeners, posted, chrome} = loadBackground({builtOrigin: LOCAL, fetch: identityFetch("{}", {calls})});
  for (const sender of [pageSender(LOCAL, {frameId: 2}), pageSender(LOCAL, {tab: undefined}),
    pageSender(LOCAL, {id: "a".repeat(32)}), pageSender("http://example.com")]) {
    assert.equal(await askHardware(listeners, {op: "hardware-key-allowed"}, sender), "ignored");
  }
  const other = "https://phishing.example", challenge = "01".repeat(32);
  const relay = await hardwareBroker(RELAY), own = await hardwareBroker(other);
  for (const message of [
    {},
    {identity: "not json", proof: "{}", activation: true},
    // Another broker's statement and proof, copied: they name another origin.
    {identity: relay.identity, proof: await relay.proof(challenge), activation: true},
    // Its own statement without a proof, with an old proof, or a proof for another challenge.
    {identity: own.identity, activation: true},
    {identity: own.identity, proof: await own.proof(challenge, Math.floor(Date.now() / 1000) - 7200), activation: true},
    {identity: own.identity, proof: await own.proof("02".repeat(32)), activation: true},
  ]) {
    assert.deepEqual(await askHardware(listeners, {op: "hardware-key-allowed", challenge, ...message},
      pageSender(other)), {ok: false});
    assert.deepEqual(await askHardware(listeners, {op: "hardware-key", challenge, ...message}, pageSender(other)),
      {error: "denied"});
  }
  assert.equal(chrome.windows.opened.length, 0);
  assert.equal(posted.some(message => message.type === "hardware-key"), false);
  assert.deepEqual(calls, []);  // no request to the site: it cannot tell that the extension is there
});

test("another akdbx broker asks once, after a click, and the answer needs a fresh signature by the same key", async () => {
  const broker = await hardwareBroker(RELAY), challenge = "02".repeat(32);
  const local = {};
  const {listeners, posted, chrome} = loadBackground({builtOrigin: LOCAL, local});
  const fresh = async () => ({challenge, identity: broker.identity, proof: await broker.proof(challenge)});
  // Without a click on the page, a new identity gets no answer and no window.
  assert.deepEqual(await askHardware(listeners, {op: "hardware-key-allowed", ...await fresh()}, pageSender(RELAY)),
    {ok: false});
  const asked = {op: "hardware-key", ...await fresh(), activation: true};
  assert.deepEqual(await askHardware(listeners, {...asked, op: "hardware-key-allowed"}, pageSender(RELAY)), {ok: true});
  // The user closes the window: denied, nothing asked.
  let reply = askHardware(listeners, asked, pageSender(RELAY));
  await settleHardware(() => chrome.windows.opened.length === 1);
  listeners["windows.removed"](41);
  assert.deepEqual(await reply, {error: "denied"});
  // Only the consent page may read the request and answer it; it learns the origin from the worker.
  reply = askHardware(listeners, asked, pageSender(RELAY));
  await settleHardware(() => chrome.windows.opened.length === 2);
  const url = new URL(chrome.windows.opened[1].url);
  assert.equal(url.pathname, "/hardware.html");
  assert.equal(url.searchParams.has("origin"), false);
  const id = url.searchParams.get("id");
  const consentPage = {id: "jjoamaejjkldcjcpgncoomoaagdfimhg", url: url.href};
  assert.equal(await askHardware(listeners, {op: "hardware-consent", id, allow: true}, pageSender(RELAY)), "ignored");
  assert.deepEqual(await askHardware(listeners, {op: "hardware-consent-origin", id}, consentPage), {origin: RELAY});
  await askHardware(listeners, {op: "hardware-consent", id, allow: true}, consentPage);
  await settleHardware(() => posted.some(message => message.type === "hardware-key"));
  const request = posted.find(message => message.type === "hardware-key");
  fromHost(listeners, {type: "hardware-key", id: request.id, responses: [HARDWARE_ANSWER]});
  assert.deepEqual(await reply, {responses: [HARDWARE_ANSWER]});
  assert.deepEqual(copy(local.hardware_key_identities), [{origin: RELAY, key_id: broker.keyId}]);
  // Allowed: a fresh signature by the same key needs no click and no window next time.
  const again = askHardware(listeners, {op: "hardware-key", ...await fresh()}, pageSender(RELAY));
  await settleHardware(() => posted.filter(message => message.type === "hardware-key").length === 2);
  assert.equal(chrome.windows.opened.length, 2);
  const next = posted.filter(message => message.type === "hardware-key").at(-1);
  fromHost(listeners, {type: "hardware-key", id: next.id, error: "timeout"});
  assert.deepEqual(await again, {error: "timeout"});
  // A server that later answers at this address with the copied public statement, but no fresh
  // signature by that key, gets nothing; another key at the address is a new question.
  assert.deepEqual(await askHardware(listeners, {op: "hardware-key-allowed", challenge, identity: broker.identity},
    pageSender(RELAY)), {ok: false});
  const replaced = await hardwareBroker(RELAY);
  assert.deepEqual(await askHardware(listeners, {op: "hardware-key-allowed", challenge, identity: replaced.identity,
    proof: await replaced.proof(challenge)}, pageSender(RELAY)), {ok: false});
});
