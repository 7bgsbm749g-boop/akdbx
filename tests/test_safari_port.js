"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "../src/akdbx/fill_extension/safari-port.js"), "utf8");
const token = "a".repeat(64);
const hello = {type: "hello", protocol: 1, public_key: "synthetic public point", version: "0.11.0.1"};
const tick = () => new Promise(resolve => setImmediate(resolve));

function lab(handler) {
  const calls = [];
  const context = vm.createContext({TextEncoder, setTimeout, clearTimeout,
    akdbxBrowser: {runtime: {sendNativeMessage: async (host, message) => {
      assert.equal(host, "org.akdbx.extension");
      const copy = JSON.parse(JSON.stringify(message));
      calls.push(copy);
      return handler(copy);
    }}}
  });
  vm.runInContext(source, context);
  return {port: context.akdbxConnectNative("org.akdbx.extension"), calls};
}

test("the native hello precedes queued writes and broker frames reach listeners", async () => {
  let resolveRead;
  const {port, calls} = lab(message => {
    if (message.op === "open") return {ok: true, session: token};
    if (message.op === "read") return new Promise(resolve => { resolveRead = resolve; });
    return {ok: true};
  });
  const received = [];
  port.onMessage.addListener(message => received.push(message));
  port.postMessage(hello);
  const outgoing = {type: "request", id: "1", op: "ping"};
  port.postMessage(outgoing);
  outgoing.op = "changed after enqueue";
  await tick();
  assert.deepEqual(calls.filter(m => m.op !== "read"), [
    {op: "open", hello}, {op: "write", session: token, message: {type: "request", id: "1", op: "ping"}}
  ]);
  resolveRead({ok: true, message: {type: "attached", connected: true}});
  await tick();
  assert.deepEqual(received, [{type: "attached", connected: true}]);
  port.disconnect();
  resolveRead({ok: true});
  await tick();
  assert.equal(calls.filter(m => m.op === "close").length, 1);
});

test("disconnect during open closes the newly opened session without delivering frames", async () => {
  let resolveOpen;
  const {port, calls} = lab(message => message.op === "open"
    ? new Promise(resolve => { resolveOpen = resolve; }) : {ok: true});
  let disconnected = 0;
  port.onDisconnect.addListener(() => { disconnected++; });
  port.postMessage(hello);
  await tick();
  port.disconnect();
  resolveOpen({ok: true, session: token});
  await tick();
  assert.equal(disconnected, 1);
  assert.deepEqual(calls.map(m => m.op), ["open", "close"]);
  assert.throws(() => port.postMessage({type: "request"}), /disconnected/);
});

test("a rejected native operation disconnects once and drops queued writes", async () => {
  const {port, calls} = lab(() => ({ok: false}));
  let disconnected = 0;
  port.onDisconnect.addListener(() => { disconnected++; });
  port.postMessage(hello);
  port.postMessage({type: "request"});
  await tick();
  assert.equal(disconnected, 1);
  assert.deepEqual(calls.map(m => m.op), ["open"]);
});

test("invalid session tokens and invalid broker frames are refused", async t => {
  await t.test("session token", async () => {
    const {port, calls} = lab(() => ({ok: true, session: "bad"}));
    let disconnected = false;
    port.onDisconnect.addListener(() => { disconnected = true; });
    port.postMessage(hello);
    await tick();
    assert.equal(disconnected, true);
    assert.deepEqual(calls.map(m => m.op), ["open"]);
  });
  await t.test("non-object broker frame", async () => {
    const {port} = lab(m => m.op === "open" ? {ok: true, session: token}
      : m.op === "read" ? {ok: true, message: []} : {ok: true});
    let received = false, disconnected = false;
    port.onMessage.addListener(() => { received = true; });
    port.onDisconnect.addListener(() => { disconnected = true; });
    port.postMessage(hello);
    await tick();
    assert.equal(received, false);
    assert.equal(disconnected, true);
  });
});

test("oversized and non-object outgoing frames never call native messaging", () => {
  const {port, calls} = lab(() => { throw new Error("must not run"); });
  assert.throws(() => port.postMessage({type: "hello", value: "x".repeat(64 * 1024)}), /limit/);
  assert.throws(() => port.postMessage([]), /invalid/);
  assert.equal(calls.length, 0);
  port.disconnect();
});
