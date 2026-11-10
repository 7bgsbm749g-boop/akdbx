/* Node tests use synthetic QR pixels and mocked Chrome/DOM APIs only. */
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");
const fixture = require("./synthetic_qr.json");
const root = path.join(__dirname, "../src/akdbx");
const jsQR = require(path.join(root, "import_assets/jsQR.js"));
const {captureSetup} = require(path.join(root, "browser_extension/popup.js"));

function pixels() {
  const scale = 4, width = fixture.rows.length * scale;
  const data = new Uint8ClampedArray(width * width * 4);
  for (let y = 0; y < width; y++) for (let x = 0; x < width; x++) {
    const i = (y * width + x) * 4;
    const value = fixture.rows[Math.floor(y / scale)][Math.floor(x / scale)] === "1" ? 0 : 255;
    data[i] = data[i+1] = data[i+2] = value; data[i+3] = 255;
  }
  return {data, width, height: width};
}

test("vendored decoder reads independent synthetic QR matrix", () => {
  const p = pixels();
  assert.equal(jsQR(p.data, p.width, p.height).data, fixture.uri);
  assert.equal(jsQR(new Uint8ClampedArray(p.data.length), p.width, p.height), null);
});

test("capture finds one QR, wipes pixel buffer, and rejects ambiguity", () => {
  const p = pixels();
  global.jsQR = jsQR;
  let links = [];
  global.document = {
    querySelectorAll: selector => selector === "canvas,img" ? [{width:p.width,height:p.height}] : links,
    createElement: () => ({getContext: () => ({drawImage() {},getImageData: () => p})})
  };
  try {
    assert.deepEqual(captureSetup(), {ok:true,payloads:[fixture.uri]});
    assert.ok(p.data.every(x => x === 0));
    links = [fixture.uri, fixture.uri.replace("synthetic-account", "second")].map(uri => ({tagName:"A",getAttribute:()=>uri}));
    assert.deepEqual(captureSetup(), {ok:false});
  } finally { delete global.document; delete global.jsQR; }
});

test("capture has no screenshot fallback for a tainted canvas", () => {
  global.document = {querySelectorAll:selector => selector === "canvas,img" ? [{width:200,height:200}] : [],
    createElement:()=>({getContext:()=>({drawImage(){throw new Error("synthetic taint");}})})};
  try { assert.deepEqual(captureSetup(),{ok:false}); }
  finally { delete global.document; }
});

function popup({url="https://example.test/setup", changed=false, documentChanged=false, receipt={ok:true,state:"awaiting-private-confirmation"}}={}) {
  const elements = {capture:{disabled:false},status:{textContent:""},destination:{value:"https://private.example:9443/totp?token=synthetic"}};
  const calls = [];
  let injections=0;
  const context = {
    document:{getElementById:id=>elements[id]},URL,
    chrome:{
      tabs:{query:async()=>[{id:42,url}],get:async()=>({url:changed?"https://other.test":url})},
      scripting:{executeScript:async options=>{
        calls.push(options);injections++;
        return [{documentId:documentChanged&&injections===3?"changed":"one-document",result:options.files?undefined:injections===2?{ok:true,payloads:[fixture.uri]}:true}];
      }},
      runtime:{sendNativeMessage:async(name,payload)=>{calls.push({name,payload});return receipt;}}
    }
  };
  vm.runInNewContext(fs.readFileSync(path.join(root,"browser_extension/popup.js"),"utf8"),context);
  return {elements,calls,run:()=>elements.capture.onclick()};
}

test("popup sends only to native host, shows receipt, and clears link", async () => {
  const p = popup();await p.run();
  const transfer = p.calls.find(c=>c.name);
  assert.equal(transfer.name,"org.akdbx.private_import");
  assert.equal(transfer.payload.source_url,"https://example.test/setup");
  assert.equal(transfer.payload.payloads[0],fixture.uri);
  assert.equal(p.elements.destination.value,"");
  assert.match(p.elements.status.textContent,/Captured privately/);
  assert.ok(!p.elements.status.textContent.includes(fixture.uri));
});

for (const options of [{url:"http://example.test"},{changed:true},{documentChanged:true}]) {
  test("popup refuses insecure or changed document "+JSON.stringify(options),async()=>{
    const p=popup(options);await p.run();assert.ok(!p.calls.some(c=>c.name));
    assert.match(p.elements.status.textContent,/not confirmed/);
  });
}
test("popup rejects secret-bearing native responses without reflecting them",async()=>{
  const p=popup({receipt:{ok:true,state:"awaiting-private-confirmation",key:fixture.uri}});
  await p.run();assert.match(p.elements.status.textContent,/not confirmed/);
  assert.ok(!p.elements.status.textContent.includes(fixture.uri));
});
