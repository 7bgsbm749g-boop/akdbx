"use strict";
// This function runs in Chrome's isolated extension world, not agent evaluation.
function captureSetup() {
  const found = new Set();
  function add(value) {
    if (typeof value === "string" && value.startsWith("otpauth://totp/") && value.length <= 4096) found.add(value);
  }
  for (const element of Array.from(document.querySelectorAll("a[href],code")).slice(0, 128)) {
    add(element.getAttribute("href"));
    if (element.tagName === "CODE") add(element.textContent.trim());
  }
  const elements = Array.from(document.querySelectorAll("canvas,img")).slice(0, 32);
  let remainingPixels = 12 * 1024 * 1024;
  for (const element of elements) {
    const width = element.naturalWidth || element.width;
    const height = element.naturalHeight || element.height;
    if (!width || !height || width > 2048 || height > 2048) continue;
    if (width * height > remainingPixels) break;
    remainingPixels -= width * height;
    const canvas = document.createElement("canvas");
    let pixels;
    try {
      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext("2d", {willReadFrequently: true});
      ctx.drawImage(element, 0, 0);
      pixels = ctx.getImageData(0, 0, width, height);
      const qr = jsQR(pixels.data, width, height);
      if (qr) add(qr.data);
    } catch {
      // Tainted canvas, inaccessible image, or unsupported page: no screenshot
      // fallback and no page data in errors.
    } finally {
      if (pixels) pixels.data.fill(0);
      canvas.width = canvas.height = 0;
    }
  }
  if (found.size !== 1) return {ok: false};
  return {ok: true, payloads: Array.from(found)};
}

if (typeof document !== "undefined") {
  document.getElementById("capture").onclick = async () => {
    const button = document.getElementById("capture");
    const status = document.getElementById("status");
    const destination = document.getElementById("destination");
    button.disabled = true;
    try {
      const privateUrl = new URL(destination.value);
      if (privateUrl.protocol !== "https:" || privateUrl.pathname !== "/totp" || !privateUrl.searchParams.get("token")) throw new Error();
      const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
      if (!tab || !tab.id || new URL(tab.url).protocol !== "https:") throw new Error();
      const [decoder] = await chrome.scripting.executeScript({target: {tabId: tab.id}, files: ["jsQR.js"]});
      const [capture] = await chrome.scripting.executeScript({target: {tabId: tab.id}, func: captureSetup});
      if (!decoder || !capture || !capture.documentId || decoder.documentId !== capture.documentId || !capture.result || capture.result.ok !== true) throw new Error();
      // Recheck navigation: never label data from a different document as the
      // origin whose page was inspected. Full-document navigation is rejected.
      const current = await chrome.tabs.get(tab.id);
      if (current.url !== tab.url) throw new Error();
      const [check] = await chrome.scripting.executeScript({target: {tabId: tab.id}, func: () => true});
      if (!check || check.documentId !== capture.documentId) throw new Error();
      const receipt = await chrome.runtime.sendNativeMessage("org.akdbx.private_import", {
        private_url: privateUrl.href, source_url: tab.url, payloads: capture.result.payloads
      });
      capture.result.payloads = [];
      if (!receipt || Object.keys(receipt).sort().join(",") !== "ok,state" || receipt.ok !== true || receipt.state !== "awaiting-private-confirmation") throw new Error();
      status.textContent = "Captured privately. Open the original akdbx link, choose Import / review, and confirm the account before saving.";
    } catch {
      status.textContent = "Capture not confirmed. Check the native host, matching HTTPS site, private request, and one readable setup QR. No automatic retry.";
    } finally {
      destination.value = "";
      button.disabled = false;
    }
  };
}
if (typeof module !== "undefined") module.exports = {captureSetup};
