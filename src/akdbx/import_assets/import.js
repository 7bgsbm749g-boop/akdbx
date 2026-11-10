/* Private UI: no storage, telemetry, remote libraries, console, or image upload. */
"use strict";
(() => {
  const images = document.getElementById("images");
  const camera = document.getElementById("camera");
  const manual = document.getElementById("manual");
  const hidden = document.getElementById("payloads");
  const message = document.getElementById("message");
  const form = hidden.form;
  let busy = false;
  let payloads = [];
  let inputRevision = 0;
  function invalidate() {
    inputRevision++;
    payloads = [];
    hidden.value = "";
    message.textContent = "";
  }
  function clear() {
    invalidate();
    for (const element of [images, camera, manual, hidden]) element.value = "";
  }
  images.onchange = () => { camera.value = ""; invalidate(); };
  camera.onchange = () => { images.value = ""; invalidate(); };
  manual.oninput = invalidate;
  async function decode(revision) {
    const selected = Array.from(camera.files.length ? camera.files : images.files);
    if (!selected.length || selected.length > 8) throw new Error();
    const result = [];
    for (const file of selected) {
      if (!file.size || file.size > 4 * 1024 * 1024 || !/^image\/(png|jpeg|webp)$/.test(file.type)) throw new Error();
      const url = URL.createObjectURL(file);
      const image = new Image();
      const canvas = document.createElement("canvas");
      let pixels;
      try {
        image.src = url;
        await image.decode();
        if (revision !== inputRevision) return false;
        if (!image.naturalWidth || !image.naturalHeight || image.naturalWidth > 4096 || image.naturalHeight > 4096) throw new Error();
        canvas.width = image.naturalWidth;
        canvas.height = image.naturalHeight;
        const ctx = canvas.getContext("2d", {willReadFrequently: true});
        ctx.drawImage(image, 0, 0);
        pixels = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const qr = jsQR(pixels.data, canvas.width, canvas.height);
        if (!qr || !qr.data || qr.data.length > 8192) throw new Error();
        result.push(qr.data);
      } finally {
        if (pixels) pixels.data.fill(0);
        canvas.width = canvas.height = 0;
        image.src = "";
        URL.revokeObjectURL(url);
      }
    }
    if (revision !== inputRevision) return false;
    payloads = result;
    manual.value = "";
    message.textContent = "QR data read privately. Select Review accounts to continue.";
    return true;
  }
  document.getElementById("decode").onclick = async () => {
    if (busy) return;
    busy = true;
    const revision = inputRevision;
    try { await decode(revision); }
    catch {
      if (revision === inputRevision) {
        clear(); message.textContent = "Could not read a supported QR image. Try PNG/JPEG/WebP or enter the original setup key.";
      }
    }
    finally { busy = false; }
  };
  form.onsubmit = async event => {
    event.preventDefault();
    if (busy) return;
    busy = true;
    let revision = inputRevision;
    try {
      if (manual.value.trim()) payloads = [manual.value.trim()];
      else if (!payloads.length && !await decode(revision)) return;
      if (revision !== inputRevision) return;
      const body = new URLSearchParams({payloads: JSON.stringify(payloads)});
      clear();
      revision = inputRevision;
      const response = await fetch(form.action, {method: "POST", body, cache: "no-store", credentials: "same-origin", redirect: "error"});
      if (revision !== inputRevision) return;
      if (!response.ok) throw new Error();
      location.replace("/totp/review" + location.search);
    } catch {
      if (revision === inputRevision) {
        clear();
        message.textContent = "Import not confirmed. Check the request status; use a complete supported export or a fresh request.";
      }
    } finally { busy = false; }
  };
  addEventListener("pagehide", clear);
  addEventListener("pageshow", clear);
})();
