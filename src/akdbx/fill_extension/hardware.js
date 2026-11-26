/* The hardware key consent window. The service worker opened it for one
 * request and tells it the requesting page's origin; the page itself cannot
 * draw, read or click this window. The answer goes back to the service worker,
 * which remembers an allowed origin.
 */
"use strict";
(async () => {
  const id = new URLSearchParams(location.search).get("id") || "";
  const reply = await akdbxBrowser.runtime.sendMessage({op: "hardware-consent-origin", id}).catch(() => null);
  const question = document.getElementById("question");
  if (!reply || typeof reply.origin !== "string") {
    question.textContent = "This request is not valid any more. You may close this window.";
    return;
  }
  question.textContent = "Allow this akdbx unlock page to use your hardware key?";
  const origin = document.getElementById("origin");
  origin.textContent = reply.origin;
  origin.hidden = false;
  document.getElementById("explain").hidden = false;
  document.getElementById("actions").hidden = false;
  const answer = allow => {
    akdbxBrowser.runtime.sendMessage({op: "hardware-consent", id, allow}).catch(() => {}).finally(() => window.close());
  };
  document.getElementById("allow").addEventListener("click", () => answer(true));
  document.getElementById("deny").addEventListener("click", () => answer(false));
  document.getElementById("deny").focus();
})();
