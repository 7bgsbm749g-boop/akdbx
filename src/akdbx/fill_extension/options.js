/* akdbx settings page. Settings live in local storage, which only extension pages
 * reach (background.js); the service worker reads them for each fill. */
"use strict";

const SETTINGS_KEY = "settings";
// Enhanced security takes tab screenshots: captureVisibleTab needs <all_urls>.
const ALL_SITES = {origins: ["<all_urls>"]};

async function readSettings(storage) {
  const found = (await storage.get(SETTINGS_KEY))[SETTINGS_KEY];
  return found && typeof found === "object" && !Array.isArray(found) ? found : {};
}

// Turn enhanced security on or off; the answer says what the page shows next.
async function setEnhanced(api, on) {
  // permissions.request must run in the click's activation, so it is the first call.
  if (on && !(await api.permissions.request(ALL_SITES))) return {on: false, granted: false, denied: true};
  const settings = await readSettings(api.storage.local);
  await api.storage.local.set({[SETTINGS_KEY]: {...settings, enhanced_security: on}});
  // Never permissions.remove here: Chrome then also withholds the required https:// access.
  return {on, granted: await api.permissions.contains(ALL_SITES), denied: false};
}

async function currentState(api) {
  const settings = await readSettings(api.storage.local);
  return {on: settings.enhanced_security === true, granted: await api.permissions.contains(ALL_SITES), denied: false};
}

// The note under the switch: [class, text]; an empty text hides it.
function statusText({on, granted, denied}) {
  if (denied) return ["warning", "Enhanced security is still off: the browser did not allow the screenshots."];
  if (on && !granted) {
    return ["warning", "The browser no longer lets akdbx take screenshots, so every card, address and secret fill " +
      "stops. Turn this off, or turn it off and on again to allow the screenshots."];
  }
  if (!on && granted) return ["detail", "Off: akdbx takes no screenshots. The browser keeps the access you gave."];
  return ["", ""];
}

function versionText(manifest) {
  const version = manifest && typeof manifest.version === "string" ? manifest.version : "";
  return /^\d{1,5}\.\d{1,5}\.\d{1,5}(\.\d{1,5})?$/.test(version) ? "akdbx extension " + version : "akdbx extension";
}

function unreadable() {
  const status = document.getElementById("enhanced-status");
  status.textContent = "The settings could not be read. Close this page and open it again.";
  status.className = "status warning";
  status.hidden = false;
  document.getElementById("enhanced").disabled = true;
}

async function main() {
  const toggle = document.getElementById("enhanced");
  const status = document.getElementById("enhanced-status");
  document.getElementById("version").textContent = versionText(akdbxBrowser.runtime.getManifest());
  const show = state => {
    toggle.checked = state.on;
    const [kind, text] = statusText(state);
    status.className = "status " + kind;
    status.textContent = text;
    status.hidden = !text;
  };
  const refresh = async () => show(await currentState(chrome));
  toggle.addEventListener("change", async event => {
    if (!event.isTrusted) return;
    toggle.disabled = true;
    try {
      show(await setEnhanced(chrome, toggle.checked));
      toggle.disabled = false;
    } catch {
      // Show what is saved; if even that cannot be read, keep the switch locked with a warning.
      try {
        await refresh();
        toggle.disabled = false;
      } catch {
        unreadable();
      }
    }
  });
  // Site access can also change on the browser's own extension page.
  const changed = () => refresh().catch(unreadable);
  akdbxBrowser.permissions.onAdded.addListener(changed);
  akdbxBrowser.permissions.onRemoved.addListener(changed);
  akdbxBrowser.storage.onChanged.addListener((changes, area) => { if (area === "local" && SETTINGS_KEY in changes) changed(); });
  await refresh();
  toggle.disabled = false;
}

if (typeof document !== "undefined" && typeof akdbxBrowser !== "undefined" && akdbxBrowser.runtime) {
  main().catch(unreadable);
}
if (typeof module !== "undefined") module.exports = {setEnhanced, currentState, statusText, readSettings, SETTINGS_KEY, ALL_SITES};
