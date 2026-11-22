/* akdbx extension trust: the one origin where pairing and unlock links may open.
 *
 * Links arrive through the native host, and a replaced host could send the
 * user to a look-alike master-password page. So the popup opens a link only
 * on the origin this extension trusts:
 *
 * - The extension always has an origin that it trusts independently of the
 *   host: the one `akdbx extension build` wrote into config.js, or the one it
 *   stored after a verified HTTPS key binding (or a signed move). With
 *   neither, it opens no link at all and asks the user to build it.
 * - It never stores a broker key or origin that only the native host sent.
 *   It reads the broker's statement over HTTPS from the trusted origin
 *   (`/.well-known/akdbx-identity`) and stores the key, origin and sequence
 *   number only when that statement verifies, names the trusted origin and
 *   has the key the host sent. A failed read stores nothing; the next
 *   identity message tries again.
 * - Later, it accepts a new origin only in a statement that the stored key
 *   signed, with the stored key id, a higher sequence number and a valid
 *   HTTPS origin. Anything else keeps the stored origin.
 * - A different broker key is never accepted silently, and no link opens
 *   while it is offered. "Reset broker trust" in the popup clears only the
 *   stored key and sequence number and keeps the trusted origin; the next
 *   key is again bound only through that origin's HTTPS page.
 * - A broker that names another origin than the trusted one, with no
 *   signature by the stored key, gets no reset: only a local
 *   `akdbx extension build` changes the first trusted origin.
 * - Each saved record keeps the built origin it was made under (`built`).
 *   When config.js names another built origin (the user ran
 *   `akdbx extension build` for another address and reloaded), the saved
 *   record no longer counts and trust starts again from the new built
 *   origin. The native host cannot write config.js. A record with no
 *   `built` counts as made under the current build.
 *
 * The signed bytes are the statement's JSON text with sorted keys and no
 * whitespace; src/akdbx/broker_identity.py documents the encoding and signs.
 */
"use strict";
(function () {
  const ORIGIN = new RegExp("^https://(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*" +
    "|\\[[0-9a-f:.]{2,45}\\])(?::[1-9][0-9]{0,4})?$");
  const KEY_ID = /^[A-Za-z0-9_-]{43}$/, PUBLIC_KEY = /^[A-Za-z0-9_-]{87}$/, SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
  const STORAGE_KEY = "broker_trust";
  const IDENTITY_PATH = "/.well-known/akdbx-identity";
  const FETCH_MS = 3000, MAX_IDENTITY = 4096;

  function encode(data) {
    return btoa(String.fromCharCode(...new Uint8Array(data))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function decode(text) {
    return Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
  }

  function plain(value) {
    return Object.prototype.toString.call(value) === "[object Object]";
  }

  function hasKeys(value, keys) {
    return plain(value) && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
  }

  // The browser serialization of an HTTPS origin, with no path, query, fragment or credentials.
  function validOrigin(value) {
    if (typeof value !== "string" || !ORIGIN.test(value)) return false;
    try {
      const url = new URL(value);
      return url.protocol === "https:" && url.origin === value && url.pathname === "/" && !url.search &&
        !url.hash && !url.username && !url.password;
    } catch {
      return false;
    }
  }

  // A link from the host opens only on the trusted origin, at one exact path.
  function privateLink(value, path, trusted) {
    try {
      const url = new URL(value);
      return typeof trusted === "string" && url.origin === new URL(trusted).origin && url.protocol === "https:" &&
        url.pathname === path && !url.username && !url.password ? url.href : null;
    } catch {
      return null;
    }
  }

  // Sorted keys, no whitespace. Callers pass only checked ASCII strings and safe integers.
  function canonical(value) {
    if (plain(value)) {
      return "{" + Object.keys(value).sort().map(k => JSON.stringify(k) + ":" + canonical(value[k])).join(",") + "}";
    }
    return JSON.stringify(value);
  }

  // The verified facts of a broker `identity` message, or null.
  async function verifyIdentity(identity) {
    try {
      if (!hasKeys(identity, ["public_key", "signature", "statement"])) return null;
      const statement = identity.statement;
      if (!hasKeys(statement, ["key_id", "origin", "seq", "type", "v"]) || statement.type !== "akdbx-origin" ||
          statement.v !== 1 || !Number.isSafeInteger(statement.seq) || statement.seq < 1 ||
          typeof statement.key_id !== "string" || !KEY_ID.test(statement.key_id) || !validOrigin(statement.origin) ||
          typeof identity.public_key !== "string" || !PUBLIC_KEY.test(identity.public_key) ||
          typeof identity.signature !== "string" || !SIGNATURE.test(identity.signature)) return null;
      const point = decode(identity.public_key);
      const signature = decode(identity.signature);
      if (point.length !== 65 || point[0] !== 4 || signature.length !== 64) return null;
      if (encode(await crypto.subtle.digest("SHA-256", point)) !== statement.key_id) return null;
      const key = await crypto.subtle.importKey("raw", point, {name: "ECDSA", namedCurve: "P-256"}, false, ["verify"]);
      const valid = await crypto.subtle.verify({name: "ECDSA", hash: "SHA-256"}, key, signature,
        new TextEncoder().encode(canonical(statement)));
      return valid ? {public_key: identity.public_key, key_id: statement.key_id, origin: statement.origin,
        seq: statement.seq} : null;
    } catch {
      return null;
    }
  }

  /* The broker's statement, read over HTTPS from `origin`: the verified facts, or null when the read fails.
   * TLS, the Host check and the exact origin bind it to the page where the user enters the master password. */
  async function fetchIdentity(origin, fetchImpl = typeof fetch === "function" ? fetch.bind(globalThis) : null,
      timeout = FETCH_MS) {
    if (!validOrigin(origin) || typeof fetchImpl !== "function") return null;
    let timer = null;
    try {
      const controller = new AbortController();
      timer = setTimeout(() => controller.abort(), timeout);
      const response = await fetchImpl(origin + IDENTITY_PATH, {method: "GET", redirect: "error", credentials: "omit",
        cache: "no-store", referrerPolicy: "no-referrer", headers: {Accept: "application/json"}, signal: controller.signal});
      if (!response || response.status !== 200 || response.redirected ||
          (response.url && response.url !== origin + IDENTITY_PATH)) return null;
      const type = response.headers && typeof response.headers.get === "function" ? response.headers.get("content-type") : null;
      if (typeof type !== "string" || type.split(";")[0].trim().toLowerCase() !== "application/json") return null;
      const text = await response.text();
      if (typeof text !== "string" || text.length > MAX_IDENTITY) return null;
      return await verifyIdentity(JSON.parse(text));
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  // The record without its `built` field, when that field is absent, null or a valid origin; else null.
  function withoutBuilt(record) {
    if (!plain(record)) return null;
    const {built, ...rest} = record;
    return built === undefined || built === null || validOrigin(built) ? rest : null;
  }

  function storedKey(stored) {
    const record = withoutBuilt(stored);
    return hasKeys(record, ["key_id", "origin", "public_key", "seq", "v"]) && record.v === 1 &&
      typeof record.public_key === "string" && PUBLIC_KEY.test(record.public_key) &&
      typeof record.key_id === "string" && KEY_ID.test(record.key_id) && validOrigin(record.origin) &&
      Number.isSafeInteger(record.seq) && record.seq >= 1;
  }

  const KEY_CHANGED = "This broker signs with another identity key than the one this extension trusts, so akdbx " +
    "opens no pairing or unlock page. If you set up this broker again yourself (another computer, or its saved " +
    "state was deleted), reset the broker trust below: the extension then reads the new key from the broker's " +
    "HTTPS page at the same address. If you did not set up this broker again yourself, do not reset and do not " +
    "enter your master password.";
  const NOT_BUILT = "This extension has no trusted broker address, so akdbx opens no pairing or unlock page. " +
    "Run “akdbx extension build” on the computer with the broker, then load the new extension in this browser.";

  // The broker names another origin than the trusted one, and the stored key did not sign that move.
  function elsewhere(named, trusted, built) {
    return `The broker names ${named}, but this extension ${trusted === built ? "was built for" : "trusts"} ` +
      `${trusted}, so akdbx opens no pairing or unlock page on ${named}. If you moved the broker to ${named} ` +
      "yourself, run “akdbx extension build” again on the computer with the broker and reload the extension: " +
      "a build for a new address replaces the saved broker trust. Otherwise, do not enter your master password.";
  }

  // An origin that the user's reset kept: the key is gone, the origin stays.
  function resetRecord(stored) {
    const record = withoutBuilt(stored);
    return hasKeys(record, ["origin", "reset", "v"]) && record.v === 1 && record.reset === true &&
      validOrigin(record.origin);
  }

  // The built origin from config.js, or null.
  function builtOf(built) {
    return validOrigin(built) ? built : null;
  }

  // The saved record when it belongs to the current build, else null: a rebuild for another address starts over.
  function current(stored, built) {
    if (!(storedKey(stored) || resetRecord(stored))) return null;
    return stored.built === undefined || stored.built === builtOf(built) ? stored : null;
  }

  // The origin this extension trusts independently of the native host, or null.
  function trustedOrigin(stored, built) {
    const record = current(stored, built);
    return record ? record.origin : builtOf(built);
  }

  // A record to save, with the built origin it was made under.
  function saveRecord(facts, built) {
    return {v: 1, ...facts, built: builtOf(built)};
  }

  /* What to trust now. `stored` is the saved record (or null), `built` the origin from config.js,
   * `verified` the result of verifyIdentity, and `received` whether the host sent an identity at all.
   * `fetched` is the statement read over HTTPS: undefined before the read, null when it failed.
   * Returns {origin, store?, fetch?, from?, error, reset, changed, learned}: `origin` is the only origin for
   * links (or null: no link opens), `store` a new record to save, `fetch` the origin whose statement to read
   * before a first key is stored (then call again with `fetched`), `from` the old origin of a signed move,
   * `error` fixed text for the user, and `reset` whether the popup offers the reset. A saved record made under
   * another built origin is ignored, as if nothing were saved. */
  function decide(stored, built, verified, received, fetched) {
    const saved = current(stored, built);
    const known = storedKey(saved) ? saved : null;
    const trusted = trustedOrigin(stored, built);
    const keep = (origin, error, reset = false) => ({origin, error, reset, changed: false, learned: false});
    if (!trusted) return keep(null, NOT_BUILT);
    if (known) {
      if (!received) return keep(known.origin, null);  // An older broker: no statement to check.
      if (!verified) return keep(known.origin, `The broker's origin statement could not be verified; akdbx keeps ${known.origin}.`);
      if (verified.public_key !== known.public_key || verified.key_id !== known.key_id) {
        // No link opens until a reset and a new binding through the trusted origin's HTTPS page.
        if (verified.origin !== known.origin) return keep(null, elsewhere(verified.origin, known.origin, built));
        return keep(null, KEY_CHANGED, true);
      }
      if (verified.seq > known.seq) {
        const changed = verified.origin !== known.origin;
        return {origin: verified.origin, store: saveRecord(verified, built), error: null, reset: false, changed,
          learned: false, ...(changed ? {from: known.origin} : {})};
      }
      if (verified.seq === known.seq && verified.origin === known.origin) return keep(known.origin, null);
      return keep(known.origin, `The broker sent an older origin statement; akdbx keeps ${known.origin}.`);
    }
    // No key yet: the first key must come over HTTPS from the trusted origin.
    if (!received) return keep(trusted, null);
    if (!verified) return keep(trusted, `The broker's origin statement could not be verified; akdbx keeps ${trusted}.`);
    if (verified.origin !== trusted) return keep(trusted, elsewhere(verified.origin, trusted, built));
    if (fetched === undefined) return {...keep(trusted, null), fetch: trusted};
    if (!fetched) return keep(trusted, null);  // The read failed: store nothing, try again later.
    if (fetched.origin !== trusted || fetched.public_key !== verified.public_key || fetched.key_id !== verified.key_id) {
      return keep(trusted, `The broker page at ${trusted} names another identity than the native host sent, so ` +
        "akdbx learns no broker key. Do not enter your master password until the broker and the akdbx native host " +
        "are the ones you installed.");
    }
    return {origin: fetched.origin, store: saveRecord(fetched, built), error: null, reset: false, changed: false, learned: true};
  }

  const api = {STORAGE_KEY, IDENTITY_PATH, validOrigin, privateLink, canonical, verifyIdentity, fetchIdentity, decide,
    storedKey, trustedOrigin, saveRecord};
  globalThis.akdbxTrust = api;
  if (typeof module !== "undefined") module.exports = api;
})();
