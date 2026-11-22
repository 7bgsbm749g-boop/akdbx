/* akdbx extension trust: the one origin where pairing and unlock links may open.
 *
 * Links arrive through the native host, and a replaced host could send the
 * user to a look-alike master-password page. So the popup opens a link only
 * on the origin this extension trusts:
 *
 * - `akdbx extension build` may write a first origin into config.js.
 * - The extension never stores a first broker key that only the native host
 *   sent. It reads the broker's statement over HTTPS from the trusted origin
 *   (`/.well-known/akdbx-identity`) and stores the key, origin and sequence
 *   number only when that statement verifies, names the trusted origin and
 *   has the key the host sent. A failed read stores nothing and keeps the
 *   trusted origin; the next popup tries again.
 * - With no trusted origin at all (no built origin, or after the user's
 *   reset), it reads the statement from the origin that the statement names.
 *   When that read fails, it trusts the host's statement on first use.
 * - Later, it accepts a new origin only in a statement that the stored key
 *   signed, with the stored key id, a higher sequence number and a valid
 *   HTTPS origin. Anything else keeps the stored origin.
 * - A different broker key is never accepted silently: the user must click
 *   "Reset broker trust" in the popup and pair again.
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

  function storedKey(record) {
    return hasKeys(record, ["key_id", "origin", "public_key", "seq", "v"]) && record.v === 1 &&
      typeof record.public_key === "string" && PUBLIC_KEY.test(record.public_key) &&
      typeof record.key_id === "string" && KEY_ID.test(record.key_id) && validOrigin(record.origin) &&
      Number.isSafeInteger(record.seq) && record.seq >= 1;
  }

  const KEY_CHANGED = "This broker signs with another identity key than the one this extension trusts, so akdbx " +
    "opens no pairing or unlock page. If you moved akdbx to another computer or deleted its saved state, reset the " +
    "broker trust below and pair again. Otherwise, do not enter your master password.";

  /* What to trust now. `stored` is the saved record (or null), `built` the origin from config.js,
   * `verified` the result of verifyIdentity, and `received` whether the host sent an identity at all.
   * `fetched` is the statement read over HTTPS: undefined before the read, null when it failed.
   * Returns {origin, store?, fetch?, error, reset, changed, learned}: `origin` is the only origin for links
   * (or null), `store` a new record to save, `fetch` the origin whose statement to read before a first key
   * is stored (then call again with `fetched`), `error` fixed text for the user, and `reset` whether the
   * popup offers the reset. */
  function decide(stored, built, verified, received, fetched) {
    const known = storedKey(stored) ? stored : null;
    const afterReset = plain(stored) && stored.v === 1 && stored.reset === true;
    const builtOrigin = !afterReset && validOrigin(built) ? built : null;
    const keep = (origin, error, reset = false) => ({origin, error, reset, changed: false, learned: false});
    const learn = facts => ({origin: facts.origin, store: {v: 1, ...facts}, error: null, reset: false, changed: false,
      learned: true});
    if (known) {
      if (!received) return keep(known.origin, null);  // An older broker: no statement to check.
      if (!verified) return keep(known.origin, `The broker's origin statement could not be verified; akdbx keeps ${known.origin}.`);
      if (verified.public_key !== known.public_key || verified.key_id !== known.key_id) {
        return keep(known.origin, KEY_CHANGED, true);
      }
      if (verified.seq > known.seq) {
        return {origin: verified.origin, store: {v: 1, ...verified}, error: null, reset: false,
          changed: verified.origin !== known.origin, learned: false};
      }
      if (verified.seq === known.seq && verified.origin === known.origin) return keep(known.origin, null);
      return keep(known.origin, `The broker sent an older origin statement; akdbx keeps ${known.origin}.`);
    }
    // No key yet: the first key must also come over HTTPS from the trusted origin.
    if (!received) return keep(builtOrigin, null);
    if (!verified) return keep(builtOrigin, "The broker's origin statement could not be verified; akdbx does not trust its origin.");
    if (builtOrigin && verified.origin !== builtOrigin) {
      return keep(builtOrigin, `The broker names ${verified.origin}, but this extension was built for ${builtOrigin}. ` +
        "Reset the broker trust below to pair on the broker's origin, or run akdbx extension build again.", true);
    }
    const target = builtOrigin || verified.origin;
    if (fetched === undefined) return {...keep(builtOrigin, null), fetch: target};
    if (fetched) {
      if (fetched.origin !== target || fetched.public_key !== verified.public_key || fetched.key_id !== verified.key_id) {
        return keep(builtOrigin, `The broker page at ${target} names another identity than the native host sent, so ` +
          "akdbx learns no broker key. Do not enter your master password until the broker and the akdbx native host " +
          "are the ones you installed.");
      }
      return learn(fetched);
    }
    // The read failed. With a trusted origin, store nothing and try again at the next popup.
    if (builtOrigin) return keep(builtOrigin, null);
    // No trusted origin at all: trust the host's statement on first use.
    return learn(verified);
  }

  const api = {STORAGE_KEY, IDENTITY_PATH, validOrigin, privateLink, canonical, verifyIdentity, fetchIdentity, decide,
    storedKey};
  globalThis.akdbxTrust = api;
  if (typeof module !== "undefined") module.exports = api;
})();
