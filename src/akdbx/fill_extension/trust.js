/* akdbx extension trust: the one origin where pairing and unlock links may open.
 *
 * Links arrive through the native host, and a replaced host could send the
 * user to a look-alike master-password page. So the popup opens a link only
 * on the origin this extension trusts:
 *
 * - `akdbx extension build` may write a first origin into config.js.
 * - At the first pairing, the extension stores the broker's identity key, its
 *   origin and sequence number in chrome.storage.local (trust on first use).
 *   It takes them only when the origin equals the built origin, or when there
 *   is no built origin.
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
   * Returns {origin, store?, error, reset, changed, learned}: `origin` is the only origin for links
   * (or null), `store` a new record to save, `error` fixed text for the user, and `reset` whether the
   * popup offers the reset. */
  function decide(stored, built, verified, received) {
    const known = storedKey(stored) ? stored : null;
    const afterReset = plain(stored) && stored.v === 1 && stored.reset === true;
    const builtOrigin = !afterReset && validOrigin(built) ? built : null;
    const keep = (origin, error, reset = false) => ({origin, error, reset, changed: false, learned: false});
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
    // No key yet: trust on first use, bound to the built origin when there is one.
    if (!received) return keep(builtOrigin, null);
    if (!verified) return keep(builtOrigin, "The broker's origin statement could not be verified; akdbx does not trust its origin.");
    if (builtOrigin && verified.origin !== builtOrigin) {
      return keep(builtOrigin, `The broker names ${verified.origin}, but this extension was built for ${builtOrigin}. ` +
        "Reset the broker trust below to pair on the broker's origin, or run akdbx extension build again.", true);
    }
    return {origin: verified.origin, store: {v: 1, ...verified}, error: null, reset: false, changed: false, learned: true};
  }

  const api = {STORAGE_KEY, validOrigin, privateLink, canonical, verifyIdentity, decide, storedKey};
  globalThis.akdbxTrust = api;
  if (typeof module !== "undefined") module.exports = api;
})();
