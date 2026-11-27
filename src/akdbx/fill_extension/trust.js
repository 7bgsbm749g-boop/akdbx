/* akdbx extension trust: the one origin where pairing and unlock links may open.
 *
 * Links arrive through the native host, and a replaced host could send the
 * user to a look-alike master-password page. So the popup opens a link only
 * on the origin this extension trusts. Fill extension 0.19.0 is one generic
 * build for every user: config.js holds no broker address and no build ID.
 *
 * - First use. With no saved trust, the extension takes the origin that the
 *   native host's signed identity statement names only as a proposal. The
 *   popup shows that exact origin and asks the user to confirm it; until then
 *   no pairing or unlock link opens and no captured secret is sealed to the
 *   broker. The confirmation saves that origin only (`{v, origin}`), and only
 *   while the host still names it. This is the one point where the native
 *   host chooses anything: a host that a same-user attacker replaced before
 *   the first confirmation can propose its own origin, and the user's check
 *   of the shown origin is the guard (README "Browser extension trust").
 * - It never stores a broker key that only the native host sent. It reads the
 *   broker's statement over HTTPS from the trusted origin
 *   (`/.well-known/akdbx-identity`) and stores the key, origin and sequence
 *   number only when that statement verifies, names the trusted origin and
 *   has the key the host sent. A failed read stores nothing new; the next
 *   identity message tries again.
 * - Later, it accepts a new origin only in a statement that the stored key
 *   signed, with the stored key id, a higher sequence number and a valid
 *   HTTPS origin. Anything else keeps the stored origin.
 * - A different broker key is never accepted silently, and no link opens
 *   while it is offered. "Reset broker trust" in the popup clears only the
 *   stored key and sequence number and keeps the trusted origin; the next
 *   key is again bound only through that origin's HTTPS page.
 * - A broker that names another origin than the trusted one, with no
 *   signature by the stored key, gets no reset. The popup offers "Forget this
 *   broker" instead: it deletes the saved trust, and the next origin again
 *   needs the user's confirmation (first use). The native host cannot click
 *   in the popup, so it cannot forget or confirm anything itself.
 * - Records saved by a per-deployment build (fill extension 0.18.x and
 *   earlier, which baked the origin and a random build ID into config.js)
 *   carry a `build` field. This build keeps them: the extension wrote them
 *   itself after the same HTTPS key binding, so an update keeps the broker
 *   trust and needs no new confirmation. A newer record is saved without it.
 *
 * The signed bytes are the statement's JSON text with sorted keys and no
 * whitespace; src/akdbx/broker_identity.py documents the encoding and signs.
 */
"use strict";
(function () {
  const ORIGIN = new RegExp("^https://(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*" +
    "|\\[[0-9a-f:.]{2,45}\\])(?::[1-9][0-9]{0,4})?$");
  const KEY_ID = /^[A-Za-z0-9_-]{43}$/, PUBLIC_KEY = /^[A-Za-z0-9_-]{87}$/, SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
  // The random build ID that per-deployment builds (fill extension 0.18.x and earlier) saved with each record.
  const LEGACY_BUILD = /^[A-Za-z0-9_-]{22}$/;
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

  /* The broker's signature over one connection: its per-connection ECDH key and this extension's key,
   * signed by the identity key in `trusted` (a saved record). The native host relays that ECDH key, so
   * only this signature shows that the broker, not the host, made it. */
  async function verifyChannel(trusted, brokerKey, extensionKey, signature) {
    try {
      if (!plain(trusted) || typeof trusted.public_key !== "string" || !PUBLIC_KEY.test(trusted.public_key) ||
          typeof trusted.key_id !== "string" || !KEY_ID.test(trusted.key_id) ||
          typeof brokerKey !== "string" || !PUBLIC_KEY.test(brokerKey) ||
          typeof extensionKey !== "string" || !PUBLIC_KEY.test(extensionKey) ||
          typeof signature !== "string" || !SIGNATURE.test(signature)) return false;
      const statement = {broker_key: brokerKey, extension_key: extensionKey, key_id: trusted.key_id,
        type: "akdbx-channel", v: 1};
      const key = await crypto.subtle.importKey("raw", decode(trusted.public_key), {name: "ECDSA", namedCurve: "P-256"},
        false, ["verify"]);
      return await crypto.subtle.verify({name: "ECDSA", hash: "SHA-256"}, key, decode(signature),
        new TextEncoder().encode(canonical(statement)));
    } catch {
      return false;
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

  // The record without the `build` field of a per-deployment build, or null when that field is malformed.
  function withoutBuild(record) {
    if (!plain(record)) return null;
    const {build, ...rest} = record;
    if (Object.prototype.hasOwnProperty.call(record, "build") && !(typeof build === "string" && LEGACY_BUILD.test(build))) {
      return null;
    }
    return rest;
  }

  // A bound broker key: its public key, key id, trusted origin and sequence number.
  function storedKey(stored) {
    const record = withoutBuild(stored);
    return hasKeys(record, ["key_id", "origin", "public_key", "seq", "v"]) && record.v === 1 &&
      typeof record.public_key === "string" && PUBLIC_KEY.test(record.public_key) &&
      typeof record.key_id === "string" && KEY_ID.test(record.key_id) && validOrigin(record.origin) &&
      Number.isSafeInteger(record.seq) && record.seq >= 1;
  }

  // A trusted origin with no key yet: the user confirmed it (`{v, origin}`), or a reset kept it
  // (`{v, origin, reset: true}`, the form that builds before 0.19.0 wrote).
  function originOnly(stored) {
    const record = withoutBuild(stored);
    if (!plain(record) || record.v !== 1 || !validOrigin(record.origin)) return false;
    return hasKeys(record, ["origin", "v"]) || (hasKeys(record, ["origin", "reset", "v"]) && record.reset === true);
  }

  // The saved record when it is one this extension trusts, else null (then nothing is trusted yet).
  function current(stored) {
    return storedKey(stored) || originOnly(stored) ? stored : null;
  }

  // The broker identity key this extension trusts ({public_key, key_id}), or null before the first binding.
  function trustedKey(stored) {
    const record = current(stored);
    return storedKey(record) ? {public_key: record.public_key, key_id: record.key_id} : null;
  }

  // The origin this extension trusts, or null: then no link opens and the popup asks for a confirmation.
  function trustedOrigin(stored) {
    const record = current(stored);
    return record ? record.origin : null;
  }

  // A record to save: the verified facts {public_key, key_id, origin, seq}.
  function saveRecord(facts) {
    return {v: 1, ...facts};
  }

  // A trusted origin with no key: what the user's confirmation (first use) and a reset save.
  function originRecord(origin) {
    return validOrigin(origin) ? {v: 1, origin} : null;
  }

  const KEY_CHANGED = "This broker signs with another identity key than the one this extension trusts, so akdbx " +
    "opens no pairing or unlock page. If you set up this broker again yourself (another computer, or its saved " +
    "state was deleted), reset the broker trust below: the extension then reads the new key from the broker's " +
    "HTTPS page at the same address. If you did not set up this broker again yourself, do not reset and do not " +
    "enter your master password.";
  const NO_STATEMENT = "The broker sent no signed address, so akdbx has no broker address to show you and opens " +
    "no pairing or unlock page. Update akdbx on the computer with the broker and restart the broker; " +
    "“akdbx status” there shows extension_trust when the broker signs its address.";
  const UNVERIFIED = "The broker's origin statement could not be verified, so akdbx has no broker address to show " +
    "you and opens no pairing or unlock page.";

  // The broker names another origin than the trusted one, and the stored key did not sign that move.
  function elsewhere(named, trusted) {
    return `The broker names ${named}, but this extension trusts ${trusted}, so akdbx opens no pairing or unlock ` +
      `page on ${named}. If you moved the broker to ${named} yourself, forget this broker below and confirm ` +
      `${named} when akdbx asks. Otherwise, do not forget it and do not enter your master password.`;
  }

  /* What to trust now. `stored` is the saved record (or null), `verified` the result of verifyIdentity, and
   * `received` whether the host sent an identity at all. `fetched` is the statement read over HTTPS: undefined
   * before the read, null when it failed.
   * Returns {origin, store?, fetch?, from?, propose, error, reset, forget, changed, learned}: `origin` is the only
   * origin for links (or null: no link opens), `store` a new record to save, `fetch` the origin whose statement
   * to read before a first key is stored (then call again with `fetched`), `from` the old origin of a signed
   * move, `propose` the host's origin that the popup asks the user to confirm (nothing is trusted yet), `error`
   * fixed text for the user, `reset` whether the popup offers the reset and `forget` whether it offers to forget
   * the broker. */
  function decide(stored, verified, received, fetched) {
    const saved = current(stored);
    const known = storedKey(saved) ? saved : null;
    const trusted = saved ? saved.origin : null;
    const keep = (origin, error, {reset = false, forget = false, propose = null} = {}) =>
      ({origin, error, reset, forget, propose, changed: false, learned: false});
    if (!trusted) {
      // First use: the host's origin is only a proposal, shown to the user; nothing opens before the confirmation.
      if (!received) return keep(null, NO_STATEMENT);
      if (!verified) return keep(null, UNVERIFIED);
      return keep(null, null, {propose: verified.origin});
    }
    if (known) {
      if (!received) return keep(known.origin, null);  // An older broker: no statement to check.
      if (!verified) return keep(known.origin, `The broker's origin statement could not be verified; akdbx keeps ${known.origin}.`);
      if (verified.public_key !== known.public_key || verified.key_id !== known.key_id) {
        // No link opens until a reset (same origin) or a forget (another origin) and a new binding.
        if (verified.origin !== known.origin) return keep(null, elsewhere(verified.origin, known.origin), {forget: true});
        return keep(null, KEY_CHANGED, {reset: true});
      }
      if (verified.seq > known.seq) {
        const changed = verified.origin !== known.origin;
        return {origin: verified.origin, store: saveRecord(verified), error: null, reset: false, forget: false,
          propose: null, changed, learned: false, ...(changed ? {from: known.origin} : {})};
      }
      if (verified.seq === known.seq && verified.origin === known.origin) return keep(known.origin, null);
      return keep(known.origin, `The broker sent an older origin statement; akdbx keeps ${known.origin}.`);
    }
    // A trusted origin with no key yet: the first key must come over HTTPS from that origin.
    if (!received) return keep(trusted, null);
    if (!verified) return keep(trusted, `The broker's origin statement could not be verified; akdbx keeps ${trusted}.`);
    if (verified.origin !== trusted) return keep(trusted, elsewhere(verified.origin, trusted), {forget: true});
    if (fetched === undefined) return {...keep(trusted, null), fetch: trusted};
    if (!fetched) return keep(trusted, null);  // The read failed: store nothing, try again later.
    if (fetched.origin !== trusted || fetched.public_key !== verified.public_key || fetched.key_id !== verified.key_id) {
      return keep(trusted, `The broker page at ${trusted} names another identity than the native host sent, so ` +
        "akdbx learns no broker key. Do not enter your master password until the broker and the akdbx native host " +
        "are the ones you installed.");
    }
    return {origin: fetched.origin, store: saveRecord(fetched), error: null, reset: false, forget: false, propose: null,
      changed: false, learned: true};
  }

  const api = {STORAGE_KEY, IDENTITY_PATH, validOrigin, privateLink, canonical, verifyIdentity, fetchIdentity, decide,
    storedKey, trustedOrigin, saveRecord, originRecord, trustedKey, verifyChannel};
  globalThis.akdbxTrust = api;
  if (typeof module !== "undefined") module.exports = api;
})();
