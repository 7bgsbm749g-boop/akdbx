/* akdbx content script. It runs in the extension's isolated world only.
 *
 * Page scripts cannot read this world's variables, retained elements or the
 * values that pass through it. `akdbx extension build` fills the markers below
 * with the CDP route's own DOM checks, so both routes apply the same rules.
 * No value is stored, logged or copied. A field is read back only by a read
 * pin (secret capture), and that value goes only to the service worker.
 */
"use strict";
(() => {
  if (globalThis.__akdbxContent) return;
  const CAPTURE = __PASSWORD_CAPTURE__;
  const PASSWORD_FILL = __PASSWORD_FILL__;
  const READ_CAPTURE = __READ_CAPTURE__;
  const READ = __READ__;
  const OWNER_GUARD = __OWNER_GUARD__;
  // The broker's read-pin selector grammar: tags, #id, .class and :nth-*(n) only.
  // Attribute and functional selectors could test a secret, so the extension
  // refuses them too: the pin call comes through the untrusted native host.
  const READ_SELECTOR = new RegExp("^(?:" + __READ_SELECTOR__ + ")$");
  const MAX_READ_SELECTOR = __MAX_READ_SELECTOR__;
  // True only when the manifest's document_start entry ran early.js first, before
  // any page script; content.js injected later by the worker finds no flag.
  const STARTED_EARLY = globalThis.__akdbxEarly === true;
  const CARD_PIN = __CARD_PIN_SCRIPT__;
  const GUARD = __CARD_GUARD__;
  const STRIPE_ELEMENTS = __STRIPE_ELEMENTS__;
  const count = () => __PASSWORD_COUNT__;
  const MAX_PINS = 16, MAX_PROBES = 4, PIN_MS = 30000, PROBE_MS = 60000;
  const CARD_TOKENS = ["cc-name", "cc-number", "cc-exp-month", "cc-exp-year", "cc-exp", "cc-csc"];
  const IDENTITY_TOKENS = ["name", "given-name", "additional-name", "family-name", "address-line1", "address-line2",
    "address-line3", "address-level2", "address-level1", "postal-code", "country", "country-name", "tel", "email",
    "street-address"];
  const COMPUTOP_IDS = {"cc-name": "creditCardHolder", "cc-number": "_KKnr", "cc-exp": "expiry_date", "cc-csc": "cccvc"};
  const pins = new Map(), guards = new Map(), probes = new Map();
  const owners = new Map(), listens = new Map(), ownerProbes = new Map();
  const MAX_NODES = 50000, MAX_FRAMES = 256, LISTEN_MS = 5000;
  let lastFocus = null;

  const randomId = () => Array.from(crypto.getRandomValues(new Uint8Array(16)),
    b => b.toString(16).padStart(2, "0")).join("");
  const remember = (map, limit, id, value) => {
    while (map.size >= limit) map.delete(map.keys().next().value);
    map.set(id, value);
  };

  // The user-click route fills the field that last received focus in this
  // document. Shadow-DOM fields retarget to their host and are not tracked.
  document.addEventListener("focusin", event => {
    const el = event.target;
    if (el instanceof HTMLInputElement || el instanceof HTMLSelectElement || el instanceof HTMLTextAreaElement) {
      lastFocus = {el, t: Date.now()};
    }
  }, true);

  // Owner probes (see ownerListen). This listener is added at document_start,
  // before any page listener, so a page can neither see a probe nor stop one.
  window.addEventListener("message", event => {
    const data = event.data;
    if (!data || typeof data !== "object" || !Object.prototype.hasOwnProperty.call(data, "akdbx_owner")) return;
    event.stopImmediatePropagation();
    if (Object.keys(data).length !== 1 || typeof data.akdbx_owner !== "string" ||
        !/^[0-9a-f]{32}$/.test(data.akdbx_owner) || event.source !== window.parent) return;
    for (const item of listens.values()) {
      if (event.origin === item.parentOrigin && item.heard.size < 8) item.heard.add(data.akdbx_owner);
    }
  }, true);

  // ----- agent route: retained pins --------------------------------------
  function pin(kind, spec, frameURL, topURL) {
    for (const [id, item] of pins) {
      if (performance.now() - item.created >= PIN_MS) release(id);
    }
    if (pins.size >= MAX_PINS) return null;
    if (kind === "read" && (typeof spec.selector !== "string" || spec.selector.length > MAX_READ_SELECTOR ||
        !READ_SELECTOR.test(spec.selector))) return null;
    let state, el = null;
    try {
      if (kind === "password") {
        state = CAPTURE(spec.selector, spec.username_selector, spec.mode, frameURL, spec.password_purpose,
          spec.allow_autocomplete_off === true, spec.frame_origin);
      } else if (kind === "read") {
        // The CDP route's read pin: a focused, visible, single-line text, never a
        // selection. The extension reads only in the top document.
        if (window !== window.top) return null;
        state = READ_CAPTURE(spec.selector, frameURL, null);
        el = state && document.querySelector(spec.selector);
      } else if (kind === "card" || kind === "identity") {
        state = CARD_PIN(spec.selector, spec.field, frameURL, topURL, spec.processor || false, kind === "identity");
      }
    } catch {
      state = null;
    }
    if (!state) return null;
    // The pin's own DOM checks passed. The service worker now asks for the cover check
    // (clear, then challengeSpec when something overlaps) before it reports the pin.
    const id = randomId();
    pins.set(id, {kind, mode: kind === "password" ? spec.mode : kind === "read" ? "read" : spec.field, state, el,
      processor: kind === "card" && Boolean(spec.processor), created: performance.now()});
    return id;
  }

  function geometry(id) {
    const item = pins.get(id);
    try {
      if (!item || item.kind === "password" || item.kind === "read") return null;
      return item.state.geometry() || null;
    } catch {
      return null;
    }
  }

  function release(id) {
    const item = pins.get(id);
    pins.delete(id);
    try {
      if (item && item.state.dispose) item.state.dispose();
    } catch {
      // Nothing to clean up.
    }
  }

  async function fill(id, kind, values, maxAgeMs, proven) {
    const item = pins.get(id);
    pins.delete(id);
    if (!item || item.kind !== kind || performance.now() - item.created >= PIN_MS) {
      if (item && item.state.dispose) item.state.dispose();
      return "refused";
    }
    try {
      if (kind === "password") {
        let valid = false;
        try {
          valid = values.mode === item.mode && item.state.check();
        } catch {
          valid = false;
        }
        if (!valid) return "refused";
        const deadline = item.created + Math.max(0, Math.min(maxAgeMs, PIN_MS));
        return PASSWORD_FILL.call(item.state, values.mode, values.username, values.password, deadline) ? "filled" : "refused";
      }
      // A fresh occlusion test, unless the service worker just proved the field with a
      // pixel challenge. Its result arrives in one task; every DOM check and the fill
      // run in that same task, so no page task runs between them.
      let seen = proven === true;
      try {
        seen = seen || await unoccluded(item.state.node());
      } catch {
        seen = false;
      }
      if (!seen || !item.state.geometry()) return "refused";
      const state = item.state.fill(values.value, maxAgeMs);
      return state === "filled" || state === "refused" ? state : "uncertain";
    } catch {
      return "uncertain";
    } finally {
      try {
        if (item.state.dispose) item.state.dispose();
      } catch {
        // Nothing to clean up.
      }
    }
  }

  // Secret capture: the checked value of a read pin, once. It goes back only to the
  // extension's service worker, which seals it to the broker.
  async function read(id, maxAgeMs, proven) {
    const item = pins.get(id);
    pins.delete(id);
    if (!item || item.kind !== "read" || performance.now() - item.created >= PIN_MS) {
      if (item && item.state.dispose) item.state.dispose();
      return null;
    }
    try {
      const deadline = item.created + Math.max(0, Math.min(maxAgeMs, PIN_MS));
      // As in fill(): the occlusion result, the checks and the read share one task.
      if (proven !== true && !(await unoccluded(item.el))) return null;
      if (!item.state.check()) return null;
      const value = READ.call(item.state, deadline);
      return typeof value === "string" ? value : null;
    } catch {
      return null;
    } finally {
      try {
        item.state.dispose();
      } catch {
        // Nothing to clean up.
      }
    }
  }

  // ----- child-frame owners ----------------------------------------------
  // The browser names a frame's parent document but not its <iframe> element.
  // The parent's isolated world posts a fresh nonce into each of its child
  // windows; the child's isolated world reports the nonces that its parent
  // window sent. Exactly one names the child's window. A page that forwards a
  // nonce it saw in another frame makes the child hear two, which refuses. The
  // <iframe> that holds that window then gets the CDP route's owner guard.
  function ownerListen(parentOrigin) {
    // A script injected after the page started could be preceded by page listeners.
    if (!STARTED_EARLY || window === window.top || typeof parentOrigin !== "string") return null;
    const id = randomId();
    remember(listens, MAX_PINS, id, {heard: new Set(), parentOrigin});
    setTimeout(() => listens.delete(id), LISTEN_MS);
    return id;
  }

  function ownerHeard(id) {
    const item = listens.get(id);
    return item ? Array.from(item.heard) : null;
  }

  function ownerDone(id) {
    listens.delete(id);
  }

  function ownerProbe(childOrigin) {
    // Every child window: those the window lists and those of every iframe,
    // frame and object element, also in shadow roots (window.frames leaves
    // those out). The real child always gets its own nonce, so a page that
    // forwards another frame's nonce to it makes it hear two. An embed's
    // window cannot be reached, so a document with one refuses.
    if (typeof childOrigin !== "string" || window.length > MAX_FRAMES) return null;
    const roots = shadowRoots();
    if (roots === null) return null;
    const views = new Set();
    for (let i = 0; i < window.length; ++i) {
      if (window[i]) views.add(window[i]);
    }
    for (const root of [document, ...roots]) {
      if (root.querySelector("embed")) return null;
      for (const el of root.querySelectorAll("iframe, frame, object")) {
        if (el.contentWindow) views.add(el.contentWindow);
      }
    }
    if (views.size > MAX_FRAMES) return null;
    const sent = new Map();
    for (const view of views) {
      const nonce = randomId();
      try {
        view.postMessage({akdbx_owner: nonce}, childOrigin);
        sent.set(nonce, view);
      } catch {
        // A frame that cannot take the message cannot be the owner.
      }
    }
    const id = randomId();
    remember(ownerProbes, MAX_PINS, id, sent);
    return id;
  }

  // Every open or closed shadow root of this document; null when the page is too large.
  function shadowRoots(doc = document) {
    const found = [];
    const pending = [doc];
    let seen = 0;
    while (pending.length) {
      const root = pending.pop();
      for (const el of root.querySelectorAll("*")) {
        if (++seen > MAX_NODES) return null;
        const shadow = chrome.dom.openOrClosedShadowRoot(el);
        if (shadow) {
          found.push(shadow);
          pending.push(shadow);
        }
      }
    }
    return found;
  }

  function ownerGuard(probeId, nonce) {
    const sent = ownerProbes.get(probeId);
    ownerProbes.delete(probeId);
    const view = sent && sent.get(nonce);
    if (!view) return null;
    // Exactly one <iframe> of this document's own tree holds that window; an
    // owner in a shadow root, an object or an embed refuses, as on the CDP route.
    const frames = Array.from(document.querySelectorAll("iframe")).slice(0, MAX_FRAMES + 1)
      .filter(frame => frame.contentWindow === view);
    if (frames.length !== 1) return null;
    let guardState;
    try {
      guardState = OWNER_GUARD.call(frames[0], true);
    } catch {
      guardState = null;
    }
    if (!guardState) return null;
    const id = randomId();
    while (owners.size >= MAX_PINS) ownerRelease(owners.keys().next().value);
    owners.set(id, {state: guardState, frame: frames[0]});
    return id;
  }

  function ownerCheck(id) {
    const item = owners.get(id);
    try {
      return Boolean(item && item.state.check());
    } catch {
      return false;
    }
  }

  function ownerRelease(id) {
    const item = owners.get(id);
    owners.delete(id);
    try {
      if (item) item.state.dispose();
    } catch {
      // Nothing to clean up.
    }
  }

  // ----- covers: the browser's occlusion test, then a pixel challenge --------
  // A field or a secret must be visible, not hidden under another element.
  // elementFromPoint cannot prove that: it skips click-through and inert covers,
  // and no list of selectors or pseudo-elements names every cover.
  //
  // 1. IntersectionObserver v2 (trackVisibility) is the browser's own answer. Its
  //    isVisible runs the occlusion hit test that CDP's DOM.getNodeForLocation
  //    runs (pointer-events and inert ignored, visual overflow included) over the
  //    element's whole box, from the top document down: each same-process parent
  //    document is part of that one hit test, and a cross-origin parent reports
  //    the occlusion of the whole <iframe> to its child. A popover, a backdrop,
  //    an exit transition, a pseudo-element, an inert or shadow cover: each is a
  //    box above the element, so isVisible is false. Opacity below 1, a filter or
  //    a distorting transform on the element's chain also make it false.
  // 2. That test is all-or-nothing for the whole box. A floating label, an icon
  //    in the field or the transparent backdrop of a popover elsewhere also make
  //    it false. Then the service worker runs a pixel challenge: a user-origin
  //    rule paints this one element in a random colour for a moment, and a
  //    screenshot of the tab must show that colour at the checked points. Only
  //    this element can show it there, and only if nothing is painted over it.
  const OCCLUSION_MS = 400, PAINT_MS = 1000, MAX_POINTS = 600;

  // The same-origin documents above this one, each with the frame element that
  // holds the next one down, up to the top; null when one cannot be reached.
  function ancestors() {
    const hops = [];
    for (let view = window; view !== view.top; view = view.parent) {
      const frame = view.frameElement;
      if (!frame || hops.length >= 16) return null;
      hops.push({doc: frame.ownerDocument, target: frame});
    }
    return hops;
  }

  // One fresh result of the browser's occlusion test for this element: true only
  // when the browser guarantees that nothing is painted over any part of it. No
  // rendered frame (a hidden tab) gives no result, which is false.
  function unoccluded(el) {
    return new Promise(resolve => {
      let observer = null, timer = null;
      const finish = value => {
        clearTimeout(timer);
        if (observer) observer.disconnect();
        observer = null;
        resolve(value);
      };
      // Below a cross-origin parent the first result can come before the parent
      // reported the frame's occlusion, so a later result may still be true.
      const final = ancestors() !== null;
      observer = new IntersectionObserver(entries => {
        const entry = entries[entries.length - 1];
        if (!observer || entry.target !== el) return;
        if (entry.isIntersecting && entry.isVisible === true) finish(true);
        else if (final) finish(false);
      }, {trackVisibility: true, delay: 100});
      observer.observe(el);
      timer = setTimeout(() => finish(false), OCCLUSION_MS);
    });
  }

  const pinned = item => item.kind === "read" ? item.el : item.state.node();

  function clear(id) {
    const item = pins.get(id);
    try {
      return item && item.kind !== "password" ? unoccluded(pinned(item)) : false;
    } catch {
      return false;
    }
  }

  // A structural selector for exactly this element of the document tree. The
  // challenge rule uses it, so the page's DOM gets no marker attribute.
  function pathTo(el) {
    const steps = [];
    for (let node = el; node !== document.documentElement; node = node.parentElement) {
      const parent = node.parentElement;
      if (!parent || steps.length >= 64) return null;
      steps.unshift(":nth-child(" + (Array.prototype.indexOf.call(parent.children, node) + 1) + ")");
    }
    if (!steps.length) return null;
    const path = ":root>" + steps.join(">");
    const found = document.querySelectorAll(path);
    return found.length === 1 && found[0] === el ? path : null;
  }

  // The points of a read pin, inside the element's padding box and clear of a focus
  // ring (the challenge colour paints neither the border nor an outline): for a
  // text input its start, centre and end, as the hit tests; for other text a point
  // every few pixels along each line, so a narrow cover over the text also refuses.
  function textPoints(el) {
    const box = el.getBoundingClientRect(), style = getComputedStyle(el), edge = 4;
    const inner = {left: box.left + parseFloat(style.borderLeftWidth) + edge, right: box.right - parseFloat(style.borderRightWidth) - edge,
      top: box.top + parseFloat(style.borderTopWidth) + edge, bottom: box.bottom - parseFloat(style.borderBottomWidth) - edge};
    if (!(inner.right >= inner.left) || !(inner.bottom >= inner.top)) return null;
    const input = el instanceof HTMLInputElement;
    let rects = [box];
    if (!input) {
      const range = document.createRange();
      range.selectNodeContents(el);
      rects = Array.from(range.getClientRects());
    }
    if (!rects.length || rects.length * 3 > MAX_POINTS) return null;
    const clamp = (value, low, high) => Math.min(Math.max(value, low), high);
    const each = Math.floor(MAX_POINTS / rects.length);
    const points = [];
    for (const rect of rects) {
      const y = clamp(rect.top + rect.height / 2, inner.top, inner.bottom);
      const from = clamp(rect.left + edge, inner.left, inner.right), to = clamp(rect.right - edge, inner.left, inner.right);
      const count = input ? 3 : clamp(Math.ceil((to - from) / 6) + 1, 3, each);
      for (let i = 0; i < count; ++i) points.push([from + (to - from) * i / (count - 1), y]);
    }
    return points;
  }

  function ownPaint(el) {
    const style = getComputedStyle(el);
    const drawn = value => value !== "none" && value !== "normal";
    if (style.display.includes("list-item")) {
      // ::marker content decides first: none draws nothing, normal draws the list style.
      const marker = getComputedStyle(el, "::marker").content;
      if (marker !== "none" && (marker !== "normal" || style.listStyleType !== "none" || style.listStyleImage !== "none")) {
        return true;
      }
    }
    // A scroll container's own scroll markers are generated boxes too, unless the group has no box.
    const markers = style.getPropertyValue("scroll-marker-group");
    if (markers && markers !== "none" && getComputedStyle(el, "::scroll-marker-group").display !== "none") return true;
    return ["::before", "::after"].some(pseudo => {
      const generated = getComputedStyle(el, pseudo);
      return drawn(generated.content) && generated.display !== "none";
    });
  }

  // What the service worker needs for a pixel challenge: the element's selector
  // and the points to look at, in the top document's viewport. A processor frame
  // cannot see its parents: it gives its own point, and the merchant-side guard
  // maps it (guardPoint).
  function challengeSpec(id) {
    const item = pins.get(id);
    try {
      if (!item || item.kind === "password") return null;
      const path = pathTo(pinned(item));
      if (!path) return null;
      if (item.kind === "read") {
        // Generated content of the element itself inherits the challenge colour, so
        // the pixels could not tell it from the text: a secret element that draws a
        // ::before, ::after or list marker refuses.
        if (ownPaint(item.el)) return null;
        const points = item.state.check() && textPoints(item.el);
        return points ? {path, points, view: [innerWidth, innerHeight]} : null;
      }
      const point = item.state.geometry();
      if (!point) return null;
      if (item.processor) return {path, local: point};
      const top = window.top;
      return {path, points: [[point.rootX - top.scrollX, point.rootY - top.scrollY]], view: [top.innerWidth, top.innerHeight]};
    } catch {
      return null;
    }
  }

  // Two animation frames: the challenge rule is then in a rendered frame.
  function painted() {
    return new Promise(resolve => {
      const timer = setTimeout(() => resolve(false), PAINT_MS);
      requestAnimationFrame(() => requestAnimationFrame(() => {
        clearTimeout(timer);
        resolve(document.visibilityState === "visible");
      }));
    });
  }

  // After the screenshot: the challenge rule still selects only the pinned element
  // and that element still has the challenge colour, so the colour in the
  // screenshot was this element's.
  function challengeHeld(id, path, colour) {
    const item = pins.get(id);
    try {
      if (!item || item.kind === "password" || typeof path !== "string") return false;
      const el = pinned(item), found = document.querySelectorAll(path);
      const shadow = getComputedStyle(el).boxShadow;
      return found.length === 1 && found[0] === el && shadow.startsWith(colour + " ") && shadow.endsWith(" inset") &&
        Boolean(item.kind === "read" ? item.state.check() : item.state.geometry());
    } catch {
      return false;
    }
  }

  // Processor frames: retain the merchant's iframe owner and check its chain.
  function guard(frameURL, topURL, processor) {
    const frames = Array.from(document.querySelectorAll("iframe")).slice(0, 256);
    const found = frames.map(frame => {
      try {
        const state = GUARD.call(frame, frameURL, topURL, processor);
        return state ? {state, frame} : null;
      } catch {
        return null;
      }
    }).filter(Boolean);
    if (found.length !== 1) return null;
    const id = randomId();
    remember(guards, MAX_PINS, id, found[0]);
    return id;
  }

  function guardCheck(id, point) {
    const item = guards.get(id);
    try {
      return Boolean(item && point && item.state.check(point));
    } catch {
      return false;
    }
  }

  // The processor field's own point, mapped through the retained merchant <iframe>
  // and its same-origin parents into the top document's viewport.
  function guardPoint(id, point) {
    const item = guards.get(id);
    try {
      const top = item && point && item.state.check(point);
      return top ? {points: [[top.x, top.y]], view: [window.top.innerWidth, window.top.innerHeight]} : null;
    } catch {
      return null;
    }
  }

  // ----- user-click route ------------------------------------------------
  function tokens(el) {
    const list = (el.getAttribute("autocomplete") || "").toLowerCase().match(/[^\t\n\f\r ]+/g) || [];
    if (list[list.length - 1] === "webauthn") list.pop();
    return list;
  }

  function shown(el) {
    if (!el.isConnected || el.disabled || el.readOnly || el.closest("[inert]") || document.visibilityState !== "visible") {
      return false;
    }
    const r = el.getBoundingClientRect(), s = getComputedStyle(el);
    return el.checkVisibility({checkOpacity: true, checkVisibilityCSS: true}) && r.width > 0 && r.height > 0 &&
      s.visibility === "visible" && s.display !== "none" && Number(s.opacity) !== 0;
  }

  function processorHere() {
    return {"js.stripe.com": "stripe", "www.computop-paygate.com": "computop",
      "checkoutshopper-live.adyen.com": "adyen"}[location.hostname] || null;
  }

  function role(el, processor) {
    const input = el instanceof HTMLInputElement;
    const type = input ? el.type : el.tagName.toLowerCase();
    const last = tokens(el).slice(-1)[0] || "";
    if (processor === "stripe") {
      // The popup fills only the Payment Element's id/name pairs. The classic
      // Card Element's inputs have no id; only the verified agent pin route
      // (exact type, autocomplete, unique name, merchant iframe owner and hit
      // test) may target them, so no input in such a document matches here.
      // Only an embedded Payment Element frame at its exact path matches: a
      // top-level Stripe document has no merchant owner, and an unrecognized
      // Stripe path is not a frame whose inputs akdbx has verified.
      if (window === window.top || !new RegExp(STRIPE_ELEMENTS["payment-element"].path).test(location.pathname)) return null;
      const hit = Object.entries(STRIPE_ELEMENTS["payment-element"].fields).find(([, [id, name]]) =>
        id !== null && el.id === id && el.getAttribute("name") === name);
      return hit && input ? {kind: "card", role: hit[0]} : null;
    }
    if (processor === "computop") {
      const hit = Object.entries(COMPUTOP_IDS).find(([, id]) => el.id === id && el.getAttribute("name") === id);
      return hit && input ? {kind: "card", role: hit[0]} : null;
    }
    if (CARD_TOKENS.includes(last) && (input && ["text", "tel", "password"].includes(type) ||
        type === "select" && ["cc-exp-month", "cc-exp-year"].includes(last))) {
      return {kind: "card", role: last};
    }
    if (input && type === "password") return {kind: "login", role: "password"};
    if (processor) return null;
    if (input && ["text", "email"].includes(type) && last === "username") return {kind: "login", role: "username"};
    if (IDENTITY_TOKENS.includes(last) && (input && ["text", "email", "tel"].includes(type) ||
        type === "select" && ["country", "country-name", "address-level1"].includes(last) ||
        type === "textarea" && last === "street-address")) {
      return {kind: "identity", role: last};
    }
    return null;
  }

  function isLoginPassword(el, processor) {
    const found = role(el, processor);
    return Boolean(found && found.kind === "login" && found.role === "password");
  }

  function sameScope(focused, el) {
    return focused.form ? el.form === focused.form : !el.form;
  }

  function probe() {
    const focus = lastFocus;
    if (!focus || focus.el !== document.activeElement || !shown(focus.el)) return null;
    const processor = processorHere();
    let first = role(focus.el, processor);
    const inputs = Array.from(document.querySelectorAll("input,select,textarea")).slice(0, 256)
      .filter(el => sameScope(focus.el, el) && shown(el));
    const index = inputs.indexOf(focus.el);
    if (!first && focus.el instanceof HTMLInputElement && ["text", "email"].includes(focus.el.type) &&
        inputs.slice(index + 1).some(el => isLoginPassword(el, processor))) {
      first = {kind: "login", role: "username"};  // A sign-in form without hints.
    }
    if (!first || index < 0) return null;
    const fields = [{el: focus.el, role: first.role}];
    if (first.kind === "login") {
      const text = el => el instanceof HTMLInputElement && ["text", "email"].includes(el.type);
      const partner = first.role === "password"
        ? inputs.slice(0, index).reverse().find(text)
        : inputs.slice(index + 1).find(el => isLoginPassword(el, processor));
      if (partner) fields.push({el: partner, role: first.role === "password" ? "username" : "password"});
    } else {
      for (const el of inputs) {
        const other = el === focus.el ? null : role(el, processor);
        if (other && other.kind === first.kind && !fields.some(item => item.role === other.role)) {
          fields.push({el, role: other.role});
        }
      }
    }
    const formats = {};
    for (const item of fields) {
      if (item.role === "cc-exp") {
        formats[item.role] = processor === "stripe" || processor === "computop" || !(item.el.maxLength >= 7)
          ? "MM/YY" : "MM/YYYY";
      } else if (item.role === "cc-exp-year") {
        formats[item.role] = item.el instanceof HTMLSelectElement
          ? (Array.from(item.el.options).some(o => /^[0-9]{4}$/.test(o.value)) ? "YYYY" : "YY")
          : (item.el.maxLength === 2 ? "YY" : "YYYY");
      }
    }
    for (const item of fields) {
      item.identity = identity(item.el);
      item.form = item.el.form;
    }
    const id = randomId();
    remember(probes, MAX_PROBES, id, {fields, focused: focus.el, created: performance.now()});
    return {id, t: focus.t, kind: first.kind, roles: fields.map(item => item.role), formats};
  }

  // What a retained field was when the user opened the popup.
  function identity(el) {
    return JSON.stringify([el.tagName, el instanceof HTMLInputElement ? el.type : "", el.getAttribute("autocomplete"),
      el.id, el.getAttribute("name"), el.parentElement === null]);
  }

  // Plan one assignment without touching the field; null refuses.
  function plan(el, value, fieldRole) {
    if (el instanceof HTMLSelectElement) {
      const options = Array.from(el.options).filter(o => !o.disabled && (o.value === value ||
        fieldRole === "cc-exp-month" && /^[0-9]{1,2}$/.test(o.value) && Number(o.value) === Number(value) ||
        fieldRole.startsWith("country") && o.textContent.trim().toLowerCase() === value.toLowerCase()));
      if (options.length !== 1) return null;
      const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "selectedIndex").set;
      const step = () => setter.call(el, options[0].index);
      step.expected = options[0].value;
      return step;
    }
    if (el instanceof HTMLInputElement && value.includes("\n")) return null;
    if (el.maxLength >= 0 && value.length > el.maxLength) return null;
    const proto = el instanceof HTMLInputElement ? HTMLInputElement.prototype : HTMLTextAreaElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, "value").set;
    const step = () => setter.call(el, value);
    step.expected = value;
    return step;
  }

  function accepted(field, value, expected) {
    const el = field.el;
    const proto = el instanceof HTMLInputElement ? HTMLInputElement.prototype
      : el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLSelectElement.prototype;
    const actual = Object.getOwnPropertyDescriptor(proto, "value").get.call(el);
    // Card fields may add grouping spaces in their own input handler.
    return actual === expected || ["cc-number", "cc-exp"].includes(field.role) &&
      actual.replace(/\s/g, "") === expected.replace(/\s/g, "");
  }

  function probeFill(id, values) {
    const item = probes.get(id);
    probes.delete(id);
    if (!item || performance.now() - item.created >= PROBE_MS || document.activeElement !== item.focused ||
        !shown(item.focused) || typeof values !== "object" || values === null) return "refused";
    const targets = item.fields.filter(field => typeof values[field.role] === "string");
    // A field that became hidden, disabled, detached or different never
    // receives a value. Every check and assignment runs before any page event.
    if (!targets.length || targets.some(field => !shown(field.el) || identity(field.el) !== field.identity ||
        field.el.form !== field.form)) return "refused";
    const steps = targets.map(field => plan(field.el, values[field.role], field.role));
    if (steps.some(step => step === null)) return "refused";
    steps.forEach(step => step());
    for (const field of targets) {
      field.el.dispatchEvent(new Event("input", {bubbles: true}));
      field.el.dispatchEvent(new Event("change", {bubbles: true}));
    }
    // A page handler may change a later field; never report that as filled.
    // The comparison stays in this isolated world and returns only a state.
    const kept = targets.every((field, i) => field.el.isConnected && identity(field.el) === field.identity &&
      field.el.form === field.form && accepted(field, values[field.role], steps[i].expected));
    return kept ? "filled" : "uncertain";
  }

  Object.defineProperty(globalThis, "__akdbxContent", {value: Object.freeze({
    pin, geometry, release, fill, read, guard, guardCheck, guardPoint, count, probe, probeFill,
    clear, challengeSpec, challengeHeld, painted,
    releaseGuard: id => guards.delete(id),
    ownerListen, ownerHeard, ownerDone, ownerProbe, ownerGuard, ownerCheck, ownerRelease,
  })});
})();
