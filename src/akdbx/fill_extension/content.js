/* akdbx content script. It runs in the extension's isolated world only.
 *
 * Page scripts cannot read this world's variables, retained elements or the
 * values that pass through it. `akdbx extension build` fills the markers below
 * with the CDP route's own DOM checks, so both routes apply the same rules.
 * No value is stored, logged, copied or read back from a field.
 */
"use strict";
(() => {
  if (globalThis.__akdbxContent) return;
  const CAPTURE = __PASSWORD_CAPTURE__;
  const PASSWORD_FILL = __PASSWORD_FILL__;
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

  // ----- agent route: retained pins --------------------------------------
  function pin(kind, spec, frameURL, topURL) {
    for (const [id, item] of pins) {
      if (performance.now() - item.created >= PIN_MS) release(id);
    }
    if (pins.size >= MAX_PINS) return null;
    let state;
    try {
      if (kind === "password") {
        state = CAPTURE(spec.selector, spec.username_selector, spec.mode, frameURL, spec.password_purpose,
          spec.allow_autocomplete_off === true, spec.frame_origin);
      } else if (kind === "card" || kind === "identity") {
        state = CARD_PIN(spec.selector, spec.field, frameURL, topURL, spec.processor || false, kind === "identity");
      }
    } catch {
      state = null;
    }
    if (!state) return null;
    const id = randomId();
    pins.set(id, {kind, mode: kind === "password" ? spec.mode : spec.field, state, created: performance.now()});
    return id;
  }

  function geometry(id) {
    const item = pins.get(id);
    try {
      return item && item.kind !== "password" ? item.state.geometry() : null;
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

  function fill(id, kind, values, maxAgeMs) {
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

  // Processor frames: retain the merchant's iframe owner and check its chain.
  function guard(frameURL, topURL, processor) {
    const frames = Array.from(document.querySelectorAll("iframe")).slice(0, 256);
    const found = frames.map(frame => {
      try {
        return GUARD.call(frame, frameURL, topURL, processor);
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
      return Boolean(item && point && item.check(point));
    } catch {
      return false;
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
    pin, geometry, release, fill, guard, guardCheck, count, probe, probeFill,
    releaseGuard: id => guards.delete(id),
  })});
})();
