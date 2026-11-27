"""DOM-bound card delivery. This module has no keyboard or clipboard backend."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import sys
import time
from urllib.parse import urlsplit

from .cards import FILL_FIELDS
from . import card_processor
from . import card_hit_test
from .runtime import open_private_runtime_directory
from . import cdp_peer
from . import browser_slots

DELIVERY = 'cdp-card-element-v1'
CARD_PURPOSE_PROTOCOL = 1
TTL = 30
MAX_PINS = 16


class CardTargetError(Exception):
    pass


def failure(started=False, *, kind='card'):
    return dict(ok=False, delivery='uncertain' if started else 'not-started',
                error=f'{kind} fill outcome uncertain; do not retry automatically' if started else
                f'{kind} fill not started: target unavailable, changed or unsupported; pin again')


# An app field (native or Android) has no page whose handlers could see the value.
NOTIFY_PAGE_REFUSED = dict(ok=False, delivery='not-started',
                           error='identity fill not started: --notify-page needs a web page, and an app field has none; '
                                 'pin again and fill without --notify-page')


def secure_url(value):
    if (not isinstance(value, str) or len(value) > 4096 or not value.isascii()
            or any(ord(c) <= 32 or ord(c) == 127 for c in value) or '\\' in value):
        raise CardTargetError()
    u = urlsplit(value)
    if u.scheme != 'https' or not u.hostname or u.username is not None or u.password is not None or u.port == 0:
        raise CardTargetError()
    return u.hostname.lower(), u.port or 443


def browser_endpoint(profile):
    # Reuse the broker's anchored, owned, private-directory policy. The profile
    # is local deployment configuration, never supplied by a fill RPC.
    if os.name == 'nt':
        from . import windows_browser
        try:
            return windows_browser.endpoint(profile)
        except Exception:
            raise CardTargetError() from None
    _, directory = open_private_runtime_directory(Path(profile))
    try:
        fd = os.open('DevToolsActivePort', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, 'r', encoding='ascii') as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o022 or info.st_size > 256 or info.st_nlink != 1):
                raise CardTargetError()
            if sys.platform == 'darwin':
                from .macos import require_private_acl
                require_private_acl(fd)
            parts = source.read(257).splitlines()
        if (len(parts) != 2 or not re.fullmatch(r'[0-9]{1,5}', parts[0])
                or not 1 <= int(parts[0]) <= 65535
                or not re.fullmatch(r'/devtools/browser/[a-zA-Z0-9-]{1,80}', parts[1])):
            raise CardTargetError()
        return 'ws://127.0.0.1:' + parts[0] + parts[1]
    finally:
        os.close(directory)


def verify_peer(connection):
    try:
        cdp_peer.verify_peer(connection)
    except Exception:
        raise CardTargetError() from None


class CDP:
    def __init__(self, profile):
        import websocket
        url = browser_endpoint(profile)
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection = None
        try:
            raw.settimeout(2)
            raw.connect(('127.0.0.1', urlsplit(url).port))
            verify_peer(raw)
            connection = websocket.create_connection(url, socket=raw, redirect_limit=0, timeout=2,
                                                      suppress_origin=True, http_no_proxy=['127.0.0.1'])
            if connection.sock is not raw or connection.getstatus() != 101:
                raise CardTargetError()
        except BaseException:
            try:
                if connection is not None:
                    connection.close(timeout=0)
            finally:
                raw.close()
            raise
        self.socket = connection
        self.counter = 0

    def call(self, method, params=None, session=None):
        self.counter += 1
        request = dict(id=self.counter, method=method, params=params or {})
        if session:
            request['sessionId'] = session
        deadline = time.monotonic() + 2
        self.socket.send(json.dumps(request, separators=(',', ':')))
        for _ in range(128):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CardTargetError()
            self.socket.settimeout(remaining)
            raw = self.socket.recv()
            if not isinstance(raw, str) or len(raw) > 1024 * 1024:
                raise CardTargetError()
            result = json.loads(raw)
            if result.get('id') != self.counter:
                continue
            if 'error' in result or not isinstance(result.get('result'), dict):
                raise CardTargetError()
            return result['result']
        raise CardTargetError()

    def close(self):
        self.socket.close(timeout=0)


# All DOM methods run in a private isolated world. Page JavaScript cannot replace
# its builtins or the native value setter. Capture the actual element, not a
# selector to resolve later. Every check and the write run in one JS task.
PIN_SCRIPT = r'''(selector, field, frameURL, topURL, processor=false, identity=false, purpose=false, allowOff=false, shadowRootOf=null) => {
  __STYLE_GUARD__
  const matches = document.querySelectorAll(selector);
  if (matches.length !== 1) return null;
  const el = matches[0], doc = document, form = el.form, parent = el.parentElement;
  const input = el instanceof HTMLInputElement;
  const select = el instanceof HTMLSelectElement;
  const textarea = identity && field === 'street-address' && el instanceof HTMLTextAreaElement;
  // A card expiry month or year in a custom dropdown, with an explicit field
  // purpose: a type=button <button> or a role=combobox element that opens one
  // listbox, named by aria-controls or aria-owns, of role=option choices.
  function ariaList() {
    if (identity || processor || purpose !== field || !['cc-exp-month','cc-exp-year'].includes(field) ||
        input || select || !(el instanceof HTMLElement)) return null;
    const role = el.getAttribute('role'), popup = (el.getAttribute('aria-haspopup') || '').toLowerCase();
    if (el instanceof HTMLButtonElement ? el.type !== 'button' || role !== null && role !== 'combobox' :
        role !== 'combobox') return null;
    if (role === 'combobox' ? el.hasAttribute('aria-haspopup') && popup !== 'listbox' : popup !== 'listbox') return null;
    // A click must not also follow a link, submit a form or activate a label.
    if (el.parentElement?.closest('a[href],button,label,summary') ||
        el.getAttribute('aria-disabled') === 'true' || el.closest('[inert]')) return null;
    const owned = ['aria-controls','aria-owns'].filter(a => el.hasAttribute(a)).map(a => el.getAttribute(a).trim());
    if (!owned.length || owned.some(n => !/^[^\t\n\f\r ]+$/.test(n)) || new Set(owned).size !== 1) return null;
    return owned[0];
  }
  const listId = ariaList(), aria = listId !== null;
  if (!input && !select && !textarea && !aria) return null;
  if (select && el.multiple) return null;
  if (select && !(identity ? ['country', 'country-name', 'address-level1'] :
                               ['cc-exp-month', 'cc-exp-year']).includes(field)) return null;
  const type = el.type, autocomplete = el.getAttribute('autocomplete');
  const tokens = identity ?
    (autocomplete || '').replace(/[A-Z]/g, c => c.toLowerCase()).match(/[^\t\n\f\r ]+/g) || [] :
    (autocomplete || '').trim().toLowerCase().split(/\s+/);
  // Computop's hosted form has no cc-* annotations. This explicit processor
  // route accepts only its known id/name pairs, never arbitrary off fields.
  const computop = processor === 'computop';
  const stripe = processor === 'stripe';
  const ids = {'cc-name':'creditCardHolder','cc-number':'_KKnr',
               'cc-exp':'expiry_date','cc-csc':'cccvc'};
  // One `stripe` processor, two frames: the exact frame path selects the
  // Payment Element (id + name) or the classic Card Element (name, no id).
  function stripeTable() {
    let path;
    try { path = new URL(frameURL).pathname; } catch { return null; }
    const hits = Object.values(__STRIPE_ELEMENTS__).filter(e => new RegExp(e.path).test(path));
    return hits.length === 1 ? hits[0].fields : null;
  }
  const stripeFields = stripe ? stripeTable() : null;
  const id = el.id, name = el.getAttribute('name');
  function knownComputopField() {
    return input && type === 'text' && form !== null && autocomplete === 'off' &&
      Object.hasOwn(ids,field) && id === ids[field] && name === ids[field] &&
      el.id === id && el.getAttribute('name') === name &&
      document.querySelectorAll('[id="'+ids[field]+'"]').length === 1;
  }
  function knownStripeField() {
    if (!stripeFields || !Object.hasOwn(stripeFields, field)) return false;
    const [expectedId, expectedName] = stripeFields[field];
    const bound = expectedId === null ?
      !el.hasAttribute('id') && document.querySelectorAll('[name="'+expectedName+'"]').length === 1 :
      el.id === expectedId && document.querySelectorAll('[id="'+expectedId+'"]').length === 1;
    return input && type === 'text' && autocomplete === field &&
      el.getAttribute('name') === expectedName && bound;
  }
  // Identity fields follow the ordered HTML autocomplete token grammar.
  const prefix = tokens.slice(0, -1);
  // An explicit field purpose (the agent verified it on the page) also accepts
  // a field with no autocomplete token or only `on`, and `off` only with its own
  // flag. Any other hint must still name this field.
  const attested = identity && purpose === field &&
    (tokens.length === 0 || tokens.length === 1 && (tokens[0] === 'on' || tokens[0] === 'off' && allowOff === true));
  if (purpose !== false && purpose !== field) return null;
  // A card field purpose likewise accepts no hint, an empty one or only `on`
  // (and `off` only with its own flag). Never on a processor route.
  const hint = (autocomplete || '').trim().toLowerCase();
  const cardAttested = !identity && !processor && purpose === field &&
    (hint === '' || hint === 'on' || hint === 'off' && allowOff === true);
  if (identity && !attested) {
    if (prefix[0]?.startsWith('section-')) prefix.shift();
    if (['shipping','billing'].includes(prefix[0])) prefix.shift();
    if (['tel','email'].includes(field) && ['home','work','mobile','fax','pager'].includes(prefix[0])) prefix.shift();
    if (prefix.length || tokens[tokens.length - 1] !== field) return null;
  }
  if (identity) {
    if (input && !(type === 'text' || type === 'email' && field === 'email' ||
                   type === 'tel' && field === 'tel')) return null;
  } else if (computop ? !knownComputopField() : !cardAttested && (
      tokens[tokens.length - 1] !== field ||
      tokens.slice(0,-1).some(t => t !== 'billing' && !/^section-[a-z0-9_-]+$/.test(t)))) return null;
  if (stripe && !knownStripeField()) return null;
  if (!identity && input && !['text','tel','password'].includes(type)) return null;
  const proto = input ? HTMLInputElement.prototype :
    textarea ? HTMLTextAreaElement.prototype : HTMLSelectElement.prototype;
  const setter = Object.getOwnPropertyDescriptor(proto, 'value').set;
  const getter = Object.getOwnPropertyDescriptor(proto, 'value').get;
  const selectIndex = identity && select && Object.getOwnPropertyDescriptor(proto, 'selectedIndex');
  // An ancestor's clip-path inset that holds the node's whole border box is
  // accepted; from that ancestor up, nothing may scale, rotate or reparent it.
  function shown(node, owner, forbidTransform=false) {
    const rect = node.getBoundingClientRect();
    let ancestor = node, flat = false;
    for (let i = 0; ancestor; ++i, ancestor = ancestor.parentElement) {
      if (i >= 64) return false;
      const style = owner.defaultView.getComputedStyle(ancestor), clipper = ancestor;
      let inset = false;
      const clipped = value => inset = insetContains(value, clipper, rect, style);
      if (!supportedStyle(style,forbidTransform,false,clipped)) return false;
      flat = flat || inset;
      if (flat && !flatChain(ancestor, style, shadowRootOf)) return false;
    }
    return owner.visibilityState === 'visible' && !node.closest('[inert]');
  }
  function exposed(node, owner) {
    const rect = node.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0 || !shown(node, owner)) return false;
    const hit = owner.elementFromPoint(rect.left + rect.width/2, rect.top + rect.height/2);
    // A dropdown button's own text and icon are part of it.
    return hit === node || aria && node === el && ownPart(hit);
  }
  function valid() {
    if (!isSecureContext || location.href !== frameURL || (!processor && window.top.location.href !== topURL) ||
        !el.isConnected || el.ownerDocument !== doc || el.getRootNode() !== doc ||
        el.form !== form || el.parentElement !== parent ||
        el.type !== type || el.getAttribute('autocomplete') !== autocomplete ||
        (computop && !knownComputopField()) ||
        (stripe && !knownStripeField()) ||
        (aria && ariaList() !== listId) ||
        el.disabled || el.matches(':disabled') || el.readOnly || el.hidden || el.closest('[inert]') ||
        document.querySelectorAll(selector).length !== 1 || document.querySelector(selector) !== el ||
        document.visibilityState !== 'visible') return false;
    if (identity && (!doc.hasFocus() || doc.activeElement !== el || (select && el.multiple))) return false;
    if (!exposed(el, doc)) return false;
    // A processor cannot inspect its cross-origin parents. The retained
    // merchant-side guard and browser frame ancestry supply that check.
    const rect = el.getBoundingClientRect();
    let x = rect.left + rect.width/2, y = rect.top + rect.height/2;
    const point={x,y,width:innerWidth,height:innerHeight,rootX:x+scrollX,rootY:y+scrollY};
    if (processor) return point;
    let view = window;
    for (let i = 0; view !== view.top; ++i) {
      const frame = view.frameElement, owner = view.parent.document;
      if (i >= 16 || !frame || !shown(frame, owner, true) || !frame.offsetWidth || !frame.offsetHeight) return false;
      const box = frame.getBoundingClientRect();
      x = box.left + (frame.clientLeft + x) * box.width / frame.offsetWidth;
      y = box.top + (frame.clientTop + y) * box.height / frame.offsetHeight;
      if (owner.elementFromPoint(x,y) !== frame) return false;
      view = view.parent;
    }
    return {...point,rootX:x+window.top.scrollX,rootY:y+window.top.scrollY};
  }
  // Elements inside the dropdown button, never an embedded document.
  function ownPart(node) {
    return node instanceof Element && node !== el && el.contains(node) &&
      !node.closest('iframe,frame,object,embed') && node.getRootNode() === doc;
  }
  const text = node => (node.textContent || '').replace(/\s+/g, ' ').trim();
  const pause = () => new Promise(resolve => setTimeout(resolve, 25));
  // The open listbox's enabled choices, or null while it has none.
  function ariaOptions() {
    const list = doc.getElementById(listId);
    if (!list || list.getAttribute('role') !== 'listbox' || list.getRootNode() !== doc ||
        doc.querySelectorAll('#' + CSS.escape(listId)).length !== 1 || list.contains(el) || el.contains(list) ||
        list.closest('[hidden],[inert]')) return null;
    const options = Array.from(list.querySelectorAll('[role="option"]')).filter(o =>
      o.closest('[role="listbox"]') === list && o.getAttribute('aria-disabled') !== 'true' &&
      !o.closest('[hidden],[inert]') && !(o.disabled === true));
    return options.length ? options : null;
  }
  // An option's visible text and its value attributes.
  const names = o => [text(o), o.getAttribute('data-value'), o.getAttribute('value')]
    .filter(v => v !== null).map(v => v.trim()).filter(v => v !== '');
  const MONTHS = ['january','february','march','april','may','june','july','august','september','october',
                  'november','december'];
  // The visible text names the saved value. A value attribute counts only when
  // the text is that month's English name: a list that shows names may count
  // its values from 0, so a value alone could name another month.
  function matching(o, forms) {
    const shown = text(o);
    if (forms.includes(shown)) return true;
    const name = field === 'cc-exp-month' ? MONTHS[Number(forms[0]) - 1] : null;
    const label = shown.toLowerCase().replace(/\.$/, '');
    return name !== null && (label === name || label === name.slice(0, 3)) &&
      names(o).slice(1).some(v => forms.includes(v));
  }
  // Open the dropdown, choose the one option that names the saved month or
  // year, and confirm the choice. No keys are sent; the value is never typed.
  async function choose(value, maxAgeMs) {
    const forms = field === 'cc-exp-month' ?
      (/^(0[1-9]|1[0-2])$/.test(value) ? [value, String(Number(value))] : null) :
      /^[0-9]{4}$/.test(value) ? [value, value.slice(2)] : /^[0-9]{2}$/.test(value) ? ['20' + value, value] : null;
    if (!forms) return 'refused';
    const late = () => performance.now() - pinnedAt >= Math.min(30000, maxAgeMs);
    const opened = el.getAttribute('aria-expanded') !== 'true';
    // A refusal leaves the selection as it was: it only closes what it opened.
    const refuse = () => {
      try {
        if (opened && el.isConnected && el.getAttribute('aria-expanded') === 'true') el.click();
      } catch {
        // The selection did not change.
      }
      return 'refused';
    };
    if (opened) el.click();
    let options = null;
    for (let i = 0; i < 24 && options === null; ++i) {
      await pause();
      if (late() || !valid()) return refuse();
      options = ariaOptions();
    }
    if (options === null) return refuse();
    const matches = options.filter(o => matching(o, forms));
    if (matches.length !== 1) return refuse();
    // Confirm only with what named the saved value: the visible text, and a value
    // attribute only when it names it too (never a stale label equal to another value).
    const option = matches[0], chosen = [text(option), ...names(option).slice(1).filter(n => forms.includes(n))];
    if (option.closest('a[href],label,summary,input,select,textarea,button:not([type="button" i])') ||
        option.querySelector('a[href],input,select,textarea,button,iframe,frame,object,embed') ||
        late() || !valid() || ariaOptions()?.includes(option) !== true) return refuse();
    option.click();
    // The button (or its label inside it, beside an icon) shows the choice, or
    // the option stays selected.
    for (let i = 0; i < 24; ++i) {
      if (!el.isConnected) return 'uncertain';
      // The button's own value attributes never confirm: they may be stale.
      const shows = [el, ...el.querySelectorAll('*')].some(n => chosen.includes(text(n)));
      if (shows || option.isConnected && option.getAttribute('aria-selected') === 'true') return 'filled';
      await pause();
    }
    return 'uncertain';
  }
  if (!valid()) return null;
  const pinnedAt = performance.now();
  return {node() { return el; },geometry() { return valid() || null; },
  // The browser's own hit test may land on the dropdown button's text or icon.
  part(node) {
    const element = node instanceof Text ? node.parentElement : node;
    return aria && (node instanceof Text && element === el || ownPart(element));
  },
  fill(value, maxAgeMs, notifyPage) {
    if (performance.now() - pinnedAt >= Math.min(30000, maxAgeMs) || !valid()) return 'refused';
    if (aria) return choose(value, maxAgeMs);
    if ((computop || stripe) && field === 'cc-exp' && !/^[0-9]{2}\/[0-9]{2}$/.test(value)) return 'refused';
    if (identity && input && value.includes('\n')) return 'refused';
    if ((input || textarea) && el.maxLength >= 0 && value.length > el.maxLength) return 'refused';
    let actual = value, option;
    if (select) {
      const options = Array.from(el.options).filter(o => !o.disabled && !o.parentElement.disabled &&
        (o.value === value || field === 'cc-exp-month' && /^[0-9]{1,2}$/.test(o.value) && Number(o.value) === Number(value)));
      if (options.length !== 1) return 'refused';
      option = options[0];
      actual = option.value;
    }
    if (performance.now() - pinnedAt >= Math.min(30000, maxAgeMs)) return 'refused';
    if (selectIndex) {
      selectIndex.set.call(el, option.index);
    } else {
      setter.call(el, actual);
    }
    if (identity) {
      const retained = () => getter.call(el) === actual && (!selectIndex || el.options[el.selectedIndex] === option);
      if (notifyPage === true) {
        el.dispatchEvent(new Event('input', {bubbles:true}));
        if (!valid() || !retained()) return 'uncertain';
        el.dispatchEvent(new Event('change', {bubbles:true}));
        if (!valid()) return 'uncertain';
      }
      return retained() ? 'filled' : 'uncertain';
    }
    el.dispatchEvent(new Event('input', {bubbles:true}));
    el.dispatchEvent(new Event('change', {bubbles:true}));
    const accepted=getter.call(el);
    // Secured fields may format grouping spaces during their input handler.
    // Accept only an equivalent number/expiry; other edits remain uncertain.
    const equivalent=processor && ['cc-number','cc-exp'].includes(field) &&
      accepted.replace(/\s/g,'') === actual.replace(/\s/g,'');
    return accepted === actual || equivalent ? 'filled' : 'uncertain';
  }};
}'''.replace('__STYLE_GUARD__', card_processor.STYLE_GUARD).replace(
    '__STRIPE_ELEMENTS__', card_processor.STRIPE_ELEMENTS_JSON)


# Card fields that take an explicit purpose (pin-card-target --field-purpose).
CARD_PURPOSE_FIELDS = ('cc-number', 'cc-csc', 'cc-exp-month', 'cc-exp-year', 'cc-name')


def field_purpose(kind, request):
    """The pin's explicit field purpose and autocomplete-off flag, checked.

    ``field_purpose`` must name the pinned field; ``allow_autocomplete_off``
    must be ``True`` and needs ``field_purpose``. Identity pins take them; a
    card pin takes them for ``CARD_PURPOSE_FIELDS`` only, never with a processor.
    """
    purpose, allow_off = request.get('field_purpose', False), request.get('allow_autocomplete_off', False)
    card = kind == 'card' and 'processor' not in request and purpose in CARD_PURPOSE_FIELDS
    if ('field_purpose' in request or 'allow_autocomplete_off' in request) and (
            kind != 'identity' and not card
            or 'field_purpose' in request and request['field_purpose'] != request.get('field')
            or 'allow_autocomplete_off' in request and (request['allow_autocomplete_off'] is not True
                                                        or 'field_purpose' not in request)):
        raise CardTargetError()
    return purpose, allow_off


class BrowserCards:
    kind = 'card'
    delivery = DELIVERY
    fields = FILL_FIELDS
    # Verification-code pins use their own derived script (browser_code).
    pin_script = PIN_SCRIPT
    pin_extra = ()

    def _failure(self, started=False):
        return failure(started, kind=self.kind)

    def _receipt(self):
        return {f'{self.kind}_delivery': self.delivery}

    def __init__(self, profile=None, *, clock=time.monotonic, connector=CDP, slots=None):
        self.profile, self.clock, self.connector, self.slots = profile, clock, connector, slots
        self.pins = {}

    @property
    def configured(self):
        return self.profile is not None or self.slots is not None

    def capabilities(self):
        return dict(cards_supported=True, card_protocol=1, card_delivery=DELIVERY,
                    card_browser_configured=self.configured,
                    card_processor_frames_protocol=card_processor.PROTOCOL,
                    card_processors=list(card_processor.PROCESSORS),
                    # `stripe` also accepts the classic Card Element frame.
                    stripe_card_element=True,
                    # pin-card-target --field-purpose, and ARIA expiry dropdowns.
                    card_field_purpose_protocol=CARD_PURPOSE_PROTOCOL)

    def prune(self):
        for token, pin in list(self.pins.items()):
            if pin['expires'] <= self.clock():
                self._close(self.pins.pop(token))

    @staticmethod
    def _close(pin):
        try:
            pin['cdp'].close()
        except Exception:
            pass

    def close(self):
        for pin in self.pins.values():
            self._close(pin)
        self.pins.clear()

    @staticmethod
    def _frames(cdp, session, request):
        tree = cdp.call('Page.getFrameTree', session=session)['frameTree']
        if card_processor.document_url(tree['frame']) != request['top_url']:
            raise CardTargetError()
        pending = [tree]
        for _ in range(256):
            if not pending:
                break
            node = pending.pop()
            frame = node['frame']
            if frame['id'] == request['frame_id']:
                if card_processor.document_url(frame) != request['frame_url']:
                    raise CardTargetError()
                return
            pending.extend(node.get('childFrames', []))
        raise CardTargetError()

    def pin(self, request):
        request, profile, slot = browser_slots.select(request, self.profile, self.slots)
        protocol = f'{self.kind}_protocol'
        allowed = {'action', protocol, 'page_id', 'frame_id', 'top_url', 'frame_url', 'selector', 'field'}
        processor = request.get('processor')
        if self.kind == 'card' and 'processor' in request:
            allowed |= {'processor', 'processor_protocol'}
        purpose, allow_off = field_purpose(self.kind, request)
        allowed |= set(request) & {'field_purpose', 'allow_autocomplete_off'}
        self.prune()
        if (set(request) != allowed or type(request.get(protocol)) is not int or request[protocol] != 1
                or profile is None or len(self.pins) >= MAX_PINS or request.get('field') not in self.fields
                or any(not isinstance(request.get(k), str) or not 0 < len(request[k]) <= 4096
                       for k in ('page_id', 'frame_id', 'selector'))
                or (processor is None and secure_url(request['top_url']) != secure_url(request['frame_url']))):
            raise CardTargetError()
        if processor is not None:
            secure_url(request['top_url'])
            secure_url(request['frame_url'])
            if (processor not in card_processor.PROCESSORS or type(request.get('processor_protocol')) is not int
                    or request['processor_protocol'] != card_processor.PROTOCOL
                    or not card_processor.supported_request(processor, request['frame_url'], request['field'])
                    or secure_url(request['top_url']) == secure_url(request['frame_url'])):
                raise CardTargetError()
        elif 'processor' in request:
            raise CardTargetError()
        cdp = self.connector(profile)
        try:
            info = cdp.call('Target.getTargetInfo', dict(targetId=request['page_id']))['targetInfo']
            if info['type'] != 'page' or info['url'] != request['top_url']:
                raise CardTargetError()
            session = cdp.call('Target.attachToTarget', dict(targetId=request['page_id'], flatten=True))['sessionId']
            if processor is not None:
                state = card_processor.pin(cdp, session, request, PIN_SCRIPT, secure_url, CardTargetError, self.clock)
                if self.clock() >= state['created'] + TTL:
                    raise CardTargetError()
                token = secrets.token_hex(32)
                self.pins[token] = dict(cdp=cdp, **state, field=request['field'], processor=processor,
                    request=dict(request), expires=state['created'] + TTL, slot=slot)
                return dict(ok=True, target=token, expires_in=TTL, field=request['field'], **self._receipt())
            self._frames(cdp, session, request)
            context = cdp.call('Page.createIsolatedWorld', dict(frameId=request['frame_id'],
                               worldName=f'akdbx-{self.kind}-v1'), session)['executionContextId']
            arguments = [request[k] for k in ('selector', 'field', 'frame_url', 'top_url')]
            if self.kind == 'identity':
                arguments.extend((False, True, purpose, allow_off))
            elif self.kind == 'card' and purpose is not False:
                arguments.extend((False, False, purpose, allow_off))
            arguments.extend(self.pin_extra)
            expression = '(' + self.pin_script + ')(' + ','.join(map(json.dumps, arguments)) + ')'
            result = cdp.call('Runtime.evaluate', dict(expression=expression, contextId=context,
                              silent=True, timeout=1000), session)
            created = self.clock()
            obj = result.get('result', {})
            if 'exceptionDetails' in result or obj.get('subtype') == 'null' or not obj.get('objectId'):
                raise CardTargetError()
            input_node = card_hit_test.retained_node(cdp,session,obj['objectId'])
            if card_hit_test.input_point(cdp,session,obj['objectId'],input_node,request['frame_id'],context) is None:
                raise CardTargetError()
            if self.clock() >= created + TTL:
                raise CardTargetError()
            token = secrets.token_hex(32)
            self.pins[token] = dict(cdp=cdp, session=session, obj=obj['objectId'], field=request['field'],
                                    request=dict(request), created=created, expires=created + TTL,input_node=input_node,
                                    slot=slot, context=context)
            return dict(ok=True, target=token, expires_in=TTL, field=request['field'], **self._receipt())
        except BaseException:
            cdp.close()
            raise

    def consume(self, token):
        self.prune()
        pin = self.pins.pop(token, None) if isinstance(token, str) else None
        if pin is None:
            raise CardTargetError()
        return pin

    def fill(self, pin, value, field, ready, deadline=None, *, notify_page=False):
        started = False
        try:
            if field != pin['field'] or not ready() or pin['expires'] <= self.clock():
                return self._failure()
            if pin.get('processor'):
                if not card_processor.check(pin['cdp'], pin, pin['request'], secure_url, CardTargetError):
                    return self._failure()
            else:
                self._frames(pin['cdp'], pin['session'], pin['request'])
                if card_hit_test.input_point(pin['cdp'],pin['session'],pin['obj'],
                        pin['input_node'],pin['request']['frame_id'],pin.get('context')) is None:
                    return self._failure()
            if not ready() or pin['expires'] <= self.clock():
                return self._failure()
            deadline = self.clock() + 4 if deadline is None else deadline
            max_age_ms = max(0, min(30000, (deadline - pin['created']) * 1000))
            started = True  # An unanswered RPC may already have changed the field.
            # A dropdown choice (an ARIA expiry button) spans a few tasks and returns a promise.
            result = pin['cdp'].call('Runtime.callFunctionOn', dict(objectId=pin['obj'],
                functionDeclaration='function(value, maxAgeMs, notify) { return this.fill(value, maxAgeMs, notify); }',
                arguments=[dict(value=value), dict(value=max_age_ms), dict(value=notify_page)], returnByValue=True,
                awaitPromise=True, silent=True), pin['session'])
            state = result.get('result', {}).get('value') if 'exceptionDetails' not in result else None
            if state == 'refused':
                return self._failure()
            if state != 'filled':
                return self._failure(True)
            if pin.get('processor') and not card_processor.check(
                    pin['cdp'], pin, pin['request'], secure_url, CardTargetError):
                return self._failure(True)
            if not pin.get('processor') and card_hit_test.input_point(pin['cdp'],pin['session'],pin['obj'],
                    pin['input_node'],pin['request']['frame_id'],pin.get('context')) is None:
                return self._failure(True)
            return dict(ok=True, filled=field, **self._receipt())
        except Exception:
            return self._failure(started)
        finally:
            self._close(pin)
