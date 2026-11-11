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
from .runtime import open_private_runtime_directory

DELIVERY = 'cdp-card-element-v1'
TTL = 30
MAX_PINS = 16


class CardTargetError(Exception):
    pass


def failure(started=False):
    return dict(ok=False, delivery='uncertain' if started else 'not-started',
                error='card fill outcome uncertain; do not retry automatically' if started else
                'card fill not started: target unavailable, changed or unsupported; pin again')


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
    _, directory = open_private_runtime_directory(Path(profile))
    try:
        fd = os.open('DevToolsActivePort', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, 'r', encoding='ascii') as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o022 or info.st_size > 256 or info.st_nlink != 1):
                raise CardTargetError()
            parts = source.read(257).splitlines()
        if (len(parts) != 2 or not re.fullmatch(r'[0-9]{1,5}', parts[0])
                or not 1 <= int(parts[0]) <= 65535
                or not re.fullmatch(r'/devtools/browser/[a-zA-Z0-9-]{1,80}', parts[1])):
            raise CardTargetError()
        return 'ws://127.0.0.1:' + parts[0] + parts[1]
    finally:
        os.close(directory)


def verify_peer(connection):
    """Prove our UID owns the server side of this connected Linux TCP socket.

    A pre-connect listener check races port reuse. Match the reciprocal
    ESTABLISHED tuple instead, before sending any WebSocket bytes, and keep
    this exact connection. Missing, ambiguous or oversized kernel data refuses.
    """
    local, remote = connection.getsockname(), connection.getpeername()
    if (connection.family != socket.AF_INET or local[0] != '127.0.0.1'
            or remote[0] != '127.0.0.1'):
        raise CardTargetError()
    def address(value):
        return f'{int.from_bytes(socket.inet_aton(value[0]), sys.byteorder):08X}:{value[1]:04X}'.encode('ascii')
    server, client = address(remote), address(local)
    owners = []
    with open('/proc/self/net/tcp', 'rb') as table:
        for _ in range(16384):
            line = table.readline(1025)
            if not line:
                break
            if len(line) > 1024:
                raise CardTargetError()
            fields = line.split()
            if len(fields) >= 4 and fields[1:4] == [server, client, b'01']:
                if len(fields) < 8:
                    raise CardTargetError()
                owners.append(int(fields[7]))
        else:
            raise CardTargetError()
    if owners != [os.getuid()]:
        raise CardTargetError()


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
PIN_SCRIPT = r'''(selector, field, frameURL, topURL, processor=false) => {
  __STYLE_GUARD__
  const matches = document.querySelectorAll(selector);
  if (matches.length !== 1) return null;
  const el = matches[0], doc = document, form = el.form, parent = el.parentElement;
  const input = el instanceof HTMLInputElement;
  const select = el instanceof HTMLSelectElement;
  if (!input && !select) return null;
  if (select && el.multiple) return null;
  if (select && !['cc-exp-month', 'cc-exp-year'].includes(field)) return null;
  const type = el.type, autocomplete = el.getAttribute('autocomplete');
  const tokens = (autocomplete || '').trim().toLowerCase().split(/\s+/);
  if (tokens[tokens.length - 1] !== field ||
      tokens.slice(0,-1).some(t => t !== 'billing' && !/^section-[a-z0-9_-]+$/.test(t))) return null;
  if (input && !['text','tel','password'].includes(type)) return null;
  const proto = input ? HTMLInputElement.prototype : HTMLSelectElement.prototype;
  const setter = Object.getOwnPropertyDescriptor(proto, 'value').set;
  const getter = Object.getOwnPropertyDescriptor(proto, 'value').get;
  function shown(node, owner, forbidTransform=false) {
    let ancestor = node;
    for (let i = 0; ancestor; ++i, ancestor = ancestor.parentElement) {
      if (i >= 64) return false;
      const style = owner.defaultView.getComputedStyle(ancestor);
      if (!supportedStyle(style,forbidTransform)) return false;
    }
    return owner.visibilityState === 'visible' && !node.closest('[inert]');
  }
  function exposed(node, owner) {
    const rect = node.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0 || !shown(node, owner)) return false;
    return owner.elementFromPoint(rect.left + rect.width/2, rect.top + rect.height/2) === node;
  }
  function valid() {
    if (!isSecureContext || location.href !== frameURL || (!processor && window.top.location.href !== topURL) ||
        !el.isConnected || el.ownerDocument !== doc || el.getRootNode() !== doc ||
        el.form !== form || el.parentElement !== parent ||
        el.type !== type || el.getAttribute('autocomplete') !== autocomplete ||
        el.disabled || el.matches(':disabled') || el.readOnly || el.hidden || el.closest('[inert]') ||
        document.querySelectorAll(selector).length !== 1 || document.querySelector(selector) !== el ||
        document.visibilityState !== 'visible') return false;
    if (!exposed(el, doc)) return false;
    // A processor cannot inspect its cross-origin parents. The retained
    // merchant-side guard and browser frame ancestry supply that check.
    if (processor) return true;
    const rect = el.getBoundingClientRect();
    let x = rect.left + rect.width/2, y = rect.top + rect.height/2;
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
    return true;
  }
  if (!valid()) return null;
  const pinnedAt = performance.now();
  return {geometry() {
    if (!valid()) return null;
    const r=el.getBoundingClientRect();
    return {x:r.left+r.width/2,y:r.top+r.height/2,width:innerWidth,height:innerHeight};
  },fill(value, maxAgeMs) {
    if (performance.now() - pinnedAt >= Math.min(30000, maxAgeMs) || !valid()) return 'refused';
    if (input && el.maxLength >= 0 && value.length > el.maxLength) return 'refused';
    let actual = value;
    if (select) {
      const options = Array.from(el.options).filter(o => !o.disabled && !o.parentElement.disabled &&
        (o.value === value || field === 'cc-exp-month' && /^[0-9]{1,2}$/.test(o.value) && Number(o.value) === Number(value)));
      if (options.length !== 1) return 'refused';
      actual = options[0].value;
    }
    if (performance.now() - pinnedAt >= Math.min(30000, maxAgeMs)) return 'refused';
    setter.call(el, actual);
    el.dispatchEvent(new Event('input', {bubbles:true}));
    el.dispatchEvent(new Event('change', {bubbles:true}));
    const accepted=getter.call(el);
    // Secured fields may format grouping spaces during their input handler.
    // Accept only an equivalent number/expiry; other edits remain uncertain.
    const equivalent=processor && ['cc-number','cc-exp'].includes(field) &&
      accepted.replace(/\s/g,'') === actual.replace(/\s/g,'');
    return accepted === actual || equivalent ? 'filled' : 'uncertain';
  }};
}'''.replace('__STYLE_GUARD__', card_processor.STYLE_GUARD)


class BrowserCards:
    def __init__(self, profile=None, *, clock=time.monotonic, connector=CDP):
        self.profile, self.clock, self.connector = profile, clock, connector
        self.pins = {}

    def capabilities(self):
        return dict(cards_supported=True, card_protocol=1, card_delivery=DELIVERY,
                    card_browser_configured=self.profile is not None,
                    card_processor_frames_protocol=card_processor.PROTOCOL,
                    card_processors=list(card_processor.PROCESSORS))

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
        allowed = {'action', 'card_protocol', 'page_id', 'frame_id', 'top_url', 'frame_url', 'selector', 'field'}
        processor = request.get('processor')
        if 'processor' in request:
            allowed |= {'processor', 'processor_protocol'}
        self.prune()
        if (set(request) != allowed or type(request.get('card_protocol')) is not int or request['card_protocol'] != 1
                or self.profile is None or len(self.pins) >= MAX_PINS or request.get('field') not in FILL_FIELDS
                or any(not isinstance(request.get(k), str) or not 0 < len(request[k]) <= 4096
                       for k in ('page_id', 'frame_id', 'selector'))
                or (processor is None and secure_url(request['top_url']) != secure_url(request['frame_url']))):
            raise CardTargetError()
        if processor is not None:
            secure_url(request['top_url'])
            secure_url(request['frame_url'])
            if (processor != 'adyen' or type(request.get('processor_protocol')) is not int
                    or request['processor_protocol'] != card_processor.PROTOCOL
                    or not card_processor.adyen_url(request['frame_url'])
                    or secure_url(request['top_url']) == secure_url(request['frame_url'])):
                raise CardTargetError()
        elif 'processor' in request:
            raise CardTargetError()
        cdp = self.connector(self.profile)
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
                    request=dict(request), expires=state['created'] + TTL)
                return dict(ok=True, target=token, expires_in=TTL, field=request['field'], card_delivery=DELIVERY)
            self._frames(cdp, session, request)
            context = cdp.call('Page.createIsolatedWorld', dict(frameId=request['frame_id'],
                               worldName='akdbx-card-v1'), session)['executionContextId']
            expression = '(' + PIN_SCRIPT + ')(' + ','.join(json.dumps(request[k]) for k in
                         ('selector', 'field', 'frame_url', 'top_url')) + ')'
            result = cdp.call('Runtime.evaluate', dict(expression=expression, contextId=context,
                              silent=True, timeout=1000), session)
            created = self.clock()
            obj = result.get('result', {})
            if 'exceptionDetails' in result or obj.get('subtype') == 'null' or not obj.get('objectId'):
                raise CardTargetError()
            token = secrets.token_hex(32)
            self.pins[token] = dict(cdp=cdp, session=session, obj=obj['objectId'], field=request['field'],
                                    request=dict(request), created=created, expires=created + TTL)
            return dict(ok=True, target=token, expires_in=TTL, field=request['field'], card_delivery=DELIVERY)
        except BaseException:
            cdp.close()
            raise

    def consume(self, token):
        self.prune()
        pin = self.pins.pop(token, None) if isinstance(token, str) else None
        if pin is None:
            raise CardTargetError()
        return pin

    def fill(self, pin, value, field, ready, deadline=None):
        started = False
        try:
            if field != pin['field'] or not ready() or pin['expires'] <= self.clock():
                return failure()
            if pin.get('processor'):
                if not card_processor.check(pin['cdp'], pin, pin['request'], secure_url, CardTargetError):
                    return failure()
            else:
                self._frames(pin['cdp'], pin['session'], pin['request'])
            if not ready() or pin['expires'] <= self.clock():
                return failure()
            deadline = self.clock() + 4 if deadline is None else deadline
            max_age_ms = max(0, min(30000, (deadline - pin['created']) * 1000))
            started = True  # An unanswered RPC may already have changed the field.
            result = pin['cdp'].call('Runtime.callFunctionOn', dict(objectId=pin['obj'],
                functionDeclaration='function(value, maxAgeMs) { return this.fill(value, maxAgeMs); }',
                arguments=[dict(value=value), dict(value=max_age_ms)], returnByValue=True, silent=True), pin['session'])
            state = result.get('result', {}).get('value') if 'exceptionDetails' not in result else None
            if state == 'refused':
                return failure()
            if state != 'filled':
                return failure(True)
            if pin.get('processor') and not card_processor.check(
                    pin['cdp'], pin, pin['request'], secure_url, CardTargetError):
                return failure(True)
            return dict(ok=True, filled=field, card_delivery=DELIVERY)
        except Exception:
            return failure(started)
        finally:
            self._close(pin)
