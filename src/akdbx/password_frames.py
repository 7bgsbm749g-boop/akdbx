"""Child-frame routes for DOM password delivery; read-only frame discovery.

A child-frame pin names the page target, the exact top-level URL, the CDP
frame id and the frame's exact HTTPS origin. The broker resolves the frame
chain itself from the browser (in-process frames from the page's frame tree,
out-of-process iframes from their own targets), and accepts it only when:

* the top document has the exact caller-verified URL;
* every document in the chain, top to field frame, is an HTTPS secure context
  with a non-opaque origin, and all share one registrable domain as computed by
  Chrome (`domainAndRegistry`, which uses the public suffix list). Hosts
  without a registrable domain, such as IP literals, must share one exact
  origin;
* the field frame's security origin is exactly the caller's `frame_origin`;
  the saved credential's origin must later equal this same frame origin;
* each frame owner is a connected, visible `<iframe>` in its parent document
  (not in a shadow root, no `srcdoc`, and a `sandbox` attribute only when it
  keeps both `allow-scripts` and `allow-same-origin`).

The exact frame URLs, ids, parents and hosting targets form a proof that fill
compares again. Navigation of any frame destroys its isolated world and the
retained owner guards; either refuses delivery. The listing returns origins and
counts only, never frame URLs, field values or page-controlled names.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from .target import TargetError
from .totp import https_origin

PROTOCOL = 1
POLICY = 'same-site-chain-v1'
MAX_DEPTH = 8
MAX_FRAMES = 256
MAX_OOPIFS = 32
MAX_LISTED = 64


def document_url(frame):
    """Reconstruct CDP's exact frame URL, without stripping or decoding anything."""
    url, fragment = frame.get('url'), frame.get('urlFragment', '')
    # Page.Frame.url excludes the fragment; urlFragment includes its leading #.
    if not isinstance(url, str) or not isinstance(fragment, str) or '#' in url or fragment and not fragment.startswith('#'):
        raise TargetError()
    return url + fragment


def canonical_origin(value):
    """Return the browser serialization of an exact HTTPS origin or refuse."""
    if not isinstance(value, str) or not 0 < len(value) <= 512:
        raise TargetError()
    parsed = urlsplit(value)
    try:
        scheme, host, port = https_origin(value)
    except Exception:
        raise TargetError() from None
    if (scheme != 'https' or parsed.path or parsed.query or parsed.fragment or value.endswith(('?', '#'))
            or parsed.username is not None or parsed.password is not None):
        raise TargetError()
    serialized = 'https://' + (f'[{host}]' if ':' in host else host) + ('' if port == 443 else f':{port}')
    if value != serialized:
        raise TargetError()
    return serialized


def _origin_of(frame):
    """The frame's own non-opaque HTTPS security origin, matching its URL."""
    url = document_url(frame)
    origin = frame.get('securityOrigin')
    try:
        scheme, host, port = https_origin(url)
    except Exception:
        raise TargetError() from None
    if not isinstance(origin, str) or canonical_origin(origin) != origin or https_origin(origin) != (scheme, host, port):
        raise TargetError()
    if frame.get('secureContextType') not in (None, 'Secure'):
        raise TargetError()
    return url, origin


def _site(frame):
    site = frame.get('domainAndRegistry', '')
    if not isinstance(site, str) or len(site) > 255:
        raise TargetError()
    return site


def _add_tree(frames, tree, session, target):
    pending = [tree]
    while pending:
        node = pending.pop()
        frame = node.get('frame')
        if not isinstance(frame, dict) or not isinstance(frame.get('id'), str) or len(frames) >= MAX_FRAMES:
            raise TargetError()
        if frame['id'] in frames:
            raise TargetError()  # One id must identify one document.
        frames[frame['id']] = dict(frame=frame, session=session, target=target)
        pending.extend(node.get('childFrames', []))


def forest(cdp, top_session, page_id, *, attach=True):
    """Map every reachable frame of one tab, including bounded OOPIF targets.

    Returns (frames, sessions). Only iframe targets whose ancestry leads to this
    page are attached. The caller detaches sessions it does not retain.
    """
    frames, sessions = {}, {page_id: top_session}
    _add_tree(frames, cdp.call('Page.getFrameTree', session=top_session)['frameTree'], top_session, page_id)
    if not attach:
        return frames, sessions
    infos = [t for t in cdp.call('Target.getTargets')['targetInfos'] if t.get('type') == 'iframe']
    progress = True
    while progress:
        progress = False
        for info in infos:
            target = info.get('targetId')
            if (target in sessions or info.get('parentId') not in sessions
                    or info.get('parentFrameId') not in frames):
                continue
            if len(sessions) > MAX_OOPIFS:
                return frames, sessions
            try:
                session = cdp.call('Target.attachToTarget', {'targetId': target, 'flatten': True})['sessionId']
            except Exception:
                continue  # A vanished unrelated iframe; its frames stay unknown.
            sessions[target] = session
            tree = cdp.call('Page.getFrameTree', session=session)['frameTree']
            root = tree.get('frame', {})
            if root.get('id') != target or root.get('parentId') != info['parentFrameId']:
                raise TargetError()
            _add_tree(frames, tree, session, target)
            progress = True
    return frames, sessions


def chain(frames, frame_id):
    """Top-to-frame list of frame records, or refuse an unknown/detached frame."""
    found = frames.get(frame_id)
    if found is None:
        raise TargetError()
    path = [found]
    while path[-1]['frame'].get('parentId'):
        if len(path) > MAX_DEPTH:
            raise TargetError()
        parent = frames.get(path[-1]['frame']['parentId'])
        if parent is None:
            raise TargetError()
        path.append(parent)
    return path[::-1]


def check_chain(path, top_url, frame_origin):
    """Apply the same-site child-frame policy; return the comparable proof."""
    if len(path) < 2 or len(path) > MAX_DEPTH + 1 or document_url(path[0]['frame']) != top_url:
        raise TargetError()
    origins, sites = [], set()
    for hop in path:
        _, origin = _origin_of(hop['frame'])
        origins.append(origin)
        sites.add(_site(hop['frame']))
    if len(sites) != 1:
        raise TargetError()  # Hostile top embedding a legitimate frame, or the reverse.
    if sites == {''} and len(set(origins)) != 1:
        raise TargetError()  # No registrable domain: require one exact origin.
    if origins[-1] != frame_origin:
        raise TargetError()
    return tuple((hop['frame']['id'], document_url(hop['frame']), hop['frame'].get('parentId'), hop['target'])
                 for hop in path)


# Runs on the actual iframe element in its parent's isolated world. Retain the
# owner, parent, document and attributes. No credential crosses this context.
# With `track`, any parent navigation, owner attribute change or owner removal
# after capture taints the guard permanently, even if the state is restored.
OWNER_GUARD = r'''function(track) {
  const frame = this, doc = document, parent = frame.parentElement, url = location.href;
  const attribute = Element.prototype.getAttribute, has = Element.prototype.hasAttribute;
  if (!(frame instanceof HTMLIFrameElement) || !frame.isConnected || frame.ownerDocument !== doc || frame.getRootNode() !== doc) return null;
  if (has.call(frame, 'srcdoc')) return null;
  const names = ['src', 'srcdoc', 'sandbox', 'allow', 'name', 'credentialless'];
  const values = names.map(n => attribute.call(frame, n));
  if (has.call(frame, 'sandbox')) {
    const tokens = (values[2] || '').split(/[\t\n\f\r ]+/).filter(Boolean).map(t => t.replace(/[A-Z]/g, c => c.toLowerCase()));
    if (!tokens.includes('allow-scripts') || !tokens.includes('allow-same-origin')) return null;
  }
  const child = frame.contentWindow;
  let tainted = false, dispose = () => {};
  const check = () => {
    if (tainted || location.href !== url || !frame.isConnected || frame.ownerDocument !== doc || frame.getRootNode() !== doc || frame.parentElement !== parent ||
        !child || frame.contentWindow !== child || names.some((n, i) => attribute.call(frame, n) !== values[i]) ||
        doc.visibilityState !== 'visible' || frame.closest('[inert]')) return false;
    const r = frame.getBoundingClientRect(), s = getComputedStyle(frame);
    return frame.checkVisibility({checkOpacity: true, checkVisibilityCSS: true}) && r.width > 0 && r.height > 0 &&
      r.bottom > 0 && r.right > 0 && r.top < innerHeight && r.left < innerWidth && s.visibility === 'visible' && s.display !== 'none';
  };
  if (!check()) return null;
  if (track) {
    if (!window.navigation) return null;
    const dirty = () => { tainted = true; };
    window.navigation.addEventListener('navigate', dirty);
    doc.addEventListener('visibilitychange', dirty, true);
    const observer = new MutationObserver(records => {
      for (const r of records) {
        if (r.type === 'attributes' && r.target === frame) dirty();
        if (r.type === 'childList' && [...r.removedNodes].some(n => n === frame || n.contains(frame))) dirty();
      }
    });
    observer.observe(frame, {attributes: true, attributeFilter: names});
    observer.observe(doc, {childList: true, subtree: true});
    dispose = () => {
      window.navigation.removeEventListener('navigate', dirty);
      doc.removeEventListener('visibilitychange', dirty, true);
      observer.disconnect();
    };
  }
  return {check, dispose: () => dispose()};
}'''
GUARD_CHECK = 'function() { return this.check(); }'
GUARD_DISPOSE = 'function() { this.dispose(); }'


def owner_guards(cdp, path, track=True):
    """Retain one owner guard per child hop, in its parent document."""
    guards = []
    for parent, child in zip(path, path[1:]):
        session = parent['session']
        owner = cdp.call('DOM.getFrameOwner', {'frameId': child['frame']['id']}, session)['backendNodeId']
        context = cdp.call('Page.createIsolatedWorld', {'frameId': parent['frame']['id'],
                           'worldName': 'akdbx-password-owner-v1'}, session)['executionContextId']
        node = cdp.call('DOM.resolveNode', {'backendNodeId': owner, 'executionContextId': context}, session)['object']['objectId']
        result = cdp.call('Runtime.callFunctionOn', {'objectId': node, 'functionDeclaration': OWNER_GUARD,
                          'arguments': [{'value': track}], 'silent': True}, session)
        obj = result.get('result', {})
        if 'exceptionDetails' in result or obj.get('type') != 'object' or obj.get('subtype') == 'null' or not obj.get('objectId'):
            raise TargetError()
        guards.append((session, obj['objectId']))
    return guards


def release_guards(cdp, guards):
    for session, obj in guards:
        try:
            cdp.call('Runtime.callFunctionOn', {'objectId': obj, 'functionDeclaration': GUARD_DISPOSE, 'silent': True},
                     session, timeout=0.2)
        except Exception:
            pass


def guards_hold(cdp, guards):
    for session, obj in guards:
        result = cdp.call('Runtime.callFunctionOn', {'objectId': obj, 'functionDeclaration': GUARD_CHECK,
                          'returnByValue': True, 'silent': True}, session)
        if 'exceptionDetails' in result or result.get('result', {}).get('value') is not True:
            return False
    return True


def resolve(cdp, top_session, page_id, top_url, frame_id, frame_origin):
    """Resolve and verify a child frame route; retain only the chain's sessions."""
    frames, sessions = forest(cdp, top_session, page_id)
    path = chain(frames, frame_id)
    proof = check_chain(path, top_url, frame_origin)
    used = {hop['target'] for hop in path}
    for target, session in sessions.items():
        if target not in used:
            try:
                cdp.call('Target.detachFromTarget', {'sessionId': session})
            except Exception:
                pass
    return dict(proof=proof, path=path, sessions={t: sessions[t] for t in used}, field_session=path[-1]['session'],
                top_session=top_session)


def verify(cdp, route, top_url, frame_origin, guards):
    """Recompute the chain from the retained sessions and compare its proof."""
    frames = {}
    for target, session in route['sessions'].items():
        if target != route['proof'][0][3]:
            info = cdp.call('Target.getTargetInfo', {'targetId': target})['targetInfo']
            if info.get('type') != 'iframe':
                return False
        _add_tree(frames, cdp.call('Page.getFrameTree', session=session)['frameTree'], session, target)
    path = chain(frames, route['proof'][-1][0])
    if check_chain(path, top_url, frame_origin) != route['proof']:
        return False
    return guards_hold(cdp, guards)


# Read-only, value-free field counts for eligible frames in an isolated world.
COUNT = r'''(function() {
  const shown = e => e.checkVisibility({checkOpacity: true, checkVisibilityCSS: true}) && !e.disabled && !e.closest('[inert]');
  const inputs = Array.from(document.querySelectorAll('input')).slice(0, 512);
  const type = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'type').get;
  return {password: inputs.filter(e => type.call(e) === 'password' && shown(e)).length,
          text: inputs.filter(e => ['text', 'email'].includes(type.call(e)) && shown(e)).length};
})()'''


def listing(cdp, top_session, page_id, top_url):
    """List one tab's frames with origins, eligibility and visible field counts."""
    frames, sessions = forest(cdp, top_session, page_id)
    top = next((f for f in frames.values() if not f['frame'].get('parentId')), None)
    if top is None or top['target'] != page_id or document_url(top['frame']) != top_url:
        raise TargetError()
    entries = []
    for frame_id, record in list(frames.items())[:MAX_LISTED]:
        frame = record['frame']
        try:
            path = chain(frames, frame_id)
        except TargetError:
            continue
        origin = frame.get('securityOrigin')
        try:
            _origin_of(frame)
        except TargetError:
            origin = None
        eligible = True
        if len(path) == 1:
            eligible = origin is not None
        else:
            try:
                check_chain(path, top_url, origin)
                owner_guards(cdp, path, track=False)  # Same owner rules as a pin.
            except Exception:
                eligible = False
        fields = None
        if eligible:
            try:
                world = cdp.call('Page.createIsolatedWorld', {'frameId': frame_id, 'worldName': 'akdbx-password-list-v1'},
                                 record['session'])['executionContextId']
                counted = cdp.call('Runtime.evaluate', {'expression': COUNT, 'contextId': world, 'returnByValue': True,
                                   'silent': True, 'timeout': 500}, record['session'])
                value = counted.get('result', {}).get('value')
                if 'exceptionDetails' not in counted and isinstance(value, dict) and all(
                        type(value.get(k)) is int and 0 <= value[k] <= 512 for k in ('password', 'text')):
                    fields = dict(password=value['password'], text=value['text'])
            except Exception:
                fields = None
        entries.append(dict(frame_id=frame_id, parent_frame_id=frame.get('parentId'), depth=len(path) - 1,
                            origin=origin if origin is not None else 'opaque-or-insecure',
                            out_of_process=record['target'] != page_id, eligible=eligible,
                            visible_fields=fields))
    return dict(ok=True, page_id=page_id, main_frame_id=top['frame']['id'], frame_policy=POLICY,
                frames=entries, truncated=len(frames) > MAX_LISTED)
