"""Explicit Adyen OOPIF pins; no card values, keyboard or clipboard here."""
import json
import re
from urllib.parse import urlsplit


PROTOCOL = 1
PROCESSORS = ('adyen',)


def document_url(frame):
    """CDP Frame splits hash routes from the URL; TargetInfo does not."""
    url = frame['url']
    fragment = frame.get('urlFragment', '')
    if not isinstance(url, str) or not isinstance(fragment, str):
        raise ValueError('invalid browser frame URL')
    if not fragment:
        return url
    if not fragment.startswith('#'):
        raise ValueError('invalid browser frame fragment')
    if '#' in url:
        if url[url.index('#'):] != fragment:
            raise ValueError('conflicting browser frame fragment')
        return url
    return url + fragment


def adyen_url(url):
    """Only the production secured-field endpoint, never an arbitrary frame."""
    parsed = urlsplit(url)
    return (parsed.scheme == 'https' and parsed.hostname == 'checkoutshopper-live.adyen.com'
            and parsed.port in (None, 443) and parsed.username is None and parsed.password is None
            and not parsed.fragment and bool(re.fullmatch(
                r'/checkoutshopper/securedfields/[A-Za-z0-9_-]+/[0-9]+(?:\.[0-9]+){1,3}/securedFields\.html',
                parsed.path)))


# Executed on the actual iframe element in its merchant parent's isolated world.
# Retain the owner element, parent, document and same-origin ancestor chain.
# Only coordinates and booleans cross contexts; no card value enters this guard.
GUARD = r'''function(frameURL, topURL) {
  const frame = this, doc = document, parent = frame.parentElement;
  if (!(frame instanceof HTMLIFrameElement) || frame.getRootNode() !== doc) return null;
  const childWindow = frame.contentWindow;
  const attributes = ['src','srcdoc','sandbox','name'].map(k => frame.getAttribute(k));
  const ancestors = [];
  let view = window;
  for (let i=0;; ++i) {
    if (i >= 16 || view.location.origin !== window.top.location.origin) return null;
    const owner=view.frameElement;
    ancestors.push({view, doc:view.document, url:view.location.href,
      root:view.document.documentElement, owner, ownerParent:owner?.parentElement,
      attributes:owner ? ['src','srcdoc','sandbox','name'].map(k=>owner.getAttribute(k)) : null});
    if (view === view.top) break;
    view = view.parent;
  }
  function shown(node, owner) {
    for (let e=node, i=0; e; e=e.parentElement, ++i) {
      if (i >= 64) return false;
      const s=owner.defaultView.getComputedStyle(e);
      if (s.display === 'none' || s.visibility !== 'visible' || Number(s.opacity) === 0 ||
          s.transform !== 'none' || e.hasAttribute('inert')) return false;
    }
    return owner.visibilityState === 'visible';
  }
  return {check(point) {
    if (!point || window.top.location.href !== topURL || !frame.isConnected ||
        frame.ownerDocument !== doc || frame.getRootNode() !== doc ||
        frame.parentElement !== parent || frame.contentWindow !== childWindow ||
        frame.src !== frameURL || frame.hasAttribute('srcdoc') ||
        attributes.some((v,i) => frame.getAttribute(['src','srcdoc','sandbox','name'][i]) !== v) ||
        frame.clientWidth !== point.width || frame.clientHeight !== point.height ||
        !Number.isFinite(point.x) || !Number.isFinite(point.y) ||
        point.x < 0 || point.y < 0 || point.x >= point.width || point.y >= point.height) return false;
    for (const a of ancestors) {
      if (a.view.document !== a.doc || a.doc.documentElement !== a.root ||
          a.view.location.href !== a.url || a.view.frameElement !== a.owner) return false;
      if (a.owner && (a.owner.parentElement !== a.ownerParent ||
          a.attributes.some((v,i)=>a.owner.getAttribute(['src','srcdoc','sandbox','name'][i]) !== v))) return false;
    }
    let ownerFrame=frame, x=point.x, y=point.y;
    for (const a of ancestors) {
      if (!ownerFrame || !shown(ownerFrame,a.doc) || !ownerFrame.offsetWidth || !ownerFrame.offsetHeight) return false;
      const box=ownerFrame.getBoundingClientRect();
      x=box.left+(ownerFrame.clientLeft+x)*box.width/ownerFrame.offsetWidth;
      y=box.top+(ownerFrame.clientTop+y)*box.height/ownerFrame.offsetHeight;
      if (a.doc.elementFromPoint(x,y) !== ownerFrame) return false;
      if (a.view === a.view.top) return true;
      ownerFrame=a.owner;
    }
    return false;
  }};
}'''


def _object(result, error):
    obj = result.get('result', {})
    if 'exceptionDetails' in result or obj.get('subtype') == 'null' or not obj.get('objectId'):
        raise error()
    return obj['objectId']


def route(cdp, top_session, request, secure_url, error):
    """Prove the OOPIF belongs to this tab through same-origin merchant parents."""
    info = cdp.call('Target.getTargetInfo', {'targetId':request['frame_id']})['targetInfo']
    if (info.get('type') != 'iframe' or info.get('url') != request['frame_url']
            or info.get('parentId') != request['page_id'] or not info.get('parentFrameId')):
        raise error()
    tree = cdp.call('Page.getFrameTree', session=top_session)['frameTree']
    if document_url(tree['frame']) != request['top_url']:
        raise error()
    pending = [(tree, ())]
    for _ in range(256):
        if not pending:
            break
        node, parents = pending.pop()
        frame = node['frame']
        chain = parents + (frame,)
        if frame['id'] == info['parentFrameId']:
            if len(chain) > 16 or any(secure_url(document_url(f)) != secure_url(request['top_url']) for f in chain):
                raise error()
            return {'parent_id':frame['id'], 'chain':[(f['id'],document_url(f)) for f in chain]}
        pending.extend((child,chain) for child in node.get('childFrames', []))
    raise error()


def pin(cdp, top_session, request, pin_script, secure_url, error):
    proof = route(cdp, top_session, request, secure_url, error)
    session = cdp.call('Target.attachToTarget', {'targetId':request['frame_id'],'flatten':True})['sessionId']
    frame = cdp.call('Page.getFrameTree', session=session)['frameTree']['frame']
    if (frame['id'] != request['frame_id'] or document_url(frame) != request['frame_url']
            or frame.get('parentId') != proof['parent_id']):
        raise error()
    parent_context = cdp.call('Page.createIsolatedWorld',
        {'frameId':proof['parent_id'],'worldName':'akdbx-card-parent-v1'},top_session)['executionContextId']
    owner = cdp.call('DOM.getFrameOwner',{'frameId':request['frame_id']},top_session)['backendNodeId']
    owner_obj = cdp.call('DOM.resolveNode',{'backendNodeId':owner,'executionContextId':parent_context},top_session)['object']['objectId']
    guard = _object(cdp.call('Runtime.callFunctionOn', {'objectId':owner_obj,
        'functionDeclaration':GUARD, 'arguments':[{'value':request['frame_url']},{'value':request['top_url']}],
        'silent':True},top_session),error)
    context = cdp.call('Page.createIsolatedWorld',
        {'frameId':request['frame_id'],'worldName':'akdbx-card-processor-v1'},session)['executionContextId']
    expression='('+pin_script+')('+','.join(json.dumps(request[k]) for k in
        ('selector','field','frame_url','top_url'))+',true)'
    obj = _object(cdp.call('Runtime.evaluate',{'expression':expression,'contextId':context,
        'silent':True,'timeout':1000},session),error)
    state={'session':session,'obj':obj,'top_session':top_session,'guard':guard,'proof':proof}
    if not check(cdp,state,request,secure_url,error):
        raise error()
    return state


def check(cdp, state, request, secure_url, error):
    if route(cdp,state['top_session'],request,secure_url,error) != state['proof']:
        raise error()
    frame=cdp.call('Page.getFrameTree',session=state['session'])['frameTree']['frame']
    if (frame['id'] != request['frame_id'] or document_url(frame) != request['frame_url']
            or frame.get('parentId') != state['proof']['parent_id']):
        raise error()
    geometry=cdp.call('Runtime.callFunctionOn',{'objectId':state['obj'],
        'functionDeclaration':'function() { return this.geometry(); }','returnByValue':True,'silent':True},state['session'])
    if 'exceptionDetails' in geometry or not geometry.get('result',{}).get('value'):
        return False
    checked=cdp.call('Runtime.callFunctionOn',{'objectId':state['guard'],
        'functionDeclaration':'function(point) { return this.check(point); }',
        'arguments':[{'value':geometry['result']['value']}],'returnByValue':True,'silent':True},state['top_session'])
    return 'exceptionDetails' not in checked and checked.get('result',{}).get('value') is True
