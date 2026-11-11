"""Explicit Adyen OOPIF pins; no card values, keyboard or clipboard here."""
import json
import re
from urllib.parse import urlsplit

from . import card_hit_test


PROTOCOL = 1
PROCESSORS = ('adyen',)


# Shared by the merchant iframe guard and the input's isolated-world checks.
# Rectangles and elementFromPoint cannot prove visual exposure through masks or
# filters or blending. Mapping child coordinates also excludes individual/3D transforms.
STYLE_GUARD = r'''function supportedStyle(style, mapping=false) {
  if (style.display === 'none' || style.visibility !== 'visible' || Number(style.opacity) === 0 ||
      style.getPropertyValue('content-visibility') === 'hidden') return false;
  const blend = style.getPropertyValue('mix-blend-mode').trim();
  if (blend !== '' && blend !== 'normal') return false;
  const visual=['filter','backdrop-filter','clip','clip-path','mask-image','-webkit-mask-image',
                '-webkit-mask-box-image-source','mask-border-source'];
  const geometry=mapping ? ['transform','rotate','translate','scale','perspective','offset-path'] : [];
  return [...visual,...geometry].every(k => {
    const value=style.getPropertyValue(k).trim();
    return value === '' || value === 'none' || k === 'clip' && value === 'auto';
  });
}'''


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
  __STYLE_GUARD__
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
      if (!supportedStyle(s,true) || e.hasAttribute('inert')) return false;
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
      if (a.view === a.view.top) return {x,y,rootX:x+a.view.scrollX,rootY:y+a.view.scrollY};
      ownerFrame=a.owner;
    }
    return false;
  }};
}'''.replace('__STYLE_GUARD__', STYLE_GUARD)


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


def pin(cdp, top_session, request, pin_script, secure_url, error, clock):
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
    result = cdp.call('Runtime.evaluate',{'expression':expression,'contextId':context,
        'silent':True,'timeout':1000},session)
    # The browser's pin clock starts just before the reply. This upper bound
    # maps its age conservatively and excludes later merchant verification.
    created = clock()
    obj = _object(result,error)
    input_node = card_hit_test.retained_node(cdp,session,obj)
    state={'session':session,'obj':obj,'top_session':top_session,'guard':guard,
           'proof':proof,'created':created,'input_node':input_node,'owner_node':owner}
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
    geometry=card_hit_test.input_point(cdp,state['session'],state['obj'],
        state['input_node'],request['frame_id'])
    if geometry is None:
        return False
    checked=cdp.call('Runtime.callFunctionOn',{'objectId':state['guard'],
        'functionDeclaration':'function(point) { return this.check(point); }',
        'arguments':[{'value':geometry}],'returnByValue':True,'silent':True},state['top_session'])
    return ('exceptionDetails' not in checked and card_hit_test.hit(cdp,state['top_session'],
        checked.get('result',{}).get('value'),state['owner_node'],state['proof']['parent_id']))
