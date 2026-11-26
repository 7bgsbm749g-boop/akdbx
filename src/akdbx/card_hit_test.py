"""Pointer-independent browser hit tests. Never reads an input value."""
import math


def retained_node(cdp, session, obj):
    result = cdp.call('Runtime.callFunctionOn', dict(objectId=obj,
        functionDeclaration='function() { return this.node(); }', silent=True), session)
    node = result.get('result', {})
    if 'exceptionDetails' in result or not node.get('objectId'):
        raise ValueError('retained card node unavailable')
    try:
        described = cdp.call('DOM.describeNode', dict(objectId=node['objectId']), session)['node']
        backend = described['backendNodeId']
        if type(backend) is not int or backend <= 0:
            raise ValueError('retained card node unavailable')
        return backend
    finally:
        cdp.call('Runtime.releaseObject', dict(objectId=node['objectId']), session)


def point(cdp, session, obj):
    result = cdp.call('Runtime.callFunctionOn', dict(objectId=obj,
        functionDeclaration='function() { return this.geometry(); }', returnByValue=True,
        silent=True), session)
    value = result.get('result', {}).get('value')
    return value if 'exceptionDetails' not in result and isinstance(value, dict) else None


def hit(cdp, session, point, node, frame, part=None):
    if not isinstance(point, dict):
        return False
    # DOM.getNodeForLocation uses the CDP target's root document coordinates.
    # The frame guards also retain local viewport coordinates for their mapping.
    x, y = point.get('rootX', point.get('x')), point.get('rootY', point.get('y'))
    if any(type(v) not in (int, float) or not math.isfinite(v) or abs(v) >= 2**30 for v in (x,y)):
        return False
    result = cdp.call('DOM.getNodeForLocation', dict(x=round(x), y=round(y),
        includeUserAgentShadowDOM=False, ignorePointerEventsNone=True), session)
    if type(result.get('backendNodeId')) is not int or result.get('frameId') != frame:
        return False
    return result['backendNodeId'] == node or part is not None and part(result['backendNodeId'])


def own_part(cdp, session, obj, context, backend):
    """Whether the pin's ``part()`` claims the hit node: a dropdown button's own text or icon."""
    resolved = cdp.call('DOM.resolveNode', dict(backendNodeId=backend, executionContextId=context), session)['object']
    try:
        result = cdp.call('Runtime.callFunctionOn', dict(objectId=obj,
            functionDeclaration='function(node) { return this.part(node) === true; }',
            arguments=[dict(objectId=resolved['objectId'])], returnByValue=True, silent=True), session)
        return 'exceptionDetails' not in result and result.get('result', {}).get('value') is True
    finally:
        cdp.call('Runtime.releaseObject', dict(objectId=resolved['objectId']), session)


def input_point(cdp, session, obj, node, frame, context=None):
    value = point(cdp, session, obj)
    part = None if context is None else lambda backend: own_part(cdp, session, obj, context, backend)
    return value if hit(cdp, session, value, node, frame, part) else None
