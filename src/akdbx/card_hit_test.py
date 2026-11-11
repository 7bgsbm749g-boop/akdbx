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


def hit(cdp, session, point, node, frame):
    if not isinstance(point, dict):
        return False
    # DOM.getNodeForLocation uses the CDP target's root document coordinates.
    # The frame guards also retain local viewport coordinates for their mapping.
    x, y = point.get('rootX', point.get('x')), point.get('rootY', point.get('y'))
    if any(type(v) not in (int, float) or not math.isfinite(v) or abs(v) >= 2**30 for v in (x,y)):
        return False
    result = cdp.call('DOM.getNodeForLocation', dict(x=round(x), y=round(y),
        includeUserAgentShadowDOM=False, ignorePointerEventsNone=True), session)
    return (type(result.get('backendNodeId')) is int and result['backendNodeId'] == node
            and result.get('frameId') == frame)


def input_point(cdp, session, obj, node, frame):
    value = point(cdp, session, obj)
    return value if hit(cdp, session, value, node, frame) else None
