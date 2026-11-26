"""One HTTPS request to the Mozilla add-ons (AMO) API, in a child process of the broker.

`akdbx extension sign` talks to AMO through this file. The broker starts it
with ``python -I`` for each request, sends one JSON object on stdin and kills
it at a fixed deadline, so a slow DNS lookup, TLS handshake or server never
holds a broker thread longer than that. It uses only the standard library.

The input names the method, the URL, an optional request body (base64) and
its content type, and a JSON Web Token that expires within a minute. The
API secret never reaches this process: the broker signs the token. The
token goes only in the Authorization header of this one request. This file
ignores proxy variables and follows no redirect, so the header never goes to
another host; the broker decides about a redirect itself. The output is one
JSON object: the HTTP status, the Location header and the body (base64), or
``{"error": "network"}``. Nothing is logged.
"""
import base64
import json
import ssl
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

MAX_INPUT = 16 * 1024 * 1024
MAX_BODY = 8 * 1024 * 1024
METHODS = ('GET', 'POST', 'PUT')
USER_AGENT = 'akdbx-extension-sign/1'


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # urllib then raises HTTPError with the 3xx status.


def _read(response):
    body = response.read(MAX_BODY + 1)
    if len(body) > MAX_BODY:
        raise ValueError('response too large')
    return body


def perform(request):
    """Send one request; return the result object (never raise for HTTP status codes)."""
    method, url = request['method'], request['url']
    parts = urlsplit(url)
    if method not in METHODS or parts.scheme != 'https' or not parts.hostname or parts.username or parts.password:
        raise ValueError('invalid request')
    context = ssl.create_default_context(cafile=request.get('ca_file'))
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), _NoRedirect())
    headers = {'Accept': 'application/json', 'User-Agent': USER_AGENT}
    if request.get('token'):
        headers['Authorization'] = 'JWT ' + request['token']
    body = base64.b64decode(request['body'], validate=True) if request.get('body') is not None else None
    if body is not None:
        headers['Content-Type'] = request['content_type']
    timeout = float(request.get('timeout', 30))
    try:
        with opener.open(Request(url, data=body, method=method, headers=headers), timeout=timeout) as response:
            status, location, data = response.status, response.headers.get('Location'), _read(response)
    except HTTPError as exc:
        status, location = exc.code, exc.headers.get('Location') if exc.headers else None
        try:
            data = _read(exc)
        except Exception:
            data = b''
    return dict(status=status, location=location if isinstance(location, str) else None,
                body=base64.b64encode(data).decode('ascii'))


def main():
    try:
        request = json.loads(sys.stdin.buffer.read(MAX_INPUT + 1))
        if not isinstance(request, dict):
            raise ValueError
        result = perform(request)
    except (URLError, OSError, ValueError, KeyError, TypeError):
        result = {'error': 'network'}
    sys.stdout.write(json.dumps(result))
    sys.stdout.flush()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
