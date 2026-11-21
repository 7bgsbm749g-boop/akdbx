"""Presentation contracts against real handlers; synthetic fixtures only."""
import base64
import hashlib
import re
from html.parser import HTMLParser
from urllib.parse import urlsplit

import pytest

from pykeepass.exceptions import CredentialsError
from akdbx import portal
from akdbx.broker import Broker
from akdbx.web_unlock import start_unlock_server
from test_broker import Entry, RecordingTyper, Vault
from test_cards import begin as begin_card, post as post_card
from test_import_totp import private as import_private, nonce
from test_totp import KEY, prepare
from test_web_unlock import call
from test_writes import begin, deployed, template, private_post


class Markup(HTMLParser):
    def __init__(self, page):
        super().__init__()
        self.tags = []
        self.feed(page.decode())

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def check_page(headers, page):
    assert b'KeePass' not in page
    assert b'<title>AKDBX: ' in page
    policy = headers['Content-Security-Policy']
    directives = dict(part.strip().split(' ', 1) for part in policy.split(';'))
    assert directives['default-src'] == "'none'"
    assert directives['base-uri'] == "'none'"
    assert directives['form-action'] == "'self'"
    assert directives['frame-ancestors'] == "'none'"
    assert "'unsafe-inline'" not in directives['script-src']
    assert "'unsafe-eval'" not in directives['script-src']
    scripts = re.findall(rb'<script>(.*?)</script>', page, re.S)
    assert scripts == [portal.SCRIPT.encode()]
    digest = base64.b64encode(hashlib.sha256(scripts[0]).digest()).decode()
    assert f"'sha256-{digest}'" in directives['script-src']
    markup = Markup(page)
    for tag, attrs in markup.tags:
        assert not any(name.startswith('on') for name in attrs)
        if tag == 'input' and attrs.get('type') == 'password':
            toggle, = [a for t, a in markup.tags if t == 'button' and a.get('aria-controls') == attrs['id']]
            assert toggle['type'] == 'button'
            assert toggle['aria-pressed'] == 'false'
            assert toggle['aria-label'].startswith('Show ')
            assert 'value' not in attrs
    return markup


@pytest.mark.parametrize('kind', ['password', 'card', 'totp', 'import'])
def test_private_forms_results_errors_and_branding(deployed, kind):
    broker, _, _, socket = deployed
    if kind == 'card':
        op = begin_card(broker)
    elif kind in {'totp', 'import'}:
        op = prepare(broker)
    else:
        op = begin(broker)
    parts = urlsplit(op['private_url'])
    route = ('/totp/import' if kind == 'import' else parts.path) + '?' + parts.query
    code, headers, page = call(socket, 'GET', route)
    assert code == 200
    markup = check_page(headers, page)
    if kind == 'import':
        manual, = [a for t, a in markup.tags if t == 'input' and a.get('id') == 'manual']
        assert 'name' not in manual and 'required' not in manual
        assert manual['maxlength'] == '8192'
        assert "script-src 'self' " in headers['Content-Security-Policy']
        import json
        code, headers, page = import_private(socket, op, '/totp/import', {'payloads': json.dumps([KEY])})
        assert code == 200
        check_page(headers, page)
        code, headers, page = import_private(socket, op, '/totp/review', {
            'choice': '0', 'nonce': nonce(broker, op), 'confirmed': 'yes'})
    elif kind == 'card':
        code, headers, page = post_card(socket, op, confirmed='no')
        assert code == 409
        check_page(headers, page)
        code, headers, page = post_card(socket, op)
    elif kind == 'totp':
        from urllib.parse import urlencode
        code, headers, page = call(socket, 'POST', route, urlencode({'setup': KEY, 'confirmed': 'yes'}))
    else:
        code, headers, page = private_post(socket, op, confirmation='mismatch')
        assert code == 409
        check_page(headers, page)
        code, headers, page = private_post(socket, op)
    assert code == 200
    check_page(headers, page)
    assert b'saved to AKDBX' in page


def test_unlock_failed_rate_limit_and_ready_pages(tmp_path):
    def opener(*_args):
        raise CredentialsError('synthetic diagnostic must not appear')

    broker = Broker(None, RecordingTyper())
    socket = tmp_path / 'private' / 'portal.sock'
    server, url = start_unlock_server(broker, tmp_path / 'unused.kdbx', None,
                                      socket, 'https://node.example', opener=opener)
    parts = urlsplit(url)
    route = parts.path + '?' + parts.query
    try:
        code, headers, page = call(socket, 'GET', route)
        assert code == 200
        check_page(headers, page)
        assert b'<h1 id="portal-title">Unlock AKDBX</h1>' in page
        assert b'role="progressbar"' in page and b'aria-valuenow' not in page
        assert b'role="status"' in page
        for left in (2, 1):
            code, headers, page = call(socket, 'POST', route, 'password=synthetic')
            assert code == 401
            check_page(headers, page)
            assert b'data-unlock-form' in page and b'role="alert"' in page
            assert f'{left} attempt'.encode() in page
            assert b'synthetic diagnostic' not in page
        for method in ['POST', 'GET', 'POST']:
            code, headers, page = call(socket, method, route, 'password=synthetic' if method == 'POST' else None)
            assert code == 403
            check_page(headers, page)
            assert b'Unlock link blocked' in page and b'Ask your agent for a new unlock link' in page
            assert b'<form' not in page and b'synthetic diagnostic' not in page
        url = broker.dispatch({'action': 'new-unlock-link', 'user_confirmed': True})['unlock_url']
        parts = urlsplit(url)
        route = parts.path + '?' + parts.query
        broker.unlock(Vault([Entry()]))
        for method in ['GET', 'POST']:
            code, headers, page = call(socket, method, route, 'password=synthetic' if method == 'POST' else None)
            assert code == 200
            check_page(headers, page)
            assert b'The AKDBX broker is ready.' in page
    finally:
        server.shutdown()
        server.server_close()


def test_visibility_controls_do_not_inspect_or_persist_secrets():
    # Visibility uses types/attributes. Only standard form encoding handles the POST.
    assert not re.search(r'\b(value|XMLHttpRequest|console|localStorage|sessionStorage)\b', portal.SCRIPT)
    assert portal.SCRIPT.count('new FormData(form)') == 1
    assert 'body: new URLSearchParams(new FormData(form))' in portal.SCRIPT
    escaped = portal.field('Master <password>', 'secret"name')
    assert 'Master &lt;password&gt;' in escaped and 'id="secret&quot;name"' in escaped
