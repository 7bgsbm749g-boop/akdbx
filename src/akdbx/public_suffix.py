"""Offline registrable-domain lookup from the vendored Public Suffix List.

Used only to keep agent-added additional URLs on the saved site. Hosts are the
ASCII (punycode) lowercase spelling that `https_origin` returns. The list
includes private suffixes such as `github.io`, so different users' subdomains
are different sites, as in Chrome.
"""
from __future__ import annotations

import functools
from importlib import resources

import idna


@functools.lru_cache(maxsize=1)
def _rules():
    rules, exceptions = set(), set()
    text = resources.files('akdbx').joinpath('public_suffix_assets/public_suffix_list.dat').read_text(encoding='utf-8')
    for line in text.splitlines():
        rule = line.strip().split(' ', 1)[0]
        if not rule or rule.startswith('//'):
            continue
        exception = rule.startswith('!')
        rule = rule.lstrip('!')
        try:
            labels = [label if label == '*' else idna.encode(label, uts46=True).decode('ascii')
                      for label in rule.lower().split('.')]
        except idna.IDNAError:
            continue  # A rule this codec cannot express cannot match an ASCII host either.
        (exceptions if exception else rules).add('.'.join(labels))
    if len(rules) < 1000:
        raise RuntimeError('public suffix list missing or truncated')
    return frozenset(rules), frozenset(exceptions)


def registrable_domain(host):
    """Return the host's registrable domain, or None for a public suffix or invalid host."""
    if not isinstance(host, str) or not host or not host.isascii() or host.endswith('.') or '..' in host:
        return None
    labels = host.lower().split('.')
    rules, exceptions = _rules()
    suffix_length = 1  # The implicit "*" rule.
    for start in range(len(labels)):
        candidate = labels[start:]
        name = '.'.join(candidate)
        wildcard = '.'.join(['*', *candidate[1:]])
        if name in exceptions:
            suffix_length = len(candidate) - 1
            break
        if name in rules or wildcard in rules:
            suffix_length = max(suffix_length, len(candidate))
    if len(labels) <= suffix_length:
        return None
    return '.'.join(labels[-suffix_length - 1:])
