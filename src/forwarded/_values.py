"""Value syntax of the ``host`` and ``proto`` parameters (RFC 7239 sections 5.3 and 5.4)."""

from __future__ import annotations

import re
from ipaddress import IPv6Address

# RFC 3986 section 3.1: scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*")
# RFC 3986 section 3.2.2: reg-name = *( unreserved / pct-encoded / sub-delims ); an
# IPv4address is a reg-name too, so it needs no rule of its own here.
_REG_NAME = re.compile(r"(?:[A-Za-z0-9._~!$&'()*+,;=-]|%[0-9A-Fa-f]{2})*")
_IPV_FUTURE = re.compile(r"[vV][0-9A-Fa-f]+\.[A-Za-z0-9._~!$&'()*+,;=:-]+")
_PORT = re.compile(r"[0-9]*")


def is_scheme(value: str) -> bool:
    """Return whether ``value`` is a URI scheme name, the syntax of ``proto``."""
    return bool(_SCHEME.fullmatch(value))


def is_host(value: str) -> bool:
    """Return whether ``value`` follows ``Host = uri-host [ ":" port ]`` (RFC 9110 7.2)."""
    if value.startswith("["):
        close = value.find("]")
        if close < 0 or not _is_ip_literal(value[1:close]):
            return False
        rest = value[close + 1 :]
    else:
        host, colon, port = value.partition(":")
        if not _REG_NAME.fullmatch(host):
            return False
        rest = colon + port
    return not rest or (rest[0] == ":" and bool(_PORT.fullmatch(rest[1:])))


def _is_ip_literal(text: str) -> bool:
    if _IPV_FUTURE.fullmatch(text):
        return True
    if not re.fullmatch(r"[0-9A-Fa-f:.]+", text):
        return False
    try:
        IPv6Address(text)
    except ValueError:
        return False
    return True
