"""The Forwarded grammar compiled from the fetched RFC 7239, RFC 9110 and RFC 3986 texts.

Every regular expression here comes from ABNF printed in those files (see abnf.py), so
the oracle owes nothing to this library's code. The list rule is the RFC 9110 recipient
form, and the checks after it are the RFC 7239 sentences: each parameter at most once
per element (section 4) and the value syntax of for, by, host and proto (sections 5, 6).
The one rule of this library's own is that a header needs at least one parameter.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from abnf import compile_expression, compile_rules, rule_sources

URI_RULES = [
    "dec-octet",
    "IPv4address",
    "h16",
    "ls32",
    "IPv6address",
    "unreserved",
    "pct-encoded",
    "sub-delims",
    "IPvFuture",
    "IP-literal",
    "reg-name",
    "host",
    "port",
    "scheme",
]
HTTP_RULES = ["obs-text", "qdtext", "quoted-pair", "quoted-string", "tchar", "token", "OWS", "Host"]


def section(text: str, title: str, end: str) -> str:
    """The body of a section: its last heading (the first is in the contents) to ``end``."""
    return text.rsplit(title, 1)[1].split(end, 1)[0]


def unquote(value: str) -> str:
    """Undo a quoted-string: drop the quotes, keep the character after each backslash."""
    if not value.startswith('"'):
        return value
    return re.sub(r"\\(.)", r"\1", value[1:-1], flags=re.DOTALL)


@dataclass(frozen=True)
class Grammar:
    header: re.Pattern[str]
    piece: re.Pattern[str]
    node: re.Pattern[str]
    host: re.Pattern[str]
    scheme: re.Pattern[str]
    ipv6: re.Pattern[str]

    def elements(self, value: str) -> list[list[tuple[str, str]]]:
        """Read a value the list rule accepts: per element, (lower-cased name, value) pairs."""
        found: list[list[tuple[str, str]]] = [[]]
        position = 0
        while position < len(value):
            match = self.piece.match(value, position)
            assert match is not None, value[position:]
            if match.group(1):
                found[-1].append((match.group(1).lower(), unquote(match.group(2))))
            elif "," in match.group(0):
                found.append([])
            position = match.end()
        return found

    def strict(self, header: str) -> list[dict[str, str]] | None:
        """What a strict reader returns for one field line, or ``None`` when it must refuse."""
        value = header.strip(" \t")  # a field value never includes its surrounding OWS
        if not self.header.fullmatch(value):
            return None
        elements = self.elements(value)
        if not any(elements):
            return None
        result = []
        for pairs in elements:
            names = [name for name, _ in pairs]
            if len(set(names)) != len(names):
                return None
            for name, text in pairs:
                syntax = {"for": self.node, "by": self.node, "host": self.host}.get(name)
                syntax = self.scheme if name == "proto" else syntax
                if syntax is not None and not syntax.fullmatch(text):
                    return None
            if pairs:
                result.append(dict(pairs))
        return result


def load(rfc7239: str, rfc9110: str, rfc3986: str) -> Grammar:
    """Compile the grammar from the three fetched RFC texts."""
    uri_text = section(rfc3986, "Appendix A.  Collected ABNF for URI", "Appendix B.")
    uri = compile_rules(rule_sources(uri_text, URI_RULES), URI_RULES, {})
    http_text = section(rfc9110, "Appendix A.  Collected ABNF", "Appendix B.")
    http_imports = {"uri-host": uri["host"], "port": uri["port"]}
    http = compile_rules(rule_sources(http_text, HTTP_RULES), HTTP_RULES, http_imports)
    syntax_text = section(rfc7239, "4.  Forwarded HTTP Header Field", "5.  Parameters")
    pair_rules = ["value", "forwarded-pair", "forwarded-element"]
    imports = {"token": http["token"], "quoted-string": http["quoted-string"]}
    forwarded = compile_rules(rule_sources(syntax_text, pair_rules), pair_rules, imports)
    node_text = section(rfc7239, "6.  Node Identifiers", "6.1.  ")
    node_rules = ["obfnode", "nodename", "port", "obfport", "node-port", "node"]
    node_imports = {"IPv4address": uri["IPv4address"], "IPv6address": uri["IPv6address"]}
    node = compile_rules(rule_sources(node_text, node_rules), node_rules, node_imports)
    recipient = rfc9110.split("a recipient MUST accept lists", 1)[1]
    list_rule = re.findall(r"^ +#element => (.+)$", recipient, flags=re.MULTILINE)[0]
    list_env = {"element": forwarded["forwarded-element"], "OWS": http["OWS"]}
    piece = rf"({http['token']})=({http['token']}|{http['quoted-string']})|;|[ \t]*,[ \t]*"
    return Grammar(
        header=re.compile(compile_expression(list_rule, list_env)),
        piece=re.compile(piece),
        node=re.compile(node["node"]),
        host=re.compile(http["Host"]),
        scheme=re.compile(uri["scheme"]),
        ipv6=re.compile(uri["IPv6address"]),
    )
