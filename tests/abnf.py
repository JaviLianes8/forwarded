"""A small ABNF (RFC 5234) to regular expression compiler for the grammar tests.

It reads rules exactly as they are printed in the fetched RFCs, so the oracles built with
it come from the specification text and not from this library's code. It covers what
those rules use: names, case-insensitive strings, %x values and ranges, alternation,
concatenation, groups, options, repetition and prose rules supplied by the caller.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

# RFC 5234 appendix B.1; HEXDIG is case-insensitive like every ABNF string.
CORE = {
    "ALPHA": "[A-Za-z]",
    "DIGIT": "[0-9]",
    "HEXDIG": "[0-9A-Fa-f]",
    "DQUOTE": '"',
    "SP": " ",
    "HTAB": "\\t",
    "VCHAR": "[!-~]",
}

_START = re.compile(r"^\s*([A-Za-z][A-Za-z0-9-]*)\s+=(?![/=>])\s*(.*)$")
_TOKEN = re.compile(
    r'\s*(?:(?P<str>"[^"]*")|(?P<num>%x[0-9A-Fa-f]+(?:-[0-9A-Fa-f]+)?)'
    r"|(?P<rep>\d*\*\d*|\d+)|(?P<name>[A-Za-z][A-Za-z0-9-]*)|(?P<prose><[^>]*>)"
    r"|(?P<op>[()\[\]/]))"
)


def rule_sources(text: str, names: Iterable[str]) -> dict[str, str]:
    """Return the ABNF source of each named rule in ``text``: comments dropped, lines joined.

    A rule starts at ``name =`` and runs over the following indented lines up to a blank
    line or the next rule. The first definition of a name in ``text`` wins.
    """
    wanted, found = set(names), dict[str, str]()
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = _START.match(line)
        if not match or match.group(1) not in wanted or match.group(1) in found:
            continue
        body = [_uncomment(match.group(2))]
        for following in lines[index + 1 :]:
            if not following.strip() or _START.match(following):
                break
            body.append(_uncomment(following))
        found[match.group(1)] = " ".join(part for part in body if part)
    missing = wanted - found.keys()
    assert not missing, f"rules not found in the text: {sorted(missing)}"
    return found


def compile_rules(
    sources: Mapping[str, str], order: Iterable[str], imports: Mapping[str, str]
) -> dict[str, str]:
    """Compile rules in dependency ``order``; ``imports`` gives regexes for outside names."""
    env = {**CORE, **imports}
    for name in order:
        env[name] = compile_expression(sources[name], env)
    return env


def compile_expression(source: str, env: Mapping[str, str]) -> str:
    """Compile one ABNF expression to a regular expression, names looked up in ``env``."""
    return _Parser(source, env).parse()


def _uncomment(line: str) -> str:
    out: list[str] = []
    quoted = False
    for char in line:
        if char == '"':
            quoted = not quoted
        elif char == ";" and not quoted:
            break
        out.append(char)
    return "".join(out).strip()


def _char(code: int) -> str:
    return re.escape(chr(code))


class _Parser:
    def __init__(self, source: str, env: Mapping[str, str]) -> None:
        self.tokens: list[tuple[str, str]] = []
        position = 0
        while source[position:].strip():
            match = _TOKEN.match(source, position)
            assert match is not None and match.lastgroup is not None, source[position:]
            self.tokens.append((match.lastgroup, match.group(match.lastgroup)))
            position = match.end()
        self.index = 0
        self.env = env

    def parse(self) -> str:
        result = self.alternation()
        assert self.index == len(self.tokens), self.tokens[self.index :]
        return result

    def peek(self) -> tuple[str, str]:
        return self.tokens[self.index] if self.index < len(self.tokens) else ("end", "")

    def alternation(self) -> str:
        options = [self.concatenation()]
        while self.peek() == ("op", "/"):
            self.index += 1
            options.append(self.concatenation())
        return options[0] if len(options) == 1 else "(?:" + "|".join(options) + ")"

    def concatenation(self) -> str:
        parts = []
        while self.peek() not in (("op", "/"), ("op", ")"), ("op", "]"), ("end", "")):
            parts.append(self.repetition())
        return "".join(parts)

    def repetition(self) -> str:
        kind, text = self.peek()
        if kind != "rep":
            return self.element()
        self.index += 1
        low, star, high = text.partition("*")
        element = self.element()
        if not star:
            return f"(?:{element}){{{low}}}"
        return f"(?:{element}){{{low or 0},{high}}}"

    def element(self) -> str:
        kind, text = self.peek()
        self.index += 1
        if (kind, text) in (("op", "("), ("op", "[")):
            inner = self.alternation()
            closing = ")" if text == "(" else "]"
            assert self.peek() == ("op", closing), self.peek()
            self.index += 1
            return f"(?:{inner})" if text == "(" else f"(?:{inner})?"
        if kind == "str":
            return "".join(
                f"[{c.upper()}{c.lower()}]" if c.isascii() and c.isalpha() else re.escape(c)
                for c in text[1:-1]
            )
        if kind == "num":
            low, _, high = text[2:].partition("-")
            return f"[{_char(int(low, 16))}-{_char(int(high or low, 16))}]"
        if kind in ("name", "prose"):
            assert text in self.env, f"no definition for {text}"
            return f"(?:{self.env[text]})"
        raise AssertionError(f"unexpected ABNF token {text!r}")
