"""Split one Forwarded header line into elements and pairs (RFC 7239 section 4).

A quoted-string starts only where a value starts, never in the middle of a name or a
token, and a line never continues into the next one. In lenient mode an error is recorded
on its element and scanning resumes at a delimiter the error cannot hide: after a broken
quoted-string that is the first comma after its opening quote, so text a client sent can
never swallow an element a proxy appended after it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ._errors import ForwardedError
from ._tokens import OWS, is_quotable, is_token


@dataclass
class Pair:
    name: str
    value: str
    position: int


@dataclass
class Element:
    pairs: list[Pair] = field(default_factory=list)
    error: ForwardedError | None = None

    def as_dict(self) -> dict[str, str]:
        return {pair.name: pair.value for pair in self.pairs}


class _Resync(Exception):
    """Abandon the current element and resume scanning at ``position``."""

    def __init__(self, position: int) -> None:
        self.position = position


class _Scanner:
    def __init__(self, line: str, strict: bool) -> None:
        self.line = line
        self.strict = strict
        self.element = Element()

    def fail(self, message: str, position: int) -> None:
        error = ForwardedError(message, position)
        if self.strict:
            raise error
        if self.element.error is None:
            self.element.error = error

    def skip_ows(self, i: int) -> int:
        while i < len(self.line) and self.line[i] in OWS:
            i += 1
        return i

    def skip_to(self, i: int, stops: str) -> int:
        while i < len(self.line) and self.line[i] not in stops:
            i += 1
        return i

    def elements(self) -> list[Element]:
        found: list[Element] = []
        i = 0
        while True:
            self.element = Element()
            try:
                i = self.scan_element(self.skip_ows(i))
            except _Resync as resync:
                i = resync.position
            if self.element.pairs or self.element.error is not None:
                found.append(self.element)
            if i >= len(self.line):
                return found
            i += 1

    def scan_element(self, i: int) -> int:
        """Scan pairs from ``i``; return the index of the ending comma or the line length."""
        line = self.line
        while True:
            if not self.strict:
                i = self.skip_ows(i)
            if i >= len(line) or line[i] == ",":
                return i
            if line[i] == ";":
                i += 1
                continue
            i = self.scan_pair(i)
            if self.strict and i < len(line) and line[i] in OWS:
                i = self.skip_ows(i)
                if i < len(line) and line[i] != ",":
                    self.fail("whitespace is only allowed around commas", i)
            if i < len(line) and line[i] == ";":
                i += 1
            elif i < len(line) and line[i] != ",":
                self.fail("expected ';' or ','", i)
                i = self.skip_to(i, ";,")

    def scan_pair(self, i: int) -> int:
        start = i
        i = self.skip_to(i, "=;,")
        name = self.line[start:i].strip(OWS) if not self.strict else self.line[start:i]
        if not is_token(name) or i >= len(self.line) or self.line[i] != "=":
            self.fail("expected a parameter name followed by '='", start)
            return self.skip_to(i, ";,")
        i += 1
        if not self.strict:
            i = self.skip_ows(i)
        if i < len(self.line) and self.line[i] == '"':
            value, end = self.quoted(i)
            after = end if self.strict else self.skip_ows(end)
            if after < len(self.line) and self.line[after] not in ";," + OWS:
                self.fail("unexpected text after a quoted-string", after)
                raise _Resync(self.skip_to(i + 1, ","))
        else:
            value, end = self.token(i)
            if not value:
                self.fail(f"parameter {name!r} needs a token or a quoted-string", i)
                return end
        self.add(name.lower(), value, i)
        return end if self.strict else self.skip_ows(end)

    def token(self, i: int) -> tuple[str, int]:
        if not self.strict:
            end = self.skip_to(i, ";,")
            return self.line[i:end].strip(OWS), end
        end = i
        while end < len(self.line) and is_token(self.line[end]):
            end += 1
        return self.line[i:end], end

    def quoted(self, i: int) -> tuple[str, int]:
        """Read the quoted-string opening at ``i``; return its content and the index after it."""
        line, j = self.line, i + 1
        out: list[str] = []
        while j < len(line):
            char = line[j]
            if char == '"':
                return "".join(out), j + 1
            if char == "\\" and j + 1 < len(line):
                if self.strict and not is_quotable(line[j + 1]):
                    self.fail("invalid character after a backslash", j + 1)
                out.append(line[j + 1])
                j += 2
                continue
            if self.strict and not is_quotable(char):
                self.fail("invalid character in a quoted-string", j)
            out.append(char)
            j += 1
        self.fail("unterminated quoted-string", i)
        raise _Resync(self.skip_to(i + 1, ","))

    def add(self, name: str, value: str, position: int) -> None:
        pairs = self.element.pairs
        if any(pair.name == name for pair in pairs):
            self.fail(f"parameter {name!r} occurs twice in one element", position)
        pairs.append(Pair(name, value, position))


def scan_line(line: str, *, strict: bool) -> list[Element]:
    """Return the non-empty elements of one header line, in order."""
    return _Scanner(line, strict).elements()
