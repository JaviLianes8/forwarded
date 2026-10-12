"""The error raised for headers and values that break RFC 7239."""

from __future__ import annotations


class ForwardedError(ValueError):
    """A header or value that does not follow RFC 7239.

    ``position`` is the offset in the header line where the problem was found, or
    ``None`` when the problem is with a whole value rather than a place in a line.
    """

    def __init__(self, message: str, position: int | None = None) -> None:
        super().__init__(message if position is None else f"{message} at offset {position}")
        self.position = position
