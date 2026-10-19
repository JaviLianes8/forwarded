"""The error raised for headers and values that break RFC 7239, and safe message parts."""

from __future__ import annotations


class ForwardedError(ValueError):
    """A header or value that does not follow RFC 7239.

    ``position`` is the offset in the header line where the problem was found, or
    ``None`` when the problem is with a whole value rather than a place in a line.
    Messages quote at most 80 characters of the input.

    >>> from forwarded import ForwardedError, parse
    >>> try:
    ...     parse("for=192.0.2.43;for=192.0.2.44", strict=True)
    ... except ForwardedError as error:
    ...     print(error.position, isinstance(error, ValueError))
    ...     print(error)
    15 True
    parameter 'for' occurs twice in one element at offset 15
    """

    def __init__(self, message: str, position: int | None = None) -> None:
        super().__init__(message if position is None else f"{message} at offset {position}")
        self.position = position


def show(value: object, limit: int = 80) -> str:
    """Return ``repr(value)`` cut to ``limit`` characters, so huge input stays out of messages."""
    try:
        text = repr(value)
    except Exception:
        # An int past the digit limit, a structure too deep or a broken __repr__.
        return f"<{kind(value)}>"
    return text if len(text) <= limit else text[: limit - 3] + "..."


def kind(value: object) -> str:
    """Return the type name of ``value`` for a message, cut to 40 characters."""
    name = type(value).__name__
    return name if len(name) <= 40 else name[:37] + "..."
