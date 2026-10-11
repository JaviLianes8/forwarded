"""Parse and build the HTTP Forwarded header (RFC 7239), with correct quoting."""

from __future__ import annotations

from ._build import build
from ._parse import parse

__version__ = "0.1.0"

__all__ = ["build", "parse"]
