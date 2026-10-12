"""Parse and build the HTTP Forwarded header (RFC 7239), and find the real client."""

from __future__ import annotations

from ._build import build
from ._client import Client, client_from_forwarded, client_from_x_forwarded
from ._errors import ForwardedError
from ._node import Node, parse_node
from ._parse import parse
from ._xff import convert_x_forwarded_for, parse_x_forwarded

__version__ = "0.2.0"

__all__ = [
    "Client",
    "ForwardedError",
    "Node",
    "build",
    "client_from_forwarded",
    "client_from_x_forwarded",
    "convert_x_forwarded_for",
    "parse",
    "parse_node",
    "parse_x_forwarded",
]
