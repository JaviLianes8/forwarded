"""Parse and build the HTTP Forwarded header (RFC 7239), and find the real client."""

from ._build import build
from ._client import Client, client_from_forwarded, client_from_x_forwarded
from ._errors import ForwardedError
from ._node import Node, parse_node
from ._parse import parse
from ._xff import convert_x_forwarded_for, parse_x_forwarded

__version__ = "1.0.0"

# The public classes show and pickle as forwarded.<Name>, so a pickle never depends on
# the private module that defines them; pickles made by 0.2.0 still load.
for _cls in (Client, ForwardedError, Node):
    _cls.__module__ = __name__
    # Methods follow, so doctest finds their examples here (it takes properties anyway).
    for _member in vars(_cls).values():
        if callable(_member) and str(getattr(_member, "__module__", "")).startswith("forwarded._"):
            _member.__module__ = __name__
del _cls, _member

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
