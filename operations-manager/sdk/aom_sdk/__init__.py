"""
Official Python client SDK for the Couchbase Agent Operations Manager.

    from aom_sdk import AOMClient

    client = AOMClient("http://localhost:8090", api_key="demo-support-agent-9f21")
    print(client.health())

See README.md in this package, the bundled examples/, or the appliance's
Tools -> Developer SDK page for the full quickstart.
"""
from .client import AOMClient
from .exceptions import (
    AOMAuthenticationError,
    AOMAuthorizationError,
    AOMConnectionError,
    AOMError,
    AOMNotFoundError,
    AOMServerError,
)
from .mcp_tools import to_mcp_tool, to_mcp_tools

__version__ = "0.2.0"

__all__ = [
    "AOMClient",
    "AOMError",
    "AOMAuthenticationError",
    "AOMAuthorizationError",
    "AOMConnectionError",
    "AOMNotFoundError",
    "AOMServerError",
    "to_mcp_tool",
    "to_mcp_tools",
    "__version__",
]
