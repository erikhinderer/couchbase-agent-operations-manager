"""Exceptions raised by the Couchbase Agent Operations Manager SDK.

Every error the gateway can return over HTTP is mapped to one of these, so
calling code can `except AOMAuthenticationError` instead of inspecting an
HTTP status code by hand.
"""
from __future__ import annotations

from typing import Optional


class AOMError(Exception):
    """Base class for every error this SDK raises."""

    def __init__(self, message: str, status_code: Optional[int] = None, detail: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail if detail is not None else message

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        if self.status_code is not None:
            return f"[{self.status_code}] {super().__str__()}"
        return super().__str__()


class AOMConnectionError(AOMError):
    """Could not reach the operations manager at all (network/DNS/timeout)."""


class AOMAuthenticationError(AOMError):
    """401 - missing or invalid `Authorization: Bearer <api_key>` header."""


class AOMAuthorizationError(AOMError):
    """403 - authenticated, but this role is not allowed to do that."""


class AOMNotFoundError(AOMError):
    """404 - the tool/server/entry does not exist in the vetted catalog."""


class AOMServerError(AOMError):
    """5xx - the operations manager, or a downstream MCP server, failed."""
