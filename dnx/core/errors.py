from __future__ import annotations


class DNXError(Exception):
    """Base dnsRecon exception."""


class ModuleError(DNXError):
    """Raised when a scanner module fails in a controlled way."""
