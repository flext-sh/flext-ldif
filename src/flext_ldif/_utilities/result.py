"""LDIF result alias over the canonical flext-core result."""

from __future__ import annotations

from flext_core import FlextResult

FlextLdifUtilitiesResult = FlextResult
r = FlextResult

__all__ = ["FlextLdifUtilitiesResult", "r"]
