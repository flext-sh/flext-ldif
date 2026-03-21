"""Test utilities facade with shared helper re-exports."""

from __future__ import annotations

from flext_tests import u

from flext_ldif import FlextLdifUtilities
from flext_ldif._utilities import FlextLdifUtilitiesOID


class TestsFlextLdifUtilities(u, FlextLdifUtilities):
    """Project test utility namespace extension."""

    OID = FlextLdifUtilitiesOID

    class TestCategorization:
        """Test categorization utilities."""


__all__ = ["TestsFlextLdifUtilities", "u"]

u = TestsFlextLdifUtilities


# Lazy-load helpers to avoid circular imports
def __getattr__(name: str) -> type[object]:
    """Lazy-load test helpers from constants."""
    if name in {"TestDeduplicationHelpers", "RfcTestHelpers"}:
        from tests.constants import TestsFlextLdifConstants

        return getattr(TestsFlextLdifConstants, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
