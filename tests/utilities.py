"""Test utilities facade with shared helper re-exports."""

from __future__ import annotations

from flext_tests import FlextTestsDocker, FlextTestsUtilities

from flext_ldif import FlextLdifUtilities


class FlextLdifTestUtilities(FlextTestsUtilities, FlextLdifUtilities):
    """Project test utility namespace extension."""

    class Ldif(FlextLdifUtilities.Ldif):
        """LDIF test utility namespace."""

        class Tests(FlextTestsUtilities.Tests):
            """Test utilities with Matchers and Docker support."""

            Docker = FlextTestsDocker


u = FlextLdifTestUtilities

__all__ = ["FlextLdifTestUtilities", "u"]
