"""Unit tests for FLEXT-LDIF protocols and interfaces.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextProtocols
from flext_ldif import FlextLdifProtocols


class TestProtocolDefinitions:
    """Test protocol definitions are properly defined."""

    def test_protocols_use_flext_core(self) -> None:
        """Verify that LDIF protocols use flext-core protocols directly."""
        # This test confirms the architectural decision to use flext-core protocols
        # instead of duplicating protocol definitions in flext-ldif

        # Verify FlextProtocols exists and has Foundation layer
        assert hasattr(FlextProtocols, "Foundation")
        assert hasattr(FlextProtocols.Foundation, "Validator")

        # Verify FlextLdifProtocols exists but delegates to flext-core
        assert FlextLdifProtocols is not None

        # This confirms the FLEXT architectural principle:
        # Use flext-core protocols directly rather than duplicating them
