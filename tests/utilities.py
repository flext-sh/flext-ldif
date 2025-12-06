"""Test utility definitions extending src utilities for centralized test utilities.

This module provides test-specific utility extensions that inherit from
src/flext_ldif/utilities.py classes. This centralizes test utilities without
duplicating parent class functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests.utilities import FlextTestsUtilities

from flext_ldif.utilities import FlextLdifUtilities


class TestsFlextLdifUtilities(FlextTestsUtilities, FlextLdifUtilities):
    """Test utilities extending FlextTestsUtilities and FlextLdifUtilities.

    Provides test-specific utility extensions without duplicating parent functionality.
    All parent utilities are accessible via inheritance hierarchy.

    Naming convention: Tests[FlextLdif] where FlextLdif is the project name.
    Short name 'u' for convenient access in tests (note: 'u' is also used for FlextLdifUtilities).
    """

    # Test-specific utility extensions can be added here
    # All parent utilities are accessible via inheritance


# Standardized short name for use in tests (same pattern as flext-core)
u = TestsFlextLdifUtilities

__all__ = [
    "TestsFlextLdifUtilities",
    "u",
]
