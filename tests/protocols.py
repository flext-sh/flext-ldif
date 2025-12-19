"""Test protocol definitions extending src protocols for centralized test protocols.

This module provides test-specific protocol extensions that inherit from
src/flext_ldif/protocols.py classes. This centralizes test protocols without
duplicating parent class functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests.protocols import FlextTestsProtocols

from flext_ldif.protocols import FlextLdifProtocols


class TestsFlextLdifProtocols(FlextTestsProtocols, FlextLdifProtocols):
    """Test protocols extending FlextTestsProtocols and FlextLdifProtocols.

    Provides test-specific protocol extensions without duplicating parent functionality.
    All parent protocols are accessible via inheritance hierarchy.

    Naming convention: Tests[FlextLdif] where FlextLdif is the project name.
    Short name 'p' for convenient access in tests.
    """

    # Test-specific protocol extensions can be added here
    # All parent protocols are accessible via inheritance


# Standardized short name for use in tests (same pattern as flext-core)
p = TestsFlextLdifProtocols
Testsp = TestsFlextLdifProtocols  # Alias for tests/__init__.py

__all__ = [
    "TestsFlextLdifProtocols",
    "p",
]
