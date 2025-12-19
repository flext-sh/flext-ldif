"""Test type definitions extending src typings for centralized test types.

This module provides test-specific type extensions that inherit from
src/flext_ldif/typings.py classes. This centralizes test types without
duplicating parent class functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TypeAlias

from flext_tests.typings import FlextTestsTypes

from flext_ldif.typings import FlextLdifTypes

# Type aliases for test data structures
GenericFieldsDict: TypeAlias = dict[str, object]


class TestsFlextLdifTypes(FlextTestsTypes, FlextLdifTypes):
    """Test types extending FlextTestsTypes and FlextLdifTypes.

    Provides test-specific type extensions without duplicating parent functionality.
    All parent types are accessible via inheritance hierarchy.

    Naming convention: Tests[FlextLdif] where FlextLdif is the project name.
    Short name 't' for convenient access in tests.
    """

    # Test-specific type extensions can be added here
    # All parent types (from FlextTestsTypes and FlextLdifTypes) are accessible via inheritance


# Standardized short name for use in tests (same pattern as flext-core)
t = TestsFlextLdifTypes
Testst = TestsFlextLdifTypes  # Alias for tests/__init__.py

__all__ = [
    "GenericFieldsDict",
    "TestsFlextLdifTypes",
    "Testst",
    "t",
]
