"""Test type definitions extending src typings for centralized test types.

This module provides test-specific type extensions that inherit from
src/flext_ldif/typings.py classes. This centralizes test types without
duplicating parent class functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TypedDict

from flext_tests.typings import FlextTestsTypes

from flext_ldif.typings import FlextLdifTypes


class TestsFlextLdifTypes(FlextTestsTypes, FlextLdifTypes):
    """Test types extending FlextTestsTypes and FlextLdifTypes.

    Provides test-specific type extensions without duplicating parent functionality.
    All parent types are accessible via inheritance hierarchy.

    Hierarchy:
    - FlextTestsTypes.Tests.* (generic test types from flext_tests)
    - FlextLdifTypes.Ldif.* (source types from flext_ldif)
    - TestsFlextLdifTypes.Tests.* (flext-ldif-specific test types)

    Naming convention: Tests[FlextLdif] where FlextLdif is the project name.
    Short name 't' for convenient access in tests, 'tt' as test-specific alias.
    """

    class Tests:
        """flext-ldif-specific test type definitions namespace.

        Use tt.Tests.* for flext-ldif-specific test types.
        Use t.Tests.* for generic test types from FlextTestsTypes.
        """

        class Fixtures:
            """TypedDict definitions for LDIF test fixtures."""

            class GenericFieldsDict(TypedDict, total=False):
                """Generic dictionary for flexible test data and configurations."""

            class LdifEntryDict(TypedDict, total=False):
                """Test LDIF entry data."""

                dn: str
                changetype: str
                attributes: dict[str, list[str]]

            class LdifParseResultDict(TypedDict, total=False):
                """LDIF parse result test data."""

                entries: list[dict[str, object]]
                errors: list[str]
                warnings: list[str]


# Standardized short name for use in tests (same pattern as flext-core)
t = TestsFlextLdifTypes
tt = TestsFlextLdifTypes

__all__ = [
    "TestsFlextLdifTypes",
    "t",
    "tt",
]
