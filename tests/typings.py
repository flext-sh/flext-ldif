"""Test type definitions extending src typings for centralized test types.

This module provides test-specific type extensions that inherit from
src/flext_ldif/typings.py classes. This centralizes test types without
duplicating parent class functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import t

from flext_ldif import FlextLdifTypes


class TestsFlextLdifTypes(t, FlextLdifTypes):
    """Test types extending t and FlextLdifTypes.

    Provides test-specific type extensions without duplicating parent functionality.
    All parent types are accessible via inheritance hierarchy.

    Hierarchy:
    - t.Tests.* (generic test types from flext_tests)
    - FlextLdifTypes.Ldif.* (source types from flext_ldif)
    - TestsFlextLdifTypes.Tests.* (flext-ldif-specific test types)

    Naming convention: Tests[FlextLdif] where FlextLdif is the project name.
    Short name 't' for convenient access in tests, 'tt' as test-specific alias.
    """

    class Tests(t.Tests):
        """flext-ldif-specific test type definitions namespace.

        Use tt.LdifTests.* for flext-ldif-specific test types.
        Use t.Tests.* for generic test types from t.
        """

        class Fixtures:
            """TypedDict definitions for LDIF test fixtures."""


t = TestsFlextLdifTypes
type GenericFieldsDict = dict[str, str]
__all__ = ["GenericFieldsDict", "TestsFlextLdifTypes", "t"]
