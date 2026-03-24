"""Test type definitions extending src typings for centralized test types.

This module provides test-specific type extensions that inherit from
src/flext_ldif/typings.py classes. This centralizes test types without
duplicating parent class functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import FlextTestsTypes

from flext_ldif import FlextLdifTypes


class FlextLdifTestTypes(FlextTestsTypes, FlextLdifTypes):
    """Test types extending FlextTestsTypes and FlextLdifTypes.

    Provides test-specific type extensions without duplicating parent functionality.
    All parent types are accessible via inheritance hierarchy.

    Hierarchy:
    - FlextTestsTypes.Tests.* (generic test types from flext_tests)
    - FlextLdifTypes.Ldif.* (source types from flext_ldif)
    - FlextLdifTestTypes.Tests.* (flext-ldif-specific test types)

    Naming convention: Flext[Project]Test* where Project is the project name.
    Short name 't' for convenient access in tests.
    """

    class Ldif(FlextLdifTypes.Ldif):


        class Tests(FlextTestsTypes.Tests):
            """flext-ldif-specific test type definitions namespace.

            Use t.Tests.* for generic test types from FlextTestsTypes.
            """

            class Fixtures:
                """TypedDict definitions for LDIF test fixtures."""


t = FlextLdifTestTypes
type GenericFieldsDict = t.StrMapping
__all__ = ["FlextLdifTestTypes", "GenericFieldsDict", "t"]
