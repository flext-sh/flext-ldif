"""Test helpers module.

Provides reusable test utilities to reduce duplication across test files.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from .test_assertions import TestAssertions
from .test_deduplication_helpers import DeduplicationHelpers
from .test_entry_helpers import EntryTestHelpers
from .test_factories import FlextLdifTestFactories
from .test_fixture_helpers import FixtureTestHelpers
from .test_operations import TestOperations
from .test_oud_helpers import OudTestHelpers
from .test_quirk_helpers import QuirkTestHelpers
from .test_rfc_helpers import RfcTestHelpers
from .test_schema_helpers import SchemaTestHelpers

# Alias for backward compatibility
TestDeduplicationHelpers = DeduplicationHelpers

__all__ = [
    "DeduplicationHelpers",
    "EntryTestHelpers",
    "FixtureTestHelpers",
    "FlextLdifTestFactories",
    "OudTestHelpers",
    "QuirkTestHelpers",
    "RfcTestHelpers",
    "SchemaTestHelpers",
    "TestAssertions",
    "TestDeduplicationHelpers",
    "TestOperations",
]
