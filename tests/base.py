"""Test service base class for flext-ldif tests.

Extends FlextTestsServiceBase from flext_tests with LDIF-specific test utilities.

All test classes should inherit from FlextLdifTestsServiceBase to leverage
unified entry creation, assertions, and fixture management from flext_tests
plus LDIF-specific helpers.

Naming convention: FlextLdifTestsServiceBase
Short name 's' for convenient access in tests (from tests import s).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence
from itertools import starmap

from flext_tests import s as flext_tests_s

from flext_ldif.models import m
from flext_ldif.services.entries import FlextLdifEntries


class FlextLdifTestsServiceBase(flext_tests_s):
    """Base class for all test services in flext-ldif.

    Extends FlextTestsServiceBase from flext_tests with LDIF-specific utilities:
    1. Unified entry creation via create_entry()
    2. Multiple entry creation via create_entries()
    3. Real implementations (NO mocks)
    4. All utilities from flext_tests (assert_success, assert_failure, etc.)

    Example usage:
        from tests import s

        class TestsFlextLdifMyService(s):
            def test_something(self) -> None:
                entry = self.create_entry(
                    "cn=test,dc=example,dc=com",
                    {"cn": ["test"], "objectClass": ["person"]}
                )
                result = some_service.process(entry)
                unwrapped = self.assert_success(result)

    """

    def create_entry(
        self,
        dn: str,
        attributes: dict[str, str | list[str]],
    ) -> m.Ldif.Entry:
        """Create test entry using real FlextLdifEntries service.

        Args:
            dn: Distinguished Name for the entry
            attributes: Dictionary of attribute names to values

        Returns:
            m.Ldif.Entry: Real Entry instance

        Raises:
            AssertionError: If entry creation fails

        """
        service = FlextLdifEntries()
        result = service.create_entry(dn=dn, attributes=attributes)
        if not result.is_success:
            msg = f"Entry creation failed: {result.error}"
            raise AssertionError(msg)
        return result.unwrap()

    def create_entries(
        self,
        entries_data: Sequence[tuple[str, dict[str, str | list[str]]]],
    ) -> list[m.Ldif.Entry]:
        """Create multiple test entries.

        Args:
            entries_data: Sequence of (dn, attributes) tuples

        Returns:
            list[m.Ldif.Entry]: List of real Entry instances

        """
        return list(starmap(self.create_entry, entries_data))


# Standardized short name for use in tests
s = FlextLdifTestsServiceBase

__all__ = [
    "FlextLdifTestsServiceBase",
    "s",
]
