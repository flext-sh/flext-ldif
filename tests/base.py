"""Test service base class for flext-ldif tests.

Extends s from flext_tests with LDIF-specific test utilities.

All test classes should inherit from FlextLdifTestsServiceBase to leverage
unified entry creation, assertions, and fixture management from flext_tests
plus LDIF-specific helpers.

Naming convention: FlextLdifTestsServiceBase
Short name 's' for convenient access in tests (from tests import s).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, MutableSequence, Sequence
from itertools import starmap
from typing import override

from flext_core import r

from flext_ldif import FlextLdifEntries
from tests import m, s, t


class FlextLdifTestsServiceBase(s[m.Ldif.Entry]):
    """Base class for all test services in flext-ldif.

    Extends s from flext_tests with LDIF-specific utilities:
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

    @override
    def execute(self) -> r[m.Ldif.Entry]:
        """No-op execute for test base — tests don't run as services."""
        return r[m.Ldif.Entry].fail("Test base class: execute not applicable")

    @staticmethod
    def assert_failure[TResult](
        result: r[TResult],
        expected_error: str | None = None,
    ) -> str:
        """Assert result is failure and return error message."""
        if result.is_success:
            msg = f"Expected failure but got success: {result.value}"
            raise AssertionError(msg)
        error = result.error
        if error is None:
            msg = "Expected error but got None"
            raise AssertionError(msg)
        if expected_error and expected_error not in error:
            msg = f"Expected error containing '{expected_error}' but got: {error}"
            raise AssertionError(msg)
        return error

    @staticmethod
    def assert_success[TResult](
        result: r[TResult],
        error_msg: str | None = None,
    ) -> TResult:
        """Assert result is success and return unwrapped value."""
        if not result.is_success:
            msg = error_msg or f"Expected success but got failure: {result.error}"
            raise AssertionError(msg)
        return result.value

    @classmethod
    def create_entry(
        cls,
        dn: str,
        attributes: MutableMapping[str, str | MutableSequence[str]] | None = None,
    ) -> m.Ldif.Entry:
        """Create test entry using real FlextLdifEntries service.

        Args:
            dn: Distinguished Name for the entry
            attributes: Dictionary of attribute names to values (defaults to empty dict)

        Returns:
            p.Entry: Real Entry instance

        Raises:
            AssertionError: If entry creation fails

        """
        if attributes is None:
            attributes = {}
        service = FlextLdifEntries()
        result = service.create_entry(dn=dn, attributes=attributes)
        if not result.is_success:
            msg = f"Entry creation failed: {result.error}"
            raise AssertionError(msg)
        return result.value

    @classmethod
    def create_entries(
        cls,
        entries_data: Sequence[tuple[str, Mapping[str, str | t.StrSequence]]],
    ) -> Sequence[m.Ldif.Entry]:
        """Create multiple test entries.

        Args:
            entries_data: Sequence of (dn, attributes) tuples

        Returns:
            Sequence[p.Entry]: List of real Entry instances

        """
        return list(starmap(cls.create_entry, entries_data))


s = FlextLdifTestsServiceBase
__all__ = ["FlextLdifTestsServiceBase", "s"]
