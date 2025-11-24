"""Test assertion helpers to reduce duplication across test files.

Provides reusable assertion functions for common test patterns:
- FlextResult assertions (success/failure)
- Entry validation
- Schema validation (attribute/objectClass)
- Roundtrip validation
- Parse/Write validation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import cast

from flext_core import FlextResult, T
from flext_tests import FlextTestsMatchers

from flext_ldif import FlextLdifModels

from .test_factories import FlextLdifTestFactories


class TestAssertions:
    """Reusable assertion helpers for tests.

    Delegates to FlextTestsMatchers for common assertions to avoid duplication.
    """

    # Prevent pytest from collecting static methods as tests
    __test__ = False

    @staticmethod
    def assert_success(
        result: FlextResult[T],
        error_msg: str | None = None,
    ) -> T:
        """Assert result is success and return unwrapped value.

        Delegates to FlextTestsMatchers.assert_success().

        Args:
            result: FlextResult to check
            error_msg: Optional custom error message

        Returns:
            Unwrapped value from result

        Raises:
            AssertionError: If result is failure

        """
        return FlextTestsMatchers.assert_success(result, error_msg)

    @staticmethod
    def assert_failure(
        result: FlextResult[T],
        expected_error: str | None = None,
    ) -> str:
        """Assert result is failure and return error message.

        Delegates to FlextTestsMatchers.assert_failure().

        Args:
            result: FlextResult to check
            expected_error: Optional expected error substring

        Returns:
            Error message from result

        Raises:
            AssertionError: If result is success

        """
        # Cast to object for FlextTestsMatchers which expects FlextResult[object]
        result_obj: FlextResult[object] = cast("FlextResult[object]", result)
        return FlextTestsMatchers.assert_failure(result_obj, expected_error)

    @staticmethod
    def assert_entry_valid(entry: FlextLdifModels.Entry) -> None:
        """Assert entry has valid structure.

        Args:
            entry: Entry to validate

        Raises:
            AssertionError: If entry is invalid

        """
        assert entry.dn is not None, "Entry must have DN"
        assert entry.dn.value, "Entry DN must not be empty"
        assert entry.attributes is not None, "Entry must have attributes"
        assert len(entry.attributes) > 0, "Entry must have at least one attribute"

    @staticmethod
    def assert_entries_valid(entries: Sequence[FlextLdifModels.Entry]) -> None:
        """Assert all entries are valid.

        Args:
            entries: Sequence of entries to validate

        Raises:
            AssertionError: If any entry is invalid

        """
        assert len(entries) > 0, "Must have at least one entry"
        for entry in entries:
            TestAssertions.assert_entry_valid(entry)

    @staticmethod
    def assert_schema_attribute_valid(
        attr: FlextLdifModels.SchemaAttribute,
        expected_oid: str | None = None,
        expected_name: str | None = None,
    ) -> None:
        """Assert schema attribute is valid.

        Args:
            attr: SchemaAttribute to validate
            expected_oid: Optional expected OID
            expected_name: Optional expected name

        Raises:
            AssertionError: If attribute is invalid

        """
        assert attr.oid, "Attribute must have OID"
        if expected_oid:
            assert attr.oid == expected_oid, (
                f"Expected OID {expected_oid}, got {attr.oid}"
            )
        if expected_name:
            assert attr.name == expected_name, (
                f"Expected name {expected_name}, got {attr.name}"
            )

    @staticmethod
    def assert_schema_objectclass_valid(
        oc: FlextLdifModels.SchemaObjectClass,
        expected_oid: str | None = None,
        expected_name: str | None = None,
    ) -> None:
        """Assert schema objectClass is valid.

        Args:
            oc: SchemaObjectClass to validate
            expected_oid: Optional expected OID
            expected_name: Optional expected name

        Raises:
            AssertionError: If objectClass is invalid

        """
        assert oc.oid, "ObjectClass must have OID"
        if expected_oid:
            assert oc.oid == expected_oid, f"Expected OID {expected_oid}, got {oc.oid}"
        if expected_name:
            assert oc.name == expected_name, (
                f"Expected name {expected_name}, got {oc.name}"
            )

    @staticmethod
    def assert_parse_success(
        result: FlextResult[FlextLdifModels.Entry | list[FlextLdifModels.Entry] | str],
        expected_count: int | None = None,
    ) -> list[FlextLdifModels.Entry]:
        """Assert parse result is success and return entries.

        Args:
            result: Parse result
            expected_count: Optional expected entry count

        Returns:
            List of parsed entries

        Raises:
            AssertionError: If parse failed

        """
        unwrapped = TestAssertions.assert_success(result, "Parse should succeed")
        if isinstance(unwrapped, str):
            msg = "Parse returned string instead of entries"
            raise AssertionError(msg)
        # Handle ParseResponse objects
        entries: list[FlextLdifModels.Entry]
        # Check if unwrapped has entries attribute (ParseResponse-like)
        if hasattr(unwrapped, "entries"):
            # unwrapped is ParseResponse-like object - use protocol for type safety
            from flext_ldif.protocols import FlextLdifProtocols

            if isinstance(unwrapped, FlextLdifProtocols.Services.HasEntriesProtocol):
                entries_raw = unwrapped.entries
                if isinstance(entries_raw, list):
                    entries = [
                        entry
                        for entry in entries_raw
                        if isinstance(entry, FlextLdifModels.Entry)
                    ]
                elif isinstance(entries_raw, FlextLdifModels.Entry):
                    entries = [entries_raw]
                else:
                    msg = "Parse returned unexpected entry type"
                    raise AssertionError(msg)
            else:
                # Fallback for objects with entries attribute but not protocol
                entries_raw = unwrapped.entries
                if isinstance(entries_raw, list):
                    entries = [
                        entry
                        for entry in entries_raw
                        if isinstance(entry, FlextLdifModels.Entry)
                    ]
                elif isinstance(entries_raw, FlextLdifModels.Entry):
                    entries = [entries_raw]
                else:
                    msg = "Parse returned unexpected entry type"
                    raise AssertionError(msg)
        elif isinstance(unwrapped, list):
            entries = [
                entry for entry in unwrapped if isinstance(entry, FlextLdifModels.Entry)
            ]
        elif isinstance(unwrapped, FlextLdifModels.Entry):
            entries = [unwrapped]
        else:
            msg = "Parse returned unexpected type"
            raise AssertionError(msg)
        if expected_count is not None:
            assert len(entries) == expected_count, (
                f"Expected {expected_count} entries, got {len(entries)}"
            )
        TestAssertions.assert_entries_valid(entries)
        return entries

    @staticmethod
    def assert_write_success(
        result: FlextResult[T],
        expected_content: str | None = None,
    ) -> str:
        """Assert write result is success and return LDIF string.

        Args:
            result: Write result
            expected_content: Optional expected content substring

        Returns:
            Written LDIF string

        Raises:
            AssertionError: If write failed

        """
        ldif = TestAssertions.assert_success(result, "Write should succeed")
        assert isinstance(ldif, str), "Write should return string"
        if expected_content:
            assert expected_content in ldif, (
                f"Expected content '{expected_content}' not found in LDIF"
            )
        return ldif

    @staticmethod
    def assert_roundtrip_preserves(
        original_entries: list[FlextLdifModels.Entry],
        roundtripped_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Assert roundtrip preserves entry count and structure.

        Args:
            original_entries: Original entries
            roundtripped_entries: Entries after roundtrip

        Raises:
            AssertionError: If roundtrip doesn't preserve structure

        """
        assert len(roundtripped_entries) == len(original_entries), (
            f"Roundtrip should preserve entry count: "
            f"original={len(original_entries)}, "
            f"roundtripped={len(roundtripped_entries)}"
        )
        for i, (original, roundtripped) in enumerate(
            zip(original_entries, roundtripped_entries, strict=True),
        ):
            assert original.dn is not None, f"Entry {i} original DN should not be None"
            assert roundtripped.dn is not None, (
                f"Entry {i} roundtripped DN should not be None"
            )
            assert original.dn.value == roundtripped.dn.value, (
                f"Entry {i} DN should be preserved: "
                f"original={original.dn.value}, "
                f"roundtripped={roundtripped.dn.value}"
            )

    @staticmethod
    def create_entry(
        dn: str,
        attributes: dict[str, str | list[str]] | None = None,
        *,
        validate: bool = False,
    ) -> FlextLdifModels.Entry:
        """Create Entry using FlextLdifTestFactories - delegates to factory.

        Replaces multiple create_entry_* helper methods:
        - create_entry_simple: Basic creation with optional validation
        - create_entry_from_dict: Creation from dictionary
        - create_entry_with_validation: Creation with required validation
        - create_entry_and_unwrap: Wrapper that unwraps result

        Args:
            dn: Distinguished name as string
            attributes: Optional dictionary of attribute names to values
            validate: Whether to validate entry structure (default: False)

        Returns:
            Created Entry model

        Raises:
            AssertionError: If entry creation fails

        """
        entry = FlextLdifTestFactories.create_entry(dn=dn, attributes=attributes)
        if validate:
            TestAssertions.assert_entry_valid(entry)
        return entry


__all__ = ["TestAssertions"]
