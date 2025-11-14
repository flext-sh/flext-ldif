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

from typing import TYPE_CHECKING

from flext_core import FlextResult

if TYPE_CHECKING:
    from flext_ldif.models import FlextLdifModels


class TestAssertions:
    """Reusable assertion helpers for tests."""

    @staticmethod
    def assert_success(result: FlextResult[object], error_msg: str | None = None) -> object:
        """Assert result is success and return unwrapped value.

        Args:
            result: FlextResult to check
            error_msg: Optional custom error message

        Returns:
            Unwrapped value from result

        Raises:
            AssertionError: If result is failure

        """
        if not result.is_success:
            msg = error_msg or f"Expected success but got failure: {result.error}"
            raise AssertionError(msg)
        return result.unwrap()

    @staticmethod
    def assert_failure(result: FlextResult[object], expected_error: str | None = None) -> str:
        """Assert result is failure and return error message.

        Args:
            result: FlextResult to check
            expected_error: Optional expected error substring

        Returns:
            Error message from result

        Raises:
            AssertionError: If result is success

        """
        if result.is_success:
            raise AssertionError(f"Expected failure but got success: {result.unwrap()}")
        error = result.error
        if expected_error and expected_error not in error:
            raise AssertionError(
                f"Expected error containing '{expected_error}' but got: {error}"
            )
        return error

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
    def assert_entries_valid(entries: list[FlextLdifModels.Entry]) -> None:
        """Assert all entries are valid.

        Args:
            entries: List of entries to validate

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
            assert attr.oid == expected_oid, f"Expected OID {expected_oid}, got {attr.oid}"
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
            raise AssertionError("Parse returned string instead of entries")
        if isinstance(unwrapped, list):
            entries = unwrapped
        else:
            entries = [unwrapped]
        if expected_count is not None:
            assert len(entries) == expected_count, (
                f"Expected {expected_count} entries, got {len(entries)}"
            )
        TestAssertions.assert_entries_valid(entries)
        return entries

    @staticmethod
    def assert_write_success(
        result: FlextResult[str],
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
            zip(original_entries, roundtripped_entries, strict=True)
        ):
            assert original.dn.value == roundtripped.dn.value, (
                f"Entry {i} DN should be preserved: "
                f"original={original.dn.value}, "
                f"roundtripped={roundtripped.dn.value}"
            )


__all__ = ["TestAssertions"]
