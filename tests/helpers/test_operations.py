"""Test operation helpers to reduce duplication across test files.

Provides reusable operation functions for common test patterns:
- Parse operations with validation
- Write operations with validation
- Roundtrip operations
- Schema parse operations (attribute/objectClass)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

from flext_ldif import FlextLdif, FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.servers.base import FlextLdifServersBase

from .test_assertions import TestAssertions

# Use protocols from src instead of defining locally
HasParseMethod = FlextLdifProtocols.Services.HasParseMethodProtocol
HasWriteMethod = FlextLdifProtocols.Services.HasWriteMethodProtocol
HasEntryWriteMethod = FlextLdifProtocols.Services.HasEntryWriteMethodProtocol


class TestOperations:
    """Reusable operation helpers for tests."""

    # Prevent pytest from collecting static methods as tests
    __test__ = False

    @staticmethod
    def parse_and_validate(
        parser: HasParseMethod | FlextLdif,
        ldif_content: str | Path,
        expected_count: int | None = None,
    ) -> list[FlextLdifModels.Entry]:
        """Parse LDIF and validate result.

        Args:
            parser: Parser instance (FlextLdif or quirk)
            ldif_content: LDIF content or file path
            expected_count: Optional expected entry count

        Returns:
            Parsed entries

        Raises:
            AssertionError: If parse fails or validation fails

        """
        if isinstance(ldif_content, Path):
            if isinstance(parser, FlextLdif):
                result = parser.parse(ldif_content)
            else:
                result = parser.parse(ldif_content)
        elif isinstance(parser, FlextLdif):
            result = parser.parse(ldif_content)
        else:
            result = parser.parse(ldif_content)

        # Use improved type alias for parse results
        return TestAssertions.assert_parse_success(
            result,
            expected_count,
        )

    @staticmethod
    def write_and_validate(
        writer: HasWriteMethod | FlextLdif,
        entries: list[FlextLdifModels.Entry] | FlextLdifModels.Entry,
        expected_content: str | None = None,
    ) -> str:
        """Write entries and validate result.

        Args:
            writer: Writer instance (FlextLdif or quirk)
            entries: Entry or list of entries to write
            expected_content: Optional expected content substring

        Returns:
            Written LDIF string

        Raises:
            AssertionError: If write fails or validation fails

        """
        if isinstance(entries, list):
            if isinstance(writer, FlextLdif):
                result = writer.write(entries)
            else:
                result = writer.write(entries)
        elif isinstance(writer, FlextLdif):
            result = writer.write([entries])
        else:
            result = writer.write([entries])

        return TestAssertions.assert_write_success(result, expected_content)

    @staticmethod
    def roundtrip_and_validate(
        api: FlextLdif,
        ldif_content: str | Path,
        tmp_path: Path,
        expected_count: int | None = None,
    ) -> tuple[list[FlextLdifModels.Entry], list[FlextLdifModels.Entry]]:
        """Perform roundtrip (parse -> write -> parse) and validate.

        Args:
            api: FlextLdif API instance
            ldif_content: Original LDIF content or file path
            tmp_path: Temporary directory for output file
            expected_count: Optional expected entry count

        Returns:
            Tuple of (original_entries, roundtripped_entries)

        Raises:
            AssertionError: If any step fails or validation fails

        """
        # Parse original
        original_entries = TestOperations.parse_and_validate(
            api,
            ldif_content,
            expected_count,
        )

        # Write to temporary file
        output_file = tmp_path / "roundtrip.ldif"
        write_result = api.write(original_entries, output_file)
        TestAssertions.assert_success(write_result, "Write should succeed")

        # Parse written file
        roundtripped_entries = TestOperations.parse_and_validate(
            api,
            output_file,
            expected_count,
        )

        # Validate roundtrip preserves structure
        TestAssertions.assert_roundtrip_preserves(
            original_entries,
            roundtripped_entries,
        )

        return (original_entries, roundtripped_entries)

    @staticmethod
    def parse_attribute_and_validate(
        schema_quirk: FlextLdifServersBase.Schema,
        attr_def: str,
        expected_oid: str | None = None,
        expected_name: str | None = None,
    ) -> FlextLdifModels.SchemaAttribute:
        """Parse attribute definition and validate result.

        Args:
            schema_quirk: Schema quirk instance
            attr_def: Attribute definition string
            expected_oid: Optional expected OID
            expected_name: Optional expected name

        Returns:
            Parsed SchemaAttribute

        Raises:
            AssertionError: If parse fails or validation fails

        """
        result = schema_quirk.parse_attribute(attr_def)
        attr = TestAssertions.assert_success(result, "Attribute parse should succeed")
        assert isinstance(attr, FlextLdifModels.SchemaAttribute), (
            "Parse should return SchemaAttribute"
        )
        TestAssertions.assert_schema_attribute_valid(attr, expected_oid, expected_name)
        return attr

    @staticmethod
    def parse_objectclass_and_validate(
        schema_quirk: FlextLdifServersBase.Schema,
        oc_def: str,
        expected_oid: str | None = None,
        expected_name: str | None = None,
    ) -> FlextLdifModels.SchemaObjectClass:
        """Parse objectClass definition and validate result.

        Args:
            schema_quirk: Schema quirk instance
            oc_def: ObjectClass definition string
            expected_oid: Optional expected OID
            expected_name: Optional expected name

        Returns:
            Parsed SchemaObjectClass

        Raises:
            AssertionError: If parse fails or validation fails

        """
        result = schema_quirk.parse_objectclass(oc_def)
        oc = TestAssertions.assert_success(result, "ObjectClass parse should succeed")
        assert isinstance(oc, FlextLdifModels.SchemaObjectClass), (
            "Parse should return SchemaObjectClass"
        )
        TestAssertions.assert_schema_objectclass_valid(oc, expected_oid, expected_name)
        return oc

    @staticmethod
    def write_entry_and_validate(
        entry_quirk: HasEntryWriteMethod,
        entry: FlextLdifModels.Entry,
        expected_content: str | None = None,
    ) -> str:
        """Write entry and validate result.

        Args:
            entry_quirk: Entry quirk instance
            entry: Entry to write
            expected_content: Optional expected content substring

        Returns:
            Written LDIF string

        Raises:
            AssertionError: If write fails or validation fails

        """
        # entry_quirk is an instance of FlextLdifServersBase.Entry (quirk class)
        # which has a write method that takes a list of entries
        result = entry_quirk.write([entry])
        return TestAssertions.assert_write_success(result, expected_content)


__all__ = ["TestOperations"]
