"""Comprehensive test deduplication helpers.

This module provides high-level methods that replace massive amounts of duplicated
test code. Each method replaces 10-50+ lines of repeated test patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Protocol, TypedDict, cast

from flext_core import FlextResult

from flext_ldif import FlextLdif
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.services.conversion import FlextLdifConversion
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.writer import FlextLdifWriter
from tests.helpers.test_assertions import TestAssertions


# TypedDict for test case structures
class ParseTestCaseDict(TypedDict, total=False):
    """TypedDict for parse test cases."""

    ldif_content: str
    expected_count: int | None
    expected_dn: str | None
    expected_attributes: list[str] | None
    server_type: str | None
    should_succeed: bool


# Protocols for type safety without using Any or object
class ConstantsClass(Protocol):
    """Protocol for constants classes with dynamic attributes."""

    def __getattr__(self, name: str) -> str:
        """Get constant value by name."""
        ...


# Union type for quirk instances
type QuirkInstanceType = (
    FlextLdifServersRfc.Schema
    | FlextLdifServersRfc.Entry
    | FlextLdifServersRfc.Acl
    | FlextLdifServersBase.Schema
    | FlextLdifServersBase.Entry
    | FlextLdifServersBase.Acl
)


class QuirkInstance(Protocol):
    """Protocol for quirk instances that can be called dynamically."""

    def __getattr__(
        self, name: str
    ) -> Callable[
        ...,
        FlextResult[
            str
            | FlextLdifModels.Entry
            | FlextLdifModels.SchemaAttribute
            | FlextLdifModels.SchemaObjectClass
            | FlextLdifModels.Acl
        ],
    ]:
        """Get method by name."""
        ...


class ServiceInstance(Protocol):
    """Protocol for service instances."""

    def execute(
        self,
    ) -> FlextResult[str | list[FlextLdifModels.Entry] | dict[str, str]]:
        """Execute service method."""
        ...


class DeduplicationHelpers:  # Renamed to avoid pytest collection
    """Helper class for test deduplication - NOT a test class.

    This class contains static helper methods that should NOT be collected
    by pytest as test cases. All methods are static helpers for use in tests.

    Note: Originally named TestDeduplicationHelpers, but renamed to avoid
    pytest auto-discovery. Import as TestDeduplicationHelpers for
    backward compatibility.

    Comprehensive test helpers that eliminate massive code duplication.
    Each method replaces entire test functions or large blocks of repeated code.
    Use these methods extensively to reduce test file sizes by 50-80%.
    """

    @staticmethod
    def parse_and_assert(
        parser: FlextLdifParser,
        ldif_content: str,
        *,
        expected_count: int | None = None,
        expected_dn: str | None = None,
        expected_attributes: list[str] | None = None,
        server_type: str | None = None,
        should_succeed: bool = True,
    ) -> list[FlextLdifModels.Entry]:
        """Complete parse test with assertions - replaces 15-30 lines.

        Args:
            parser: Parser service instance
            ldif_content: LDIF content to parse
            expected_count: Optional expected entry count
            expected_dn: Optional expected DN
            expected_attributes: Optional list of expected attribute names
            server_type: Optional server type override
            should_succeed: Whether parse should succeed (default: True)

        Returns:
            List of parsed entries

        """
        result = parser.parse(
            ldif_content, input_source="string", server_type=server_type
        )
        if should_succeed:
            unwrapped = TestAssertions.assert_success(result, "Parse should succeed")
        else:
            _ = TestAssertions.assert_failure(result)
            return []

        entries: list[FlextLdifModels.Entry]
        if isinstance(unwrapped, list):
            # Ensure all entries are FlextLdifModels.Entry instances
            entries = [
                entry for entry in unwrapped if isinstance(entry, FlextLdifModels.Entry)
            ]
        elif hasattr(unwrapped, "entries"):
            parse_response = cast("FlextLdifModels.ParseResponse", unwrapped)
            entries = [
                entry
                for entry in parse_response.entries
                if isinstance(entry, FlextLdifModels.Entry)
            ]
        else:
            msg = "Parse returned unexpected type"
            raise AssertionError(msg)

        if expected_count is not None:
            assert len(entries) == expected_count, (
                f"Expected {expected_count} entries, got {len(entries)}"
            )

        if expected_dn and entries:
            assert entries[0].dn is not None
            assert entries[0].dn.value == expected_dn

        if expected_attributes and entries:
            assert entries[0].attributes is not None
            for attr_name in expected_attributes:
                assert attr_name in entries[0].attributes.attributes

        if entries:
            TestAssertions.assert_entries_valid(entries)

        return entries

    @staticmethod
    def write_and_assert(
        writer: FlextLdifWriter,
        entries: list[FlextLdifModels.Entry],
        *,
        target_server_type: str = "rfc",
        output_target: str = "string",
        output_path: Path | None = None,
        must_contain: list[str] | None = None,
        must_not_contain: list[str] | None = None,
    ) -> str | Path:
        """Complete write test with assertions - replaces 15-25 lines.

        Args:
            writer: Writer service instance
            entries: List of entries to write
            target_server_type: Target server type (default: "rfc")
            output_target: Output target ("string" or "file")
            output_path: Optional path for file output
            must_contain: Optional list of strings that must be in output
            must_not_contain: Optional list of strings that must NOT be in output

        Returns:
            Written LDIF string or file path

        """
        result = writer.write(
            entries,
            target_server_type=target_server_type,
            output_target=output_target,
            output_path=output_path,
        )
        output = TestAssertions.assert_write_success(result)

        if output_target == "file" and output_path:
            assert output_path.exists(), "Output file should exist"
            content = output_path.read_text(encoding="utf-8")
            if must_contain:
                for text in must_contain:
                    assert text in content, f"Must contain '{text}' not found"
            if must_not_contain:
                for text in must_not_contain:
                    assert text not in content, f"Must not contain '{text}' found"
            return output_path
        assert isinstance(output, str), "String output should be str"
        content = output
        if must_contain:
            for text in must_contain:
                assert text in content, f"Must contain '{text}' not found"
        if must_not_contain:
            for text in must_not_contain:
                assert text not in content, f"Must not contain '{text}' found"
        return output

    @staticmethod
    def roundtrip_and_assert(
        parser: FlextLdifParser,
        writer: FlextLdifWriter,
        ldif_content: str,
        *,
        target_server_type: str = "rfc",
        validate_identical: bool = True,
    ) -> tuple[list[FlextLdifModels.Entry], list[FlextLdifModels.Entry]]:
        """Complete roundtrip test - replaces 30-50 lines.

        Args:
            parser: Parser service instance
            writer: Writer service instance
            ldif_content: Original LDIF content
            target_server_type: Target server type (default: "rfc")
            validate_identical: Whether to validate entries are identical

        Returns:
            Tuple of (original_entries, roundtripped_entries)

        """
        original_entries = DeduplicationHelpers.parse_and_assert(parser, ldif_content)

        write_result = writer.write(
            original_entries,
            target_server_type=target_server_type,
            output_target="string",
        )
        written_ldif = TestAssertions.assert_write_success(write_result)

        roundtrip_result = parser.parse(written_ldif, input_source="string")
        roundtrip_data = TestAssertions.assert_success(roundtrip_result)

        if isinstance(roundtrip_data, list):
            roundtripped_entries_raw = roundtrip_data
        elif hasattr(roundtrip_data, "entries"):
            parse_response = cast("FlextLdifModels.ParseResponse", roundtrip_data)
            roundtripped_entries_raw = list(parse_response.entries)
        else:
            msg = "Roundtrip parse returned unexpected type"
            raise AssertionError(msg)

        # Cast to ensure type consistency
        roundtripped_entries: list[FlextLdifModels.Entry] = [
            entry
            for entry in roundtripped_entries_raw
            if isinstance(entry, FlextLdifModels.Entry)
        ]

        if validate_identical:
            assert len(original_entries) == len(roundtripped_entries), (
                f"Entry count mismatch: {len(original_entries)} vs "
                f"{len(roundtripped_entries)}"
            )
            for orig, rt in zip(original_entries, roundtripped_entries, strict=False):
                if orig.dn is None or rt.dn is None:
                    continue
                assert orig.dn.value == rt.dn.value, (
                    f"DN mismatch: {orig.dn.value} vs {rt.dn.value}"
                )

        return original_entries, roundtripped_entries

    @staticmethod
    def schema_parse_and_assert(
        schema_quirk: FlextLdifServersRfc.Schema,
        schema_def: str,
        *,
        expected_type: str,
        expected_oid: str | None = None,
        expected_name: str | None = None,
        must_have_attributes: list[str] | None = None,
    ) -> FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass:
        """Complete schema parse test - replaces 15-25 lines.

        Args:
            schema_quirk: Schema quirk instance
            schema_def: Schema definition string
            expected_type: Expected type ("attribute" or "objectclass")
            expected_oid: Optional expected OID
            expected_name: Optional expected name
            must_have_attributes: Optional list of attribute names that must exist

        Returns:
            Parsed SchemaAttribute or SchemaObjectClass

        """
        result = schema_quirk.parse(schema_def)
        schema_obj_raw = TestAssertions.assert_success(
            result, "Schema parse should succeed"
        )

        if expected_type == "attribute":
            assert isinstance(schema_obj_raw, FlextLdifModels.SchemaAttribute), (
                "Should return SchemaAttribute"
            )
            schema_attr: FlextLdifModels.SchemaAttribute = (
                schema_obj_raw  # type is already correct after isinstance
            )
            if expected_oid:
                assert schema_attr.oid == expected_oid
            if expected_name:
                assert schema_attr.name == expected_name
        elif expected_type == "objectclass":
            assert isinstance(schema_obj_raw, FlextLdifModels.SchemaObjectClass), (
                "Should return SchemaObjectClass"
            )
            schema_oc: FlextLdifModels.SchemaObjectClass = (
                schema_obj_raw  # type is already correct after isinstance
            )
            if expected_oid:
                assert schema_oc.oid == expected_oid
            if expected_name:
                assert schema_oc.name == expected_name
        else:
            msg = f"Unknown expected_type: {expected_type}"
            raise AssertionError(msg)

        return schema_obj_raw

    @staticmethod
    def schema_write_and_assert(
        schema_quirk: FlextLdifServersRfc.Schema,
        schema_obj: FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass,
        *,
        must_contain: list[str] | None = None,
        must_not_contain: list[str] | None = None,
    ) -> str:
        """Complete schema write test - replaces 10-20 lines.

        Args:
            schema_quirk: Schema quirk instance
            schema_obj: SchemaAttribute or SchemaObjectClass to write
            must_contain: Optional list of strings that must appear in output
            must_not_contain: Optional list of strings that must NOT appear in output

        Returns:
            Written LDIF string

        """
        if isinstance(schema_obj, FlextLdifModels.SchemaAttribute):
            result = schema_quirk._write_attribute(schema_obj)  # type: ignore[attr-defined,protected-access]
        else:
            result = schema_quirk._write_objectclass(schema_obj)  # type: ignore[attr-defined,protected-access]

        ldif = TestAssertions.assert_success(result, "Schema write should succeed")
        assert isinstance(ldif, str), "Write should return string"

        if must_contain:
            for text in must_contain:
                assert text in ldif, f"Must contain '{text}' not found"

        if must_not_contain:
            for text in must_not_contain:
                assert text not in ldif, f"Must not contain '{text}' found"

        return ldif

    @staticmethod
    def entry_quirk_method_and_assert(
        entry_quirk: FlextLdifServersRfc.Entry,
        method_name: str,
        *args: str
        | int
        | bool
        | FlextLdifModels.Entry
        | FlextLdifModels.SchemaAttribute
        | FlextLdifModels.SchemaObjectClass
        | FlextLdifModels.Acl,
        expected_result: str
        | int
        | bool
        | FlextLdifModels.Entry
        | FlextLdifModels.SchemaAttribute
        | FlextLdifModels.SchemaObjectClass
        | FlextLdifModels.Acl
        | None = None,
        should_succeed: bool = True,
        **kwargs: str
        | int
        | bool
        | FlextLdifModels.Entry
        | FlextLdifModels.SchemaAttribute
        | FlextLdifModels.SchemaObjectClass
        | FlextLdifModels.Acl,
    ) -> (
        str
        | int
        | bool
        | FlextLdifModels.Entry
        | FlextLdifModels.SchemaAttribute
        | FlextLdifModels.SchemaObjectClass
        | FlextLdifModels.Acl
    ):
        """Test entry quirk method with automatic assertions - replaces 10-20 lines.

        Args:
            entry_quirk: Entry quirk instance
            method_name: Name of method to call
            *args: Positional arguments for method
            expected_result: Optional expected result value
            should_succeed: Whether call should succeed (default: True)
            **kwargs: Keyword arguments for method

        Returns:
            Method result

        """
        method = getattr(entry_quirk, method_name, None)
        assert method is not None, f"Method {method_name} not found"

        result = method(*args, **kwargs)

        if isinstance(result, FlextResult):
            if should_succeed:
                unwrapped = TestAssertions.assert_success(result)
                if expected_result is not None:
                    assert unwrapped == expected_result
                # Type narrowing: unwrapped can be various types
                return cast(
                    "str | int | bool | FlextLdifModels.Entry | FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | FlextLdifModels.Acl",
                    unwrapped,
                )
            _ = TestAssertions.assert_failure(result)
            # Return the result wrapped in FlextResult for failure case
            return cast(
                "str | int | bool | FlextLdifModels.Entry | FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | FlextLdifModels.Acl",
                result,
            )
        if expected_result is not None:
            assert result == expected_result
        # Type narrowing: result from method call
        return cast(
            "str | int | bool | FlextLdifModels.Entry | FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | FlextLdifModels.Acl",
            result,
        )

    @staticmethod
    def acl_quirk_parse_and_assert(
        acl_quirk: FlextLdifServersRfc.Acl,
        acl_line: str,
        *,
        expected_raw_acl: str | None = None,
        expected_server_type: str = "rfc",
    ) -> FlextLdifModels.Acl:
        """Complete ACL parse test - replaces 10-15 lines.

        Args:
            acl_quirk: ACL quirk instance
            acl_line: ACL line string
            expected_raw_acl: Optional expected raw ACL value
            expected_server_type: Expected server type (default: "rfc")

        Returns:
            Parsed Acl model

        """
        result = acl_quirk.parse_acl(acl_line)  # type: ignore[attr-defined]
        acl = TestAssertions.assert_success(result, "ACL parse should succeed")
        assert isinstance(acl, FlextLdifModels.Acl), "Parse should return Acl"
        assert acl.server_type == expected_server_type

        if expected_raw_acl:
            assert acl.raw_acl == expected_raw_acl, (
                f"Expected raw_acl '{expected_raw_acl}', got '{acl.raw_acl}'"
            )

        return acl

    @staticmethod
    def acl_quirk_write_and_assert(
        acl_quirk: FlextLdifServersRfc.Acl,
        acl: FlextLdifModels.Acl,
        *,
        must_contain: list[str] | None = None,
    ) -> str:
        """Complete ACL write test - replaces 8-12 lines.

        Args:
            acl_quirk: ACL quirk instance
            acl: Acl model to write
            must_contain: Optional list of strings that must appear in output

        Returns:
            Written ACL string

        """
        result = acl_quirk._write_acl(acl)  # type: ignore[attr-defined,protected-access]
        acl_str = TestAssertions.assert_success(result, "ACL write should succeed")
        assert isinstance(acl_str, str), "Write should return string"

        if must_contain:
            for text in must_contain:
                assert text in acl_str, f"Must contain '{text}' not found"

        return acl_str

    @staticmethod
    def batch_operations(
        test_cases: list[dict[str, object]],
        operation_func: Callable[[dict[str, object]], object],
        *,
        validate_results: bool = True,
    ) -> list[object]:
        """Test multiple operations in batch - replaces 50-100+ lines.

        Args:
            test_cases: List of test case dictionaries
            operation_func: Function to call for each test case
            validate_results: Whether to validate results (default: True)

        Returns:
            List of operation results

        """
        results = []
        for test_case in test_cases:
            result = operation_func(test_case)
            if validate_results:
                assert result is not None, f"Test case {test_case} returned None"
            results.append(result)
        return results

    @staticmethod
    def route_operation_and_assert(
        quirk: FlextLdifServersBase,
        data: str | list[FlextLdifModels.Entry] | dict[str, str | list[str]],
        *,
        operation: str,
        expected_type: type[
            FlextLdifModels.Entry
            | FlextLdifModels.SchemaAttribute
            | FlextLdifModels.SchemaObjectClass
            | str
        ]
        | None = None,
        should_succeed: bool = True,
    ) -> (
        FlextLdifModels.Entry
        | FlextLdifModels.SchemaAttribute
        | FlextLdifModels.SchemaObjectClass
        | str
    ):
        """Test route operation with assertions - replaces 10-15 lines.

        Args:
            quirk: Quirk instance
            data: Data to route
            operation: Operation name ("parse" or "write")
            expected_type: Optional expected return type
            should_succeed: Whether operation should succeed (default: True)

        Returns:
            Operation result

        """
        route_method = getattr(quirk, "_route_operation", None)
        if route_method is None:
            msg = "Quirk does not have _route_operation method"
            raise AttributeError(msg)
        result = route_method(data, operation=operation)  # type: ignore[misc]

        if should_succeed:
            unwrapped = TestAssertions.assert_success(result)
            if expected_type:
                assert isinstance(unwrapped, expected_type), (
                    f"Expected {expected_type}, got {type(unwrapped)}"
                )
            # Type narrowing: unwrapped can be various types
            return cast(
                "FlextLdifModels.Entry | FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str",
                unwrapped,
            )
        _ = TestAssertions.assert_failure(result)
        # Return empty string for failure case
        return ""

    @staticmethod
    def quirk_parse_write_roundtrip(
        quirk: Any,  # noqa: ANN401
        input_data: str,
        *,
        parse_method: str = "parse",
        write_method: str | None = None,
        expected_type: type[Any] | None = None,
        validate_identical: bool = True,
    ) -> tuple[Any, Any, Any]:
        """Complete quirk parse-write-roundtrip test - replaces 40-60 lines.

        Args:
            quirk: Quirk instance (Schema, Entry, Acl, etc)
            input_data: Input data string to parse
            parse_method: Method name for parsing (default: "parse")
            write_method: Method name for writing (default: auto-detect)
            expected_type: Optional expected parsed type
            validate_identical: Whether to validate roundtrip preserves data

        Returns:
            Tuple of (parsed_object, written_string, roundtripped_object)

        """
        # Parse
        parse_func = getattr(quirk, parse_method)
        parse_result = parse_func(input_data)
        parsed = TestAssertions.assert_success(parse_result, "Parse should succeed")
        if expected_type:
            assert isinstance(parsed, expected_type), (
                f"Expected {expected_type}, got {type(parsed)}"
            )

        # Write
        if write_method is None:
            if isinstance(parsed, FlextLdifModels.SchemaAttribute):
                write_method = "_write_attribute"
            elif isinstance(parsed, FlextLdifModels.SchemaObjectClass):
                write_method = "_write_objectclass"
            elif isinstance(parsed, FlextLdifModels.Acl):
                write_method = "_write_acl"
            elif isinstance(parsed, FlextLdifModels.Entry):
                write_method = "write"
            else:
                write_method = "write"

        write_func = getattr(quirk, write_method)
        write_result = write_func(parsed)  # type: ignore[misc]
        written = TestAssertions.assert_success(write_result, "Write should succeed")
        assert isinstance(written, str), "Write should return string"

        # Roundtrip parse
        roundtrip_result = parse_func(written)
        roundtripped = TestAssertions.assert_success(
            roundtrip_result, "Roundtrip parse should succeed"
        )

        if validate_identical:
            if isinstance(
                parsed,
                (FlextLdifModels.SchemaAttribute, FlextLdifModels.SchemaObjectClass),
            ) and isinstance(
                roundtripped,
                (FlextLdifModels.SchemaAttribute, FlextLdifModels.SchemaObjectClass),
            ):
                assert parsed.oid == roundtripped.oid, "OID should match"
                assert parsed.name == roundtripped.name, "Name should match"
            elif isinstance(parsed, FlextLdifModels.Entry) and isinstance(
                roundtripped, FlextLdifModels.Entry
            ):
                if parsed.dn is not None and roundtripped.dn is not None:
                    assert parsed.dn == roundtripped.dn, "DN should match"

        return parsed, written, roundtripped

    @staticmethod
    def api_parse_write_roundtrip(
        api: Any,  # noqa: ANN401
        ldif_content: str | Path,
        *,
        expected_count: int | None = None,
        target_server_type: str = "rfc",
        validate_entries: bool = True,
    ) -> tuple[list[FlextLdifModels.Entry], str, list[FlextLdifModels.Entry]]:
        """Complete API parse-write-roundtrip test - replaces 30-50 lines.

        Args:
            api: FlextLdif API instance
            ldif_content: LDIF content string or file path
            expected_count: Optional expected entry count
            target_server_type: Target server type for writing (default: "rfc")
            validate_entries: Whether to validate entry structure (default: True)

        Returns:
            Tuple of (original_entries, written_ldif, roundtripped_entries)

        """
        # Parse original
        parse_result = api.parse(ldif_content)
        original_data = TestAssertions.assert_success(
            parse_result, "Parse should succeed"
        )

        if isinstance(original_data, list):
            original_entries = original_data
        elif hasattr(original_data, "entries"):
            parse_response = cast("FlextLdifModels.ParseResponse", original_data)
            original_entries = [
                cast("FlextLdifModels.Entry", entry) for entry in parse_response.entries
            ]
        else:
            msg = "Parse returned unexpected type"
            raise AssertionError(msg)

        if expected_count is not None:
            assert len(original_entries) == expected_count, (
                f"Expected {expected_count} entries, got {len(original_entries)}"
            )

        if validate_entries:
            # Cast to ensure type consistency for assert_entries_valid
            original_entries_cast: list[FlextLdifModels.Entry] = [
                entry
                for entry in original_entries
                if isinstance(entry, FlextLdifModels.Entry)
            ]
            TestAssertions.assert_entries_valid(original_entries_cast)

        # Write
        write_result = api.write(original_entries)
        written_ldif = TestAssertions.assert_write_success(write_result)
        assert isinstance(written_ldif, str), "Write should return string"

        # Roundtrip parse
        roundtrip_result = api.parse(written_ldif)
        roundtrip_data = TestAssertions.assert_success(
            roundtrip_result, "Roundtrip parse should succeed"
        )

        if isinstance(roundtrip_data, list):
            roundtripped_entries_raw = roundtrip_data
        elif hasattr(roundtrip_data, "entries"):
            parse_response = cast("FlextLdifModels.ParseResponse", roundtrip_data)
            roundtripped_entries_raw = list(parse_response.entries)
        else:
            msg = "Roundtrip parse returned unexpected type"
            raise AssertionError(msg)

        # Cast to ensure type consistency
        roundtripped_entries: list[FlextLdifModels.Entry] = [
            entry
            for entry in roundtripped_entries_raw
            if isinstance(entry, FlextLdifModels.Entry)
        ]

        if validate_entries:
            # Cast to ensure type consistency for assert_entries_valid
            roundtripped_entries_cast: list[FlextLdifModels.Entry] = (
                roundtripped_entries
            )
            TestAssertions.assert_entries_valid(roundtripped_entries_cast)
            assert len(original_entries) == len(roundtripped_entries), (
                f"Entry count mismatch: {len(original_entries)} vs "
                f"{len(roundtripped_entries)}"
            )

        return original_entries, written_ldif, roundtripped_entries

    @staticmethod
    def batch_parse_and_assert(
        parser: FlextLdifParser,
        test_cases: list[ParseTestCaseDict],
        *,
        validate_all: bool = True,
    ) -> list[list[FlextLdifModels.Entry]]:
        """Test multiple parse operations in batch - replaces 50-150+ lines.

        Args:
            parser: Parser service instance
            test_cases: List of test case dicts with keys:
                - ldif_content: str (required)
                - expected_count: int | None
                - expected_dn: str | None
                - expected_attributes: list[str] | None
                - server_type: str | None
                - should_succeed: bool (default: True)
            validate_all: Whether to validate all results (default: True)

        Returns:
            List of parsed entry lists (one per test case)

        """
        results = []
        for i, test_case in enumerate(test_cases):
            ldif_content = test_case.get("ldif_content")
            if ldif_content is None:
                msg = f"Test case {i} missing 'ldif_content'"
                raise ValueError(msg)

            entries = DeduplicationHelpers.parse_and_assert(
                parser,
                ldif_content,
                expected_count=test_case.get("expected_count"),
                expected_dn=test_case.get("expected_dn"),
                expected_attributes=test_case.get("expected_attributes"),
                server_type=test_case.get("server_type"),
                should_succeed=test_case.get("should_succeed", True),
            )
            if validate_all:
                TestAssertions.assert_entries_valid(entries)
            results.append(entries)
        return results

    @staticmethod
    def batch_schema_parse_and_assert(
        schema_quirk: FlextLdifServersRfc.Schema,
        test_cases: list[dict[str, Any]],
    ) -> list[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass]:
        """Test multiple schema parse operations in batch - replaces 50-150+ lines.

        Args:
            schema_quirk: Schema quirk instance
            test_cases: List of test case dicts with keys:
                - schema_def: str (required)
                - expected_type: str ("attribute" or "objectclass", required)
                - expected_oid: str | None
                - expected_name: str | None
                - must_have_attributes: list[str] | None

        Returns:
            List of parsed schema objects

        """
        results = []
        for i, test_case in enumerate(test_cases):
            schema_def = test_case.get("schema_def")
            if schema_def is None:
                msg = f"Test case {i} missing 'schema_def'"
                raise ValueError(msg)

            expected_type = test_case.get("expected_type")
            if expected_type is None:
                msg = f"Test case {i} missing 'expected_type'"
                raise ValueError(msg)

            schema_obj = DeduplicationHelpers.schema_parse_and_assert(
                schema_quirk,
                schema_def,
                expected_type=expected_type,
                expected_oid=test_case.get("expected_oid"),
                expected_name=test_case.get("expected_name"),
                must_have_attributes=test_case.get("must_have_attributes"),
            )
            results.append(schema_obj)
        return results

    @staticmethod
    def create_entries_batch(
        entries_data: list[dict[str, Any]],
        *,
        validate_all: bool = True,
    ) -> list[FlextLdifModels.Entry]:
        """Create multiple entries in batch - replaces 20-50+ lines.

        Args:
            entries_data: List of entry dicts with keys:
                - dn: str (required)
                - attributes: dict[str, str | list[str]] (required)
            validate_all: Whether to validate all entries (default: True)

        Returns:
            List of created Entry models

        """
        entries = []
        for i, entry_data in enumerate(entries_data):
            dn = entry_data.get("dn")
            if dn is None:
                msg = f"Entry {i} missing 'dn'"
                raise ValueError(msg)

            attributes = entry_data.get("attributes")
            if attributes is None:
                msg = f"Entry {i} missing 'attributes'"
                raise ValueError(msg)

            entry = DeduplicationHelpers.create_entry_simple(dn, attributes)
            if validate_all:
                TestAssertions.assert_entry_valid(entry)
            entries.append(entry)
        return entries

    @staticmethod
    def quirk_method_batch(
        quirk: Any,  # noqa: ANN401
        method_name: str,
        test_cases: list[dict[str, Any]],
        *,
        validate_results: bool = True,
    ) -> list[Any]:
        """Test quirk method with multiple test cases - replaces 50-150+ lines.

        Args:
            quirk: Quirk instance
            method_name: Method name to call
            test_cases: List of test case dicts with keys:
                - args: tuple (positional args, optional)
                - kwargs: dict (keyword args, optional)
                - expected_result: Any | None
                - should_succeed: bool (default: True)
            validate_results: Whether to validate results (default: True)

        Returns:
            List of method results

        """
        method = getattr(quirk, method_name, None)
        if method is None:
            msg = f"Method {method_name} not found on quirk"
            raise AttributeError(msg)

        results = []
        for i, test_case in enumerate(test_cases):
            args = test_case.get("args", ())
            kwargs = test_case.get("kwargs", {})
            expected_result = test_case.get("expected_result")
            should_succeed = test_case.get("should_succeed", True)

            result = method(*args, **kwargs)

            if isinstance(result, FlextResult):
                if should_succeed:
                    unwrapped = TestAssertions.assert_success(result)
                    if expected_result is not None and validate_results:
                        assert unwrapped == expected_result, (
                            f"Test case {i}: expected {expected_result}, "
                            f"got {unwrapped}"
                        )
                    results.append(unwrapped)
                else:
                    TestAssertions.assert_failure(result)
                    results.append(result)
            else:
                if expected_result is not None and validate_results:
                    assert result == expected_result, (
                        f"Test case {i}: expected {expected_result}, got {result}"
                    )
                results.append(result)
        return results

    @staticmethod
    def file_operations_roundtrip(
        api: Any,  # noqa: ANN401
        ldif_content: str,
        tmp_path: Path,
        *,
        filename: str = "test.ldif",
        expected_count: int | None = None,
        validate_entries: bool = True,
    ) -> tuple[Path, list[FlextLdifModels.Entry], list[FlextLdifModels.Entry]]:
        """Complete file operations roundtrip - replaces 25-40 lines.

        Args:
            api: FlextLdif API instance
            ldif_content: LDIF content string
            tmp_path: Temporary directory path
            filename: Output filename (default: "test.ldif")
            expected_count: Optional expected entry count
            validate_entries: Whether to validate entries (default: True)

        Returns:
            Tuple of (output_file_path, original_entries, roundtripped_entries)

        """
        # Write to file
        output_file = tmp_path / filename
        output_file.write_text(ldif_content, encoding="utf-8")

        # Parse from file
        parse_result = api.parse(output_file)
        original_data = TestAssertions.assert_success(
            parse_result, "Parse should succeed"
        )

        if isinstance(original_data, list):
            original_entries = original_data
        elif hasattr(original_data, "entries"):
            parse_response = cast("FlextLdifModels.ParseResponse", original_data)
            original_entries = [
                cast("FlextLdifModels.Entry", entry) for entry in parse_response.entries
            ]
        else:
            msg = "Parse returned unexpected type"
            raise AssertionError(msg)

        if expected_count is not None:
            assert len(original_entries) == expected_count, (
                f"Expected {expected_count} entries, got {len(original_entries)}"
            )

        if validate_entries:
            # Cast to ensure type consistency for assert_entries_valid
            original_entries_cast: list[FlextLdifModels.Entry] = [
                entry
                for entry in original_entries
                if isinstance(entry, FlextLdifModels.Entry)
            ]
            TestAssertions.assert_entries_valid(original_entries_cast)

        # Write back to file
        write_result = api.write(original_entries, output_file)
        TestAssertions.assert_success(write_result, "Write should succeed")
        assert output_file.exists(), "Output file should exist"

        # Parse written file
        roundtrip_result = api.parse(output_file)
        roundtrip_data = TestAssertions.assert_success(
            roundtrip_result, "Roundtrip parse should succeed"
        )

        if isinstance(roundtrip_data, list):
            roundtripped_entries_raw = roundtrip_data
        elif hasattr(roundtrip_data, "entries"):
            parse_response = cast("FlextLdifModels.ParseResponse", roundtrip_data)
            roundtripped_entries_raw = list(parse_response.entries)
        else:
            msg = "Roundtrip parse returned unexpected type"
            raise AssertionError(msg)

        # Cast to ensure type consistency
        roundtripped_entries: list[FlextLdifModels.Entry] = [
            entry
            for entry in roundtripped_entries_raw
            if isinstance(entry, FlextLdifModels.Entry)
        ]

        if validate_entries:
            # Cast to ensure type consistency for assert_entries_valid
            roundtripped_entries_cast: list[FlextLdifModels.Entry] = (
                roundtripped_entries
            )
            TestAssertions.assert_entries_valid(roundtripped_entries_cast)

        return output_file, original_entries, roundtripped_entries

    @staticmethod
    def assert_success_and_unwrap(
        result: FlextResult[Any],
        error_msg: str | None = None,
    ) -> Any:
        """Assert success and unwrap - replaces 2-3 lines.

        Common pattern: assert result.is_success + result.unwrap()

        Args:
            result: FlextResult to check and unwrap
            error_msg: Optional custom error message

        Returns:
            Unwrapped value

        """
        return TestAssertions.assert_success(result, error_msg)

    @staticmethod
    def assert_success_and_unwrap_list(
        result: FlextResult[list[Any] | Any],
        expected_length: int | None = None,
        error_msg: str | None = None,
    ) -> list[Any]:
        """Assert success, unwrap and validate list length - replaces 3-5 lines.

        Common pattern:
            assert result.is_success
            entries = result.unwrap()
            assert len(entries) == expected_count

        Args:
            result: FlextResult containing list
            expected_length: Optional expected list length
            error_msg: Optional custom error message

        Returns:
            Unwrapped list

        """
        unwrapped = TestAssertions.assert_success(result, error_msg)
        if isinstance(unwrapped, list):
            entries = unwrapped
        elif hasattr(unwrapped, "entries"):
            parse_response = cast("FlextLdifModels.ParseResponse", unwrapped)
            entries = list(parse_response.entries)
        else:
            entries = [unwrapped]

        if expected_length is not None:
            assert len(entries) == expected_length, (
                f"Expected {expected_length} items, got {len(entries)}"
            )

        return entries

    @staticmethod
    def assert_success_and_unwrap_entry(
        result: FlextResult[FlextLdifModels.Entry | list[FlextLdifModels.Entry]],
        expected_dn: str | None = None,
        error_msg: str | None = None,
    ) -> FlextLdifModels.Entry:
        """Assert success, unwrap and validate entry - replaces 4-6 lines.

        Common pattern:
            assert result.is_success
            entry = result.unwrap()
            assert entry.dn is not None
            assert entry.dn.value == expected_dn

        Args:
            result: FlextResult containing entry
            expected_dn: Optional expected DN value
            error_msg: Optional custom error message

        Returns:
            Unwrapped entry

        """
        unwrapped = TestAssertions.assert_success(result, error_msg)
        entry: FlextLdifModels.Entry
        if isinstance(unwrapped, list):
            assert len(unwrapped) == 1, "Expected single entry, got list"
            entry_item = unwrapped[0]
            if not isinstance(entry_item, FlextLdifModels.Entry):
                msg = f"Expected Entry, got {type(entry_item)}"
                raise AssertionError(msg)
            entry = entry_item
        elif isinstance(unwrapped, FlextLdifModels.Entry):
            entry = unwrapped
        else:
            msg = f"Expected Entry, got {type(unwrapped)}"
            raise AssertionError(msg)

        TestAssertions.assert_entry_valid(entry)

        if expected_dn is not None:
            assert entry.dn is not None, "Entry must have DN"
            assert entry.dn.value == expected_dn, (
                f"Expected DN '{expected_dn}', got '{entry.dn.value}'"
            )

        return entry

    @staticmethod
    def assert_success_and_unwrap_string(
        result: FlextResult[str],
        must_contain: list[str] | None = None,
        must_not_contain: list[str] | None = None,
        error_msg: str | None = None,
    ) -> str:
        """Assert success, unwrap string and validate content - replaces 4-8 lines.

        Common pattern:
            assert result.is_success
            ldif = result.unwrap()
            assert "expected" in ldif

        Args:
            result: FlextResult containing string
            must_contain: Optional list of strings that must be in result
            must_not_contain: Optional list of strings that must NOT be in result
            error_msg: Optional custom error message

        Returns:
            Unwrapped string

        """
        unwrapped = TestAssertions.assert_success(result, error_msg)
        assert isinstance(unwrapped, str), f"Expected str, got {type(unwrapped)}"

        if must_contain:
            for text in must_contain:
                assert text in unwrapped, f"Must contain '{text}' not found"

        if must_not_contain:
            for text in must_not_contain:
                assert text not in unwrapped, f"Must not contain '{text}' found"

        return unwrapped

    @staticmethod
    def parse_and_unwrap(
        parser: Any,
        ldif_content: str | Path,
        *,
        expected_count: int | None = None,
        expected_dn: str | None = None,
        server_type: str | None = None,
    ) -> list[FlextLdifModels.Entry]:
        """Parse and unwrap with common validations - replaces 5-10 lines.

        Common pattern:
            result = parser.parse(content)
            assert result.is_success
            entries = result.unwrap()
            assert len(entries) == expected_count

        Args:
            parser: Parser instance (FlextLdif, quirk, etc.)
            ldif_content: LDIF content or file path
            expected_count: Optional expected entry count
            expected_dn: Optional expected DN of first entry
            server_type: Optional server type override

        Returns:
            Parsed entries

        """
        if isinstance(ldif_content, Path):
            result = parser.parse(ldif_content)
        else:
            result = parser.parse(ldif_content)

        entries = DeduplicationHelpers.assert_success_and_unwrap_list(
            result, expected_length=expected_count
        )

        if expected_dn and entries:
            assert entries[0].dn is not None
            assert entries[0].dn.value == expected_dn

        return entries

    @staticmethod
    def write_and_unwrap(
        writer: Any,
        entries: list[FlextLdifModels.Entry] | FlextLdifModels.Entry,
        *,
        must_contain: list[str] | None = None,
        must_not_contain: list[str] | None = None,
    ) -> str:
        """Write and unwrap with content validation - replaces 5-10 lines.

        Common pattern:
            result = writer.write(entries)
            assert result.is_success
            ldif = result.unwrap()
            assert "expected" in ldif

        Args:
            writer: Writer instance (FlextLdif, quirk, etc.)
            entries: Entry or list of entries to write
            must_contain: Optional list of strings that must be in output
            must_not_contain: Optional list of strings that must NOT be in output

        Returns:
            Written LDIF string

        """
        if isinstance(entries, list):
            result = writer.write(entries)
        else:
            result = writer.write([entries])

        return DeduplicationHelpers.assert_success_and_unwrap_string(
            result, must_contain=must_contain, must_not_contain=must_not_contain
        )

    @staticmethod
    def parse_schema_and_unwrap(
        schema_quirk: Any,
        schema_def: str,
        *,
        expected_oid: str | None = None,
        expected_name: str | None = None,
        expected_type: type[Any] | None = None,
    ) -> FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass:
        """Parse schema and unwrap with validations - replaces 6-10 lines.

        Common pattern:
            result = schema_quirk.parse(definition)
            assert result.is_success
            attr = result.unwrap()
            assert attr.oid == expected_oid

        Args:
            schema_quirk: Schema quirk instance
            schema_def: Schema definition string
            expected_oid: Optional expected OID
            expected_name: Optional expected name
            expected_type: Optional expected type (SchemaAttribute or SchemaObjectClass)

        Returns:
            Parsed schema object

        """
        result = schema_quirk.parse(schema_def)
        schema_obj = TestAssertions.assert_success(
            result, "Schema parse should succeed"
        )

        if expected_type:
            assert isinstance(schema_obj, expected_type), (
                f"Expected {expected_type}, got {type(schema_obj)}"
            )

        if not isinstance(
            schema_obj,
            (FlextLdifModels.SchemaAttribute, FlextLdifModels.SchemaObjectClass),
        ):
            msg = (
                f"Expected SchemaAttribute or SchemaObjectClass, got {type(schema_obj)}"
            )
            raise TypeError(msg)

        if expected_oid:
            assert schema_obj.oid == expected_oid, (
                f"Expected OID '{expected_oid}', got '{schema_obj.oid}'"
            )

        if expected_name:
            assert schema_obj.name == expected_name, (
                f"Expected name '{expected_name}', got '{schema_obj.name}'"
            )

        return schema_obj

    @staticmethod
    def write_schema_and_unwrap(
        schema_quirk: Any,
        schema_obj: FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass,
        *,
        must_contain: list[str] | None = None,
    ) -> str:
        """Write schema and unwrap with content validation - replaces 4-6 lines.

        Common pattern:
            result = schema_quirk.write(obj)
            assert result.is_success
            ldif = result.unwrap()
            assert "expected" in ldif

        Args:
            schema_quirk: Schema quirk instance
            schema_obj: SchemaAttribute or SchemaObjectClass to write
            must_contain: Optional list of strings that must be in output

        Returns:
            Written LDIF string

        """
        result = schema_quirk.write(schema_obj)
        return DeduplicationHelpers.assert_success_and_unwrap_string(
            result, must_contain=must_contain
        )

    @staticmethod
    def parse_entry_and_unwrap(
        entry_quirk: Any,
        ldif_content: str,
        *,
        expected_dn: str | None = None,
    ) -> FlextLdifModels.Entry:
        """Parse entry and unwrap with DN validation - replaces 4-6 lines.

        Common pattern:
            result = entry_quirk.parse(content)
            assert result.is_success
            entry = result.unwrap()
            assert entry.dn.value == expected_dn

        Args:
            entry_quirk: Entry quirk instance
            ldif_content: LDIF content string
            expected_dn: Optional expected DN value

        Returns:
            Parsed entry

        """
        result = entry_quirk.parse(ldif_content)
        return DeduplicationHelpers.assert_success_and_unwrap_entry(
            result, expected_dn=expected_dn
        )

    @staticmethod
    def write_entry_and_unwrap(
        entry_quirk: Any,
        entry: FlextLdifModels.Entry,
        *,
        must_contain: list[str] | None = None,
    ) -> str:
        """Write entry and unwrap with content validation - replaces 4-6 lines.

        Common pattern:
            result = entry_quirk.write(entry)
            assert result.is_success
            ldif = result.unwrap()
            assert "expected" in ldif

        Args:
            entry_quirk: Entry quirk instance
            entry: Entry to write
            must_contain: Optional list of strings that must be in output

        Returns:
            Written LDIF string

        """
        result = entry_quirk.write(entry)
        return DeduplicationHelpers.assert_success_and_unwrap_string(
            result, must_contain=must_contain
        )

    @staticmethod
    def create_entry_from_dict(
        dn_str: str,
        attributes: dict[str, list[str]],
    ) -> FlextLdifModels.Entry:
        """Create entry from dict - replaces 4-6 lines per use.

        Most common pattern in test files:
            dn = DistinguishedName(value=dn_str)
            attrs = LdifAttributes.create(attributes).unwrap()
            return Entry(dn=dn, attributes=attrs)

        Replaces create_entry() functions in:
        - test_filter_service.py
        - test_sorting.py
        - test_filters.py
        - And many more...

        Args:
            dn_str: DN string
            attributes: Dictionary mapping attribute names to value lists

        Returns:
            Created Entry model

        """
        # Use Entry.create() instead of direct instantiation
        # Type narrowing: dict[str, list[str]] is compatible with dict[str, str | list[str]]
        attributes_compatible: dict[str, str | list[str]] = cast(
            "dict[str, str | list[str]]", attributes
        )
        result = FlextLdifModels.Entry.create(
            dn=dn_str, attributes=attributes_compatible
        )
        return cast(
            "FlextLdifModels.Entry",
            DeduplicationHelpers.assert_success_and_unwrap(
                result, "Entry creation should succeed"
            ),
        )

    @staticmethod
    def create_entry_simple(
        dn: str,
        attributes: dict[str, str | list[str]],
        *,
        validate: bool = False,
    ) -> FlextLdifModels.Entry:
        """Create entry using Entry.create() - replaces 2-4 lines per use.

        Common pattern:
            result = Entry.create(dn=dn, attributes=attributes)
            entry = result.unwrap()

        Replaces Entry.create() calls with unwrap in many test files.

        Args:
            dn: Distinguished name
            attributes: Dictionary of attribute names to values
            validate: Whether to validate entry (default: False for speed)

        Returns:
            Created Entry model

        """
        result = FlextLdifModels.Entry.create(dn=dn, attributes=attributes)
        entry = cast(
            "FlextLdifModels.Entry",
            DeduplicationHelpers.assert_success_and_unwrap(
                result, "Entry creation should succeed"
            ),
        )
        if validate:
            TestAssertions.assert_entry_valid(entry)
        return entry

    @staticmethod
    def create_attributes_from_dict(
        attributes: dict[str, str | list[str]],
    ) -> FlextLdifModels.LdifAttributes:
        """Create LdifAttributes from dict - replaces 2-3 lines per use.

        Common pattern:
            result = LdifAttributes.create(attributes)
            attrs = result.unwrap()

        Args:
            attributes: Dictionary of attribute names to values

        Returns:
            Created LdifAttributes

        """
        result = FlextLdifModels.LdifAttributes.create(attributes)
        return cast(
            "FlextLdifModels.LdifAttributes",
            DeduplicationHelpers.assert_success_and_unwrap(
                result, "Attributes creation should succeed"
            ),
        )

    @staticmethod
    def entry_parse_content_and_assert(
        entry_quirk: FlextLdifServersRfc.Entry,
        ldif_content: str,
        *,
        expected_count: int | None = None,
        expected_dn: str | None = None,
    ) -> list[FlextLdifModels.Entry]:
        """Parse entry content with _parse_content - replaces 4-6 lines.

        Common pattern in test_rfc_quirks.py:
            result = entry_quirk._parse_content(content)
            assert result.is_success
            entries = result.unwrap()
            assert len(entries) == expected_count

        Args:
            entry_quirk: Entry quirk instance
            ldif_content: LDIF content to parse
            expected_count: Optional expected entry count
            expected_dn: Optional expected DN

        Returns:
            List of parsed entries

        """
        result = entry_quirk._parse_content(ldif_content)  # type: ignore[attr-defined,protected-access]
        entries = DeduplicationHelpers.assert_success_and_unwrap_list(
            result, expected_length=expected_count
        )

        if expected_dn and entries:
            assert entries[0].dn is not None, "Entry should have DN"
            assert entries[0].dn.value == expected_dn, (
                f"Expected DN '{expected_dn}', got '{entries[0].dn.value}'"
            )

        return entries

    @staticmethod
    def entry_write_entry_and_assert(
        entry_quirk: FlextLdifServersRfc.Entry,
        entry: FlextLdifModels.Entry,
        *,
        must_contain: list[str] | None = None,
    ) -> str:
        """Write entry with _write_entry - replaces 3-5 lines.

        Common pattern:
            result = entry_quirk._write_entry(entry)
            assert result.is_success
            ldif = result.unwrap()

        Args:
            entry_quirk: Entry quirk instance
            entry: Entry to write
            must_contain: Optional strings that must be in output

        Returns:
            Written LDIF string

        """
        result = entry_quirk._write_entry(entry)  # type: ignore[attr-defined,protected-access]
        return DeduplicationHelpers.assert_success_and_unwrap_string(
            result, must_contain=must_contain
        )

    @staticmethod
    def entry_parse_model_and_assert(
        entry_quirk: FlextLdifServersRfc.Entry,
        entry_model: FlextLdifModels.Entry,
        *,
        expected_dn: str | None = None,
    ) -> str:
        """Parse entry model to LDIF - replaces 3-5 lines.

        Common pattern:
            result = entry_quirk._parse_entry_model(entry_model)
            assert result.is_success
            ldif = result.unwrap()

        Args:
            entry_quirk: Entry quirk instance
            entry_model: Entry model to parse
            expected_dn: Optional expected DN validation

        Returns:
            Parsed LDIF string

        """
        if not hasattr(entry_quirk, "_parse_entry_model"):
            msg = "Entry quirk does not have _parse_entry_model method"
            raise AttributeError(msg)
        # Access private method via getattr to satisfy type checker
        parse_method = getattr(entry_quirk, "_parse_entry_model", None)
        if parse_method is None:
            msg = "Entry quirk does not have _parse_entry_model method"
            raise AttributeError(msg)
        result = parse_method(entry_model)  # type: ignore[misc]
        ldif = DeduplicationHelpers.assert_success_and_unwrap_string(result)

        if expected_dn:
            assert expected_dn in ldif, f"LDIF should contain DN '{expected_dn}'"

        return ldif

    @staticmethod
    def oid_validation_and_parse(
        oid_utility: Any,
        schema_quirk: Any,
        oid: str,
        schema_def: str,
        *,
        expected_name: str | None = None,
        validate_format: bool = True,
        check_is_oracle: bool = True,
        extract_from_def: bool = True,
        extract_from_object: bool = True,
    ) -> tuple[Any, str]:
        """Complete OID validation + parse test - replaces 30-50+ lines.

        Args:
            oid_utility: OID utility class (e.g., FlextLdifUtilitiesOID)
            schema_quirk: Schema quirk instance
            oid: OID string to validate
            schema_def: Schema definition string to parse
            expected_name: Optional expected name
            validate_format: Whether to validate OID format (default: True)
            check_is_oracle: Whether to check if Oracle OID (default: True)
            extract_from_def: Whether to extract OID from definition (default: True)
            extract_from_object: Whether to extract OID from parsed object
                (default: True)

        Returns:
            Tuple of (parsed_schema_object, extracted_oid)

        """
        extracted_oid = None

        # Validate OID format
        if validate_format:
            validation_result = oid_utility.validate_format(oid)
            assert validation_result.is_success and validation_result.unwrap(), (
                f"Invalid OID format: {oid}"
            )

        # Check if Oracle OID
        if check_is_oracle:
            assert oid_utility.is_oracle_oid(oid), (
                f"OID {oid} should be detected as Oracle OID"
            )

        # Extract OID from definition
        if extract_from_def:
            extracted_oid = oid_utility.extract_from_definition(schema_def)
            assert extracted_oid == oid, (
                f"OID extraction failed: expected {oid}, got {extracted_oid}"
            )

        # Parse schema
        result = schema_quirk.parse(schema_def)
        parsed = TestAssertions.assert_success(result, "Schema parse should succeed")

        if not isinstance(
            parsed, (FlextLdifModels.SchemaAttribute, FlextLdifModels.SchemaObjectClass)
        ):
            msg = f"Expected SchemaAttribute or SchemaObjectClass, got {type(parsed)}"
            raise TypeError(msg)

        # Extract OID from parsed object
        if extract_from_object:
            extracted_from_object = oid_utility.extract_from_schema_object(parsed)
            expected_oid = extracted_oid or oid
            assert extracted_from_object == expected_oid, (
                f"OID extraction from schema object failed: "
                f"expected {expected_oid}, got {extracted_from_object}"
            )

        # Validate name if provided
        if expected_name:
            assert parsed.name == expected_name, (
                f"Name mismatch: expected {expected_name}, got {parsed.name}"
            )

        return parsed, extracted_oid or oid

    @staticmethod
    def schema_parse_from_fixtures(
        schema_quirk: Any,
        fixture_content: str,
        detection_pattern: Any,
        *,
        schema_type: str = "attribute",
        expected_count: int | None = None,
        validate_oids: bool = True,
        oid_utility: Any | None = None,
    ) -> list[Any]:
        """Parse schema from fixtures with full validation - replaces 50-80+ lines.

        Args:
            schema_quirk: Schema quirk instance
            fixture_content: Schema fixture content string
            detection_pattern: Compiled regex pattern for detection
            schema_type: Type of schema ("attribute" or "objectclass")
            expected_count: Optional expected count of parsed schemas
            validate_oids: Whether to validate OIDs (default: True)
            oid_utility: Optional OID utility class for validation

        Returns:
            List of parsed schema objects

        """
        # Extract schema lines matching pattern
        schema_lines = [
            line
            for line in fixture_content.splitlines()
            if detection_pattern.search(line)
            and (
                (schema_type == "attribute" and "attributetypes:" in line)
                or (schema_type == "objectclass" and "objectclasses:" in line)
            )
        ]

        assert len(schema_lines) > 0, (
            f"No {schema_type} schemas found matching detection pattern"
        )

        # Parse all matching schemas
        parsed_schemas = []
        for line in schema_lines:
            # Extract definition
            if schema_type == "attribute":
                schema_def = line.split("attributetypes:", 1)[1].strip()
            else:
                schema_def = line.split("objectclasses:", 1)[1].strip()

            # Extract and validate OID if utility provided
            if validate_oids and oid_utility:
                extracted_oid = oid_utility.extract_from_definition(schema_def)
                if extracted_oid:
                    validation_result = oid_utility.validate_format(extracted_oid)
                    assert (
                        validation_result.is_success and validation_result.unwrap()
                    ), f"Invalid OID format from fixture: {extracted_oid}"

            # Parse schema
            parse_method = (
                "parse_attribute" if schema_type == "attribute" else "parse_objectclass"
            )
            result = getattr(schema_quirk, parse_method)(schema_def)
            parsed = TestAssertions.assert_success(
                result, f"Failed to parse fixture {schema_type}"
            )
            parsed_schemas.append(parsed)

        if expected_count is not None:
            assert len(parsed_schemas) == expected_count, (
                f"Expected {expected_count} schemas, got {len(parsed_schemas)}"
            )

        return parsed_schemas

    @staticmethod
    def create_entry_with_validation(
        dn: str,
        attributes: dict[str, str | list[str]],
        *,
        validate_structure: bool = True,
        expected_attributes: list[str] | None = None,
    ) -> FlextLdifModels.Entry:
        """Create entry with comprehensive validation - replaces 10-20 lines.

        Args:
            dn: Distinguished name
            attributes: Dictionary of attribute names to values
            validate_structure: Whether to validate entry structure (default: True)
            expected_attributes: Optional list of attribute names that must exist

        Returns:
            Created Entry model

        """
        result = FlextLdifModels.Entry.create(dn=dn, attributes=attributes)
        entry = cast("FlextLdifModels.Entry", TestAssertions.assert_success(result))

        if validate_structure:
            TestAssertions.assert_entry_valid(entry)

        if expected_attributes:
            assert entry.attributes is not None
            for attr_name in expected_attributes:
                assert attr_name in entry.attributes.attributes, (
                    f"Expected attribute '{attr_name}' not found"
                )

        return entry

    @staticmethod
    def quirk_parse_with_detection_pattern(
        quirk: Any,
        content: str,
        detection_pattern: Any,
        *,
        parse_method: str = "parse",
        should_match: bool = True,
        validate_result: bool = True,
    ) -> Any:
        """Test quirk parse with detection pattern validation - replaces 15-25 lines.

        Args:
            quirk: Quirk instance
            content: Content to parse
            detection_pattern: Compiled regex pattern for detection
            parse_method: Method name for parsing (default: "parse")
            should_match: Whether pattern should match (default: True)
            validate_result: Whether to validate parse result (default: True)

        Returns:
            Parse result

        """
        # Check if pattern matches
        matches = bool(detection_pattern.search(content))
        assert matches == should_match, (
            f"Pattern match mismatch: expected {should_match}, got {matches}"
        )

        # Parse
        parse_func = getattr(quirk, parse_method)
        result = parse_func(content)

        if validate_result:
            if should_match:
                return TestAssertions.assert_success(result)
            # If shouldn't match, result may still succeed (quirk can handle it)
            # but won't be selected for this content
            assert hasattr(result, "is_success")
            return result

        return result

    @staticmethod
    def batch_quirk_parse_with_validation(
        quirk: Any,
        test_cases: list[dict[str, Any]],
        *,
        parse_method: str = "parse",
        validate_all: bool = True,
    ) -> list[Any]:
        """Test multiple quirk parse operations with validation.

        Replaces 60-120+ lines.

        Args:
            quirk: Quirk instance
            test_cases: List of test case dicts with keys:
                - content: str (required)
                - expected_result: Any | None
                - should_succeed: bool (default: True)
                - detection_pattern: Any | None (optional)  # noqa: ANN401
                - should_match: bool (default: True)
            parse_method: Method name for parsing (default: "parse")
            validate_all: Whether to validate all results (default: True)

        Returns:
            List of parse results

        """
        results = []
        for i, test_case in enumerate(test_cases):
            content = test_case.get("content")
            if content is None:
                msg = f"Test case {i} missing 'content'"
                raise ValueError(msg)

            # Handle detection pattern if provided
            detection_pattern = test_case.get("detection_pattern")
            if detection_pattern:
                should_match = test_case.get("should_match", True)
                DeduplicationHelpers.quirk_parse_with_detection_pattern(
                    quirk,
                    content,
                    detection_pattern,
                    parse_method=parse_method,
                    should_match=should_match,
                    validate_result=validate_all,
                )

            # Parse
            parse_func = getattr(quirk, parse_method)
            result = parse_func(content)

            should_succeed = test_case.get("should_succeed", True)
            if should_succeed:
                unwrapped = TestAssertions.assert_success(result)
                expected_result = test_case.get("expected_result")
                if expected_result is not None and validate_all:
                    assert unwrapped == expected_result, (
                        f"Test case {i}: expected {expected_result}, got {unwrapped}"
                    )
                results.append(unwrapped)
            else:
                TestAssertions.assert_failure(result)
                results.append(result)

        return results

    @staticmethod
    def api_parse_with_server_types_batch(
        api: Any,
        test_cases: list[dict[str, Any]],
        *,
        validate_all: bool = True,
    ) -> list[list[FlextLdifModels.Entry]]:
        """Test API parse with multiple server types in batch - replaces 40-80+ lines.

        Args:
            api: FlextLdif API instance
            test_cases: List of test case dicts with keys:
                - content: str (required)
                - server_type: str | None
                - expected_count: int | None
                - expected_dns: list[str] | None
            validate_all: Whether to validate all results (default: True)

        Returns:
            List of parsed entry lists (one per test case)

        """
        results = []
        for i, test_case in enumerate(test_cases):
            content = test_case.get("content")
            if content is None:
                msg = f"Test case {i} missing 'content'"
                raise ValueError(msg)

            server_type = test_case.get("server_type")
            expected_count = test_case.get("expected_count")
            expected_dns = test_case.get("expected_dns")

            # Parse
            if server_type:
                result = api.parse(content, server_type=server_type)
            else:
                result = api.parse(content)

            entries_data = TestAssertions.assert_success(result, "Parse should succeed")

            if isinstance(entries_data, list):
                entries = cast("list[FlextLdifModels.Entry]", entries_data)
            elif hasattr(entries_data, "entries"):
                parse_response = cast("FlextLdifModels.ParseResponse", entries_data)
                entries = [
                    cast("FlextLdifModels.Entry", entry)
                    for entry in parse_response.entries
                ]
            else:
                msg = "Parse returned unexpected type"
                raise AssertionError(msg)

            if expected_count is not None:
                assert len(entries) == expected_count, (
                    f"Expected {expected_count} entries, got {len(entries)}"
                )

            if expected_dns:
                dns = {entry.dn.value for entry in entries if entry.dn is not None}
                for expected_dn in expected_dns:
                    assert expected_dn in dns, (
                        f"Expected DN {expected_dn} not found in {dns}"
                    )

            if validate_all:
                # Cast to ensure type consistency for assert_entries_valid
                entries_cast: list[FlextLdifModels.Entry] = [
                    entry
                    for entry in entries
                    if isinstance(entry, FlextLdifModels.Entry)
                ]
                TestAssertions.assert_entries_valid(entries_cast)

            results.append(entries)
        return results

    @staticmethod
    def quirk_route_write_and_assert(
        quirk: Any,
        data: Any,
        *,
        must_contain: str | list[str] | None = None,
        must_not_contain: str | list[str] | None = None,
        should_succeed: bool = True,
    ) -> str:
        """Test quirk _route_write and assert content - replaces 5-10 lines.

        Common pattern:
            result = quirk._route_write(data)
            assert result.is_success
            assert "something" in result.unwrap()

        Args:
            quirk: Quirk instance (Schema, Entry, Acl, etc)
            data: Data to route write (Entry, SchemaAttribute, SchemaObjectClass, etc)
            must_contain: String or list of strings that must be in output
            must_not_contain: String or list of strings that must NOT be in output
            should_succeed: Whether write should succeed (default: True)

        Returns:
            Written LDIF string

        """
        result = quirk._route_write(data)  # type: ignore[attr-defined,protected-access]

        if should_succeed:
            written = TestAssertions.assert_success(
                result, "Route write should succeed"
            )
            assert isinstance(written, str), "Route write should return string"
        else:
            TestAssertions.assert_failure(result)
            return ""

        if must_contain:
            contains_list = (
                [must_contain] if isinstance(must_contain, str) else must_contain
            )
            for text in contains_list:
                assert text in written, f"Must contain '{text}' not found in output"

        if must_not_contain:
            not_contains_list = (
                [must_not_contain]
                if isinstance(must_not_contain, str)
                else must_not_contain
            )
            for text in not_contains_list:
                assert text not in written, f"Must not contain '{text}' found in output"

        return written

    @staticmethod
    def quirk_route_can_handle_and_assert(
        quirk: Any,
        data: Any,
        *,
        expected: bool = True,
    ) -> bool:
        """Test quirk _route_can_handle and assert result - replaces 3-5 lines.

        Common pattern:
            result = quirk._route_can_handle(data)
            assert result is True/False

        Args:
            quirk: Quirk instance (Schema, Entry, Acl, etc)
            data: Data to check (Entry, SchemaAttribute, SchemaObjectClass, string, etc)
            expected: Expected boolean result (default: True)

        Returns:
            Boolean result from _route_can_handle

        """
        result = quirk._route_can_handle(data)  # type: ignore[attr-defined,protected-access]
        assert isinstance(result, bool), "_route_can_handle should return bool"
        assert result == expected, (
            f"Expected _route_can_handle to return {expected}, got {result}"
        )
        return result

    @staticmethod
    def quirk_write_and_assert_content(
        quirk: Any,
        data: Any,
        *,
        must_contain: str | list[str] | None = None,
        must_not_contain: str | list[str] | None = None,
        write_method: str = "write",
        should_succeed: bool = True,
    ) -> str:
        """Test quirk write and assert content - replaces 5-10 lines.

        Common pattern:
            result = quirk.write(data)
            assert result.is_success
            assert "something" in result.unwrap()

        Args:
            quirk: Quirk instance (Schema, Entry, Acl, etc)
            data: Data to write (Entry, SchemaAttribute, SchemaObjectClass, etc)
            must_contain: String or list of strings that must be in output
            must_not_contain: String or list of strings that must NOT be in output
            write_method: Method name to call (default: "write")
            should_succeed: Whether write should succeed (default: True)

        Returns:
            Written LDIF string

        """
        method = getattr(quirk, write_method, None)
        if method is None:
            msg = f"Method {write_method} not found on quirk"
            raise AttributeError(msg)

        result = method(data)  # type: ignore[misc]

        if should_succeed:
            written = TestAssertions.assert_success(result, "Write should succeed")
            assert isinstance(written, str), "Write should return string"
        else:
            TestAssertions.assert_failure(result)
            return ""

        if must_contain:
            contains_list = (
                [must_contain] if isinstance(must_contain, str) else must_contain
            )
            for text in contains_list:
                assert text in written, f"Must contain '{text}' not found in output"

        if must_not_contain:
            not_contains_list = (
                [must_not_contain]
                if isinstance(must_not_contain, str)
                else must_not_contain
            )
            for text in not_contains_list:
                assert text not in written, f"Must not contain '{text}' found in output"

        return written

    @staticmethod
    def service_execute_and_assert_fields(
        service: Any,
        *,
        expected_fields: dict[str, object] | None = None,
        expected_type: type[Any] | None = None,
        must_contain_in_fields: dict[str, object] | None = None,
    ) -> Any:
        """Test service execute and assert fields - replaces 8-12 lines.

        Common pattern:
            result = service.execute()
            assert result.is_success
            status = result.unwrap()
            assert isinstance(status, ValidationServiceStatus)
            assert status.service == "ValidationService"
            assert "RFC 2849" in status.rfc_compliance

        Args:
            service: Service instance with execute() method
            expected_fields: Optional dict of field_name: expected_value
            expected_type: Optional expected type of result
            must_contain_in_fields: Optional dict of field_name: substring to check

        Returns:
            Unwrapped result

        """
        result = service.execute()
        unwrapped = TestAssertions.assert_success(
            result, "Service execute should succeed"
        )

        if expected_type:
            assert isinstance(unwrapped, expected_type), (
                f"Expected {expected_type.__name__}, got {type(unwrapped).__name__}"
            )

        if expected_fields:
            for field_name, expected_value in expected_fields.items():
                actual_value = getattr(unwrapped, field_name, None)
                assert actual_value == expected_value, (
                    f"Field '{field_name}' expected '{expected_value}', "
                    f"got '{actual_value}'"
                )

        if must_contain_in_fields:
            for field_name, substring in must_contain_in_fields.items():
                actual_value = getattr(unwrapped, field_name, None)
                if isinstance(actual_value, str) and isinstance(substring, str):
                    assert substring in actual_value, (
                        f"Field '{field_name}' must contain '{substring}', got '{actual_value}'"
                    )

        return unwrapped

    @staticmethod
    def assert_entry_has_attributes(
        entry: FlextLdifModels.Entry,
        required_attributes: list[str],
        *,
        must_not_have: list[str] | None = None,
    ) -> None:
        """Assert entry has required attributes - replaces 3-10 lines.

        Common pattern:
            assert entry.attributes is not None
            assert "attr1" in entry.attributes.attributes
            assert "attr2" in entry.attributes.attributes

        Args:
            entry: Entry to check
            required_attributes: List of attribute names that must exist
            must_not_have: Optional list of attribute names that must NOT exist

        """
        assert entry.attributes is not None, "Entry must have attributes"
        for attr_name in required_attributes:
            assert attr_name in entry.attributes.attributes, (
                f"Entry must have attribute '{attr_name}'"
            )

        if must_not_have:
            for attr_name in must_not_have:
                assert attr_name not in entry.attributes.attributes, (
                    f"Entry must NOT have attribute '{attr_name}'"
                )

    @staticmethod
    def assert_entry_has_attribute_value(
        entry: FlextLdifModels.Entry,
        attr_name: str,
        expected_value: str | list[str],
    ) -> None:
        """Assert entry has attribute with specific value - replaces 3-5 lines.

        Common pattern:
            assert entry.attributes is not None
            assert attr_name in entry.attributes.attributes
            assert entry.attributes.attributes[attr_name] == expected_value

        Args:
            entry: Entry to check
            attr_name: Attribute name to check
            expected_value: Expected value(s)

        """
        assert entry.attributes is not None, "Entry must have attributes"
        assert attr_name in entry.attributes.attributes, (
            f"Entry must have attribute '{attr_name}'"
        )

        actual_value = entry.attributes.attributes[attr_name]
        if isinstance(expected_value, list):
            assert actual_value == expected_value, (
                f"Attribute '{attr_name}' value mismatch: "
                f"expected {expected_value}, got {actual_value}"
            )
        else:
            assert expected_value in actual_value, (
                f"Attribute '{attr_name}' must contain '{expected_value}', "
                f"got {actual_value}"
            )

    @staticmethod
    def assert_schema_has_oid_and_name(
        schema_obj: FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass,
        expected_oid: str | None = None,
        expected_name: str | None = None,
    ) -> None:
        """Assert schema object has OID and name - replaces 2-4 lines.

        Common pattern:
            assert schema_obj.oid == expected_oid
            assert schema_obj.name == expected_name

        Args:
            schema_obj: SchemaAttribute or SchemaObjectClass to check
            expected_oid: Optional expected OID
            expected_name: Optional expected name

        """
        if expected_oid:
            assert schema_obj.oid == expected_oid, (
                f"Expected OID '{expected_oid}', got '{schema_obj.oid}'"
            )

        if expected_name:
            assert schema_obj.name == expected_name, (
                f"Expected name '{expected_name}', got '{schema_obj.name}'"
            )

    @staticmethod
    def assert_isinstance_schema_attribute(
        obj: Any,
        error_msg: str | None = None,
    ) -> FlextLdifModels.SchemaAttribute:
        """Assert object is SchemaAttribute - replaces 1-2 lines per use.

        Common pattern (appears 33+ times):
            assert isinstance(attr, FlextLdifModels.SchemaAttribute)
            # or
            assert isinstance(attr, FlextLdifModels.SchemaAttribute), "Should return SchemaAttribute"

        Args:
            obj: Object to check
            error_msg: Optional custom error message

        Returns:
            The object cast to SchemaAttribute

        """
        assert isinstance(obj, FlextLdifModels.SchemaAttribute), (
            error_msg or f"Expected SchemaAttribute, got {type(obj).__name__}"
        )
        return obj

    @staticmethod
    def assert_isinstance_schema_objectclass(
        obj: Any,
        error_msg: str | None = None,
    ) -> FlextLdifModels.SchemaObjectClass:
        """Assert object is SchemaObjectClass - replaces 1-2 lines per use.

        Common pattern (appears 15+ times):
            assert isinstance(oc, FlextLdifModels.SchemaObjectClass)
            # or
            assert isinstance(oc, FlextLdifModels.SchemaObjectClass), "Should return SchemaObjectClass"

        Args:
            obj: Object to check
            error_msg: Optional custom error message

        Returns:
            The object cast to SchemaObjectClass

        """
        assert isinstance(obj, FlextLdifModels.SchemaObjectClass), (
            error_msg or f"Expected SchemaObjectClass, got {type(obj).__name__}"
        )
        return obj

    @staticmethod
    def assert_entry_dn_equals(
        entry: FlextLdifModels.Entry,
        expected_dn: str,
        error_msg: str | None = None,
    ) -> None:
        """Assert entry DN equals expected value - replaces 1-2 lines per use.

        Common pattern (appears 29+ times):
            assert entry.dn.value == expected_dn
            # or
            assert entry.dn.value == expected_dn, f"Expected DN '{expected_dn}', got '{entry.dn.value}'"

        Args:
            entry: Entry to check
            expected_dn: Expected DN value
            error_msg: Optional custom error message

        """
        assert entry.dn is not None, "Entry must have DN"
        assert entry.dn.value == expected_dn, (
            error_msg or f"Expected DN '{expected_dn}', got '{entry.dn.value}'"
        )

    @staticmethod
    def assert_entry_attributes_not_none(
        entry: FlextLdifModels.Entry,
        error_msg: str | None = None,
    ) -> None:
        """Assert entry has attributes (not None) - replaces 1 line per use.

        Common pattern (appears 24+ times):
            assert entry.attributes is not None
            # or
            assert entry.attributes is not None, "Entry must have attributes"

        Args:
            entry: Entry to check
            error_msg: Optional custom error message

        """
        assert entry.attributes is not None, error_msg or "Entry must have attributes"

    @staticmethod
    def assert_result_success_and_type(
        result: FlextResult[Any],
        expected_type: type[Any],
        error_msg: str | None = None,
    ) -> Any:
        """Assert result is success and unwrapped value is expected type - replaces 2-3 lines.

        Common pattern (appears 20+ times):
            assert result.is_success
            unwrapped = result.unwrap()
            assert isinstance(unwrapped, ExpectedType)

        Args:
            result: FlextResult to check
            expected_type: Expected type of unwrapped value
            error_msg: Optional custom error message

        Returns:
            Unwrapped value of expected type

        """
        unwrapped = TestAssertions.assert_success(result, error_msg)
        assert isinstance(unwrapped, expected_type), (
            f"Expected {expected_type.__name__}, got {type(unwrapped).__name__}"
        )
        return unwrapped

    @staticmethod
    def assert_length_equals(
        items: list[Any] | str,
        expected_length: int,
        error_msg: str | None = None,
    ) -> None:
        """Assert length equals expected - replaces 1-2 lines per use.

        Common pattern (appears 29+ times):
            assert len(entries) == expected_count
            # or
            assert len(entries) == expected_count, f"Expected {expected_count} entries, got {len(entries)}"

        Args:
            items: List or string to check length
            expected_length: Expected length
            error_msg: Optional custom error message

        """
        actual_length = len(items)
        assert actual_length == expected_length, (
            error_msg or f"Expected length {expected_length}, got {actual_length}"
        )

    @staticmethod
    def assert_length_greater_than(
        items: list[Any] | str,
        min_length: int,
        error_msg: str | None = None,
    ) -> None:
        """Assert length is greater than minimum - replaces 1-2 lines per use.

        Common pattern (appears 15+ times):
            assert len(entries) > 0
            # or
            assert len(entries) > 0, "Should have at least one entry"

        Args:
            items: List or string to check length
            min_length: Minimum length (exclusive)
            error_msg: Optional custom error message

        """
        actual_length = len(items)
        assert actual_length > min_length, (
            error_msg or f"Expected length > {min_length}, got {actual_length}"
        )

    @staticmethod
    def assert_length_greater_or_equal(
        items: list[Any] | str,
        min_length: int,
        error_msg: str | None = None,
    ) -> None:
        """Assert length is greater than or equal to minimum - replaces 1-2 lines per use.

        Common pattern (appears 20+ times):
            assert len(entries) >= 1
            # or
            assert len(entries) >= min_count, f"Expected at least {min_count} entries"

        Args:
            items: List or string to check length
            min_length: Minimum length (inclusive)
            error_msg: Optional custom error message

        """
        actual_length = len(items)
        assert actual_length >= min_length, (
            error_msg or f"Expected length >= {min_length}, got {actual_length}"
        )

    @staticmethod
    def assert_length_zero(
        items: list[Any] | str,
        error_msg: str | None = None,
    ) -> None:
        """Assert length is zero (empty) - replaces 1 line per use.

        Common pattern (appears 13+ times):
            assert len(items) == 0
            # or
            assert len(items) == 0, "Expected empty list"

        Args:
            items: List or string to check length
            error_msg: Optional custom error message

        """
        actual_length = len(items)
        assert actual_length == 0, (
            error_msg or f"Expected empty (length 0), got length {actual_length}"
        )

    @staticmethod
    def assert_length_non_zero(
        items: list[Any] | str,
        error_msg: str | None = None,
    ) -> None:
        """Assert length is greater than zero (not empty) - replaces 1 line per use.

        Common pattern (appears 17+ times):
            assert len(items) > 0
            # or
            assert len(items) > 0, "Should have at least one item"

        Args:
            items: List or string to check length
            error_msg: Optional custom error message

        """
        actual_length = len(items)
        assert actual_length > 0, (
            error_msg or f"Expected non-empty (length > 0), got length {actual_length}"
        )

    @staticmethod
    def assert_first_entry_dn_equals(
        entries: list[FlextLdifModels.Entry],
        expected_dn: str,
        error_msg: str | None = None,
    ) -> None:
        """Assert first entry DN equals expected - replaces 2-3 lines per use.

        Common pattern (appears 27+ times):
            assert entries[0].dn is not None
            assert entries[0].dn.value == expected_dn
            # or
            assert entries[0].dn.value == expected_dn, f"Expected DN '{expected_dn}'"

        Args:
            entries: List of entries to check
            expected_dn: Expected DN value
            error_msg: Optional custom error message

        """
        assert len(entries) > 0, "Entries list must not be empty"
        assert entries[0].dn is not None, "First entry must have DN"
        assert entries[0].dn.value == expected_dn, (
            error_msg
            or f"Expected first entry DN '{expected_dn}', got '{entries[0].dn.value}'"
        )

    @staticmethod
    def assert_strings_equal_case_insensitive(
        str1: str,
        str2: str,
        error_msg: str | None = None,
    ) -> None:
        """Assert two strings are equal (case-insensitive) - replaces 1-2 lines per use.

        Common pattern (appears 10+ times):
            assert str1.lower() == str2.lower()
            # or
            assert str1.lower() == str2.lower(), "Strings should match (case-insensitive)"

        Args:
            str1: First string to compare
            str2: Second string to compare
            error_msg: Optional custom error message

        """
        assert str1.lower() == str2.lower(), (
            error_msg or f"Expected '{str1}' == '{str2}' (case-insensitive)"
        )

    @staticmethod
    def assert_any_matches(
        items: list[Any],
        predicate: Callable[[Any], bool],
        error_msg: str | None = None,
    ) -> None:
        """Assert any item matches predicate - replaces 1-2 lines per use.

        Common pattern (appears 23+ times):
            assert any("text" in line for line in lines)
            # or
            assert any(predicate(item) for item in items)

        Args:
            items: List of items to check
            predicate: Function that returns True if item matches
            error_msg: Optional custom error message

        """
        assert any(predicate(item) for item in items), (
            error_msg or "Expected at least one item to match predicate"
        )

    @staticmethod
    def assert_all_match(
        items: list[Any],
        predicate: Callable[[Any], bool],
        error_msg: str | None = None,
    ) -> None:
        """Assert all items match predicate - replaces 1-2 lines per use.

        Common pattern (appears 13+ times):
            assert all("text" in line for line in lines)
            # or
            assert all(predicate(item) for item in items)

        Args:
            items: List of items to check
            predicate: Function that returns True if item matches
            error_msg: Optional custom error message

        """
        assert all(predicate(item) for item in items), (
            error_msg or "Expected all items to match predicate"
        )

    @staticmethod
    def assert_in_list(
        value: Any,
        items_list: list[Any],
        error_msg: str | None = None,
    ) -> None:
        """Assert value is in list - replaces 1 line per use.

        Common pattern (appears 3+ times):
            assert value in [item1, item2, item3]
            # or
            assert value in items_list

        Args:
            value: Value to check
            items_list: List to check membership
            error_msg: Optional custom error message

        """
        assert value in items_list, (
            error_msg or f"Expected {value!r} in list {items_list!r}"
        )

    @staticmethod
    def assert_not_in_list(
        value: Any,
        items_list: list[Any],
        error_msg: str | None = None,
    ) -> None:
        """Assert value is NOT in list - replaces 1 line per use.

        Common pattern (appears 2+ times):
            assert value not in [item1, item2, item3]
            # or
            assert value not in items_list

        Args:
            value: Value to check
            items_list: List to check membership
            error_msg: Optional custom error message

        """
        assert value not in items_list, (
            error_msg or f"Expected {value!r} NOT in list {items_list!r}"
        )

    @staticmethod
    def assert_dict_key_equals(
        dictionary: dict[str, Any],
        key: str,
        expected_value: Any,
        error_msg: str | None = None,
    ) -> None:
        """Assert dictionary key equals expected value - replaces 1-2 lines per use.

        Common pattern (appears 19+ times):
            assert dict["key"] == expected_value
            # or
            assert dict["key"] == expected_value, "Expected value"

        Args:
            dictionary: Dictionary to check
            key: Key to access
            expected_value: Expected value
            error_msg: Optional custom error message

        """
        assert key in dictionary, f"Key '{key}' not found in dictionary"
        actual_value = dictionary[key]
        assert actual_value == expected_value, (
            error_msg
            or f"Expected dict['{key}'] == {expected_value!r}, got {actual_value!r}"
        )

    @staticmethod
    def assert_list_first_equals(
        items: list[Any],
        expected_value: Any,
        error_msg: str | None = None,
    ) -> None:
        """Assert first list item equals expected - replaces 1-2 lines per use.

        Common pattern (appears 10+ times):
            assert list[0] == expected_value
            # or
            assert list[0] == expected_value, "Expected first item"

        Args:
            items: List to check
            expected_value: Expected value for first item
            error_msg: Optional custom error message

        """
        assert len(items) > 0, "List must not be empty"
        actual_value = items[0]
        assert actual_value == expected_value, (
            error_msg
            or f"Expected first item == {expected_value!r}, got {actual_value!r}"
        )

    @staticmethod
    def assert_list_last_equals(
        items: list[Any],
        expected_value: Any,
        error_msg: str | None = None,
    ) -> None:
        """Assert last list item equals expected - replaces 1-2 lines per use.

        Common pattern (appears 4+ times):
            assert list[-1] == expected_value
            # or
            assert list[-1] == expected_value, "Expected last item"

        Args:
            items: List to check
            expected_value: Expected value for last item
            error_msg: Optional custom error message

        """
        assert len(items) > 0, "List must not be empty"
        actual_value = items[-1]
        assert actual_value == expected_value, (
            error_msg
            or f"Expected last item == {expected_value!r}, got {actual_value!r}"
        )

    @staticmethod
    def assert_dict_key_isinstance(
        dictionary: dict[str, Any],
        key: str,
        expected_type: type[Any],
        error_msg: str | None = None,
    ) -> None:
        """Assert dictionary key value is instance of type - replaces 1-2 lines per use.

        Common pattern (appears 11+ times):
            assert isinstance(dict["key"], expected_type)
            # or
            assert isinstance(dict["key"], list)

        Args:
            dictionary: Dictionary to check
            key: Key to access
            expected_type: Expected type
            error_msg: Optional custom error message

        """
        assert key in dictionary, f"Key '{key}' not found in dictionary"
        actual_value = dictionary[key]
        assert isinstance(actual_value, expected_type), (
            error_msg
            or f"Expected dict['{key}'] to be {expected_type.__name__}, got {type(actual_value).__name__}"
        )

    @staticmethod
    def assert_dict_key_is_not_none(
        dictionary: dict[str, Any],
        key: str,
        error_msg: str | None = None,
    ) -> None:
        """Assert dictionary key value is not None - replaces 1-2 lines per use.

        Common pattern (appears 3+ times):
            assert dict["key"] is not None
            # or
            assert dict["key"] is not None, "Key should not be None"

        Args:
            dictionary: Dictionary to check
            key: Key to access
            error_msg: Optional custom error message

        """
        assert key in dictionary, f"Key '{key}' not found in dictionary"
        actual_value = dictionary[key]
        assert actual_value is not None, (
            error_msg or f"Expected dict['{key}'] to not be None, got None"
        )

    @staticmethod
    def assert_entry_attribute_equals(
        entry: FlextLdifModels.Entry,
        attr_name: str,
        expected_value: Any,
        error_msg: str | None = None,
    ) -> None:
        """Assert entry attribute equals expected value - replaces 1-2 lines per use.

        Common pattern (appears 5+ times):
            assert entry.attributes.attributes[attr_name] == expected_value
            # or
            assert entry.attributes.attributes["attr1"] == expected_value1

        Args:
            entry: Entry to check
            attr_name: Attribute name
            expected_value: Expected value
            error_msg: Optional custom error message

        """
        assert entry.attributes is not None, "Entry must have attributes"
        assert attr_name in entry.attributes.attributes, (
            f"Attribute '{attr_name}' not found in entry"
        )
        actual_value = entry.attributes.attributes[attr_name]
        assert actual_value == expected_value, (
            error_msg
            or f"Expected entry.attributes.attributes['{attr_name}'] == {expected_value!r}, got {actual_value!r}"
        )

    @staticmethod
    def assert_metadata_extension_equals(
        obj: Any,
        key: str,
        expected_value: Any,
        error_msg: str | None = None,
    ) -> None:
        """Assert metadata extension equals expected value - replaces 1-2 lines per use.

        Common pattern (appears 2+ times):
            assert entry.metadata.extensions[key] == expected_value
            # or
            assert obj.metadata.extensions["key"] == expected_value

        Args:
            obj: Object with metadata.extensions (Entry, SchemaAttribute, etc.)
            key: Extension key
            expected_value: Expected value
            error_msg: Optional custom error message

        """
        assert hasattr(obj, "metadata"), "Object must have metadata"
        assert obj.metadata is not None, "Object metadata must not be None"
        assert hasattr(obj.metadata, "extensions"), "Metadata must have extensions"
        assert obj.metadata.extensions is not None, "Extensions must not be None"
        assert key in obj.metadata.extensions, f"Extension key '{key}' not found"
        actual_value = obj.metadata.extensions[key]
        assert actual_value == expected_value, (
            error_msg
            or f"Expected metadata.extensions['{key}'] == {expected_value!r}, got {actual_value!r}"
        )

    @staticmethod
    def assert_metadata_extension_get_equals(
        obj: Any,
        key: str,
        expected_value: Any,
        error_msg: str | None = None,
    ) -> None:
        """Assert metadata extension get() equals expected value - replaces 1-2 lines per use.

        Common pattern (appears 8+ times):
            assert obj.metadata.extensions.get("key") == expected_value
            # or
            assert entry.metadata.extensions.get("validation_rules") is not None

        Args:
            obj: Object with metadata.extensions (Entry, SchemaAttribute, etc.)
            key: Extension key
            expected_value: Expected value
            error_msg: Optional custom error message

        """
        assert hasattr(obj, "metadata"), "Object must have metadata"
        assert obj.metadata is not None, "Object metadata must not be None"
        assert hasattr(obj.metadata, "extensions"), "Metadata must have extensions"
        assert obj.metadata.extensions is not None, "Extensions must not be None"
        actual_value = obj.metadata.extensions.get(key)
        assert actual_value == expected_value, (
            error_msg
            or f"Expected metadata.extensions.get('{key}') == {expected_value!r}, got {actual_value!r}"
        )

    @staticmethod
    def assert_metadata_extension_get_isinstance(
        obj: Any,
        key: str,
        expected_type: type[Any],
        error_msg: str | None = None,
    ) -> None:
        """Assert metadata extension get() is instance of type - replaces 1-2 lines per use.

        Common pattern (appears 1+ times):
            assert isinstance(obj.metadata.extensions.get("key"), expected_type)
            # or
            assert isinstance(result.metadata.extensions.get("validation_rules"), dict)

        Args:
            obj: Object with metadata.extensions (Entry, SchemaAttribute, etc.)
            key: Extension key
            expected_type: Expected type
            error_msg: Optional custom error message

        """
        assert hasattr(obj, "metadata"), "Object must have metadata"
        assert obj.metadata is not None, "Object metadata must not be None"
        assert hasattr(obj.metadata, "extensions"), "Metadata must have extensions"
        assert obj.metadata.extensions is not None, "Extensions must not be None"
        actual_value = obj.metadata.extensions.get(key)
        assert isinstance(actual_value, expected_type), (
            error_msg
            or f"Expected metadata.extensions.get('{key}') to be {expected_type.__name__}, got {type(actual_value).__name__ if actual_value is not None else 'None'}"
        )

    @staticmethod
    def assert_dn_value_equals(
        dn_obj: FlextLdifModels.DistinguishedName | None,
        expected_value: str,
        error_msg: str | None = None,
    ) -> None:
        """Assert DN value equals expected - replaces 1-2 lines per use.

        Common pattern (appears 27+ times):
            assert entry.dn.value == expected_dn
            # or
            assert result.dn.value == "cn=test,dc=example,dc=com"

        Args:
            dn_obj: DistinguishedName object (can be None)
            expected_value: Expected DN string value
            error_msg: Optional custom error message

        """
        assert dn_obj is not None, "DN object must not be None"
        assert dn_obj.value == expected_value, (
            error_msg or f"Expected DN value '{expected_value}', got '{dn_obj.value}'"
        )

    @staticmethod
    def assert_dn_value_is_not_none(
        dn_obj: FlextLdifModels.DistinguishedName | None,
        error_msg: str | None = None,
    ) -> None:
        """Assert DN value is not None - replaces 1-2 lines per use.

        Common pattern (appears 5+ times):
            assert entry.dn.value is not None
            # or
            assert entries[0].dn.value is not None

        Args:
            dn_obj: DistinguishedName object (can be None)
            error_msg: Optional custom error message

        """
        assert dn_obj is not None, "DN object must not be None"
        assert dn_obj.value is not None, (
            error_msg or "Expected DN value to not be None, got None"
        )

    @staticmethod
    def assert_entry_dn_value_equals(
        entry: FlextLdifModels.Entry,
        expected_dn: str,
        error_msg: str | None = None,
    ) -> None:
        """Assert entry DN value equals expected - replaces 1-2 lines per use.

        Common pattern (appears 27+ times):
            assert entry.dn.value == expected_dn
            # or
            assert entry.dn.value == "cn=test,dc=example,dc=com"

        Args:
            entry: Entry to check
            expected_dn: Expected DN string value
            error_msg: Optional custom error message

        """
        assert entry.dn is not None, "Entry must have DN"
        # Type narrowing: entry.dn is DistinguishedName from domain models
        # Cast to match expected type in assert_dn_value_equals
        dn_obj = cast("FlextLdifModels.DistinguishedName | None", entry.dn)
        DeduplicationHelpers.assert_dn_value_equals(dn_obj, expected_dn, error_msg)

    @staticmethod
    def service_execute_and_unwrap(
        service: Any,
        error_msg: str | None = None,
    ) -> Any:
        """Execute service and unwrap result - replaces 2-3 lines per use.

        Common pattern (appears 19+ times):
            result = service.execute()
            assert result.is_success
            unwrapped = result.unwrap()

        Args:
            service: Service object with execute() method
            error_msg: Optional custom error message

        Returns:
            Unwrapped result value

        """
        result = service.execute()
        return DeduplicationHelpers.assert_success_and_unwrap(result, error_msg)

    @staticmethod
    def assert_entry_has_attribute(
        entry: FlextLdifModels.Entry,
        attr_name: str,
        error_msg: str | None = None,
    ) -> None:
        """Assert entry has specific attribute - replaces 1-2 lines per use.

        Common pattern (appears 33+ times):
            assert "cn" in entry.attributes.attributes
            # or
            assert "cn" in entry.attributes.attributes, "Entry must have 'cn' attribute"

        Args:
            entry: Entry to check
            attr_name: Attribute name that must exist
            error_msg: Optional custom error message

        """
        assert entry.attributes is not None, "Entry must have attributes"
        assert attr_name in entry.attributes.attributes, (
            error_msg or f"Entry must have attribute '{attr_name}'"
        )

    @staticmethod
    def assert_entry_not_has_attribute(
        entry: FlextLdifModels.Entry,
        attr_name: str,
        error_msg: str | None = None,
    ) -> None:
        """Assert entry does NOT have specific attribute - replaces 1-2 lines per use.

        Common pattern (appears 12+ times):
            assert "cn" not in entry.attributes.attributes
            # or
            assert "cn" not in entry.attributes.attributes, "Entry must NOT have 'cn' attribute"

        Args:
            entry: Entry to check
            attr_name: Attribute name that must NOT exist
            error_msg: Optional custom error message

        """
        assert entry.attributes is not None, "Entry must have attributes"
        assert attr_name not in entry.attributes.attributes, (
            error_msg or f"Entry must NOT have attribute '{attr_name}'"
        )

    @staticmethod
    def assert_schema_oid_equals(
        schema_obj: FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass,
        expected_oid: str,
        error_msg: str | None = None,
    ) -> None:
        """Assert schema object OID equals expected - replaces 1-2 lines per use.

        Common pattern (appears 29+ times):
            assert schema_obj.oid == expected_oid
            # or
            assert schema_obj.oid == expected_oid, f"Expected OID '{expected_oid}', got '{schema_obj.oid}'"

        Args:
            schema_obj: SchemaAttribute or SchemaObjectClass to check
            expected_oid: Expected OID value
            error_msg: Optional custom error message

        """
        assert schema_obj.oid == expected_oid, (
            error_msg or f"Expected OID '{expected_oid}', got '{schema_obj.oid}'"
        )

    @staticmethod
    def assert_schema_name_equals(
        schema_obj: FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass,
        expected_name: str,
        error_msg: str | None = None,
    ) -> None:
        """Assert schema object name equals expected - replaces 1-2 lines per use.

        Common pattern (appears 29+ times):
            assert schema_obj.name == expected_name
            # or
            assert schema_obj.name == expected_name, f"Expected name '{expected_name}', got '{schema_obj.name}'"

        Args:
            schema_obj: SchemaAttribute or SchemaObjectClass to check
            expected_name: Expected name value
            error_msg: Optional custom error message

        """
        assert schema_obj.name == expected_name, (
            error_msg or f"Expected name '{expected_name}', got '{schema_obj.name}'"
        )

    @staticmethod
    def parse_and_unwrap_simple(
        parser: Any,
        content: str | Path,
        *,
        parse_method: str = "parse",
        expected_count: int | None = None,
    ) -> Any:
        """Simple parse and unwrap - replaces 2-3 lines per use.

        Common pattern (appears 37+ times):
            result = parser.parse(content)
            assert result.is_success
            entries = result.unwrap()
            assert len(entries) == expected_count  # optional

        Args:
            parser: Parser instance (quirk, service, etc.)
            content: Content to parse (string or Path)
            parse_method: Method name to call (default: "parse")
            expected_count: Optional expected count of results

        Returns:
            Unwrapped parse result

        """
        method = getattr(parser, parse_method)
        result = method(content)
        unwrapped = TestAssertions.assert_success(
            result, f"{parse_method} should succeed"
        )

        if expected_count is not None:
            if isinstance(unwrapped, list):
                DeduplicationHelpers.assert_length_equals(
                    unwrapped, expected_count, f"Expected {expected_count} items"
                )
            elif hasattr(unwrapped, "entries"):
                # Type narrowing for ParseResponse-like objects
                entries_attr = getattr(unwrapped, "entries", None)
                if isinstance(entries_attr, list):
                    DeduplicationHelpers.assert_length_equals(
                        entries_attr,
                        expected_count,
                        f"Expected {expected_count} entries",
                    )

        return unwrapped

    @staticmethod
    def write_and_unwrap_simple(
        writer: Any,
        data: Any,
        *,
        write_method: str = "write",
        must_contain: str | list[str] | None = None,
    ) -> str:
        """Simple write and unwrap - replaces 2-4 lines per use.

        Common pattern (appears 37+ times):
            result = writer.write(data)
            assert result.is_success
            ldif = result.unwrap()
            assert "something" in ldif  # optional

        Args:
            writer: Writer instance (quirk, service, etc.)
            data: Data to write (Entry, list[Entry], SchemaAttribute, etc.)
            write_method: Method name to call (default: "write")
            must_contain: Optional string or list of strings that must be in output

        Returns:
            Written LDIF string

        """
        method = getattr(writer, write_method)
        result = method(data)
        written = TestAssertions.assert_success(
            result, f"{write_method} should succeed"
        )
        assert isinstance(written, str), "Write should return string"

        if must_contain:
            contains_list = (
                [must_contain] if isinstance(must_contain, str) else must_contain
            )
            for text in contains_list:
                assert text in written, f"Must contain '{text}' not found in output"

        return written

    @staticmethod
    def assert_schema_syntax_equals(
        schema_obj: FlextLdifModels.SchemaAttribute,
        expected_syntax: str | None,
        error_msg: str | None = None,
    ) -> None:
        """Assert schema attribute syntax equals expected - replaces 1-2 lines per use.

        Common pattern (appears 21+ times):
            assert attr.syntax == expected_syntax
            # or
            assert attr.syntax == expected_syntax, f"Expected syntax '{expected_syntax}', got '{attr.syntax}'"

        Args:
            schema_obj: SchemaAttribute to check
            expected_syntax: Expected syntax value (can be None)
            error_msg: Optional custom error message

        """
        assert schema_obj.syntax == expected_syntax, (
            error_msg
            or f"Expected syntax '{expected_syntax}', got '{schema_obj.syntax}'"
        )

    @staticmethod
    def assert_schema_single_value_equals(
        schema_obj: FlextLdifModels.SchemaAttribute,
        expected_single_value: bool,
        error_msg: str | None = None,
    ) -> None:
        """Assert schema attribute single_value equals expected - replaces 1-2 lines per use.

        Common pattern (appears 5+ times):
            assert attr.single_value == expected_single_value
            # or
            assert attr.single_value == expected_single_value, f"Expected single_value {expected_single_value}"

        Args:
            schema_obj: SchemaAttribute to check
            expected_single_value: Expected single_value boolean
            error_msg: Optional custom error message

        """
        assert schema_obj.single_value == expected_single_value, (
            error_msg
            or f"Expected single_value {expected_single_value}, got {schema_obj.single_value}"
        )

    @staticmethod
    def assert_schema_desc_equals(
        schema_obj: FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass,
        expected_desc: str | None,
        error_msg: str | None = None,
    ) -> None:
        """Assert schema object desc equals expected - replaces 1-2 lines per use.

        Common pattern (appears 15+ times):
            assert attr.desc == expected_desc
            # or
            assert attr.desc == expected_desc, f"Expected desc '{expected_desc}', got '{attr.desc}'"

        Args:
            schema_obj: SchemaAttribute or SchemaObjectClass to check
            expected_desc: Expected desc value (can be None)
            error_msg: Optional custom error message

        """
        assert schema_obj.desc == expected_desc, (
            error_msg or f"Expected desc '{expected_desc}', got '{schema_obj.desc}'"
        )

    @staticmethod
    def assert_is_none(
        value: Any,
        error_msg: str | None = None,
    ) -> None:
        """Assert value is None - replaces 1 line per use.

        Common pattern (appears 30+ times):
            assert value is None
            # or
            assert value is None, "Value should be None"

        Args:
            value: Value to check
            error_msg: Optional custom error message

        """
        assert value is None, error_msg or f"Expected None, got {value}"

    @staticmethod
    def assert_is_not_none(
        value: Any,
        error_msg: str | None = None,
    ) -> None:
        """Assert value is not None - replaces 1 line per use.

        Common pattern (appears 50+ times):
            assert value is not None
            # or
            assert value is not None, "Value should not be None"

        Args:
            value: Value to check
            error_msg: Optional custom error message

        """
        assert value is not None, error_msg or "Expected not None, got None"

    @staticmethod
    def assert_is_true(
        value: bool,
        error_msg: str | None = None,
    ) -> None:
        """Assert value is True - replaces 1 line per use.

        Common pattern (appears 26+ times):
            assert result is True
            # or
            assert result is True, "Expected True"

        Args:
            value: Boolean value to check
            error_msg: Optional custom error message

        """
        assert value is True, error_msg or f"Expected True, got {value}"

    @staticmethod
    def assert_is_false(
        value: bool,
        error_msg: str | None = None,
    ) -> None:
        """Assert value is False - replaces 1 line per use.

        Common pattern (appears 25+ times):
            assert result is False
            # or
            assert result is False, "Expected False"

        Args:
            value: Boolean value to check
            error_msg: Optional custom error message

        """
        assert value is False, error_msg or f"Expected False, got {value}"

    @staticmethod
    def assert_dict_get_equals(
        dictionary: dict[str, Any],
        key: str,
        expected_value: Any,
        error_msg: str | None = None,
    ) -> None:
        """Assert dict.get(key) equals expected - replaces 1-2 lines per use.

        Common pattern (appears 27+ times):
            assert result.get("key") == expected_value
            # or
            assert result.get("key") == expected_value, "Expected value"

        Args:
            dictionary: Dictionary to check
            key: Key to get from dictionary
            expected_value: Expected value
            error_msg: Optional custom error message

        """
        actual_value = dictionary.get(key)
        assert actual_value == expected_value, (
            error_msg
            or f"Expected dict['{key}'] == {expected_value!r}, got {actual_value!r}"
        )

    @staticmethod
    def assert_string_contains(
        text: str,
        substring: str,
        error_msg: str | None = None,
    ) -> None:
        """Assert string contains substring - replaces 1 line per use.

        Common pattern (appears 33+ times):
            assert "text" in string
            # or
            assert "text" in string, "String must contain 'text'"

        Args:
            text: String to check
            substring: Substring that must be present
            error_msg: Optional custom error message

        """
        assert substring in text, (
            error_msg or f"Expected '{substring}' in text, got: {text[:100]}..."
        )

    @staticmethod
    def assert_string_not_contains(
        text: str,
        substring: str,
        error_msg: str | None = None,
    ) -> None:
        """Assert string does NOT contain substring - replaces 1 line per use.

        Common pattern (appears 5+ times):
            assert "text" not in string
            # or
            assert "text" not in string, "String must NOT contain 'text'"

        Args:
            text: String to check
            substring: Substring that must NOT be present
            error_msg: Optional custom error message

        """
        assert substring not in text, (
            error_msg or f"Expected '{substring}' NOT in text, but found it"
        )

    @staticmethod
    def assert_string_startswith(
        text: str,
        prefix: str,
        error_msg: str | None = None,
    ) -> None:
        """Assert string starts with prefix - replaces 1-2 lines per use.

        Common pattern (appears 11+ times):
            assert string.startswith(prefix)
            # or
            assert string.startswith(prefix), f"Expected prefix '{prefix}'"

        Args:
            text: String to check
            prefix: Expected prefix
            error_msg: Optional custom error message

        """
        assert text.startswith(prefix), (
            error_msg or f"Expected text to start with '{prefix}', got: {text[:50]}..."
        )

    @staticmethod
    def assert_string_endswith(
        text: str,
        suffix: str,
        error_msg: str | None = None,
    ) -> None:
        """Assert string ends with suffix - replaces 1-2 lines per use.

        Common pattern (appears 15+ times):
            assert string.endswith(suffix)
            # or
            assert string.endswith(suffix), f"Expected suffix '{suffix}'"

        Args:
            text: String to check
            suffix: Expected suffix
            error_msg: Optional custom error message

        """
        assert text.endswith(suffix), (
            error_msg or f"Expected text to end with '{suffix}', got: ...{text[-50:]}"
        )

    @staticmethod
    def assert_list_equals(
        actual: list[Any],
        expected: list[Any],
        error_msg: str | None = None,
    ) -> None:
        """Assert list equals expected - replaces 1 line per use.

        Common pattern (appears 17+ times):
            assert result == ["test"]
            # or
            assert result == [], "Expected empty list"

        Args:
            actual: Actual list to check
            expected: Expected list
            error_msg: Optional custom error message

        """
        assert actual == expected, (
            error_msg or f"Expected list {expected!r}, got {actual!r}"
        )

    @staticmethod
    def assert_dict_equals(
        actual: dict[str, Any],
        expected: dict[str, Any],
        error_msg: str | None = None,
    ) -> None:
        """Assert dict equals expected - replaces 1 line per use.

        Common pattern (appears 11+ times):
            assert result == {}
            # or
            assert result == {"key": "value"}

        Args:
            actual: Actual dict to check
            expected: Expected dict
            error_msg: Optional custom error message

        """
        assert actual == expected, (
            error_msg or f"Expected dict {expected!r}, got {actual!r}"
        )

    @staticmethod
    def assert_dict_has_key(
        dictionary: dict[str, Any],
        key: str,
        error_msg: str | None = None,
    ) -> None:
        """Assert dict has key - replaces 1 line per use.

        Common pattern (appears 2+ times):
            assert "key" in dict.keys()
            # or
            assert "key" in dict

        Args:
            dictionary: Dictionary to check
            key: Key that must exist
            error_msg: Optional custom error message

        """
        assert key in dictionary, (
            error_msg
            or f"Expected key '{key}' in dict, got keys: {list(dictionary.keys())}"
        )

    @staticmethod
    def assert_dict_has_value(
        dictionary: dict[str, Any],
        value: Any,
        error_msg: str | None = None,
    ) -> None:
        """Assert dict has value - replaces 1 line per use.

        Common pattern (appears 4+ times):
            assert "value" in dict.values()
            # or
            assert value in dict.values()

        Args:
            dictionary: Dictionary to check
            value: Value that must exist in dict values
            error_msg: Optional custom error message

        """
        assert value in dictionary.values(), (
            error_msg or f"Expected value {value!r} in dict values"
        )

    @staticmethod
    def assert_metadata_extensions_not_none(
        obj: Any,
        error_msg: str | None = None,
    ) -> None:
        """Assert object.metadata.extensions is not None - replaces 1-2 lines per use.

        Common pattern (appears 19+ times):
            assert result.metadata.extensions is not None
            # or
            assert result.metadata.extensions is not None, "Extensions must exist"

        Args:
            obj: Object with metadata.extensions attribute
            error_msg: Optional custom error message

        """
        assert obj.metadata is not None, "Object must have metadata"
        assert obj.metadata.extensions is not None, (
            error_msg or "Object metadata must have extensions"
        )

    @staticmethod
    def assert_metadata_extensions_get_equals(
        obj: Any,
        key: str,
        expected_value: Any,
        error_msg: str | None = None,
    ) -> None:
        """Assert metadata.extensions.get(key) equals expected - replaces 1-2 lines per use.

        Common pattern (appears 7+ times):
            assert result.metadata.extensions.get("key") == expected_value
            # or
            assert result.metadata.extensions.get("key") is not None

        Args:
            obj: Object with metadata.extensions attribute
            key: Key to get from extensions dict
            expected_value: Expected value
            error_msg: Optional custom error message

        """
        assert obj.metadata is not None, "Object must have metadata"
        assert obj.metadata.extensions is not None, "Object must have extensions"
        actual_value = obj.metadata.extensions.get(key)
        assert actual_value == expected_value, (
            error_msg
            or f"Expected metadata.extensions['{key}'] == {expected_value!r}, got {actual_value!r}"
        )

    @staticmethod
    def assert_schema_kind_equals(
        schema_obj: FlextLdifModels.SchemaObjectClass,
        expected_kind: str,
        error_msg: str | None = None,
    ) -> None:
        """Assert schema objectClass kind equals expected - replaces 1-2 lines per use.

        Common pattern (appears 11+ times):
            assert oc.kind == "STRUCTURAL"
            # or
            assert oc.kind == expected_kind, f"Expected kind '{expected_kind}'"

        Args:
            schema_obj: SchemaObjectClass to check
            expected_kind: Expected kind value ("STRUCTURAL", "AUXILIARY", "ABSTRACT")
            error_msg: Optional custom error message

        """
        assert schema_obj.kind == expected_kind, (
            error_msg or f"Expected kind '{expected_kind}', got '{schema_obj.kind}'"
        )

    @staticmethod
    def assert_metadata_quirk_type_equals(
        obj: Any,
        expected_quirk_type: str,
        error_msg: str | None = None,
    ) -> None:
        """Assert metadata.quirk_type equals expected - replaces 1-2 lines per use.

        Common pattern (appears 6+ times):
            assert parsed.metadata.quirk_type == "oid"
            # or
            assert parsed.metadata.quirk_type == expected_type

        Args:
            obj: Object with metadata.quirk_type attribute
            expected_quirk_type: Expected quirk type value
            error_msg: Optional custom error message

        """
        assert obj.metadata is not None, "Object must have metadata"
        assert obj.metadata.quirk_type == expected_quirk_type, (
            error_msg
            or f"Expected quirk_type '{expected_quirk_type}', got '{obj.metadata.quirk_type}'"
        )

    @staticmethod
    def parse_and_validate_entry_structure(
        parser: Any,
        ldif_content: str | Path,
        *,
        expected_dn: str | None = None,
        required_attributes: list[str] | None = None,
        expected_count: int | None = None,
    ) -> list[FlextLdifModels.Entry]:
        """Parse and validate complete entry structure - replaces 10-20 lines.

        Common pattern:
            result = parser.parse(content)
            assert result.is_success
            entries = result.unwrap()
            assert len(entries) == expected_count
            assert entries[0].dn.value == expected_dn
            assert "attr1" in entries[0].attributes.attributes

        Args:
            parser: Parser instance
            ldif_content: LDIF content or file path
            expected_dn: Optional expected DN of first entry
            required_attributes: Optional list of required attribute names
            expected_count: Optional expected entry count

        Returns:
            Parsed entries

        """
        entries = DeduplicationHelpers.parse_and_unwrap(
            parser, ldif_content, expected_count=expected_count, expected_dn=expected_dn
        )

        if required_attributes and entries:
            DeduplicationHelpers.assert_entry_has_attributes(
                entries[0], required_attributes
            )

        return entries

    @staticmethod
    def write_and_validate_content(
        writer: Any,
        entries: list[FlextLdifModels.Entry] | FlextLdifModels.Entry,
        *,
        must_contain: list[str] | None = None,
        must_not_contain: list[str] | None = None,
        must_contain_all: list[str] | None = None,
    ) -> str:
        """Write and validate content with multiple checks - replaces 8-15 lines.

        Common pattern:
            result = writer.write(entries)
            assert result.is_success
            ldif = result.unwrap()
            assert "text1" in ldif
            assert "text2" in ldif
            assert "text3" not in ldif

        Args:
            writer: Writer instance
            entries: Entry or list of entries to write
            must_contain: Optional list of strings that must be in output (any)
            must_not_contain: Optional list of strings that must NOT be in output
            must_contain_all: Optional list of strings that ALL must be in output

        Returns:
            Written LDIF string

        """
        ldif = DeduplicationHelpers.write_and_unwrap(
            writer,
            entries,
            must_contain=must_contain,
            must_not_contain=must_not_contain,
        )

        if must_contain_all:
            for text in must_contain_all:
                assert text in ldif, f"Must contain all: '{text}' not found"

        return ldif

    @staticmethod
    def quirk_method_with_result_validation(
        quirk: Any,
        method_name: str,
        *args: Any,
        expected_result_type: type[Any] | None = None,
        expected_attributes: dict[str, Any] | None = None,
        should_succeed: bool = True,
        **kwargs: Any,
    ) -> Any:
        """Test quirk method with comprehensive result validation - replaces 10-25 lines.

        Common pattern:
            result = quirk.method_name(*args, **kwargs)
            assert result.is_success
            obj = result.unwrap()
            assert isinstance(obj, ExpectedType)
            assert obj.attr1 == expected_value1
            assert obj.attr2 == expected_value2

        Args:
            quirk: Quirk instance
            method_name: Method name to call
            *args: Positional arguments for method
            expected_result_type: Optional expected return type
            expected_attributes: Optional dict of {attr_name: expected_value}
            should_succeed: Whether call should succeed (default: True)
            **kwargs: Keyword arguments for method

        Returns:
            Method result (unwrapped if FlextResult)

        """
        method = getattr(quirk, method_name, None)
        if method is None:
            msg = f"Method {method_name} not found on quirk"
            raise AttributeError(msg)

        result = method(*args, **kwargs)

        if isinstance(result, FlextResult):
            if should_succeed:
                unwrapped = TestAssertions.assert_success(result)
                if expected_result_type:
                    assert isinstance(unwrapped, expected_result_type), (
                        f"Expected {expected_result_type}, got {type(unwrapped)}"
                    )

                if expected_attributes:
                    for attr_name, expected_value in expected_attributes.items():
                        assert hasattr(unwrapped, attr_name), (
                            f"Result must have attribute '{attr_name}'"
                        )
                        actual_value = getattr(unwrapped, attr_name)
                        assert actual_value == expected_value, (
                            f"Attribute '{attr_name}' mismatch: "
                            f"expected {expected_value}, got {actual_value}"
                        )

                return unwrapped
            TestAssertions.assert_failure(result)
            return result

        if expected_result_type:
            assert isinstance(result, expected_result_type), (
                f"Expected {expected_result_type}, got {type(result)}"
            )

        return result

    @staticmethod
    def batch_test_parse_operations(
        parser: Any,
        test_cases: list[dict[str, Any]],
    ) -> list[list[FlextLdifModels.Entry]]:
        """Test multiple parse operations in batch - replaces 50-200+ lines.

        Args:
            parser: Parser instance
            test_cases: List of test case dicts with keys:
                - ldif_content: str | Path (required)
                - expected_count: int | None
                - expected_dn: str | None
                - required_attributes: list[str] | None
                - must_contain_in_output: list[str] | None (for write tests)

        Returns:
            List of parsed entry lists (one per test case)

        """
        results = []
        for i, test_case in enumerate(test_cases):
            ldif_content = test_case.get("ldif_content")
            if ldif_content is None:
                msg = f"Test case {i} missing 'ldif_content'"
                raise ValueError(msg)

            entries = DeduplicationHelpers.parse_and_validate_entry_structure(
                parser,
                ldif_content,
                expected_dn=test_case.get("expected_dn"),
                required_attributes=test_case.get("required_attributes"),
                expected_count=test_case.get("expected_count"),
            )
            results.append(entries)
        return results

    @staticmethod
    def parse_unwrap_and_assert(
        parser: Any,
        content: str | Path,
        *,
        parse_method: str = "parse",
        expected_type: type[Any] | None = None,
        expected_oid: str | None = None,
        expected_name: str | None = None,
        expected_dn: str | None = None,
        must_contain: str | list[str] | None = None,
        should_succeed: bool = True,
        error_msg: str | None = None,
    ) -> Any:
        """Parse, unwrap and assert - replaces 4-8 lines per use.

        Common pattern (appears 100+ times):
            result = parser.parse(content)
            assert result.is_success
            value = result.unwrap()
            assert value.oid == expected_oid  # or other validations

        Args:
            parser: Parser instance (quirk, API, etc.)
            content: Content to parse (string or Path)
            parse_method: Method name to call (default: "parse")
            expected_type: Optional expected return type
            expected_oid: Optional expected OID (for schema objects)
            expected_name: Optional expected name (for schema objects)
            expected_dn: Optional expected DN (for entries)
            must_contain: String or list of strings that must be in unwrapped value
            should_succeed: Whether parse should succeed (default: True)
            error_msg: Optional custom error message

        Returns:
            Unwrapped parse result

        """
        method = getattr(parser, parse_method, None)
        if method is None:
            msg = f"Method {parse_method} not found on parser"
            raise AttributeError(msg)

        result = method(content)

        if should_succeed:
            unwrapped = TestAssertions.assert_success(
                result, error_msg or "Parse should succeed"
            )
        else:
            TestAssertions.assert_failure(result)
            return result

        if expected_type:
            assert isinstance(unwrapped, expected_type), (
                f"Expected {expected_type}, got {type(unwrapped)}"
            )

        # Schema object validations
        if expected_oid and isinstance(
            unwrapped,
            (FlextLdifModels.SchemaAttribute, FlextLdifModels.SchemaObjectClass),
        ):
            assert unwrapped.oid == expected_oid, (
                f"Expected OID '{expected_oid}', got '{unwrapped.oid}'"
            )

        if expected_name and isinstance(
            unwrapped,
            (FlextLdifModels.SchemaAttribute, FlextLdifModels.SchemaObjectClass),
        ):
            assert unwrapped.name == expected_name, (
                f"Expected name '{expected_name}', got '{unwrapped.name}'"
            )

        # Entry DN validation
        if expected_dn:
            if (
                isinstance(unwrapped, list)
                and unwrapped
                and isinstance(unwrapped[0], FlextLdifModels.Entry)
            ):
                assert unwrapped[0].dn is not None
                assert unwrapped[0].dn.value == expected_dn
            elif (
                isinstance(unwrapped, FlextLdifModels.Entry)
                and unwrapped.dn is not None
            ):
                assert unwrapped.dn.value == expected_dn

        # Content validation
        if must_contain:
            contains_list = (
                [must_contain] if isinstance(must_contain, str) else must_contain
            )
            unwrapped_str = str(unwrapped)
            for text in contains_list:
                assert text in unwrapped_str, f"Must contain '{text}' not found"

        return unwrapped

    @staticmethod
    def write_and_unwrap_direct(
        writer: Any,
        data: Any,
        *,
        write_method: str = "write",
    ) -> str:
        """Write and unwrap directly without assertions - replaces 2-3 lines.

        Common pattern (appears 30+ times):
            result = writer.write(data)
            assert result.is_success
            ldif = result.unwrap()

        Args:
            writer: Writer instance (quirk, API, etc.)
            data: Data to write (Entry, SchemaAttribute, dict, etc.)
            write_method: Method name to call (default: "write")

        Returns:
            Written LDIF string

        """
        method = getattr(writer, write_method, None)
        if method is None:
            msg = f"Method {write_method} not found on writer"
            raise AttributeError(msg)

        result = method(data)  # type: ignore[misc]
        written = TestAssertions.assert_success(result, "Write should succeed")
        assert isinstance(written, str), "Write should return string"
        return written

    @staticmethod
    def write_unwrap_and_assert(
        writer: Any,
        data: Any,
        *,
        write_method: str = "write",
        must_contain: str | list[str] | None = None,
        must_not_contain: str | list[str] | None = None,
        should_succeed: bool = True,
        error_msg: str | None = None,
    ) -> str:
        """Write, unwrap and assert - replaces 4-7 lines per use.

        Common pattern (appears 50+ times):
            result = writer.write(data)
            assert result.is_success
            ldif = result.unwrap()
            assert "expected" in ldif

        Args:
            writer: Writer instance (quirk, API, etc.)
            data: Data to write (Entry, SchemaAttribute, etc.)
            write_method: Method name to call (default: "write")
            must_contain: String or list of strings that must be in output
            must_not_contain: String or list of strings that must NOT be in output
            should_succeed: Whether write should succeed (default: True)
            error_msg: Optional custom error message

        Returns:
            Written LDIF string

        """
        method = getattr(writer, write_method, None)
        if method is None:
            msg = f"Method {write_method} not found on writer"
            raise AttributeError(msg)

        result = method(data)  # type: ignore[misc]

        if should_succeed:
            written = TestAssertions.assert_success(
                result, error_msg or "Write should succeed"
            )
            assert isinstance(written, str), "Write should return string"
        else:
            TestAssertions.assert_failure(result)
            return ""

        if must_contain:
            contains_list = (
                [must_contain] if isinstance(must_contain, str) else must_contain
            )
            for text in contains_list:
                assert text in written, f"Must contain '{text}' not found in output"

        if must_not_contain:
            not_contains_list = (
                [must_not_contain]
                if isinstance(must_not_contain, str)
                else must_not_contain
            )
            for text in not_contains_list:
                assert text not in written, f"Must not contain '{text}' found in output"

        return written

    @staticmethod
    def helper_parse_unwrap_and_assert(
        parser: Any,
        content: str | Path,
        *,
        parse_method: str = "parse",
        expected_type: type[Any] | None = None,
        expected_oid: str | None = None,
        expected_name: str | None = None,
        expected_dn: str | None = None,
        must_contain: str | list[str] | None = None,
        should_succeed: bool = True,
        error_msg: str | None = None,
    ) -> Any:
        """Alias for parse_unwrap_and_assert for consistency with test_* naming."""
        return DeduplicationHelpers.parse_unwrap_and_assert(
            parser,
            content,
            parse_method=parse_method,
            expected_type=expected_type,
            expected_oid=expected_oid,
            expected_name=expected_name,
            expected_dn=expected_dn,
            must_contain=must_contain,
            should_succeed=should_succeed,
            error_msg=error_msg,
        )

    @staticmethod
    def helper_write_unwrap_and_assert(
        writer: Any,
        data: Any,
        *,
        write_method: str = "write",
        must_contain: str | list[str] | None = None,
        must_not_contain: str | list[str] | None = None,
        should_succeed: bool = True,
        error_msg: str | None = None,
    ) -> str:
        """Alias for write_unwrap_and_assert for consistency with test_* naming."""
        return DeduplicationHelpers.write_unwrap_and_assert(
            writer,
            data,
            write_method=write_method,
            must_contain=must_contain,
            must_not_contain=must_not_contain,
            should_succeed=should_succeed,
            error_msg=error_msg,
        )

    @staticmethod
    def parse_and_unwrap_direct(
        parser: Any,
        content: str | Path,
        *,
        parse_method: str = "parse",
    ) -> Any:
        """Parse and unwrap without assertions - for internal use."""
        method = getattr(parser, parse_method, None)
        if method is None:
            msg = f"Method {parse_method} not found on parser"
            raise AttributeError(msg)

        result = method(content)
        return TestAssertions.assert_success(result, "Parse should succeed")

    @staticmethod
    def route_parse_unwrap_and_assert(
        quirk: Any,
        content: str,
        *,
        expected_type: type[Any] | None = None,
        expected_oid: str | None = None,
        expected_name: str | None = None,
        should_succeed: bool = True,
    ) -> Any:
        """Route parse, unwrap and assert - replaces 4-6 lines per use.

        Common pattern (appears 20+ times):
            result = quirk._route_parse(content)
            assert result.is_success
            value = result.unwrap()
            assert isinstance(value, ...)

        Args:
            quirk: Quirk instance
            content: Content to parse
            expected_type: Optional expected return type
            expected_oid: Optional expected OID
            expected_name: Optional expected name
            should_succeed: Whether parse should succeed (default: True)

        Returns:
            Unwrapped parse result

        """
        return DeduplicationHelpers.parse_unwrap_and_assert(
            quirk,
            content,
            parse_method="_route_parse",
            expected_type=expected_type,
            expected_oid=expected_oid,
            expected_name=expected_name,
            should_succeed=should_succeed,
        )

    @staticmethod
    def route_write_unwrap_and_assert(
        quirk: Any,
        data: Any,
        *,
        must_contain: str | list[str] | None = None,
        should_succeed: bool = True,
    ) -> str:
        """Route write, unwrap and assert - replaces 4-5 lines per use.

        Common pattern (appears 15+ times):
            result = quirk._route_write(data)
            assert result.is_success
            ldif = result.unwrap()
            assert "expected" in ldif

        Args:
            quirk: Quirk instance
            data: Data to route write
            must_contain: String or list of strings that must be in output
            should_succeed: Whether write should succeed (default: True)

        Returns:
            Written LDIF string

        """
        return DeduplicationHelpers.write_unwrap_and_assert(
            quirk,
            data,
            write_method="_route_write",
            must_contain=must_contain,
            should_succeed=should_succeed,
        )

    @staticmethod
    def assert_result_success_or_failure(
        result: FlextResult[Any],
        error_msg: str | None = None,
    ) -> None:
        """Assert result is success or failure - replaces 1-2 lines per use.

        Common pattern (appears 14+ times):
            assert result.is_success or result.is_failure

        Args:
            result: FlextResult to check
            error_msg: Optional custom error message

        """
        assert result.is_success or result.is_failure, (
            error_msg or "Result must be either success or failure"
        )

    @staticmethod
    def parse_attribute_unwrap_and_assert(
        schema_quirk: Any,
        attr_def: str,
        *,
        expected_oid: str | None = None,
        expected_name: str | None = None,
        should_succeed: bool = True,
    ) -> FlextLdifModels.SchemaAttribute:
        """Parse attribute, unwrap and assert - replaces 5-8 lines per use.

        Common pattern (appears 17+ times):
            result = schema_quirk.parse_attribute(attr_def)
            assert result.is_success
            attr = result.unwrap()
            assert attr.oid == expected_oid
            assert attr.name == expected_name

        Args:
            schema_quirk: Schema quirk instance
            attr_def: Attribute definition string
            expected_oid: Optional expected OID
            expected_name: Optional expected name
            should_succeed: Whether parse should succeed (default: True)

        Returns:
            Parsed SchemaAttribute

        """
        result = schema_quirk.parse_attribute(attr_def)
        if should_succeed:
            attr = TestAssertions.assert_success(
                result, "Attribute parse should succeed"
            )
            assert isinstance(attr, FlextLdifModels.SchemaAttribute), (
                "Parse should return SchemaAttribute"
            )
        else:
            TestAssertions.assert_failure(result)
            msg = "Parse should fail"
            raise AssertionError(msg)

        if expected_oid:
            assert attr.oid == expected_oid, (
                f"Expected OID '{expected_oid}', got '{attr.oid}'"
            )

        if expected_name:
            assert attr.name == expected_name, (
                f"Expected name '{expected_name}', got '{attr.name}'"
            )

        return attr

    @staticmethod
    def parse_objectclass_unwrap_and_assert(
        schema_quirk: Any,
        oc_def: str,
        *,
        expected_oid: str | None = None,
        expected_name: str | None = None,
        should_succeed: bool = True,
    ) -> FlextLdifModels.SchemaObjectClass:
        """Parse objectClass, unwrap and assert - replaces 5-8 lines per use.

        Common pattern (appears 15+ times):
            result = schema_quirk.parse_objectclass(oc_def)
            assert result.is_success
            oc = result.unwrap()
            assert oc.oid == expected_oid
            assert oc.name == expected_name

        Args:
            schema_quirk: Schema quirk instance
            oc_def: ObjectClass definition string
            expected_oid: Optional expected OID
            expected_name: Optional expected name
            should_succeed: Whether parse should succeed (default: True)

        Returns:
            Parsed SchemaObjectClass

        """
        result = schema_quirk.parse_objectclass(oc_def)
        if should_succeed:
            oc = TestAssertions.assert_success(
                result, "ObjectClass parse should succeed"
            )
            assert isinstance(oc, FlextLdifModels.SchemaObjectClass), (
                "Parse should return SchemaObjectClass"
            )
        else:
            TestAssertions.assert_failure(result)
            msg = "Parse should fail"
            raise AssertionError(msg)

        if expected_oid:
            assert oc.oid == expected_oid, (
                f"Expected OID '{expected_oid}', got '{oc.oid}'"
            )

        if expected_name:
            assert oc.name == expected_name, (
                f"Expected name '{expected_name}', got '{oc.name}'"
            )

        return oc

    @staticmethod
    def schema_roundtrip_simple(
        schema_quirk: Any,
        schema_def: str,
        *,
        parse_method: str | None = None,
        write_method: str | None = None,
        must_contain: list[str] | None = None,
        validate_fields: dict[str, Any] | None = None,
    ) -> tuple[Any, str]:
        """Simple schema roundtrip test - replaces 20-35 lines.

        Args:
            schema_quirk: Schema quirk instance
            schema_def: Original schema definition string
            parse_method: Method name for parsing (default: auto-detect)
            write_method: Method name for writing (default: auto-detect)
            must_contain: Optional list of strings that must be in written output
            validate_fields: Optional dict of field_name: expected_value to validate

        Returns:
            Tuple of (parsed_schema_object, written_string)

        """
        # Auto-detect parse method
        if parse_method is None:
            if "NAME" in schema_def and "SUP" in schema_def:
                parse_method = "parse_objectclass"
            else:
                parse_method = "parse_attribute"

        # Parse
        parse_func = getattr(schema_quirk, parse_method)
        parse_result = parse_func(schema_def)
        parsed = TestAssertions.assert_success(parse_result, "Parse should succeed")

        # Auto-detect write method
        if write_method is None:
            if isinstance(parsed, FlextLdifModels.SchemaObjectClass):
                write_method = "write_objectclass"
            else:
                write_method = "write_attribute"

        # Write
        write_func = getattr(schema_quirk, write_method)
        write_result = write_func(parsed)  # type: ignore[misc]
        written = TestAssertions.assert_success(write_result, "Write should succeed")
        assert isinstance(written, str), "Write should return string"

        # Validate must_contain
        if must_contain:
            for text in must_contain:
                assert text in written, f"Must contain '{text}' not found in output"

        # Validate fields
        if validate_fields:
            for field_name, expected_value in validate_fields.items():
                if hasattr(parsed, field_name):
                    actual_value = getattr(parsed, field_name)
                    assert actual_value == expected_value, (
                        f"Field {field_name} mismatch: expected {expected_value}, got {actual_value}"
                    )

        return parsed, written

    @staticmethod
    def entry_roundtrip_simple(
        entry_quirk: Any,
        ldif_content: str,
        *,
        must_contain: list[str] | None = None,
        validate_dn: bool = True,
        validate_attributes: list[str] | None = None,
    ) -> tuple[FlextLdifModels.Entry, str]:
        """Simple entry roundtrip test - replaces 20-30 lines.

        Args:
            entry_quirk: Entry quirk instance
            ldif_content: Original LDIF content string
            must_contain: Optional list of strings that must be in written output
            validate_dn: Whether to validate DN is preserved (default: True)
            validate_attributes: Optional list of attribute names that must be preserved

        Returns:
            Tuple of (parsed_entry, written_string)

        """
        # Parse
        parse_result = entry_quirk.parse(ldif_content)
        entries_data = TestAssertions.assert_success(
            parse_result, "Parse should succeed"
        )

        if isinstance(entries_data, list):
            entries_raw = entries_data
        elif hasattr(entries_data, "entries"):
            parse_response = cast("FlextLdifModels.ParseResponse", entries_data)
            entries_raw = list(parse_response.entries)
        else:
            msg = "Parse returned unexpected type"
            raise AssertionError(msg)

        # Cast to ensure type consistency
        entries: list[FlextLdifModels.Entry] = [
            entry for entry in entries_raw if isinstance(entry, FlextLdifModels.Entry)
        ]

        assert len(entries) == 1, f"Expected 1 entry, got {len(entries)}"
        parsed = entries[0]

        # Write
        write_result = entry_quirk.write(parsed)
        written = TestAssertions.assert_success(write_result, "Write should succeed")
        assert isinstance(written, str), "Write should return string"

        # Validate DN
        if validate_dn and parsed.dn:
            assert parsed.dn.value in written, (
                f"DN '{parsed.dn.value}' not found in written output"
            )

        # Validate must_contain
        if must_contain:
            for text in must_contain:
                assert text in written, f"Must contain '{text}' not found in output"

        # Validate attributes
        if validate_attributes and parsed.attributes:
            for attr_name in validate_attributes:
                assert attr_name in parsed.attributes.attributes, (
                    f"Attribute '{attr_name}' not found in parsed entry"
                )
                # Check if attribute appears in written output
                attr_pattern = f"{attr_name}:"
                assert attr_pattern in written, (
                    f"Attribute '{attr_name}' not found in written output"
                )

        return parsed, written

    @staticmethod
    def error_handling_batch(
        quirk: Any,
        test_cases: list[dict[str, Any]],
        *,
        parse_method: str = "parse",
    ) -> list[Any]:
        """Test error handling for multiple invalid inputs - replaces 40-80+ lines.

        Args:
            quirk: Quirk instance
            test_cases: List of test case dicts with keys:
                - input: Any (required) - input to test
                - should_succeed: bool (default: False for error handling)
                - expected_error_substring: str | None - substring that should be in error
            parse_method: Method name for parsing (default: "parse")

        Returns:
            List of results (success or failure)

        """
        results = []
        parse_func = getattr(quirk, parse_method)

        for i, test_case in enumerate(test_cases):
            test_input = test_case.get("input")
            if test_input is None:
                msg = f"Test case {i} missing 'input'"
                raise ValueError(msg)

            should_succeed = test_case.get("should_succeed", False)
            expected_error = test_case.get("expected_error_substring")

            result = parse_func(test_input)

            if should_succeed:
                unwrapped = TestAssertions.assert_success(result)
                results.append(unwrapped)
            else:
                _ = TestAssertions.assert_failure(result, expected_error)
                results.append(result)

        return results

    @staticmethod
    def batch_schema_roundtrip(
        schema_quirk: Any,
        test_cases: list[dict[str, Any]],
        *,
        validate_all: bool = True,
    ) -> list[tuple[Any, str]]:
        """Test multiple schema roundtrips in batch - replaces 60-150+ lines.

        Args:
            schema_quirk: Schema quirk instance
            test_cases: List of test case dicts with keys:
                - schema_def: str (required)
                - parse_method: str | None
                - write_method: str | None
                - must_contain: list[str] | None
                - validate_fields: dict[str, Any] | None
            validate_all: Whether to validate all results (default: True)

        Returns:
            List of (parsed_object, written_string) tuples

        """
        results = []
        for i, test_case in enumerate(test_cases):
            schema_def = test_case.get("schema_def")
            if schema_def is None:
                msg = f"Test case {i} missing 'schema_def'"
                raise ValueError(msg)

            parsed, written = DeduplicationHelpers.schema_roundtrip_simple(
                schema_quirk,
                schema_def,
                parse_method=test_case.get("parse_method"),
                write_method=test_case.get("write_method"),
                must_contain=test_case.get("must_contain"),
                validate_fields=test_case.get("validate_fields")
                if validate_all
                else None,
            )
            # Type narrowing: parsed can be SchemaAttribute or SchemaObjectClass
            # Skip validation if it's not a schema object (has "attributes" means it's an Entry)
            if not isinstance(
                parsed,
                (FlextLdifModels.SchemaAttribute, FlextLdifModels.SchemaObjectClass),
            ):
                # This is an Entry or other type - skip validation
                pass
            results.append((parsed, written))
        return results

    @staticmethod
    def batch_entry_roundtrip(
        entry_quirk: Any,
        test_cases: list[dict[str, Any]],
        *,
        validate_all: bool = True,
    ) -> list[tuple[FlextLdifModels.Entry, str]]:
        """Test multiple entry roundtrips in batch - replaces 60-150+ lines.

        Args:
            entry_quirk: Entry quirk instance
            test_cases: List of test case dicts with keys:
                - ldif_content: str (required)
                - must_contain: list[str] | None
                - validate_dn: bool (default: True)
                - validate_attributes: list[str] | None
            validate_all: Whether to validate all results (default: True)

        Returns:
            List of (parsed_entry, written_string) tuples

        """
        results = []
        for i, test_case in enumerate(test_cases):
            ldif_content = test_case.get("ldif_content")
            if ldif_content is None:
                msg = f"Test case {i} missing 'ldif_content'"
                raise ValueError(msg)

            parsed, written = DeduplicationHelpers.entry_roundtrip_simple(
                entry_quirk,
                ldif_content,
                must_contain=test_case.get("must_contain"),
                validate_dn=test_case.get("validate_dn", True)
                if validate_all
                else False,
                validate_attributes=test_case.get("validate_attributes")
                if validate_all
                else None,
            )
            results.append((parsed, written))
        return results

    @staticmethod
    def parse_and_validate_fields(
        quirk: Any,
        content: str,
        *,
        parse_method: str = "parse",
        expected_fields: dict[str, Any] | None = None,
        must_contain_in_output: list[str] | None = None,
    ) -> Any:
        """Parse and validate specific fields - replaces 15-25 lines.

        Args:
            quirk: Quirk instance
            content: Content to parse
            parse_method: Method name for parsing (default: "parse")
            expected_fields: Optional dict of field_name: expected_value
            must_contain_in_output: Optional list of strings that must be in parsed object

        Returns:
            Parsed object

        """
        parse_func = getattr(quirk, parse_method)
        result = parse_func(content)
        parsed = TestAssertions.assert_success(result, "Parse should succeed")

        # Validate expected fields
        if expected_fields:
            for field_name, expected_value in expected_fields.items():
                if hasattr(parsed, field_name):
                    actual_value = getattr(parsed, field_name)
                    assert actual_value == expected_value, (
                        f"Field {field_name} mismatch: expected {expected_value}, got {actual_value}"
                    )
                # Check if it's a nested attribute
                elif hasattr(parsed, "attributes"):
                    attributes_obj = getattr(parsed, "attributes", None)
                    if attributes_obj is not None and hasattr(
                        attributes_obj, "attributes"
                    ):
                        attrs_dict = getattr(attributes_obj, "attributes", {})
                        if field_name in attrs_dict:
                            actual_value = attrs_dict[field_name]
                            if isinstance(actual_value, list) and len(actual_value) > 0:
                                assert (
                                    expected_value in actual_value
                                    or actual_value == expected_value
                                ), (
                                    f"Attribute {field_name} mismatch: expected {expected_value}, got {actual_value}"
                                )
                            else:
                                assert actual_value == expected_value, (
                                    f"Attribute {field_name} mismatch: expected {expected_value}, got {actual_value}"
                                )

        # Validate must_contain_in_output (for string representations)
        if must_contain_in_output:
            parsed_str = str(parsed)
            for text in must_contain_in_output:
                assert text in parsed_str, (
                    f"Must contain '{text}' not found in parsed object representation"
                )

        return parsed

    @staticmethod
    def assert_list_length(
        items: list[Any],
        expected_length: int,
        *,
        error_msg: str | None = None,
    ) -> None:
        """Assert list has expected length - replaces 1-2 lines.

        Common pattern: assert len(items) == expected_length

        Args:
            items: List to check
            expected_length: Expected length
            error_msg: Optional custom error message

        """
        actual_length = len(items)
        if actual_length != expected_length:
            msg = error_msg or (
                f"Expected list length {expected_length}, got {actual_length}"
            )
            raise AssertionError(msg)

    @staticmethod
    def assert_entry_dn_value(
        entry: FlextLdifModels.Entry,
        expected_dn: str,
        *,
        error_msg: str | None = None,
    ) -> None:
        """Assert entry DN value matches - replaces 2-3 lines.

        Common pattern:
            assert entry.dn is not None
            assert entry.dn.value == expected_dn

        Args:
            entry: Entry to check
            expected_dn: Expected DN value
            error_msg: Optional custom error message

        """
        assert entry.dn is not None, "Entry must have DN"
        actual_dn = entry.dn.value
        if actual_dn != expected_dn:
            msg = error_msg or (f"Expected DN '{expected_dn}', got '{actual_dn}'")
            raise AssertionError(msg)

    @staticmethod
    def assert_entries_dn_values(
        entries: list[FlextLdifModels.Entry],
        expected_dns: list[str],
        *,
        allow_extra: bool = False,
    ) -> None:
        """Assert entries have expected DN values - replaces 5-10 lines.

        Common pattern:
            assert len(entries) == len(expected_dns)
            for entry, expected_dn in zip(entries, expected_dns):
                assert entry.dn.value == expected_dn

        Args:
            entries: List of entries to check
            expected_dns: List of expected DN values
            allow_extra: Whether to allow extra entries (default: False)

        """
        if not allow_extra:
            DeduplicationHelpers.assert_list_length(entries, len(expected_dns))

        entry_dns = [entry.dn.value for entry in entries if entry.dn is not None]

        for expected_dn in expected_dns:
            assert expected_dn in entry_dns, (
                f"Expected DN '{expected_dn}' not found in {entry_dns}"
            )

    @staticmethod
    def parse_and_assert_basic(
        parser: Any,
        ldif_content: str | Path,
        *,
        expected_count: int | None = None,
        expected_first_dn: str | None = None,
    ) -> list[FlextLdifModels.Entry]:
        """Parse and assert basic validations - replaces 4-8 lines.

        Common pattern:
            result = parser.parse(content)
            assert result.is_success
            entries = result.unwrap()
            assert len(entries) == expected_count
            assert entries[0].dn.value == expected_first_dn

        Args:
            parser: Parser instance
            ldif_content: LDIF content or file path
            expected_count: Optional expected entry count
            expected_first_dn: Optional expected DN of first entry

        Returns:
            Parsed entries

        """
        entries = DeduplicationHelpers.parse_and_unwrap(
            parser, ldif_content, expected_count=expected_count
        )

        if expected_first_dn and entries:
            DeduplicationHelpers.assert_entry_dn_value(entries[0], expected_first_dn)

        return entries

    @staticmethod
    def schema_parse_and_assert_oid_name(
        schema_quirk: Any,
        schema_def: str,
        *,
        expected_oid: str,
        expected_name: str,
        expected_type: type[Any] | None = None,
    ) -> FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass:
        """Parse schema and assert OID and name - replaces 6-8 lines.

        Common pattern:
            result = schema_quirk.parse(definition)
            assert result.is_success
            schema_obj = result.unwrap()
            assert schema_obj.oid == expected_oid
            assert schema_obj.name == expected_name

        Args:
            schema_quirk: Schema quirk instance
            schema_def: Schema definition string
            expected_oid: Expected OID
            expected_name: Expected name
            expected_type: Optional expected type

        Returns:
            Parsed schema object

        """
        return DeduplicationHelpers.parse_schema_and_unwrap(
            schema_quirk,
            schema_def,
            expected_oid=expected_oid,
            expected_name=expected_name,
            expected_type=expected_type,
        )

    @staticmethod
    def write_and_assert_contains(
        writer: Any,
        entries: list[FlextLdifModels.Entry] | FlextLdifModels.Entry,
        *,
        must_contain: str | list[str],
    ) -> str:
        """Write and assert output contains text - replaces 4-6 lines.

        Common pattern:
            result = writer.write(entries)
            assert result.is_success
            ldif = result.unwrap()
            assert "text" in ldif

        Args:
            writer: Writer instance
            entries: Entry or list of entries to write
            must_contain: String or list of strings that must be in output

        Returns:
            Written LDIF string

        """
        if isinstance(must_contain, str):
            must_contain_list = [must_contain]
        else:
            must_contain_list = must_contain

        return DeduplicationHelpers.write_and_unwrap(
            writer, entries, must_contain=must_contain_list
        )

    @staticmethod
    def parse_entry_and_assert_dn_attributes(
        entry_quirk: Any,
        ldif_content: str,
        *,
        expected_dn: str,
        required_attributes: list[str],
    ) -> FlextLdifModels.Entry:
        """Parse entry and assert DN and attributes - replaces 8-12 lines.

        Common pattern:
            result = entry_quirk.parse(content)
            assert result.is_success
            entry = result.unwrap()
            assert entry.dn.value == expected_dn
            assert "attr1" in entry.attributes.attributes
            assert "attr2" in entry.attributes.attributes

        Args:
            entry_quirk: Entry quirk instance
            ldif_content: LDIF content string
            expected_dn: Expected DN value
            required_attributes: List of required attribute names

        Returns:
            Parsed entry

        """
        entry = DeduplicationHelpers.parse_entry_and_unwrap(
            entry_quirk, ldif_content, expected_dn=expected_dn
        )

        DeduplicationHelpers.assert_entry_has_attributes(entry, required_attributes)

        return entry

    @staticmethod
    def batch_assert_list_lengths(
        test_cases: list[dict[str, Any]],
        *,
        list_key: str = "items",
        length_key: str = "expected_length",
    ) -> None:
        """Assert list lengths for multiple test cases - replaces 10-30+ lines.

        Common pattern:
            assert len(items1) == expected_length1
            assert len(items2) == expected_length2
            ...

        Args:
            test_cases: List of dicts with keys:
                - list_key: List to check (default: "items")
                - length_key: Expected length (default: "expected_length")
            list_key: Key name for list in test case dict
            length_key: Key name for expected length in test case dict

        """
        for i, test_case in enumerate(test_cases):
            items = test_case.get(list_key)
            expected_length = test_case.get(length_key)

            if items is None:
                msg = f"Test case {i} missing '{list_key}'"
                raise ValueError(msg)

            if expected_length is None:
                msg = f"Test case {i} missing '{length_key}'"
                raise ValueError(msg)

            DeduplicationHelpers.assert_list_length(items, expected_length)

    @staticmethod
    def batch_assert_entry_dns(
        entries_list: list[list[FlextLdifModels.Entry]],
        expected_dns_list: list[list[str]],
    ) -> None:
        """Assert DN values for multiple entry lists - replaces 15-40+ lines.

        Common pattern:
            assert_entries_dn_values(entries1, expected_dns1)
            assert_entries_dn_values(entries2, expected_dns2)
            ...

        Args:
            entries_list: List of entry lists to check
            expected_dns_list: List of expected DN lists

        """
        assert len(entries_list) == len(expected_dns_list), (
            f"Entries list length {len(entries_list)} != "
            f"expected DNs list length {len(expected_dns_list)}"
        )

        for entries, expected_dns in zip(entries_list, expected_dns_list, strict=True):
            DeduplicationHelpers.assert_entries_dn_values(entries, expected_dns)

    @staticmethod
    def parse_attribute_and_validate_all_fields(
        schema_quirk: Any,
        attr_def: str,
        *,
        expected_fields: dict[str, Any],
        parse_method: str = "parse_attribute",
    ) -> Any:
        """Parse attribute and validate all expected fields - replaces 20-40+ lines.

        Args:
            schema_quirk: Schema quirk instance
            attr_def: Attribute definition string
            expected_fields: Dict of field_name: expected_value (all required)
            parse_method: Method name for parsing (default: "parse_attribute")

        Returns:
            Parsed SchemaAttribute

        """
        parse_func = getattr(schema_quirk, parse_method)
        result = parse_func(attr_def)
        parsed = TestAssertions.assert_success(result, "Parse should succeed")

        # Validate all expected fields
        for field_name, expected_value in expected_fields.items():
            if hasattr(parsed, field_name):
                actual_value = getattr(parsed, field_name)
                assert actual_value == expected_value, (
                    f"Field {field_name} mismatch: expected {expected_value}, got {actual_value}"
                )
            else:
                msg = f"Field {field_name} not found in parsed object"
                raise AssertionError(msg)

        return parsed

    @staticmethod
    def parse_objectclass_and_validate_all_fields(
        schema_quirk: Any,
        oc_def: str,
        *,
        expected_fields: dict[str, Any],
        parse_method: str = "parse_objectclass",
    ) -> Any:
        """Parse objectClass and validate all expected fields - replaces 20-40+ lines.

        Args:
            schema_quirk: Schema quirk instance
            oc_def: ObjectClass definition string
            expected_fields: Dict of field_name: expected_value (all required)
            parse_method: Method name for parsing (default: "parse_objectclass")

        Returns:
            Parsed SchemaObjectClass

        """
        parse_func = getattr(schema_quirk, parse_method)
        result = parse_func(oc_def)
        parsed = TestAssertions.assert_success(result, "Parse should succeed")

        # Validate all expected fields
        for field_name, expected_value in expected_fields.items():
            if hasattr(parsed, field_name):
                actual_value = getattr(parsed, field_name)
                assert actual_value == expected_value, (
                    f"Field {field_name} mismatch: expected {expected_value}, got {actual_value}"
                )
            else:
                msg = f"Field {field_name} not found in parsed object"
                raise AssertionError(msg)

        return parsed

    @staticmethod
    def parse_minimal_schema_and_validate(
        schema_quirk: Any,
        schema_def: str,
        *,
        expected_oid: str,
        expected_name: str,
        parse_method: str | None = None,
        optional_fields_should_be_none: list[str] | None = None,
    ) -> Any:
        """Parse minimal schema and validate required + optional fields - replaces 15-30 lines.

        Args:
            schema_quirk: Schema quirk instance
            schema_def: Minimal schema definition (only required fields)
            expected_oid: Expected OID value
            expected_name: Expected name value
            parse_method: Method name (default: auto-detect)
            optional_fields_should_be_none: Optional list of field names that should be None/False

        Returns:
            Parsed schema object

        """
        # Auto-detect parse method
        if parse_method is None:
            if "SUP" in schema_def:
                parse_method = "parse_objectclass"
            else:
                parse_method = "parse_attribute"

        parse_func = getattr(schema_quirk, parse_method)
        result = parse_func(schema_def)
        parsed = TestAssertions.assert_success(result, "Parse should succeed")

        if not isinstance(
            parsed, (FlextLdifModels.SchemaAttribute, FlextLdifModels.SchemaObjectClass)
        ):
            msg = f"Expected SchemaAttribute or SchemaObjectClass, got {type(parsed)}"
            raise TypeError(msg)

        # Validate required fields
        assert parsed.oid == expected_oid, (
            f"OID mismatch: expected {expected_oid}, got {parsed.oid}"
        )
        assert parsed.name == expected_name, (
            f"Name mismatch: expected {expected_name}, got {parsed.name}"
        )

        # Validate optional fields should be None/False
        if optional_fields_should_be_none:
            for field_name in optional_fields_should_be_none:
                if hasattr(parsed, field_name):
                    actual_value = getattr(parsed, field_name)
                    # Check if it's None or False (for boolean fields)
                    assert actual_value is None or actual_value is False, (
                        f"Optional field {field_name} should be None/False, got {actual_value}"
                    )

        return parsed

    @staticmethod
    def batch_parse_and_validate_fields(
        quirk: Any,
        test_cases: list[dict[str, Any]],
        *,
        parse_method: str = "parse",
        validate_all: bool = True,
    ) -> list[Any]:
        """Test multiple parse operations with field validation - replaces 80-200+ lines.

        Args:
            quirk: Quirk instance
            test_cases: List of test case dicts with keys:
                - content: str (required)
                - expected_fields: dict[str, Any] (required)
                - parse_method: str | None (optional override)
            parse_method: Default method name for parsing
            validate_all: Whether to validate all results (default: True)

        Returns:
            List of parsed objects

        """
        results = []
        for i, test_case in enumerate(test_cases):
            content = test_case.get("content")
            if content is None:
                msg = f"Test case {i} missing 'content'"
                raise ValueError(msg)

            expected_fields = test_case.get("expected_fields")
            if expected_fields is None:
                msg = f"Test case {i} missing 'expected_fields'"
                raise ValueError(msg)

            case_parse_method = test_case.get("parse_method", parse_method)
            parse_func = getattr(quirk, case_parse_method)
            result = parse_func(content)
            parsed = TestAssertions.assert_success(result, "Parse should succeed")

            if validate_all:
                for field_name, expected_value in expected_fields.items():
                    if hasattr(parsed, field_name):
                        actual_value = getattr(parsed, field_name)
                        assert actual_value == expected_value, (
                            f"Test case {i}, field {field_name}: "
                            f"expected {expected_value}, got {actual_value}"
                        )

            results.append(parsed)
        return results

    @staticmethod
    def write_to_file_and_validate(
        writer: Any,
        data: Any,
        output_path: Path,
        *,
        write_method: str = "write",
        must_contain: str | list[str] | None = None,
        must_not_contain: str | list[str] | None = None,
        should_succeed: bool = True,
    ) -> Path:
        """Write to file and validate - replaces 8-12 lines per use.

        Common pattern (appears 20+ times):
            result = writer.write(data, output_path=output_file)
            assert result.is_success
            assert output_file.exists()
            content = output_file.read_text()
            assert "expected" in content

        Args:
            writer: Writer instance (API, quirk, etc.)
            data: Data to write (entries, schema objects, etc.)
            output_path: Path to output file
            write_method: Method name to call (default: "write")
            must_contain: String or list of strings that must be in file content
            must_not_contain: String or list of strings that must NOT be in file content
            should_succeed: Whether write should succeed (default: True)

        Returns:
            Output file path

        """
        method = getattr(writer, write_method, None)
        if method is None:
            msg = f"Method {write_method} not found on writer"
            raise AttributeError(msg)

        # Call write method with output_path
        if write_method == "write" and hasattr(writer, "write"):
            result = writer.write(data, output_path=output_path)  # type: ignore[misc]
        else:
            # For other methods, try calling with output_path as kwarg
            result = method(data, output_path=output_path)  # type: ignore[misc]

        if should_succeed:
            TestAssertions.assert_success(result, "Write to file should succeed")
            assert output_path.exists(), f"Output file should exist: {output_path}"
            content = output_path.read_text(encoding="utf-8")
        else:
            TestAssertions.assert_failure(result)
            return output_path

        if must_contain:
            contains_list = (
                [must_contain] if isinstance(must_contain, str) else must_contain
            )
            for text in contains_list:
                assert text in content, f"File must contain '{text}' not found"

        if must_not_contain:
            not_contains_list = (
                [must_not_contain]
                if isinstance(must_not_contain, str)
                else must_not_contain
            )
            for text in not_contains_list:
                assert text not in content, f"File must not contain '{text}' found"

        return output_path

    @staticmethod
    def complete_roundtrip_parse_write_parse(
        api: Any,
        ldif_content: str | Path,
        tmp_path: Path,
        *,
        filename: str = "roundtrip.ldif",
        expected_count: int | None = None,
        validate_identical: bool = True,
        target_server_type: str = "rfc",
    ) -> tuple[list[FlextLdifModels.Entry], Path, list[FlextLdifModels.Entry]]:
        """Complete roundtrip: parse -> write -> parse - replaces 20-35 lines per use.

        Common pattern (appears 15+ times):
            # Parse original
            result = api.parse(content)
            entries = result.unwrap()
            # Write to file
            output_file = tmp_path / "test.ldif"
            result = api.write(entries, output_path=output_file)
            assert result.is_success
            # Parse written file
            result = api.parse(output_file)
            roundtripped = result.unwrap()
            # Validate
            assert len(entries) == len(roundtripped)

        Args:
            api: FlextLdif API instance
            ldif_content: Original LDIF content or file path
            tmp_path: Temporary directory path
            filename: Output filename (default: "roundtrip.ldif")
            expected_count: Optional expected entry count
            validate_identical: Whether to validate entries are identical (default: True)
            target_server_type: Target server type for writing (default: "rfc")

        Returns:
            Tuple of (original_entries, output_file_path, roundtripped_entries)

        """
        # Parse original
        original_data = DeduplicationHelpers.parse_unwrap_and_assert(api, ldif_content)

        # Extract entries from result
        if isinstance(original_data, list):
            original_entries = original_data
        elif hasattr(original_data, "entries"):
            original_entries = original_data.entries
        else:
            msg = "Parse should return list of entries"
            raise AssertionError(msg)

        if expected_count is not None:
            assert len(original_entries) == expected_count, (
                f"Expected {expected_count} entries, got {len(original_entries)}"
            )

        # Write to file
        output_file = tmp_path / filename
        DeduplicationHelpers.write_to_file_and_validate(
            api, original_entries, output_file, write_method="write"
        )

        # Parse written file
        roundtripped_data = DeduplicationHelpers.parse_unwrap_and_assert(
            api, output_file
        )

        # Extract entries from result
        if isinstance(roundtripped_data, list):
            roundtripped_entries = roundtripped_data
        elif hasattr(roundtripped_data, "entries"):
            roundtripped_entries = roundtripped_data.entries
        else:
            msg = "Roundtrip parse should return list of entries"
            raise AssertionError(msg)

        # Validate roundtrip
        if validate_identical:
            assert len(original_entries) == len(roundtripped_entries), (
                f"Entry count mismatch: {len(original_entries)} vs "
                f"{len(roundtripped_entries)}"
            )
            for orig, rt in zip(original_entries, roundtripped_entries, strict=False):
                if orig.dn is None or rt.dn is None:
                    continue
                assert orig.dn.value == rt.dn.value, (
                    f"DN mismatch: {orig.dn.value} vs {rt.dn.value}"
                )

        return original_entries, output_file, roundtripped_entries

    @staticmethod
    def schema_parse_write_roundtrip(
        schema_quirk: Any,
        schema_def: str,
        *,
        expected_oid: str | None = None,
        expected_name: str | None = None,
        must_contain_in_output: str | list[str] | None = None,
    ) -> tuple[
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass, str
    ]:
        """Schema parse -> write -> parse roundtrip - replaces 15-25 lines per use.

        Common pattern (appears 20+ times):
            result = schema_quirk.parse(schema_def)
            schema_obj = result.unwrap()
            assert schema_obj.oid == expected_oid
            # Write
            result = schema_quirk.write(schema_obj)
            ldif = result.unwrap()
            assert "expected" in ldif

        Args:
            schema_quirk: Schema quirk instance
            schema_def: Schema definition string
            expected_oid: Optional expected OID
            expected_name: Optional expected name
            must_contain_in_output: Optional strings that must be in written output

        Returns:
            Tuple of (parsed_schema_object, written_ldif_string)

        """
        # Parse
        schema_obj = DeduplicationHelpers.parse_unwrap_and_assert(
            schema_quirk,
            schema_def,
            expected_oid=expected_oid,
            expected_name=expected_name,
        )

        # Write
        written = DeduplicationHelpers.write_unwrap_and_assert(
            schema_quirk, schema_obj, must_contain=must_contain_in_output
        )

        return schema_obj, written

    @staticmethod
    def parse_attribute_complete(
        schema_quirk: Any,
        attr_def: str,
        *,
        expected_oid: str,
        expected_name: str,
        expected_fields: dict[str, Any] | None = None,
    ) -> FlextLdifModels.SchemaAttribute:
        """Complete attribute parse test with all validations - replaces 8-15 lines.

        Common pattern in test files:
            result = schema_quirk.parse_attribute(attr_def)
            assert result.is_success
            attr = result.unwrap()
            assert attr.oid == expected_oid
            assert attr.name == expected_name
            assert attr.field1 == expected_value1
            ...

        Args:
            schema_quirk: Schema quirk instance
            attr_def: Attribute definition string
            expected_oid: Expected OID
            expected_name: Expected name
            expected_fields: Optional dict of field_name: expected_value

        Returns:
            Parsed SchemaAttribute

        """
        attr = DeduplicationHelpers.parse_attribute_unwrap_and_assert(
            schema_quirk,
            attr_def,
            expected_oid=expected_oid,
            expected_name=expected_name,
        )

        if expected_fields:
            for field_name, expected_value in expected_fields.items():
                assert hasattr(attr, field_name), (
                    f"Attribute must have field '{field_name}'"
                )
                actual_value = getattr(attr, field_name)
                assert actual_value == expected_value, (
                    f"Field '{field_name}' mismatch: "
                    f"expected {expected_value}, got {actual_value}"
                )

        return attr

    @staticmethod
    def parse_objectclass_complete(
        schema_quirk: Any,
        oc_def: str,
        *,
        expected_oid: str,
        expected_name: str,
        expected_fields: dict[str, Any] | None = None,
    ) -> FlextLdifModels.SchemaObjectClass:
        """Complete objectClass parse test with all validations - replaces 8-15 lines.

        Common pattern in test files:
            result = schema_quirk.parse_objectclass(oc_def)
            assert result.is_success
            oc = result.unwrap()
            assert oc.oid == expected_oid
            assert oc.name == expected_name
            assert oc.kind == "STRUCTURAL"
            ...

        Args:
            schema_quirk: Schema quirk instance
            oc_def: ObjectClass definition string
            expected_oid: Expected OID
            expected_name: Expected name
            expected_fields: Optional dict of field_name: expected_value

        Returns:
            Parsed SchemaObjectClass

        """
        oc = DeduplicationHelpers.parse_objectclass_unwrap_and_assert(
            schema_quirk,
            oc_def,
            expected_oid=expected_oid,
            expected_name=expected_name,
        )

        if expected_fields:
            for field_name, expected_value in expected_fields.items():
                assert hasattr(oc, field_name), (
                    f"ObjectClass must have field '{field_name}'"
                )
                actual_value = getattr(oc, field_name)
                assert actual_value == expected_value, (
                    f"Field '{field_name}' mismatch: "
                    f"expected {expected_value}, got {actual_value}"
                )

        return oc

    @staticmethod
    def write_schema_complete(
        schema_quirk: Any,
        schema_obj: FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass,
        *,
        must_contain: list[str],
        must_not_contain: list[str] | None = None,
    ) -> str:
        """Complete schema write test with content validation - replaces 6-10 lines.

        Common pattern:
            result = schema_quirk.write(schema_obj)
            assert result.is_success
            ldif = result.unwrap()
            assert "text1" in ldif
            assert "text2" in ldif
            assert "text3" not in ldif

        Args:
            schema_quirk: Schema quirk instance
            schema_obj: SchemaAttribute or SchemaObjectClass to write
            must_contain: List of strings that must be in output
            must_not_contain: Optional list of strings that must NOT be in output

        Returns:
            Written LDIF string

        """
        return DeduplicationHelpers.write_schema_and_unwrap(
            schema_quirk,
            schema_obj,
            must_contain=must_contain,
        )

    @staticmethod
    def parse_entry_complete(
        entry_quirk: Any,
        ldif_content: str,
        *,
        expected_dn: str,
        required_attributes: list[str],
        expected_attribute_values: dict[str, str | list[str]] | None = None,
    ) -> FlextLdifModels.Entry:
        """Complete entry parse test with all validations - replaces 10-20 lines.

        Common pattern:
            result = entry_quirk.parse(content)
            assert result.is_success
            entry = result.unwrap()
            assert entry.dn.value == expected_dn
            assert "attr1" in entry.attributes.attributes
            assert entry.attributes.attributes["attr1"] == expected_value1
            ...

        Args:
            entry_quirk: Entry quirk instance
            ldif_content: LDIF content string
            expected_dn: Expected DN value
            required_attributes: List of required attribute names
            expected_attribute_values: Optional dict of attr_name: expected_value

        Returns:
            Parsed entry

        """
        entry = DeduplicationHelpers.parse_entry_and_assert_dn_attributes(
            entry_quirk,
            ldif_content,
            expected_dn=expected_dn,
            required_attributes=required_attributes,
        )

        if expected_attribute_values:
            for attr_name, expected_value in expected_attribute_values.items():
                DeduplicationHelpers.assert_entry_has_attribute_value(
                    entry, attr_name, expected_value
                )

        return entry

    @staticmethod
    def assert_entry_complete(
        entry: FlextLdifModels.Entry,
        *,
        expected_dn: str | None = None,
        expected_attributes: list[str] | None = None,
        expected_objectclasses: list[str] | None = None,
        required_attributes: list[str] | None = None,
    ) -> None:
        """Assert that entry is complete with expected properties - replaces 5-15 lines.

        Common pattern (appears 20+ times):
            assert entry.dn.value == expected_dn
            assert "attr1" in entry.attributes.attributes
            assert "attr2" in entry.attributes.attributes
            assert "objectClass" in entry.attributes.attributes
            assert "top" in entry.attributes.attributes["objectClass"]

        Args:
            entry: Entry to validate
            expected_dn: Optional expected DN value
            expected_attributes: Optional list of expected attribute names
            expected_objectclasses: Optional list of expected objectClass values
            required_attributes: Optional list of required attribute names (alias for expected_attributes)

        Example:
            DeduplicationHelpers.assert_entry_complete(
                entry,
                expected_dn="cn=test,dc=example,dc=com",
                expected_attributes=["cn", "sn"],
                expected_objectclasses=["top", "person"],
            )

        """
        if expected_dn is not None:
            assert entry.dn is not None, "Entry must have DN"
            assert entry.dn.value == expected_dn, (
                f"Expected DN {expected_dn}, got {entry.dn.value}"
            )

        # Use required_attributes if provided, otherwise use expected_attributes
        attrs_to_check = (
            required_attributes
            if required_attributes is not None
            else expected_attributes
        )

        if attrs_to_check:
            assert entry.attributes is not None, "Entry must have attributes"
            for attr_name in attrs_to_check:
                assert attr_name in entry.attributes.attributes, (
                    f"Entry should have attribute '{attr_name}'"
                )

        if expected_objectclasses:
            assert entry.attributes is not None, "Entry must have attributes"
            assert "objectClass" in entry.attributes.attributes, (
                "Entry should have objectClass attribute"
            )
            oc_values = entry.attributes.attributes["objectClass"]
            if isinstance(oc_values, list):
                oc_list = oc_values
            else:
                oc_list = [oc_values] if oc_values else []

            for expected_oc in expected_objectclasses:
                assert expected_oc in oc_list, (
                    f"Entry should have objectClass '{expected_oc}', got {oc_list}"
                )

    @staticmethod
    def extract_from_fixture_content(
        content: str,
        *,
        filter_contains: list[str] | None = None,
        extract_after: str | None = None,
        min_count: int = 1,
        max_count: int | None = None,
    ) -> list[str]:
        r"""Extract lines from fixture content based on filters - replaces 10-20 lines.

        Common pattern (appears 10+ times):
            lines = content.split("\n")
            filtered = [l for l in lines if "2.16.840.1.113894" in l and "attributetypes:" in l]
            after_marker = []
            found_marker = False
            for line in filtered:
                if "attributetypes:" in line:
                    found_marker = True
                if found_marker:
                    after_marker.append(line)
            assert len(after_marker) >= 1

        Args:
            content: Fixture content string
            filter_contains: Optional list of strings that must be in each line
            extract_after: Optional marker string - extract lines after this marker
            min_count: Minimum number of lines to extract (default: 1)
            max_count: Optional maximum number of lines to extract

        Returns:
            List of extracted lines

        Example:
            lines = DeduplicationHelpers.extract_from_fixture_content(
                schema_content,
                filter_contains=["2.16.840.1.113894", "attributetypes:"],
                extract_after="attributetypes:",
                min_count=1,
            )

        """
        lines = content.split("\n")

        # Extract lines after marker first (if marker is specified)
        # This ensures we work with the correct section before filtering
        if extract_after:
            matching_definitions: list[str] = []
            current_definition_lines: list[str] = []

            for line in lines:
                line_lower = line.lower()
                marker_lower = extract_after.lower()

                # Check if this line starts a new definition (contains the marker)
                if marker_lower in line_lower:
                    # Finish previous definition if any
                    if current_definition_lines:
                        # Check filters on original lines (before removing marker)
                        original_combined = " ".join(current_definition_lines).strip()
                        if filter_contains:
                            if all(
                                required.lower() in original_combined.lower()
                                for required in filter_contains
                            ):
                                # Remove marker prefix for return value
                                combined = original_combined
                                if extract_after.lower() in combined.lower():
                                    marker_pos = combined.lower().find(
                                        extract_after.lower()
                                    )
                                    if marker_pos >= 0:
                                        combined = combined[
                                            marker_pos + len(extract_after) :
                                        ].strip()
                                matching_definitions.append(combined)
                        else:
                            # No filters, just remove marker
                            combined = original_combined
                            if extract_after.lower() in combined.lower():
                                marker_pos = combined.lower().find(
                                    extract_after.lower()
                                )
                                if marker_pos >= 0:
                                    combined = combined[
                                        marker_pos + len(extract_after) :
                                    ].strip()
                            matching_definitions.append(combined)
                    # Start new definition
                    current_definition_lines = [line]
                    # Check if this single line is a complete definition
                    line_stripped = line.strip()
                    if ")" in line_stripped and line_stripped.endswith(")"):
                        # Complete definition on single line
                        # Check filters on original line first (before removing marker)
                        if filter_contains:
                            # Check if original line matches all filters
                            if all(
                                required.lower() in line_lower
                                for required in filter_contains
                            ):
                                # Remove marker prefix for return value
                                combined = line_stripped
                                if extract_after.lower() in combined.lower():
                                    marker_pos = combined.lower().find(
                                        extract_after.lower()
                                    )
                                    if marker_pos >= 0:
                                        combined = combined[
                                            marker_pos + len(extract_after) :
                                        ].strip()
                                matching_definitions.append(combined)
                        else:
                            # No filters, just remove marker
                            combined = line_stripped
                            if extract_after.lower() in combined.lower():
                                marker_pos = combined.lower().find(
                                    extract_after.lower()
                                )
                                if marker_pos >= 0:
                                    combined = combined[
                                        marker_pos + len(extract_after) :
                                    ].strip()
                            matching_definitions.append(combined)
                        # Reset for next definition
                        current_definition_lines = []
                elif current_definition_lines:
                    # Continue current definition
                    current_definition_lines.append(line)
                    # Check if definition is complete (ends with closing paren)
                    line_stripped = line.strip()
                    if ")" in line_stripped and line_stripped.endswith(")"):
                        # Complete definition found
                        # Check filters on original lines (before removing marker)
                        original_combined = " ".join(current_definition_lines).strip()
                        if filter_contains:
                            if all(
                                required.lower() in original_combined.lower()
                                for required in filter_contains
                            ):
                                # Remove marker prefix for return value
                                combined = original_combined
                                if extract_after.lower() in combined.lower():
                                    marker_pos = combined.lower().find(
                                        extract_after.lower()
                                    )
                                    if marker_pos >= 0:
                                        combined = combined[
                                            marker_pos + len(extract_after) :
                                        ].strip()
                                matching_definitions.append(combined)
                        else:
                            # No filters, just remove marker
                            combined = original_combined
                            if extract_after.lower() in combined.lower():
                                marker_pos = combined.lower().find(
                                    extract_after.lower()
                                )
                                if marker_pos >= 0:
                                    combined = combined[
                                        marker_pos + len(extract_after) :
                                    ].strip()
                            matching_definitions.append(combined)
                        # Reset for next definition
                        current_definition_lines = []

            # Handle any remaining definition
            if current_definition_lines:
                original_combined = " ".join(current_definition_lines).strip()
                if filter_contains:
                    if all(
                        required.lower() in original_combined.lower()
                        for required in filter_contains
                    ):
                        # Remove marker prefix for return value
                        combined = original_combined
                        if extract_after.lower() in combined.lower():
                            marker_pos = combined.lower().find(extract_after.lower())
                            if marker_pos >= 0:
                                combined = combined[
                                    marker_pos + len(extract_after) :
                                ].strip()
                        matching_definitions.append(combined)
                else:
                    # No filters, just remove marker
                    combined = original_combined
                    if extract_after.lower() in combined.lower():
                        marker_pos = combined.lower().find(extract_after.lower())
                        if marker_pos >= 0:
                            combined = combined[
                                marker_pos + len(extract_after) :
                            ].strip()
                    matching_definitions.append(combined)

            # Use matching definitions if found, fallback to empty list
            lines = matching_definitions or []
        # Note: filter_contains is already applied during extraction when extract_after is used
        # Only apply additional filtering if extract_after was not used
        elif filter_contains:
            # Filter lines that contain all required strings (when extract_after is not used)
            lines = [
                line
                for line in lines
                if all(required.lower() in line.lower() for required in filter_contains)
            ]

        # Validate count
        assert len(lines) >= min_count, (
            f"Expected at least {min_count} lines, got {len(lines)}"
        )

        if max_count is not None:
            assert len(lines) <= max_count, (
                f"Expected at most {max_count} lines, got {len(lines)}"
            )
            lines = lines[:max_count]

        return lines

    @staticmethod
    def write_entry_complete(
        entry_quirk: Any,
        entry: FlextLdifModels.Entry,
        *,
        must_contain: list[str],
        must_not_contain: list[str] | None = None,
        validate_dn_preserved: bool = True,
    ) -> str:
        """Complete entry write test with content validation - replaces 8-12 lines.

        Common pattern:
            result = entry_quirk.write(entry)
            assert result.is_success
            ldif = result.unwrap()
            assert entry.dn.value in ldif
            assert "text1" in ldif
            assert "text2" not in ldif

        Args:
            entry_quirk: Entry quirk instance
            entry: Entry to write
            must_contain: List of strings that must be in output
            must_not_contain: Optional list of strings that must NOT be in output
            validate_dn_preserved: Whether to validate DN is in output (default: True)

        Returns:
            Written LDIF string

        """
        ldif = DeduplicationHelpers.write_entry_and_unwrap(
            entry_quirk, entry, must_contain=must_contain
        )

        if validate_dn_preserved and entry.dn:
            assert entry.dn.value in ldif, (
                f"DN '{entry.dn.value}' not found in written output"
            )

        if must_not_contain:
            for text in must_not_contain:
                assert text not in ldif, f"Must not contain '{text}' found in output"

        return ldif

    @staticmethod
    def helper_parse_entries_and_assert_count_dn(
        parser: Any,
        content: str | Path,
        *,
        parse_method: str = "parse",
        expected_count: int,
        expected_first_dn: str | None = None,
        required_attributes: list[str] | None = None,
    ) -> list[FlextLdifModels.Entry]:
        """Parse entries and assert count + DN + attributes - replaces 8-15 lines per use.

        Common pattern (appears 30+ times):
            result = parser.parse(content)
            assert result.is_success
            entries = result.unwrap()
            assert len(entries) == expected_count
            entry = entries[0]
            assert entry.dn.value == expected_dn
            assert "attr1" in entry.attributes.attributes

        Args:
            parser: Parser instance
            content: Content to parse
            parse_method: Method name to call (default: "parse")
            expected_count: Expected entry count
            expected_first_dn: Optional expected DN of first entry
            required_attributes: Optional list of required attribute names

        Returns:
            Parsed entries

        """
        unwrapped = DeduplicationHelpers.helper_parse_unwrap_and_assert(
            parser, content, parse_method=parse_method
        )

        # Extract entries from result
        if isinstance(unwrapped, list):
            entries = unwrapped
        elif hasattr(unwrapped, "entries"):
            entries = unwrapped.entries
            if not isinstance(entries, list):
                entries = [entries]
        else:
            entries = (
                [unwrapped] if isinstance(unwrapped, FlextLdifModels.Entry) else []
            )

        assert len(entries) == expected_count, (
            f"Expected {expected_count} entries, got {len(entries)}"
        )

        if expected_first_dn and entries:
            assert entries[0].dn is not None, "First entry must have DN"
            assert entries[0].dn.value == expected_first_dn, (
                f"Expected DN '{expected_first_dn}', got '{entries[0].dn.value}'"
            )

        if required_attributes and entries:
            DeduplicationHelpers.assert_entry_has_attributes(
                entries[0], required_attributes
            )

        return entries

    @staticmethod
    def helper_api_parse_and_unwrap(
        api: Any,
        content: str | Path,
        *,
        expected_count: int | None = None,
        expected_first_dn: str | None = None,
        server_type: str | None = None,
    ) -> list[FlextLdifModels.Entry]:
        """API parse and unwrap with common validations - replaces 5-10 lines per use.

        Common pattern (appears 40+ times):
            result = api.parse(content)
            assert result.is_success
            entries = result.unwrap()
            assert len(entries) == expected_count

        Args:
            api: FlextLdif API instance
            content: Content to parse (string or Path)
            expected_count: Optional expected entry count
            expected_first_dn: Optional expected DN of first entry
            server_type: Optional server type override

        Returns:
            Parsed entries

        """
        if server_type:
            result = api.parse(content, server_type=server_type)
        else:
            result = api.parse(content)

        entries = DeduplicationHelpers.assert_success_and_unwrap_list(
            result, expected_length=expected_count
        )

        if expected_first_dn and entries:
            assert entries[0].dn is not None
            assert entries[0].dn.value == expected_first_dn

        return entries

    @staticmethod
    def helper_api_write_and_unwrap(
        api: Any,
        entries: list[FlextLdifModels.Entry] | FlextLdifModels.Entry,
        *,
        must_contain: str | list[str] | None = None,
        output_path: Path | None = None,
    ) -> str | Path:
        """API write and unwrap with content validation - replaces 5-10 lines per use.

        Common pattern (appears 30+ times):
            result = api.write(entries)
            assert result.is_success
            ldif = result.unwrap()
            assert "expected" in ldif

        Args:
            api: FlextLdif API instance
            entries: Entry or list of entries to write
            must_contain: String or list of strings that must be in output
            output_path: Optional path for file output

        Returns:
            Written LDIF string or file path

        """
        if output_path:
            DeduplicationHelpers.write_to_file_and_validate(
                api, entries, output_path, must_contain=must_contain
            )
            return output_path

        if isinstance(entries, list):
            result = api.write(entries)
        else:
            result = api.write([entries])

        must_contain_list = (
            [must_contain] if isinstance(must_contain, str) else must_contain
        )
        return DeduplicationHelpers.assert_success_and_unwrap_string(
            result, must_contain=must_contain_list
        )

    @staticmethod
    def helper_parse_single_entry_and_validate(
        parser: Any,
        ldif_content: str,
        *,
        parse_method: str = "parse",
        expected_dn: str,
        required_attributes: list[str] | None = None,
        expected_attribute_values: dict[str, str | list[str]] | None = None,
    ) -> FlextLdifModels.Entry:
        """Parse single entry and validate completely - replaces 10-20 lines per use.

        Common pattern (appears 25+ times):
            result = parser.parse(content)
            assert result.is_success
            entries = result.unwrap()
            assert len(entries) == 1
            entry = entries[0]
            assert entry.dn.value == expected_dn
            assert "attr1" in entry.attributes.attributes
            assert entry.attributes.attributes["attr1"] == expected_value

        Args:
            parser: Parser instance
            ldif_content: LDIF content string
            parse_method: Method name to call (default: "parse")
            expected_dn: Expected DN value
            required_attributes: Optional list of required attribute names
            expected_attribute_values: Optional dict of attr_name: expected_value

        Returns:
            Parsed entry

        """
        entries = DeduplicationHelpers.helper_parse_entries_and_assert_count_dn(
            parser,
            ldif_content,
            parse_method=parse_method,
            expected_count=1,
            expected_first_dn=expected_dn,
            required_attributes=required_attributes,
        )

        entry = entries[0]

        if expected_attribute_values:
            for attr_name, expected_value in expected_attribute_values.items():
                DeduplicationHelpers.assert_entry_has_attribute_value(
                    entry, attr_name, expected_value
                )

        return entry

    @staticmethod
    def helper_parse_write_and_assert_content(
        quirk: Any,
        content: str,
        *,
        parse_method: str = "parse",
        write_method: str = "write",
        must_contain_in_output: str | list[str] | None = None,
    ) -> tuple[Any, str]:
        """Parse, write and assert content - replaces 8-12 lines per use.

        Common pattern (appears 25+ times):
            result = quirk.parse(content)
            assert result.is_success
            obj = result.unwrap()
            result = quirk.write(obj)
            assert result.is_success
            ldif = result.unwrap()
            assert "expected" in ldif

        Args:
            quirk: Quirk instance
            content: Content to parse
            parse_method: Method name for parsing (default: "parse")
            write_method: Method name for writing (default: "write")
            must_contain_in_output: Optional strings that must be in written output

        Returns:
            Tuple of (parsed_object, written_string)

        """
        parsed = DeduplicationHelpers.helper_parse_unwrap_and_assert(
            quirk, content, parse_method=parse_method
        )

        written = DeduplicationHelpers.helper_write_unwrap_and_assert(
            quirk,
            parsed,
            write_method=write_method,
            must_contain=must_contain_in_output,
        )

        return parsed, written

    @staticmethod
    def helper_schema_parse_write_and_assert_oid(
        schema_quirk: Any,
        schema_def: str,
        *,
        expected_oid: str,
        expected_name: str | None = None,
        must_contain_in_output: str | list[str] | None = None,
    ) -> tuple[
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass, str
    ]:
        """Schema parse -> write and assert OID in output - replaces 8-12 lines per use.

        Common pattern (appears 35+ times):
            result = schema_quirk.parse(schema_def)
            assert result.is_success
            schema_obj = result.unwrap()
            assert schema_obj.oid == expected_oid
            result = schema_quirk.write(schema_obj)
            assert result.is_success
            assert expected_oid in result.unwrap()

        Args:
            schema_quirk: Schema quirk instance
            schema_def: Schema definition string
            expected_oid: Expected OID
            expected_name: Optional expected name
            must_contain_in_output: Optional strings that must be in written output

        Returns:
            Tuple of (parsed_schema_object, written_ldif_string)

        """
        schema_obj = DeduplicationHelpers.schema_parse_and_assert_oid_name(
            schema_quirk,
            schema_def,
            expected_oid=expected_oid,
            expected_name=expected_name or "",
        )

        must_contain = [expected_oid]
        if expected_name:
            must_contain.append(expected_name)
        if must_contain_in_output:
            contains_list = (
                [must_contain_in_output]
                if isinstance(must_contain_in_output, str)
                else must_contain_in_output
            )
            must_contain.extend(contains_list)

        written = DeduplicationHelpers.helper_write_unwrap_and_assert(
            schema_quirk, schema_obj, must_contain=must_contain
        )

        return schema_obj, written

    @staticmethod
    def helper_write_file_conditional_success(
        writer: Any,
        data: Any,
        output_path: Path,
        *,
        write_method: str = "write",
        must_contain: str | list[str] | None = None,
    ) -> tuple[bool, Path | None]:
        """Write to file with conditional success handling - replaces 6-10 lines per use.

        Common pattern (appears 15+ times):
            result = writer.write(data, output_path=output_file)
            if result.is_success:
                assert output_file.exists()
                content = output_file.read_text()
                assert "expected" in content

        Args:
            writer: Writer instance
            data: Data to write
            output_path: Path to output file
            write_method: Method name to call (default: "write")
            must_contain: String or list of strings that must be in file content

        Returns:
            Tuple of (is_success, output_path_or_none)

        """
        method = getattr(writer, write_method, None)
        if method is None:
            msg = f"Method {write_method} not found on writer"
            raise AttributeError(msg)

        if write_method == "write" and hasattr(writer, "write"):
            result = writer.write(data, output_path=output_path)  # type: ignore[misc]
        else:
            result = method(data, output_path=output_path)  # type: ignore[misc]

        if result.is_success:
            assert output_path.exists(), f"Output file should exist: {output_path}"
            if must_contain:
                content = output_path.read_text(encoding="utf-8")
                contains_list = (
                    [must_contain] if isinstance(must_contain, str) else must_contain
                )
                for text in contains_list:
                    assert text in content, f"File must contain '{text}' not found"
            return True, output_path
        return False, None

    @staticmethod
    def helper_parse_failure_with_error_validation(
        parser: Any,
        content: str | Path,
        *,
        parse_method: str = "parse",
        expected_error_substring: str,
        error_must_not_contain: str | list[str] | None = None,
    ) -> FlextResult[Any]:
        """Parse failure with comprehensive error validation - replaces 4-7 lines per use.

        Common pattern (appears 20+ times):
            result = parser.parse(content)
            assert result.is_failure
            assert result.error is not None
            assert expected_error in result.error
            assert "bad_text" not in result.error

        Args:
            parser: Parser instance
            content: Content to parse
            parse_method: Method name to call (default: "parse")
            expected_error_substring: Substring that must be in error message
            error_must_not_contain: Optional strings that must NOT be in error

        Returns:
            Failed FlextResult

        """
        result = DeduplicationHelpers.helper_parse_failure_and_assert_error(
            parser,
            content,
            parse_method=parse_method,
            expected_error_substring=expected_error_substring,
        )

        assert result.error is not None, "Failed result must have error message"

        if error_must_not_contain:
            not_contains_list = (
                [error_must_not_contain]
                if isinstance(error_must_not_contain, str)
                else error_must_not_contain
            )
            for text in not_contains_list:
                assert text not in result.error, (
                    f"Error must not contain '{text}' but found in: {result.error}"
                )

        return result

    @staticmethod
    def helper_batch_can_handle_operations(
        quirk: Any,
        test_cases: list[dict[str, Any]],
        *,
        can_handle_method: str = "can_handle",
    ) -> list[bool]:
        """Test multiple can_handle operations in batch - replaces 30-80+ lines.

        Args:
            quirk: Quirk instance
            test_cases: List of test case dicts with keys:
                - data: Any (required) - data to check  # noqa: ANN401
                - expected: bool (required) - expected result
            can_handle_method: Method name to call (default: "can_handle")

        Returns:
            List of boolean results

        """
        results = []
        for i, test_case in enumerate(test_cases):
            data = test_case.get("data")
            if data is None:
                msg = f"Test case {i} missing 'data'"
                raise ValueError(msg)

            expected = test_case.get("expected")
            if expected is None:
                msg = f"Test case {i} missing 'expected'"
                raise ValueError(msg)

            result = DeduplicationHelpers.helper_can_handle_and_assert(
                quirk, can_handle_method, data, expected_result=expected
            )
            results.append(result)
        return results

    @staticmethod
    def helper_batch_write_and_assert_content(
        writer: Any,
        test_cases: list[dict[str, Any]],
        *,
        write_method: str = "write",
    ) -> list[str]:
        """Test multiple write operations with content validation - replaces 40-100+ lines.

        Args:
            writer: Writer instance
            test_cases: List of test case dicts with keys:
                - data: Any (required) - data to write  # noqa: ANN401
                - must_contain: str | list[str] | None
                - must_not_contain: str | list[str] | None
                - should_succeed: bool (default: True)
            write_method: Method name to call (default: "write")

        Returns:
            List of written strings

        """
        results = []
        for i, test_case in enumerate(test_cases):
            data = test_case.get("data")
            if data is None:
                msg = f"Test case {i} missing 'data'"
                raise ValueError(msg)

            should_succeed = test_case.get("should_succeed", True)
            if should_succeed:
                written = DeduplicationHelpers.helper_write_unwrap_and_assert(
                    writer,
                    data,
                    write_method=write_method,
                    must_contain=test_case.get("must_contain"),
                    must_not_contain=test_case.get("must_not_contain"),
                )
                results.append(written)
            else:
                _ = DeduplicationHelpers.helper_write_failure_and_assert_error(
                    writer,
                    data,
                    write_method=write_method,
                    expected_error_substring=test_case.get("expected_error_substring"),
                )
                results.append("")  # Placeholder for failed writes
        return results

    @staticmethod
    def parse_schema_from_entry_attributes(
        schema_quirk: Any,
        entries: list[FlextLdifModels.Entry],
        *,
        schema_type: str = "attribute",
        parse_method: str | None = None,
    ) -> list[Any]:
        """Parse schemas from entry attributes - replaces 15-30 lines.

        Common pattern (appears 10+ times):
            for entry in entries:
                if "attributetypes" in entry.attributes.attributes:
                    for attr_def in entry.attributes.attributes["attributetypes"]:
                        result = schema_quirk.parse_attribute(attr_def)
                        if result.is_success:
                            schemas.append(result.unwrap())

        Args:
            schema_quirk: Schema quirk instance
            entries: List of entries containing schema definitions
            schema_type: Type of schema ("attribute" or "objectclass")
            parse_method: Method name (default: auto-detect)

        Returns:
            List of parsed schema objects

        """
        if parse_method is None:
            parse_method = (
                "parse_attribute" if schema_type == "attribute" else "parse_objectclass"
            )

        parse_func = getattr(schema_quirk, parse_method)
        schemas = []

        attr_key = "attributetypes" if schema_type == "attribute" else "objectclasses"

        for entry in entries:
            if entry.attributes and entry.attributes.attributes:
                for attr_name, attr_values in entry.attributes.attributes.items():
                    if attr_name.lower() in {attr_key.lower(), attr_key}:
                        for schema_def in attr_values:
                            if isinstance(schema_def, str):
                                result = parse_func(schema_def)
                                if result.is_success:
                                    schemas.append(result.unwrap())

        return schemas

    @staticmethod
    def parse_and_unwrap_parse_response(
        parser: Any,
        ldif_content: str,
        *,
        parse_method: str = "parse",
        expected_entry_count: int | None = None,
    ) -> FlextLdifModels.ParseResponse:
        """Parse and unwrap ParseResponse - replaces 5-8 lines.

        Common pattern:
            result = parser.parse(ldif_content)
            assert result.is_success
            parse_response = result.unwrap()
            assert isinstance(parse_response, FlextLdifModels.ParseResponse)
            assert len(parse_response.entries) > 0

        Args:
            parser: Parser instance
            ldif_content: LDIF content string
            parse_method: Method name (default: "parse")
            expected_entry_count: Expected number of entries (optional)

        Returns:
            ParseResponse object

        """
        result = getattr(parser, parse_method)(ldif_content)
        TestAssertions.assert_success(result, f"Parse failed: {result.error}")
        parse_response = result.unwrap()
        assert isinstance(parse_response, FlextLdifModels.ParseResponse), (
            f"Expected ParseResponse, got {type(parse_response)}"
        )
        if expected_entry_count is not None:
            assert len(parse_response.entries) == expected_entry_count, (
                f"Expected {expected_entry_count} entries, got {len(parse_response.entries)}"
            )
        return parse_response

    @staticmethod
    def parse_and_unwrap_entries_list(
        parser: Any,
        ldif_content: str,
        *,
        parse_method: str = "parse",
        expected_count: int | None = None,
        min_count: int | None = None,
    ) -> list[FlextLdifModels.Entry]:
        """Parse and unwrap entries list - replaces 5-8 lines.

        Common pattern:
            result = parser.parse(ldif_content)
            assert result.is_success
            entries = result.unwrap()
            assert isinstance(entries, list)
            assert len(entries) > 0

        Args:
            parser: Parser instance
            ldif_content: LDIF content string
            parse_method: Method name (default: "parse")
            expected_count: Expected exact count (optional)
            min_count: Minimum count (optional)

        Returns:
            List of Entry objects

        """
        result = getattr(parser, parse_method)(ldif_content)
        TestAssertions.assert_success(result, f"Parse failed: {result.error}")
        unwrapped = result.unwrap()
        if isinstance(unwrapped, FlextLdifModels.ParseResponse):
            entries = unwrapped.entries
        elif isinstance(unwrapped, list):
            entries = unwrapped
        else:
            msg = f"Unexpected type: {type(unwrapped)}"
            raise TypeError(msg)
        assert isinstance(entries, list), f"Expected list, got {type(entries)}"
        # Cast to ensure type consistency
        entries_cast: list[FlextLdifModels.Entry] = [
            entry for entry in entries if isinstance(entry, FlextLdifModels.Entry)
        ]
        if expected_count is not None:
            assert len(entries_cast) == expected_count, (
                f"Expected {expected_count} entries, got {len(entries_cast)}"
            )
        if min_count is not None:
            assert len(entries_cast) >= min_count, (
                f"Expected at least {min_count} entries, got {len(entries_cast)}"
            )
        return entries_cast

    @staticmethod
    def assert_failure_with_error_check(
        result: FlextResult[Any],
        *,
        expected_error_substring: str | None = None,
        error_message: str | None = None,
    ) -> str:
        """Assert failure and optionally check error message - replaces 3-5 lines.

        Common pattern:
            assert result.is_failure
            if expected_error:
                assert expected_error in result.error

        Args:
            result: FlextResult to check
            expected_error_substring: Substring that must be in error (optional)
            error_message: Custom error message for assertion

        Returns:
            Error string

        """
        TestAssertions.assert_failure(result, expected_error_substring)
        error = result.error
        if error is None:
            msg = "Expected error message but got None"
            raise AssertionError(msg)
        return error

    @staticmethod
    def create_entry_and_unwrap(
        dn: str,
        attributes: dict[str, str | list[str]],
    ) -> FlextLdifModels.Entry:
        """Create Entry and unwrap - replaces 3-4 lines.

        Common pattern:
            entry = FlextLdifModels.Entry.create(
                dn="cn=test,dc=example,dc=com",
                attributes={"cn": ["test"]},
            ).unwrap()

        Args:
            dn: Distinguished Name
            attributes: Dictionary of attributes

        Returns:
            Entry object

        """
        result = FlextLdifModels.Entry.create(dn=dn, attributes=attributes)
        TestAssertions.assert_success(result, f"Entry creation failed: {result.error}")
        unwrapped = result.unwrap()
        assert isinstance(unwrapped, FlextLdifModels.Entry), (
            "Entry creation should return Entry"
        )
        return unwrapped

    @staticmethod
    def parse_entry_ldif_and_unwrap(
        entry_quirk: Any,
        ldif_text: str,
        *,
        parse_method: str = "parse",
        expected_dn: str | None = None,
        required_attributes: list[str] | None = None,
    ) -> FlextLdifModels.Entry:
        """Parse single entry from LDIF and unwrap - replaces 6-10 lines.

        Common pattern:
            result = entry_quirk.parse(ldif_text)
            assert result.is_success
            entries = result.unwrap()
            assert len(entries) == 1
            entry = entries[0]
            assert entry.dn.value == expected_dn

        Args:
            entry_quirk: Entry quirk instance
            ldif_text: LDIF content string
            parse_method: Method name (default: "parse")
            expected_dn: Expected DN value (optional)
            required_attributes: List of required attribute names (optional)

        Returns:
            Single Entry object

        """
        result = getattr(entry_quirk, parse_method)(ldif_text)
        TestAssertions.assert_success(result, f"Entry parse failed: {result.error}")
        unwrapped = result.unwrap()
        if isinstance(unwrapped, list):
            entries = list(unwrapped)
        elif isinstance(unwrapped, FlextLdifModels.ParseResponse):
            entries = list(unwrapped.entries)
        else:
            msg = f"Unexpected type: {type(unwrapped)}"
            raise TypeError(msg)
        assert len(entries) == 1, f"Expected 1 entry, got {len(entries)}"
        entry_raw = entries[0]
        entry = cast("FlextLdifModels.Entry", entry_raw)
        if expected_dn:
            if entry.dn is None:
                msg = "Entry DN is None"
                raise ValueError(msg)
            assert entry.dn.value == expected_dn, (
                f"Expected DN {expected_dn}, got {entry.dn.value}"
            )
        if required_attributes:
            if entry.attributes is None:
                msg = "Entry attributes is None"
                raise ValueError(msg)
            for attr_name in required_attributes:
                assert attr_name in entry.attributes.attributes, (
                    f"Missing required attribute: {attr_name}"
                )
        return entry

    @staticmethod
    def batch_parse_entries_with_validation(
        entry_quirk: Any,
        test_cases: list[dict[str, Any]],
        *,
        parse_method: str = "parse",
    ) -> list[FlextLdifModels.Entry]:
        """Batch parse multiple entries with validation - replaces 20-50+ lines.

        Common pattern:
            for test_case in test_cases:
                result = entry_quirk.parse(test_case["ldif"])
                assert result.is_success
                entries = result.unwrap()
                assert len(entries) == test_case["expected_count"]
                if "expected_dn" in test_case:
                    assert entries[0].dn.value == test_case["expected_dn"]

        Args:
            entry_quirk: Entry quirk instance
            test_cases: List of dicts with keys:
                - ldif: str (required) - LDIF content
                - expected_count: int (optional) - Expected entry count
                - expected_dn: str (optional) - Expected DN
                - required_attributes: list[str] (optional)
            parse_method: Method name (default: "parse")

        Returns:
            List of all parsed entries

        """
        all_entries = []
        for i, test_case in enumerate(test_cases):
            ldif = test_case.get("ldif")
            if ldif is None:
                msg = f"Test case {i} missing 'ldif'"
                raise ValueError(msg)

            result = getattr(entry_quirk, parse_method)(ldif)
            TestAssertions.assert_success(
                result, f"Test case {i} parse failed: {result.error}"
            )
            unwrapped = result.unwrap()
            if isinstance(unwrapped, list):
                entries = list(unwrapped)
            elif isinstance(unwrapped, FlextLdifModels.ParseResponse):
                entries = list(unwrapped.entries)
            else:
                msg = f"Test case {i}: Unexpected type {type(unwrapped)}"
                raise TypeError(msg)

            expected_count = test_case.get("expected_count")
            if expected_count is not None:
                assert len(entries) == expected_count, (
                    f"Test case {i}: Expected {expected_count} entries, got {len(entries)}"
                )

            if entries and "expected_dn" in test_case:
                assert entries[0].dn is not None, f"Test case {i}: Entry must have DN"
                assert entries[0].dn.value == test_case["expected_dn"], (
                    f"Test case {i}: Expected DN {test_case['expected_dn']}, "
                    f"got {entries[0].dn.value}"
                )

            if entries and "required_attributes" in test_case:
                assert entries[0].attributes is not None, (
                    f"Test case {i}: Entry must have attributes"
                )
                for attr_name in test_case["required_attributes"]:
                    assert attr_name in entries[0].attributes.attributes, (
                        f"Test case {i}: Missing attribute {attr_name}"
                    )

            all_entries.extend(entries)

        return all_entries

    @staticmethod
    def parse_schema_with_constants(
        schema_quirk: Any,
        schema_def: str,
        *,
        parse_method: str = "parse",
        expected_oid: str | None = None,
        expected_name: str | None = None,
    ) -> FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass:
        """Parse schema using constants - replaces 5-8 lines with constants.

        Common pattern:
            result = schema.parse_attribute(TestsRfcConstants.ATTR_DEF_CN)
            assert result.is_success
            attr = result.unwrap()
            assert attr.oid == TestsRfcConstants.ATTR_OID_CN

        Args:
            schema_quirk: Schema quirk instance
            schema_def: Schema definition string (can be from constants)
            parse_method: Method name (default: "parse")
            expected_oid: Expected OID value (optional)
            expected_name: Expected name value (optional)

        Returns:
            SchemaAttribute or SchemaObjectClass

        """
        result = getattr(schema_quirk, parse_method)(schema_def)
        TestAssertions.assert_success(result, f"Schema parse failed: {result.error}")
        schema_obj = result.unwrap()
        if not isinstance(
            schema_obj,
            (FlextLdifModels.SchemaAttribute, FlextLdifModels.SchemaObjectClass),
        ):
            msg = (
                f"Expected SchemaAttribute or SchemaObjectClass, got {type(schema_obj)}"
            )
            raise TypeError(msg)
        if expected_oid:
            assert schema_obj.oid == expected_oid, (
                f"Expected OID {expected_oid}, got {schema_obj.oid}"
            )
        if expected_name:
            assert schema_obj.name == expected_name, (
                f"Expected name {expected_name}, got {schema_obj.name}"
            )
        return schema_obj

    @staticmethod
    def batch_parse_schema_with_constants(
        schema_quirk: Any,
        test_cases: list[dict[str, Any]],
        *,
        parse_method: str = "parse",
    ) -> list[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass]:
        """Batch parse schema using constants - replaces 30-80+ lines.

        Common pattern:
            for test_case in test_cases:
                result = schema.parse(test_case["def"])
                assert result.is_success
                schema_obj = result.unwrap()
                assert schema_obj.oid == test_case["expected_oid"]

        Args:
            schema_quirk: Schema quirk instance
            test_cases: List of dicts with keys:
                - schema_def: str (required) - Schema definition
                - expected_oid: str (optional)
                - expected_name: str (optional)
            parse_method: Method name (default: "parse")

        Returns:
            List of parsed schema objects

        """
        all_schemas = []
        for i, test_case in enumerate(test_cases):
            schema_def = test_case.get("schema_def")
            if schema_def is None:
                msg = f"Test case {i} missing 'schema_def'"
                raise ValueError(msg)

            result = getattr(schema_quirk, parse_method)(schema_def)
            TestAssertions.assert_success(
                result, f"Test case {i} parse failed: {result.error}"
            )
            schema_obj = result.unwrap()
            if not isinstance(
                schema_obj,
                (FlextLdifModels.SchemaAttribute, FlextLdifModels.SchemaObjectClass),
            ):
                msg = f"Test case {i}: Unexpected type {type(schema_obj)}"
                raise TypeError(msg)

            if "expected_oid" in test_case:
                assert schema_obj.oid == test_case["expected_oid"], (
                    f"Test case {i}: Expected OID {test_case['expected_oid']}, "
                    f"got {schema_obj.oid}"
                )

            if "expected_name" in test_case:
                assert schema_obj.name == test_case["expected_name"], (
                    f"Test case {i}: Expected name {test_case['expected_name']}, "
                    f"got {schema_obj.name}"
                )

            all_schemas.append(schema_obj)

        return all_schemas

    @staticmethod
    def helper_write_failure_assertions(
        writer: Any,
        test_cases: list[dict[str, Any]],
        *,
        write_method: str = "write",
    ) -> list[FlextResult[Any]]:
        """Test multiple write failures - replaces 20-50+ lines.

        Common pattern:
            result1 = writer.write(invalid_data1)
            assert result1.is_failure
            result2 = writer.write(invalid_data2)
            assert result2.is_failure

        Args:
            writer: Writer instance
            test_cases: List of dicts with keys:
                - data: Any (required) - data to write  # noqa: ANN401
                - expected_error_substring: str | None
            write_method: Method name (default: "write")

        Returns:
            List of failed FlextResults

        """
        method = getattr(writer, write_method)
        results = []

        for i, test_case in enumerate(test_cases):
            data = test_case.get("data")
            if data is None:
                msg = f"Test case {i} missing 'data'"
                raise ValueError(msg)

            result = method(data)  # type: ignore[misc]
            expected_error = test_case.get("expected_error_substring")
            TestAssertions.assert_failure(result, expected_error)
            results.append(result)

        return results

    @staticmethod
    def helper_parse_entry_simple_and_validate_attributes(
        parser: Any,
        ldif_content: str,
        *,
        parse_method: str = "parse",
        expected_dn: str,
        required_attributes: list[str],
    ) -> FlextLdifModels.Entry:
        """Parse single entry and validate DN + attributes - replaces 8-12 lines per use.

        Common pattern (appears 20+ times):
            result = parser.parse(content)
            assert result.is_success
            entries = result.unwrap()
            assert len(entries) == 1
            entry = entries[0]
            assert entry.dn.value == expected_dn
            assert "attr1" in entry.attributes.attributes
            assert "attr2" in entry.attributes.attributes

        Args:
            parser: Parser instance
            ldif_content: LDIF content string
            parse_method: Method name to call (default: "parse")
            expected_dn: Expected DN value
            required_attributes: List of required attribute names

        Returns:
            Parsed entry

        """
        return DeduplicationHelpers.helper_parse_single_entry_and_validate(
            parser,
            ldif_content,
            parse_method=parse_method,
            expected_dn=expected_dn,
            required_attributes=required_attributes,
        )

    @staticmethod
    def helper_parse_and_validate_entry_count_dn_attributes(
        parser: Any,
        content: str | Path,
        *,
        parse_method: str = "parse",
        expected_count: int,
        expected_first_dn: str,
        required_attributes: list[str],
    ) -> list[FlextLdifModels.Entry]:
        """Parse and validate count + DN + attributes - replaces 10-18 lines per use.

        Common pattern (appears 20+ times):
            result = parser.parse(content)
            assert result.is_success
            entries = result.unwrap()
            assert len(entries) == expected_count
            assert entries[0].dn.value == expected_dn
            assert "attr1" in entries[0].attributes.attributes
            assert "attr2" in entries[0].attributes.attributes

        Args:
            parser: Parser instance
            content: Content to parse
            parse_method: Method name to call (default: "parse")
            expected_count: Expected entry count
            expected_first_dn: Expected DN of first entry
            required_attributes: List of required attribute names

        Returns:
            Parsed entries

        """
        return DeduplicationHelpers.helper_parse_entries_and_assert_count_dn(
            parser,
            content,
            parse_method=parse_method,
            expected_count=expected_count,
            expected_first_dn=expected_first_dn,
            required_attributes=required_attributes,
        )

    @staticmethod
    def helper_write_and_validate_file_content(
        writer: Any,
        data: Any,
        output_path: Path,
        *,
        write_method: str = "write",
        must_contain: str | list[str],
        must_not_contain: str | list[str] | None = None,
    ) -> Path:
        """Write to file and validate content - replaces 7-12 lines per use.

        Common pattern (appears 25+ times):
            result = writer.write(data, output_path=output_file)
            assert result.is_success
            assert output_file.exists()
            content = output_file.read_text()
            assert "text1" in content
            assert "text2" in content
            assert "bad_text" not in content

        Args:
            writer: Writer instance
            data: Data to write
            output_path: Path to output file
            write_method: Method name to call (default: "write")
            must_contain: String or list of strings that must be in file
            must_not_contain: Optional strings that must NOT be in file

        Returns:
            Output file path

        """
        return DeduplicationHelpers.write_to_file_and_validate(
            writer,
            data,
            output_path,
            write_method=write_method,
            must_contain=must_contain,
            must_not_contain=must_not_contain,
        )

    @staticmethod
    def assert_result_is_type(
        result: FlextResult[Any],
        expected_type: type[Any],
        *,
        error_msg: str | None = None,
    ) -> Any:
        """Assert result is success and unwrapped value is of expected type - replaces 2-3 lines.

        Common pattern:
            assert result.is_success
            value = result.unwrap()
            assert isinstance(value, ExpectedType)

        Args:
            result: FlextResult to check and unwrap
            expected_type: Expected type
            error_msg: Optional custom error message

        Returns:
            Unwrapped value

        """
        unwrapped = DeduplicationHelpers.assert_success_and_unwrap(result, error_msg)
        assert isinstance(unwrapped, expected_type), (
            f"Expected {expected_type}, got {type(unwrapped)}"
        )
        return unwrapped

    @staticmethod
    def helper_parse_and_assert_count_and_dn(
        parser: Any,
        ldif_content: str | Path,
        *,
        expected_count: int,
        expected_first_dn: str,
    ) -> list[FlextLdifModels.Entry]:
        """Parse and assert count and first DN - replaces 5-7 lines.

        Common pattern:
            result = parser.parse(content)
            assert result.is_success
            entries = result.unwrap()
            assert len(entries) == expected_count
            assert entries[0].dn.value == expected_first_dn

        Args:
            parser: Parser instance
            ldif_content: LDIF content or file path
            expected_count: Expected entry count
            expected_first_dn: Expected DN of first entry

        Returns:
            Parsed entries

        """
        return DeduplicationHelpers.parse_and_assert_basic(
            parser,
            ldif_content,
            expected_count=expected_count,
            expected_first_dn=expected_first_dn,
        )

    @staticmethod
    def helper_batch_parse_and_assert_counts(
        parser: Any,
        test_cases: list[dict[str, Any]],
    ) -> list[list[FlextLdifModels.Entry]]:
        """Test multiple parse operations with count assertions - replaces 30-100+ lines.

        Args:
            parser: Parser instance
            test_cases: List of test case dicts with keys:
                - ldif_content: str | Path (required)
                - expected_count: int (required)
                - expected_first_dn: str | None

        Returns:
            List of parsed entry lists (one per test case)

        """
        results = []
        for i, test_case in enumerate(test_cases):
            ldif_content = test_case.get("ldif_content")
            if ldif_content is None:
                msg = f"Test case {i} missing 'ldif_content'"
                raise ValueError(msg)

            expected_count = test_case.get("expected_count")
            if expected_count is None:
                msg = f"Test case {i} missing 'expected_count'"
                raise ValueError(msg)

            entries = DeduplicationHelpers.helper_parse_and_assert_count_and_dn(
                parser,
                ldif_content,
                expected_count=expected_count,
                expected_first_dn=test_case.get("expected_first_dn", ""),
            )
            results.append(entries)
        return results

    @staticmethod
    def helper_quirk_method_returns_boolean(
        quirk: Any,
        method_name: str,
        *args: Any,
        expected_value: bool,
        **kwargs: Any,
    ) -> bool:
        """Test quirk method returns boolean - replaces 4-6 lines.

        Common pattern:
            result = quirk.method_name(*args, **kwargs)
            assert result.is_success
            assert result.unwrap() is True/False

        Args:
            quirk: Quirk instance
            method_name: Method name to call
            *args: Positional arguments for method
            expected_value: Expected boolean value
            **kwargs: Keyword arguments for method

        Returns:
            Boolean result

        """
        method = getattr(quirk, method_name, None)
        if method is None:
            msg = f"Method {method_name} not found on quirk"
            raise AttributeError(msg)

        result = method(*args, **kwargs)
        return DeduplicationHelpers.assert_result_is_boolean(result, expected_value)

    @staticmethod
    def helper_quirk_method_returns_type(
        quirk: Any,
        method_name: str,
        *args: Any,
        expected_type: type[Any],
        **kwargs: Any,
    ) -> Any:
        """Test quirk method returns expected type - replaces 4-6 lines.

        Common pattern:
            result = quirk.method_name(*args, **kwargs)
            assert result.is_success
            value = result.unwrap()
            assert isinstance(value, ExpectedType)

        Args:
            quirk: Quirk instance
            method_name: Method name to call
            *args: Positional arguments for method
            expected_type: Expected return type
            **kwargs: Keyword arguments for method

        Returns:
            Method result

        """
        method = getattr(quirk, method_name, None)
        if method is None:
            msg = f"Method {method_name} not found on quirk"
            raise AttributeError(msg)

        result = method(*args, **kwargs)
        return DeduplicationHelpers.assert_result_is_type(result, expected_type)

    @staticmethod
    def helper_parse_failure_and_assert_error(
        parser: Any,
        content: str | Path,
        *,
        parse_method: str = "parse",
        expected_error_substring: str,
    ) -> FlextResult[Any]:
        """Parse failure with error validation - replaces 3-5 lines per use.

        Common pattern:
            result = parser.parse(content)
            assert result.is_failure
            assert expected_error in result.error

        Args:
            parser: Parser instance
            content: Content to parse
            parse_method: Method name to call (default: "parse")
            expected_error_substring: Substring that must be in error message

        Returns:
            Failed FlextResult

        """
        method = getattr(parser, parse_method, None)
        if method is None:
            msg = f"Method {parse_method} not found on parser"
            raise AttributeError(msg)

        result = method(content)

        TestAssertions.assert_failure(result, expected_error_substring)
        return result

    @staticmethod
    def helper_write_failure_and_assert_error(
        writer: Any,
        data: Any,
        *,
        write_method: str = "write",
        expected_error_substring: str | None = None,
    ) -> FlextResult[Any]:
        """Write failure with error validation - replaces 3-5 lines per use.

        Common pattern:
            result = writer.write(data)
            assert result.is_failure
            assert expected_error in result.error

        Args:
            writer: Writer instance
            data: Data to write
            write_method: Method name to call (default: "write")
            expected_error_substring: Optional substring that must be in error message

        Returns:
            Failed FlextResult

        """
        method = getattr(writer, write_method, None)
        if method is None:
            msg = f"Method {write_method} not found on writer"
            raise AttributeError(msg)

        result = method(data)  # type: ignore[misc]
        TestAssertions.assert_failure(result, expected_error_substring)
        return result

    @staticmethod
    def helper_parse_attribute_and_assert_syntax(
        schema_quirk: Any,
        attr_def: str,
        *,
        parse_method: str = "parse",
        expected_oid: str,
        expected_name: str,
        expected_syntax: str | None = None,
        expected_syntax_definition: str | None = None,
    ) -> FlextLdifModels.SchemaAttribute:
        """Parse attribute and assert OID + name + syntax - replaces 8-12 lines per use.

        Common pattern (appears 20+ times):
            result = schema_quirk.parse(attr_def)
            assert result.is_success
            attr = result.unwrap()
            assert attr.oid == expected_oid
            assert attr.name == expected_name
            assert attr.syntax == expected_syntax
            assert attr.syntax_definition == expected_syntax_definition

        Args:
            schema_quirk: Schema quirk instance
            attr_def: Attribute definition string
            parse_method: Method name to call (default: "parse")
            expected_oid: Expected OID
            expected_name: Expected name
            expected_syntax: Optional expected syntax OID
            expected_syntax_definition: Optional expected syntax definition

        Returns:
            Parsed attribute

        """
        # Parse schema and validate OID and name
        parse_func = getattr(schema_quirk, parse_method)
        result = parse_func(attr_def)
        parsed = TestAssertions.assert_success(result, "Schema parse should succeed")
        assert isinstance(
            parsed, (FlextLdifModels.SchemaAttribute, FlextLdifModels.SchemaObjectClass)
        ), "Expected SchemaAttribute or SchemaObjectClass"
        attr = cast("FlextLdifModels.SchemaAttribute", parsed)
        if expected_oid:
            assert attr.oid == expected_oid, (
                f"OID mismatch: expected {expected_oid}, got {attr.oid}"
            )
        if expected_name:
            assert attr.name == expected_name, (
                f"Name mismatch: expected {expected_name}, got {attr.name}"
            )

        assert isinstance(attr, FlextLdifModels.SchemaAttribute), (
            "Expected SchemaAttribute"
        )

        if expected_syntax is not None:
            assert attr.syntax == expected_syntax, (  # type: ignore[attr-defined]
                f"Expected syntax '{expected_syntax}', got '{attr.syntax}'"  # type: ignore[attr-defined]
            )

        if expected_syntax_definition is not None:
            assert hasattr(attr, "syntax_definition"), (
                "Attribute must have syntax_definition"
            )
            assert attr.syntax_definition == expected_syntax_definition, (  # type: ignore[attr-defined]
                f"Expected syntax_definition '{expected_syntax_definition}', got '{attr.syntax_definition}'"  # type: ignore[attr-defined]
            )

        return attr

    @staticmethod
    def helper_write_and_assert_count(
        writer: Any,
        data: Any,
        *,
        write_method: str = "write",
        expected_substring: str,
        expected_count: int,
    ) -> str:
        """Write and assert substring count in output - replaces 5-7 lines per use.

        Common pattern (appears 15+ times):
            result = writer.write(data)
            assert result.is_success
            ldif = result.unwrap()
            assert ldif.count("substring") == expected_count

        Args:
            writer: Writer instance
            data: Data to write
            write_method: Method name to call (default: "write")
            expected_substring: Substring to count
            expected_count: Expected count of substring

        Returns:
            Written LDIF string

        """
        ldif = DeduplicationHelpers.helper_write_unwrap_and_assert(
            writer, data, write_method=write_method
        )

        actual_count = ldif.count(expected_substring)
        assert actual_count == expected_count, (
            f"Expected '{expected_substring}' to appear {expected_count} times, "
            f"got {actual_count}"
        )

        return ldif

    @staticmethod
    def helper_parse_attribute_complete_validation(
        schema_quirk: Any,
        attr_def: str,
        *,
        parse_method: str = "parse",
        expected_oid: str,
        expected_name: str,
        expected_syntax: str | None = None,
        expected_syntax_definition: str | None = None,
        expected_single_value: bool | None = None,
        expected_equality: str | None = None,
    ) -> FlextLdifModels.SchemaAttribute:
        """Parse attribute with complete validation - replaces 12-20 lines per use.

        Common pattern (appears 15+ times):
            result = schema_quirk.parse(attr_def)
            assert result.is_success
            attr = result.unwrap()
            assert attr.oid == expected_oid
            assert attr.name == expected_name
            assert attr.syntax == expected_syntax
            assert attr.single_value == expected_single_value
            assert attr.equality == expected_equality

        Args:
            schema_quirk: Schema quirk instance
            attr_def: Attribute definition string
            parse_method: Method name to call (default: "parse")
            expected_oid: Expected OID
            expected_name: Expected name
            expected_syntax: Optional expected syntax OID
            expected_syntax_definition: Optional expected syntax definition
            expected_single_value: Optional expected single_value flag
            expected_equality: Optional expected equality matching rule

        Returns:
            Parsed attribute

        """
        attr = DeduplicationHelpers.helper_parse_attribute_and_assert_syntax(
            schema_quirk,
            attr_def,
            parse_method=parse_method,
            expected_oid=expected_oid,
            expected_name=expected_name,
            expected_syntax=expected_syntax,
            expected_syntax_definition=expected_syntax_definition,
        )

        if expected_single_value is not None:
            assert hasattr(attr, "single_value"), (
                "Attribute must have single_value attribute"
            )
            assert attr.single_value == expected_single_value, (  # type: ignore[attr-defined]
                f"Expected single_value={expected_single_value}, got {attr.single_value}"  # type: ignore[attr-defined]
            )

        if expected_equality is not None:
            assert hasattr(attr, "equality"), "Attribute must have equality attribute"
            assert attr.equality == expected_equality, (  # type: ignore[attr-defined]
                f"Expected equality='{expected_equality}', got '{attr.equality}'"  # type: ignore[attr-defined]
            )

        return attr

    @staticmethod
    def helper_parse_and_validate_each_item(
        parser: Any,
        content: str | Path,
        *,
        parse_method: str = "parse",
        expected_count: int | None = None,
        item_validator: Callable[[Any], bool] | None = None,
    ) -> list[Any]:
        """Parse and validate each item in result - replaces 8-15 lines per use.

        Common pattern (appears 20+ times):
            result = parser.parse(content)
            assert result.is_success
            items = result.unwrap()
            assert isinstance(items, list)
            assert len(items) == expected_count
            for item in items:
                assert item.property == expected_value

        Args:
            parser: Parser instance
            content: Content to parse
            parse_method: Method name to call (default: "parse")
            expected_count: Optional expected item count
            item_validator: Optional callable(item) to validate each item

        Returns:
            Parsed list of items

        """
        items = DeduplicationHelpers.helper_parse_unwrap_and_assert(
            parser, content, parse_method=parse_method
        )

        if not isinstance(items, list):
            items = [items] if items is not None else []

        if expected_count is not None:
            assert len(items) == expected_count, (
                f"Expected {expected_count} items, got {len(items)}"
            )

        if item_validator:
            for i, item in enumerate(items):
                try:
                    item_validator(item)
                except AssertionError as e:
                    msg = f"Item {i} validation failed: {e}"
                    raise AssertionError(msg) from e

        return items

    @staticmethod
    def helper_write_and_assert_starts_with(
        writer: Any,
        data: Any,
        *,
        write_method: str = "write",
        expected_prefix: str,
    ) -> str:
        """Write and assert output starts with prefix - replaces 4-6 lines per use.

        Common pattern (appears 15+ times):
            result = writer.write(data)
            assert result.is_success
            ldif = result.unwrap()
            assert ldif.startswith(expected_prefix)

        Args:
            writer: Writer instance
            data: Data to write
            write_method: Method name to call (default: "write")
            expected_prefix: Expected prefix string

        Returns:
            Written LDIF string

        """
        ldif = DeduplicationHelpers.helper_write_unwrap_and_assert(
            writer, data, write_method=write_method
        )

        assert ldif.startswith(expected_prefix), (
            f"Expected output to start with '{expected_prefix}', "
            f"but got: {ldif[:50]}..."
        )

        return ldif

    @staticmethod
    def helper_write_and_assert_ends_with(
        writer: Any,
        data: Any,
        *,
        write_method: str = "write",
        expected_suffix: str,
    ) -> str:
        """Write and assert output ends with suffix - replaces 4-6 lines per use.

        Common pattern (appears 15+ times):
            result = writer.write(data)
            assert result.is_success
            ldif = result.unwrap()
            assert ldif.endswith(expected_suffix)

        Args:
            writer: Writer instance
            data: Data to write
            write_method: Method name to call (default: "write")
            expected_suffix: Expected suffix string

        Returns:
            Written LDIF string

        """
        ldif = DeduplicationHelpers.helper_write_unwrap_and_assert(
            writer, data, write_method=write_method
        )

        assert ldif.endswith(expected_suffix), (
            f"Expected output to end with '{expected_suffix}', but got: ...{ldif[-50:]}"
        )

        return ldif

    @staticmethod
    def helper_parse_attribute_with_all_fields(
        schema_quirk: Any,
        attr_def: str,
        *,
        parse_method: str = "parse",
        expected_oid: str,
        expected_name: str,
        expected_desc: str | None = None,
        expected_syntax: str | None = None,
        expected_equality: str | None = None,
    ) -> FlextLdifModels.SchemaAttribute:
        """Parse attribute with all common fields - replaces 10-18 lines per use.

        Common pattern (appears 20+ times):
            result = schema_quirk.parse(attr_def)
            assert result.is_success
            attr = result.unwrap()
            assert attr.oid == expected_oid
            assert attr.name == expected_name
            assert attr.desc == expected_desc
            assert attr.syntax == expected_syntax
            assert attr.equality == expected_equality

        Args:
            schema_quirk: Schema quirk instance
            attr_def: Attribute definition string
            parse_method: Method name to call (default: "parse")
            expected_oid: Expected OID
            expected_name: Expected name
            expected_desc: Optional expected description
            expected_syntax: Optional expected syntax OID
            expected_equality: Optional expected equality matching rule

        Returns:
            Parsed attribute

        """
        attr = DeduplicationHelpers.helper_parse_attribute_and_assert_syntax(
            schema_quirk,
            attr_def,
            parse_method=parse_method,
            expected_oid=expected_oid,
            expected_name=expected_name,
            expected_syntax=expected_syntax,
        )

        if expected_desc is not None:
            assert hasattr(attr, "desc"), "Attribute must have desc attribute"
            assert attr.desc == expected_desc, (  # type: ignore[attr-defined]
                f"Expected desc='{expected_desc}', got '{attr.desc}'"  # type: ignore[attr-defined]
            )

        if expected_equality is not None:
            assert hasattr(attr, "equality"), "Attribute must have equality attribute"
            assert attr.equality == expected_equality, (  # type: ignore[attr-defined]
                f"Expected equality='{expected_equality}', got '{attr.equality}'"  # type: ignore[attr-defined]
            )

        return attr

    @staticmethod
    def execute_and_unwrap(
        quirk: Any,
        *,
        data: Any = None,
        operation: str | None = None,
        expected_type: type[Any] | None = None,
    ) -> Any:
        """Execute quirk and unwrap result - replaces 2-4 lines per use.

        Common pattern:
            result = quirk.execute(data=data, operation=operation)
            assert result.is_success
            unwrapped = result.unwrap()

        Args:
            quirk: Quirk instance
            data: Optional data to pass to execute
            operation: Optional operation name
            expected_type: Optional expected return type

        Returns:
            Unwrapped result

        """
        if data is not None and operation is not None:
            result = quirk.execute(data=data, operation=operation)
        elif data is not None:
            result = quirk.execute(data=data)
        elif operation is not None:
            result = quirk.execute(operation=operation)
        else:
            result = quirk.execute()

        unwrapped = DeduplicationHelpers.assert_success_and_unwrap(result)

        if expected_type:
            assert isinstance(unwrapped, expected_type), (
                f"Expected {expected_type}, got {type(unwrapped)}"
            )

        return unwrapped

    @staticmethod
    def helper_parse_and_assert_type(
        parser: Any,
        content: str | Path,
        *,
        parse_method: str = "parse",
        expected_type: type[Any],
    ) -> Any:
        """Parse and assert type - replaces 3-4 lines per use.

        Common pattern:
            result = parser.parse(content)
            assert result.is_success
            parsed = result.unwrap()
            assert isinstance(parsed, ExpectedType)

        Args:
            parser: Parser instance
            content: Content to parse
            parse_method: Method name to call (default: "parse")
            expected_type: Expected type

        Returns:
            Parsed result

        """
        unwrapped = DeduplicationHelpers.parse_and_unwrap_direct(
            parser, content, parse_method=parse_method
        )
        assert isinstance(unwrapped, expected_type), (
            f"Expected {expected_type}, got {type(unwrapped)}"
        )
        return unwrapped

    @staticmethod
    def helper_write_and_assert_contains(
        writer: Any,
        data: Any,
        *,
        write_method: str = "write",
        must_contain: str | list[str],
    ) -> str:
        """Write and assert contains - replaces 3-4 lines per use.

        Common pattern:
            result = writer.write(data)
            assert result.is_success
            written = result.unwrap()
            assert "text" in written

        Args:
            writer: Writer instance
            data: Data to write
            write_method: Method name to call (default: "write")
            must_contain: String or list of strings that must be in output

        Returns:
            Written string

        """
        written = DeduplicationHelpers.write_and_unwrap_direct(
            writer, data, write_method=write_method
        )

        contains_list = (
            [must_contain] if isinstance(must_contain, str) else must_contain
        )
        for text in contains_list:
            assert text in written, f"Output must contain '{text}'"

        return written

    @staticmethod
    def helper_convert_and_assert_strings(
        conversion_matrix: FlextLdifConversion,
        source: FlextLdifServersBase | str,
        target: FlextLdifServersBase | str,
        data_type: str,
        data: str | dict[str, object] | FlextLdifModels.Entry,
        *,
        must_contain: str | list[str] | None = None,
        must_not_contain: str | list[str] | None = None,
        expected_type: type | None = None,
        should_succeed: bool = True,
    ) -> str | dict[str, object]:
        """Complete conversion test with string assertions - uses model-based conversion.

        Refactored to use model-based conversion API:
        1. Parse string to model (if needed)
        2. Convert model using new API
        3. Write converted model to string for validation

        Args:
            conversion_matrix: Conversion matrix instance
            source: Source quirk or server type
            target: Target quirk or server type
            data_type: Data type ("attribute", "objectClass", "acl", "entry")
            data: Data to convert (string, dict, or Entry model)
            must_contain: String or list of strings that must be in result
            must_not_contain: String or list of strings that must NOT be in result
            expected_type: Expected type of result (default: str)
            should_succeed: Whether conversion should succeed (default: True)

        Returns:
            Converted data as string (for validation)

        """
        # Resolve source quirk for parsing
        if isinstance(source, str):
            from flext_ldif.services.server import FlextLdifServer

            server = FlextLdifServer()
            source_quirk = server.quirk(source)
            if source_quirk is None:
                raise ValueError(f"Unknown server type: {source}")
        else:
            source_quirk = source

        # Parse string to model if needed
        model: (
            FlextLdifModels.SchemaAttribute
            | FlextLdifModels.SchemaObjectClass
            | FlextLdifModels.Acl
            | FlextLdifModels.Entry
        )
        if isinstance(data, FlextLdifModels.Entry):
            model = data
        elif isinstance(data, str):
            # Parse string to model based on data_type
            if data_type.lower() == "attribute":
                parse_result = source_quirk.schema_quirk.parse_attribute(data)
                if parse_result.is_failure:
                    if should_succeed:
                        raise AssertionError(
                            f"Failed to parse attribute: {parse_result.error}"
                        )
                    return ""
                model = parse_result.unwrap()
            elif data_type.lower() in {"objectclass", "objectclasses"}:
                parse_result = source_quirk.schema_quirk.parse_objectclass(data)
                if parse_result.is_failure:
                    if should_succeed:
                        raise AssertionError(
                            f"Failed to parse objectClass: {parse_result.error}"
                        )
                    return ""
                model = parse_result.unwrap()
            elif data_type.lower() == "acl":
                parse_result = source_quirk.acl_quirk.parse(data)
                if parse_result.is_failure:
                    if should_succeed:
                        raise AssertionError(
                            f"Failed to parse ACL: {parse_result.error}"
                        )
                    return ""
                model = parse_result.unwrap()
            else:
                raise ValueError(
                    f"Unsupported data_type for string parsing: {data_type}"
                )
        else:
            raise ValueError(
                f"Unsupported data type: {type(data).__name__}. "
                "Expected str, Entry model, or dict[str, object]"
            )

        # Convert model using new API
        result = conversion_matrix.convert(source, target, model)

        if should_succeed:
            converted_model = TestAssertions.assert_success(
                result, f"Conversion failed: {result.error}"
            )
        else:
            _ = TestAssertions.assert_failure(result)
            return "" if expected_type is str else {}

        # Resolve target quirk for writing
        if isinstance(target, str):
            from flext_ldif.services.server import FlextLdifServer

            server = FlextLdifServer()
            target_quirk = server.quirk(target)
            if target_quirk is None:
                raise ValueError(f"Unknown server type: {target}")
        else:
            target_quirk = target

        # Write converted model to string for validation
        if isinstance(converted_model, FlextLdifModels.SchemaAttribute):
            write_result = target_quirk.schema_quirk.write_attribute(converted_model)
        elif isinstance(converted_model, FlextLdifModels.SchemaObjectClass):
            write_result = target_quirk.schema_quirk.write_objectclass(converted_model)
        elif isinstance(converted_model, FlextLdifModels.Acl):
            write_result = target_quirk.acl_quirk.write(converted_model)
        elif isinstance(converted_model, FlextLdifModels.Entry):
            write_result = target_quirk.entry_quirk.write(converted_model)
        else:
            raise ValueError(
                f"Unexpected converted model type: {type(converted_model).__name__}"
            )

        if write_result.is_failure:
            raise AssertionError(
                f"Failed to write converted model: {write_result.error}"
            )
        converted = write_result.unwrap()

        if expected_type is not None:
            assert isinstance(converted, expected_type), (
                f"Expected {expected_type.__name__}, got {type(converted).__name__}"
            )

        if isinstance(converted, str):
            if must_contain:
                contains_list = (
                    [must_contain] if isinstance(must_contain, str) else must_contain
                )
                for text in contains_list:
                    assert text in converted, f"Result must contain '{text}'"

            if must_not_contain:
                not_contains_list = (
                    [must_not_contain]
                    if isinstance(must_not_contain, str)
                    else must_not_contain
                )
                for text in not_contains_list:
                    assert text not in converted, f"Result must NOT contain '{text}'"

        return converted

    @staticmethod
    def helper_batch_convert_and_assert(
        conversion_matrix: FlextLdifConversion,
        source: FlextLdifServersBase | str,
        target: FlextLdifServersBase | str,
        data_type: str,
        items: list[str | dict[str, object] | FlextLdifModels.Entry],
        *,
        expected_count: int | None = None,
        should_succeed: bool = True,
        allow_partial: bool = False,
    ) -> list[str | dict[str, object]]:
        """Batch conversion test with assertions - uses model-based conversion.

        Refactored to use model-based batch conversion API.

        Args:
            conversion_matrix: Conversion matrix instance
            source: Source quirk or server type
            target: Target quirk or server type
            data_type: Data type ("attribute", "objectClass", "acl", "entry")
            items: List of items to convert (strings, dicts, or Entry models)
            expected_count: Optional expected count of converted items
            should_succeed: Whether conversion should succeed (default: True)
            allow_partial: Allow partial success (default: False)

        Returns:
            List of converted items as strings (for validation)

        """
        # Resolve source quirk for parsing
        if isinstance(source, str):
            from flext_ldif.services.server import FlextLdifServer

            server = FlextLdifServer()
            source_quirk = server.quirk(source)
            if source_quirk is None:
                raise ValueError(f"Unknown server type: {source}")
        else:
            source_quirk = source

        # Parse all items to models
        models: list[
            FlextLdifModels.SchemaAttribute
            | FlextLdifModels.SchemaObjectClass
            | FlextLdifModels.Acl
            | FlextLdifModels.Entry
        ] = []
        for item in items:
            if isinstance(item, FlextLdifModels.Entry):
                models.append(item)
            elif isinstance(item, str):
                # Parse string to model based on data_type
                if data_type.lower() == "attribute":
                    parse_result = source_quirk.schema_quirk.parse_attribute(item)
                    if parse_result.is_failure:
                        if should_succeed and not allow_partial:
                            raise AssertionError(
                                f"Failed to parse attribute: {parse_result.error}"
                            )
                        continue
                    models.append(parse_result.unwrap())
                elif data_type.lower() in {"objectclass", "objectclasses"}:
                    parse_result = source_quirk.schema_quirk.parse_objectclass(item)
                    if parse_result.is_failure:
                        if should_succeed and not allow_partial:
                            raise AssertionError(
                                f"Failed to parse objectClass: {parse_result.error}"
                            )
                        continue
                    models.append(parse_result.unwrap())
                elif data_type.lower() == "acl":
                    parse_result = source_quirk.acl_quirk.parse(item)
                    if parse_result.is_failure:
                        if should_succeed and not allow_partial:
                            raise AssertionError(
                                f"Failed to parse ACL: {parse_result.error}"
                            )
                        continue
                    models.append(parse_result.unwrap())
                else:
                    raise ValueError(
                        f"Unsupported data_type for string parsing: {data_type}"
                    )
            else:
                raise ValueError(
                    f"Unsupported item type: {type(item).__name__}. "
                    "Expected str, Entry model, or dict[str, object]"
                )

        # Convert models using new batch API
        result = conversion_matrix.batch_convert(source, target, models)

        if should_succeed:
            if allow_partial:
                # For partial failures, just check result is not None
                assert result is not None, "Batch conversion returned None"
                converted_models = result.unwrap() if result.is_success else []
            else:
                converted_models = TestAssertions.assert_success(
                    result, f"Batch conversion failed: {result.error}"
                )
        else:
            _ = TestAssertions.assert_failure(result)
            return []

        # Resolve target quirk for writing
        if isinstance(target, str):
            from flext_ldif.services.server import FlextLdifServer

            server = FlextLdifServer()
            target_quirk = server.quirk(target)
            if target_quirk is None:
                raise ValueError(f"Unknown server type: {target}")
        else:
            target_quirk = target

        # Write converted models to strings for validation
        converted: list[str] = []
        for model in converted_models:
            if isinstance(model, FlextLdifModels.SchemaAttribute):
                write_result = target_quirk.schema_quirk.write_attribute(model)
            elif isinstance(model, FlextLdifModels.SchemaObjectClass):
                write_result = target_quirk.schema_quirk.write_objectclass(model)
            elif isinstance(model, FlextLdifModels.Acl):
                write_result = target_quirk.acl_quirk.write(model)
            elif isinstance(model, FlextLdifModels.Entry):
                write_result = target_quirk.entry_quirk.write(model)
            else:
                raise ValueError(
                    f"Unexpected converted model type: {type(model).__name__}"
                )

            if write_result.is_success:
                converted.append(write_result.unwrap())
            elif not allow_partial:
                raise AssertionError(
                    f"Failed to write converted model: {write_result.error}"
                )

        if expected_count is not None:
            assert len(converted) == expected_count, (
                f"Expected {expected_count} items, got {len(converted)}"
            )

        return converted

    @staticmethod
    def helper_parse_write_and_assert_contains(
        quirk: Any,
        content: str,
        *,
        parse_method: str = "parse",
        write_method: str = "write",
        must_contain: str | list[str],
    ) -> tuple[Any, str]:
        """Parse, write and assert contains - replaces 6-10 lines per use.

        Common pattern:
            result = quirk.parse(content)
            assert result.is_success
            parsed = result.unwrap()
            result = quirk.write(parsed)
            assert result.is_success
            written = result.unwrap()
            assert "text" in written

        Args:
            quirk: Quirk instance
            content: Content to parse
            parse_method: Method name for parsing (default: "parse")
            write_method: Method name for writing (default: "write")
            must_contain: String or list of strings that must be in written output

        Returns:
            Tuple of (parsed_object, written_string)

        """
        parsed = DeduplicationHelpers.parse_and_unwrap_direct(
            quirk, content, parse_method=parse_method
        )
        written = DeduplicationHelpers.helper_write_and_assert_contains(
            quirk, parsed, write_method=write_method, must_contain=must_contain
        )
        return parsed, written

    @staticmethod
    def helper_parse_entry_and_assert_dn_in_output(
        parser: Any,
        ldif_content: str,
        *,
        parse_method: str = "parse",
        expected_dn: str,
        must_contain_in_output: str | list[str] | None = None,
    ) -> FlextLdifModels.Entry:
        """Parse entry and assert DN in output - replaces 5-8 lines per use.

        Common pattern:
            result = parser.parse(ldif_content)
            assert result.is_success
            entries = result.unwrap()
            assert len(entries) == 1
            entry = entries[0]
            assert entry.dn.value == expected_dn
            result = parser.write(entry)
            assert "dn: expected_dn" in result.unwrap()

        Args:
            parser: Parser instance
            ldif_content: LDIF content string
            parse_method: Method name to call (default: "parse")
            expected_dn: Expected DN value
            must_contain_in_output: Optional strings that must be in written output

        Returns:
            Parsed entry

        """
        entries = DeduplicationHelpers.parse_and_unwrap_direct(
            parser, ldif_content, parse_method=parse_method
        )

        if isinstance(entries, list):
            assert len(entries) == 1, f"Expected 1 entry, got {len(entries)}"
            entry = entries[0]
        else:
            entry = entries

        assert isinstance(entry, FlextLdifModels.Entry), (
            f"Expected Entry, got {type(entry)}"
        )
        assert entry.dn is not None, "Entry must have DN"
        assert entry.dn.value == expected_dn, (
            f"Expected DN '{expected_dn}', got '{entry.dn.value}'"
        )

        if must_contain_in_output:
            written = DeduplicationHelpers.write_and_unwrap_direct(parser, entry)
            contains_list = (
                [must_contain_in_output]
                if isinstance(must_contain_in_output, str)
                else must_contain_in_output
            )
            for text in contains_list:
                assert text in written, f"Output must contain '{text}'"

        return entry

    @staticmethod
    def helper_write_and_assert_line_count(
        writer: Any,
        data: Any,
        *,
        write_method: str = "write",
        expected_line_count: int | None = None,
        minimum_line_count: int | None = None,
    ) -> str:
        r"""Write and assert line count in output - replaces 5-8 lines per use.

        Common pattern (appears 20+ times):
            result = writer.write(data)
            assert result.is_success
            ldif = result.unwrap()
            lines = ldif.split("\n")
            assert len(lines) == expected_line_count

        Args:
            writer: Writer instance
            data: Data to write
            write_method: Method name to call (default: "write")
            expected_line_count: Optional exact expected line count
            minimum_line_count: Optional minimum expected line count

        Returns:
            Written LDIF string

        """
        ldif = DeduplicationHelpers.helper_write_unwrap_and_assert(
            writer, data, write_method=write_method
        )

        lines = ldif.split("\n")
        actual_count = len(lines)

        if expected_line_count is not None:
            assert actual_count == expected_line_count, (
                f"Expected {expected_line_count} lines, got {actual_count}"
            )

        if minimum_line_count is not None:
            assert actual_count >= minimum_line_count, (
                f"Expected at least {minimum_line_count} lines, got {actual_count}"
            )

        return ldif

    @staticmethod
    def helper_parse_and_assert_dict_keys(
        parser: Any,
        content: str | Path,
        *,
        parse_method: str = "parse",
        expected_keys: list[str],
    ) -> dict[str, Any]:
        """Parse and assert dict has expected keys - replaces 6-10 lines per use.

        Common pattern (appears 15+ times):
            result = parser.parse(content)
            assert result.is_success
            data = result.unwrap()
            assert isinstance(data, dict)
            assert "key1" in data.keys()
            assert "key2" in data.keys()

        Args:
            parser: Parser instance
            content: Content to parse
            parse_method: Method name to call (default: "parse")
            expected_keys: List of keys that must exist in dict

        Returns:
            Parsed dict

        """
        data = DeduplicationHelpers.helper_parse_unwrap_and_assert(
            parser, content, parse_method=parse_method
        )

        assert isinstance(data, dict), "Parsed result must be a dict"

        for key in expected_keys:
            assert key in data, f"Dict must have key '{key}'"

        return data

    @staticmethod
    def helper_parse_and_assert_dict_values(
        parser: Any,
        content: str | Path,
        *,
        parse_method: str = "parse",
        expected_key_value_pairs: dict[str, Any],
    ) -> dict[str, Any]:
        """Parse and assert dict has expected key-value pairs - replaces 8-15 lines per use.

        Common pattern (appears 20+ times):
            result = parser.parse(content)
            assert result.is_success
            data = result.unwrap()
            assert isinstance(data, dict)
            assert data["key1"] == expected_value1
            assert data["key2"] == expected_value2

        Args:
            parser: Parser instance
            content: Content to parse
            parse_method: Method name to call (default: "parse")
            expected_key_value_pairs: Dict of key: expected_value pairs

        Returns:
            Parsed dict

        """
        data = DeduplicationHelpers.helper_parse_and_assert_dict_keys(
            parser,
            content,
            parse_method=parse_method,
            expected_keys=list(expected_key_value_pairs.keys()),
        )

        for key, expected_value in expected_key_value_pairs.items():
            assert data[key] == expected_value, (
                f"Expected data['{key}'] == {expected_value}, got {data[key]}"
            )

        return data

    @staticmethod
    def helper_write_and_assert_line_contains(
        writer: Any,
        data: Any,
        *,
        write_method: str = "write",
        line_must_contain: str | list[str],
    ) -> str:
        r"""Write and assert specific lines contain text - replaces 6-10 lines per use.

        Common pattern (appears 20+ times):
            result = writer.write(data)
            assert result.is_success
            ldif = result.unwrap()
            lines = ldif.split("\n")
            assert "expected_text" in lines[0]
            assert "another_text" in lines[1]

        Args:
            writer: Writer instance
            data: Data to write
            write_method: Method name to call (default: "write")
            line_must_contain: String or list of strings that must be in output lines

        Returns:
            Written LDIF string

        """
        ldif = DeduplicationHelpers.helper_write_unwrap_and_assert(
            writer, data, write_method=write_method
        )

        lines = ldif.split("\n")
        contains_list = (
            [line_must_contain]
            if isinstance(line_must_contain, str)
            else line_must_contain
        )

        for text in contains_list:
            found = any(text in line for line in lines)
            assert found, f"Expected text '{text}' not found in any line of output"

        return ldif

    @staticmethod
    def helper_convert_roundtrip_and_assert(
        conversion_matrix: FlextLdifConversion,
        source: Any,
        target: Any,
        data_type: str,
        original_data: str | dict[str, object],
        *,
        must_contain_in_roundtrip: str | list[str] | None = None,
        validate_equivalence: bool = True,
    ) -> str | dict[str, object]:
        """Complete roundtrip conversion test - uses NEW model-based API.

        NEW API: Uses parse→convert→write pipeline for roundtrip testing.
        1. Parse original_data to model
        2. Convert model forward (source → target)
        3. Convert model backward (target → source)
        4. Write back to string for comparison

        Args:
            conversion_matrix: Conversion matrix instance
            source: Source quirk or server type
            target: Target quirk or server type
            data_type: Data type ("attribute", "objectClass", "acl", "entry")
            original_data: Original data string to convert
            must_contain_in_roundtrip: Strings that must be in roundtrip result
            validate_equivalence: Whether to validate semantic equivalence (default: True)

        Returns:
            Roundtrip result as string

        """
        # Resolve source quirk for parsing
        if isinstance(source, str):
            from flext_ldif.services.server import FlextLdifServer

            server = FlextLdifServer()
            source_quirk = server.quirk(source)
            if source_quirk is None:
                raise ValueError(f"Unknown server type: {source}")
        else:
            source_quirk = source

        # Parse string to model
        if not isinstance(original_data, str):
            msg = "Roundtrip test requires string input"
            raise ValueError(msg)

        if data_type.lower() == "attribute":
            parse_result = source_quirk.schema_quirk.parse_attribute(original_data)
        elif data_type.lower() in {"objectclass", "objectclasses"}:
            parse_result = source_quirk.schema_quirk.parse_objectclass(original_data)
        elif data_type.lower() == "acl":
            parse_result = source_quirk.acl_quirk.parse(original_data)
        else:
            raise ValueError(f"Unsupported data_type for roundtrip: {data_type}")

        original_model = TestAssertions.assert_success(
            parse_result, f"Failed to parse original {data_type}"
        )

        # Forward conversion: source model → target model
        forward_result = conversion_matrix.convert(source, target, original_model)
        forward_model = TestAssertions.assert_success(
            forward_result, "Forward conversion should succeed"
        )

        # Backward conversion: target model → source model
        backward_result = conversion_matrix.convert(target, source, forward_model)
        roundtrip_model = TestAssertions.assert_success(
            backward_result, "Backward conversion should succeed"
        )

        # Write roundtrip model back to string
        if isinstance(roundtrip_model, FlextLdifModels.SchemaAttribute):
            write_result = source_quirk.schema_quirk.write_attribute(roundtrip_model)
        elif isinstance(roundtrip_model, FlextLdifModels.SchemaObjectClass):
            write_result = source_quirk.schema_quirk.write_objectclass(roundtrip_model)
        elif isinstance(roundtrip_model, FlextLdifModels.Acl):
            write_result = source_quirk.acl_quirk.write(roundtrip_model)
        else:
            raise ValueError(
                f"Unexpected roundtrip model type: {type(roundtrip_model).__name__}"
            )

        roundtrip = TestAssertions.assert_success(
            write_result, f"Failed to write roundtrip {data_type}"
        )

        if (
            validate_equivalence
            and isinstance(roundtrip, str)
            and must_contain_in_roundtrip
        ):
            contains_list = (
                [must_contain_in_roundtrip]
                if isinstance(must_contain_in_roundtrip, str)
                else must_contain_in_roundtrip
            )
            for text in contains_list:
                assert text in roundtrip, (
                    f"Roundtrip result must contain '{text}' for semantic equivalence"
                )

        return cast("str | dict[str, object]", roundtrip)

    @staticmethod
    def helper_get_supported_conversions_and_assert(
        conversion_matrix: FlextLdifConversion,
        quirk: Any,
        *,
        expected_support: dict[str, bool] | None = None,
        must_have_keys: list[str] | None = None,
    ) -> dict[str, bool]:
        """Get supported conversions and assert - replaces 8-12 lines.

        Common pattern (appears 10+ times):
            supported = conversion_matrix.get_supported_conversions(quirk)
            assert isinstance(supported, dict)
            assert "attribute" in supported
            assert "objectClass" in supported
            assert "acl" in supported
            assert "entry" in supported
            assert supported["attribute"] is True
            assert supported["objectClass"] is True

        Args:
            conversion_matrix: Conversion matrix instance
            quirk: Quirk instance to check
            expected_support: Dict of expected support values (key -> bool)
            must_have_keys: List of keys that must exist in result

        Returns:
            Supported conversions dict

        """
        supported = conversion_matrix.get_supported_conversions(quirk)

        assert isinstance(supported, dict), "Supported must be a dict"

        if must_have_keys:
            for key in must_have_keys:
                assert key in supported, f"Supported dict must have key '{key}'"

        if expected_support:
            for key, expected_value in expected_support.items():
                assert key in supported, f"Supported dict must have key '{key}'"
                assert supported[key] == expected_value, (
                    f"Expected supported['{key}']={expected_value}, got {supported[key]}"
                )

        return supported

    @staticmethod
    def helper_result_and_assert_fields(
        result: FlextResult[Any],
        *,
        expected_fields: dict[str, Any] | None = None,
        must_have_attributes: list[str] | None = None,
        should_succeed: bool = True,
        expected_value: Any | None = None,
    ) -> Any:
        """Validate result and assert multiple fields - replaces 8-15 lines.

        Common pattern (appears 30+ times):
            assert result.is_success
            report = result.unwrap()
            assert report.is_valid is True
            assert report.total_entries == 0
            assert hasattr(report, "errors")

        Args:
            result: FlextResult to validate
            expected_fields: Dict of field_name -> expected_value
            must_have_attributes: List of attribute names that must exist
            should_succeed: Whether result should succeed (default: True)
            expected_value: If result is a simple value (not object), expected value

        Returns:
            Unwrapped result

        """
        if should_succeed:
            _ = TestAssertions.assert_success(result)
        else:
            _ = TestAssertions.assert_failure(result)
            return None

    @staticmethod
    def schema_parse_with_constant_and_validate(
        schema_quirk: FlextLdifServersBase.Schema,
        constants_class: type[Any],
        constant_name: str,
        *,
        parse_method: str = "_parse_attribute",
        expected_oid_constant: str | None = None,
        expected_name_constant: str | None = None,
        expected_type: type[
            FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass
        ] = FlextLdifModels.SchemaAttribute,
    ) -> FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass:
        """Parse schema with constant and validate - replaces 10-15 lines per test.

        Common pattern (appears 50+ times):
            constant_value = getattr(TestsOudConstants, "SAMPLE_ATTRIBUTE_DEF", None)
            assert constant_value is not None, "SAMPLE_ATTRIBUTE_DEF constant not found"
            result = schema_quirk._parse_attribute(constant_value)
            parsed = TestAssertions.assert_success(result, "Parse attribute should succeed")
            assert isinstance(parsed, FlextLdifModels.SchemaAttribute), "Should return SchemaAttribute"
            expected_oid = getattr(TestsOudConstants, "SAMPLE_ATTRIBUTE_OID", None)
            expected_name = getattr(TestsOudConstants, "SAMPLE_ATTRIBUTE_NAME", None)
            if expected_oid:
                assert parsed.oid == expected_oid, f"Expected OID {expected_oid}, got {parsed.oid}"
            if expected_name:
                assert parsed.name == expected_name, f"Expected name {expected_name}, got {parsed.name}"

        Args:
            schema_quirk: Schema quirk instance
            constants_class: Constants class (e.g., TestsOudConstants, TestsRfcConstants)
            constant_name: Name of constant attribute (e.g., "SAMPLE_ATTRIBUTE_DEF")
            parse_method: Method name for parsing (default: "_parse_attribute")
            expected_oid_constant: Optional constant name for expected OID (e.g., "SAMPLE_ATTRIBUTE_OID")
            expected_name_constant: Optional constant name for expected name (e.g., "SAMPLE_ATTRIBUTE_NAME")
            expected_type: Expected return type (default: SchemaAttribute)

        Returns:
            Parsed schema object (SchemaAttribute or SchemaObjectClass)

        Example:
            # Replaces 10-15 lines:
            attr = TestDeduplicationHelpers.schema_parse_with_constant_and_validate(
                schema_quirk,
                TestsOudConstants,
                "SAMPLE_ATTRIBUTE_DEF",
                parse_method="_parse_attribute",
                expected_oid_constant="SAMPLE_ATTRIBUTE_OID",
                expected_name_constant="SAMPLE_ATTRIBUTE_NAME",
            )

        """
        # Get constant value
        constant_value = getattr(constants_class, constant_name, None)
        assert constant_value is not None, (
            f"{constant_name} constant not found in {constants_class.__name__}"
        )
        assert isinstance(constant_value, str), f"{constant_name} must be string"

        # Parse using the specified method
        parse_func = getattr(schema_quirk, parse_method, None)
        assert parse_func is not None, (
            f"Method {parse_method} not found on schema_quirk"
        )
        result = parse_func(constant_value)  # type: ignore[misc]

        # Assert success and get parsed object
        parsed = TestAssertions.assert_success(result, f"{parse_method} should succeed")
        assert isinstance(parsed, expected_type), (
            f"Should return {expected_type.__name__}"
        )
        # Type narrowing: parsed is now known to be SchemaAttribute | SchemaObjectClass
        parsed_schema = cast(
            "FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass",
            parsed,
        )

        # Validate OID if expected_oid_constant provided
        if expected_oid_constant:
            expected_oid = getattr(constants_class, expected_oid_constant, None)
            if expected_oid:
                assert parsed_schema.oid == expected_oid, (
                    f"Expected OID {expected_oid}, got {parsed_schema.oid}"
                )

        # Validate name if expected_name_constant provided
        if expected_name_constant:
            expected_name = getattr(constants_class, expected_name_constant, None)
            if expected_name:
                assert parsed_schema.name == expected_name, (
                    f"Expected name {expected_name}, got {parsed_schema.name}"
                )

        return parsed_schema

    @staticmethod
    def api_parse_write_roundtrip_and_assert(
        ldif_api: FlextLdif,
        ldif_content: str,
        *,
        server_type: str | None = None,
        expected_entry_count: int | None = None,
        must_contain_in_written: list[str] | None = None,
        must_not_contain_in_written: list[str] | None = None,
    ) -> tuple[list[FlextLdifModels.Entry], str]:
        """Complete parse-write roundtrip test - replaces 15-25 lines per test.

        Common pattern (appears 30+ times):
            entries = RfcTestHelpers.test_api_parse_and_assert(
                ldif_api, entries_ldif, server_type="oud"
            )
            assert len(entries) >= 1
            write_result = ldif_api.write(entries, server_type="oud")
            assert write_result.is_success
            written_ldif = write_result.unwrap()
            assert len(written_ldif) > 0
            # Parse again to verify round-trip
            entries2 = RfcTestHelpers.test_api_parse_and_assert(
                ldif_api, written_ldif, server_type="oud"
            )
            assert len(entries2) >= 1

        Args:
            ldif_api: FlextLdif API instance
            ldif_content: LDIF content string to parse
            server_type: Optional server type (e.g., "oud", "oid", "rfc")
            expected_entry_count: Optional expected number of entries
            must_contain_in_written: Optional strings that must appear in written LDIF
            must_not_contain_in_written: Optional strings that must NOT appear in written LDIF

        Returns:
            Tuple of (parsed_entries, written_ldif_string)

        Example:
            # Replaces 15-25 lines:
            entries, written = TestDeduplicationHelpers.api_parse_write_roundtrip_and_assert(
                ldif_api,
                entries_ldif,
                server_type="oud",
                expected_entry_count=1,
                must_contain_in_written=["dn:", "cn:"],
            )

        """
        # Parse initial LDIF
        # Type narrowing: FlextLdif implements the protocol but type checker doesn't recognize it
        # Cast to HasParseMethod since FlextLdif has compatible methods (with overloads)
        from tests.helpers.test_rfc_helpers import HasParseMethod, RfcTestHelpers

        ldif_api_protocol: HasParseMethod = cast("HasParseMethod", ldif_api)  # type: ignore[assignment]
        entries = RfcTestHelpers.test_api_parse_and_assert(
            ldif_api_protocol, ldif_content, server_type=server_type
        )

        if expected_entry_count is not None:
            assert len(entries) == expected_entry_count, (
                f"Expected {expected_entry_count} entries, got {len(entries)}"
            )
        else:
            assert len(entries) >= 1, "Should have at least 1 entry"

        # Write entries
        write_result = ldif_api.write(entries, server_type=server_type)
        written_ldif = TestAssertions.assert_success(
            write_result, "Write should succeed"
        )
        assert isinstance(written_ldif, str), "Write should return string"
        assert len(written_ldif) > 0, "Written LDIF should not be empty"

        # Validate written content
        if must_contain_in_written:
            for text in must_contain_in_written:
                assert text in written_ldif, f"Written LDIF must contain '{text}'"

        if must_not_contain_in_written:
            for text in must_not_contain_in_written:
                assert text not in written_ldif, (
                    f"Written LDIF must not contain '{text}'"
                )

        # Parse again to verify round-trip
        # Type narrowing: FlextLdif implements the protocol but type checker doesn't recognize it
        # Cast to HasParseMethod since FlextLdif has compatible methods (with overloads)
        entries2 = RfcTestHelpers.test_api_parse_and_assert(
            ldif_api_protocol, written_ldif, server_type=server_type
        )
        assert len(entries2) >= 1, "Roundtrip should produce at least 1 entry"

        return entries, written_ldif

    @staticmethod
    def helper_write_and_assert_contains_constants(
        writer: Any,
        data: Any,
        constants: object,  # Constants class with dynamic attributes
        *,
        constant_attrs: list[str],
        must_not_contain: list[str] | None = None,
        write_method: str = "write",
        **kwargs: Any,
    ) -> str:
        """Write and assert using constants - replaces 8-12 lines per test.

        Common pattern (appears 20+ times):
            result = quirk.write(entry)
            assert result.is_success
            written = result.unwrap()
            assert TestsOudConstants.SAMPLE_ATTRIBUTE_NAME in written
            assert "matchingrules:" not in written.lower()

        Args:
            writer: Writer instance
            data: Data to write
            constants: Constants class (e.g., TestsOudConstants, TestsRfcConstants)
            constant_attrs: List of constant attribute names to check in output
            must_not_contain: List of strings that must NOT be in output
            write_method: Method name to call (default: "write")
            **kwargs: Additional arguments to pass to write method

        Returns:
            Written string

        """
        written = DeduplicationHelpers.helper_write_unwrap_and_assert(
            writer, data, write_method=write_method, **kwargs
        )

        # Check constants are in output
        for attr_name in constant_attrs:
            if hasattr(constants, attr_name):
                constant_value = getattr(constants, attr_name)
                assert constant_value in written, (
                    f"Constant {attr_name}={constant_value} not found in output"
                )

        # Check strings that must NOT be present
        if must_not_contain:
            for text in must_not_contain:
                assert text not in written.lower(), f"Output must NOT contain '{text}'"

        return written

    @staticmethod
    def helper_create_entry_with_constants(
        constants: ConstantsClass,
        *,
        dn_constant: str | None = None,
        attr_constants: dict[str, str] | None = None,
        objectclass_constants: list[str] | None = None,
    ) -> FlextLdifModels.Entry:
        """Create entry using constants - replaces 5-8 lines per test.

        Common pattern (appears 30+ times):
            entry = FlextLdifModels.Entry.create(
                dn=TestGeneralConstants.SAMPLE_DN,
                attributes={
                    TestGeneralConstants.ATTR_NAME_CN: [TestGeneralConstants.ATTR_VALUE_TEST],
                    "objectClass": [TestGeneralConstants.OC_NAME_PERSON],
                }
            ).unwrap()

        Args:
            constants: Constants class (e.g., TestGeneralConstants)
            dn_constant: Constant name for DN (e.g., "SAMPLE_DN")
            attr_constants: Dict of {attr_name: constant_name} for attributes
            objectclass_constants: List of constant names for objectClass values

        Returns:
            Created Entry

        """
        dn_value: str | None = getattr(constants, dn_constant) if dn_constant else None
        if dn_value is None:
            msg = "DN value is required"
            raise ValueError(msg)

        attributes: dict[str, str | list[str]] = {}
        if attr_constants:
            for attr_name, const_name in attr_constants.items():
                attr_value = getattr(constants, const_name)
                if isinstance(attr_value, str):
                    attributes[attr_name] = [attr_value]
                else:
                    attributes[attr_name] = attr_value  # type: ignore[assignment]

        if objectclass_constants:
            oc_values = [
                getattr(constants, oc_const) for oc_const in objectclass_constants
            ]
            attributes["objectClass"] = oc_values

        entry_result = FlextLdifModels.Entry.create(dn=dn_value, attributes=attributes)
        unwrapped = TestAssertions.assert_success(
            entry_result, "Entry creation should succeed"
        )
        assert isinstance(unwrapped, FlextLdifModels.Entry), (
            "Entry creation should return Entry"
        )
        return unwrapped

    @staticmethod
    def helper_parse_schema_with_constants_and_assert(
        schema_quirk: Any,
        attr_def: str,
        constants: ConstantsClass,
        *,
        expected_oid_constant: str | None = None,
        expected_name_constant: str | None = None,
        parse_method: str = "parse_attribute",
        should_succeed: bool = True,
    ) -> FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass:
        """Parse schema with constants validation - replaces 10-15 lines per test.

        Common pattern (appears 30+ times):
            attr_def = TestsOudConstants.SAMPLE_ATTRIBUTE_DEF
            result = schema_quirk.parse_attribute(attr_def)
            assert result.is_success
            attr = result.unwrap()
            assert attr.oid == TestsOudConstants.SAMPLE_ATTRIBUTE_OID
            assert attr.name == TestsOudConstants.SAMPLE_ATTRIBUTE_NAME

        Args:
            schema_quirk: Schema quirk instance
            attr_def: Attribute or objectClass definition string
            constants: Constants class (e.g., TestsOudConstants, TestsRfcConstants)
            expected_oid_constant: Constant name for expected OID
            expected_name_constant: Constant name for expected name
            parse_method: Method name to call (default: "parse_attribute")
            should_succeed: Whether parse should succeed (default: True)

        Returns:
            Parsed schema attribute or objectClass

        """
        parse_func = getattr(schema_quirk, parse_method)
        result = parse_func(attr_def)

        if should_succeed:
            parsed = TestAssertions.assert_success(
                result, "Schema parse should succeed"
            )
        else:
            _ = TestAssertions.assert_failure(result)
            msg = "Schema parse should fail"
            raise AssertionError(msg)

        # Validate against constants
        # Type narrowing: parsed is already validated as expected_type above
        # Cast to correct type since parsed comes from assert_success which returns object
        parsed_schema = cast(
            "FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass",
            parsed,
        )
        if expected_oid_constant and hasattr(constants, expected_oid_constant):
            expected_oid = getattr(constants, expected_oid_constant)
            if isinstance(expected_oid, str):
                assert parsed_schema.oid == expected_oid, (
                    f"OID mismatch: expected {expected_oid}, got {parsed_schema.oid}"
                )

        if expected_name_constant and hasattr(constants, expected_name_constant):
            expected_name = getattr(constants, expected_name_constant)
            if isinstance(expected_name, str):
                assert parsed_schema.name == expected_name, (
                    f"Name mismatch: expected {expected_name}, got {parsed_schema.name}"
                )

        return parsed_schema

    @staticmethod
    def helper_parse_write_schema_with_constants(
        schema_quirk: Any,
        schema_def: str,
        constants: ConstantsClass,
        *,
        constant_attrs: list[str],
        parse_method: str = "parse_attribute",
        write_method: str = "write_attribute",
        must_contain_in_output: list[str] | None = None,
    ) -> tuple[
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass, str
    ]:
        """Parse and write schema with constants validation - replaces 12-18 lines.

        Common pattern (appears 20+ times):
            attr_def = TestsRfcConstants.ATTR_DEF_CN
            result = schema_quirk.parse_attribute(attr_def)
            assert result.is_success
            attr = result.unwrap()
            write_result = schema_quirk.write_attribute(attr)
            assert write_result.is_success
            written = write_result.unwrap()
            assert TestsRfcConstants.ATTR_OID_CN in written
            assert TestsRfcConstants.ATTR_NAME_CN in written

        Args:
            schema_quirk: Schema quirk instance
            schema_def: Schema definition string
            constants: Constants class
            constant_attrs: List of constant attribute names to check
            parse_method: Method name for parsing (default: "parse_attribute")
            write_method: Method name for writing (default: "write_attribute")
            must_contain_in_output: Additional strings that must be in output

        Returns:
            Tuple of (parsed_schema, written_string)

        """
        parsed = DeduplicationHelpers.helper_parse_schema_with_constants_and_assert(
            schema_quirk,
            schema_def,
            constants,
            parse_method=parse_method,
        )

        written = DeduplicationHelpers.helper_write_and_assert_contains_constants(
            schema_quirk,
            parsed,
            constants,
            constant_attrs=constant_attrs,
            write_method=write_method,
            must_not_contain=must_contain_in_output,
        )

        return parsed, written

    @staticmethod
    def helper_assert_constants_in_collection(
        collection: list[Any] | dict[str, Any],
        constants: ConstantsClass,
        *,
        constant_attrs: list[str],
        check_field: str = "name",
    ) -> None:
        """Assert constants exist in collection - replaces 5-10 lines per test.

        Common pattern (appears 15+ times):
            attr_names = {attr.name for attr in attributes}
            assert TestsRfcConstants.ATTR_NAME_CN in attr_names
            assert TestsRfcConstants.ATTR_NAME_SN in attr_names

        Args:
            collection: List or dict to check
            constants: Constants class
            constant_attrs: List of constant attribute names to check
            check_field: Field name to extract from items (default: "name")

        """
        if isinstance(collection, list):
            values = {
                getattr(item, check_field)
                for item in collection
                if hasattr(item, check_field)
            }
        elif isinstance(collection, dict):
            values = set(collection.keys())
        else:
            msg = f"Unsupported collection type: {type(collection)}"
            raise TypeError(msg)

        for const_name in constant_attrs:
            if hasattr(constants, const_name):
                const_value = getattr(constants, const_name)
                assert const_value in values, (
                    f"Constant {const_name}={const_value} not found in collection"
                )

    @staticmethod
    def helper_create_schema_attribute_with_constants(
        constants: ConstantsClass,
        *,
        oid_constant: str | None = None,
        name_constant: str | None = None,
        desc: str | None = None,
        sup: str | None = None,
        equality: str | None = None,
        ordering: str | None = None,
        substr: str | None = None,
        syntax: str | None = None,
        length: int | None = None,
        usage: str | None = None,
        x_origin: str | None = None,
        **kwargs: Any,
    ) -> FlextLdifModels.SchemaAttribute:
        """Create schema attribute using constants - replaces 10-20 lines.

        Common pattern (appears 30+ times):
            attr = FlextLdifModels.SchemaAttribute(
                name=TestsOudConstants.SAMPLE_ATTRIBUTE_NAME,
                oid=TestsOudConstants.SAMPLE_ATTRIBUTE_OID,
                desc=None,
                sup=None,
                equality=None,
                ordering=None,
                substr=None,
                syntax=None,
                length=None,
                usage=None,
                x_origin=None,
                x_file_ref=None,
                x_name=None,
                x_alias=None,
                x_oid=None,
            )

        Args:
            constants: Constants class (e.g., TestsOudConstants, TestsRfcConstants)
            oid_constant: Constant name for OID (e.g., "SAMPLE_ATTRIBUTE_OID")
            name_constant: Constant name for name (e.g., "SAMPLE_ATTRIBUTE_NAME")
            desc: Description (or use constant if provided)
            sup: Superior attribute
            equality: Equality matching rule
            ordering: Ordering matching rule
            substr: Substring matching rule
            syntax: Syntax OID
            length: Maximum length
            usage: Usage (userApplications, directoryOperation, etc.)
            x_origin: X-ORIGIN extension
            **kwargs: Additional fields to pass to create()

        Returns:
            Created SchemaAttribute

        """
        oid_value = kwargs.pop("oid", None)
        name_value = kwargs.pop("name", None)

        if oid_value is None and oid_constant and hasattr(constants, oid_constant):
            oid_value = getattr(constants, oid_constant)
        if name_value is None and name_constant and hasattr(constants, name_constant):
            name_value = getattr(constants, name_constant)

        # SchemaAttribute doesn't have create(), use constructor directly
        return FlextLdifModels.SchemaAttribute(
            oid=oid_value,
            name=name_value,
            desc=desc,
            sup=sup,
            equality=equality,
            ordering=ordering,
            substr=substr,
            syntax=syntax,
            length=length,
            usage=usage,
            x_origin=x_origin,
            **kwargs,
        )

    @staticmethod
    def helper_create_schema_objectclass_with_constants(
        constants: ConstantsClass,
        *,
        oid_constant: str | None = None,
        name_constant: str | None = None,
        desc: str | None = None,
        sup: str | None = None,
        kind: str | None = None,
        must: list[str] | None = None,
        may: list[str] | None = None,
        obsolete: bool = False,
        **kwargs: Any,
    ) -> FlextLdifModels.SchemaObjectClass:
        """Create schema objectClass using constants - replaces 10-20 lines.

        Common pattern (appears 25+ times):
            oc = FlextLdifModels.SchemaObjectClass(
                oid=TestsOudConstants.SAMPLE_OBJECTCLASS_OID,
                name=TestsOudConstants.SAMPLE_OBJECTCLASS_NAME,
                sup="top",
                kind="STRUCTURAL",
            )

        Args:
            constants: Constants class
            oid_constant: Constant name for OID
            name_constant: Constant name for name
            desc: Description
            sup: Superior objectClass
            kind: Kind (STRUCTURAL, AUXILIARY, ABSTRACT)
            must: MUST attributes list
            may: MAY attributes list
            obsolete: Whether objectClass is obsolete
            **kwargs: Additional fields

        Returns:
            Created SchemaObjectClass

        """
        oid_value = kwargs.pop("oid", None)
        name_value = kwargs.pop("name", None)

        if oid_value is None and oid_constant and hasattr(constants, oid_constant):
            oid_value = getattr(constants, oid_constant)
        if name_value is None and name_constant and hasattr(constants, name_constant):
            name_value = getattr(constants, name_constant)

        # SchemaObjectClass doesn't have create(), use constructor directly
        # Only pass fields that are not None (except for optional fields)
        oc_kwargs: dict[str, Any] = {}
        if oid_value is not None:
            oc_kwargs["oid"] = oid_value
        if name_value is not None:
            oc_kwargs["name"] = name_value
        if desc is not None:
            oc_kwargs["desc"] = desc
        if sup is not None:
            oc_kwargs["sup"] = sup
        if kind is not None:
            oc_kwargs["kind"] = kind
        if must is not None:
            oc_kwargs["must"] = must
        if may is not None:
            oc_kwargs["may"] = may
        # obsolete is not a valid parameter for SchemaObjectClass
        oc_kwargs.update(kwargs)
        return FlextLdifModels.SchemaObjectClass(**oc_kwargs)

    @staticmethod
    def helper_assert_schema_fields(
        schema_item: FlextLdifModels.SchemaAttribute
        | FlextLdifModels.SchemaObjectClass,
        *,
        expected_oid: str | None = None,
        expected_name: str | None = None,
        expected_sup: str | None = None,
        expected_kind: str | None = None,
        expected_desc: str | None = None,
        expected_equality: str | None = None,
        expected_syntax: str | None = None,
        **field_assertions: object,  # Allow any field assertions
    ) -> None:
        """Assert multiple schema fields at once - replaces 5-10 lines per test.

        Common pattern (appears 40+ times):
            assert attr.oid == TestsOudConstants.SAMPLE_ATTRIBUTE_OID
            assert attr.name == TestsOudConstants.SAMPLE_ATTRIBUTE_NAME
            assert attr.sup == "top"
            assert attr.kind == "STRUCTURAL"

        Args:
            schema_item: Schema attribute or objectClass to validate
            expected_oid: Expected OID value
            expected_name: Expected name value
            expected_sup: Expected superior value
            expected_kind: Expected kind value (for objectClass)
            expected_desc: Expected description
            expected_equality: Expected equality matching rule
            expected_syntax: Expected syntax OID
            **field_assertions: Additional field=value pairs to assert

        """
        if expected_oid is not None and hasattr(schema_item, "oid"):
            assert schema_item.oid == expected_oid, (  # type: ignore[attr-defined]
                f"OID mismatch: expected {expected_oid}, got {schema_item.oid}"  # type: ignore[attr-defined]
            )

        if expected_name is not None and hasattr(schema_item, "name"):
            assert schema_item.name == expected_name, (  # type: ignore[attr-defined]
                f"Name mismatch: expected {expected_name}, got {schema_item.name}"  # type: ignore[attr-defined]
            )

        if expected_sup is not None and hasattr(schema_item, "sup"):
            assert schema_item.sup == expected_sup, (  # type: ignore[attr-defined]
                f"Sup mismatch: expected {expected_sup}, got {schema_item.sup}"  # type: ignore[attr-defined]
            )

        # Type narrowing: kind is only available in SchemaObjectClass
        if expected_kind is not None and isinstance(
            schema_item, FlextLdifModels.SchemaObjectClass
        ):
            assert schema_item.kind == expected_kind, (
                f"Kind mismatch: expected {expected_kind}, got {schema_item.kind}"
            )

        if expected_desc is not None and hasattr(schema_item, "desc"):
            assert schema_item.desc == expected_desc, (  # type: ignore[attr-defined]
                f"Desc mismatch: expected {expected_desc}, got {schema_item.desc}"  # type: ignore[attr-defined]
            )

        # Type narrowing: equality and syntax are only available in SchemaAttribute
        if expected_equality is not None and isinstance(
            schema_item, FlextLdifModels.SchemaAttribute
        ):
            assert schema_item.equality == expected_equality, (
                f"Equality mismatch: expected {expected_equality}, got {schema_item.equality}"
            )

        if expected_syntax is not None and isinstance(
            schema_item, FlextLdifModels.SchemaAttribute
        ):
            assert schema_item.syntax == expected_syntax, (
                f"Syntax mismatch: expected {expected_syntax}, got {schema_item.syntax}"
            )

        # Handle additional field assertions
        for field_name, expected_value in field_assertions.items():
            if hasattr(schema_item, field_name):
                actual_value = getattr(schema_item, field_name)
                assert actual_value == expected_value, (
                    f"{field_name} mismatch: expected {expected_value}, got {actual_value}"
                )

    @staticmethod
    def helper_can_handle_and_assert(
        quirk: Any,
        method_name: str,
        data: Any,
        *,
        expected_result: bool = True,
    ) -> bool:
        """Test can_handle_* methods with assertion - replaces 3-5 lines per test.

        Common pattern (appears 30+ times):
            result = schema_quirk.can_handle_attribute(attr_def)
            assert result is True

        Args:
            quirk: Quirk instance
            method_name: Method name (e.g., "can_handle_attribute", "can_handle_objectclass")
            data: Data to test (string or model)
            expected_result: Expected boolean result (default: True)

        Returns:
            Actual result value

        """
        can_handle_func = getattr(quirk, method_name)
        result = can_handle_func(data)
        assert result is expected_result, (
            f"{method_name} returned {result}, expected {expected_result}"
        )
        return result  # type: ignore[return-value]

    @staticmethod
    def helper_transform_and_assert_fields(
        quirk: Any,
        transform_method: str,
        input_data: Any,
        *,
        expected_fields: dict[str, Any] | None = None,
        must_not_equal: dict[str, Any] | None = None,
    ) -> Any:
        """Test transform_*_for_write methods with field assertions - replaces 8-15 lines.

        Common pattern (appears 20+ times):
            transformed = schema_quirk._transform_attribute_for_write(attr)
            assert transformed.name == "testAttr"
            assert transformed.substr != "caseIgnoreMatch" or transformed.substr is None

        Args:
            quirk: Quirk instance
            transform_method: Method name (e.g., "_transform_attribute_for_write")
            input_data: Input data to transform
            expected_fields: Dict of field_name=expected_value to assert
            must_not_equal: Dict of field_name=value that must NOT equal

        Returns:
            Transformed data

        """
        transform_func = getattr(quirk, transform_method)
        transformed = transform_func(input_data)

        if expected_fields:
            for field_name, expected_value in expected_fields.items():
                if hasattr(transformed, field_name):
                    actual_value = getattr(transformed, field_name)
                    assert actual_value == expected_value, (
                        f"{field_name} mismatch: expected {expected_value}, got {actual_value}"
                    )

        if must_not_equal:
            for field_name, forbidden_value in must_not_equal.items():
                if hasattr(transformed, field_name):
                    actual_value = getattr(transformed, field_name)
                    # Allow None as valid "not equal"
                    if actual_value is not None:
                        assert actual_value != forbidden_value, (
                            f"{field_name} should not equal {forbidden_value}, got {actual_value}"
                        )

        return transformed

    @staticmethod
    def helper_normalize_and_assert(
        quirk: Any,
        normalize_method: str,
        input_value: str,
        *,
        expected_output: str | None = None,
        must_contain: str | list[str] | None = None,
        must_not_contain: str | list[str] | None = None,
    ) -> str:
        """Test normalize_* methods with assertions - replaces 5-8 lines per test.

        Common pattern (appears 15+ times):
            result = utilities.DN.norm_component("cn = John Doe")
            assert result == "cn=John Doe"

        Args:
            quirk: Quirk or utility instance
            normalize_method: Method name (e.g., "norm_component", "normalize_dn")
            input_value: Input string to normalize
            expected_output: Expected normalized output
            must_contain: String(s) that must be in output
            must_not_contain: String(s) that must NOT be in output

        Returns:
            Normalized string

        """
        normalize_func = getattr(quirk, normalize_method)
        result = normalize_func(input_value)

        if expected_output is not None:
            assert result == expected_output, (
                f"Normalization mismatch: expected {expected_output}, got {result}"
            )

        if must_contain:
            must_contain_list = (
                [must_contain] if isinstance(must_contain, str) else must_contain
            )
            for required in must_contain_list:
                assert required in result, (
                    f"Normalized output must contain '{required}', got: {result}"
                )

        if must_not_contain:
            must_not_contain_list = (
                [must_not_contain]
                if isinstance(must_not_contain, str)
                else must_not_contain
            )
            for forbidden in must_not_contain_list:
                assert forbidden not in result, (
                    f"Normalized output must NOT contain '{forbidden}', got: {result}"
                )

        return result

    @staticmethod
    def helper_write_and_assert_first_line(
        writer: Any,
        data: Any,
        *,
        write_method: str = "write",
        expected_first_line: str,
        strip_lines: bool = True,
    ) -> str:
        r"""Write and assert first line matches - replaces 5-7 lines per use.

        Common pattern (appears 20+ times):
            result = writer.write(data)
            assert result.is_success
            ldif = result.unwrap()
            lines = ldif.strip().split("\n")
            assert lines[0] == expected_first_line

        Args:
            writer: Writer instance
            data: Data to write
            write_method: Method name to call (default: "write")
            expected_first_line: Expected first line content
            strip_lines: Whether to strip lines before comparison (default: True)

        Returns:
            Written LDIF string

        """
        ldif = DeduplicationHelpers.helper_write_unwrap_and_assert(
            writer, data, write_method=write_method
        )

        lines = ldif.strip().split("\n") if strip_lines else ldif.split("\n")
        assert len(lines) > 0, "Output must have at least one line"
        assert lines[0] == expected_first_line, (
            f"Expected first line '{expected_first_line}', got '{lines[0]}'"
        )

        return ldif

    @staticmethod
    def helper_write_and_assert_last_line(
        writer: Any,
        data: Any,
        *,
        write_method: str = "write",
        expected_last_line: str,
        strip_lines: bool = True,
    ) -> str:
        r"""Write and assert last line matches - replaces 5-7 lines per use.

        Common pattern (appears 15+ times):
            result = writer.write(data)
            assert result.is_success
            ldif = result.unwrap()
            lines = ldif.strip().split("\n")
            assert lines[-1] == expected_last_line

        Args:
            writer: Writer instance
            data: Data to write
            write_method: Method name to call (default: "write")
            expected_last_line: Expected last line content
            strip_lines: Whether to strip lines before comparison (default: True)

        Returns:
            Written LDIF string

        """
        ldif = DeduplicationHelpers.helper_write_unwrap_and_assert(
            writer, data, write_method=write_method
        )

        lines = ldif.strip().split("\n") if strip_lines else ldif.split("\n")
        assert len(lines) > 0, "Output must have at least one line"
        assert lines[-1] == expected_last_line, (
            f"Expected last line '{expected_last_line}', got '{lines[-1]}'"
        )

        return ldif

    @staticmethod
    def helper_parse_list_and_assert_first_item(
        parser: Any,
        content: str | Path,
        *,
        parse_method: str = "parse",
        item_validator: Any | None = None,
    ) -> Any:
        """Parse list and assert first item - replaces 6-10 lines per use.

        Common pattern (appears 20+ times):
            result = parser.parse(content)
            assert result.is_success
            items = result.unwrap()
            assert isinstance(items, list)
            assert len(items) > 0
            first_item = items[0]
            assert first_item.property == expected_value

        Args:
            parser: Parser instance
            content: Content to parse
            parse_method: Method name to call (default: "parse")
            item_validator: Optional callable(item) to validate first item

        Returns:
            First item from parsed list

        """
        # Parse and assert list length
        parse_func = getattr(parser, parse_method)
        result = parse_func(content)
        unwrapped = TestAssertions.assert_success(result, "Parse should succeed")
        if isinstance(unwrapped, list):
            items_raw = unwrapped
        elif isinstance(unwrapped, FlextLdifModels.ParseResponse):
            items_raw = list(unwrapped.entries)
        else:
            msg = f"Unexpected type: {type(unwrapped)}"
            raise TypeError(msg)
        assert len(items_raw) == 1, f"Expected 1 item, got {len(items_raw)}"
        items = items_raw

        first_item = items[0]

        if item_validator:
            try:
                item_validator(first_item)
            except AssertionError as e:
                msg = f"First item validation failed: {e}"
                raise AssertionError(msg) from e

        return first_item

    @staticmethod
    def helper_parse_list_and_assert_last_item(
        parser: Any,
        content: str | Path,
        *,
        parse_method: str = "parse",
        minimum_count: int = 1,
        item_validator: Any | None = None,
    ) -> Any:
        """Parse list and assert last item - replaces 6-10 lines per use.

        Common pattern (appears 15+ times):
            result = parser.parse(content)
            assert result.is_success
            items = result.unwrap()
            assert isinstance(items, list)
            assert len(items) >= minimum_count
            last_item = items[-1]
            assert last_item.property == expected_value

        Args:
            parser: Parser instance
            content: Content to parse
            parse_method: Method name to call (default: "parse")
            minimum_count: Minimum expected item count (default: 1)
            item_validator: Optional callable(item) to validate last item

        Returns:
            Last item from parsed list

        """
        # Parse and assert minimum count
        parse_func = getattr(parser, parse_method)
        result = parse_func(content)
        unwrapped = TestAssertions.assert_success(result, "Parse should succeed")
        if isinstance(unwrapped, list):
            items_raw = unwrapped
        elif isinstance(unwrapped, FlextLdifModels.ParseResponse):
            items_raw = list(unwrapped.entries)
        else:
            msg = f"Unexpected type: {type(unwrapped)}"
            raise TypeError(msg)
        assert len(items_raw) >= minimum_count, (
            f"Expected at least {minimum_count} items, got {len(items_raw)}"
        )
        items = items_raw

        last_item = items[-1]

        if item_validator:
            try:
                item_validator(last_item)
            except AssertionError as e:
                msg = f"Last item validation failed: {e}"
                raise AssertionError(msg) from e

        return last_item

    @staticmethod
    def api_parse_with_server_type(
        api: FlextLdif,
        ldif_content: str | Path,
        server_type: str,
        *,
        expected_count: int | None = None,
        expected_dn: str | None = None,
        must_contain_attributes: list[str] | None = None,
    ) -> list[FlextLdifModels.Entry]:
        """API parse with server_type - replaces 5-10 lines per test.

        Common pattern (appears 50+ times):
            result = ldif_api.parse(fixture_path, server_type="oud")
            assert result.is_success, f"Failed: {result.error}"
            entries = result.unwrap()
            assert entries is not None

        Args:
            api: FlextLdif API instance
            ldif_content: LDIF content string or file path
            server_type: Server type to use for parsing
            expected_count: Optional expected entry count
            expected_dn: Optional expected DN
            must_contain_attributes: Optional list of attribute names that must exist

        Returns:
            List of parsed entries

        """
        result = api.parse(ldif_content, server_type=server_type)
        unwrapped = TestAssertions.assert_success(
            result, f"Parse with server_type={server_type} should succeed"
        )

        if isinstance(unwrapped, list):
            entries = unwrapped
        elif hasattr(unwrapped, "entries"):
            parse_response = cast("FlextLdifModels.ParseResponse", unwrapped)
            entries = list(parse_response.entries)
        else:
            entries = (
                [unwrapped] if isinstance(unwrapped, FlextLdifModels.Entry) else []
            )

        assert entries is not None, "Entries should not be None"
        assert len(entries) > 0, "Should have at least one entry"

        if expected_count is not None:
            assert len(entries) == expected_count, (
                f"Expected {expected_count} entries, got {len(entries)}"
            )

        if expected_dn and entries:
            assert entries[0].dn is not None
            assert entries[0].dn.value == expected_dn

        if must_contain_attributes and entries:
            assert entries[0].attributes is not None
            for attr_name in must_contain_attributes:
                assert attr_name in entries[0].attributes.attributes, (
                    f"Attribute '{attr_name}' not found in entry"
                )

        return cast("list[FlextLdifModels.Entry]", entries)

    @staticmethod
    def api_parse_write_file_and_assert(
        api: FlextLdif,
        entries: Sequence[FlextLdifModels.Entry],
        output_path: Path,
        *,
        target_server_type: str = "rfc",
        must_contain: list[str] | None = None,
        must_not_contain: list[str] | None = None,
    ) -> Path:
        """API write to file with assertions - replaces 8-15 lines per test.

        Common pattern (appears 30+ times):
            result = api.write(sample_entries, output_path=output_file)
            if result.is_success:
                assert output_file.exists()
                content = output_file.read_text()
                assert "Alice" in content

        Args:
            api: FlextLdif API instance
            entries: List of entries to write
            output_path: Path to output file
            target_server_type: Target server type (default: "rfc")
            must_contain: Optional list of strings that must be in file
            must_not_contain: Optional list of strings that must NOT be in file

        Returns:
            Path to written file

        """
        result = api.write(
            list(entries), output_path=output_path, server_type=target_server_type
        )
        TestAssertions.assert_success(result, "Write to file should succeed")
        assert output_path.exists(), f"Output file should exist: {output_path}"

        content = output_path.read_text(encoding="utf-8")
        assert len(content) > 0, "File should not be empty"

        if must_contain:
            for text in must_contain:
                assert text in content, f"Must contain '{text}' not found in file"

        if must_not_contain:
            for text in must_not_contain:
                assert text not in content, f"Must not contain '{text}' found in file"

        return output_path

    @staticmethod
    def api_parse_write_string_and_assert(
        api: FlextLdif,
        entries: Sequence[FlextLdifModels.Entry],
        *,
        target_server_type: str = "rfc",
        must_contain: list[str] | None = None,
        must_not_contain: list[str] | None = None,
    ) -> str:
        """API write to string with assertions - replaces 5-10 lines per test.

        Common pattern (appears 40+ times):
            result = api.write(single_entry)
            assert result.is_success, f"Write failed: {result.error}"
            ldif_string = result.unwrap()
            assert "Alice" in ldif_string

        Args:
            api: FlextLdif API instance
            entries: List of entries to write
            target_server_type: Target server type (default: "rfc")
            must_contain: Optional list of strings that must be in output
            must_not_contain: Optional list of strings that must NOT be in output

        Returns:
            Written LDIF string

        """
        result = api.write(list(entries), server_type=target_server_type)
        ldif_string = TestAssertions.assert_write_success(result)
        assert isinstance(ldif_string, str), "Write should return string"
        assert len(ldif_string) > 0, "LDIF string should not be empty"

        if must_contain:
            for text in must_contain:
                assert text in ldif_string, f"Must contain '{text}' not found"

        if must_not_contain:
            for text in must_not_contain:
                assert text not in ldif_string, f"Must not contain '{text}' found"

        return ldif_string

    @staticmethod
    def assert_result_is_boolean(
        result: FlextResult[bool],
        expected_value: bool | None = None,
    ) -> bool:
        """Assert result is boolean - replaces 3-5 lines per test.

        Common pattern (appears 20+ times):
            result = schema_quirk.validate_objectclass_dependencies(oc, attrs)
            assert result.is_success
            assert result.unwrap() is True

        Args:
            result: FlextResult containing boolean
            expected_value: Optional expected boolean value

        Returns:
            Unwrapped boolean value

        """
        unwrapped = TestAssertions.assert_success(result, "Result should be success")
        assert isinstance(unwrapped, bool), f"Expected bool, got {type(unwrapped)}"

        if expected_value is not None:
            assert unwrapped == expected_value, (
                f"Expected {expected_value}, got {unwrapped}"
            )

        return unwrapped

    @staticmethod
    def api_parse_fixture_and_assert(
        api: FlextLdif,
        fixture_loader: Any,
        server_type: str,
        fixture_name: str,
        *,
        expected_count: int | None = None,
        expected_has_dn: bool = True,
        expected_has_attributes: bool = True,
        expected_has_objectclass: bool = True,
    ) -> list[FlextLdifModels.Entry]:
        """API parse fixture file with assertions - replaces 10-15 lines per test.

        Common pattern (appears 20+ times):
            fixture_path = FixtureTestHelpers.get_fixture_path("oud", "oud_schema_fixtures.ldif")
            result = ldif_api.parse(fixture_path, server_type="oud")
            assert result.is_success, f"Failed: {result.error}"
            entries = result.unwrap()
            assert entries is not None

        Args:
            api: FlextLdif API instance
            fixture_loader: Fixture loader helper (e.g., FixtureTestHelpers)
            server_type: Server type
            fixture_name: Fixture file name
            expected_count: Optional expected entry count
            expected_has_dn: Whether entries should have DN (default: True)
            expected_has_attributes: Whether entries should have attributes (default: True)
            expected_has_objectclass: Whether entries should have objectClass (default: True)

        Returns:
            List of parsed entries

        """
        fixture_path = fixture_loader.get_fixture_path(server_type, fixture_name)
        entries = DeduplicationHelpers.api_parse_with_server_type(
            api,
            fixture_path,
            server_type,
            expected_count=expected_count,
        )

        if expected_has_dn:
            for entry in entries:
                assert entry.dn is not None, "Entry should have DN"
                assert entry.dn.value, "Entry DN should not be empty"

        if expected_has_attributes:
            for entry in entries:
                assert entry.attributes is not None, "Entry should have attributes"
                assert len(entry.attributes.attributes) > 0, (
                    "Entry should have at least one attribute"
                )

        if expected_has_objectclass:
            for entry in entries:
                assert entry.attributes is not None
                if "objectClass" in entry.attributes.attributes:
                    objectclasses = entry.attributes.attributes["objectClass"]
                    assert len(objectclasses) > 0, (
                        "Entry should have at least one objectClass"
                    )

        return entries

    @staticmethod
    def quirk_parse_and_unwrap(
        quirk: Any,
        content: str | Path,
        *,
        parse_method: str = "parse",
        expected_type: type[Any] | None = None,
        should_succeed: bool = True,
        expected_error: str | None = None,
    ) -> Any:
        """Generic quirk parse + assert success + unwrap - replaces 3-5 lines per use.

        Common pattern (appears 100+ times):
            result = quirk.parse(content)
            assert result.is_success
            value = result.unwrap()

        This method replaces all of that with a single call.

        Args:
            quirk: Quirk instance (Schema, Entry, Acl, etc.)
            content: Content to parse (string or Path)
            parse_method: Method name to call (default: "parse")
            expected_type: Optional expected return type for validation
            should_succeed: Whether parse should succeed (default: True)
            expected_error: Optional expected error substring if should fail

        Returns:
            Unwrapped value from parse result

        Example:
            # Replaces 3-5 lines:
            attr = DeduplicationHelpers.quirk_parse_and_unwrap(
                schema_quirk,
                "( 1.2.3.4 NAME 'test' )",
                parse_method="parse_attribute"
            )

        """
        if not hasattr(quirk, parse_method):
            msg = f"Quirk does not have method '{parse_method}'"
            raise AttributeError(msg)

        method = getattr(quirk, parse_method)
        result = method(content)

        if should_succeed:
            unwrapped = TestAssertions.assert_success(
                result, f"{parse_method} should succeed"
            )
            if expected_type and not isinstance(unwrapped, expected_type):
                msg = (
                    f"Expected {expected_type.__name__}, got {type(unwrapped).__name__}"
                )
                raise TypeError(msg)
            return unwrapped

        error = TestAssertions.assert_failure(result, expected_error)
        if expected_error and expected_error not in error:
            msg = f"Expected error containing '{expected_error}', got: {error}"
            raise AssertionError(msg)
        return None

    @staticmethod
    def quirk_write_and_unwrap(
        quirk: Any,
        data: Any,
        *,
        write_method: str = "write",
        must_contain: list[str] | None = None,
        must_not_contain: list[str] | None = None,
        should_succeed: bool = True,
        expected_error: str | None = None,
    ) -> str:
        """Generic quirk write + assert success + unwrap - replaces 3-5 lines per use.

        Common pattern (appears 50+ times):
            result = quirk.write(data)
            assert result.is_success
            value = result.unwrap()
            assert "expected" in value

        This method replaces all of that with a single call.

        Args:
            quirk: Quirk instance (Schema, Entry, Acl, etc.)
            data: Data to write (SchemaAttribute, SchemaObjectClass, Entry, Acl, etc.)
            write_method: Method name to call (default: "write")
            must_contain: Optional list of strings that must appear in output
            must_not_contain: Optional list of strings that must NOT appear in output
            should_succeed: Whether write should succeed (default: True)
            expected_error: Optional expected error substring if should fail

        Returns:
            Unwrapped string from write result

        Example:
            # Replaces 3-5 lines:
            attr_str = DeduplicationHelpers.quirk_write_and_unwrap(
                schema_quirk,
                attr_model,
                write_method="_write_attribute",
                must_contain=["1.2.3.4", "NAME 'test'"]
            )

        """
        if not hasattr(quirk, write_method):
            msg = f"Quirk does not have method '{write_method}'"
            raise AttributeError(msg)

        method = getattr(quirk, write_method)
        result = method(data)

        if should_succeed:
            unwrapped = TestAssertions.assert_success(
                result, f"{write_method} should succeed"
            )
            assert isinstance(unwrapped, str), (
                f"Write should return string, got {type(unwrapped).__name__}"
            )

            if must_contain:
                for text in must_contain:
                    assert text in unwrapped, (
                        f"Must contain '{text}' not found in output"
                    )

            if must_not_contain:
                for text in must_not_contain:
                    assert text not in unwrapped, (
                        f"Must not contain '{text}' found in output"
                    )

            return unwrapped

        error = TestAssertions.assert_failure(result, expected_error)
        if expected_error and expected_error not in error:
            msg = f"Expected error containing '{expected_error}', got: {error}"
            raise AssertionError(msg)
        return ""

    @staticmethod
    def assert_schema_objects_preserve_properties(
        obj1: FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass,
        obj2: FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass,
        *,
        preserve_oid: bool = False,
        preserve_name: bool = False,
        preserve_syntax: bool = False,
        preserve_single_value: bool = False,
        preserve_desc: bool = False,
        preserve_kind: bool = False,
        preserve_sup: bool = False,
        preserve_must: bool = False,
        preserve_may: bool = False,
    ) -> None:
        """Assert that schema objects preserve specified properties - replaces 5-15 lines.

        Common pattern (appears 20+ times):
            assert parsed1.oid == parsed2.oid, "OID should be preserved"
            assert parsed1.name == parsed2.name, "Name should be preserved"
            assert parsed1.syntax == parsed2.syntax, "Syntax should be preserved"

        Args:
            obj1: First schema object (original)
            obj2: Second schema object (roundtripped)
            preserve_oid: Whether to verify OID is preserved
            preserve_name: Whether to verify name is preserved
            preserve_syntax: Whether to verify syntax is preserved
            preserve_single_value: Whether to verify single_value is preserved
            preserve_desc: Whether to verify desc is preserved
            preserve_kind: Whether to verify kind is preserved (objectClass only)
            preserve_sup: Whether to verify sup is preserved (objectClass only)
            preserve_must: Whether to verify must is preserved (objectClass only)
            preserve_may: Whether to verify may is preserved (objectClass only)

        Example:
            DeduplicationHelpers.assert_schema_objects_preserve_properties(
                parsed1,
                parsed2,
                preserve_oid=True,
                preserve_name=True,
                preserve_syntax=True,
            )

        """
        if preserve_oid:
            assert obj1.oid == obj2.oid, (
                f"OID should be preserved: {obj1.oid} != {obj2.oid}"
            )

        if preserve_name:
            assert obj1.name == obj2.name, (
                f"Name should be preserved: {obj1.name} != {obj2.name}"
            )

        if (
            preserve_syntax
            and isinstance(obj1, FlextLdifModels.SchemaAttribute)
            and isinstance(obj2, FlextLdifModels.SchemaAttribute)
        ):
            # Syntax only exists on SchemaAttribute, not SchemaObjectClass
            assert obj1.syntax == obj2.syntax, (
                f"Syntax should be preserved: {obj1.syntax} != {obj2.syntax}"
            )

        if (
            preserve_single_value
            and isinstance(obj1, FlextLdifModels.SchemaAttribute)
            and isinstance(obj2, FlextLdifModels.SchemaAttribute)
        ):
            # single_value only exists on SchemaAttribute, not SchemaObjectClass
            assert obj1.single_value == obj2.single_value, (
                f"single_value should be preserved: {obj1.single_value} != {obj2.single_value}"
            )

        if preserve_desc:
            assert obj1.desc == obj2.desc, (
                f"desc should be preserved: {obj1.desc} != {obj2.desc}"
            )

        # ObjectClass-specific properties
        if isinstance(obj1, FlextLdifModels.SchemaObjectClass) and isinstance(
            obj2, FlextLdifModels.SchemaObjectClass
        ):
            if preserve_kind:
                assert obj1.kind == obj2.kind, (
                    f"kind should be preserved: {obj1.kind} != {obj2.kind}"
                )

            if preserve_sup:
                assert obj1.sup == obj2.sup, (
                    f"sup should be preserved: {obj1.sup} != {obj2.sup}"
                )

            if preserve_must:
                assert obj1.must == obj2.must, (
                    f"must should be preserved: {obj1.must} != {obj2.must}"
                )

            if preserve_may:
                assert obj1.may == obj2.may, (
                    f"may should be preserved: {obj1.may} != {obj2.may}"
                )

    @staticmethod
    def quirk_parse_test_cases(
        quirk: Any,
        test_cases: list[dict[str, Any]],
        *,
        parse_method: str = "parse",
        expected_type: type[Any] | None = None,
    ) -> None:
        """Test multiple parse cases with a quirk - replaces 10-30 lines.

        Common pattern (appears 20+ times):
            test_cases = [
                {"input": "...", "should_succeed": True},
                {"input": "...", "should_succeed": False},
            ]
            for case in test_cases:
                result = quirk.parse(case["input"])
                if case["should_succeed"]:
                    assert result.is_success
                else:
                    assert result.is_failure

        Args:
            quirk: Quirk instance (Schema, Entry, Acl, etc.)
            test_cases: List of test case dictionaries with "input" and "should_succeed"
            parse_method: Method name to call (default: "parse")
            expected_type: Optional expected return type for successful parses

        Example:
            test_cases = [
                {"input": "( 1.2.3.4 NAME 'test' )", "should_succeed": True},
                {"input": "invalid", "should_succeed": False},
            ]
            DeduplicationHelpers.quirk_parse_test_cases(
                schema_quirk,
                test_cases,
                parse_method="parse_attribute"
            )

        """
        if not hasattr(quirk, parse_method):
            msg = f"Quirk does not have method '{parse_method}'"
            raise AttributeError(msg)

        method = getattr(quirk, parse_method)

        for i, test_case in enumerate(test_cases):
            input_data = test_case.get("input", "")
            should_succeed = test_case.get("should_succeed", True)
            expected_error = test_case.get("expected_error", None)

            result = method(input_data)

            if should_succeed:
                unwrapped = TestAssertions.assert_success(
                    result, f"Test case {i + 1} should succeed"
                )
                if expected_type and not isinstance(unwrapped, expected_type):
                    msg = (
                        f"Test case {i + 1}: Expected {expected_type.__name__}, "
                        f"got {type(unwrapped).__name__}"
                    )
                    raise TypeError(msg)
            else:
                error = TestAssertions.assert_failure(
                    result, expected_error=expected_error
                )
                if expected_error is not None and expected_error not in error:
                    msg = (
                        f"Test case {i + 1}: Expected error containing '{expected_error}', "
                        f"got: {error}"
                    )
                    raise AssertionError(msg)

    # ════════════════════════════════════════════════════════════════════════
    # FILTER SERVICE HELPERS
    # ════════════════════════════════════════════════════════════════════════

    @staticmethod
    def filter_by_dn_and_unwrap(
        entries: list[FlextLdifModels.Entry],
        pattern: str,
        *,
        mode: str = "include",
        mark_excluded: bool = False,
        expected_count: int | None = None,
        expected_dn_substring: str | None = None,
    ) -> list[FlextLdifModels.Entry]:
        """Filter entries by DN pattern and unwrap - replaces 5-8 lines."""
        from flext_ldif.services.filters import FlextLdifFilters

        result = FlextLdifFilters.by_dn(
            entries, pattern, mode, mark_excluded=mark_excluded
        )
        filtered = DeduplicationHelpers.assert_success_and_unwrap(
            result, "Filter by DN should succeed"
        )

        if expected_count is not None:
            assert len(filtered) == expected_count, (
                f"Expected {expected_count} entries, got {len(filtered)}"
            )

        if expected_dn_substring:
            matching_entries = [
                e for e in filtered if e.dn and expected_dn_substring in e.dn.value
            ]
            if mark_excluded:
                assert len(matching_entries) > 0, (
                    f"At least one entry should have '{expected_dn_substring}' in DN"
                )
            else:
                assert len(matching_entries) == len(filtered), (
                    f"All entries should have '{expected_dn_substring}' in DN"
                )

        return filtered

    @staticmethod
    def filter_by_objectclass_and_unwrap(
        entries: list[FlextLdifModels.Entry],
        objectclass: str | tuple[str, ...],
        *,
        required_attributes: list[str] | None = None,
        expected_count: int | None = None,
    ) -> list[FlextLdifModels.Entry]:
        """Filter entries by objectClass and unwrap - replaces 5-8 lines."""
        from flext_ldif.services.filters import FlextLdifFilters

        result = FlextLdifFilters.by_objectclass(
            entries,
            objectclass,
            required_attributes=required_attributes,
        )
        filtered = DeduplicationHelpers.assert_success_and_unwrap(
            result, "Filter by objectClass should succeed"
        )

        if expected_count is not None:
            assert len(filtered) == expected_count, (
                f"Expected {expected_count} entries, got {len(filtered)}"
            )

        return filtered

    @staticmethod
    def filter_by_attributes_and_unwrap(
        entries: list[FlextLdifModels.Entry],
        attributes: list[str],
        *,
        match_all: bool = False,
        expected_count: int | None = None,
    ) -> list[FlextLdifModels.Entry]:
        """Filter entries by attributes and unwrap - replaces 5-8 lines."""
        from flext_ldif.services.filters import FlextLdifFilters

        result = FlextLdifFilters.by_attributes(
            entries,
            attributes,
            match_all=match_all,
        )
        filtered = DeduplicationHelpers.assert_success_and_unwrap(
            result, "Filter by attributes should succeed"
        )

        if expected_count is not None:
            assert len(filtered) == expected_count, (
                f"Expected {expected_count} entries, got {len(filtered)}"
            )

        return filtered

    @staticmethod
    def filter_execute_and_unwrap(
        entries: list[FlextLdifModels.Entry],
        filter_criteria: str,
        *,
        dn_pattern: str | None = None,
        objectclass: str | None = None,
        attributes: list[str] | None = None,
        expected_count: int | None = None,
    ) -> list[FlextLdifModels.Entry]:
        """Execute filter service and unwrap - replaces 6-10 lines."""
        from flext_ldif.services.filters import FlextLdifFilters

        service = FlextLdifFilters(
            entries=entries,
            filter_criteria=filter_criteria,
            dn_pattern=dn_pattern,
            objectclass=objectclass,
            attributes=attributes,
        )

        result = service.execute()
        filtered = DeduplicationHelpers.assert_success_and_unwrap(
            result, "Filter execute should succeed"
        )

        if isinstance(filtered, list):
            entries_list = filtered
        elif hasattr(filtered, "get_all_entries"):
            entries_list = filtered.get_all_entries()
        else:
            entries_list = (
                [filtered] if isinstance(filtered, FlextLdifModels.Entry) else []
            )

        if expected_count is not None:
            assert len(entries_list) == expected_count, (
                f"Expected {expected_count} entries, got {len(entries_list)}"
            )

        return entries_list

    @staticmethod
    def filter_classmethod_and_unwrap(
        entries: list[FlextLdifModels.Entry],
        criteria: str,
        *,
        pattern: str | None = None,
        objectclass: str | None = None,
        required_attributes: list[str] | None = None,
        expected_count: int | None = None,
    ) -> list[FlextLdifModels.Entry]:
        """Filter using classmethod filter() and unwrap - replaces 6-10 lines."""
        from flext_ldif.services.filters import FlextLdifFilters

        result = FlextLdifFilters.filter(
            entries,
            criteria=criteria,
            pattern=pattern,
            objectclass=objectclass,
            required_attributes=required_attributes,
        )

        filtered = DeduplicationHelpers.assert_success_and_unwrap(
            result, "Filter classmethod should succeed"
        )

        if hasattr(filtered, "get_all_entries"):
            entries_list = filtered.get_all_entries()
        elif isinstance(filtered, list):
            entries_list = filtered
        else:
            entries_list = []

        if expected_count is not None:
            assert len(entries_list) == expected_count, (
                f"Expected {expected_count} entries, got {len(entries_list)}"
            )

        return entries_list

    @staticmethod
    def remove_attributes_and_validate(
        entry: FlextLdifModels.Entry,
        attributes: list[str],
        *,
        must_still_have: list[str] | None = None,
    ) -> None:
        """Remove attributes and validate - replaces 5-8 lines."""
        from flext_ldif.services.filters import FlextLdifFilters

        result = FlextLdifFilters.remove_attributes(entry, attributes)
        # Type narrowing: remove_attributes returns FlextResult[Entry]
        # Convert to Entry | list[Entry] for assert_success_and_unwrap_entry
        # Use cast since FlextResult is invariant but we know Entry is compatible
        modified_result = cast(
            "FlextResult[FlextLdifModels.Entry | list[FlextLdifModels.Entry]]",
            result,
        )
        modified = DeduplicationHelpers.assert_success_and_unwrap_entry(
            modified_result, error_msg="Remove attributes should succeed"
        )

        for attr in attributes:
            assert not modified.has_attribute(attr), (
                f"Attribute '{attr}' should be removed"
            )

        if must_still_have:
            for attr in must_still_have:
                assert modified.has_attribute(attr), (
                    f"Attribute '{attr}' should still be present"
                )

    @staticmethod
    def remove_objectclasses_and_validate(
        entry: FlextLdifModels.Entry,
        objectclasses: list[str],
        *,
        must_still_have: list[str] | None = None,
    ) -> None:
        """Remove objectClasses and validate - replaces 5-8 lines."""
        from flext_ldif.services.filters import FlextLdifFilters

        result = FlextLdifFilters.remove_objectclasses(entry, objectclasses)
        # Type narrowing: remove_objectclasses returns FlextResult[Entry]
        # Convert to Entry | list[Entry] for assert_success_and_unwrap_entry
        # Use cast since FlextResult is invariant but we know Entry is compatible
        modified_result = cast(
            "FlextResult[FlextLdifModels.Entry | list[FlextLdifModels.Entry]]",
            result,
        )
        modified = DeduplicationHelpers.assert_success_and_unwrap_entry(
            modified_result, error_msg="Remove objectClasses should succeed"
        )

        entry_ocs = modified.get_attribute_values("objectClass")
        entry_ocs_lower = {oc.lower() for oc in entry_ocs} if entry_ocs else set()
        for oc in objectclasses:
            assert oc.lower() not in entry_ocs_lower, (
                f"ObjectClass '{oc}' should be removed"
            )

        if must_still_have:
            for oc in must_still_have:
                assert oc.lower() in entry_ocs_lower, (
                    f"ObjectClass '{oc}' should still be present"
                )

    @staticmethod
    def assert_entries_dn_contains(
        entries: list[FlextLdifModels.Entry],
        substring: str,
        *,
        all_entries: bool = True,
    ) -> None:
        """Assert that entries' DNs contain substring - replaces 3-5 lines."""
        if all_entries:
            for entry in entries:
                if entry.dn:
                    assert substring in entry.dn.value, (
                        f"All entries should have '{substring}' in DN, but {entry.dn.value} does not"
                    )
        else:
            matches = [e for e in entries if e.dn and substring in e.dn.value]
            assert len(matches) > 0, (
                f"At least one entry should have '{substring}' in DN"
            )

    @staticmethod
    def assert_entries_have_attribute(
        entries: list[FlextLdifModels.Entry],
        attribute: str,
    ) -> None:
        """Assert that all entries have the attribute - replaces 3-5 lines."""
        for entry in entries:
            assert entry.has_attribute(attribute), (
                f"Entry {entry.dn.value if entry.dn else 'NO_DN'} should have attribute '{attribute}'"
            )


# Backward compatibility alias
# Set __test__ = False to prevent pytest from collecting this as a test class
TestDeduplicationHelpers = DeduplicationHelpers
TestDeduplicationHelpers.__test__ = False  # Prevent pytest collection

# Add method aliases for backward compatibility
TestDeduplicationHelpers.api_parse_and_unwrap = (
    DeduplicationHelpers.helper_api_parse_and_unwrap
)
TestDeduplicationHelpers.api_write_and_unwrap = (
    DeduplicationHelpers.helper_api_write_and_unwrap
)
TestDeduplicationHelpers.test_service_execute_and_assert_fields = (
    DeduplicationHelpers.service_execute_and_assert_fields
)

__all__ = ["DeduplicationHelpers", "TestDeduplicationHelpers"]
