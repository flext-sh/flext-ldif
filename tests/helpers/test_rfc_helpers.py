"""RFC test helpers to eliminate massive code duplication.

Provides high-level methods for testing RFC parsers, writers, and quirks.
Each method replaces 10-30+ lines of duplicated test code.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal, Protocol, TypeVar, cast

from flext_core import FlextResult

from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.writer import FlextLdifWriter
from tests.helpers.test_assertions import TestAssertions

T = TypeVar("T")


# Protocol for objects with entries attribute
class HasEntries(Protocol):
    """Protocol for objects that have an entries attribute."""

    entries: list[FlextLdifModels.Entry]


# Protocol for API-like objects with parse method
class HasParseMethod(Protocol):
    """Protocol for objects that have a parse method."""

    def parse(
        self, ldif_input: str | Path, server_type: str | None = None
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF input."""
        ...

    def write(
        self,
        entries: list[FlextLdifModels.Entry],
        output_path: Path | None = None,
        server_type: str | None = None,
    ) -> FlextResult[str]:
        """Write entries to LDIF."""
        ...


# Union type for quirk instances
type QuirkInstance = (
    FlextLdifServersRfc.Schema | FlextLdifServersRfc.Acl | FlextLdifServersRfc.Entry
)

# Union type for objects that can be unwrapped from parse results
type ParseResultValue = (
    HasEntries | list[FlextLdifModels.Entry] | FlextLdifModels.Entry | str
)


class RfcTestHelpers:
    """High-level RFC test helpers that replace entire test functions."""

    @staticmethod
    def test_parse_ldif_content(
        parser: FlextLdifParser,
        ldif_content: str,
        expected_count: int | None = None,
        server_type: str | None = None,
    ) -> list[FlextLdifModels.Entry]:
        r"""Complete LDIF parse test - replaces entire test function.

        Args:
            parser: Parser service instance
            ldif_content: LDIF content string
            expected_count: Optional expected entry count
            server_type: Optional server type override

        Returns:
            List of parsed entries

        Example:
            # Replaces entire test function:
            entries = RfcTestHelpers.test_parse_ldif_content(
                parser,
                "dn: cn=test,dc=example,dc=com\ncn: test\n",
                expected_count=1
            )

        """
        result = parser.parse(
            ldif_content, input_source="string", server_type=server_type
        )
        unwrapped_untyped = TestAssertions.assert_success(
            result, "Parse should succeed"
        )
        unwrapped = cast("ParseResultValue", unwrapped_untyped)
        if hasattr(unwrapped, "entries"):
            unwrapped_with_entries = cast("HasEntries", unwrapped)
            entries = unwrapped_with_entries.entries
        elif isinstance(unwrapped, list):
            entries: list[FlextLdifModels.Entry] = unwrapped
        else:
            msg = "Parse returned unexpected type"
            raise AssertionError(msg)
        if expected_count is not None:
            assert len(entries) == expected_count, (
                f"Expected {expected_count} entries, got {len(entries)}"
            )
        if len(entries) > 0:
            TestAssertions.assert_entries_valid(entries)
        return entries

    @staticmethod
    def test_parse_and_assert_entry_structure(
        parser: FlextLdifParser,
        ldif_content: str,
        *,
        expected_dn: str | None = None,
        expected_attributes: list[str] | None = None,
        expected_count: int | None = None,
        server_type: str | None = None,
    ) -> list[FlextLdifModels.Entry]:
        r"""Parse LDIF and assert entry structure - replaces 15-25 lines.

        Args:
            parser: Parser service instance
            ldif_content: LDIF content string
            expected_dn: Optional expected DN value
            expected_attributes: Optional list of attribute names that must exist
            expected_count: Optional expected entry count
            server_type: Optional server type override

        Returns:
            List of parsed entries

        Example:
            # Replaces 20+ lines:
            entries = RfcTestHelpers.test_parse_and_assert_entry_structure(
                parser,
                "dn: cn=test,dc=example,dc=com\ncn: test\nsn: Test\n",
                expected_dn="cn=test,dc=example,dc=com",
                expected_attributes=["cn", "sn"],
                expected_count=1,
            )

        """
        entries = RfcTestHelpers.test_parse_ldif_content(
            parser,
            ldif_content,
            expected_count=expected_count,
            server_type=server_type,
        )
        if entries:
            entry = entries[0]
            if expected_dn:
                assert entry.dn is not None
                assert entry.dn.value == expected_dn
            if expected_attributes:
                assert entry.attributes is not None
                for attr_name in expected_attributes:
                    assert attr_name in entry.attributes.attributes
        return entries

    @staticmethod
    def test_parse_and_assert_multiple_entries(
        parser: FlextLdifParser,
        ldif_content: str,
        *,
        expected_dns: list[str] | None = None,
        expected_count: int | None = None,
        server_type: str | None = None,
    ) -> list[FlextLdifModels.Entry]:
        """Parse multiple entries and assert DN presence - replaces 10-15 lines.

        Args:
            parser: Parser service instance
            ldif_content: LDIF content string
            expected_dns: Optional list of expected DN values
            expected_count: Optional expected entry count
            server_type: Optional server type override

        Returns:
            List of parsed entries

        """
        entries = RfcTestHelpers.test_parse_ldif_content(
            parser,
            ldif_content,
            expected_count=expected_count,
            server_type=server_type,
        )
        if expected_dns:
            dns = {entry.dn.value for entry in entries if entry.dn is not None}
            for expected_dn in expected_dns:
                assert expected_dn in dns
        return entries

    @staticmethod
    def test_parse_ldif_file(
        parser: FlextLdifParser,
        ldif_file: Path,
        expected_count: int | None = None,
    ) -> list[FlextLdifModels.Entry]:
        """Complete LDIF file parse test - replaces entire test function.

        Args:
            parser: Parser service instance
            ldif_file: Path to LDIF file
            expected_count: Optional expected entry count

        Returns:
            List of parsed entries

        """
        result = parser.parse_ldif_file(ldif_file)
        unwrapped_untyped = TestAssertions.assert_success(
            result, "Parse should succeed"
        )
        unwrapped = cast("ParseResultValue", unwrapped_untyped)
        if hasattr(unwrapped, "entries"):
            unwrapped_with_entries = cast("HasEntries", unwrapped)
            entries = unwrapped_with_entries.entries
        elif isinstance(unwrapped, list):
            entries: list[FlextLdifModels.Entry] = unwrapped
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
    def test_write_entries_to_string(
        writer: FlextLdifWriter,
        entries: list[FlextLdifModels.Entry],
        target_server_type: str = "rfc",
        expected_content: list[str] | None = None,
    ) -> str:
        """Complete entry write to string test - replaces entire test function.

        Args:
            writer: Writer service instance
            entries: List of entries to write
            target_server_type: Target server type (default: "rfc")
            expected_content: Optional list of strings that must be in output

        Returns:
            Written LDIF string

        """
        result = writer.write(
            entries,
            target_server_type=target_server_type,
            output_target="string",
        )
        ldif = TestAssertions.assert_write_success(result)
        if expected_content:
            for content in expected_content:
                assert content in ldif, (
                    f"Expected content '{content}' not found in LDIF"
                )
        return ldif

    @staticmethod
    def test_write_entries_to_file(
        writer: FlextLdifWriter,
        entries: list[FlextLdifModels.Entry],
        output_file: Path,
        target_server_type: str = "rfc",
    ) -> Path:
        """Complete entry write to file test - replaces entire test function.

        Args:
            writer: Writer service instance
            entries: List of entries to write
            output_file: Path to output file
            target_server_type: Target server type (default: "rfc")

        Returns:
            Path to written file

        """
        result = writer.write(
            entries,
            target_server_type=target_server_type,
            output_target="file",
            output_path=output_file,
        )
        _ = TestAssertions.assert_success(result, "Write to file should succeed")
        assert output_file.exists(), "Output file should exist"
        return output_file

    @staticmethod
    def test_create_entry(
        dn: str,
        attributes: dict[str, list[str]],
    ) -> FlextLdifModels.Entry:
        """Create entry for testing - replaces entry creation code.

        Args:
            dn: Distinguished name
            attributes: Dictionary of attribute names to values

        Returns:
            Created Entry model

        """
        # Convert dict[str, list[str]] to dict[str, str | list[str]] for Entry.create
        attributes_typed: dict[str, str | list[str]] = dict(attributes.items())
        result = FlextLdifModels.Entry.create(dn=dn, attributes=attributes_typed)
        return cast("FlextLdifModels.Entry", TestAssertions.assert_success(result))

    @staticmethod
    def test_schema_parse_attribute(
        schema_quirk: FlextLdifServersRfc.Schema,
        attr_def: str,
        expected_oid: str,
        expected_name: str,
    ) -> FlextLdifModels.SchemaAttribute:
        """Complete schema attribute parse test - replaces entire test function.

        Args:
            schema_quirk: Schema quirk instance
            attr_def: Attribute definition string
            expected_oid: Expected OID
            expected_name: Expected name

        Returns:
            Parsed SchemaAttribute

        """
        result = schema_quirk.parse(attr_def)
        attr = TestAssertions.assert_success(result, "Attribute parse should succeed")
        assert isinstance(attr, FlextLdifModels.SchemaAttribute), (
            "Parse should return SchemaAttribute"
        )
        TestAssertions.assert_schema_attribute_valid(attr, expected_oid, expected_name)
        return attr

    @staticmethod
    def test_schema_parse_objectclass(
        schema_quirk: FlextLdifServersRfc.Schema,
        oc_def: str,
        expected_oid: str,
        expected_name: str,
    ) -> FlextLdifModels.SchemaObjectClass:
        """Complete schema objectClass parse test - replaces entire test function.

        Args:
            schema_quirk: Schema quirk instance
            oc_def: ObjectClass definition string
            expected_oid: Expected OID
            expected_name: Expected name

        Returns:
            Parsed SchemaObjectClass

        """
        result = schema_quirk.parse(oc_def)
        oc = TestAssertions.assert_success(result, "ObjectClass parse should succeed")
        assert isinstance(oc, FlextLdifModels.SchemaObjectClass), (
            "Parse should return SchemaObjectClass"
        )
        TestAssertions.assert_schema_objectclass_valid(oc, expected_oid, expected_name)
        return oc

    @staticmethod
    def test_schema_write_attribute(
        schema_quirk: FlextLdifServersRfc.Schema,
        attr: FlextLdifModels.SchemaAttribute,
        must_contain: list[str] | None = None,
    ) -> str:
        """Complete schema attribute write test - replaces entire test function.

        Args:
            schema_quirk: Schema quirk instance
            attr: SchemaAttribute to write
            must_contain: Optional list of strings that must appear in output

        Returns:
            Written LDIF string

        """
        result = schema_quirk.write(attr)
        ldif_text = TestAssertions.assert_success(
            result, "Attribute write should succeed"
        )
        assert isinstance(ldif_text, str), "Write should return string"
        if must_contain:
            for content in must_contain:
                assert content in ldif_text, (
                    f"Must contain '{content}' not found in LDIF"
                )
        return ldif_text

    @staticmethod
    def test_schema_write_objectclass(
        schema_quirk: FlextLdifServersRfc.Schema,
        oc: FlextLdifModels.SchemaObjectClass,
        must_contain: list[str] | None = None,
    ) -> str:
        """Complete schema objectClass write test - replaces entire test function.

        Args:
            schema_quirk: Schema quirk instance
            oc: SchemaObjectClass to write
            must_contain: Optional list of strings that must appear in output

        Returns:
            Written LDIF string

        """
        result = schema_quirk.write(oc)
        ldif_text = TestAssertions.assert_success(
            result, "ObjectClass write should succeed"
        )
        assert isinstance(ldif_text, str), "Write should return string"
        if must_contain:
            for content in must_contain:
                assert content in ldif_text, (
                    f"Must contain '{content}' not found in LDIF"
                )
        return ldif_text

    @staticmethod
    def test_syntax_definition_batch(
        schema_quirk: FlextLdifServersRfc.Schema,
        test_cases: list[tuple[str, str, str, str | None]],
    ) -> list[FlextLdifModels.SchemaAttribute]:
        """Test syntax_definition resolution for multiple attributes in batch.

        Args:
            schema_quirk: Schema quirk instance
            test_cases: List of (attr_def, expected_oid, expected_name, expected_syntax_name) tuples

        Returns:
            List of parsed attributes with validated syntax_definitions

        """
        attributes = []
        for attr_def, expected_oid, expected_name, expected_syntax_name in test_cases:
            attr = RfcTestHelpers.test_schema_parse_attribute(
                schema_quirk,
                attr_def,
                expected_oid,
                expected_name,
            )
            if expected_syntax_name is not None:
                syntax = attr.syntax_definition
                assert syntax is not None
                name_attr = getattr(syntax, "name", None)
                if name_attr is not None and not callable(name_attr):
                    assert name_attr == expected_syntax_name
            attributes.append(attr)
        return attributes

    @staticmethod
    def test_schema_write_attribute_with_metadata(
        schema_quirk: FlextLdifServersRfc.Schema,
        attr_def: str,
        expected_oid: str,
        expected_name: str,
        x_origin: str | None = None,
        must_contain: list[str] | None = None,
    ) -> tuple[FlextLdifModels.SchemaAttribute, str]:
        """Test schema attribute write with metadata - replaces 20+ lines.

        Args:
            schema_quirk: Schema quirk instance
            attr_def: Attribute definition string
            expected_oid: Expected OID
            expected_name: Expected name
            x_origin: Optional X-ORIGIN value to add
            must_contain: Optional list of strings that must appear in output

        Returns:
            Tuple of (parsed_attribute, written_ldif_string)

        """
        attr = RfcTestHelpers.test_schema_parse_attribute(
            schema_quirk,
            attr_def,
            expected_oid,
            expected_name,
        )
        if x_origin:
            if not attr.metadata:
                attr.metadata = FlextLdifModels.QuirkMetadata(
                    quirk_type="rfc",
                    extensions={},
                )
            attr.metadata.extensions["x_origin"] = x_origin
        written = RfcTestHelpers.test_schema_write_attribute(
            schema_quirk,
            attr,
            must_contain=must_contain,
        )
        return (attr, written)

    @staticmethod
    def test_schema_write_objectclass_with_metadata(
        schema_quirk: FlextLdifServersRfc.Schema,
        oc_def: str,
        expected_oid: str,
        expected_name: str,
        x_origin: str | None = None,
        must_contain: list[str] | None = None,
    ) -> tuple[FlextLdifModels.SchemaObjectClass, str]:
        """Test schema objectClass write with metadata - replaces 20+ lines.

        Args:
            schema_quirk: Schema quirk instance
            oc_def: ObjectClass definition string
            expected_oid: Expected OID
            expected_name: Expected name
            x_origin: Optional X-ORIGIN value to add
            must_contain: Optional list of strings that must appear in output

        Returns:
            Tuple of (parsed_objectClass, written_ldif_string)

        """
        oc = RfcTestHelpers.test_schema_parse_objectclass(
            schema_quirk,
            oc_def,
            expected_oid,
            expected_name,
        )
        if x_origin:
            if not oc.metadata:
                oc.metadata = FlextLdifModels.QuirkMetadata(
                    quirk_type="rfc",
                    extensions={},
                )
            oc.metadata.extensions["x_origin"] = x_origin
        written = RfcTestHelpers.test_schema_write_objectclass(
            schema_quirk,
            oc,
            must_contain=must_contain,
        )
        return (oc, written)

    @staticmethod
    def test_create_entry_validated(
        dn: str,
        attributes: dict[str, list[str]],
    ) -> FlextLdifModels.Entry:
        """Create entry with automatic validation - replaces 5-10 lines.

        Args:
            dn: Distinguished name
            attributes: Dictionary of attribute names to values

        Returns:
            Created and validated Entry model

        """
        # Convert dict[str, list[str]] to dict[str, str | list[str]] for Entry.create
        attributes_typed: dict[str, str | list[str]] = dict(attributes.items())
        result = FlextLdifModels.Entry.create(dn=dn, attributes=attributes_typed)
        entry = cast("FlextLdifModels.Entry", TestAssertions.assert_success(result))
        TestAssertions.assert_entry_valid(entry)
        return entry

    @staticmethod
    def test_entry_quirk_can_handle(
        entry_quirk: FlextLdifServersRfc.Entry,
        entry: FlextLdifModels.Entry,
        *,
        expected: bool = True,
    ) -> None:
        """Test entry quirk can_handle_entry - replaces entire test function.

        Args:
            entry_quirk: Entry quirk instance
            entry: Entry to test
            expected: Expected result (default: True)

        """
        result = entry_quirk.can_handle_entry(entry)
        assert result == expected, f"Expected can_handle_entry={expected}, got {result}"

    @staticmethod
    def test_write_entry_variations(
        writer: FlextLdifWriter,
        entry_data: dict[str, dict[str, str | dict[str, list[str]]]],
        *,
        target_server_type: str = "rfc",
    ) -> None:
        """Test writing multiple entry variations using mappings.

        Args:
            writer: Writer service instance
            entry_data: Dict mapping entry names to {dn: str, attributes: dict}
            target_server_type: Target server type (default: "rfc")

        """
        for data in entry_data.values():
            dn = data["dn"]
            assert isinstance(dn, str), "DN must be string"
            attributes = data["attributes"]
            assert isinstance(attributes, dict), "Attributes must be dict"
            entry = RfcTestHelpers.test_create_entry(
                dn=dn,
                attributes=attributes,
            )
            _ = RfcTestHelpers.test_write_entries_to_string(
                writer,
                [entry],
                target_server_type=target_server_type,
            )

    @staticmethod
    def test_entry_quirk_write_and_verify(
        entry_quirk: FlextLdifServersRfc.Entry,
        entry: FlextLdifModels.Entry,
        must_contain: list[str] | None = None,
        must_not_contain: list[str] | None = None,
    ) -> str:
        """Test entry quirk write with automatic validation - replaces 8-15 lines.

        Args:
            entry_quirk: Entry quirk instance
            entry: Entry to write
            must_contain: Optional list of strings that must appear in output
            must_not_contain: Optional list of strings that must NOT appear in output

        Returns:
            Written LDIF string

        """
        result = entry_quirk.write(entry)
        ldif_text = TestAssertions.assert_success(result, "Entry write should succeed")
        assert isinstance(ldif_text, str), "Write should return string"
        assert len(ldif_text) > 0, "Written LDIF should not be empty"
        if must_contain:
            for content in must_contain:
                assert content in ldif_text, (
                    f"Must contain '{content}' not found in LDIF"
                )
        if must_not_contain:
            for content in must_not_contain:
                assert content not in ldif_text, (
                    f"Must not contain '{content}' found in LDIF"
                )
        return ldif_text

    @staticmethod
    def test_entry_quirk_write_entry_and_verify(
        entry_quirk: FlextLdifServersRfc.Entry,
        entry: FlextLdifModels.Entry,
        must_contain: list[str] | None = None,
    ) -> str:
        """Test entry quirk _write_entry with automatic validation - replaces 8-12 lines.

        Args:
            entry_quirk: Entry quirk instance
            entry: Entry to write
            must_contain: Optional list of strings that must appear in output

        Returns:
            Written LDIF string

        """
        result = entry_quirk._write_entry(entry)
        ldif_text = TestAssertions.assert_success(result, "Entry write should succeed")
        assert isinstance(ldif_text, str), "Write should return string"
        if must_contain:
            for content in must_contain:
                assert content in ldif_text, (
                    f"Must contain '{content}' not found in LDIF"
                )
        return ldif_text

    @staticmethod
    def test_entry_quirk_parse_content_and_verify(
        entry_quirk: FlextLdifServersRfc.Entry,
        ldif_content: str,
        expected_count: int | None = None,
        expected_dn: str | None = None,
    ) -> list[FlextLdifModels.Entry]:
        """Test entry quirk _parse_content with automatic validation - replaces 8-15 lines.

        Args:
            entry_quirk: Entry quirk instance
            ldif_content: LDIF content string
            expected_count: Optional expected entry count
            expected_dn: Optional expected DN

        Returns:
            List of parsed entries

        """
        result = entry_quirk._parse_content(ldif_content)
        entries = TestAssertions.assert_success(result, "Parse content should succeed")
        assert isinstance(entries, list), "Parse should return list"
        # Only check len > 0 if expected_count is None or > 0
        if expected_count is None or expected_count > 0:
            assert len(entries) > 0, "Should have at least one entry"
        if expected_count is not None:
            assert len(entries) == expected_count, (
                f"Expected {expected_count} entries, got {len(entries)}"
            )
        if expected_dn:
            assert entries[0].dn is not None
            assert entries[0].dn.value == expected_dn
        return entries

    @staticmethod
    def test_entry_quirk_parse_entry_and_verify(
        entry_quirk: FlextLdifServersRfc.Entry,
        dn: str,
        attributes: dict[str, list[bytes]],
        expected_dn: str | None = None,
    ) -> FlextLdifModels.Entry:
        """Test entry quirk _parse_entry with automatic validation - replaces 10-15 lines.

        Args:
            entry_quirk: Entry quirk instance
            dn: Distinguished name
            attributes: Dictionary of attribute names to byte values
            expected_dn: Optional expected DN (if different from input dn)

        Returns:
            Parsed Entry model

        """
        result = entry_quirk._parse_entry(dn, attributes)
        entry = TestAssertions.assert_success(result, "Parse entry should succeed")
        assert isinstance(entry, FlextLdifModels.Entry), "Parse should return Entry"
        expected = expected_dn or dn
        if expected:
            assert entry.dn is not None
            assert entry.dn.value == expected
        return entry

    @staticmethod
    def test_create_schema_attribute_simple(
        oid: str,
        name: str,
        desc: str | None = None,
        sup: str | None = None,
        syntax: str | None = None,
        **kwargs: object,
    ) -> FlextLdifModels.SchemaAttribute:
        """Create schema attribute with minimal parameters - replaces 15-25 lines.

        Args:
            oid: Attribute OID
            name: Attribute name
            desc: Optional description
            sup: Optional superior attribute
            syntax: Optional syntax OID
            **kwargs: Additional attribute properties

        Returns:
            Created SchemaAttribute

        """
        return FlextLdifModels.SchemaAttribute(
            oid=oid,
            name=name,
            desc=desc,
            sup=sup,
            equality=None,
            ordering=None,
            substr=None,
            syntax=syntax,
            length=None,
            usage=None,
            x_origin=cast("str | None", kwargs.get("x_origin")),
            x_file_ref=cast("str | None", kwargs.get("x_file_ref")),
            x_name=cast("str | None", kwargs.get("x_name")),
            x_alias=cast("str | None", kwargs.get("x_alias")),
            x_oid=cast("str | None", kwargs.get("x_oid")),
            single_value=cast("bool", kwargs.get("single_value", False)),
            no_user_modification=cast(
                "bool", kwargs.get("no_user_modification", False)
            ),
            metadata=cast(
                "FlextLdifModels.QuirkMetadata | None", kwargs.get("metadata")
            ),
        )

    @staticmethod
    def test_create_schema_objectclass_simple(
        oid: str,
        name: str,
        desc: str | None = None,
        sup: str | None = None,
        kind: str | None = None,
        **kwargs: object,
    ) -> FlextLdifModels.SchemaObjectClass:
        """Create schema objectClass with minimal parameters - replaces 10-20 lines.

        Args:
            oid: ObjectClass OID
            name: ObjectClass name
            desc: Optional description
            sup: Optional superior objectClass
            kind: Optional kind (STRUCTURAL, ABSTRACT, AUXILIARY)
            **kwargs: Additional objectClass properties

        Returns:
            Created SchemaObjectClass

        """
        return FlextLdifModels.SchemaObjectClass(
            oid=oid,
            name=name,
            desc=desc,
            sup=sup,
            kind=kind or "STRUCTURAL",
            must=cast("list[str] | None", kwargs.get("must")),
            may=cast("list[str] | None", kwargs.get("may")),
            metadata=cast(
                "FlextLdifModels.QuirkMetadata | None", kwargs.get("metadata")
            ),
        )

    @staticmethod
    def test_schema_quirk_route_parse_and_verify(
        schema_quirk: FlextLdifServersRfc.Schema,
        schema_def: str,
        expected_type: str,
        expected_name: str | None = None,
    ) -> FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass:
        """Test schema quirk _route_parse with automatic validation - replaces 8-12 lines.

        Args:
            schema_quirk: Schema quirk instance
            schema_def: Schema definition string
            expected_type: Expected type ("attribute" or "objectclass")
            expected_name: Optional expected name

        Returns:
            Parsed SchemaAttribute or SchemaObjectClass

        """
        result = schema_quirk._route_parse(schema_def)
        schema_obj_untyped = TestAssertions.assert_success(
            result, "Route parse should succeed"
        )
        schema_obj: FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass
        if expected_type == "attribute":
            assert isinstance(schema_obj_untyped, FlextLdifModels.SchemaAttribute), (
                "Should return SchemaAttribute"
            )
            schema_obj = schema_obj_untyped
        elif expected_type == "objectclass":
            assert isinstance(schema_obj_untyped, FlextLdifModels.SchemaObjectClass), (
                "Should return SchemaObjectClass"
            )
            schema_obj = schema_obj_untyped
        else:
            schema_obj = cast(
                "FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass",
                schema_obj_untyped,
            )
        if expected_name:
            assert schema_obj.name == expected_name
        return schema_obj

    @staticmethod
    def test_schema_quirk_route_write_and_verify(
        schema_quirk: FlextLdifServersRfc.Schema,
        schema_obj: FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass,
        must_contain: list[str] | None = None,
    ) -> str:
        """Test schema quirk _route_write with automatic validation - replaces 6-10 lines.

        Args:
            schema_quirk: Schema quirk instance
            schema_obj: SchemaAttribute or SchemaObjectClass to write
            must_contain: Optional list of strings that must appear in output

        Returns:
            Written LDIF string

        """
        result = schema_quirk._route_write(schema_obj)
        ldif_text = TestAssertions.assert_success(result, "Route write should succeed")
        assert isinstance(ldif_text, str), "Write should return string"
        if must_contain:
            for content in must_contain:
                assert content in ldif_text, (
                    f"Must contain '{content}' not found in LDIF"
                )
        return ldif_text

    @staticmethod
    def test_schema_quirk_execute_and_verify(
        schema_quirk: FlextLdifServersRfc.Schema,
        data: str
        | FlextLdifModels.SchemaAttribute
        | FlextLdifModels.SchemaObjectClass
        | None = None,
        operation: str | None = None,
        expected_type: type | None = None,
        must_contain: list[str] | None = None,
    ) -> FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str:
        """Test schema quirk execute with automatic validation - replaces 10-20 lines.

        Args:
            schema_quirk: Schema quirk instance
            data: Data to execute (string for parse, model for write, None for health check)
            operation: Optional operation ("parse" or "write")
            expected_type: Optional expected return type
            must_contain: Optional list of strings that must appear in output (for write)

        Returns:
            Result of execute (SchemaAttribute, SchemaObjectClass, or str)

        """
        operation_typed: Literal["parse", "write"] | None = (
            cast("Literal['parse', 'write']", operation)
            if operation in {"parse", "write"}
            else None
        )
        result = schema_quirk.execute(data=data, operation=operation_typed)
        unwrapped = TestAssertions.assert_success(result, "Execute should succeed")
        if expected_type:
            assert isinstance(unwrapped, expected_type), (
                f"Expected {expected_type}, got {type(unwrapped)}"
            )
        if must_contain and isinstance(unwrapped, str):
            for content in must_contain:
                assert content in unwrapped, f"Must contain '{content}' not found"
        return cast(
            "FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str",
            unwrapped,
        )

    @staticmethod
    def test_acl_quirk_parse_and_verify(
        acl_quirk: FlextLdifServersRfc.Acl,
        acl_line: str,
        expected_raw_acl: str | None = None,
    ) -> FlextLdifModels.Acl:
        """Test ACL quirk parse with automatic validation - replaces 8-12 lines.

        Args:
            acl_quirk: ACL quirk instance
            acl_line: ACL line string
            expected_raw_acl: Optional expected raw ACL value

        Returns:
            Parsed Acl model

        """
        result = acl_quirk.parse(acl_line)
        acl = TestAssertions.assert_success(result, "ACL parse should succeed")
        assert isinstance(acl, FlextLdifModels.Acl), "Parse should return Acl"
        if expected_raw_acl:
            assert acl.raw_acl == expected_raw_acl
        return acl

    @staticmethod
    def test_acl_quirk_write_and_verify(
        acl_quirk: FlextLdifServersRfc.Acl,
        acl: FlextLdifModels.Acl,
        *,
        expected_content: str | None = None,
        must_contain: list[str] | None = None,
    ) -> str:
        """Test ACL quirk write with automatic validation - replaces 8-12 lines.

        Args:
            acl_quirk: ACL quirk instance
            acl: Acl model to write
            expected_content: Optional expected content in output (deprecated, use must_contain)
            must_contain: Optional list of strings that must appear in output

        Returns:
            Written LDIF string

        """
        result = acl_quirk._write_acl(acl)
        ldif_text = TestAssertions.assert_success(result, "ACL write should succeed")
        assert isinstance(ldif_text, str), "Write should return string"
        if expected_content:
            assert expected_content in ldif_text, (
                f"Expected content '{expected_content}' not found in ACL string"
            )
        if must_contain:
            for content in must_contain:
                assert content in ldif_text, (
                    f"Must contain '{content}' not found in LDIF"
                )
        return ldif_text

    @staticmethod
    def test_acl_quirk_execute_and_verify(
        acl_quirk: FlextLdifServersRfc.Acl,
        data: str | FlextLdifModels.Acl | None = None,
        operation: str | None = None,
        expected_type: type | None = None,
        must_contain: list[str] | None = None,
    ) -> FlextLdifModels.Acl | str:
        """Test ACL quirk execute with automatic validation - replaces 10-20 lines.

        Args:
            acl_quirk: ACL quirk instance
            data: Data to execute (string for parse, Acl for write, None for health check)
            operation: Optional operation ("parse" or "write")
            expected_type: Optional expected return type
            must_contain: Optional list of strings that must appear in output (for write)

        Returns:
            Result of execute (Acl or str)

        """
        operation_typed: Literal["parse", "write"] | None = (
            cast("Literal['parse', 'write']", operation)
            if operation in {"parse", "write"}
            else None
        )
        result = acl_quirk.execute(data=data, operation=operation_typed)
        unwrapped = TestAssertions.assert_success(result, "Execute should succeed")
        if expected_type:
            assert isinstance(unwrapped, expected_type), (
                f"Expected {expected_type}, got {type(unwrapped)}"
            )
        if must_contain and isinstance(unwrapped, str):
            for content in must_contain:
                assert content in unwrapped, f"Must contain '{content}' not found"
        return cast("FlextLdifModels.Acl | str", unwrapped)

    @staticmethod
    def test_entry_quirk_execute_and_verify(
        entry_quirk: FlextLdifServersRfc.Entry,
        data: str | FlextLdifModels.Entry | list[FlextLdifModels.Entry] | None = None,
        operation: str | None = None,
        expected_count: int | None = None,
        must_contain: list[str] | None = None,
    ) -> list[FlextLdifModels.Entry] | str:
        """Test entry quirk execute with automatic validation - replaces 15-25 lines.

        Args:
            entry_quirk: Entry quirk instance
            data: Data to execute (string for parse, Entry/list for write, None for health check)
            operation: Optional operation ("parse" or "write")
            expected_count: Optional expected entry count (for parse)
            must_contain: Optional list of strings that must appear in output (for write)

        Returns:
            Result of execute (list[Entry] for parse, str for write)

        """
        # Convert Entry to list[Entry] if needed
        data_typed: str | list[FlextLdifModels.Entry] | None = (
            [data] if isinstance(data, FlextLdifModels.Entry) else data
        )
        operation_typed: Literal["parse", "write"] | None = (
            cast("Literal['parse', 'write']", operation)
            if operation in {"parse", "write"}
            else None
        )
        result = entry_quirk.execute(data=data_typed, operation=operation_typed)
        unwrapped = TestAssertions.assert_success(result, "Execute should succeed")
        if expected_count is not None:
            assert isinstance(unwrapped, list), "Parse should return list"
            assert len(unwrapped) == expected_count, (
                f"Expected {expected_count} entries, got {len(unwrapped)}"
            )
        if must_contain and isinstance(unwrapped, str):
            for content in must_contain:
                assert content in unwrapped, f"Must contain '{content}' not found"
        return cast("list[FlextLdifModels.Entry] | str", unwrapped)

    @staticmethod
    def test_parse_result_and_assert(
        result: object,
        *,
        should_succeed: bool = True,
        expected_type: type | None = None,
        expected_oid: str | None = None,
        expected_name: str | None = None,
    ) -> FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass:
        """Parse result assertion helper - replaces 5-10 lines.

        Args:
            result: FlextResult from parse operation
            should_succeed: Whether result should be successful
            expected_type: Optional expected type of unwrapped value
            expected_oid: Optional expected OID (for schema objects)
            expected_name: Optional expected name (for schema objects)

        Returns:
            Unwrapped result value

        """
        if should_succeed:
            unwrapped = TestAssertions.assert_success(
                cast("FlextResult[object]", result)
            )
        else:
            _ = TestAssertions.assert_failure(cast("FlextResult[object]", result))
            msg = "Cannot unwrap failed result"
            raise AssertionError(msg)
        if expected_type:
            assert isinstance(unwrapped, expected_type)
        schema_obj = cast(
            "FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass",
            unwrapped,
        )
        if expected_oid and hasattr(schema_obj, "oid"):
            assert schema_obj.oid == expected_oid
        if expected_name and hasattr(schema_obj, "name"):
            assert schema_obj.name == expected_name
        return schema_obj

    @staticmethod
    def test_schema_parse_and_assert_basic_properties(
        schema_quirk: FlextLdifServersRfc.Schema,
        schema_def: str,
        *,
        expected_oid: str,
        expected_name: str | None = None,
        expected_desc: str | None = None,
        expected_syntax: str | None = None,
        expected_sup: str | None = None,
        expected_usage: str | None = None,
    ) -> FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass:
        """Parse schema and assert basic properties - replaces 10-20 lines.

        Args:
            schema_quirk: Schema quirk instance
            schema_def: Schema definition string
            expected_oid: Expected OID
            expected_name: Optional expected name
            expected_desc: Optional expected description
            expected_syntax: Optional expected syntax OID
            expected_sup: Optional expected superior
            expected_usage: Optional expected usage

        Returns:
            Parsed schema object

        """
        result = schema_quirk.parse(schema_def)
        schema_obj = RfcTestHelpers.test_parse_result_and_assert(
            result,
            expected_oid=expected_oid,
            expected_name=expected_name,
        )
        if expected_desc and hasattr(schema_obj, "desc"):
            schema_attr = cast("FlextLdifModels.SchemaAttribute", schema_obj)
            assert schema_attr.desc == expected_desc
        if expected_syntax and hasattr(schema_obj, "syntax"):
            schema_attr = cast("FlextLdifModels.SchemaAttribute", schema_obj)
            assert schema_attr.syntax == expected_syntax
        if expected_sup and hasattr(schema_obj, "sup"):
            if isinstance(schema_obj, FlextLdifModels.SchemaAttribute):
                assert schema_obj.sup == expected_sup
            else:
                # schema_obj is SchemaObjectClass at this point
                sup_value = schema_obj.sup
                if isinstance(sup_value, str):
                    assert sup_value == expected_sup
                elif isinstance(sup_value, list):
                    assert expected_sup in sup_value
        if expected_usage and hasattr(schema_obj, "usage"):
            schema_attr = cast("FlextLdifModels.SchemaAttribute", schema_obj)
            assert schema_attr.usage == expected_usage
        return schema_obj

    @staticmethod
    def test_schema_parse_and_assert_flags(
        schema_quirk: FlextLdifServersRfc.Schema,
        attr_def: str,
        *,
        expected_oid: str,
        expected_name: str,
        single_value: bool | None = None,
        no_user_modification: bool | None = None,
        obsolete: bool | None = None,
    ) -> FlextLdifModels.SchemaAttribute:
        """Parse attribute and assert flags - replaces 8-15 lines.

        Args:
            schema_quirk: Schema quirk instance
            attr_def: Attribute definition string
            expected_oid: Expected OID
            expected_name: Expected name
            single_value: Optional expected SINGLE-VALUE flag
            no_user_modification: Optional expected NO-USER-MODIFICATION flag
            obsolete: Optional expected OBSOLETE flag

        Returns:
            Parsed attribute

        """
        attr = RfcTestHelpers.test_schema_parse_attribute(
            schema_quirk,
            attr_def,
            expected_oid,
            expected_name,
        )
        if single_value is not None:
            assert attr.single_value == single_value
        if no_user_modification is not None:
            assert attr.no_user_modification == no_user_modification
        if obsolete is not None:
            assert attr.obsolete == obsolete
        return attr

    @staticmethod
    def test_schema_parse_and_assert_matching_rules(
        schema_quirk: FlextLdifServersRfc.Schema,
        attr_def: str,
        *,
        expected_oid: str,
        expected_name: str,
        expected_equality: str | None = None,
        expected_ordering: str | None = None,
        expected_substr: str | None = None,
        has_matching_rules: bool | None = None,
    ) -> FlextLdifModels.SchemaAttribute:
        """Parse attribute and assert matching rules - replaces 10-20 lines.

        Args:
            schema_quirk: Schema quirk instance
            attr_def: Attribute definition string
            expected_oid: Expected OID
            expected_name: Expected name
            expected_equality: Optional expected equality matching rule
            expected_ordering: Optional expected ordering matching rule
            expected_substr: Optional expected substring matching rule
            has_matching_rules: Optional expected has_matching_rules value

        Returns:
            Parsed attribute

        """
        attr = RfcTestHelpers.test_schema_parse_attribute(
            schema_quirk,
            attr_def,
            expected_oid,
            expected_name,
        )
        if expected_equality is not None:
            assert attr.equality == expected_equality
        if expected_ordering is not None:
            assert attr.ordering == expected_ordering
        if expected_substr is not None:
            assert attr.substr == expected_substr
        if has_matching_rules is not None:
            assert attr.has_matching_rules == has_matching_rules
        return attr

    @staticmethod
    def test_parse_error_handling(
        parser_or_quirk: FlextLdifParser | QuirkInstance,
        invalid_input: str,
        *,
        method_name: str = "parse",
        should_fail: bool = True,
    ) -> object:
        """Test error handling for parse operations - replaces 5-10 lines.

        Args:
            parser_or_quirk: Parser or quirk instance
            invalid_input: Invalid input string
            method_name: Method name to call (default: "parse")
            should_fail: Whether operation should fail

        Returns:
            Result object

        """
        method = getattr(parser_or_quirk, method_name)
        result = method(invalid_input)
        if should_fail:
            assert result.is_failure, "Expected failure for invalid input"
        else:
            assert result.is_success or result.is_failure, (
                "Result should have is_success/is_failure"
            )
        return result

    @staticmethod
    def test_parse_and_validate_flext_result(
        parser_or_quirk: FlextLdifParser | QuirkInstance,
        input_data: str,
        *,
        method_name: str = "parse",
        expected_has_attributes: list[str] | None = None,
    ) -> object:
        """Parse and validate FlextResult structure - replaces 8-12 lines.

        Args:
            parser_or_quirk: Parser or quirk instance
            input_data: Input data string
            method_name: Method name to call (default: "parse")
            expected_has_attributes: Optional list of attribute names to check

        Returns:
            Result object

        """
        method = getattr(parser_or_quirk, method_name)
        result = method(input_data)
        assert hasattr(result, "is_success"), "Result should have is_success"
        assert hasattr(result, "is_failure"), "Result should have is_failure"
        assert hasattr(result, "unwrap"), "Result should have unwrap"
        if result.is_success and expected_has_attributes:
            unwrapped = result.unwrap()
            for attr_name in expected_has_attributes:
                assert hasattr(unwrapped, attr_name), (
                    f"Should have attribute {attr_name}"
                )
        return result

    @staticmethod
    def test_parse_edge_case(
        parser: FlextLdifParser,
        ldif_content: str,
        *,
        should_succeed: bool | None = None,
    ) -> None:
        """Test parsing edge case - replaces entire test function.

        Args:
            parser: Parser service instance
            ldif_content: LDIF content (may be malformed)
            should_succeed: Optional - if None, accepts success or failure

        """
        result = parser.parse(ldif_content, input_source="string")
        if should_succeed is True:
            _ = TestAssertions.assert_success(result, "Parse should succeed")
        elif should_succeed is False:
            _ = TestAssertions.assert_failure(result)
        else:
            assert result.is_success or result.is_failure, (
                "Parse should succeed or fail gracefully"
            )

    @staticmethod
    def test_parse_edge_cases_batch(
        parser: FlextLdifParser,
        test_cases: list[tuple[str, str, bool | None]],
    ) -> None:
        """Test multiple edge cases in batch - replaces 20-50+ lines.

        Args:
            parser: Parser service instance
            test_cases: List of (name, ldif_content, should_succeed) tuples

        """
        for name, ldif_content, should_succeed in test_cases:
            try:
                RfcTestHelpers.test_parse_edge_case(
                    parser,
                    ldif_content,
                    should_succeed=should_succeed,
                )
            except AssertionError as e:
                msg = f"Test case '{name}' failed: {e}"
                raise AssertionError(msg) from e

    @staticmethod
    def test_api_parse_and_assert(
        api: HasParseMethod,
        ldif_input: str | Path,
        *,
        expected_count: int | None = None,
        expected_dns: list[str] | None = None,
        server_type: str | None = None,
    ) -> list[FlextLdifModels.Entry]:
        """API parse with automatic validation - replaces 10-20 lines.

        Args:
            api: FlextLdif API instance
            ldif_input: LDIF content string or Path
            expected_count: Optional expected entry count
            expected_dns: Optional list of expected DN values
            server_type: Optional server type override

        Returns:
            List of parsed entries

        """
        if server_type:
            result = api.parse(ldif_input, server_type=server_type)
        else:
            result = api.parse(ldif_input)
        # result is already FlextResult[list[Entry]] from api.parse()
        assert result.is_success, (
            f"Parse failed: {result.error if hasattr(result, 'error') else 'unknown'}"
        )
        entries = result.unwrap()
        assert isinstance(entries, list), "Parse should return list"
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
        return entries

    @staticmethod
    def test_api_write_and_assert(
        api: HasParseMethod,
        entries: list[FlextLdifModels.Entry] | FlextLdifModels.Entry,
        *,
        must_contain: list[str] | None = None,
        output_path: Path | None = None,
        server_type: str | None = None,
    ) -> str:
        """API write with automatic validation - replaces 10-15 lines.

        Args:
            api: FlextLdif API instance
            entries: Entry or list of entries to write
            must_contain: Optional list of strings that must appear in output
            output_path: Optional output file path
            server_type: Optional server type override

        Returns:
            Written LDIF string

        """
        if isinstance(entries, FlextLdifModels.Entry):
            entries = [entries]
        kwargs = {}
        if output_path:
            kwargs["output_path"] = output_path
        if server_type:
            kwargs["server_type"] = server_type
        # api is object, access write method dynamically
        write_method = getattr(api, "write", None)
        if write_method is None:
            msg = "API object does not have write method"
            raise AttributeError(msg)
        result = write_method(entries, **kwargs)
        result_typed = cast("FlextResult[str]", result)
        assert result_typed.is_success, (
            f"Write failed: {result_typed.error if hasattr(result_typed, 'error') else 'unknown'}"
        )
        written = result_typed.unwrap()
        assert isinstance(written, str), "Write should return string"
        if must_contain:
            for content in must_contain:
                assert content in written, (
                    f"Output must contain '{content}': {written[:200]}"
                )
        return written

    @staticmethod
    def test_api_roundtrip(
        api: HasParseMethod,
        ldif_input: str | Path,
        *,
        expected_count: int | None = None,
        server_type: str | None = None,
        tmp_path: Path | None = None,
    ) -> tuple[list[FlextLdifModels.Entry], list[FlextLdifModels.Entry], str]:
        """API roundtrip test - replaces 20-30 lines.

        Args:
            api: FlextLdif API instance
            ldif_input: LDIF content string or Path
            expected_count: Optional expected entry count
            server_type: Optional server type override
            tmp_path: Optional temporary path for output file

        Returns:
            Tuple of (original_entries, roundtripped_entries, written_ldif)

        """
        original_entries = RfcTestHelpers.test_api_parse_and_assert(
            api,
            ldif_input,
            expected_count=expected_count,
            server_type=server_type,
        )
        if tmp_path:
            output_file = tmp_path / "roundtrip_output.ldif"
            written = RfcTestHelpers.test_api_write_and_assert(
                api,
                original_entries,
                output_path=output_file,
                server_type=server_type,
            )
            roundtripped = RfcTestHelpers.test_api_parse_and_assert(
                api,
                output_file,
                expected_count=expected_count,
                server_type=server_type,
            )
        else:
            written = RfcTestHelpers.test_api_write_and_assert(
                api,
                original_entries,
                server_type=server_type,
            )
            roundtripped = RfcTestHelpers.test_api_parse_and_assert(
                api,
                written,
                expected_count=expected_count,
                server_type=server_type,
            )
        return (original_entries, roundtripped, written)

    @staticmethod
    def test_quirk_parse_and_assert(
        quirk: QuirkInstance,
        input_data: str,
        *,
        method_name: str = "parse",
        expected_oid: str | None = None,
        expected_name: str | None = None,
        should_succeed: bool = True,
    ) -> object:
        """Quirk parse with automatic validation - replaces 8-15 lines.

        Args:
            quirk: Quirk instance (Schema, Entry, Acl, etc.)
            input_data: Input data string
            method_name: Method name to call (default: "parse")
            expected_oid: Optional expected OID
            expected_name: Optional expected name
            should_succeed: Whether operation should succeed

        Returns:
            Unwrapped result or None if should fail

        """
        method = getattr(quirk, method_name)
        result = method(input_data)
        if should_succeed:
            unwrapped_untyped = TestAssertions.assert_success(result)
            unwrapped = cast(
                "FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass",
                unwrapped_untyped,
            )
            if expected_oid and hasattr(unwrapped, "oid"):
                assert unwrapped.oid == expected_oid
            if expected_name and hasattr(unwrapped, "name"):
                assert unwrapped.name == expected_name
            return unwrapped
        _ = TestAssertions.assert_failure(result)
        return None

    @staticmethod
    def test_quirk_write_and_assert(
        quirk: QuirkInstance,
        model: FlextLdifModels.Entry
        | FlextLdifModels.SchemaAttribute
        | FlextLdifModels.SchemaObjectClass,
        *,
        method_name: str = "write",
        must_contain: list[str] | None = None,
    ) -> str:
        """Quirk write with automatic validation - replaces 8-12 lines.

        Args:
            quirk: Quirk instance
            model: Model to write (Entry, SchemaAttribute, etc.)
            method_name: Method name to call (default: "write")
            must_contain: Optional list of strings that must appear in output

        Returns:
            Written LDIF string

        """
        method = getattr(quirk, method_name)
        result = method(model)
        written = TestAssertions.assert_success(result)
        assert isinstance(written, str), "Write should return string"
        if must_contain:
            for content in must_contain:
                assert content in written, (
                    f"Output must contain '{content}': {written[:200]}"
                )
        return written

    @staticmethod
    def test_create_entry_and_validate(
        dn: str,
        attributes: dict[str, list[str]],
        *,
        expected_dn: str | None = None,
        expected_attributes: list[str] | None = None,
    ) -> FlextLdifModels.Entry:
        """Create entry and validate structure - replaces 8-15 lines.

        Args:
            dn: Distinguished name
            attributes: Dictionary of attribute names to values
            expected_dn: Optional expected DN (if different from input)
            expected_attributes: Optional list of attribute names that must exist

        Returns:
            Created and validated Entry

        """
        # Convert dict[str, list[str]] to dict[str, str | list[str]] for Entry.create
        attributes_typed: dict[str, str | list[str]] = dict(attributes.items())
        result = FlextLdifModels.Entry.create(dn=dn, attributes=attributes_typed)
        entry = cast("FlextLdifModels.Entry", TestAssertions.assert_success(result))
        TestAssertions.assert_entry_valid(entry)
        if expected_dn:
            assert entry.dn is not None
            assert entry.dn.value == expected_dn
        if expected_attributes:
            assert entry.attributes is not None
            for attr_name in expected_attributes:
                assert attr_name in entry.attributes.attributes
        return entry

    @staticmethod
    def test_parse_result_unwrap_and_validate(
        result: FlextResult[object],
        *,
        expected_type: type | None = None,
        expected_count: int | None = None,
        expected_has_attributes: list[str] | None = None,
    ) -> object:
        """Unwrap result and validate - replaces 5-10 lines.

        Args:
            result: FlextResult object
            expected_type: Optional expected type
            expected_count: Optional expected count (for lists)
            expected_has_attributes: Optional list of attribute names to check

        Returns:
            Unwrapped result

        """
        assert result.is_success, (
            f"Operation failed: {result.error if hasattr(result, 'error') else 'unknown'}"
        )
        unwrapped = result.unwrap()
        if expected_type:
            assert isinstance(unwrapped, expected_type)
        if expected_count is not None and isinstance(unwrapped, list):
            assert len(unwrapped) == expected_count
        if expected_has_attributes:
            for attr_name in expected_has_attributes:
                assert hasattr(unwrapped, attr_name), (
                    f"Should have attribute {attr_name}"
                )
        return unwrapped

    @staticmethod
    def test_service_execute_and_assert(
        service: QuirkInstance,
        *,
        data: str | FlextLdifModels.Entry | list[FlextLdifModels.Entry] | None = None,
        operation: str | None = None,
        expected_type: type | None = None,
        expected_count: int | None = None,
        must_contain: list[str] | None = None,
        should_succeed: bool = True,
    ) -> object:
        """Service execute with automatic validation - replaces 8-15 lines.

        Args:
            service: Service instance with execute() method
            data: Optional data to pass to execute
            operation: Optional operation name
            expected_type: Optional expected type of result
            expected_count: Optional expected count (for lists)
            must_contain: Optional list of strings that must appear (for strings)
            should_succeed: Whether operation should succeed

        Returns:
            Unwrapped result or None if should fail

        """
        kwargs = {}
        if data is not None:
            kwargs["data"] = data
        if operation is not None:
            kwargs["operation"] = operation
        result = service.execute(**kwargs)
        if should_succeed:
            unwrapped = TestAssertions.assert_success(result)
            if expected_type:
                assert isinstance(unwrapped, expected_type)
            if expected_count is not None and isinstance(unwrapped, list):
                assert len(unwrapped) == expected_count
            if must_contain and isinstance(unwrapped, str):
                for content in must_contain:
                    assert content in unwrapped, f"Must contain '{content}'"
            return unwrapped
        _ = TestAssertions.assert_failure(result)
        return None

    @staticmethod
    def test_parse_write_roundtrip_with_options(
        parser: FlextLdifParser,
        writer: FlextLdifWriter,
        ldif_content: str,
        *,
        parse_options: object | None = None,
        write_options: object | None = None,
        server_type: str = "rfc",
        must_contain: list[str] | None = None,
    ) -> tuple[list[FlextLdifModels.Entry], str]:
        """Parse-write roundtrip with format options - replaces 25-40 lines.

        Args:
            parser: Parser service instance
            writer: Writer service instance
            ldif_content: LDIF content string
            parse_options: Optional ParseFormatOptions
            write_options: Optional WriteFormatOptions
            server_type: Server type (default: "rfc")
            must_contain: Optional list of strings that must appear in output

        Returns:
            Tuple of (parsed_entries, written_ldif)

        """
        parse_kwargs: dict[str, Any] = {
            "content": ldif_content,
            "input_source": "string",
            "server_type": server_type,
        }
        if parse_options:
            parse_kwargs["format_options"] = parse_options
        parse_result = parser.parse(**parse_kwargs)
        parse_response_untyped = TestAssertions.assert_success(parse_result)
        if hasattr(parse_response_untyped, "entries"):
            parse_response = cast("HasEntries", parse_response_untyped)
            entries = parse_response.entries
        elif isinstance(parse_response_untyped, list):
            entries = cast("list[FlextLdifModels.Entry]", parse_response_untyped)
        else:
            msg = "Parse returned unexpected type"
            raise AssertionError(msg)

        write_kwargs: dict[str, Any] = {
            "entries": entries,
            "target_server_type": server_type,
            "output_target": "string",
        }
        if write_options:
            write_kwargs["format_options"] = write_options
        write_result = writer.write(**write_kwargs)
        written = cast("str", TestAssertions.assert_success(write_result))
        assert isinstance(written, str)

        if must_contain:
            for content in must_contain:
                assert content in written, (
                    f"Output must contain '{content}': {written[:200]}"
                )
        return (entries, written)

    @staticmethod
    def test_fixture_parse_and_validate_batch(
        api: HasParseMethod,
        fixture_paths: dict[str, Path | str],
        *,
        expected_min_entries: int | None = None,
    ) -> dict[str, list[FlextLdifModels.Entry]]:
        """Parse multiple fixtures and validate - replaces 15-25 lines per fixture.

        Args:
            api: FlextLdif API instance
            fixture_paths: Dictionary of server_name -> fixture_path
            expected_min_entries: Optional minimum expected entries per fixture

        Returns:
            Dictionary of server_name -> parsed_entries

        """
        results = {}
        for server_name, fixture_path in fixture_paths.items():
            result = api.parse(
                Path(fixture_path) if isinstance(fixture_path, str) else fixture_path
            )
            assert result.is_success, (
                f"{server_name} parse failed: {result.error if hasattr(result, 'error') else 'unknown'}"
            )
            unwrapped = result.unwrap()
            # unwrapped is already list[Entry] from parse, access directly
            entries = (
                unwrapped
                if isinstance(unwrapped, list)
                else getattr(unwrapped, "entries", [])
            )
            assert isinstance(entries, list), f"{server_name} should return list"
            if expected_min_entries is not None:
                assert len(entries) >= expected_min_entries, (
                    f"{server_name} should have at least {expected_min_entries} entries"
                )
            for entry in entries:
                assert entry.dn is not None, f"{server_name} entry missing DN"
                assert entry.attributes is not None, (
                    f"{server_name} entry missing attributes"
                )
            results[server_name] = entries
        return results

    @staticmethod
    def test_entry_create_and_unwrap(
        dn: str,
        attributes: dict[str, list[str]],
        *,
        expected_dn: str | None = None,
    ) -> FlextLdifModels.Entry:
        """Create entry and unwrap - replaces 5-8 lines.

        Args:
            dn: Distinguished name
            attributes: Dictionary of attribute names to values
            expected_dn: Optional expected DN (if different from input)

        Returns:
            Created Entry

        """
        # Convert dict[str, list[str]] to dict[str, str | list[str]] for Entry.create
        attributes_typed: dict[str, str | list[str]] = dict(attributes.items())
        result = FlextLdifModels.Entry.create(dn=dn, attributes=attributes_typed)
        entry = cast("FlextLdifModels.Entry", TestAssertions.assert_success(result))
        if expected_dn:
            assert entry.dn is not None
            assert entry.dn.value == expected_dn
        return entry

    @staticmethod
    def test_result_success_and_unwrap(
        result: FlextResult[T],
        *,
        expected_type: type[T] | None = None,
        expected_count: int | None = None,
    ) -> T:
        """Assert success and unwrap - replaces 3-5 lines.

        Args:
            result: FlextResult object
            expected_type: Optional expected type
            expected_count: Optional expected count (for lists)

        Returns:
            Unwrapped result

        """
        assert result.is_success, (
            f"Operation failed: {result.error if hasattr(result, 'error') else 'unknown'}"
        )
        unwrapped = result.unwrap()
        if expected_type:
            assert isinstance(unwrapped, expected_type)
        if expected_count is not None and isinstance(unwrapped, list):
            assert len(unwrapped) == expected_count
        return unwrapped

    @staticmethod
    def test_result_failure_and_assert_error(
        result: object,
        *,
        error_should_contain: str | None = None,
    ) -> None:
        """Assert failure and validate error - replaces 3-5 lines.

        Args:
            result: FlextResult object
            error_should_contain: Optional string that should be in error message

        """
        result_typed = cast("FlextResult[object]", result)
        assert result_typed.is_failure, "Expected operation to fail"
        if (
            hasattr(result_typed, "error")
            and result_typed.error
            and error_should_contain
        ):
            assert error_should_contain in str(result_typed.error), (
                f"Error should contain '{error_should_contain}': {result_typed.error}"
            )

    @staticmethod
    def test_model_create_and_unwrap(
        model_class: type,
        *args: object,
        **kwargs: object,
    ) -> object:
        """Generic model.create() and unwrap - replaces 3-5 lines.

        Works with any model that has .create() and returns FlextResult.

        Args:
            model_class: Model class with .create() method
            *args: Positional arguments for .create()
            **kwargs: Keyword arguments for .create()

        Returns:
            Unwrapped model instance

        """
        result = model_class.create(*args, **kwargs)
        return TestAssertions.assert_success(result)

    @staticmethod
    def test_quirk_execute_and_assert(
        quirk: QuirkInstance,
        *,
        data: str | list[FlextLdifModels.Entry] | None = None,
        operation: str = "parse",
        expected_type: type | None = None,
        expected_count: int | None = None,
        must_contain: list[str] | None = None,
        should_succeed: bool = True,
    ) -> object:
        """Quirk execute with automatic validation - replaces 8-15 lines.

        Args:
            quirk: Quirk instance with execute() method
            data: Optional data to pass to execute
            operation: Operation name (default: "parse")
            expected_type: Optional expected type of result
            expected_count: Optional expected count (for lists)
            must_contain: Optional list of strings that must appear (for strings)
            should_succeed: Whether operation should succeed

        Returns:
            Unwrapped result or None if should fail

        """
        operation_typed: Literal["parse", "write"] | None = (
            cast("Literal['parse', 'write']", operation)
            if operation in {"parse", "write"}
            else None
        )
        # Handle data type based on quirk type
        if isinstance(quirk, FlextLdifServersRfc.Entry):
            # Entry quirk accepts str | list[Entry] | None
            entry_data: str | list[FlextLdifModels.Entry] | None = (
                data if isinstance(data, (str, list)) or data is None else None
            )
            result = quirk.execute(data=entry_data, operation=operation_typed)
        elif isinstance(quirk, FlextLdifServersRfc.Schema):
            # Schema quirk accepts str | SchemaAttribute | SchemaObjectClass | None
            # Only pass if it's a string or None (not list[Entry])
            if isinstance(data, str) or data is None:
                schema_data: (
                    str
                    | FlextLdifModels.SchemaAttribute
                    | FlextLdifModels.SchemaObjectClass
                    | None
                ) = data
                result = quirk.execute(data=schema_data, operation=operation_typed)
            else:
                # list[Entry] is not valid for Schema.execute, return failure
                msg = "Schema quirk does not accept list[Entry]"
                result = FlextResult.fail(msg)
        elif isinstance(quirk, FlextLdifServersRfc.Acl):
            # Acl quirk accepts str | Acl | None
            # Only pass if it's a string or None (not list[Entry])
            if isinstance(data, str) or data is None:
                acl_data: str | FlextLdifModels.Acl | None = data
                result = quirk.execute(data=acl_data, operation=operation_typed)
            else:
                # list[Entry] is not valid for Acl.execute, return failure
                msg = "Acl quirk does not accept list[Entry]"
                result = FlextResult.fail(msg)
        else:
            # Fallback: try with data as-is
            result = quirk.execute(data=data, operation=operation_typed)
        if should_succeed:
            unwrapped = TestAssertions.assert_success(result)
            if expected_type:
                assert isinstance(unwrapped, expected_type)
            if expected_count is not None and isinstance(unwrapped, list):
                assert len(unwrapped) == expected_count
            if must_contain and isinstance(unwrapped, str):
                for content in must_contain:
                    assert content in unwrapped, f"Must contain '{content}'"
            return unwrapped
        _ = TestAssertions.assert_failure(result)
        return None

    @staticmethod
    def test_parse_and_validate_entries_batch(
        parser: FlextLdifParser,
        ldif_contents: list[str],
        *,
        server_type: str = "rfc",
        expected_counts: list[int] | None = None,
    ) -> list[list[FlextLdifModels.Entry]]:
        """Parse multiple LDIF contents and validate - replaces 20-40 lines.

        Args:
            parser: Parser instance with parse() method
            ldif_contents: List of LDIF content strings
            server_type: Server type (default: "rfc")
            expected_counts: Optional list of expected entry counts per LDIF

        Returns:
            List of entry lists (one per LDIF content)

        """
        results = []
        for i, ldif_content in enumerate(ldif_contents):
            parse_kwargs: dict[str, Any] = {
                "content": ldif_content,
                "input_source": "string",
                "server_type": server_type,
            }
            result = parser.parse(**parse_kwargs)
            parse_response_untyped = TestAssertions.assert_success(result)
            if hasattr(parse_response_untyped, "entries"):
                parse_response = cast("HasEntries", parse_response_untyped)
                entries = parse_response.entries
            elif isinstance(parse_response_untyped, list):
                entries = cast("list[FlextLdifModels.Entry]", parse_response_untyped)
            else:
                msg = "Parse returned unexpected type"
                raise AssertionError(msg)
            # entries is already list[Entry], don't access .entries again
            assert isinstance(entries, list)
            if expected_counts and i < len(expected_counts):
                assert len(entries) == expected_counts[i], (
                    f"LDIF {i} should have {expected_counts[i]} entries, got {len(entries)}"
                )
            results.append(entries)
        return results

    @staticmethod
    def test_write_and_validate_entries_batch(
        writer: FlextLdifWriter,
        entries_lists: list[list[FlextLdifModels.Entry]],
        *,
        server_type: str = "rfc",
        must_contain_per_entry: list[list[str]] | None = None,
    ) -> list[str]:
        """Write multiple entry lists and validate - replaces 25-50 lines.

        Args:
            writer: Writer instance with write() method
            entries_lists: List of entry lists to write
            server_type: Server type (default: "rfc")
            must_contain_per_entry: Optional list of must_contain lists (one per entry list)

        Returns:
            List of written LDIF strings

        """
        results = []
        for i, entries in enumerate(entries_lists):
            write_kwargs: dict[str, Any] = {
                "entries": entries,
                "target_server_type": server_type,
                "output_target": "string",
            }
            result = writer.write(**write_kwargs)
            written_untyped = TestAssertions.assert_success(result)
            written = cast("str", written_untyped)
            assert isinstance(written, str)
            if must_contain_per_entry and i < len(must_contain_per_entry):
                for content in must_contain_per_entry[i]:
                    assert content in written, (
                        f"Entry list {i} output must contain '{content}'"
                    )
            results.append(written)
        return results

    @staticmethod
    def test_quirk_parse_and_assert_batch(
        quirk: QuirkInstance,
        ldif_contents: list[str],
        *,
        expected_counts: list[int] | None = None,
        must_contain_per_ldif: list[list[str]] | None = None,
    ) -> list[object]:
        """Quirk parse multiple LDIF contents - replaces 15-30 lines per LDIF.

        Args:
            quirk: Quirk instance with execute() method
            ldif_contents: List of LDIF content strings
            expected_counts: Optional list of expected entry counts
            must_contain_per_ldif: Optional list of must_contain lists

        Returns:
            List of unwrapped results

        """
        results = []
        for i, ldif_content in enumerate(ldif_contents):
            result = quirk.execute(data=ldif_content, operation="parse")
            unwrapped_untyped = TestAssertions.assert_success(result)
            unwrapped = cast("list[FlextLdifModels.Entry]", unwrapped_untyped)
            if expected_counts and i < len(expected_counts):
                assert len(unwrapped) == expected_counts[i]
            if (
                must_contain_per_ldif
                and i < len(must_contain_per_ldif)
                and isinstance(unwrapped, str)
            ):
                for content in must_contain_per_ldif[i]:
                    assert content in unwrapped
            results.append(unwrapped)
        return results

    @staticmethod
    def test_quirk_write_and_assert_batch(
        quirk: QuirkInstance,
        entries_lists: list[list[FlextLdifModels.Entry]],
        *,
        must_contain_per_entry_list: list[list[str]] | None = None,
    ) -> list[str]:
        """Quirk write multiple entry lists - replaces 12-25 lines per list.

        Args:
            quirk: Quirk instance with execute() method
            entries_lists: List of entry lists to write
            must_contain_per_entry_list: Optional list of must_contain lists

        Returns:
            List of written LDIF strings

        """
        results = []
        for i, entries in enumerate(entries_lists):
            # Entry quirk accepts list[Entry] for write operation
            if isinstance(quirk, FlextLdifServersRfc.Entry):
                result = quirk.execute(data=entries, operation="write")
            else:
                # For Schema and Acl quirks, this shouldn't happen, but handle gracefully
                msg = f"Quirk {type(quirk)} does not support list[Entry] for write"
                raise TypeError(msg)
            written_untyped = TestAssertions.assert_success(result)
            written = cast("str", written_untyped)
            assert isinstance(written, str)
            if must_contain_per_entry_list and i < len(must_contain_per_entry_list):
                for content in must_contain_per_entry_list[i]:
                    assert content in written, (
                        f"Entry list {i} must contain '{content}'"
                    )
            results.append(written)
        return results

    @staticmethod
    def test_schema_parse_and_assert_batch(
        schema_quirk: FlextLdifServersRfc.Schema,
        definitions: list[str],
        *,
        definition_type: str = "attribute",
        expected_oids: list[str] | None = None,
        expected_names: list[str] | None = None,
    ) -> list[object]:
        """Schema parse multiple definitions - replaces 10-20 lines per definition.

        Args:
            schema_quirk: Schema quirk instance
            definitions: List of schema definition strings
            definition_type: "attribute" or "objectclass"
            expected_oids: Optional list of expected OIDs
            expected_names: Optional list of expected names

        Returns:
            List of parsed schema models

        """
        results = []
        # Use public parse method instead of protected methods
        for i, definition in enumerate(definitions):
            result = schema_quirk.parse(definition)
            parsed_untyped = TestAssertions.assert_success(result)
            parsed = cast(
                "FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass",
                parsed_untyped,
            )
            if expected_oids and i < len(expected_oids):
                assert parsed.oid == expected_oids[i]
            if expected_names and i < len(expected_names):
                assert parsed.name == expected_names[i]
            results.append(parsed)
        return results

    @staticmethod
    def test_quirk_parse_and_unwrap(
        quirk: QuirkInstance,
        data: str,
        *,
        operation: str = "parse",
        expected_type: type | None = None,
        expected_count: int | None = None,
    ) -> object:
        """Quirk parse and unwrap - replaces 3-5 lines.

        Args:
            quirk: Quirk instance with execute() method
            data: Data to parse
            operation: Operation name (default: "parse")
            expected_type: Optional expected type
            expected_count: Optional expected count (for lists)

        Returns:
            Unwrapped result

        """
        operation_typed: Literal["parse", "write"] | None = (
            cast("Literal['parse', 'write']", operation)
            if operation in {"parse", "write"}
            else None
        )
        result = quirk.execute(data=data, operation=operation_typed)
        return RfcTestHelpers.test_result_success_and_unwrap(
            cast("FlextResult[object]", result),
            expected_type=expected_type,
            expected_count=expected_count,
        )

    @staticmethod
    def test_quirk_write_and_unwrap(
        quirk: QuirkInstance,
        data: list[FlextLdifModels.Entry],
        *,
        operation: str = "write",
        must_contain: list[str] | None = None,
    ) -> str:
        """Quirk write and unwrap - replaces 3-5 lines.

        Args:
            quirk: Quirk instance with execute() method
            data: Data to write
            operation: Operation name (default: "write")
            must_contain: Optional list of strings that must appear

        Returns:
            Written LDIF string

        """
        operation_typed: Literal["parse", "write"] | None = (
            cast("Literal['parse', 'write']", operation)
            if operation in {"parse", "write"}
            else None
        )
        # Entry quirk accepts list[Entry] for write operation
        if isinstance(quirk, FlextLdifServersRfc.Entry):
            data_typed: str | list[FlextLdifModels.Entry] | None = data
            result = quirk.execute(data=data_typed, operation=operation_typed)
        else:
            # For other quirks, data should be str or model, not list[Entry]
            msg = f"Quirk {type(quirk)} does not support list[Entry] for write"
            raise TypeError(msg)
        # result is FlextResult[str] from Entry.execute(write)
        result_typed = cast("FlextResult[str]", result)
        written_untyped = RfcTestHelpers.test_result_success_and_unwrap(
            result_typed, expected_type=str
        )
        # written_untyped is already str from unwrap() with expected_type=str
        written: str = written_untyped
        if must_contain:
            for content in must_contain:
                assert content in written, f"Must contain '{content}'"
        return written

    @staticmethod
    def test_quirk_schema_parse_and_assert_properties(
        quirk: QuirkInstance,
        definition: str,
        *,
        expected_oid: str | None = None,
        expected_name: str | None = None,
        expected_desc: str | None = None,
        expected_syntax: str | None = None,
        expected_kind: str | None = None,
        expected_sup: str | None = None,
        expected_single_value: bool | None = None,
        expected_length: int | None = None,
        expected_equality: str | None = None,
        expected_ordering: str | None = None,
        expected_substr: str | None = None,
        expected_must: list[str] | None = None,
        expected_may: list[str] | None = None,
    ) -> object:
        """Parse schema definition and assert multiple properties - replaces 10-20 lines.

        Args:
            quirk: Schema quirk instance
            definition: Schema definition string
            expected_oid: Expected OID
            expected_name: Expected name
            expected_desc: Expected description
            expected_syntax: Expected syntax
            expected_kind: Expected kind (for objectClass)
            expected_sup: Expected superior
            expected_single_value: Expected single_value flag
            expected_length: Expected length
            expected_equality: Expected equality matching rule
            expected_ordering: Expected ordering matching rule
            expected_substr: Expected substring matching rule
            expected_must: Expected must attributes (for objectClass)
            expected_may: Expected may attributes (for objectClass)

        Returns:
            Parsed schema model

        """
        data_untyped = RfcTestHelpers.test_quirk_parse_and_unwrap(quirk, definition)
        data = cast(
            "FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass",
            data_untyped,
        )
        if expected_oid:
            assert data.oid == expected_oid
        if expected_name:
            assert data.name == expected_name
        if expected_desc:
            # data is already SchemaAttribute | SchemaObjectClass from type annotation
            assert data.desc == expected_desc
        if expected_syntax and isinstance(data, FlextLdifModels.SchemaAttribute):
            # Only SchemaAttribute has syntax attribute
            assert data.syntax == expected_syntax
        if expected_kind and isinstance(data, FlextLdifModels.SchemaObjectClass):
            # Only SchemaObjectClass has kind attribute
            assert data.kind == expected_kind
        if expected_sup:
            if hasattr(data, "sup") and isinstance(
                data, FlextLdifModels.SchemaAttribute
            ):
                assert data.sup == expected_sup
            elif hasattr(data, "sup"):
                # data is SchemaObjectClass at this point
                sup_value = data.sup
                if isinstance(sup_value, str):
                    assert sup_value == expected_sup
                elif isinstance(sup_value, list):
                    assert expected_sup in sup_value
        if expected_single_value is not None and isinstance(
            data, FlextLdifModels.SchemaAttribute
        ):
            assert data.single_value == expected_single_value
        if expected_length and isinstance(data, FlextLdifModels.SchemaAttribute):
            assert data.length == expected_length
        if expected_equality and isinstance(data, FlextLdifModels.SchemaAttribute):
            assert data.equality == expected_equality
        if expected_ordering and isinstance(data, FlextLdifModels.SchemaAttribute):
            assert data.ordering == expected_ordering
        if expected_substr and isinstance(data, FlextLdifModels.SchemaAttribute):
            assert data.substr == expected_substr
        if expected_must and isinstance(data, FlextLdifModels.SchemaObjectClass):
            must_attrs = data.must
            assert isinstance(must_attrs, list)
            for attr in expected_must:
                assert attr in must_attrs
        if expected_may and isinstance(data, FlextLdifModels.SchemaObjectClass):
            may_attrs = data.may
            assert isinstance(may_attrs, list)
            for attr in expected_may:
                assert attr in may_attrs
        return data

    @staticmethod
    def test_server_quirk_parse_and_unwrap(
        server_class: type,
        definition: str,
        *,
        quirk_type: str = "schema_quirk",
        operation: str = "parse",
    ) -> object:
        """Create server, get quirk, parse and unwrap - replaces 5-8 lines.

        Args:
            server_class: Server class (e.g., FlextLdifServersTivoli)
            definition: Definition to parse
            quirk_type: Type of quirk ("schema_quirk", "acl_quirk", "entry_quirk")
            operation: Operation name (default: "parse")

        Returns:
            Unwrapped result

        """
        server = server_class()
        quirk = getattr(server, quirk_type)
        return RfcTestHelpers.test_quirk_parse_and_unwrap(
            quirk, definition, operation=operation
        )

    @staticmethod
    def test_schema_quirk_parse_and_assert(
        quirk: object,
        definition: str,
        *,
        expected_oid: str | None = None,
        expected_name: str | None = None,
        expected_desc: str | None = None,
        expected_syntax: str | None = None,
        expected_kind: str | None = None,
        expected_sup: str | None = None,
        expected_single_value: bool | None = None,
        expected_equality: str | None = None,
        expected_must: list[str] | None = None,
        expected_may: list[str] | None = None,
    ) -> object:
        """Parse schema definition with quirk.parse() and assert properties - replaces 8-15 lines.

        Args:
            quirk: Schema quirk instance
            definition: Schema definition string
            expected_oid: Expected OID
            expected_name: Expected name
            expected_desc: Expected description
            expected_syntax: Expected syntax
            expected_kind: Expected kind (for objectClass)
            expected_sup: Expected superior
            expected_single_value: Expected single_value flag
            expected_equality: Expected equality matching rule
            expected_must: Expected must attributes (for objectClass)
            expected_may: Expected may attributes (for objectClass)

        Returns:
            Parsed schema model

        """
        return RfcTestHelpers.test_quirk_schema_parse_and_assert_properties(
            cast("QuirkInstance", quirk),
            definition,
            expected_oid=expected_oid,
            expected_name=expected_name,
            expected_desc=expected_desc,
            expected_syntax=expected_syntax,
            expected_kind=expected_kind,
            expected_sup=expected_sup,
            expected_single_value=expected_single_value,
            expected_equality=expected_equality,
            expected_must=expected_must,
            expected_may=expected_may,
        )

    @staticmethod
    def test_quirk_parse_success_and_unwrap(
        quirk: QuirkInstance,
        definition: str,
        *,
        operation: str = "parse",
    ) -> object:
        """Parse with quirk and unwrap - replaces 3-4 lines (simpler than test_quirk_parse_and_unwrap).

        Args:
            quirk: Quirk instance
            definition: Definition to parse
            operation: Operation name (default: "parse")

        Returns:
            Unwrapped result

        """
        if hasattr(quirk, operation):
            method = getattr(quirk, operation)
            result = method(definition)
        else:
            operation_typed: Literal["parse", "write"] | None = (
                cast("Literal['parse', 'write']", operation)
                if operation in {"parse", "write"}
                else None
            )
            result = quirk.execute(data=definition, operation=operation_typed)
        # result could be various types depending on quirk, cast to object to satisfy type checker
        result_typed = cast("FlextResult[object]", result)
        return RfcTestHelpers.test_result_success_and_unwrap(result_typed)

    @staticmethod
    def test_parse_result_success_and_unwrap(
        parse_result: FlextResult[object],
        *,
        error_msg: str | None = None,
    ) -> object:
        """Parse result success and unwrap - replaces TestDeduplicationHelpers.assert_success_and_unwrap.

        Args:
            parse_result: Parse result from quirk.parse() or similar
            error_msg: Optional error message for assertion

        Returns:
            Unwrapped result

        """
        return RfcTestHelpers.test_result_success_and_unwrap(parse_result)

    @staticmethod
    def test_quirk_parse_with_can_handle_check(
        quirk: QuirkInstance,
        definition: str,
        *,
        expected_can_handle: bool | None = None,
        can_handle_method: str = "can_handle_attribute",
    ) -> object:
        """Parse and optionally check can_handle - replaces 5-8 lines.

        Args:
            quirk: Quirk instance
            definition: Definition to parse
            expected_can_handle: Optional expected can_handle result
            can_handle_method: Method name for can_handle check

        Returns:
            Unwrapped parsed result

        """
        data = RfcTestHelpers.test_quirk_parse_success_and_unwrap(quirk, definition)
        if expected_can_handle is not None:
            can_handle = getattr(quirk, can_handle_method)
            assert can_handle(definition) == expected_can_handle
        return data

    @staticmethod
    def test_create_schema_attribute_from_dict(
        attr_dict: dict[str, object],
        *,
        default_oid: str = "1.2.3.4",
        default_name: str = "testAttr",
    ) -> FlextLdifModels.SchemaAttribute:
        """Create SchemaAttribute from dict with defaults - replaces 10-15 lines.

        Args:
            attr_dict: Dictionary with attribute properties
            default_oid: Default OID if not in dict
            default_name: Default name if not in dict

        Returns:
            SchemaAttribute instance

        """
        from flext_ldif.models import FlextLdifModels

        return FlextLdifModels.SchemaAttribute(
            oid=cast("str", attr_dict.get("oid", default_oid)),
            name=cast("str", attr_dict.get("name", default_name)),
            desc=cast("str | None", attr_dict.get("desc")),
            sup=cast("str | None", attr_dict.get("sup")),
            equality=cast("str | None", attr_dict.get("equality")),
            ordering=cast("str | None", attr_dict.get("ordering")),
            substr=cast("str | None", attr_dict.get("substr")),
            syntax=cast("str | None", attr_dict.get("syntax")),
            length=cast("int | None", attr_dict.get("length")),
            single_value=cast("bool", attr_dict.get("single_value", False)),
            usage=cast("str | None", attr_dict.get("usage")),
            x_origin=cast("str | None", attr_dict.get("x_origin")),
            x_file_ref=cast("str | None", attr_dict.get("x_file_ref")),
            x_name=cast("str | None", attr_dict.get("x_name")),
            x_alias=cast("str | None", attr_dict.get("x_alias")),
            x_oid=cast("str | None", attr_dict.get("x_oid")),
        )

    @staticmethod
    def test_create_schema_objectclass_from_dict(
        oc_dict: dict[str, object],
        *,
        default_oid: str = "1.2.3.4",
        default_name: str = "testClass",
    ) -> FlextLdifModels.SchemaObjectClass:
        """Create SchemaObjectClass from dict with defaults - replaces 10-15 lines.

        Args:
            oc_dict: Dictionary with objectClass properties
            default_oid: Default OID if not in dict
            default_name: Default name if not in dict

        Returns:
            SchemaObjectClass instance

        """
        from flext_ldif.models import FlextLdifModels

        return FlextLdifModels.SchemaObjectClass(
            oid=cast("str", oc_dict.get("oid", default_oid)),
            name=cast("str", oc_dict.get("name", default_name)),
            desc=cast("str | None", oc_dict.get("desc")),
            sup=cast("str | list[str] | None", oc_dict.get("sup")),
            kind=cast("str", oc_dict.get("kind", "STRUCTURAL")),
            must=cast("list[str] | None", oc_dict.get("must", [])),
            may=cast("list[str] | None", oc_dict.get("may", [])),
        )

    @staticmethod
    def test_quirk_write_model_and_assert_contains(
        quirk: QuirkInstance,
        model: list[FlextLdifModels.Entry],
        *,
        must_contain: list[str],
        operation: str = "write",
    ) -> str:
        """Write model with quirk and assert contains - replaces 5-8 lines.

        Args:
            quirk: Quirk instance
            model: Model to write
            must_contain: List of strings that must appear in output
            operation: Operation name (default: "write")

        Returns:
            Written string

        """
        # model is already list[Entry] from type annotation
        return RfcTestHelpers.test_quirk_write_and_unwrap(
            quirk,
            model,
            operation=operation,
            must_contain=must_contain,
        )

    @staticmethod
    def test_create_schema_attribute_minimal(
        *,
        oid: str | None = None,
        name: str | None = None,
        desc: str | None = None,
        syntax: str | None = None,
        single_value: bool = False,
    ) -> FlextLdifModels.SchemaAttribute:
        """Create minimal SchemaAttribute using constants - replaces 10-15 lines.

        Args:
            oid: OID (defaults to TestsRfcConstants.ATTR_OID_CN)
            name: Name (defaults to TestsRfcConstants.ATTR_NAME_CN)
            desc: Description
            syntax: Syntax
            single_value: Single value flag

        Returns:
            SchemaAttribute instance

        """
        from flext_ldif.models import FlextLdifModels
        from tests.unit.quirks.servers.fixtures.rfc_constants import TestsRfcConstants

        return FlextLdifModels.SchemaAttribute(
            oid=oid or TestsRfcConstants.ATTR_OID_CN,
            name=name or TestsRfcConstants.ATTR_NAME_CN,
            desc=desc,
            sup=None,
            equality=None,
            ordering=None,
            substr=None,
            syntax=syntax,
            length=None,
            single_value=single_value,
            usage=None,
            x_origin=None,
            x_file_ref=None,
            x_name=None,
            x_alias=None,
            x_oid=None,
        )

    @staticmethod
    def test_create_schema_objectclass_minimal(
        *,
        oid: str | None = None,
        name: str | None = None,
        desc: str | None = None,
        sup: str | None = None,
        kind: str = "STRUCTURAL",
    ) -> FlextLdifModels.SchemaObjectClass:
        """Create minimal SchemaObjectClass using constants - replaces 10-15 lines.

        Args:
            oid: OID (defaults to TestsRfcConstants.OC_OID_PERSON)
            name: Name (defaults to TestsRfcConstants.OC_NAME_PERSON)
            desc: Description
            sup: Superior
            kind: Kind (default: STRUCTURAL)

        Returns:
            SchemaObjectClass instance

        """
        from flext_ldif.models import FlextLdifModels
        from tests.unit.quirks.servers.fixtures.rfc_constants import TestsRfcConstants

        return FlextLdifModels.SchemaObjectClass(
            oid=oid or TestsRfcConstants.OC_OID_PERSON,
            name=name or TestsRfcConstants.OC_NAME_PERSON,
            desc=desc,
            sup=sup,
            kind=kind,
            must=[],
            may=[],
        )

    @staticmethod
    def test_create_entry_and_unwrap(
        *,
        dn: str | None = None,
        attributes: dict[str, list[str]] | None = None,
        **kwargs: object,
    ) -> FlextLdifModels.Entry:
        """Create Entry and unwrap result - replaces 2-3 lines.

        Args:
            dn: Distinguished name (defaults to TestGeneralConstants.SAMPLE_DN)
            attributes: Entry attributes (defaults to minimal person entry)
            **kwargs: Additional Entry.create() parameters

        Returns:
            Entry instance (unwrapped)

        """
        from flext_ldif.models import FlextLdifModels
        from tests.unit.quirks.servers.fixtures.general_constants import (
            TestGeneralConstants,
        )

        if dn is None:
            dn = TestGeneralConstants.SAMPLE_DN
        if attributes is None:
            attributes = {
                "objectClass": [TestGeneralConstants.OC_NAME_PERSON],
            }

        # Cast attributes to match Entry.create signature
        attributes_typed: dict[str, str | list[str]] = cast(
            "dict[str, str | list[str]]", attributes
        )
        # Extract and cast kwargs to appropriate types for Entry.create
        # QuirkMetadata and EntryStatistics are available via FlextLdifModels
        metadata = (
            cast("FlextLdifModels.QuirkMetadata | None", kwargs.get("metadata"))
            if "metadata" in kwargs
            else None
        )
        # Cast to match Entry.create's expected types (which use internal domain types)
        # Note: FlextLdifModels types are aliases of internal domain types, but type checker sees them as different
        # We use cast through Any to bridge this gap
        acls_raw = kwargs.get("acls") if "acls" in kwargs else None
        acls = (
            cast("list[FlextLdifModels.Acl] | None", cast("Any", acls_raw))
            if acls_raw is not None
            else None
        )
        objectclasses_raw = (
            kwargs.get("objectclasses") if "objectclasses" in kwargs else None
        )
        objectclasses = (
            cast(
                "list[FlextLdifModels.SchemaObjectClass] | None",
                cast("Any", objectclasses_raw),
            )
            if objectclasses_raw is not None
            else None
        )
        attributes_schema_raw = (
            kwargs.get("attributes_schema") if "attributes_schema" in kwargs else None
        )
        attributes_schema = (
            cast(
                "list[FlextLdifModels.SchemaAttribute] | None",
                cast("Any", attributes_schema_raw),
            )
            if attributes_schema_raw is not None
            else None
        )
        entry_metadata = (
            cast("dict[str, object] | None", kwargs.get("entry_metadata"))
            if "entry_metadata" in kwargs
            else None
        )
        validation_metadata = (
            cast("dict[str, object] | None", kwargs.get("validation_metadata"))
            if "validation_metadata" in kwargs
            else None
        )
        server_type_kwarg = (
            cast("str | None", kwargs.get("server_type"))
            if "server_type" in kwargs
            else None
        )
        source_entry = (
            cast("str | None", kwargs.get("source_entry"))
            if "source_entry" in kwargs
            else None
        )
        unconverted_attributes = (
            cast("dict[str, object] | None", kwargs.get("unconverted_attributes"))
            if "unconverted_attributes" in kwargs
            else None
        )
        statistics = (
            cast("FlextLdifModels.EntryStatistics | None", kwargs.get("statistics"))
            if "statistics" in kwargs
            else None
        )

        # Entry.create expects domain types, but we have FlextLdifModels types (which are aliases)
        # Cast through Any to bridge the type system gap
        result = FlextLdifModels.Entry.create(
            dn=dn,
            attributes=attributes_typed,
            metadata=metadata,
            acls=cast("Any", acls),
            objectclasses=cast("Any", objectclasses),
            attributes_schema=cast("Any", attributes_schema),
            entry_metadata=entry_metadata,
            validation_metadata=validation_metadata,
            server_type=server_type_kwarg,
            source_entry=source_entry,
            unconverted_attributes=unconverted_attributes,
            statistics=statistics,
        )
        unwrapped = RfcTestHelpers.test_result_success_and_unwrap(result)
        return cast("FlextLdifModels.Entry", unwrapped)

    @staticmethod
    def test_create_schema_attribute_and_unwrap(
        *,
        oid: str | None = None,
        name: str | None = None,
        **kwargs: object,
    ) -> object:
        """Create SchemaAttribute and unwrap result - replaces 2-3 lines.

        Args:
            oid: OID (defaults to TestsRfcConstants.ATTR_OID_CN)
            name: Name (defaults to TestsRfcConstants.ATTR_NAME_CN)
            **kwargs: Additional SchemaAttribute.create() parameters

        Returns:
            SchemaAttribute instance (unwrapped)

        """
        from flext_ldif.models import FlextLdifModels
        from tests.unit.quirks.servers.fixtures.rfc_constants import TestsRfcConstants

        if oid is None:
            oid = TestsRfcConstants.ATTR_OID_CN
        if name is None:
            name = TestsRfcConstants.ATTR_NAME_CN

        # SchemaAttribute doesn't have create method, use constructor directly
        return FlextLdifModels.SchemaAttribute(
            oid=oid,
            name=name,
            desc=cast("str | None", kwargs.get("desc")),
            sup=cast("str | None", kwargs.get("sup")),
            equality=cast("str | None", kwargs.get("equality")),
            ordering=cast("str | None", kwargs.get("ordering")),
            substr=cast("str | None", kwargs.get("substr")),
            syntax=cast("str | None", kwargs.get("syntax")),
            length=cast("int | None", kwargs.get("length")),
            single_value=cast("bool", kwargs.get("single_value", False)),
            usage=cast("str | None", kwargs.get("usage")),
            x_origin=cast("str | None", kwargs.get("x_origin")),
            x_file_ref=cast("str | None", kwargs.get("x_file_ref")),
            x_name=cast("str | None", kwargs.get("x_name")),
            x_alias=cast("str | None", kwargs.get("x_alias")),
            x_oid=cast("str | None", kwargs.get("x_oid")),
        )

    @staticmethod
    def test_create_schema_objectclass_and_unwrap(
        *,
        oid: str | None = None,
        name: str | None = None,
        **kwargs: object,
    ) -> object:
        """Create SchemaObjectClass and unwrap result - replaces 2-3 lines.

        Args:
            oid: OID (defaults to TestsRfcConstants.OC_OID_PERSON)
            name: Name (defaults to TestsRfcConstants.OC_NAME_PERSON)
            **kwargs: Additional SchemaObjectClass.create() parameters

        Returns:
            SchemaObjectClass instance (unwrapped)

        """
        from flext_ldif.models import FlextLdifModels
        from tests.unit.quirks.servers.fixtures.rfc_constants import TestsRfcConstants

        if oid is None:
            oid = TestsRfcConstants.OC_OID_PERSON
        if name is None:
            name = TestsRfcConstants.OC_NAME_PERSON

        # SchemaObjectClass doesn't have create method, use constructor directly
        return FlextLdifModels.SchemaObjectClass(
            oid=oid,
            name=name,
            desc=cast("str | None", kwargs.get("desc")),
            sup=cast("str | list[str] | None", kwargs.get("sup")),
            kind=cast("str", kwargs.get("kind", "STRUCTURAL")),
            must=cast("list[str] | None", kwargs.get("must")),
            may=cast("list[str] | None", kwargs.get("may")),
            metadata=cast(
                "FlextLdifModels.QuirkMetadata | None", kwargs.get("metadata")
            ),
        )

    @staticmethod
    def test_api_parse_fixture_and_validate(
        api: HasParseMethod,
        fixture_path: Path | str,
        *,
        server_type: str | None = None,
        expected_min_count: int | None = None,
    ) -> list[FlextLdifModels.Entry]:
        """Parse fixture file using API and validate entries - replaces 10-15 lines.

        Args:
            api: FlextLdif API instance
            fixture_path: Path to fixture file (Path or str)
            server_type: Optional server type override
            expected_min_count: Optional minimum expected entry count

        Returns:
            List of parsed entries

        """
        path = Path(fixture_path) if isinstance(fixture_path, str) else fixture_path

        if server_type:
            result = api.parse(path, server_type=server_type)
        else:
            result = api.parse(path)

        unwrapped = TestAssertions.assert_success(
            result, "Fixture parse should succeed"
        )

        if isinstance(unwrapped, list):
            entries = cast("list[FlextLdifModels.Entry]", unwrapped)
        elif hasattr(unwrapped, "entries"):
            unwrapped_with_entries = cast("HasEntries", unwrapped)
            entries = unwrapped_with_entries.entries
        else:
            msg = "Parse returned unexpected type"
            raise AssertionError(msg)

        assert isinstance(entries, list), "Should return list of entries"
        if expected_min_count is not None:
            assert len(entries) >= expected_min_count, (
                f"Expected at least {expected_min_count} entries, got {len(entries)}"
            )

        TestAssertions.assert_entries_valid(entries)
        return entries


__all__ = ["RfcTestHelpers"]
