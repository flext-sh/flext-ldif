"""Test utility definitions extending src utilities for centralized test utilities.

This module provides test-specific utility extensions that inherit from
src/flext_ldif/utilities.py classes. This centralizes test utilities without
duplicating parent class functionality.

Also includes test helper methods that were moved from constants.py per FLEXT
architecture rules (constants.py should contain ONLY constants, no methods).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

from flext_tests.utilities import FlextTestsUtilities

from flext_ldif import FlextLdif
from flext_ldif.models import m
from flext_ldif.services.entries import FlextLdifEntries
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.schema import FlextLdifSchema
from flext_ldif.services.writer import FlextLdifWriter
from flext_ldif.utilities import FlextLdifUtilities


class TestsFlextLdifUtilities(FlextTestsUtilities, FlextLdifUtilities):
    """Test utilities extending FlextTestsUtilities and FlextLdifUtilities.

    Provides test-specific utility extensions without duplicating parent functionality.
    All parent utilities are accessible via inheritance hierarchy.

    Naming convention: Tests[FlextLdif] where FlextLdif is the project name.
    Short name 'u' for convenient access in tests (note: 'u' is also used for FlextLdifUtilities).
    """

    # Test-specific utility extensions can be added here
    # All parent utilities are accessible via inheritance

    # Aliases for frequently used nested utilities (tests use u.OID, not u.Ldif.OID)
    OID = FlextLdifUtilities.Ldif.OID


class RfcTestHelpers:
    """RFC test helper utilities for LDIF testing.

    Note: Moved from constants.py per FLEXT architecture rules
    (constants.py should contain ONLY constants, no methods).
    """

    @staticmethod
    def test_parse_ldif_content(
        parser_service: object,
        content: str,
        expected_count: int,
        server_type: str,
    ) -> list[object]:
        """Parse LDIF content and return entries.

        Args:
            parser_service: The parser service instance
            content: LDIF content to parse
            expected_count: Expected number of entries (for validation)
            server_type: Server type for parsing

        Returns:
            List of parsed entries

        """
        if not isinstance(parser_service, FlextLdifParser):
            raise TypeError(f"Expected FlextLdifParser, got {type(parser_service)}")

        result = parser_service.parse_string(
            content=content,
            server_type=server_type,
        )

        if result.is_failure:
            raise AssertionError(f"Parsing failed: {result.error}")

        entries = result.value.entries
        if len(entries) != expected_count:
            raise AssertionError(
                f"Expected {expected_count} entries, got {len(entries)}",
            )

        return list(entries)

    @staticmethod
    def test_entry_create_and_unwrap(
        dn: str,
        attributes: dict[str, object],
    ) -> object:
        """Create an entry and unwrap the result.

        Args:
            dn: Distinguished Name for the entry
            attributes: Dictionary of attributes for the entry

        Returns:
            The unwrapped Entry instance

        Raises:
            AssertionError: If entry creation fails

        """
        result = m.Ldif.Entry.create(dn=dn, attributes=attributes)
        if result.is_failure:
            raise AssertionError(f"Entry creation failed: {result.error}")

        return result.value

    @staticmethod
    def test_quirk_schema_parse_and_assert_properties(
        quirk: object,
        schema_def: str,
        *,
        expected_oid: str | None = None,
        expected_name: str | None = None,
        expected_desc: str | None = None,
        expected_syntax: str | None = None,
        expected_single_value: bool | None = None,
        expected_length: int | None = None,
        expected_kind: str | None = None,
        expected_sup: str | None = None,
        expected_must: list[str] | None = None,
        expected_may: list[str] | None = None,
    ) -> object:
        """Parse schema definition and assert properties.

        Args:
            quirk: Schema quirk instance
            schema_def: Schema definition string (attribute or objectClass)
            expected_oid: Expected OID
            expected_name: Expected NAME
            expected_desc: Expected DESC
            expected_syntax: Expected SYNTAX (without length)
            expected_single_value: Expected SINGLE-VALUE flag
            expected_length: Expected syntax length (e.g., 256 from {256})
            expected_kind: Expected KIND (STRUCTURAL, AUXILIARY, ABSTRACT)
            expected_sup: Expected SUP (superior class)
            expected_must: Expected MUST attributes
            expected_may: Expected MAY attributes

        Returns:
            The parsed schema object

        Raises:
            AssertionError: If parsing fails or properties don't match

        """
        # Determine parse method based on content
        if (
            "STRUCTURAL" in schema_def
            or "AUXILIARY" in schema_def
            or "ABSTRACT" in schema_def
        ):
            parse_method = getattr(quirk, "parse_objectclass", None)
        else:
            parse_method = getattr(quirk, "parse_attribute", None)

        if parse_method is None:
            parse_method = getattr(quirk, "parse", None)

        if parse_method is None:
            msg = "Quirk has no suitable parse method"
            raise AssertionError(msg)

        result = parse_method(schema_def)

        if hasattr(result, "is_failure") and result.is_failure:
            raise AssertionError(f"Parsing failed: {result.error}")

        value = result.value if hasattr(result, "value") else result

        # Assert expected properties
        if expected_oid is not None:
            actual_oid = getattr(value, "oid", None)
            if actual_oid != expected_oid:
                raise AssertionError(
                    f"Expected OID '{expected_oid}', got '{actual_oid}'",
                )

        if expected_name is not None:
            actual_name = getattr(value, "name", None)
            if actual_name != expected_name:
                raise AssertionError(
                    f"Expected NAME '{expected_name}', got '{actual_name}'",
                )

        if expected_desc is not None:
            actual_desc = getattr(value, "desc", None)
            if actual_desc != expected_desc:
                raise AssertionError(
                    f"Expected DESC '{expected_desc}', got '{actual_desc}'",
                )

        if expected_syntax is not None:
            actual_syntax = getattr(value, "syntax", None)
            if actual_syntax != expected_syntax:
                raise AssertionError(
                    f"Expected SYNTAX '{expected_syntax}', got '{actual_syntax}'",
                )

        if expected_single_value is not None:
            actual_sv = getattr(value, "single_value", None)
            if actual_sv != expected_single_value:
                raise AssertionError(
                    f"Expected SINGLE-VALUE {expected_single_value}, got {actual_sv}",
                )

        if expected_length is not None:
            actual_length = getattr(value, "length", None)
            if actual_length != expected_length:
                raise AssertionError(
                    f"Expected length {expected_length}, got {actual_length}",
                )

        if expected_kind is not None:
            actual_kind = getattr(value, "kind", None)
            if actual_kind != expected_kind:
                raise AssertionError(
                    f"Expected KIND '{expected_kind}', got '{actual_kind}'",
                )

        if expected_sup is not None:
            actual_sup = getattr(value, "sup", None)
            if actual_sup != expected_sup:
                raise AssertionError(
                    f"Expected SUP '{expected_sup}', got '{actual_sup}'",
                )

        if expected_must is not None:
            actual_must = getattr(value, "must", None) or []
            if list(actual_must) != expected_must:
                raise AssertionError(
                    f"Expected MUST {expected_must}, got {list(actual_must)}",
                )

        if expected_may is not None:
            actual_may = getattr(value, "may", None) or []
            if list(actual_may) != expected_may:
                raise AssertionError(
                    f"Expected MAY {expected_may}, got {list(actual_may)}",
                )

        return value

    @staticmethod
    def test_result_success_and_unwrap(
        result: object,
        expected_type: type | None = None,
        expected_count: int | None = None,
    ) -> object:
        """Assert result is successful and unwrap its value.

        Args:
            result: FlextResult instance to check
            expected_type: Optional expected type for the unwrapped value
            expected_count: Optional expected count if value is a sequence

        Returns:
            The unwrapped value from the result

        Raises:
            AssertionError: If result is failure or type mismatch

        """
        # Check result has is_failure attribute (duck typing for FlextResult)
        if not hasattr(result, "is_failure"):
            raise TypeError(f"Expected FlextResult-like object, got {type(result)}")

        if result.is_failure:
            error = getattr(result, "error", "Unknown error")
            raise AssertionError(f"Result is failure: {error}")

        value = result.value
        if expected_type is not None and not isinstance(value, expected_type):
            raise AssertionError(
                f"Expected {expected_type.__name__}, got {type(value).__name__}",
            )

        if expected_count is not None:
            if not hasattr(value, "__len__"):
                raise AssertionError(
                    f"Cannot check count on {type(value).__name__} - not a sequence",
                )
            if len(value) != expected_count:
                raise AssertionError(
                    f"Expected count {expected_count}, got {len(value)}",
                )

        return value

    @staticmethod
    def test_create_entry_and_unwrap(
        dn: str,
        attributes: dict[str, object] | None = None,
    ) -> object:
        """Create an entry and unwrap the result.

        Alias for test_entry_create_and_unwrap for naming consistency.

        Args:
            dn: Distinguished Name for the entry
            attributes: Dictionary of attributes for the entry

        Returns:
            The unwrapped Entry instance

        Raises:
            AssertionError: If entry creation fails

        """
        if attributes is None:
            attributes = {}
        result = m.Ldif.Entry.create(dn=dn, attributes=attributes)
        if result.is_failure:
            raise AssertionError(f"Entry creation failed: {result.error}")

        return result.value

    @staticmethod
    def test_create_schema_attribute_and_unwrap(
        oid: str,
        name: str,
        desc: str | None = None,
        syntax: str | None = None,
        *,
        single_value: bool = False,
    ) -> object:
        """Create a schema attribute and unwrap the result.

        Args:
            oid: Object Identifier
            name: Attribute name
            desc: Description
            syntax: Syntax OID
            single_value: Single value flag

        Returns:
            The unwrapped SchemaAttribute instance

        Raises:
            AssertionError: If creation fails

        """
        return m.Ldif.SchemaAttribute(
            oid=oid,
            name=name,
            desc=desc,
            syntax=syntax,
            single_value=single_value,
        )

    @staticmethod
    def test_create_schema_objectclass_and_unwrap(
        oid: str,
        name: str,
        desc: str | None = None,
        kind: str = "STRUCTURAL",
        sup: str | None = None,
        must: list[str] | None = None,
        may: list[str] | None = None,
    ) -> object:
        """Create a schema objectClass and unwrap the result.

        Args:
            oid: Object Identifier
            name: ObjectClass name
            desc: Description
            kind: Kind (STRUCTURAL, AUXILIARY, ABSTRACT)
            sup: Superior class
            must: Required attributes
            may: Optional attributes

        Returns:
            The unwrapped SchemaObjectClass instance

        Raises:
            AssertionError: If creation fails

        """
        return m.Ldif.SchemaObjectClass(
            oid=oid,
            name=name,
            desc=desc,
            kind=kind,
            sup=sup,
            must=must or [],
            may=may or [],
        )

    @staticmethod
    def test_quirk_parse_success_and_unwrap(
        quirk: object,
        content: str,
        parse_method: str | None = None,
    ) -> object:
        """Parse using quirk and assert success.

        Args:
            quirk: Schema quirk instance
            content: Content to parse
            parse_method: Optional specific parse method name

        Returns:
            The parsed value

        Raises:
            AssertionError: If parsing fails

        """
        if parse_method:
            method = getattr(quirk, parse_method, None)
            if method is None:
                raise AssertionError(f"Quirk has no method '{parse_method}'")
            result = method(content)
        else:
            result = quirk.parse(content)

        if hasattr(result, "is_failure") and result.is_failure:
            error = getattr(result, "error", "Unknown error")
            raise AssertionError(f"Parsing failed: {error}")

        return result.value if hasattr(result, "value") else result

    @staticmethod
    def test_schema_quirk_parse_and_assert(
        quirk: object,
        content: str,
        expected_oid: str | None = None,
        expected_name: str | None = None,
        expected_desc: str | None = None,
        expected_sup: str | None = None,
        expected_kind: str | None = None,
        expected_must: list[str] | None = None,
        expected_may: list[str] | None = None,
        expected_syntax: str | None = None,
        expected_equality: str | None = None,
        expected_single_value: bool | None = None,
    ) -> object:
        """Parse schema content and assert properties.

        Args:
            quirk: Schema quirk instance
            content: Schema definition content
            expected_oid: Expected OID
            expected_name: Expected name
            expected_desc: Expected description
            expected_sup: Expected superior
            expected_kind: Expected kind
            expected_must: Expected MUST attributes
            expected_may: Expected MAY attributes
            expected_syntax: Expected syntax
            expected_equality: Expected equality matching rule
            expected_single_value: Expected single value flag

        Returns:
            The parsed schema object

        Raises:
            AssertionError: If parsing fails or properties don't match

        """
        # Determine parse method based on content
        if "STRUCTURAL" in content or "AUXILIARY" in content or "ABSTRACT" in content:
            parse_method = getattr(quirk, "parse_objectclass", None)
        else:
            parse_method = getattr(quirk, "parse_attribute", None)

        if parse_method is None:
            parse_method = getattr(quirk, "parse", None)

        if parse_method is None:
            msg = "Quirk has no suitable parse method"
            raise AssertionError(msg)

        result = parse_method(content)

        if hasattr(result, "is_failure") and result.is_failure:
            raise AssertionError(f"Parsing failed: {result.error}")

        value = result.value if hasattr(result, "value") else result

        if expected_oid is not None:
            actual_oid = getattr(value, "oid", None)
            if actual_oid != expected_oid:
                raise AssertionError(
                    f"Expected OID '{expected_oid}', got '{actual_oid}'",
                )

        if expected_name is not None:
            actual_name = getattr(value, "name", None)
            if actual_name != expected_name:
                raise AssertionError(
                    f"Expected name '{expected_name}', got '{actual_name}'",
                )

        if expected_desc is not None:
            actual_desc = getattr(value, "desc", None)
            if actual_desc != expected_desc:
                raise AssertionError(
                    f"Expected desc '{expected_desc}', got '{actual_desc}'",
                )

        if expected_sup is not None:
            actual_sup = getattr(value, "sup", None)
            if actual_sup != expected_sup:
                raise AssertionError(
                    f"Expected sup '{expected_sup}', got '{actual_sup}'",
                )

        if expected_kind is not None:
            actual_kind = getattr(value, "kind", None)
            if actual_kind != expected_kind:
                raise AssertionError(
                    f"Expected kind '{expected_kind}', got '{actual_kind}'",
                )

        if expected_must is not None:
            actual_must = getattr(value, "must", None)
            if actual_must != expected_must:
                raise AssertionError(
                    f"Expected must '{expected_must}', got '{actual_must}'",
                )

        if expected_may is not None:
            actual_may = getattr(value, "may", None)
            if actual_may != expected_may:
                raise AssertionError(
                    f"Expected may '{expected_may}', got '{actual_may}'",
                )

        if expected_syntax is not None:
            actual_syntax = getattr(value, "syntax", None)
            if actual_syntax != expected_syntax:
                raise AssertionError(
                    f"Expected syntax '{expected_syntax}', got '{actual_syntax}'",
                )

        if expected_equality is not None:
            actual_equality = getattr(value, "equality", None)
            if actual_equality != expected_equality:
                raise AssertionError(
                    f"Expected equality '{expected_equality}', got '{actual_equality}'",
                )

        if expected_single_value is not None:
            actual_single_value = getattr(value, "single_value", None)
            if actual_single_value != expected_single_value:
                raise AssertionError(
                    f"Expected single_value '{expected_single_value}', "
                    f"got '{actual_single_value}'",
                )

        return value

    @staticmethod
    def test_create_schema_attribute_from_dict(
        data: dict[str, object],
    ) -> object:
        """Create a schema attribute from dictionary.

        Args:
            data: Dictionary with attribute properties

        Returns:
            The SchemaAttribute instance

        """
        return m.Ldif.SchemaAttribute(
            oid=str(data.get("oid", "")),
            name=str(data.get("name", "")),
            desc=data.get("desc"),
            syntax=data.get("syntax"),
            single_value=bool(data.get("single_value")),
        )

    @staticmethod
    def test_create_schema_objectclass_from_dict(
        data: dict[str, object],
    ) -> object:
        """Create a schema objectClass from dictionary.

        Args:
            data: Dictionary with objectClass properties

        Returns:
            The SchemaObjectClass instance

        """
        must = data.get("must", [])
        may = data.get("may", [])
        return m.Ldif.SchemaObjectClass(
            oid=str(data.get("oid", "")),
            name=str(data.get("name", "")),
            desc=data.get("desc"),
            kind=str(data.get("kind", "STRUCTURAL")),
            sup=data.get("sup"),
            must=list(must) if must else [],
            may=list(may) if may else [],
        )

    @staticmethod
    def test_schema_parse_attribute(
        schema_quirk: object,
        attr_def: str,
        expected_oid: str,
        expected_name: str,
    ) -> object:
        """Parse attribute definition and validate expected properties.

        Args:
            schema_quirk: Schema quirk instance
            attr_def: Attribute definition string
            expected_oid: Expected OID
            expected_name: Expected name

        Returns:
            The parsed SchemaAttribute instance

        Raises:
            AssertionError: If parsing fails or properties don't match

        """
        # Get parse method
        parse_method = getattr(schema_quirk, "_parse_attribute", None)
        if parse_method is None:
            parse_method = getattr(schema_quirk, "parse_attribute", None)

        if parse_method is None:
            msg = "Schema quirk has no attribute parse method"
            raise AssertionError(msg)

        result = parse_method(attr_def)

        if hasattr(result, "is_failure") and result.is_failure:
            raise AssertionError(f"Attribute parsing failed: {result.error}")

        value = result.value if hasattr(result, "value") else result

        # Validate expected properties
        actual_oid = getattr(value, "oid", None)
        if actual_oid != expected_oid:
            raise AssertionError(f"Expected OID '{expected_oid}', got '{actual_oid}'")

        actual_name = getattr(value, "name", None)
        if actual_name != expected_name:
            raise AssertionError(
                f"Expected name '{expected_name}', got '{actual_name}'",
            )

        return value

    @staticmethod
    def test_schema_parse_objectclass(
        schema_quirk: object,
        oc_def: str,
        expected_oid: str,
        expected_name: str,
    ) -> object:
        """Parse objectClass definition and validate expected properties.

        Args:
            schema_quirk: Schema quirk instance
            oc_def: ObjectClass definition string
            expected_oid: Expected OID
            expected_name: Expected name

        Returns:
            The parsed SchemaObjectClass instance

        Raises:
            AssertionError: If parsing fails or properties don't match

        """
        # Get parse method
        parse_method = getattr(schema_quirk, "_parse_objectclass", None)
        if parse_method is None:
            parse_method = getattr(schema_quirk, "parse_objectclass", None)

        if parse_method is None:
            msg = "Schema quirk has no objectClass parse method"
            raise AssertionError(msg)

        result = parse_method(oc_def)

        if hasattr(result, "is_failure") and result.is_failure:
            raise AssertionError(f"ObjectClass parsing failed: {result.error}")

        value = result.value if hasattr(result, "value") else result

        # Validate expected properties
        actual_oid = getattr(value, "oid", None)
        if actual_oid != expected_oid:
            raise AssertionError(f"Expected OID '{expected_oid}', got '{actual_oid}'")

        actual_name = getattr(value, "name", None)
        if actual_name != expected_name:
            raise AssertionError(
                f"Expected name '{expected_name}', got '{actual_name}'",
            )

        return value

    @staticmethod
    def test_schema_write_attribute_with_metadata(
        schema_quirk: object,
        attr_def: str,
        expected_oid: str,
        expected_name: str,
        must_contain: list[str] | None = None,
    ) -> tuple[object, str]:
        """Parse attribute definition, write it back, and validate output.

        Args:
            schema_quirk: Schema quirk instance
            attr_def: Attribute definition string to parse
            expected_oid: Expected OID in the parsed attribute
            expected_name: Expected name in the parsed attribute
            must_contain: List of strings that must appear in written output

        Returns:
            Tuple of (parsed attribute, written string)

        Raises:
            AssertionError: If parsing/writing fails or validations don't pass

        """
        # First parse the attribute
        attr = RfcTestHelpers.test_schema_parse_attribute(
            schema_quirk,
            attr_def,
            expected_oid,
            expected_name,
        )

        # Get write method
        write_method = getattr(schema_quirk, "write_attribute", None)
        if write_method is None:
            msg = "Schema quirk has no write_attribute method"
            raise AssertionError(msg)

        # Write the attribute back
        result = write_method(attr)

        if hasattr(result, "is_failure") and result.is_failure:
            raise AssertionError(f"Attribute writing failed: {result.error}")

        written = result.value if hasattr(result, "value") else result

        # Validate written contains expected elements
        if must_contain:
            for element in must_contain:
                if element not in written:
                    raise AssertionError(
                        f"Expected '{element}' in written output: {written}",
                    )

        return attr, written

    @staticmethod
    def test_parse_and_assert_entry_structure(
        parser_service: object,
        content: str,
        expected_dn: str,
        expected_attributes: list[str],
        expected_count: int = 1,
    ) -> list[object]:
        """Parse LDIF content and assert entry structure.

        Args:
            parser_service: The parser service instance
            content: LDIF content to parse
            expected_dn: Expected DN of first entry
            expected_attributes: Expected attribute names
            expected_count: Expected number of entries

        Returns:
            List of parsed entries

        Raises:
            AssertionError: If parsing fails or structure doesn't match

        """
        if not isinstance(parser_service, FlextLdifParser):
            raise TypeError(f"Expected FlextLdifParser, got {type(parser_service)}")

        result = parser_service.parse_string(content=content, server_type="rfc")

        if result.is_failure:
            raise AssertionError(f"Parsing failed: {result.error}")

        entries = list(result.value.entries)
        if len(entries) != expected_count:
            raise AssertionError(
                f"Expected {expected_count} entries, got {len(entries)}",
            )

        if entries and expected_dn:
            actual_dn = getattr(entries[0], "dn", None)
            if str(actual_dn) != expected_dn:
                raise AssertionError(f"Expected DN '{expected_dn}', got '{actual_dn}'")

        if entries and expected_attributes:
            entry = entries[0]
            attrs = getattr(entry, "attributes", {})
            for attr_name in expected_attributes:
                if attr_name not in attrs:
                    raise AssertionError(
                        f"Expected attribute '{attr_name}' not found in entry",
                    )

        return entries

    @staticmethod
    def test_parse_and_assert_multiple_entries(
        parser_service: object,
        content: str,
        expected_dns: list[str],
        expected_count: int,
    ) -> list[object]:
        """Parse LDIF content with multiple entries and assert structure.

        Args:
            parser_service: The parser service instance
            content: LDIF content to parse
            expected_dns: Expected DNs of entries (in order)
            expected_count: Expected number of entries

        Returns:
            List of parsed entries

        Raises:
            AssertionError: If parsing fails or structure doesn't match

        """
        if not isinstance(parser_service, FlextLdifParser):
            raise TypeError(f"Expected FlextLdifParser, got {type(parser_service)}")

        result = parser_service.parse_string(content=content, server_type="rfc")

        if result.is_failure:
            raise AssertionError(f"Parsing failed: {result.error}")

        entries = list(result.value.entries)
        if len(entries) != expected_count:
            raise AssertionError(
                f"Expected {expected_count} entries, got {len(entries)}",
            )

        for i, expected_dn in enumerate(expected_dns):
            if i < len(entries):
                actual_dn = getattr(entries[i], "dn", None)
                if str(actual_dn) != expected_dn:
                    raise AssertionError(
                        f"Entry {i}: Expected DN '{expected_dn}', got '{actual_dn}'",
                    )

        return entries

    @staticmethod
    def test_create_entry(
        dn: str,
        attributes: dict[str, object],
    ) -> object:
        """Create an entry for testing.

        Args:
            dn: Distinguished Name for the entry
            attributes: Dictionary of attributes for the entry

        Returns:
            Entry instance

        Raises:
            AssertionError: If entry creation fails

        """
        result = m.Ldif.Entry.create(dn=dn, attributes=attributes)
        if result.is_failure:
            raise AssertionError(f"Entry creation failed: {result.error}")
        return result.value

    @staticmethod
    def test_write_entries_to_string(
        writer_service: object,
        entries: list[object],
        expected_content: list[str] | None = None,
    ) -> str:
        """Write entries to LDIF string.

        Args:
            writer_service: The writer service instance
            entries: List of entries to write
            expected_content: Optional list of strings that must appear in output

        Returns:
            LDIF string

        Raises:
            AssertionError: If writing fails or expected content not found

        """
        if not isinstance(writer_service, FlextLdifWriter):
            raise TypeError(f"Expected FlextLdifWriter, got {type(writer_service)}")

        result = writer_service.write_to_string(entries=entries)

        if result.is_failure:
            raise AssertionError(f"Writing failed: {result.error}")

        ldif_string = result.value
        if not isinstance(ldif_string, str):
            raise AssertionError(f"Expected string, got {type(ldif_string)}")

        if expected_content:
            for substring in expected_content:
                if substring not in ldif_string:
                    raise AssertionError(f"'{substring}' not found in LDIF output")

        return ldif_string

    @staticmethod
    def test_write_entries_to_file(
        writer_service: object,
        entries: list[object],
        file_path: object,
        expected_content: list[str] | None = None,
    ) -> None:
        """Write entries to LDIF file.

        Args:
            writer_service: The writer service instance
            entries: List of entries to write
            file_path: Path to write to
            expected_content: Optional list of strings that must appear in output

        Raises:
            AssertionError: If writing fails or expected content not found

        """
        if not isinstance(writer_service, FlextLdifWriter):
            raise TypeError(f"Expected FlextLdifWriter, got {type(writer_service)}")

        if not isinstance(file_path, Path):
            raise TypeError(f"Expected Path, got {type(file_path)}")

        result = writer_service.write_to_file(entries=entries, path=file_path)

        if result.is_failure:
            raise AssertionError(f"Writing to file failed: {result.error}")

        if not file_path.exists():
            raise AssertionError(f"Output file {file_path} was not created")

        if expected_content:
            content = file_path.read_text()
            for substring in expected_content:
                if substring not in content:
                    raise AssertionError(f"'{substring}' not found in file content")

    @staticmethod
    def test_parse_edge_case(
        parser_service: object,
        content: str,
        should_succeed: bool | None = None,
    ) -> object | None:
        """Parse edge case LDIF content.

        Args:
            parser_service: The parser service instance
            content: LDIF content to parse
            should_succeed: Expected success state (None = either outcome acceptable)

        Returns:
            Parse result value if successful, None otherwise

        Raises:
            AssertionError: If should_succeed specified and result doesn't match

        """
        if not isinstance(parser_service, FlextLdifParser):
            raise TypeError(f"Expected FlextLdifParser, got {type(parser_service)}")

        result = parser_service.parse_string(content=content, server_type="rfc")

        if should_succeed is True and result.is_failure:
            raise AssertionError(f"Expected success but got failure: {result.error}")

        if should_succeed is False and result.is_success:
            msg = "Expected failure but got success"
            raise AssertionError(msg)

        return result.map_or(None)

    @staticmethod
    def test_write_entry_variations(
        writer_service: object,
        entry_data: dict[str, dict[str, str | dict[str, list[str]]]],
    ) -> None:
        """Test writing entries with various data types.

        Args:
            writer_service: The writer service instance
            entry_data: Dict mapping test case names to entry data

        Raises:
            AssertionError: If any write operation fails

        """
        if not isinstance(writer_service, FlextLdifWriter):
            raise TypeError(f"Expected FlextLdifWriter, got {type(writer_service)}")

        for test_name, data in entry_data.items():
            dn = str(data.get("dn", ""))
            attributes = data.get("attributes", {})
            if not isinstance(attributes, dict):
                attributes = {}

            entry_result = m.Ldif.Entry.create(dn=dn, attributes=attributes)
            if entry_result.is_failure:
                raise AssertionError(
                    f"Entry creation failed for {test_name}: {entry_result.error}",
                )

            write_result = writer_service.write_to_string(entries=[entry_result.value])
            if write_result.is_failure:
                raise AssertionError(
                    f"Write failed for {test_name}: {write_result.error}",
                )

            if dn and dn not in write_result.value:
                raise AssertionError(f"DN '{dn}' not found in output for {test_name}")

    @staticmethod
    def test_entry_quirk_can_handle(
        entry_quirk: object,
        entry: object,
        expected: bool,
    ) -> None:
        """Test Entry quirk can_handle method.

        Args:
            entry_quirk: Entry quirk instance
            entry: Entry to test
            expected: Expected result from can_handle

        Raises:
            AssertionError: If can_handle returns unexpected result

        """
        can_handle_method = getattr(entry_quirk, "can_handle", None)
        if can_handle_method is None:
            msg = "Entry quirk has no can_handle method"
            raise AssertionError(msg)

        dn = str(getattr(entry, "dn", ""))
        attributes = getattr(entry, "attributes", {})

        result = can_handle_method(dn, attributes)
        if result != expected:
            raise AssertionError(
                f"Expected can_handle to return {expected}, got {result}",
            )

    @staticmethod
    def test_acl_quirk_parse_and_verify(
        acl_quirk: object,
        acl_line: str,
        expected_raw_acl: str | None = None,
    ) -> object:
        """Parse ACL and verify result.

        Args:
            acl_quirk: ACL quirk instance
            acl_line: ACL line to parse
            expected_raw_acl: Expected raw ACL value

        Returns:
            Parsed ACL object

        Raises:
            AssertionError: If parsing fails or verification fails

        """
        parse_method = getattr(acl_quirk, "parse", None)
        if parse_method is None:
            msg = "ACL quirk has no parse method"
            raise AssertionError(msg)

        result = parse_method(acl_line)

        if hasattr(result, "is_failure") and result.is_failure:
            raise AssertionError(f"ACL parsing failed: {result.error}")

        value = result.value if hasattr(result, "value") else result

        if expected_raw_acl is not None:
            raw_acl = getattr(value, "raw_acl", None)
            if raw_acl != expected_raw_acl:
                raise AssertionError(
                    f"Expected raw_acl '{expected_raw_acl}', got '{raw_acl}'",
                )

        return value

    @staticmethod
    def test_acl_quirk_write_and_verify(
        acl_quirk: object,
        acl: object,
        expected_content: str | None = None,
    ) -> str:
        """Write ACL and verify result.

        Args:
            acl_quirk: ACL quirk instance
            acl: ACL object to write
            expected_content: Expected content in output

        Returns:
            Written ACL string

        Raises:
            AssertionError: If writing fails or verification fails

        """
        write_method = getattr(acl_quirk, "write", None)
        if write_method is None:
            msg = "ACL quirk has no write method"
            raise AssertionError(msg)

        result = write_method(acl)

        if hasattr(result, "is_failure") and result.is_failure:
            raise AssertionError(f"ACL writing failed: {result.error}")

        output = result.value if hasattr(result, "value") else result

        if not isinstance(output, str):
            raise AssertionError(f"Expected string output, got {type(output)}")

        if expected_content is not None and expected_content not in output:
            raise AssertionError(f"Expected '{expected_content}' not found in output")

        return output

    @staticmethod
    def test_parse_error_handling(
        schema_quirk: object,
        invalid_def: str,
        *,
        should_fail: bool = True,
    ) -> object | None:
        """Test parsing error handling for invalid definitions.

        Args:
            schema_quirk: Schema quirk instance
            invalid_def: Invalid attribute/objectClass definition string
            should_fail: Whether parsing should fail (default True)

        Returns:
            Parse result value if successful, None otherwise

        Raises:
            AssertionError: If should_fail and parsing succeeds,
                           or if not should_fail and parsing fails

        """
        # Try attribute parse method
        parse_method = getattr(schema_quirk, "_parse_attribute", None)
        if parse_method is None:
            parse_method = getattr(schema_quirk, "parse_attribute", None)

        if parse_method is None:
            msg = "Schema quirk has no attribute parse method"
            raise AssertionError(msg)

        result = parse_method(invalid_def)

        if hasattr(result, "is_failure"):
            is_failure = result.is_failure
        else:
            is_failure = result is None

        if should_fail and not is_failure:
            msg = "Expected parsing to fail but it succeeded"
            raise AssertionError(msg)

        if not should_fail and is_failure:
            error_msg = result.error if hasattr(result, "error") else "Unknown error"
            raise AssertionError(f"Expected parsing to succeed but got: {error_msg}")

        if is_failure:
            return None

        return result.value if hasattr(result, "value") else result


class TestDeduplicationHelpers:
    """Test helpers for deduplication functionality.

    Note: Moved from constants.py per FLEXT architecture rules
    (constants.py should contain ONLY constants, no methods).
    """

    @staticmethod
    def create_entries_batch(
        entries_data: list[dict[str, object]],
        *,
        validate_all: bool = True,
    ) -> list[object]:
        """Create multiple entries from data dictionaries.

        Args:
            entries_data: List of dicts with 'dn' and 'attributes' keys
            validate_all: Whether to validate all entries (currently unused)

        Returns:
            List of created Entry instances

        """
        service = FlextLdifEntries()
        entries = []
        for entry_data in entries_data:
            dn: str = entry_data["dn"]
            attrs: dict[str, object] = entry_data["attributes"]
            result = service.create_entry(dn=dn, attributes=attrs)
            if result.is_success:
                entries.append(result.value)
        return entries

    @staticmethod
    def batch_parse_and_assert(
        parser_service: object,
        test_cases: list[dict[str, object]],
        *,
        validate_all: bool = True,
    ) -> list[object]:
        """Batch parse LDIF content and assert results.

        Args:
            parser_service: The parser service instance
            test_cases: List of dicts with 'ldif_content', 'should_succeed',
                       and optionally 'server_type' keys
            validate_all: Whether to validate all results strictly

        Returns:
            List of parse results

        Raises:
            AssertionError: If validation fails when validate_all is True

        """
        if not isinstance(parser_service, FlextLdifParser):
            raise TypeError(f"Expected FlextLdifParser, got {type(parser_service)}")

        results = []
        for test_case in test_cases:
            ldif_content = str(test_case.get("ldif_content", ""))
            should_succeed = test_case.get("should_succeed")
            server_type = str(test_case.get("server_type", "rfc"))

            result = parser_service.parse_string(
                content=ldif_content,
                server_type=server_type,
            )

            if validate_all and should_succeed is True and result.is_failure:
                raise AssertionError(
                    f"Expected success but got failure: {result.error}",
                )

            if validate_all and should_succeed is False and result.is_success:
                msg = "Expected failure but got success"
                raise AssertionError(msg)

            results.append(result)

        return results

    @staticmethod
    def helper_api_write_and_unwrap(
        api: object,
        entries: list[object],
        must_contain: list[str] | None = None,
    ) -> str:
        """Write entries to string and unwrap result.

        Args:
            api: FlextLdif instance
            entries: List of entries to write
            must_contain: List of strings that must appear in output

        Returns:
            LDIF string

        """
        if not isinstance(api, FlextLdif):
            raise TypeError(f"Expected FlextLdif, got {type(api)}")
        result = api.write(entries)
        if result.is_failure:
            raise AssertionError(f"write() failed: {result.error}")
        ldif_string = result.value
        if not isinstance(ldif_string, str):
            raise TypeError(f"Expected str, got {type(ldif_string)}")

        if must_contain:
            for substring in must_contain:
                if substring not in ldif_string:
                    raise AssertionError(
                        f"'{substring}' not found in LDIF output",
                    )

        return ldif_string

    @staticmethod
    def api_parse_write_file_and_assert(
        api: object,
        entries: list[object],
        output_file: object,
        must_contain: list[str] | None = None,
    ) -> None:
        """Write entries to file and assert content.

        Args:
            api: FlextLdif instance
            entries: List of entries to write
            output_file: Path to output file
            must_contain: List of strings that must appear in output

        """
        if not isinstance(api, FlextLdif):
            raise TypeError(f"Expected FlextLdif, got {type(api)}")
        if not isinstance(output_file, Path):
            raise TypeError(f"Expected Path, got {type(output_file)}")

        ldif_string = TestDeduplicationHelpers.helper_api_write_and_unwrap(
            api,
            entries,
            must_contain=must_contain,
        )

        output_file.write_text(ldif_string)
        if not output_file.exists():
            raise AssertionError(f"Output file {output_file} was not created")

    @staticmethod
    def api_parse_write_string_and_assert(
        api: object,
        entries: list[object],
        must_contain: list[str] | None = None,
    ) -> None:
        """Write entries to string and assert content.

        Args:
            api: FlextLdif instance
            entries: List of entries to write
            must_contain: List of strings that must appear in output

        """
        TestDeduplicationHelpers.helper_api_write_and_unwrap(
            api,
            entries,
            must_contain=must_contain,
        )

    @staticmethod
    def quirk_parse_and_unwrap(
        quirk: object,
        content: str,
        msg: str | None = None,
        parse_method: str | None = None,
        expected_type: type | None = None,
        should_succeed: bool | None = None,
    ) -> object | None:
        """Parse using quirk and unwrap result.

        Args:
            quirk: Schema quirk instance with parse method
            content: Content to parse
            msg: Optional message for assertion
            parse_method: Optional specific parse method name (e.g., 'parse_attribute')
            expected_type: Optional expected type for validation
            should_succeed: Expected outcome (True=must succeed, False=must fail,
                None=any outcome acceptable)

        Returns:
            Parsed result value if successful, None if expected failure

        Raises:
            AssertionError: If should_succeed specified and result doesn't match,
                or if type doesn't match

        """
        # Get the appropriate parse method
        if parse_method:
            method = getattr(quirk, parse_method, None)
            if method is None:
                raise AssertionError(f"Quirk has no method '{parse_method}'")
            result = method(content)
        else:
            result = quirk.parse(content)

        # Handle expected failure cases
        if should_succeed is False:
            if result.is_success:
                raise AssertionError(msg or "Expected failure but parse succeeded")
            return None  # Expected failure, return None

        # Handle expected success or default case
        if should_succeed is True and result.is_failure:
            raise AssertionError(
                msg or f"Expected success but parse failed: {result.error}",
            )

        # Default behavior for should_succeed=None: assert success
        if should_succeed is None and result.is_failure:
            raise AssertionError(msg or f"quirk.parse() failed: {result.error}")

        # For failures with should_succeed=None, return None
        if result.is_failure:
            return None

        value = result.value
        if expected_type is not None:
            # For Protocol types, use duck typing check
            if hasattr(expected_type, "__protocol_attrs__"):
                # It's a Protocol, just return the value (structural typing)
                pass
            elif not isinstance(value, expected_type):
                raise AssertionError(
                    f"Expected {expected_type.__name__}, got {type(value).__name__}",
                )
        return value

    @staticmethod
    def quirk_write_and_unwrap(
        quirk: object,
        data: object,
        msg: str | None = None,
        write_method: str | None = None,
        must_contain: list[str] | None = None,
    ) -> str:
        """Write using quirk and unwrap result.

        Args:
            quirk: Schema quirk instance with write method
            data: Data to write (Entry, SchemaAttribute, SchemaObjectClass, etc.)
            msg: Optional message for assertion
            write_method: Optional specific write method name (e.g., '_write_attribute')
            must_contain: Optional list of strings that must appear in output

        Returns:
            Written string result

        Raises:
            AssertionError: If writing fails or must_contain strings not found

        """
        # Get the appropriate write method
        if write_method:
            method = getattr(quirk, write_method, None)
            if method is None:
                raise AssertionError(f"Quirk has no method '{write_method}'")
            result = method(data)
        else:
            method = getattr(quirk, "write", None)
            if method is None:
                msg_text = "Quirk has no write method"
                raise AssertionError(msg_text)
            result = method(data)

        # Handle FlextResult or direct string
        if hasattr(result, "is_success"):
            if result.is_failure:
                raise AssertionError(msg or f"quirk.write() failed: {result.error}")
            output = result.value
        else:
            output = result

        if not isinstance(output, str):
            raise TypeError(f"Expected str, got {type(output).__name__}")

        # Check must_contain strings
        if must_contain:
            for substring in must_contain:
                if substring not in output:
                    raise AssertionError(
                        f"'{substring}' not found in output: {output[:200]}...",
                    )

        return output

    @staticmethod
    def helper_convert_and_assert_strings(
        conversion_matrix: object,
        source_quirk: object,
        target_quirk: object,
        conversion_type: str,
        data: str,
        must_contain: list[str] | None = None,
        expected_type: type | None = None,
    ) -> str:
        """Convert data between quirks and assert result.

        Args:
            conversion_matrix: FlextLdifConversion instance
            source_quirk: Source server quirk
            target_quirk: Target server quirk
            conversion_type: Type of conversion ('attribute', 'objectClass', etc.)
            data: Data to convert (string)
            must_contain: List of strings that must appear in output
            expected_type: Expected type for validation (default: str)

        Returns:
            Converted string result

        Raises:
            AssertionError: If conversion fails or validation fails

        """
        # Get convert method
        convert_method = getattr(conversion_matrix, "convert", None)
        if convert_method is None:
            msg = "conversion_matrix has no convert method"
            raise AssertionError(msg)

        # Parse data into model instance based on conversion type
        conversion_type_lower = conversion_type.lower()
        if conversion_type_lower == "attribute":
            schema_service = FlextLdifSchema()
            parse_result = schema_service.parse_attribute(data)
            if not parse_result.is_success:
                raise AssertionError(f"Failed to parse attribute: {parse_result.error}")
            model_instance = parse_result.value
        elif conversion_type_lower in {"objectclass", "objectclasses"}:
            schema_service = FlextLdifSchema()
            parse_result = schema_service.parse_objectclass(data)
            if not parse_result.is_success:
                raise AssertionError(
                    f"Failed to parse objectclass: {parse_result.error}",
                )
            model_instance = parse_result.value
        else:
            raise AssertionError(f"Unknown conversion_type: {conversion_type}")

        # Perform conversion
        result = convert_method(
            source=source_quirk,
            target=target_quirk,
            model_instance=model_instance,
        )

        # Check result
        if hasattr(result, "is_success"):
            if result.is_failure:
                raise AssertionError(f"convert() failed: {result.error}")
            output = result.value
        else:
            output = result

        # Convert model instances to string if expected
        if expected_type is str and not isinstance(output, str):
            output = str(output)

        # Type check
        if expected_type is not None and not isinstance(output, expected_type):
            raise AssertionError(
                f"Expected {expected_type.__name__}, got {type(output).__name__}",
            )

        # Check must_contain strings
        if must_contain and isinstance(output, str):
            for substring in must_contain:
                if substring not in output:
                    raise AssertionError(
                        f"'{substring}' not found in output: {output[:200]}...",
                    )

        return output

    @staticmethod
    def helper_get_supported_conversions_and_assert(
        conversion_matrix: object,
        quirk: object,
        must_have_keys: list[str] | None = None,
        expected_support: dict[str, bool] | None = None,
    ) -> dict[str, bool]:
        """Get supported conversions and assert result.

        Args:
            conversion_matrix: FlextLdifConversion instance
            quirk: Server quirk to check support for
            must_have_keys: List of keys that must appear in result
            expected_support: Dict of expected key:bool values

        Returns:
            Dict of supported conversion types

        Raises:
            AssertionError: If result doesn't have expected keys or values

        """
        # Get supported conversions method
        get_support_method = getattr(
            conversion_matrix,
            "get_supported_conversions",
            None,
        )
        if get_support_method is None:
            msg = "conversion_matrix has no get_supported_conversions"
            raise AssertionError(msg)

        # Get supported conversions
        result = get_support_method(quirk)

        # Handle FlextResult
        if hasattr(result, "is_success"):
            if result.is_failure:
                raise AssertionError(
                    f"get_supported_conversions failed: {result.error}",
                )
            support_dict = result.value
        else:
            support_dict = result

        if not isinstance(support_dict, dict):
            raise TypeError(f"Expected dict, got {type(support_dict).__name__}")

        # Check must_have_keys
        if must_have_keys:
            for key in must_have_keys:
                if key not in support_dict:
                    raise AssertionError(f"Missing key '{key}' in support dict")

        # Check expected_support values
        if expected_support:
            for key, expected_value in expected_support.items():
                if key in support_dict and support_dict[key] != expected_value:
                    raise AssertionError(
                        f"Expected {key}={expected_value}, got {support_dict[key]}",
                    )

        return support_dict

    @staticmethod
    def helper_batch_convert_and_assert(
        conversion_matrix: object,
        source_quirk: object,
        target_quirk: object,
        conversion_type: str,
        items: list[object],
        expected_count: int | None = None,
    ) -> list[object]:
        """Batch convert items and assert result.

        Args:
            conversion_matrix: FlextLdifConversion instance
            source_quirk: Source server quirk
            target_quirk: Target server quirk
            conversion_type: Type of conversion ('attribute', 'objectClass', etc.)
            items: List of items to convert
            expected_count: Expected number of results (default: len(items))

        Returns:
            List of converted items

        Raises:
            AssertionError: If conversion fails or count doesn't match

        """
        # Get batch_convert method
        batch_convert_method = getattr(conversion_matrix, "batch_convert", None)
        if batch_convert_method is None:
            msg = "conversion_matrix has no batch_convert method"
            raise AssertionError(msg)

        # Parse items into model instances based on conversion type
        model_list = []
        conversion_type_lower = conversion_type.lower()
        if conversion_type_lower == "attribute":
            schema_service = FlextLdifSchema()
            for item in items:
                parse_result = schema_service.parse_attribute(item)
                if not parse_result.is_success:
                    raise AssertionError(
                        f"Failed to parse attribute: {parse_result.error}",
                    )
                model_list.append(parse_result.value)
        elif conversion_type_lower in {"objectclass", "objectclasses"}:
            schema_service = FlextLdifSchema()
            for item in items:
                parse_result = schema_service.parse_objectclass(item)
                if not parse_result.is_success:
                    raise AssertionError(
                        f"Failed to parse objectclass: {parse_result.error}",
                    )
                model_list.append(parse_result.value)
        else:
            raise AssertionError(f"Unknown conversion_type: {conversion_type}")

        # Perform batch conversion
        result = batch_convert_method(
            source=source_quirk,
            target=target_quirk,
            model_list=model_list,
        )

        # Handle FlextResult
        if hasattr(result, "is_success"):
            if result.is_failure:
                raise AssertionError(f"batch_convert() failed: {result.error}")
            converted_items = result.value
        else:
            converted_items = result

        if not isinstance(converted_items, list):
            raise TypeError(f"Expected list, got {type(converted_items).__name__}")

        # Check expected count
        if expected_count is not None and len(converted_items) != expected_count:
            raise AssertionError(
                f"Expected {expected_count} items, got {len(converted_items)}",
            )

        return converted_items


class TestCategorization:
    """Test categorization helpers.

    Note: Moved from constants.py per FLEXT architecture rules.
    """

    # Placeholder for categorization helper methods if needed


# Standardized short name for use in tests (same pattern as flext-core)
u = TestsFlextLdifUtilities
Testsu = TestsFlextLdifUtilities  # Alias for tests/__init__.py

__all__ = [
    "RfcTestHelpers",
    "TestCategorization",
    "TestDeduplicationHelpers",
    "TestsFlextLdifUtilities",
    "Testsu",
    "u",
]
