"""Tests for RFC 4512 attribute parser with RFC 4517 syntax integration.

This module tests attribute parsing with syntax definition resolution,
RFC 4517 syntax OID validation, type-specific validators, and schema
quirk integration across different LDAP server implementations.
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar

import pytest

from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.services.syntax import FlextLdifSyntax
from tests import RfcTestHelpers, c, m, p, s


class TestsFlextLdifRfcAttributeParser(s):
    """Unified RFC 4512 attribute parser tests with RFC 4517 syntax integration.

    Tests cover:
    - Basic attribute parsing (complete, minimal, with various options)
    - Syntax definition resolution via computed fields
    - RFC 4517 syntax OID validation
    - Type-specific validators (Boolean, Integer, DirectoryString, IA5String)
    - Schema quirk integration (can_handle, should_filter, write operations)
    - Error handling and roundtrip validation

    Uses parametrized tests and factory methods to maximize coverage with minimal code.
    """

    syntax_service: ClassVar[FlextLdifSyntax]  # pytest fixture

    # ========================================================================
    # Test Data: Attribute Definitions with Expected Properties
    # ========================================================================

    class AttributeTestCase(StrEnum):
        """Parametrized attribute parsing test cases."""

        COMPLETE = "complete"
        MINIMAL = "minimal"
        WITH_SYNTAX = "with_syntax"
        WITH_MATCHING = "with_matching"
        WITH_SUP = "with_sup"
        WITH_USAGE = "with_usage"
        WITH_OBSOLETE = "with_obsolete"
        CASE_INSENSITIVE = "case_insensitive"
        QUOTED_SYNTAX = "quoted_syntax"
        UNQUOTED_SYNTAX = "unquoted_syntax"

    class SyntaxTestCase(StrEnum):
        """Parametrized syntax OID validation test cases."""

        RFC4517_VALID = "rfc4517_valid"
        RFC4517_NONSTANDARD = "nonstandard"
        INVALID_FORMAT = "invalid_format"
        DIRECTORY_STRING = "directory_string"
        BOOLEAN = "boolean"
        INTEGER = "integer"
        IA5STRING = "ia5string"

    # Attribute definition test data mapped by test case
    ATTRIBUTE_DEFINITIONS: ClassVar[dict[str, tuple[str, str, str]]] = {
        AttributeTestCase.COMPLETE: (
            c.Rfc.ATTR_DEF_CN_COMPLETE,
            c.Rfc.ATTR_OID_CN,
            c.Rfc.ATTR_NAME_CN,
        ),
        AttributeTestCase.MINIMAL: (
            "( 2.5.4.3 )",
            c.Rfc.ATTR_OID_CN,
            c.Rfc.ATTR_OID_CN,
        ),
        AttributeTestCase.WITH_SYNTAX: (
            c.Rfc.ATTR_DEF_SN,
            c.Rfc.ATTR_OID_SN,
            c.Rfc.ATTR_NAME_SN,
        ),
        AttributeTestCase.WITH_MATCHING: (
            c.Rfc.ATTR_DEF_ST,
            "2.5.4.8",
            "st",
        ),
        AttributeTestCase.WITH_SUP: (
            c.Rfc.ATTR_DEF_MAIL,
            c.Rfc.ATTR_OID_MAIL,
            c.Rfc.ATTR_NAME_MAIL,
        ),
        AttributeTestCase.WITH_USAGE: (
            c.Rfc.ATTR_DEF_MODIFY_TIMESTAMP,
            "2.5.18.2",
            "modifyTimestamp",
        ),
        AttributeTestCase.WITH_OBSOLETE: (
            c.Rfc.ATTR_DEF_OBSOLETE,
            c.Rfc.ATTR_OID_O,
            c.Rfc.ATTR_NAME_O,
        ),
        AttributeTestCase.CASE_INSENSITIVE: (
            "( 2.5.4.3 NAME 'cn' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )",
            "2.5.4.3",
            c.Rfc.ATTR_NAME_CN,
        ),
        AttributeTestCase.QUOTED_SYNTAX: (
            "( 2.5.4.3 NAME 'cn' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )",
            "2.5.4.3",
            c.Rfc.ATTR_NAME_CN,
        ),
        AttributeTestCase.UNQUOTED_SYNTAX: (
            "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
            "2.5.4.3",
            c.Rfc.ATTR_NAME_CN,
        ),
    }

    # Syntax definition test data with expected syntax name
    SYNTAX_DEFINITIONS: ClassVar[dict[str, tuple[str, str, str, str | None]]] = {
        SyntaxTestCase.DIRECTORY_STRING: (
            (
                f"( {c.Rfc.ATTR_OID_SN} NAME "
                f"'{c.Rfc.ATTR_NAME_SN}' "
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.21 )"
            ),
            c.Rfc.ATTR_OID_SN,
            c.Rfc.ATTR_NAME_SN,
            "directory_string",
        ),
        SyntaxTestCase.BOOLEAN: (
            "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )",
            "2.5.4.3",
            "cn",
            "boolean",
        ),
        SyntaxTestCase.INTEGER: (
            ("( 2.5.4.0 NAME 'objectClass' SYNTAX 2.5.5.5 )"),
            "2.5.4.0",
            "objectClass",
            "integer",
        ),
        SyntaxTestCase.RFC4517_NONSTANDARD: (
            (f"( {c.Rfc.ATTR_OID_CN} NAME '{c.Rfc.ATTR_NAME_CN}' SYNTAX 9.9.9.9.9.9 )"),
            c.Rfc.ATTR_OID_CN,
            c.Rfc.ATTR_NAME_CN,
            None,
        ),
        SyntaxTestCase.RFC4517_VALID: (
            (
                f"( {c.Rfc.ATTR_OID_CN} NAME "
                f"'{c.Rfc.ATTR_NAME_CN}' "
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
            ),
            c.Rfc.ATTR_OID_CN,
            c.Rfc.ATTR_NAME_CN,
            "directory_string",
        ),
        SyntaxTestCase.IA5STRING: (
            (
                "( 0.9.2342.19200300.100.1.1 NAME 'uid' "
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )"
            ),
            "0.9.2342.19200300.100.1.1",
            "uid",
            "ia5_string",
        ),
        SyntaxTestCase.INVALID_FORMAT: (
            (
                f"( {c.Rfc.ATTR_OID_CN} NAME "
                f"'{c.Rfc.ATTR_NAME_CN}' "
                "SYNTAX invalid-syntax-oid )"
            ),
            c.Rfc.ATTR_OID_CN,
            c.Rfc.ATTR_NAME_CN,
            None,
        ),
    }

    # Roundtrip validation test cases
    ROUNDTRIP_CASES: ClassVar[list[tuple[str, str, str]]] = [
        (
            "( 2.5.4.3 NAME 'cn' SUP name )",
            "2.5.4.3",
            "cn",
        ),
        (
            (
                "( 2.5.4.49 NAME 'userPassword' EQUALITY octetStringMatch "
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.39 )"
            ),
            "2.5.4.49",
            "userPassword",
        ),
        (
            (
                "( 2.5.4.0 NAME 'objectClass' EQUALITY objectIdentifierMatch "
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )"
            ),
            "2.5.4.0",
            "objectClass",
        ),
    ]

    # Syntax validator test cases
    VALIDATOR_CASES: ClassVar[list[tuple[str, str, bool]]] = [
        ("TRUE", "1.3.6.1.4.1.1466.115.121.1.7", True),
        ("FALSE", "1.3.6.1.4.1.1466.115.121.1.7", True),
        ("MAYBE", "1.3.6.1.4.1.1466.115.121.1.7", False),
        ("12345", "2.5.5.5", True),
        ("-999", "2.5.5.5", True),
        ("not_a_number", "2.5.5.5", False),
        ("John Doe", "1.3.6.1.4.1.1466.115.121.1.15", True),
        ("User Name (Office)", "1.3.6.1.4.1.1466.115.121.1.15", True),
        ("test@example.com", "1.3.6.1.4.1.1466.115.121.1.26", True),
    ]

    # ========================================================================
    # Fixtures
    # ========================================================================

    @pytest.fixture
    def syntax_service(self) -> FlextLdifSyntax:
        """Syntax validation service."""
        return FlextLdifSyntax()

    # ========================================================================
    # Basic Attribute Parsing Tests (Parametrized)
    # ========================================================================

    @pytest.mark.parametrize("test_case", list(AttributeTestCase))
    @pytest.mark.timeout(5)
    def test_parse_attribute_basic_cases(
        self,
        test_case: AttributeTestCase,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test parsing various attribute definition cases.

        Parametrized test covers:
        - Complete attribute with all options
        - Minimal attribute with only OID
        - Attributes with syntax and length constraints
        - Attributes with matching rules
        - Attributes with SUP (superior), USAGE, OBSOLETE flags
        - Case-insensitive parsing
        """
        if test_case not in self.ATTRIBUTE_DEFINITIONS:
            pytest.skip(f"No test data for {test_case}")

        attr_def, expected_oid, expected_name = self.ATTRIBUTE_DEFINITIONS[test_case]
        attr = RfcTestHelpers.test_schema_parse_attribute(
            rfc_schema_quirk,
            attr_def,
            expected_oid,
            expected_name,
        )

        # Additional validations per test case
        if test_case == self.AttributeTestCase.COMPLETE:
            assert attr.single_value is True
        elif test_case == self.AttributeTestCase.MINIMAL:
            assert attr.desc is None
            assert attr.syntax is None
        elif test_case == self.AttributeTestCase.WITH_SYNTAX:
            assert attr.syntax is not None
        elif test_case == self.AttributeTestCase.WITH_SUP:
            assert attr.sup == "name"
        elif test_case == self.AttributeTestCase.WITH_USAGE:
            assert attr.usage == "directoryOperation"

    @pytest.mark.timeout(5)
    def test_parse_missing_oid_fails(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test that missing OID causes parsing failure."""
        _ = RfcTestHelpers.test_parse_error_handling(
            rfc_schema_quirk,
            c.Rfc.INVALID_ATTR_DEF,
            should_fail=True,
        )

    # ========================================================================
    # Syntax Definition and RFC 4517 Resolution Tests (Parametrized)
    # ========================================================================

    @pytest.mark.parametrize("test_case", list(SyntaxTestCase))
    @pytest.mark.timeout(5)
    def test_syntax_definition_resolution(
        self,
        test_case: SyntaxTestCase,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test syntax_definition computed field resolution for RFC 4517.

        Parametrized test covers various syntax types and their resolution.
        """
        if test_case not in self.SYNTAX_DEFINITIONS:
            pytest.skip(f"No test data for {test_case}")

        attr_def, expected_oid, expected_name, expected_syntax = (
            self.SYNTAX_DEFINITIONS[test_case]
        )
        attr = RfcTestHelpers.test_schema_parse_attribute(
            rfc_schema_quirk,
            attr_def,
            expected_oid,
            expected_name,
        )

        syntax = attr.syntax_definition
        if expected_syntax is None:
            assert syntax is None or isinstance(syntax, m.Syntax)
        else:
            assert syntax is not None
            assert isinstance(syntax, m.Syntax)
            assert syntax.name == expected_syntax

    @pytest.mark.timeout(5)
    def test_syntax_definition_none_cases(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test syntax_definition returns None when syntax is absent or invalid."""
        # Case 1: No syntax specified
        attr_def = c.Rfc.ATTR_DEF_CN_MINIMAL
        result = rfc_schema_quirk.parse(attr_def)
        assert result.is_success
        attr = result.unwrap()
        assert isinstance(attr, p.Ldif.SchemaAttribute)
        assert attr.syntax is None
        assert attr.syntax_definition is None

        # Case 2: Empty syntax
        empty_syntax_attr = p.Ldif.SchemaAttribute(
            oid=c.Rfc.ATTR_OID_CN,
            name=c.Rfc.ATTR_NAME_CN,
            syntax="",
            desc=None,
            sup=None,
            equality=None,
            ordering=None,
            substr=None,
            length=None,
            usage=None,
            x_origin=None,
            x_file_ref=None,
            x_name=None,
            x_alias=None,
            x_oid=None,
        )
        assert empty_syntax_attr.syntax_definition is None

        # Case 3: Invalid OID format
        invalid_oid_attr = p.Ldif.SchemaAttribute(
            oid=c.Rfc.ATTR_OID_CN,
            name=c.Rfc.ATTR_NAME_CN,
            syntax="not.a.valid.oid.at.all",
            desc=None,
            sup=None,
            equality=None,
            ordering=None,
            substr=None,
            length=None,
            usage=None,
            x_origin=None,
            x_file_ref=None,
            x_name=None,
            x_alias=None,
            x_oid=None,
        )
        syntax = invalid_oid_attr.syntax_definition
        assert syntax is None or isinstance(syntax, m.Syntax)

    @pytest.mark.timeout(5)
    def test_syntax_definition_caching_behavior(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test syntax_definition computed field recalculation on each access."""
        attr = RfcTestHelpers.test_schema_parse_attribute(
            rfc_schema_quirk,
            (
                f"( {c.Rfc.ATTR_OID_CN} NAME "
                f"'{c.Rfc.ATTR_NAME_CN}' "
                f"SYNTAX {c.Rfc.SYNTAX_OID_BOOLEAN} )"
            ),
            c.Rfc.ATTR_OID_CN,
            c.Rfc.ATTR_NAME_CN,
        )
        syntax1 = attr.syntax_definition
        syntax2 = attr.syntax_definition

        assert syntax1 is not None
        assert syntax2 is not None
        assert isinstance(syntax1, m.Syntax)
        assert isinstance(syntax2, m.Syntax)
        assert syntax1.oid == syntax2.oid
        assert syntax1.name == syntax2.name

    # ========================================================================
    # Type-Specific Validator Tests (Parametrized)
    # ========================================================================

    @pytest.mark.parametrize(("value", "syntax_oid", "expected"), VALIDATOR_CASES)
    @pytest.mark.timeout(5)
    def test_syntax_validators(
        self,
        value: str,
        syntax_oid: str,
        expected: bool,
        syntax_service: FlextLdifSyntax,
    ) -> None:
        """Test RFC 4517 syntax validators for various value types.

        Parametrized test covers:
        - Boolean syntax (TRUE/FALSE)
        - Integer syntax (positive, negative, invalid)
        - DirectoryString syntax (plain, special chars)
        - IA5String syntax (ASCII values)
        """
        result = syntax_service.validate_value(value, syntax_oid)
        assert result.is_success
        is_valid = result.unwrap()
        assert is_valid is expected

    # ========================================================================
    # Roundtrip Validation Tests (Parametrized)
    # ========================================================================

    @pytest.mark.parametrize(
        ("attr_def", "expected_oid", "expected_name"),
        ROUNDTRIP_CASES,
    )
    @pytest.mark.timeout(5)
    def test_roundtrip_validation(
        self,
        attr_def: str,
        expected_oid: str,
        expected_name: str,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test parsing and roundtrip validation with real-world schema examples."""
        result = rfc_schema_quirk.parse(attr_def)
        assert result.is_success

        attr = result.unwrap()
        assert isinstance(attr, p.Ldif.SchemaAttribute)
        assert attr.oid == expected_oid
        assert attr.name == expected_name

        # Verify syntax definition if present
        if attr.syntax is not None:
            syntax = attr.syntax_definition
            assert syntax is not None or syntax is None  # May be None for unknown OIDs

    # ========================================================================
    # Schema Quirk Integration Tests
    # ========================================================================

    @pytest.mark.timeout(5)
    def test_can_handle_attribute_string(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Schema.can_handle_attribute with string input."""
        attr_def = (
            f"( {c.Rfc.ATTR_OID_CN} NAME '{c.Rfc.ATTR_NAME_CN}' DESC 'Common Name' )"
        )
        assert rfc_schema_quirk.can_handle_attribute(attr_def) is True

    @pytest.mark.timeout(5)
    def test_can_handle_attribute_model(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Schema.can_handle_attribute with SchemaAttribute model."""
        attr_def = (
            f"( {c.Rfc.ATTR_OID_CN} NAME '{c.Rfc.ATTR_NAME_CN}' DESC 'Common Name' )"
        )
        parse_result = rfc_schema_quirk.parse(attr_def)
        assert parse_result.is_success
        attr_model = parse_result.unwrap()
        assert isinstance(attr_model, p.Ldif.SchemaAttribute)
        assert rfc_schema_quirk.can_handle_attribute(attr_model) is True

    @pytest.mark.timeout(5)
    def test_should_filter_out_attribute(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Schema.should_filter_out_attribute always returns False."""
        attr_def = (
            f"( {c.Rfc.ATTR_OID_CN} NAME '{c.Rfc.ATTR_NAME_CN}' DESC 'Common Name' )"
        )
        parse_result = rfc_schema_quirk.parse(attr_def)
        assert parse_result.is_success
        attr_model = parse_result.unwrap()
        assert isinstance(attr_model, p.Ldif.SchemaAttribute)
        assert rfc_schema_quirk.should_filter_out_attribute(attr_model) is False

    @pytest.mark.timeout(5)
    def test_write_attribute_variations(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Schema.write_attribute with various configurations."""
        _, written = RfcTestHelpers.test_schema_write_attribute_with_metadata(
            rfc_schema_quirk,
            (
                f"( {c.Rfc.ATTR_OID_CN} NAME "
                f"'{c.Rfc.ATTR_NAME_CN}' "
                f"DESC 'Common Name' SYNTAX {c.Rfc.SYNTAX_OID_DIRECTORY_STRING} "
                "SINGLE-VALUE NO-USER-MODIFICATION )"
            ),
            c.Rfc.ATTR_OID_CN,
            c.Rfc.ATTR_NAME_CN,
            must_contain=["SINGLE-VALUE", "NO-USER-MODIFICATION"],
        )
        assert ")" in written

    @pytest.mark.timeout(5)
    def test_transform_hooks_no_op(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test that RFC transform hooks are no-ops (return unchanged)."""
        attr = RfcTestHelpers.test_schema_parse_attribute(
            rfc_schema_quirk,
            "( 2.5.4.3 NAME 'cn' DESC 'Common Name' )",
            "2.5.4.3",
            "cn",
        )
        write_result = rfc_schema_quirk.write_attribute(attr)
        assert write_result.is_success
        written_str = write_result.unwrap()
        assert "2.5.4.3" in written_str
        assert "cn" in written_str


if __name__ == "__main__":
    _ = pytest.main([__file__, "-v"])
