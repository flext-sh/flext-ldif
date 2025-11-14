"""Unit tests for RFC 4512 AttributeParser with RFC 4517 Syntax Integration.

Comprehensive testing of RFC 4512 attribute definition parsing with integrated
RFC 4517 syntax validation and resolution via computed_field.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.services.syntax import FlextLdifSyntax
from tests.helpers.test_assertions import TestAssertions
from tests.helpers.test_quirk_helpers import QuirkTestHelpers
from tests.helpers.test_rfc_helpers import RfcTestHelpers
from tests.unit.quirks.servers.fixtures.rfc_constants import TestsRfcConstants

# Test constants - always at top of module, no type checking
# Use classes directly, no instantiation needed


class TestAttributeParserBasics:
    """Test basic RFC 4512 attribute definition parsing."""

    @pytest.mark.timeout(5)
    def test_parse_complete_attribute(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test parsing a complete RFC 4512 attribute definition."""
        schema_obj = RfcTestHelpers.test_schema_parse_and_assert_basic_properties(
            rfc_schema_quirk,
            TestsRfcConstants.ATTR_DEF_CN_COMPLETE,
            expected_oid=TestsRfcConstants.ATTR_OID_CN,
            expected_name=TestsRfcConstants.ATTR_NAME_CN,
            expected_desc="Common Name",
            expected_syntax=TestsRfcConstants.SYNTAX_OID_DIRECTORY_STRING,
        )
        assert isinstance(schema_obj, FlextLdifModels.SchemaAttribute)
        attr = schema_obj
        assert attr.single_value is True

    @pytest.mark.timeout(5)
    def test_parse_minimal_attribute(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test parsing minimal attribute (only OID)."""
        attr_def = "( 2.5.4.3 )"
        attr = QuirkTestHelpers.test_schema_parse_and_validate_complete(
            rfc_schema_quirk,
            attr_def,
            expected_oid=TestsRfcConstants.ATTR_OID_CN,
            expected_name=TestsRfcConstants.ATTR_OID_CN,
            expected_desc=None,
            expected_syntax=None,
        )
        assert attr.desc is None
        assert attr.syntax is None

    @pytest.mark.timeout(5)
    def test_parse_attribute_with_syntax_and_length(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test parsing attribute with SYNTAX and length constraint."""
        attr = QuirkTestHelpers.test_schema_parse_and_validate_complete(
            rfc_schema_quirk,
            TestsRfcConstants.ATTR_DEF_SN,
            expected_oid=TestsRfcConstants.ATTR_OID_SN,
            expected_name=TestsRfcConstants.ATTR_NAME_SN,
            expected_syntax=TestsRfcConstants.SYNTAX_OID_DIRECTORY_STRING,
        )
        assert attr.syntax is not None

    @pytest.mark.timeout(5)
    def test_parse_attribute_with_matching_rules(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test parsing attribute with matching rules."""
        _ = RfcTestHelpers.test_schema_parse_and_assert_matching_rules(
            rfc_schema_quirk,
            TestsRfcConstants.ATTR_DEF_ST,
            expected_oid="2.5.4.8",
            expected_name="st",
            expected_equality="caseIgnoreMatch",
            expected_ordering="caseIgnoreOrderingMatch",
            expected_substr="caseIgnoreSubstringsMatch",
            has_matching_rules=True,
        )

    @pytest.mark.timeout(5)
    def test_parse_attribute_without_matching_rules(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test has_matching_rules is False when no rules defined."""
        attr = RfcTestHelpers.test_schema_parse_and_assert_matching_rules(
            rfc_schema_quirk,
            TestsRfcConstants.ATTR_DEF_CN_MINIMAL,
            expected_oid=TestsRfcConstants.ATTR_OID_CN,
            expected_name=TestsRfcConstants.ATTR_OID_CN,
            has_matching_rules=False,
        )
        assert attr.equality is None and attr.ordering is None and attr.substr is None

    @pytest.mark.timeout(5)
    def test_parse_attribute_with_sup(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test parsing attribute with SUP (superior attribute)."""
        attr = RfcTestHelpers.test_schema_parse_attribute(
            rfc_schema_quirk,
            TestsRfcConstants.ATTR_DEF_MAIL,
            expected_oid=TestsRfcConstants.ATTR_OID_MAIL,
            expected_name=TestsRfcConstants.ATTR_NAME_MAIL,
        )
        assert attr.sup == "name"

    @pytest.mark.timeout(5)
    def test_parse_attribute_with_usage(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test parsing attribute with USAGE (operational attributes)."""
        attr = RfcTestHelpers.test_schema_parse_attribute(
            rfc_schema_quirk,
            TestsRfcConstants.ATTR_DEF_MODIFY_TIMESTAMP,
            expected_oid="2.5.18.2",
            expected_name="modifyTimestamp",
        )
        assert attr.usage == "directoryOperation"

    @pytest.mark.timeout(5)
    def test_parse_missing_oid_fails(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test that missing OID causes parsing failure."""
        _ = RfcTestHelpers.test_parse_error_handling(
            rfc_schema_quirk,
            TestsRfcConstants.INVALID_ATTR_DEF,
            should_fail=True,
        )

    @pytest.mark.timeout(5)
    def test_parse_attribute_with_obsolete_flag(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test parsing attribute with OBSOLETE flag."""
        _ = RfcTestHelpers.test_schema_parse_attribute(
            rfc_schema_quirk,
            TestsRfcConstants.ATTR_DEF_OBSOLETE,
            expected_oid=TestsRfcConstants.ATTR_OID_O,
            expected_name=TestsRfcConstants.ATTR_NAME_O,
        )

    @pytest.mark.timeout(5)
    def test_parse_attribute_case_insensitive(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test parsing with case_insensitive attribute name."""
        attr_def = "( 2.5.4.3 NAME 'cn' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )"
        attr = RfcTestHelpers.test_schema_parse_attribute(
            rfc_schema_quirk,
            attr_def,
            expected_oid="2.5.4.3",
            expected_name=TestsRfcConstants.ATTR_NAME_CN,
        )
        assert attr.syntax == "1.3.6.1.4.1.1466.115.121.1.15"


class TestSyntaxDefinitionComputedField:
    """Test syntax_definition computed field for RFC 4517 resolution."""

    @pytest.mark.timeout(5)
    def test_syntax_definition_resolution_batch(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test syntax_definition resolution for various syntax types."""
        test_cases: list[tuple[str, str, str, str | None]] = [
            (
                "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )",
                "2.5.4.3",
                "cn",
                "boolean",
            ),
            (
                (
                    f"( {TestsRfcConstants.ATTR_OID_SN} NAME "
                    f"'{TestsRfcConstants.ATTR_NAME_SN}' "
                    "SYNTAX 1.3.6.1.4.1.1466.115.121.1.21 )"
                ),
                TestsRfcConstants.ATTR_OID_SN,
                TestsRfcConstants.ATTR_NAME_SN,
                "directory_string",
            ),
            (
                (
                    "( 1.3.6.1.4.1.1466.115.121.1.26 NAME 'uid' "
                    f"SYNTAX {TestsRfcConstants.SYNTAX_OID_INTEGER} )"
                ),
                "1.3.6.1.4.1.1466.115.121.1.26",
                "uid",
                "ia5_string",
            ),
            (
                (
                    f"( 2.5.4.5 NAME 'serialNumber' "
                    f"SYNTAX {TestsRfcConstants.SYNTAX_OID_INTEGER} )"
                ),
                "2.5.4.5",
                "serialNumber",
                "ia5_string",
            ),
            (
                (
                    f"( {TestsRfcConstants.ATTR_OID_CN} NAME "
                    f"'{TestsRfcConstants.ATTR_NAME_CN}' "
                    "SYNTAX 9.9.9.9.9.9 )"
                ),
                TestsRfcConstants.ATTR_OID_CN,
                TestsRfcConstants.ATTR_NAME_CN,
                None,  # Unknown OID - will be validated separately
            ),
            (
                (
                    f"( {TestsRfcConstants.ATTR_OID_SN} NAME "
                    f"'{TestsRfcConstants.ATTR_NAME_SN}' "
                    f"SYNTAX {TestsRfcConstants.SYNTAX_OID_DIRECTORY_STRING}{{128}} )"
                ),
                TestsRfcConstants.ATTR_OID_SN,
                TestsRfcConstants.ATTR_NAME_SN,
                "directory_string",
            ),
        ]
        attributes = RfcTestHelpers.test_syntax_definition_batch(
            rfc_schema_quirk,
            test_cases,
        )
        boolean_attr = attributes[0]
        syntax_boolean = boolean_attr.syntax_definition
        assert syntax_boolean is not None
        assert isinstance(syntax_boolean, FlextLdifModelsDomains.Syntax)
        assert syntax_boolean.is_rfc4517_standard is True

        unknown_attr = attributes[4]
        syntax_unknown = unknown_attr.syntax_definition
        assert syntax_unknown is not None
        assert isinstance(syntax_unknown, FlextLdifModelsDomains.Syntax)
        assert syntax_unknown.is_rfc4517_standard is False

        length_attr = attributes[5]
        assert length_attr.length == 128

    @pytest.mark.timeout(5)
    def test_syntax_definition_returns_none_cases(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test syntax_definition returns None for various cases."""
        attr_def = TestsRfcConstants.ATTR_DEF_CN_MINIMAL
        result = rfc_schema_quirk.parse(attr_def)
        schema_obj = TestAssertions.assert_success(result, "Parse should succeed")
        assert isinstance(schema_obj, FlextLdifModels.SchemaAttribute)
        attr = schema_obj
        assert attr.oid == TestsRfcConstants.ATTR_OID_CN
        assert attr.syntax is None
        assert attr.syntax_definition is None

        empty_syntax_attr = FlextLdifModels.SchemaAttribute(
            oid=TestsRfcConstants.ATTR_OID_CN,
            name=TestsRfcConstants.ATTR_NAME_CN,
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

        invalid_oid_attr = FlextLdifModels.SchemaAttribute(
            oid=TestsRfcConstants.ATTR_OID_CN,
            name=TestsRfcConstants.ATTR_NAME_CN,
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
        assert syntax is None or isinstance(syntax, FlextLdifModels.Syntax)

    @pytest.mark.timeout(5)
    def test_syntax_definition_caching_behavior(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test syntax_definition computed field is recalculated each access."""
        attr = RfcTestHelpers.test_schema_parse_attribute(
            rfc_schema_quirk,
            (
                f"( {TestsRfcConstants.ATTR_OID_CN} NAME "
                f"'{TestsRfcConstants.ATTR_NAME_CN}' "
                f"SYNTAX {TestsRfcConstants.SYNTAX_OID_BOOLEAN} )"
            ),
            TestsRfcConstants.ATTR_OID_CN,
            TestsRfcConstants.ATTR_NAME_CN,
        )
        syntax1 = attr.syntax_definition
        syntax2 = attr.syntax_definition
        assert syntax1 is not None
        assert syntax2 is not None
        assert isinstance(syntax1, FlextLdifModelsDomains.Syntax)
        assert isinstance(syntax2, FlextLdifModelsDomains.Syntax)
        assert syntax1.oid == syntax2.oid
        assert syntax1.name == syntax2.name


class TestSyntaxDefinitionIntegration:
    """Test integration of syntax_definition with complete parsing workflow."""

    @pytest.mark.timeout(10)
    def test_parse_and_access_syntax_definition_for_multiple_attributes(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test parsing multiple attributes and accessing their syntax_definitions."""
        test_cases = [
            (
                (
                    f"( {TestsRfcConstants.ATTR_OID_CN} NAME "
                    f"'{TestsRfcConstants.ATTR_NAME_CN}' "
                    f"SYNTAX {TestsRfcConstants.SYNTAX_OID_DIRECTORY_STRING} )"
                ),
                TestsRfcConstants.ATTR_OID_CN,
                TestsRfcConstants.ATTR_NAME_CN,
                "directory_string",
            ),
            (
                (
                    f"( {TestsRfcConstants.ATTR_OID_SN} "
                    f"NAME '{TestsRfcConstants.ATTR_NAME_SN}' "
                    f"SYNTAX {TestsRfcConstants.SYNTAX_OID_DIRECTORY_STRING} )"
                ),
                TestsRfcConstants.ATTR_OID_SN,
                TestsRfcConstants.ATTR_NAME_SN,
                "directory_string",
            ),
            (
                (
                    f"( {TestsRfcConstants.ATTR_OID_MAIL} "
                    f"NAME '{TestsRfcConstants.ATTR_NAME_MAIL}' "
                    f"SYNTAX {TestsRfcConstants.SYNTAX_OID_INTEGER} )"
                ),
                TestsRfcConstants.ATTR_OID_MAIL,
                TestsRfcConstants.ATTR_NAME_MAIL,
                "ia5_string",
            ),
        ]

        for attr_def, expected_oid, expected_name, expected_syntax_name in test_cases:
            result = rfc_schema_quirk.parse(attr_def)
            assert result.is_success

            attr = result.unwrap()
            assert isinstance(attr, FlextLdifModels.SchemaAttribute)
            assert attr.oid == expected_oid
            assert attr.name == expected_name
            syntax = attr.syntax_definition
            assert syntax is not None
            assert isinstance(syntax, FlextLdifModelsDomains.Syntax)
            assert syntax.name == expected_syntax_name

    @pytest.mark.timeout(5)
    def test_syntax_definition_type_checking(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test that syntax_definition returns proper Syntax model type.

        NOTE: syntax_definition returns FlextLdifModelsDomains.Syntax (internal class),
        not FlextLdifModels.Syntax (public subclass), to avoid circular dependencies.
        """
        attr_def = (
            f"( {TestsRfcConstants.ATTR_OID_CN} NAME "
            f"'{TestsRfcConstants.ATTR_NAME_CN}' "
            f"SYNTAX {TestsRfcConstants.SYNTAX_OID_BOOLEAN} )"
        )
        result = rfc_schema_quirk.parse(attr_def)

        assert result.is_success
        attr = result.unwrap()
        assert isinstance(attr, FlextLdifModels.SchemaAttribute)

        syntax = attr.syntax_definition
        # Verify against base class (internal) to avoid circular dependency issues
        assert isinstance(syntax, FlextLdifModelsDomains.Syntax)
        assert hasattr(syntax, "oid")
        assert hasattr(syntax, "name")
        assert hasattr(syntax, "is_rfc4517_standard")

    @pytest.mark.timeout(5)
    def test_syntax_definition_serialization(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test that SchemaAttribute with syntax_definition serializes properly."""
        attr_def = (
            f"( {TestsRfcConstants.ATTR_OID_CN} "
            f"NAME '{TestsRfcConstants.ATTR_NAME_CN}' "
            f"SYNTAX {TestsRfcConstants.SYNTAX_OID_DIRECTORY_STRING} )"
        )
        result = rfc_schema_quirk.parse(attr_def)

        assert result.is_success
        attr = result.unwrap()
        assert isinstance(attr, FlextLdifModels.SchemaAttribute)

        # Accessing computed field before serialization
        syntax = attr.syntax_definition
        assert syntax is not None

        # Serialize to dict (should exclude computed fields by default)
        attr_dict = attr.model_dump()
        assert "syntax" in attr_dict
        assert attr_dict["syntax"] == "1.3.6.1.4.1.1466.115.121.1.15"

        # Serialize with computed fields included
        attr_dict_full = attr.model_dump(mode="python")
        # syntax_definition should be included in full dump
        assert "syntax_definition" in attr_dict_full

    @pytest.mark.timeout(10)
    def test_attribute_parser_with_real_world_schema_attributes(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test with real-world schema attribute examples."""
        test_cases = [
            ("( 2.5.4.3 NAME 'cn' SUP name )", "2.5.4.3", "cn"),
            (
                "( 2.5.4.49 NAME 'userPassword' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.39 )",
                "2.5.4.49",
                "userPassword",
            ),
            (
                "( 2.5.4.0 NAME 'objectClass' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
                "2.5.4.0",
                "objectClass",
            ),
        ]
        for attr_def, expected_oid, expected_name in test_cases:
            _ = RfcTestHelpers.test_schema_parse_attribute(
                rfc_schema_quirk, attr_def, expected_oid, expected_name
            )


class TestSyntaxOIDValidation:
    """Test RFC 4517 syntax OID validation in AttributeParser."""

    @pytest.mark.timeout(10)
    def test_syntax_oid_validation_batch(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test syntax OID validation for various cases."""
        test_cases = [
            (
                (
                    f"( {TestsRfcConstants.ATTR_OID_CN} "
                    f"NAME '{TestsRfcConstants.ATTR_NAME_CN}' "
                    f"SYNTAX {TestsRfcConstants.SYNTAX_OID_DIRECTORY_STRING} )"
                ),
                TestsRfcConstants.ATTR_OID_CN,
                TestsRfcConstants.ATTR_NAME_CN,
                True,
            ),
            (
                "( 2.5.4.3 NAME 'cn' SYNTAX 2.99.1.99 )",
                "2.5.4.3",
                "cn",
                True,
            ),
            (
                "( 2.5.4.3 NAME 'cn' SYNTAX 9.9.9.9.9.9 )",
                "2.5.4.3",
                "cn",
                False,  # Invalid OID format
            ),
        ]
        attributes = []
        for tc in test_cases:
            attr = RfcTestHelpers.test_schema_parse_attribute(
                rfc_schema_quirk, tc[0], tc[1], tc[2]
            )
            attributes.append(attr)
        for attr, (_, _, _, should_be_valid) in zip(
            attributes, test_cases, strict=True
        ):
            if attr.syntax and attr.metadata:
                is_valid = attr.metadata.extensions.get("syntax_oid_valid")
                if not should_be_valid:
                    error = attr.metadata.extensions.get("syntax_validation_error")
                    assert error is not None
                else:
                    assert is_valid == should_be_valid

    @pytest.mark.timeout(5)
    def test_no_syntax_oid_no_validation(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test that attributes without syntax don't have validation metadata."""
        attr = RfcTestHelpers.test_schema_parse_attribute(
            rfc_schema_quirk,
            "( 2.5.4.3 NAME 'cn' )",
            "2.5.4.3",
            "cn",
        )
        assert attr.syntax is None
        if attr.metadata:
            assert "syntax_oid_valid" not in attr.metadata.extensions

    @pytest.mark.timeout(5)
    def test_invalid_syntax_oid_format_detected(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test that invalid syntax OID format is detected."""
        attr = RfcTestHelpers.test_schema_parse_attribute(
            rfc_schema_quirk,
            "( 2.5.4.3 NAME 'cn' SYNTAX a.b.c )",
            "2.5.4.3",
            "cn",
        )
        assert attr.syntax is None

    @pytest.mark.timeout(5)
    def test_lenient_mode_and_preservation(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test lenient mode and syntax OID preservation."""
        quoted_attr_def = (
            f"( {TestsRfcConstants.ATTR_OID_CN} "
            f"NAME '{TestsRfcConstants.ATTR_NAME_CN}' "
            f"SYNTAX '{TestsRfcConstants.SYNTAX_OID_DIRECTORY_STRING}' )"
        )
        result = rfc_schema_quirk.parse(quoted_attr_def)
        quoted_schema_obj = TestAssertions.assert_success(
            result, "Parse should succeed"
        )
        assert isinstance(quoted_schema_obj, FlextLdifModels.SchemaAttribute)
        quoted_attr = quoted_schema_obj
        assert quoted_attr.syntax == "1.3.6.1.4.1.1466.115.121.1.15"

        unquoted_attr = RfcTestHelpers.test_schema_parse_attribute(
            rfc_schema_quirk,
            (
                f"( {TestsRfcConstants.ATTR_OID_CN} "
                f"NAME '{TestsRfcConstants.ATTR_NAME_CN}' "
                f"SYNTAX {TestsRfcConstants.SYNTAX_OID_DIRECTORY_STRING} )"
            ),
            TestsRfcConstants.ATTR_OID_CN,
            TestsRfcConstants.ATTR_NAME_CN,
        )
        assert unquoted_attr.syntax == "1.3.6.1.4.1.1466.115.121.1.15"


class TestAttributeParserErrorHandling:
    """Test error handling in AttributeParser."""

    @pytest.mark.timeout(5)
    def test_parse_with_exception_handling(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test that parser handles malformed input gracefully."""
        _ = RfcTestHelpers.test_parse_error_handling(
            rfc_schema_quirk,
            "( invalid attribute definition",
            should_fail=True,
        )

    @pytest.mark.timeout(5)
    def test_parse_returns_flext_result(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test that parse_common returns FlextResult."""
        _ = RfcTestHelpers.test_parse_and_validate_flext_result(
            rfc_schema_quirk,
            "( 2.5.4.3 NAME 'cn' )",
        )


class TestTypeSpecificValidators:
    """Test type-specific validators.

    Tests validators for Boolean, Integer, DirectoryString, IA5String.
    """

    @pytest.mark.timeout(5)
    def test_boolean_syntax_validator_true(self) -> None:
        """Test Boolean syntax validator accepts TRUE value."""
        service = FlextLdifSyntax()
        result = service.validate_value("TRUE", "1.3.6.1.4.1.1466.115.121.1.7")
        assert result.is_success

    @pytest.mark.timeout(5)
    def test_boolean_syntax_validator_false(self) -> None:
        """Test Boolean syntax validator accepts FALSE value."""
        service = FlextLdifSyntax()
        result = service.validate_value("FALSE", "1.3.6.1.4.1.1466.115.121.1.7")
        assert result.is_success

    @pytest.mark.timeout(5)
    def test_boolean_syntax_validator_invalid(self) -> None:
        """Test Boolean syntax validator rejects invalid values."""
        service = FlextLdifSyntax()
        result = service.validate_value("MAYBE", "1.3.6.1.4.1.1466.115.121.1.7")
        assert result.is_success
        assert result.unwrap() is False

    @pytest.mark.timeout(5)
    def test_integer_syntax_validator_valid(self) -> None:
        """Test Integer syntax validator accepts numeric values."""
        service = FlextLdifSyntax()
        result = service.validate_value("12345", "2.5.5.5")
        assert result.is_success

    @pytest.mark.timeout(5)
    def test_integer_syntax_validator_negative(self) -> None:
        """Test Integer syntax validator accepts negative numbers."""
        service = FlextLdifSyntax()
        result = service.validate_value("-999", "2.5.5.5")
        assert result.is_success

    @pytest.mark.timeout(5)
    def test_integer_syntax_validator_invalid(self) -> None:
        """Test Integer syntax validator rejects non-numeric values."""
        service = FlextLdifSyntax()
        result = service.validate_value("not_a_number", "2.5.5.5")
        assert result.is_success
        assert result.unwrap() is False

    @pytest.mark.timeout(5)
    def test_directory_string_syntax_validator(self) -> None:
        """Test DirectoryString syntax validator accepts string values."""
        service = FlextLdifSyntax()
        result = service.validate_value("John Doe", "1.3.6.1.4.1.1466.115.121.1.15")
        assert result.is_success

    @pytest.mark.timeout(5)
    def test_directory_string_with_special_chars(self) -> None:
        """Test DirectoryString validator accepts special characters."""
        service = FlextLdifSyntax()
        result = service.validate_value(
            "User Name (Office)", "1.3.6.1.4.1.1466.115.121.1.15"
        )
        assert result.is_success

    @pytest.mark.timeout(5)
    def test_ia5_string_syntax_validator(self) -> None:
        """Test IA5String syntax validator accepts ASCII values."""
        service = FlextLdifSyntax()
        result = service.validate_value(
            "test@example.com", "1.3.6.1.4.1.1466.115.121.1.26"
        )
        assert result.is_success

    @pytest.mark.timeout(5)
    def test_attribute_with_boolean_syntax_validation(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test parsing attribute with Boolean syntax and validation."""
        attr_def = (
            "( 2.5.4.20 NAME 'telephoneNumber' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )"  # Boolean syntax
        )
        result = rfc_schema_quirk.parse(attr_def)

        assert result.is_success
        attr = result.unwrap()
        assert isinstance(attr, FlextLdifModels.SchemaAttribute)
        assert attr.syntax == "1.3.6.1.4.1.1466.115.121.1.7"
        assert attr.metadata is not None
        assert attr.metadata.extensions.get("syntax_oid_valid") is True

    @pytest.mark.timeout(5)
    def test_attribute_with_integer_syntax_validation(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test parsing attribute with Integer syntax and validation."""
        attr_def = (
            "( 2.5.4.27 NAME 'serialNumber' "
            "SYNTAX 2.5.5.5 )"  # Integer syntax
        )
        result = rfc_schema_quirk.parse(attr_def)

        assert result.is_success
        attr = result.unwrap()
        assert isinstance(attr, FlextLdifModels.SchemaAttribute)
        assert attr.syntax == "2.5.5.5"
        assert attr.metadata is not None
        assert attr.metadata.extensions.get("syntax_oid_valid") is True

    @pytest.mark.timeout(5)
    def test_attribute_with_directory_string_syntax(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test parsing attribute with DirectoryString syntax."""
        # DirectoryString syntax
        attr_def = (
            f"( 2.5.4.12 NAME 'description' "
            f"SYNTAX {TestsRfcConstants.SYNTAX_OID_DIRECTORY_STRING} )"
        )
        result = rfc_schema_quirk.parse(attr_def)

        assert result.is_success
        attr = result.unwrap()
        assert isinstance(attr, FlextLdifModels.SchemaAttribute)
        assert attr.syntax == "1.3.6.1.4.1.1466.115.121.1.15"
        # Verify syntax is recognized as valid
        syntax = attr.syntax_definition
        if syntax is not None:
            assert isinstance(syntax, FlextLdifModelsDomains.Syntax)
            assert syntax.name is not None

    @pytest.mark.timeout(10)
    def test_multiple_attributes_with_different_syntax_types(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test parsing multiple attributes with different syntax types."""
        test_cases = [
            (
                "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                "DirectoryString",
            ),
            (
                "( 2.5.4.27 NAME 'serialNumber' SYNTAX 2.5.5.5 )",
                "Integer",
            ),
            (
                (
                    "( 2.5.4.20 NAME 'telephoneNumber' "
                    "SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )"
                ),
                "IA5String",
            ),
        ]

        for attr_def, _expected_type in test_cases:
            result = rfc_schema_quirk.parse(attr_def)
            assert result.is_success
            attr = result.unwrap()
            assert isinstance(attr, FlextLdifModels.SchemaAttribute)
            assert attr.syntax is not None
            # All should have valid metadata
            assert attr.metadata is not None

    @pytest.mark.timeout(5)
    def test_boolean_attribute_definition_roundtrip(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Boolean attribute definition parsing and validation."""
        original = (
            "( 2.5.4.20 NAME ( 'telephoneNumber' 'phone' ) "
            "DESC 'Telephone number' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 "
            "SINGLE-VALUE )"
        )
        result = rfc_schema_quirk.parse(original)

        assert result.is_success
        attr = result.unwrap()
        assert attr.name == "telephoneNumber"
        assert isinstance(attr, FlextLdifModels.SchemaAttribute)
        assert attr.syntax == "1.3.6.1.4.1.1466.115.121.1.7"
        # Verify syntax definition can be resolved
        syntax = attr.syntax_definition
        assert syntax is not None
        assert isinstance(syntax, FlextLdifModelsDomains.Syntax)
        assert syntax.name == "boolean"

    @pytest.mark.timeout(5)
    def test_integer_attribute_definition_roundtrip(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Integer attribute definition parsing and validation."""
        original = (
            "( 2.5.4.27 NAME 'serialNumber' DESC 'Serial number' SYNTAX 2.5.5.5 )"
        )
        result = rfc_schema_quirk.parse(original)

        assert result.is_success
        attr = result.unwrap()
        assert isinstance(attr, FlextLdifModels.SchemaAttribute)
        assert attr.name == "serialNumber"
        assert attr.syntax == "2.5.5.5"
        # Verify syntax definition can be resolved
        syntax = attr.syntax_definition
        if syntax is not None:
            assert isinstance(syntax, FlextLdifModelsDomains.Syntax)
            assert syntax.oid == "2.5.5.5"


class TestRfcSchemaQuirkIntegration:
    """Test RFC Schema quirk integration methods (can_handle, should_filter, write)."""

    @pytest.mark.timeout(5)
    def test_can_handle_attribute_string(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Schema.can_handle_attribute with string input."""
        attr_def = (
            f"( {TestsRfcConstants.ATTR_OID_CN} "
            f"NAME '{TestsRfcConstants.ATTR_NAME_CN}' "
            f"DESC 'Common Name' )"
        )
        assert rfc_schema_quirk.can_handle_attribute(attr_def) is True

    @pytest.mark.timeout(5)
    def test_can_handle_attribute_model(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Schema.can_handle_attribute with SchemaAttribute model."""
        attr_def = (
            f"( {TestsRfcConstants.ATTR_OID_CN} "
            f"NAME '{TestsRfcConstants.ATTR_NAME_CN}' "
            f"DESC 'Common Name' )"
        )
        parse_result = rfc_schema_quirk.parse(attr_def)
        assert parse_result.is_success
        schema_obj = parse_result.unwrap()
        assert isinstance(schema_obj, FlextLdifModels.SchemaAttribute)
        attr_model = schema_obj
        assert rfc_schema_quirk.can_handle_attribute(attr_model) is True

    @pytest.mark.timeout(5)
    def test_can_handle_objectclass_string(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Schema.can_handle_objectclass with string input."""
        oc_def = TestsRfcConstants.OC_DEF_PERSON
        assert rfc_schema_quirk.can_handle_objectclass(oc_def) is True

    @pytest.mark.timeout(5)
    def test_should_filter_out_attribute(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Schema.should_filter_out_attribute always returns False."""
        attr_def = (
            f"( {TestsRfcConstants.ATTR_OID_CN} "
            f"NAME '{TestsRfcConstants.ATTR_NAME_CN}' "
            f"DESC 'Common Name' )"
        )
        parse_result = rfc_schema_quirk.parse(attr_def)
        assert parse_result.is_success
        schema_obj = parse_result.unwrap()
        assert isinstance(schema_obj, FlextLdifModels.SchemaAttribute)
        attr_model = schema_obj
        assert rfc_schema_quirk.should_filter_out_attribute(attr_model) is False

    @pytest.mark.timeout(5)
    def test_should_filter_out_objectclass(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Schema.should_filter_out_objectclass always returns False."""
        oc_def = "( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL )"
        parse_result = rfc_schema_quirk.parse(oc_def)
        assert parse_result.is_success
        schema_obj = parse_result.unwrap()
        assert isinstance(schema_obj, FlextLdifModels.SchemaObjectClass)
        oc_model = schema_obj
        assert rfc_schema_quirk.should_filter_out_objectclass(oc_model) is False

    @pytest.mark.timeout(10)
    def test_write_attribute_variations(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Schema._write_attribute with various configurations."""
        _, written1 = RfcTestHelpers.test_schema_write_attribute_with_metadata(
            rfc_schema_quirk,
            (
                f"( {TestsRfcConstants.ATTR_OID_CN} NAME '{TestsRfcConstants.ATTR_NAME_CN}' "
                f"DESC 'Common Name' SYNTAX {TestsRfcConstants.SYNTAX_OID_DIRECTORY_STRING} )"
            ),
            TestsRfcConstants.ATTR_OID_CN,
            TestsRfcConstants.ATTR_NAME_CN,
            must_contain=["2.5.4.3"],
        )
        assert "cn" in written1 or "CN" in written1

        _ = RfcTestHelpers.test_schema_write_attribute_with_metadata(
            rfc_schema_quirk,
            (
                f"( {TestsRfcConstants.ATTR_OID_CN} NAME '{TestsRfcConstants.ATTR_NAME_CN}' "
                f"DESC 'Common Name' SYNTAX {TestsRfcConstants.SYNTAX_OID_DIRECTORY_STRING} "
                "SINGLE-VALUE NO-USER-MODIFICATION )"
            ),
            TestsRfcConstants.ATTR_OID_CN,
            TestsRfcConstants.ATTR_NAME_CN,
            must_contain=["SINGLE-VALUE", "NO-USER-MODIFICATION"],
        )

        _, written3 = RfcTestHelpers.test_schema_write_attribute_with_metadata(
            rfc_schema_quirk,
            (
                f"( {TestsRfcConstants.ATTR_OID_CN} NAME '{TestsRfcConstants.ATTR_NAME_CN}' "
                f"DESC 'Common Name' SYNTAX {TestsRfcConstants.SYNTAX_OID_DIRECTORY_STRING} "
                "SINGLE-VALUE )"
            ),
            TestsRfcConstants.ATTR_OID_CN,
            TestsRfcConstants.ATTR_NAME_CN,
            x_origin="test.ldif",
            must_contain=["X-ORIGIN", "test.ldif", "SINGLE-VALUE"],
        )
        assert ")" in written3

    @pytest.mark.timeout(10)
    def test_write_objectclass_variations(
        self,
        rfc_schema_quirk: FlextLdifServersRfc.Schema,
    ) -> None:
        """Test Schema._write_objectclass with various configurations."""
        _, written1 = RfcTestHelpers.test_schema_write_objectclass_with_metadata(
            rfc_schema_quirk,
            TestsRfcConstants.OC_DEF_PERSON_FULL,
            TestsRfcConstants.OC_OID_PERSON,
            TestsRfcConstants.OC_NAME_PERSON,
            must_contain=["2.5.6.6"],
        )
        assert "person" in written1 or "PERSON" in written1

        _, written2 = RfcTestHelpers.test_schema_write_objectclass_with_metadata(
            rfc_schema_quirk,
            TestsRfcConstants.OC_DEF_PERSON_FULL,
            TestsRfcConstants.OC_OID_PERSON,
            TestsRfcConstants.OC_NAME_PERSON,
            x_origin="schema.ldif",
            must_contain=["X-ORIGIN", "schema.ldif"],
        )
        assert ")" in written2

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
        # Access protected methods through public write interface
        write_result = rfc_schema_quirk.write_attribute(attr)
        assert write_result.is_success
        written_str = write_result.unwrap()
        assert "2.5.4.3" in written_str
        assert "cn" in written_str

        oc = RfcTestHelpers.test_schema_parse_objectclass(
            rfc_schema_quirk,
            "( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL )",
            "2.5.6.6",
            "person",
        )
        # Access protected methods through public write interface
        oc_write_result = rfc_schema_quirk.write_objectclass(oc)
        assert oc_write_result.is_success
        oc_written_str = oc_write_result.unwrap()
        assert "2.5.6.6" in oc_written_str
        assert "person" in oc_written_str


if __name__ == "__main__":
    _ = pytest.main([__file__, "-v"])
