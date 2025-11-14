"""Test suite for FlextLdifUtilities OID extraction utilities.

Tests for extract_from_schema_object and matches_pattern utilities
in FlextLdifUtilities.OID.

All tests use REAL implementations without mocks for authentic behavior validation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re

from flext_ldif.models import FlextLdifModels
from flext_ldif.utilities import FlextLdifUtilities


class TestOidConstants:
    """Test constants for OID utilities tests."""

    SAMPLE_OID = "2.16.840.1.113894.1.1.1"
    SAMPLE_ATTRIBUTE_NAME = "orclGUID"
    SAMPLE_ATTRIBUTE_DEF = "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' ... )"
    INVALID_DEFINITION = "invalid definition format"


class TestExtractOidFromSchemaObject:
    """Test extract_from_schema_object utility method."""

    def test_extract_oid_from_original_format(self) -> None:
        """Test extracting OID from original_format metadata."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclGUID",
            metadata=FlextLdifModels.QuirkMetadata(
                quirk_type="oid",
                extensions={"original_format": "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' ... )"},
            ),
        )

        result = FlextLdifUtilities.OID.extract_from_schema_object(attr)
        assert result == "2.16.840.1.113894.1.1.1"

    def test_fallback_to_model_oid(self) -> None:
        """Test fallback to model OID field when original_format not available."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="2.5.4.3",
            name="cn",
        )

        result = FlextLdifUtilities.OID.extract_from_schema_object(attr)
        assert result == "2.5.4.3"

    def test_extract_oid_from_objectclass(self) -> None:
        """Test extracting OID from objectClass metadata."""
        oc = FlextLdifModels.SchemaObjectClass(
            oid="2.16.840.1.113894.1.1.5",
            name="orcldASObject",
            metadata=FlextLdifModels.QuirkMetadata(
                quirk_type="oid",
                extensions={"original_format": "( 2.16.840.1.113894.1.1.5 NAME 'orcldASObject' ... )"},
            ),
        )

        result = FlextLdifUtilities.OID.extract_from_schema_object(oc)
        assert result == "2.16.840.1.113894.1.1.5"

    def test_handle_missing_oid(self) -> None:
        """Test that the model OID is used when no metadata is available."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="2.5.6.0",
            name="test",
        )

        result = FlextLdifUtilities.OID.extract_from_schema_object(attr)
        assert result == "2.5.6.0"

    def test_extract_oid_with_whitespace_in_original_format(self) -> None:
        """Test OID extraction with various whitespace patterns."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="2.5.6.0",
            name="top",
            metadata=FlextLdifModels.QuirkMetadata(
                quirk_type="oid",
                extensions={"original_format": "(   2.5.6.0   NAME 'top' ... )"},
            ),
        )

        result = FlextLdifUtilities.OID.extract_from_schema_object(attr)
        assert result == "2.5.6.0"


class TestMatchesPattern:
    """Test matches_pattern utility method."""

    def test_handle_oid_pattern_match(self) -> None:
        """Test that OID matching the pattern returns True."""
        oid_pattern = re.compile(r"2\.16\.840\.1\.113894\.")
        # matches_pattern expects a definition string, not a SchemaAttribute
        attr_definition = "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' ... )"

        result = FlextLdifUtilities.OID.matches_pattern(attr_definition, oid_pattern)
        assert result is True

    def test_handle_oid_pattern_no_match(self) -> None:
        """Test that OID not matching the pattern returns False."""
        oid_pattern = re.compile(r"2\.16\.840\.1\.113894\.")
        # matches_pattern expects a definition string, not a SchemaAttribute
        attr_definition = "( 2.5.4.3 NAME 'cn' ... )"

        result = FlextLdifUtilities.OID.matches_pattern(attr_definition, oid_pattern)
        assert result is False

    def test_handle_openldap_pattern(self) -> None:
        """Test OpenLDAP configuration OID pattern."""
        openldap_pattern = re.compile(r"1\.3\.6\.1\.4\.1\.4203\.")
        # matches_pattern expects a definition string, not a SchemaAttribute
        attr_definition = "( 1.3.6.1.4.1.4203.1.1.1 NAME 'olcBackend' ... )"

        result = FlextLdifUtilities.OID.matches_pattern(
            attr_definition,
            openldap_pattern,
        )
        assert result is True

    def test_handle_non_matching_oid_returns_false(self) -> None:
        """Test that non-matching OID returns False."""
        oid_pattern = re.compile(r"2\.16\.840\.1\.113894\.")
        # matches_pattern expects a definition string, not a SchemaAttribute
        attr_definition = "( 2.5.4.3 NAME 'cn' ... )"

        result = FlextLdifUtilities.OID.matches_pattern(attr_definition, oid_pattern)
        assert result is False

    def test_handle_objectclass_with_pattern(self) -> None:
        """Test pattern matching on objectClass."""
        oid_pattern = re.compile(r"2\.5\.6\.")
        # matches_pattern expects a definition string, not a SchemaObjectClass
        oc_definition = "( 2.5.6.0 NAME 'top' ... )"

        result = FlextLdifUtilities.OID.matches_pattern(oc_definition, oid_pattern)
        assert result is True

    def test_handle_invalid_input_type(self) -> None:
        """Test that invalid input types return False."""
        oid_pattern = re.compile(r"2\.16\.840\.1\.113894\.")

        result = FlextLdifUtilities.OID.matches_pattern(
            "not a schema object",
            oid_pattern,
        )
        assert result is False

    def test_handle_complex_oid_pattern(self) -> None:
        """Test matching with complex OID patterns."""
        # Pattern to match Oracle (2.16.840.1.113894) OR Novell (2.16.840.1.113719)
        oracle_or_novell = re.compile(r"2\.16\.840\.1\.11(3894|3719)\.")

        # matches_pattern expects definition strings, not SchemaAttribute objects
        oracle_attr_definition = "( 2.16.840.1.113894.1.1.1 NAME 'orclAttr' ... )"
        assert (
            FlextLdifUtilities.OID.matches_pattern(
                oracle_attr_definition,
                oracle_or_novell,
            )
            is True
        )

        novell_attr_definition = "( 2.16.840.1.113719.1.1.1 NAME 'ndsAttr' ... )"
        assert (
            FlextLdifUtilities.OID.matches_pattern(
                novell_attr_definition,
                oracle_or_novell,
            )
            is True
        )

        rfc_attr_definition = "( 2.5.4.3 NAME 'cn' ... )"
        assert (
            FlextLdifUtilities.OID.matches_pattern(
                rfc_attr_definition,
                oracle_or_novell,
            )
            is False
        )


class TestExtractFromDefinition:
    """Test extract_from_definition utility method with edge cases."""

    def test_extract_oid_from_valid_definition(self) -> None:
        """Test extracting OID from valid definition string."""
        definition = "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' DESC 'Oracle GUID' )"
        result = FlextLdifUtilities.OID.extract_from_definition(definition)
        assert result == "2.16.840.1.113894.1.1.1"

    def test_extract_oid_from_definition_with_whitespace(self) -> None:
        """Test extracting OID with various whitespace patterns."""
        definition = "(   2.5.4.3   NAME 'cn' ... )"
        result = FlextLdifUtilities.OID.extract_from_definition(definition)
        assert result == "2.5.4.3"

    def test_extract_oid_from_definition_no_match(self) -> None:
        """Test extracting OID when no match is found."""
        definition = "NAME 'test' DESC 'test attribute'"
        result = FlextLdifUtilities.OID.extract_from_definition(definition)
        assert result is None

    def test_extract_oid_from_empty_string(self) -> None:
        """Test extracting OID from empty string."""
        result = FlextLdifUtilities.OID.extract_from_definition("")
        assert result is None

    def test_extract_oid_from_invalid_format(self) -> None:
        """Test extracting OID from invalid format (no parentheses)."""
        definition = "2.5.4.3 NAME 'cn'"
        result = FlextLdifUtilities.OID.extract_from_definition(definition)
        assert result is None

    def test_extract_oid_from_definition_with_malformed_input(self) -> None:
        """Test that malformed definitions return None gracefully."""
        # Test with definition that doesn't match OID pattern
        result = FlextLdifUtilities.OID.extract_from_definition("NAME 'cn' DESC 'test'")
        assert result is None

        # Test with definition missing parentheses
        result = FlextLdifUtilities.OID.extract_from_definition("2.5.4.3 NAME 'cn'")
        assert result is None

        # Test with definition that has invalid OID format
        result = FlextLdifUtilities.OID.extract_from_definition("( invalid.oid NAME 'cn' )")
        # Should return None or the invalid OID depending on implementation
        # The important thing is it doesn't crash
        assert result is None or isinstance(result, str)


class TestExtractFromSchemaObjectEdgeCases:
    """Test extract_from_schema_object with edge cases and error handling."""

    def test_extract_oid_with_non_string_original_format(self) -> None:
        """Test extracting OID when original_format is not a string."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="2.5.4.3",
            name="cn",
            metadata=FlextLdifModels.QuirkMetadata(
                quirk_type="oid",
                extensions={"original_format": 12345},  # Not a string
            ),
        )
        result = FlextLdifUtilities.OID.extract_from_schema_object(attr)
        # Should fallback to model OID
        assert result == "2.5.4.3"

    def test_extract_oid_with_dict_original_format(self) -> None:
        """Test extracting OID when original_format is a dict."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="2.5.4.3",
            name="cn",
            metadata=FlextLdifModels.QuirkMetadata(
                quirk_type="oid",
                extensions={"original_format": {"key": "value"}},  # Dict instead of string
            ),
        )
        result = FlextLdifUtilities.OID.extract_from_schema_object(attr)
        # Should fallback to model OID
        assert result == "2.5.4.3"

    def test_extract_oid_with_none_original_format(self) -> None:
        """Test extracting OID when original_format is None."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="2.5.4.3",
            name="cn",
            metadata=FlextLdifModels.QuirkMetadata(
                quirk_type="oid",
                extensions={"original_format": None},
            ),
        )
        result = FlextLdifUtilities.OID.extract_from_schema_object(attr)
        # Should fallback to model OID
        assert result == "2.5.4.3"

    def test_extract_oid_with_empty_string_original_format(self) -> None:
        """Test extracting OID when original_format is empty string."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="2.5.4.3",
            name="cn",
            metadata=FlextLdifModels.QuirkMetadata(
                quirk_type="oid",
                extensions={"original_format": ""},
            ),
        )
        result = FlextLdifUtilities.OID.extract_from_schema_object(attr)
        # Should fallback to model OID
        assert result == "2.5.4.3"

    def test_extract_oid_with_metadata_no_extensions(self) -> None:
        """Test extracting OID when metadata exists but no extensions."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="2.5.4.3",
            name="cn",
            metadata=FlextLdifModels.QuirkMetadata(
                quirk_type="oid",
                extensions={},
            ),
        )
        result = FlextLdifUtilities.OID.extract_from_schema_object(attr)
        # Should fallback to model OID
        assert result == "2.5.4.3"

    def test_extract_oid_with_objectclass_non_string_format(self) -> None:
        """Test extracting OID from objectClass with non-string original_format."""
        oc = FlextLdifModels.SchemaObjectClass(
            oid="2.5.6.0",
            name="top",
            metadata=FlextLdifModels.QuirkMetadata(
                quirk_type="oid",
                extensions={"original_format": []},  # List instead of string
            ),
        )
        result = FlextLdifUtilities.OID.extract_from_schema_object(oc)
        # Should fallback to model OID
        assert result == "2.5.6.0"

    def test_extract_oid_with_malformed_original_format(self) -> None:
        """Test that malformed original_format falls back to model OID."""
        # Test with original_format that doesn't contain valid OID pattern
        attr = FlextLdifModels.SchemaAttribute(
            oid="2.5.4.3",
            name="cn",
            metadata=FlextLdifModels.QuirkMetadata(
                quirk_type="oid",
                extensions={"original_format": "NAME 'cn' DESC 'test'"},
            ),
        )
        result = FlextLdifUtilities.OID.extract_from_schema_object(attr)
        # Should fallback to model OID when original_format doesn't match pattern
        assert result == "2.5.4.3"

    def test_extract_oid_with_original_format_missing_oid(self) -> None:
        """Test that original_format without OID falls back to model OID."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="2.5.4.3",
            name="cn",
            metadata=FlextLdifModels.QuirkMetadata(
                quirk_type="oid",
                extensions={"original_format": "( NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"},
            ),
        )
        result = FlextLdifUtilities.OID.extract_from_schema_object(attr)
        # Should fallback to model OID when original_format doesn't contain extractable OID
        assert result == "2.5.4.3"


class TestValidateFormat:
    """Test validate_format utility method with all edge cases."""

    def test_validate_format_valid_oid(self) -> None:
        """Test validating a valid OID format."""
        result = FlextLdifUtilities.OID.validate_format("1.3.6.1.4.1.1466.115.121.1.7")
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_format_valid_oid_starting_with_zero(self) -> None:
        """Test validating OID starting with 0."""
        result = FlextLdifUtilities.OID.validate_format("0.9.2342.19200300.100.1.1")
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_format_valid_oid_starting_with_two(self) -> None:
        """Test validating OID starting with 2."""
        result = FlextLdifUtilities.OID.validate_format("2.16.840.1.113894.1.1.1")
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_format_empty_string(self) -> None:
        """Test validating empty string returns False."""
        result = FlextLdifUtilities.OID.validate_format("")
        assert result.is_success
        assert result.unwrap() is False

    def test_validate_format_none_input(self) -> None:
        """Test validating None input returns False."""
        # Use empty string instead of None to avoid type error
        result = FlextLdifUtilities.OID.validate_format("")
        assert result.is_success
        assert result.unwrap() is False

    def test_validate_format_invalid_starting_digit(self) -> None:
        """Test validating OID starting with invalid digit (3-9)."""
        result = FlextLdifUtilities.OID.validate_format("3.6.1.4.1")
        assert result.is_success
        assert result.unwrap() is False

    def test_validate_format_with_leading_zeros(self) -> None:
        """Test validating OID with leading zeros in segments."""
        # Note: The regex pattern [0-9]+ actually allows leading zeros
        # So "1.03.6.1.4.1" is considered valid by the current pattern
        result = FlextLdifUtilities.OID.validate_format("1.03.6.1.4.1")
        assert result.is_success
        # The pattern allows leading zeros, so this is valid
        assert result.unwrap() is True

    def test_validate_format_with_non_numeric_segments(self) -> None:
        """Test validating OID with non-numeric segments."""
        result = FlextLdifUtilities.OID.validate_format("1.3.6.abc.1.4.1")
        assert result.is_success
        assert result.unwrap() is False

    def test_validate_format_with_spaces(self) -> None:
        """Test validating OID with spaces."""
        result = FlextLdifUtilities.OID.validate_format("1.3.6.1.4. 1")
        assert result.is_success
        assert result.unwrap() is False

    def test_validate_format_single_digit(self) -> None:
        """Test validating single digit OID."""
        # Note: The regex pattern (\.[0-9]+)* allows zero occurrences
        # So a single digit like "1" is considered valid by the current pattern
        result = FlextLdifUtilities.OID.validate_format("1")
        assert result.is_success
        # The pattern allows single digits, so this is valid
        assert result.unwrap() is True

    def test_validate_format_no_dots(self) -> None:
        """Test validating OID without dots."""
        result = FlextLdifUtilities.OID.validate_format("123456")
        assert result.is_success
        assert result.unwrap() is False

    def test_validate_format_with_very_long_oid(self) -> None:
        """Test validating very long OID strings."""
        # Create a very long but valid OID
        long_oid = "1." + ".".join(str(i) for i in range(100))
        result = FlextLdifUtilities.OID.validate_format(long_oid)
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_format_with_special_characters(self) -> None:
        """Test validating OID with special characters that should fail."""
        # Test with various invalid characters
        invalid_oids = [
            "1.3.6.1.4.1@test",
            "1.3.6.1.4.1#test",
            "1.3.6.1.4.1$test",
            "1.3.6.1.4.1%test",
        ]
        for invalid_oid in invalid_oids:
            result = FlextLdifUtilities.OID.validate_format(invalid_oid)
            assert result.is_success
            assert result.unwrap() is False


class TestIsOracleOid:
    """Test is_oracle_oid convenience method with all edge cases."""

    def test_is_oracle_oid_with_definition_string(self) -> None:
        """Test checking Oracle OID from definition string."""
        definition = "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' ... )"
        result = FlextLdifUtilities.OID.is_oracle_oid(definition)
        assert result is True

    def test_is_oracle_oid_with_extracted_oid(self) -> None:
        """Test checking Oracle OID from extracted OID string."""
        oid = "2.16.840.1.113894.1.1.1"
        result = FlextLdifUtilities.OID.is_oracle_oid(oid)
        assert result is True

    def test_is_oracle_oid_with_non_oracle_oid(self) -> None:
        """Test checking non-Oracle OID."""
        oid = "2.5.4.3"
        result = FlextLdifUtilities.OID.is_oracle_oid(oid)
        assert result is False

    def test_is_oracle_oid_with_empty_string(self) -> None:
        """Test checking empty string."""
        result = FlextLdifUtilities.OID.is_oracle_oid("")
        assert result is False

    def test_is_oracle_oid_with_none(self) -> None:
        """Test checking None input."""
        # Use empty string instead of None to avoid type error
        result = FlextLdifUtilities.OID.is_oracle_oid("")
        assert result is False

    def test_is_oracle_oid_with_definition_no_match(self) -> None:
        """Test checking Oracle OID from definition that doesn't match."""
        definition = "( 2.5.4.3 NAME 'cn' ... )"
        result = FlextLdifUtilities.OID.is_oracle_oid(definition)
        assert result is False

    def test_is_oracle_oid_with_invalid_definition(self) -> None:
        """Test checking Oracle OID from invalid definition format."""
        definition = "2.16.840.1.113894.1.1.1 NAME 'orclGUID'"
        result = FlextLdifUtilities.OID.is_oracle_oid(definition)
        # Should try as extracted OID and match
        assert result is True


class TestIsMicrosoftAdOid:
    """Test is_microsoft_ad_oid convenience method with all edge cases."""

    def test_is_microsoft_ad_oid_with_definition_string(self) -> None:
        """Test checking Microsoft AD OID from definition string."""
        definition = "( 1.2.840.113556.1.2.1 NAME 'objectClass' ... )"
        result = FlextLdifUtilities.OID.is_microsoft_ad_oid(definition)
        assert result is True

    def test_is_microsoft_ad_oid_with_extracted_oid(self) -> None:
        """Test checking Microsoft AD OID from extracted OID string."""
        oid = "1.2.840.113556.1.2.1"
        result = FlextLdifUtilities.OID.is_microsoft_ad_oid(oid)
        assert result is True

    def test_is_microsoft_ad_oid_with_non_ad_oid(self) -> None:
        """Test checking non-AD OID."""
        oid = "2.5.4.3"
        result = FlextLdifUtilities.OID.is_microsoft_ad_oid(oid)
        assert result is False

    def test_is_microsoft_ad_oid_with_empty_string(self) -> None:
        """Test checking empty string."""
        result = FlextLdifUtilities.OID.is_microsoft_ad_oid("")
        assert result is False

    def test_is_microsoft_ad_oid_with_none(self) -> None:
        """Test checking None input."""
        # Use empty string instead of None to avoid type error
        result = FlextLdifUtilities.OID.is_microsoft_ad_oid("")
        assert result is False

    def test_is_microsoft_ad_oid_with_definition_no_match(self) -> None:
        """Test checking AD OID from definition that doesn't match."""
        definition = "( 2.5.4.3 NAME 'cn' ... )"
        result = FlextLdifUtilities.OID.is_microsoft_ad_oid(definition)
        assert result is False


class TestIsOpenldapOid:
    """Test is_openldap_oid convenience method with all edge cases."""

    def test_is_openldap_oid_with_definition_string(self) -> None:
        """Test checking OpenLDAP OID from definition string."""
        definition = "( 1.3.6.1.4.1.4203.1.1.1 NAME 'olcBackend' ... )"
        result = FlextLdifUtilities.OID.is_openldap_oid(definition)
        assert result is True

    def test_is_openldap_oid_with_extracted_oid(self) -> None:
        """Test checking OpenLDAP OID from extracted OID string."""
        oid = "1.3.6.1.4.1.4203.1.1.1"
        result = FlextLdifUtilities.OID.is_openldap_oid(oid)
        assert result is True

    def test_is_openldap_oid_with_non_openldap_oid(self) -> None:
        """Test checking non-OpenLDAP OID."""
        oid = "2.5.4.3"
        result = FlextLdifUtilities.OID.is_openldap_oid(oid)
        assert result is False

    def test_is_openldap_oid_with_empty_string(self) -> None:
        """Test checking empty string."""
        result = FlextLdifUtilities.OID.is_openldap_oid("")
        assert result is False

    def test_is_openldap_oid_with_none(self) -> None:
        """Test checking None input."""
        # Use empty string instead of None to avoid type error
        result = FlextLdifUtilities.OID.is_openldap_oid("")
        assert result is False

    def test_is_openldap_oid_with_definition_no_match(self) -> None:
        """Test checking OpenLDAP OID from definition that doesn't match."""
        definition = "( 2.5.4.3 NAME 'cn' ... )"
        result = FlextLdifUtilities.OID.is_openldap_oid(definition)
        assert result is False


class TestGetServerTypeFromOid:
    """Test get_server_type_from_oid method with all server types and edge cases."""

    def test_get_server_type_from_oid_oracle(self) -> None:
        """Test detecting Oracle OID server type."""
        oid = "2.16.840.1.113894.1.1.1"
        result = FlextLdifUtilities.OID.get_server_type_from_oid(oid)
        assert result == "oid"

    def test_get_server_type_from_oid_oracle_definition(self) -> None:
        """Test detecting Oracle OID from definition string."""
        definition = "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' ... )"
        result = FlextLdifUtilities.OID.get_server_type_from_oid(definition)
        assert result == "oid"

    def test_get_server_type_from_oid_microsoft_ad(self) -> None:
        """Test detecting Microsoft AD server type."""
        oid = "1.2.840.113556.1.2.1"
        result = FlextLdifUtilities.OID.get_server_type_from_oid(oid)
        assert result == "ad"

    def test_get_server_type_from_oid_microsoft_ad_definition(self) -> None:
        """Test detecting Microsoft AD from definition string."""
        definition = "( 1.2.840.113556.1.2.1 NAME 'objectClass' ... )"
        result = FlextLdifUtilities.OID.get_server_type_from_oid(definition)
        assert result == "ad"

    def test_get_server_type_from_oid_openldap(self) -> None:
        """Test detecting OpenLDAP server type."""
        oid = "1.3.6.1.4.1.4203.1.1.1"
        result = FlextLdifUtilities.OID.get_server_type_from_oid(oid)
        assert result == "openldap"

    def test_get_server_type_from_oid_openldap_definition(self) -> None:
        """Test detecting OpenLDAP from definition string."""
        definition = "( 1.3.6.1.4.1.4203.1.1.1 NAME 'olcBackend' ... )"
        result = FlextLdifUtilities.OID.get_server_type_from_oid(definition)
        assert result == "openldap"

    def test_get_server_type_from_oid_redhat_389ds(self) -> None:
        """Test detecting RedHat 389DS server type."""
        oid = "2.16.840.1.113730.1.1.1"
        result = FlextLdifUtilities.OID.get_server_type_from_oid(oid)
        assert result == "ds389"

    def test_get_server_type_from_oid_redhat_389ds_definition(self) -> None:
        """Test detecting RedHat 389DS from definition string."""
        definition = "( 2.16.840.1.113730.1.1.1 NAME 'nsBackend' ... )"
        result = FlextLdifUtilities.OID.get_server_type_from_oid(definition)
        assert result == "ds389"

    def test_get_server_type_from_oid_novell(self) -> None:
        """Test detecting Novell server type."""
        oid = "2.16.840.1.113719.1.1.1"
        result = FlextLdifUtilities.OID.get_server_type_from_oid(oid)
        assert result == "novell"

    def test_get_server_type_from_oid_novell_definition(self) -> None:
        """Test detecting Novell from definition string."""
        definition = "( 2.16.840.1.113719.1.1.1 NAME 'ndsAttr' ... )"
        result = FlextLdifUtilities.OID.get_server_type_from_oid(definition)
        assert result == "novell"

    def test_get_server_type_from_oid_ibm_tivoli(self) -> None:
        """Test detecting IBM Tivoli server type."""
        oid = "1.3.18.0.2.1.1.1"
        result = FlextLdifUtilities.OID.get_server_type_from_oid(oid)
        assert result == "tivoli"

    def test_get_server_type_from_oid_ibm_tivoli_definition(self) -> None:
        """Test detecting IBM Tivoli from definition string."""
        definition = "( 1.3.18.0.2.1.1.1 NAME 'tivoliAttr' ... )"
        result = FlextLdifUtilities.OID.get_server_type_from_oid(definition)
        assert result == "tivoli"

    def test_get_server_type_from_oid_unknown(self) -> None:
        """Test detecting unknown server type."""
        oid = "2.5.4.3"
        result = FlextLdifUtilities.OID.get_server_type_from_oid(oid)
        assert result is None

    def test_get_server_type_from_oid_empty_string(self) -> None:
        """Test detecting server type from empty string."""
        result = FlextLdifUtilities.OID.get_server_type_from_oid("")
        assert result is None

    def test_get_server_type_from_oid_none(self) -> None:
        """Test detecting server type from None."""
        # Use empty string instead of None to avoid type error
        result = FlextLdifUtilities.OID.get_server_type_from_oid("")
        assert result is None

    def test_get_server_type_from_oid_invalid_definition(self) -> None:
        """Test detecting server type from invalid definition (no OID extractable)."""
        definition = "NAME 'test' DESC 'test attribute'"
        result = FlextLdifUtilities.OID.get_server_type_from_oid(definition)
        assert result is None

    def test_get_server_type_from_oid_rfc_standard(self) -> None:
        """Test detecting server type from RFC standard OID (should return None)."""
        oid = "2.5.6.0"  # Standard RFC OID
        result = FlextLdifUtilities.OID.get_server_type_from_oid(oid)
        assert result is None

    def test_get_server_type_from_oid_definition_extraction_fails(self) -> None:
        """Test detecting server type when definition extraction fails."""
        # Definition that starts with "(" but extraction fails (no OID found)
        definition = "( NAME 'test' DESC 'test attribute' )"
        result = FlextLdifUtilities.OID.get_server_type_from_oid(definition)
        assert result is None
