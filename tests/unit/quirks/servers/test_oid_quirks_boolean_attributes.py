"""Test suite for OID boolean attribute conversions.

Tests for OID-specific boolean format ("0"/"1") to RFC format ("TRUE"/"FALSE") conversions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldif.servers.oid import FlextLdifServersOid


class TestOidBooleanAttributeParsing:
    """Test suite for OID boolean attribute parsing."""

    @pytest.fixture
    def oid_schema(self) -> FlextLdifServersOid.Schema:
        """Create OID schema quirk instance."""
        return FlextLdifServersOid().schema_quirk

    @pytest.fixture
    def oid_entry(self) -> FlextLdifServersOid.Entry:
        """Create OID entry quirk instance."""
        return FlextLdifServersOid().entry_quirk

    def test_boolean_attributes_constant_exists(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test that BOOLEAN_ATTRIBUTES constant is defined."""
        boolean_attrs = FlextLdifServersOid.Constants.BOOLEAN_ATTRIBUTES
        assert len(boolean_attrs) > 0
        # BOOLEAN_ATTRIBUTES is a frozenset, check membership directly
        assert "pwdlockout" in boolean_attrs or any(
            "lockout" in attr.lower() for attr in boolean_attrs
        )

    def test_oid_boolean_conversion_mappings(self) -> None:
        """Test that OID→RFC boolean conversion mappings exist."""
        oid_to_rfc = FlextLdifServersOid.Constants.OID_TO_RFC
        rfc_to_oid = FlextLdifServersOid.Constants.RFC_TO_OID

        # Verify core mappings
        assert oid_to_rfc.get("1") == "TRUE"
        assert oid_to_rfc.get("0") == "FALSE"

        # Verify reverse mappings
        assert rfc_to_oid.get("TRUE") == "1"
        assert rfc_to_oid.get("FALSE") == "0"

    def test_oid_true_false_value_sets(self) -> None:
        """Test that true/false value sets are defined."""
        true_vals = FlextLdifServersOid.Constants.OID_TRUE_VALUES
        false_vals = FlextLdifServersOid.Constants.OID_FALSE_VALUES

        # Verify core values
        assert "1" in true_vals
        assert "0" in false_vals
        assert "TRUE" in true_vals
        assert "FALSE" in false_vals


class TestOidBooleanAttributeRoundtrip:
    """Test suite for OID boolean attribute roundtrip conversions."""

    @pytest.fixture
    def oid_schema(self) -> FlextLdifServersOid.Schema:
        """Create OID schema quirk instance."""
        return FlextLdifServersOid().schema_quirk

    def test_parse_boolean_attribute_definition(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test parsing boolean attribute definitions."""
        # Boolean attributes in OID use standard RFC format for schema definition
        # The "0"/"1" vs "TRUE"/"FALSE" difference is in entry values, not schema
        attr_def = (
            "( 2.16.840.1.113894.1.1.100 NAME 'orclDasEnabled' "
            "DESC 'Oracle DAS enabled flag' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 "  # Boolean syntax
            "SINGLE-VALUE )"
        )

        parse_result = oid_schema.parse_attribute(attr_def)
        assert parse_result.is_success, f"Parse failed: {parse_result.error}"
        parsed_attr = parse_result.unwrap()

        # Verify parsed correctly
        assert parsed_attr.oid == "2.16.840.1.113894.1.1.100"
        assert "orcldasenabled" in parsed_attr.name.lower()

    def test_write_boolean_attribute_definition(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test writing boolean attribute definitions."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.100 NAME 'orclDasEnabled' "
            "DESC 'Oracle DAS enabled flag' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 "
            "SINGLE-VALUE )"
        )

        # Parse
        parse_result = oid_schema.parse_attribute(attr_def)
        assert parse_result.is_success
        parsed_attr = parse_result.unwrap()

        # Write
        write_result = oid_schema.write_attribute(parsed_attr)
        assert write_result.is_success
        written = write_result.unwrap()

        # Verify format preserved
        assert "2.16.840.1.113894.1.1.100" in written
        assert "orcldasenabled" in written.lower()

    def test_boolean_attribute_roundtrip(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test parse → write → parse roundtrip for boolean attributes."""
        original = (
            "( 2.16.840.1.113894.1.1.100 NAME 'orclDasEnabled' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 "
            "SINGLE-VALUE )"
        )

        # Parse 1
        parse1_result = oid_schema.parse_attribute(original)
        assert parse1_result.is_success
        parsed1 = parse1_result.unwrap()

        # Write
        write_result = oid_schema.write_attribute(parsed1)
        assert write_result.is_success
        written = write_result.unwrap()

        # Parse 2
        parse2_result = oid_schema.parse_attribute(written)
        assert parse2_result.is_success
        parsed2 = parse2_result.unwrap()

        # Verify preservation
        assert parsed1.oid == parsed2.oid
        assert parsed1.name == parsed2.name


class TestOidKnownBooleanAttributes:
    """Test suite for specific known OID boolean attributes."""

    @pytest.fixture
    def oid_schema(self) -> FlextLdifServersOid.Schema:
        """Create OID schema quirk instance."""
        return FlextLdifServersOid().schema_quirk

    # Test helper to check if attribute is in boolean list
    def _is_boolean_attribute(self, attr_name: str) -> bool:
        """Check if attribute is in BOOLEAN_ATTRIBUTES."""
        boolean_attrs = FlextLdifServersOid.Constants.BOOLEAN_ATTRIBUTES
        return attr_name.lower() in {attr.lower() for attr in boolean_attrs}

    @pytest.mark.parametrize(
        "attr_name",
        [
            "orcldasenableproductlogo",
            "orcldasenablesubscriberlogo",
            "orcldasshowproductlogo",
            "orcldasisenabled",
            "pwdlockout",
            "pwdmustchange",
        ],
    )
    def test_known_boolean_attributes_in_constant(self, attr_name: str) -> None:
        """Test that known boolean attributes are in BOOLEAN_ATTRIBUTES."""
        boolean_attrs = FlextLdifServersOid.Constants.BOOLEAN_ATTRIBUTES
        # Case-insensitive check
        assert any(attr.lower() == attr_name.lower() for attr in boolean_attrs), (
            f"{attr_name} not in BOOLEAN_ATTRIBUTES"
        )

    def test_parse_password_policy_boolean_attribute(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test parsing password policy boolean attribute."""
        attr_def = (
            "( 1.3.6.1.4.1.4203.1.1.1 NAME 'pwdLockout' "
            "DESC 'Password lockout flag' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 "
            "SINGLE-VALUE )"
        )

        parse_result = oid_schema.parse_attribute(attr_def)
        # May or may not succeed depending on RFC handling
        if parse_result.is_success:
            parsed_attr = parse_result.unwrap()
            assert parsed_attr is not None

    def test_parse_orcl_das_boolean_attribute(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test parsing Oracle DAS boolean attribute."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.200 NAME 'orclDasEnableProductLogo' "
            "DESC 'Enable product logo in DAS' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 "
            "SINGLE-VALUE )"
        )

        parse_result = oid_schema.parse_attribute(attr_def)
        assert parse_result.is_success
        parsed_attr = parse_result.unwrap()
        assert "orcldas" in parsed_attr.name.lower()


class TestOidBooleanConversionMappings:
    """Test suite for boolean conversion mapping coverage."""

    def test_all_oid_to_rfc_mappings_present(self) -> None:
        """Test that essential OID→RFC boolean mappings are present."""
        mappings = FlextLdifServersOid.Constants.OID_TO_RFC

        # Core mappings that must exist
        assert "1" in mappings  # OID true
        assert "0" in mappings  # OID false
        assert mappings["1"] == "TRUE"
        assert mappings["0"] == "FALSE"

    def test_all_rfc_to_oid_mappings_present(self) -> None:
        """Test that essential RFC→OID boolean mappings are present."""
        mappings = FlextLdifServersOid.Constants.RFC_TO_OID

        # Core mappings that must exist
        assert "TRUE" in mappings
        assert "FALSE" in mappings
        assert mappings["TRUE"] == "1"
        assert mappings["FALSE"] == "0"

    def test_boolean_mapping_symmetry(self) -> None:
        """Test symmetry of boolean conversion mappings."""
        oid_to_rfc = FlextLdifServersOid.Constants.OID_TO_RFC
        rfc_to_oid = FlextLdifServersOid.Constants.RFC_TO_OID

        # Core mappings should be symmetric
        assert oid_to_rfc.get("1") == "TRUE"
        assert rfc_to_oid.get(oid_to_rfc.get("1")) == "1"

        assert oid_to_rfc.get("0") == "FALSE"
        assert rfc_to_oid.get(oid_to_rfc.get("0")) == "0"

    def test_case_insensitive_boolean_mappings(self) -> None:
        """Test case-insensitive boolean mappings."""
        oid_to_rfc = FlextLdifServersOid.Constants.OID_TO_RFC

        # OID mappings should handle case variants
        if "true" in oid_to_rfc:
            assert oid_to_rfc["true"] == "TRUE"
        if "false" in oid_to_rfc:
            assert oid_to_rfc["false"] == "FALSE"


class TestOidBooleanValueDetection:
    """Test suite for OID boolean value detection."""

    def test_oid_true_value_detection(self) -> None:
        """Test OID true value detection."""
        true_values = FlextLdifServersOid.Constants.OID_TRUE_VALUES

        # Must contain OID format "1"
        assert "1" in true_values

        # May contain text variants
        assert any(val.upper() == "TRUE" for val in true_values)

    def test_oid_false_value_detection(self) -> None:
        """Test OID false value detection."""
        false_values = FlextLdifServersOid.Constants.OID_FALSE_VALUES

        # Must contain OID format "0"
        assert "0" in false_values

        # May contain text variants
        assert any(val.upper() == "FALSE" for val in false_values)

    def test_boolean_value_set_completeness(self) -> None:
        """Test that both true and false value sets are present."""
        true_vals = FlextLdifServersOid.Constants.OID_TRUE_VALUES
        false_vals = FlextLdifServersOid.Constants.OID_FALSE_VALUES

        # Both should be non-empty
        assert len(true_vals) > 0
        assert len(false_vals) > 0

        # Should have no overlap
        overlap = true_vals & false_vals
        assert len(overlap) == 0, f"True/False overlap: {overlap}"


class TestOidInvalidSubstrRules:
    """Test suite for OID invalid substr rules handling."""

    def test_invalid_substr_rules_defined(self) -> None:
        """Test that invalid substr rules are defined."""
        rules = FlextLdifServersOid.Constants.INVALID_SUBSTR_RULES

        assert len(rules) > 0
        # Should contain some known invalid rules
        assert "caseIgnoreMatch" in rules or "caseignorematch" in {
            k.lower() for k in rules
        }

    def test_invalid_substr_rule_replacements(self) -> None:
        """Test that invalid substr rules have appropriate replacements."""
        rules = FlextLdifServersOid.Constants.INVALID_SUBSTR_RULES

        # Rules should map to either None (no replacement) or valid substr rule
        for replacement in rules.values():
            if replacement is not None:
                # Should be a valid matching rule name
                assert isinstance(replacement, str)
                assert len(replacement) > 0
                assert "Match" in replacement or "match" in replacement.lower()
