"""Test suite for OID syntax and matching rule transformations.

Tests for OID-to-OUD compatibility transformations including syntax OID replacements
and matching rule fixes.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re

import pytest

from flext_ldif.servers.oid import FlextLdifServersOid
from tests.fixtures.loader import FlextLdifFixtures


class TestOidSyntaxOidReplacements:
    """Test suite for OID syntax OID replacements (for OUD compatibility)."""

    @pytest.fixture
    def oid_schema(self) -> FlextLdifServersOid.Schema:
        """Create OID schema quirk instance."""
        return FlextLdifServersOid().schema_quirk

    def test_syntax_replacements_defined(self) -> None:
        """Test that syntax OID replacements are defined."""
        replacements = FlextLdifServersOid.Constants.SYNTAX_OID_TO_RFC

        assert len(replacements) > 0
        # Should contain at least ACI List → Directory String
        assert "1.3.6.1.4.1.1466.115.121.1.1" in replacements

    def test_aci_list_to_directory_string_replacement(self) -> None:
        """Test ACI List syntax is replaced with Directory String."""
        replacements = FlextLdifServersOid.Constants.SYNTAX_OID_TO_RFC

        aci_list_oid = "1.3.6.1.4.1.1466.115.121.1.1"
        directory_string_oid = "1.3.6.1.4.1.1466.115.121.1.15"

        assert replacements.get(aci_list_oid) == directory_string_oid

    def test_parse_applies_aci_list_replacement(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test that parsing applies ACI List → Directory String replacement."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclaci' "
            "DESC 'Oracle ACL' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.1 )"  # ACI List
        )

        parse_result = oid_schema.parse_attribute(attr_def)
        assert parse_result.is_success
        parsed_attr = parse_result.unwrap()

        # Verify replacement applied
        assert parsed_attr.syntax == "1.3.6.1.4.1.1466.115.121.1.15"

    def test_parse_preserves_unreplaced_syntax_oids(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test that parsing preserves syntax OIDs not in replacement table."""
        # Directory String syntax (should not be replaced)
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 NAME 'testAttr' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )

        parse_result = oid_schema.parse_attribute(attr_def)
        assert parse_result.is_success
        parsed_attr = parse_result.unwrap()

        # Verify preserved unchanged
        assert parsed_attr.syntax == "1.3.6.1.4.1.1466.115.121.1.15"

    def test_write_preserves_replaced_syntax_oids(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test that writing preserves replaced syntax OIDs."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 NAME 'testAttr' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.1 )"  # ACI List (will be replaced)
        )

        # Parse (applies replacement)
        parse_result = oid_schema.parse_attribute(attr_def)
        assert parse_result.is_success
        parsed_attr = parse_result.unwrap()

        # Write (should output replaced syntax)
        write_result = oid_schema.write_attribute(parsed_attr)
        assert write_result.is_success
        written = write_result.unwrap()

        # Verify replaced OID in output
        # Use word boundary check to avoid false positives from substring matching
        # Check replaced OID appears (with word boundaries)
        assert re.search(r"\b1\.3\.6\.1\.4\.1\.1466\.115\.121\.1\.15\b", written), (
            f"Expected replaced OID 1.3.6.1.4.1.1466.115.121.1.15 not found in: {written}"
        )
        # Check original OID does not appear (with word boundaries)
        assert not re.search(r"\b1\.3\.6\.1\.4\.1\.1466\.115\.121\.1\.1\b", written), (
            f"Original OID 1.3.6.1.4.1.1466.115.121.1.1 should not appear in: {written}"
        )


class TestOidMatchingRuleReplacements:
    """Test suite for OID matching rule replacements (for OUD compatibility)."""

    @pytest.fixture
    def oid_schema(self) -> FlextLdifServersOid.Schema:
        """Create OID schema quirk instance."""
        return FlextLdifServersOid().schema_quirk

    def test_matching_rule_replacements_defined(self) -> None:
        """Test that matching rule replacements are defined."""
        replacements = FlextLdifServersOid.Constants.MATCHING_RULE_TO_RFC

        assert len(replacements) > 0
        # Should contain at least caseIgnoreSubStringsMatch fix
        assert "caseIgnoreSubStringsMatch" in replacements

    def test_case_ignore_substr_fix_replacement(self) -> None:
        """Test caseIgnoreSubStringsMatch is fixed to caseIgnoreSubstringsMatch."""
        replacements = FlextLdifServersOid.Constants.MATCHING_RULE_TO_RFC

        # OID format has uppercase S in Strings: caseIgnoreSubStringsMatch
        # Should be fixed to: caseIgnoreSubstringsMatch (lowercase s)
        assert (
            replacements.get("caseIgnoreSubStringsMatch") == "caseIgnoreSubstringsMatch"
        )

    def test_access_directive_replacement(self) -> None:
        """Test accessDirectiveMatch is replaced with caseIgnoreMatch."""
        replacements = FlextLdifServersOid.Constants.MATCHING_RULE_TO_RFC

        # OID-specific rule: accessDirectiveMatch
        # Should be replaced with standard: caseIgnoreMatch
        if "accessDirectiveMatch" in replacements:
            assert replacements.get("accessDirectiveMatch") == "caseIgnoreMatch"

    def test_parse_applies_case_ignore_substr_fix(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test that parsing applies caseIgnoreSubStringsMatch fix."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 NAME 'testAttr' "
            "SUBSTR caseIgnoreSubStringsMatch "  # With uppercase S
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )

        parse_result = oid_schema.parse_attribute(attr_def)
        assert parse_result.is_success
        parsed_attr = parse_result.unwrap()

        # Verify fix applied
        assert parsed_attr.substr == "caseIgnoreSubstringsMatch"  # lowercase s

    def test_parse_preserves_standard_matching_rules(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test that parsing preserves standard matching rules."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 NAME 'testAttr' "
            "EQUALITY caseIgnoreMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )

        parse_result = oid_schema.parse_attribute(attr_def)
        assert parse_result.is_success
        parsed_attr = parse_result.unwrap()

        # Verify preserved unchanged
        assert parsed_attr.equality == "caseIgnoreMatch"

    def test_write_preserves_fixed_matching_rules(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test that writing preserves fixed matching rules."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 NAME 'testAttr' "
            "SUBSTR caseIgnoreSubStringsMatch "  # Will be fixed during parse
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )

        # Parse (applies fix)
        parse_result = oid_schema.parse_attribute(attr_def)
        assert parse_result.is_success
        parsed_attr = parse_result.unwrap()

        # Write (should output fixed rule)
        write_result = oid_schema.write_attribute(parsed_attr)
        assert write_result.is_success
        written = write_result.unwrap()

        # Verify fixed rule in output
        assert "caseIgnoreSubstringsMatch" in written  # lowercase s
        # Original incorrect form should not appear
        assert "caseIgnoreSubStringsMatch" not in written


class TestOidOudCompatibilityTransformations:
    """Test suite for OID→OUD compatibility transformations."""

    @pytest.fixture
    def oid_schema(self) -> FlextLdifServersOid.Schema:
        """Create OID schema quirk instance."""
        return FlextLdifServersOid().schema_quirk

    @pytest.fixture
    def oid_fixtures(self) -> FlextLdifFixtures.OID:
        """Create OID fixture loader."""
        return FlextLdifFixtures.OID()

    def test_roundtrip_applies_transformations(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test that roundtrip (parse → write) applies OUD transformations."""
        # Original has ACI List syntax
        original = (
            "( 2.16.840.1.113894.1.1.1 NAME 'testAttr' "
            "SUBSTR caseIgnoreSubStringsMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.1 )"  # ACI List, uppercase S
        )

        # Parse (applies fixes)
        parse_result = oid_schema.parse_attribute(original)
        assert parse_result.is_success
        parsed_attr = parse_result.unwrap()

        # Write (outputs fixed format)
        write_result = oid_schema.write_attribute(parsed_attr)
        assert write_result.is_success
        written = write_result.unwrap()

        # Verify transformations applied
        assert "caseIgnoreSubstringsMatch" in written  # Fixed capitalization
        assert "1.3.6.1.4.1.1466.115.121.1.15" in written  # Replaced syntax

    def test_real_fixture_transformations(
        self,
        oid_schema: FlextLdifServersOid.Schema,
        oid_fixtures: FlextLdifFixtures.OID,
    ) -> None:
        """Test transformations on real OID fixture attributes."""
        schema_content = oid_fixtures.schema()

        # Extract Oracle attributes from fixture
        oracle_attrs = [
            line
            for line in schema_content.splitlines()
            if "2.16.840.1.113894" in line and "attributetypes:" in line
        ]

        assert len(oracle_attrs) > 0

        # Test transformation on first attribute
        first_attr = oracle_attrs[0]
        attr_def = first_attr.split("attributetypes:", 1)[1].strip()

        # Parse (applies transformations)
        parse_result = oid_schema.parse_attribute(attr_def)
        assert parse_result.is_success
        parsed_attr = parse_result.unwrap()

        # Write (outputs transformed format)
        write_result = oid_schema.write_attribute(parsed_attr)
        assert write_result.is_success
        written = write_result.unwrap()

        # Verify basic format
        assert written.startswith("( ")
        assert written.rstrip().endswith(")")


class TestOidAttributeTransformations:
    """Test suite for OID attribute transformations."""

    def test_attribute_transformation_mappings_defined(self) -> None:
        """Test that attribute transformation mappings are defined."""
        oid_to_rfc = FlextLdifServersOid.Constants.ATTRIBUTE_TRANSFORMATION_OID_TO_RFC
        rfc_to_oid = FlextLdifServersOid.Constants.ATTRIBUTE_TRANSFORMATION_RFC_TO_OID

        assert len(oid_to_rfc) > 0
        assert len(rfc_to_oid) > 0

    def test_orclguid_transformation(self) -> None:
        """Test orclguid → entryUUID transformation mapping."""
        oid_to_rfc = FlextLdifServersOid.Constants.ATTRIBUTE_TRANSFORMATION_OID_TO_RFC

        assert oid_to_rfc.get("orclguid") == "entryUUID"

    def test_entryuuid_reverse_transformation(self) -> None:
        """Test entryUUID → orclguid reverse transformation mapping."""
        rfc_to_oid = FlextLdifServersOid.Constants.ATTRIBUTE_TRANSFORMATION_RFC_TO_OID

        assert rfc_to_oid.get("entryUUID") == "orclguid"


class TestOidTransformationCompleteness:
    """Test suite for completeness of OID transformations."""

    def test_all_replacements_have_valid_targets(self) -> None:
        """Test that all replacement mappings have valid target values."""
        # Syntax replacements
        syntax_repls = FlextLdifServersOid.Constants.SYNTAX_OID_TO_RFC
        for source, target in syntax_repls.items():
            # Both should be OID-like strings
            assert isinstance(source, str)
            assert isinstance(target, str)
            # OIDs should have dots
            assert "." in target, f"Invalid target syntax OID: {target}"

        # Matching rule replacements
        rule_repls = FlextLdifServersOid.Constants.MATCHING_RULE_TO_RFC
        for source, target in rule_repls.items():
            assert isinstance(source, str)
            assert isinstance(target, str)
            # Rules should have "Match" in name
            assert "match" in target.lower(), f"Invalid target rule: {target}"

    def test_no_circular_transformations(self) -> None:
        """Test that transformations don't create circular mappings."""
        syntax_repls = FlextLdifServersOid.Constants.SYNTAX_OID_TO_RFC

        for source, target in syntax_repls.items():
            # Target shouldn't map back to source
            reverse = syntax_repls.get(target)
            if reverse is not None:
                assert reverse != source, (
                    f"Circular transformation: {source} ↔ {target}"
                )

    def test_transformation_symmetry(self) -> None:
        """Test symmetry of bidirectional transformations."""
        oid_to_rfc = FlextLdifServersOid.Constants.ATTRIBUTE_TRANSFORMATION_OID_TO_RFC
        rfc_to_oid = FlextLdifServersOid.Constants.ATTRIBUTE_TRANSFORMATION_RFC_TO_OID

        # For orclguid ↔ entryUUID, should be bidirectional
        oid_mapping = oid_to_rfc.get("orclguid")
        if oid_mapping:
            rfc_mapping = rfc_to_oid.get(oid_mapping)
            # Should be able to round-trip
            if rfc_mapping:
                assert rfc_mapping == "orclguid"
