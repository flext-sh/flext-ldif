"""Test suite for OID syntax and matching rule transformations.

Tests for OID-to-OUD compatibility transformations including syntax OID replacements
and matching rule fixes.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import dataclasses
import re
from enum import StrEnum
from typing import cast

import pytest

from flext_ldif.servers.oid import FlextLdifServersOid
from tests.fixtures.loader import FlextLdifFixtures


class TransformationType(StrEnum):
    """OID transformation types."""

    SYNTAX = "syntax"
    MATCHING_RULE = "matching_rule"
    ATTRIBUTE = "attribute"


@dataclasses.dataclass(frozen=True)
class SyntaxReplacement:
    """Syntax OID replacement test case."""

    source_oid: str
    target_oid: str
    source_name: str
    target_name: str
    attr_definition: str


@dataclasses.dataclass(frozen=True)
class MatchingRuleReplacement:
    """Matching rule replacement test case."""

    source_rule: str
    target_rule: str
    attr_definition: str
    attr_field: str


@dataclasses.dataclass(frozen=True)
class AttributeTransformation:
    """Attribute transformation test case."""

    oid_name: str
    rfc_name: str


# Test data for syntax replacements
SYNTAX_REPLACEMENTS = (
    SyntaxReplacement(
        source_oid="1.3.6.1.4.1.1466.115.121.1.1",
        target_oid="1.3.6.1.4.1.1466.115.121.1.15",
        source_name="ACI List",
        target_name="Directory String",
        attr_definition=(
            "( 2.16.840.1.113894.1.1.1 NAME 'orclaci' "
            "DESC 'Oracle ACL' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.1 )"
        ),
    ),
)

# Test data for matching rule replacements
MATCHING_RULE_REPLACEMENTS = (
    MatchingRuleReplacement(
        source_rule="caseIgnoreSubStringsMatch",
        target_rule="caseIgnoreSubstringsMatch",
        attr_definition=(
            "( 2.16.840.1.113894.1.1.1 NAME 'testAttr' "
            "SUBSTR caseIgnoreSubStringsMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        ),
        attr_field="substr",
    ),
)

# Test data for attribute transformations
ATTRIBUTE_TRANSFORMATIONS = (
    AttributeTransformation(oid_name="orclguid", rfc_name="entryUUID"),
)


@pytest.fixture
def oid_schema() -> FlextLdifServersOid.Schema:
    """Create OID schema quirk instance."""
    return cast("FlextLdifServersOid.Schema", FlextLdifServersOid().schema_quirk)


@pytest.fixture
def oid_fixtures() -> FlextLdifFixtures.OID:
    """Create OID fixture loader."""
    return FlextLdifFixtures.OID()


class TestOidSyntaxTransformations:
    """Test OID syntax transformations."""

    def test_syntax_replacements_defined(self) -> None:
        """Test that syntax OID replacements are defined."""
        replacements = FlextLdifServersOid.Constants.SYNTAX_OID_TO_RFC

        assert len(replacements) > 0
        assert "1.3.6.1.4.1.1466.115.121.1.1" in replacements

    @pytest.mark.parametrize("replacement", SYNTAX_REPLACEMENTS)
    def test_replacement_mapping(
        self,
        replacement: SyntaxReplacement,
    ) -> None:
        """Test syntax replacement mapping exists and is correct."""
        replacements = FlextLdifServersOid.Constants.SYNTAX_OID_TO_RFC
        assert replacements.get(replacement.source_oid) == replacement.target_oid

    @pytest.mark.parametrize("replacement", SYNTAX_REPLACEMENTS)
    def test_parse_applies_replacement(
        self,
        replacement: SyntaxReplacement,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test that parsing applies syntax replacement."""
        parse_result = oid_schema.parse_attribute(replacement.attr_definition)
        assert parse_result.is_success
        parsed_attr = parse_result.unwrap()

        assert parsed_attr.syntax == replacement.target_oid

    def test_parse_preserves_unreplaced_syntax_oids(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test that parsing preserves syntax OIDs not in replacement table."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 NAME 'testAttr' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )

        parse_result = oid_schema.parse_attribute(attr_def)
        assert parse_result.is_success
        parsed_attr = parse_result.unwrap()

        assert parsed_attr.syntax == "1.3.6.1.4.1.1466.115.121.1.15"

    @pytest.mark.parametrize("replacement", SYNTAX_REPLACEMENTS)
    def test_write_preserves_replaced_syntax_oids(
        self,
        replacement: SyntaxReplacement,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test that writing preserves replaced syntax OIDs."""
        parse_result = oid_schema.parse_attribute(replacement.attr_definition)
        assert parse_result.is_success
        parsed_attr = parse_result.unwrap()

        write_result = oid_schema.write_attribute(parsed_attr)
        assert write_result.is_success
        written = write_result.unwrap()

        assert re.search(
            rf"\b{re.escape(replacement.source_oid)}\b",
            written,
        ), (
            f"Expected OID syntax {replacement.source_oid} (denormalized) not found in: {written}"
        )
        assert not re.search(
            rf"\b{re.escape(replacement.target_oid)}\b",
            written,
        ), (
            f"RFC syntax {replacement.target_oid} should be denormalized to OID in: {written}"
        )


class TestOidMatchingRuleTransformations:
    """Test OID matching rule transformations."""

    def test_matching_rule_replacements_defined(self) -> None:
        """Test that matching rule replacements are defined."""
        replacements = FlextLdifServersOid.Constants.MATCHING_RULE_TO_RFC

        assert len(replacements) > 0
        assert "caseIgnoreSubStringsMatch" in replacements

    @pytest.mark.parametrize("replacement", MATCHING_RULE_REPLACEMENTS)
    def test_replacement_mapping(
        self,
        replacement: MatchingRuleReplacement,
    ) -> None:
        """Test matching rule replacement mapping exists and is correct."""
        replacements = FlextLdifServersOid.Constants.MATCHING_RULE_TO_RFC
        assert replacements.get(replacement.source_rule) == replacement.target_rule

    def test_access_directive_replacement(self) -> None:
        """Test accessDirectiveMatch is replaced with caseIgnoreMatch."""
        replacements = FlextLdifServersOid.Constants.MATCHING_RULE_TO_RFC

        if "accessDirectiveMatch" in replacements:
            assert replacements.get("accessDirectiveMatch") == "caseIgnoreMatch"

    @pytest.mark.parametrize("replacement", MATCHING_RULE_REPLACEMENTS)
    def test_parse_applies_replacement(
        self,
        replacement: MatchingRuleReplacement,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test that parsing applies matching rule replacement."""
        parse_result = oid_schema.parse_attribute(replacement.attr_definition)
        assert parse_result.is_success
        parsed_attr = parse_result.unwrap()

        assert getattr(parsed_attr, replacement.attr_field) == replacement.target_rule

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

        assert parsed_attr.equality == "caseIgnoreMatch"

    @pytest.mark.parametrize("replacement", MATCHING_RULE_REPLACEMENTS)
    def test_write_denormalizes_matching_rules(
        self,
        replacement: MatchingRuleReplacement,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test that writing denormalizes matching rules (RFC → OID)."""
        parse_result = oid_schema.parse_attribute(replacement.attr_definition)
        assert parse_result.is_success
        parsed_attr = parse_result.unwrap()
        assert getattr(parsed_attr, replacement.attr_field) == replacement.target_rule

        write_result = oid_schema.write_attribute(parsed_attr)
        assert write_result.is_success
        written = write_result.unwrap()

        assert replacement.source_rule in written
        assert replacement.target_rule not in written


class TestOidOudCompatibilityTransformations:
    """Test OID→OUD compatibility transformations."""

    def test_roundtrip_denormalizes_to_oid(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test that native OID roundtrip (parse → write) denormalizes back to OID format."""
        original = (
            "( 2.16.840.1.113894.1.1.1 NAME 'testAttr' "
            "SUBSTR caseIgnoreSubStringsMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.1 )"
        )

        parse_result = oid_schema.parse_attribute(original)
        assert parse_result.is_success
        parsed_attr = parse_result.unwrap()
        assert parsed_attr.substr == "caseIgnoreSubstringsMatch"
        assert parsed_attr.syntax == "1.3.6.1.4.1.1466.115.121.1.15"

        write_result = oid_schema.write_attribute(parsed_attr)
        assert write_result.is_success
        written = write_result.unwrap()

        assert "caseIgnoreSubStringsMatch" in written
        assert "1.3.6.1.4.1.1466.115.121.1.1" in written

    def test_real_fixture_transformations(
        self,
        oid_schema: FlextLdifServersOid.Schema,
        oid_fixtures: FlextLdifFixtures.OID,
    ) -> None:
        """Test transformations on real OID fixture attributes."""
        schema_content = oid_fixtures.schema()

        oracle_attrs = [
            line
            for line in schema_content.splitlines()
            if "2.16.840.1.113894" in line and "attributetypes:" in line
        ]

        assert len(oracle_attrs) > 0

        first_attr = oracle_attrs[0]
        attr_def = first_attr.split("attributetypes:", 1)[1].strip()

        parse_result = oid_schema.parse_attribute(attr_def)
        assert parse_result.is_success
        parsed_attr = parse_result.unwrap()

        write_result = oid_schema.write_attribute(parsed_attr)
        assert write_result.is_success
        written = write_result.unwrap()

        assert written.startswith("( ")
        assert written.rstrip().endswith(")")


class TestOidAttributeTransformations:
    """Test attribute transformations."""

    def test_attribute_transformation_mappings_defined(self) -> None:
        """Test that attribute transformation mappings are defined."""
        oid_to_rfc = FlextLdifServersOid.Constants.ATTRIBUTE_TRANSFORMATION_OID_TO_RFC
        rfc_to_oid = FlextLdifServersOid.Constants.ATTRIBUTE_TRANSFORMATION_RFC_TO_OID

        assert len(oid_to_rfc) > 0
        assert len(rfc_to_oid) > 0

    @pytest.mark.parametrize("transformation", ATTRIBUTE_TRANSFORMATIONS)
    def test_oid_to_rfc_mapping(
        self,
        transformation: AttributeTransformation,
    ) -> None:
        """Test OID to RFC attribute transformation mapping."""
        oid_to_rfc = FlextLdifServersOid.Constants.ATTRIBUTE_TRANSFORMATION_OID_TO_RFC
        assert oid_to_rfc.get(transformation.oid_name) == transformation.rfc_name

    @pytest.mark.parametrize("transformation", ATTRIBUTE_TRANSFORMATIONS)
    def test_rfc_to_oid_mapping(
        self,
        transformation: AttributeTransformation,
    ) -> None:
        """Test RFC to OID attribute transformation mapping."""
        rfc_to_oid = FlextLdifServersOid.Constants.ATTRIBUTE_TRANSFORMATION_RFC_TO_OID
        assert rfc_to_oid.get(transformation.rfc_name) == transformation.oid_name


class TestOidTransformationCompleteness:
    """Test completeness of OID transformations."""

    def test_all_syntax_replacements_have_valid_targets(self) -> None:
        """Test that all syntax replacement mappings have valid target values."""
        syntax_repls = FlextLdifServersOid.Constants.SYNTAX_OID_TO_RFC
        for source, target in syntax_repls.items():
            assert isinstance(source, str)
            assert isinstance(target, str)
            assert "." in target, f"Invalid target syntax OID: {target}"

    def test_all_matching_rule_replacements_have_valid_targets(self) -> None:
        """Test that all matching rule replacements have valid target values."""
        rule_repls = FlextLdifServersOid.Constants.MATCHING_RULE_TO_RFC
        for source, target in rule_repls.items():
            assert isinstance(source, str)
            assert isinstance(target, str)
            assert "match" in target.lower(), f"Invalid target rule: {target}"

    def test_no_circular_transformations(self) -> None:
        """Test that transformations don't create circular mappings."""
        syntax_repls = FlextLdifServersOid.Constants.SYNTAX_OID_TO_RFC

        for source, target in syntax_repls.items():
            reverse = syntax_repls.get(target)
            if reverse is not None:
                assert reverse != source, (
                    f"Circular transformation: {source} ↔ {target}"
                )

    def test_transformation_symmetry(self) -> None:
        """Test symmetry of bidirectional transformations."""
        oid_to_rfc = FlextLdifServersOid.Constants.ATTRIBUTE_TRANSFORMATION_OID_TO_RFC
        rfc_to_oid = FlextLdifServersOid.Constants.ATTRIBUTE_TRANSFORMATION_RFC_TO_OID

        oid_mapping = oid_to_rfc.get("orclguid")
        if oid_mapping:
            rfc_mapping = rfc_to_oid.get(oid_mapping)
            if rfc_mapping:
                assert rfc_mapping == "orclguid"


__all__ = [
    "ATTRIBUTE_TRANSFORMATIONS",
    "MATCHING_RULE_REPLACEMENTS",
    "SYNTAX_REPLACEMENTS",
    "AttributeTransformation",
    "MatchingRuleReplacement",
    "SyntaxReplacement",
    "TestOidAttributeTransformations",
    "TestOidMatchingRuleTransformations",
    "TestOidOudCompatibilityTransformations",
    "TestOidSyntaxTransformations",
    "TestOidTransformationCompleteness",
    "TransformationType",
]
