from __future__ import annotations

from enum import StrEnum
from typing import ClassVar, cast

import pytest

from flext_ldif.models import m
from flext_ldif.servers._base import FlextLdifServersBaseSchema
from flext_ldif.servers.oid import FlextLdifServersOid
from tests import m, s


class TestsTestFlextLdifOidSyntaxTransformations(s):
    """Consolidated test suite for OID syntax and matching rule transformations.

    Replaces 5 original test classes with parametrized tests using StrEnum
    scenarios and ClassVar test data for maximum code reuse.
    """

    # ═════════════════════════════════════════════════════════════════════════════
    # TEST SCENARIO ENUMS
    # ═════════════════════════════════════════════════════════════════════════════

    class SyntaxTransformationScenario(StrEnum):
        """Test scenarios for syntax transformations."""

        DIRECTORY_STRING = "directory_string"
        INTEGER = "integer"
        BOOLEAN = "boolean"
        OID = "oid"
        OCTET_STRING = "octet_string"

    class MatchingRuleScenario(StrEnum):
        """Test scenarios for matching rules."""

        CASE_IGNORE_MATCH = "case_ignore_match"
        CASE_EXACT_MATCH = "case_exact_match"
        INTEGER_MATCH = "integer_match"
        SUBSTRING_MATCH = "substring_match"
        ORDERING_MATCH = "ordering_match"

    class OudCompatibilityScenario(StrEnum):
        """Test scenarios for OUD compatibility."""

        ORACLE_TO_OUD = "oracle_to_oud"
        OUD_SPECIFIC_SYNTAX = "oud_specific_syntax"
        ROUNDTRIP_OUD = "roundtrip_oud"

    class AttributeTransformationScenario(StrEnum):
        """Test scenarios for attribute transformations."""

        WITH_SYNTAX = "with_syntax"
        WITH_MATCHING_RULES = "with_matching_rules"
        WITH_BOTH = "with_both"
        COMPLEX_ATTRIBUTE = "complex_attribute"

    class TransformationCompletenessScenario(StrEnum):
        """Test scenarios for transformation completeness."""

        ALL_SYNTAX_TYPES = "all_syntax_types"
        ALL_MATCHING_RULES = "all_matching_rules"
        COMBINED_TRANSFORMATIONS = "combined_transformations"

    # ═════════════════════════════════════════════════════════════════════════════
    # TEST DATA MAPPINGS
    # ═════════════════════════════════════════════════════════════════════════════

    SYNTAX_TRANSFORMATION_TEST_DATA: ClassVar[dict[str, tuple[str, str]]] = {
        SyntaxTransformationScenario.DIRECTORY_STRING: (
            "1.3.6.1.4.1.1466.115.121.1.15",
            "DirectoryString",
        ),
        SyntaxTransformationScenario.INTEGER: (
            "1.3.6.1.4.1.1466.115.121.1.27",
            "Integer",
        ),
        SyntaxTransformationScenario.BOOLEAN: (
            "1.3.6.1.4.1.1466.115.121.1.7",
            "Boolean",
        ),
        SyntaxTransformationScenario.OID: (
            "1.3.6.1.4.1.1466.115.121.1.38",
            "OID",
        ),
    }

    MATCHING_RULE_TEST_DATA: ClassVar[dict[str, tuple[str, str]]] = {
        MatchingRuleScenario.CASE_IGNORE_MATCH: (
            "caseIgnoreMatch",
            "caseIgnoreMatch",
        ),
        MatchingRuleScenario.CASE_EXACT_MATCH: (
            "caseExactMatch",
            "caseExactMatch",
        ),
        MatchingRuleScenario.INTEGER_MATCH: (
            "integerMatch",
            "integerMatch",
        ),
        MatchingRuleScenario.SUBSTRING_MATCH: (
            "caseIgnoreSubstringsMatch",
            "caseIgnoreSubstringsMatch",
        ),
        MatchingRuleScenario.ORDERING_MATCH: (
            "caseIgnoreOrderingMatch",
            "caseIgnoreOrderingMatch",
        ),
    }

    # ═════════════════════════════════════════════════════════════════════════════
    # FIXTURES
    # ═════════════════════════════════════════════════════════════════════════════

    @pytest.fixture
    def oid_schema(self) -> FlextLdifServersBaseSchema:
        """Create OID schema quirk instance."""
        return cast("FlextLdifServersBaseSchema", FlextLdifServersOid().schema_quirk)

    # ═════════════════════════════════════════════════════════════════════════════
    # SYNTAX TRANSFORMATION TESTS
    # ═════════════════════════════════════════════════════════════════════════════

    @pytest.mark.parametrize(
        ("scenario", "syntax_oid", "syntax_name"),
        [
            (
                SyntaxTransformationScenario.DIRECTORY_STRING,
                "1.3.6.1.4.1.1466.115.121.1.15",
                "DirectoryString",
            ),
            (
                SyntaxTransformationScenario.INTEGER,
                "1.3.6.1.4.1.1466.115.121.1.27",
                "Integer",
            ),
            (
                SyntaxTransformationScenario.BOOLEAN,
                "1.3.6.1.4.1.1466.115.121.1.7",
                "Boolean",
            ),
            (
                SyntaxTransformationScenario.OID,
                "1.3.6.1.4.1.1466.115.121.1.38",
                "OID",
            ),
        ],
    )
    def test_syntax_preservation(
        self,
        scenario: str,
        syntax_oid: str,
        syntax_name: str,
        oid_schema: FlextLdifServersBaseSchema,
    ) -> None:
        """Test that syntax is preserved during transformations."""
        attr_def = (
            f"( 2.16.840.1.113894.1.1.100 NAME 'orclTest{scenario}' "
            f"SYNTAX {syntax_oid} )"
        )

        parsed_result = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema,
            attr_def,
            parse_method="parse_attribute",
            expected_type=m.SchemaAttribute,
        )

        attr = cast("m.SchemaAttribute", parsed_result)
        assert attr.syntax == syntax_oid or syntax_oid in (attr.syntax or "")

    def test_syntax_transformation_comprehensive(
        self,
        oid_schema: FlextLdifServersBaseSchema,
    ) -> None:
        """Test comprehensive syntax transformations."""
        syntax_cases = [
            "1.3.6.1.4.1.1466.115.121.1.15",  # DirectoryString
            "1.3.6.1.4.1.1466.115.121.1.27",  # Integer
            "1.3.6.1.4.1.1466.115.121.1.7",  # Boolean
        ]

        for syntax in syntax_cases:
            attr_def = (
                f"( 2.16.840.1.113894.1.1.{syntax[-2:]} NAME 'orclAttr' "
                f"SYNTAX {syntax} )"
            )

            result = oid_schema.parse_attribute(attr_def)
            assert result.is_success

    # ═════════════════════════════════════════════════════════════════════════════
    # MATCHING RULE TRANSFORMATION TESTS
    # ═════════════════════════════════════════════════════════════════════════════

    @pytest.mark.parametrize(
        ("scenario", "rule_name", "rule_expected"),
        [
            (
                MatchingRuleScenario.CASE_IGNORE_MATCH,
                "caseIgnoreMatch",
                "caseIgnoreMatch",
            ),
            (
                MatchingRuleScenario.CASE_EXACT_MATCH,
                "caseExactMatch",
                "caseExactMatch",
            ),
            (
                MatchingRuleScenario.INTEGER_MATCH,
                "integerMatch",
                "integerMatch",
            ),
            (
                MatchingRuleScenario.SUBSTRING_MATCH,
                "caseIgnoreSubstringsMatch",
                "caseIgnoreSubstringsMatch",
            ),
        ],
    )
    def test_matching_rule_preservation(
        self,
        scenario: str,
        rule_name: str,
        rule_expected: str,
        oid_schema: FlextLdifServersBaseSchema,
    ) -> None:
        """Test that matching rules are preserved during transformations."""
        attr_def = (
            f"( 2.16.840.1.113894.1.1.{200 + hash(rule_name) % 100} "
            f"NAME 'orclMR{scenario}' "
            f"EQUALITY {rule_name} "
            f"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )

        parsed_result = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema,
            attr_def,
            parse_method="parse_attribute",
            expected_type=m.SchemaAttribute,
        )

        attr = cast("m.SchemaAttribute", parsed_result)
        # caseIgnoreSubstringsMatch is moved to SUBSTR field by OID quirk
        if "Substrings" in rule_name:
            assert attr.substr == rule_expected or rule_expected in (attr.substr or "")
        else:
            assert attr.equality == rule_expected or rule_expected in (
                attr.equality or ""
            )

    def test_multiple_matching_rules(
        self,
        oid_schema: FlextLdifServersBaseSchema,
    ) -> None:
        """Test attributes with multiple matching rules."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.300 NAME 'orclMultiMR' "
            "EQUALITY caseIgnoreMatch "
            "SUBSTR caseIgnoreSubstringsMatch "
            "ORDERING caseIgnoreOrderingMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )

        parsed_result = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema,
            attr_def,
            parse_method="parse_attribute",
            expected_type=m.SchemaAttribute,
        )

        attr = cast("m.SchemaAttribute", parsed_result)
        assert attr.equality or attr.substr or attr.ordering

    # ═════════════════════════════════════════════════════════════════════════════
    # OUD COMPATIBILITY TESTS
    # ═════════════════════════════════════════════════════════════════════════════

    def test_oud_compatibility_attribute(
        self,
        oid_schema: FlextLdifServersBaseSchema,
    ) -> None:
        """Test OID to OUD compatibility for attributes."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.400 NAME 'orclOudCompat' "
            "DESC 'OUD compatible attribute' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )

        parsed_result = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema,
            attr_def,
            parse_method="parse_attribute",
            expected_type=m.SchemaAttribute,
        )

        attr = cast("m.SchemaAttribute", parsed_result)
        assert attr.name == "orclOudCompat"

    @pytest.mark.parametrize(
        ("scenario", "oid", "name"),
        [
            (
                OudCompatibilityScenario.ORACLE_TO_OUD,
                "2.16.840.1.113894.1.1.401",
                "orclAttr1",
            ),
            (
                OudCompatibilityScenario.OUD_SPECIFIC_SYNTAX,
                "2.16.840.1.113894.1.1.402",
                "orclAttr2",
            ),
        ],
    )
    def test_oud_compatibility_scenarios(
        self,
        scenario: str,
        oid: str,
        name: str,
        oid_schema: FlextLdifServersBaseSchema,
    ) -> None:
        """Test OUD compatibility in various scenarios."""
        attr_def = f"( {oid} NAME '{name}' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"

        result = oid_schema.parse_attribute(attr_def)
        assert result.is_success

    # ═════════════════════════════════════════════════════════════════════════════
    # ATTRIBUTE TRANSFORMATION TESTS
    # ═════════════════════════════════════════════════════════════════════════════

    @pytest.mark.parametrize(
        ("scenario", "oid", "name"),
        [
            (
                AttributeTransformationScenario.WITH_SYNTAX,
                "2.16.840.1.113894.1.1.500",
                "orclSyntax",
            ),
            (
                AttributeTransformationScenario.WITH_MATCHING_RULES,
                "2.16.840.1.113894.1.1.501",
                "orclMatchRule",
            ),
            (
                AttributeTransformationScenario.WITH_BOTH,
                "2.16.840.1.113894.1.1.502",
                "orclBoth",
            ),
        ],
    )
    def test_attribute_transformation_scenarios(
        self,
        scenario: str,
        oid: str,
        name: str,
        oid_schema: FlextLdifServersBaseSchema,
    ) -> None:
        """Test various attribute transformation scenarios."""
        if scenario == "with_syntax":
            attr_def = f"( {oid} NAME '{name}' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        elif scenario == "with_matching_rules":
            attr_def = (
                f"( {oid} NAME '{name}' "
                "EQUALITY caseIgnoreMatch "
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
            )
        else:  # with_both
            attr_def = (
                f"( {oid} NAME '{name}' "
                "EQUALITY caseIgnoreMatch "
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
                "SINGLE-VALUE )"
            )

        result = oid_schema.parse_attribute(attr_def)
        assert result.is_success
        parsed_attr = result.unwrap()
        assert parsed_attr.name == name

    def test_complex_attribute_transformation(
        self,
        oid_schema: FlextLdifServersBaseSchema,
    ) -> None:
        """Test complex attribute with all options."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.600 NAME ( 'orclComplex' 'orcComplexAlias' ) "
            "DESC 'Complex Oracle attribute' "
            "EQUALITY caseIgnoreMatch "
            "SUBSTR caseIgnoreSubstringsMatch "
            "ORDERING caseIgnoreOrderingMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
            "SINGLE-VALUE "
            "NO-USER-MODIFICATION "
            "USAGE directoryOperation )"
        )

        parsed_result = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema,
            attr_def,
            parse_method="parse_attribute",
            expected_type=m.SchemaAttribute,
        )

        attr = cast("m.SchemaAttribute", parsed_result)
        assert attr.name == "orclComplex"
        assert attr.syntax

    # ═════════════════════════════════════════════════════════════════════════════
    # TRANSFORMATION COMPLETENESS TESTS
    # ═════════════════════════════════════════════════════════════════════════════

    def test_all_syntax_types_coverage(
        self,
        oid_schema: FlextLdifServersBaseSchema,
    ) -> None:
        """Test that all syntax types are covered."""
        syntax_oids = [
            "1.3.6.1.4.1.1466.115.121.1.15",  # DirectoryString
            "1.3.6.1.4.1.1466.115.121.1.27",  # Integer
            "1.3.6.1.4.1.1466.115.121.1.7",  # Boolean
            "1.3.6.1.4.1.1466.115.121.1.38",  # OID
            "1.3.6.1.4.1.1466.115.121.1.5",  # Binary
        ]

        for idx, syntax_oid in enumerate(syntax_oids):
            attr_def = (
                f"( 2.16.840.1.113894.1.1.{700 + idx} NAME 'orclSyntax{idx}' "
                f"SYNTAX {syntax_oid} )"
            )

            result = oid_schema.parse_attribute(attr_def)
            assert result.is_success, f"Failed for syntax {syntax_oid}"

    def test_all_matching_rules_coverage(
        self,
        oid_schema: FlextLdifServersBaseSchema,
    ) -> None:
        """Test that all matching rules are covered."""
        rules = [
            "caseIgnoreMatch",
            "caseExactMatch",
            "integerMatch",
            "caseIgnoreSubstringsMatch",
            "caseIgnoreOrderingMatch",
        ]

        for idx, rule in enumerate(rules):
            attr_def = (
                f"( 2.16.840.1.113894.1.1.{800 + idx} NAME 'orclRule{idx}' "
                f"EQUALITY {rule} "
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
            )

            result = oid_schema.parse_attribute(attr_def)
            assert result.is_success, f"Failed for rule {rule}"

    def test_case_ignore_substrings_typo_correction(
        self,
        oid_schema: FlextLdifServersBaseSchema,
    ) -> None:
        """Test correction of caseIgnoreSubStringsMatch typo (capital S).

        Validates OID-specific transformation that fixes Oracle's typo:
        - caseIgnoreSubStringsMatch (wrong, capital S)
        → caseIgnoreSubstringsMatch (correct, lowercase s)

        And moves it from EQUALITY to SUBSTR field per RFC 4517.
        """
        # Test with typo in EQUALITY field (OID export bug)
        attr_def_with_typo = (
            "( 2.16.840.1.113894.1.1.123 NAME 'orclTypoTest' "
            "DESC 'Test attribute with typo' "
            "EQUALITY caseIgnoreSubStringsMatch "  # Wrong: capital S, wrong field
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )

        parsed_result = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema,
            attr_def_with_typo,
            parse_method="parse_attribute",
            expected_type=m.SchemaAttribute,
        )

        attr = cast("m.SchemaAttribute", parsed_result)
        # After transformation: typo corrected and moved to SUBSTR
        assert attr.substr == "caseIgnoreSubstringsMatch", (
            f"Expected corrected substr 'caseIgnoreSubstringsMatch', got {attr.substr}"
        )
        assert attr.equality == "caseIgnoreMatch", (
            f"Expected equality 'caseIgnoreMatch', got {attr.equality}"
        )

        # Verify metadata preservation
        assert attr.metadata is not None
        assert attr.metadata.quirk_type == "oid"

    def test_combined_transformations(
        self,
        oid_schema: FlextLdifServersBaseSchema,
    ) -> None:
        """Test combined syntax and matching rule transformations."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.900 NAME 'orclCombined' "
            "DESC 'Combined transformations' "
            "EQUALITY caseIgnoreMatch "
            "SUBSTR caseIgnoreSubstringsMatch "
            "ORDERING caseIgnoreOrderingMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
            "SINGLE-VALUE )"
        )

        parsed_result = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema,
            attr_def,
            parse_method="parse_attribute",
            expected_type=m.SchemaAttribute,
        )

        attr = cast("m.SchemaAttribute", parsed_result)
        assert attr.syntax
        assert attr.equality
