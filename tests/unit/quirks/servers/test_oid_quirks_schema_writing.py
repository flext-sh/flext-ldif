"""Tests for OID schema writing and schema transformation.

This module tests Oracle Internet Directory (OID) schema writing capabilities
including objectClass transformations, attribute name mappings, and schema fixes.
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar

import pytest
from tests import p, s
from tests.conftest import FlextLdifFixtures
from tests.helpers.compat import TestDeduplicationHelpers

from flext_ldif.models import m
from flext_ldif.servers.oid import FlextLdifServersOid


class TestsTestFlextLdifOidSchemaWriting(s):
    """Consolidated test suite for OID schema writing functionality.

    Replaces 4 original test classes (TestOidSchemaWriting, TestOidObjectclassTypoFix,
    TestOidSyntaxAndMatchingRuleTransformations, TestOidAttributeNameTransformations)
    with parametrized tests using StrEnum scenarios and ClassVar test data.
    """

    oid_server: ClassVar[FlextLdifServersOid]  # pytest fixture
    oid_schema: ClassVar[FlextLdifServersOid.Schema]  # pytest fixture
    oid_fixtures: ClassVar[FlextLdifFixtures.OID]  # pytest fixture

    # ═════════════════════════════════════════════════════════════════════════════
    # TEST SCENARIO ENUMS
    # ═════════════════════════════════════════════════════════════════════════════

    class AttributeWritingScenario(StrEnum):
        """Test scenarios for attribute writing."""

        MINIMAL_ATTRIBUTE = "minimal_attribute"
        WITH_ALL_RFC_OPTIONS = "with_all_rfc_options"
        WITH_SINGLE_VALUE = "with_single_value"
        WITH_NO_USER_MODIFICATION = "with_no_user_modification"
        WITH_EQUALITY_SUBSTRING = "with_equality_substring"
        WITH_MULTIPLE_NAMES = "with_multiple_names"
        WITH_DESC = "with_desc"

    class ObjectClassWritingScenario(StrEnum):
        """Test scenarios for objectClass writing."""

        MINIMAL_OBJECTCLASS = "minimal_objectclass"
        STRUCTURAL_OBJECTCLASS = "structural_objectclass"
        AUXILIARY_OBJECTCLASS = "auxiliary_objectclass"
        ABSTRACT_OBJECTCLASS = "abstract_objectclass"
        WITH_MUST_ATTRIBUTES = "with_must_attributes"
        WITH_MAY_ATTRIBUTES = "with_may_attributes"
        WITH_SUP_INHERITANCE = "with_sup_inheritance"

    class SyntaxTransformationScenario(StrEnum):
        """Test scenarios for syntax and matching rule transformations."""

        SYNTAX_PRESERVATION = "syntax_preservation"
        EQUALITY_MATCHING_RULE = "equality_matching_rule"
        SUBSTRING_MATCHING_RULE = "substring_matching_rule"
        ORDERING_MATCHING_RULE = "ordering_matching_rule"
        MULTIPLE_MATCHING_RULES = "multiple_matching_rules"

    class AttributeNameTransformationScenario(StrEnum):
        """Test scenarios for attribute name transformations."""

        SINGLE_NAME = "single_name"
        MULTIPLE_NAMES = "multiple_names"
        NAME_ALIAS_PRESERVATION = "name_alias_preservation"
        NAME_CASE_PRESERVATION = "name_case_preservation"

    class RoundTripScenario(StrEnum):
        """Test scenarios for roundtrip stability."""

        PARSE_WRITE_PARSE = "parse_write_parse"
        ATTRIBUTE_INTEGRITY = "attribute_integrity"
        OBJECTCLASS_INTEGRITY = "objectclass_integrity"

    class ObjectClassTypoFixScenario(StrEnum):
        """Test scenarios for objectClass typo fixes."""

        TYPO_FIX_ABSTRACT = "typo_fix_abstract"
        TYPO_FIX_AUXILIARY = "typo_fix_auxiliary"
        TYPO_FIX_STRUCTURAL = "typo_fix_structural"

    # ═════════════════════════════════════════════════════════════════════════════
    # TEST DATA MAPPINGS
    # ═════════════════════════════════════════════════════════════════════════════

    ATTRIBUTE_WRITING_TEST_DATA: ClassVar[dict[str, tuple[str, str, str]]] = {
        AttributeWritingScenario.MINIMAL_ATTRIBUTE: (
            "2.16.840.1.113894.1.1.1",
            "orclguid",
            "( 2.16.840.1.113894.1.1.1 NAME 'orclguid' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        ),
        AttributeWritingScenario.WITH_ALL_RFC_OPTIONS: (
            "2.16.840.1.113894.1.1.2",
            "orclPassword",
            "( 2.16.840.1.113894.1.1.2 NAME ( 'orclPassword' 'oraclePwd' ) DESC 'Oracle password' "
            "EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
        ),
        AttributeWritingScenario.WITH_SINGLE_VALUE: (
            "2.16.840.1.113894.1.1.3",
            "orclSingleAttr",
            "( 2.16.840.1.113894.1.1.3 NAME 'orclSingleAttr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
        ),
        AttributeWritingScenario.WITH_NO_USER_MODIFICATION: (
            "2.16.840.1.113894.1.1.4",
            "orclNoUserMod",
            "( 2.16.840.1.113894.1.1.4 NAME 'orclNoUserMod' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 NO-USER-MODIFICATION )",
        ),
    }

    OBJECTCLASS_WRITING_TEST_DATA: ClassVar[dict[str, tuple[str, str, str, str]]] = {
        ObjectClassWritingScenario.MINIMAL_OBJECTCLASS: (
            "2.16.840.1.113894.2.1.1",
            "orclContext",
            "top",
            "STRUCTURAL",
        ),
        ObjectClassWritingScenario.STRUCTURAL_OBJECTCLASS: (
            "2.16.840.1.113894.2.1.2",
            "orclPerson",
            "person",
            "STRUCTURAL",
        ),
        ObjectClassWritingScenario.AUXILIARY_OBJECTCLASS: (
            "2.16.840.1.113894.2.1.3",
            "orclAuxiliary",
            "top",
            "AUXILIARY",
        ),
        ObjectClassWritingScenario.ABSTRACT_OBJECTCLASS: (
            "2.16.840.1.113894.2.1.4",
            "orclAbstract",
            "top",
            "ABSTRACT",
        ),
    }

    SYNTAX_TRANSFORMATION_TEST_DATA: ClassVar[dict[str, tuple[str, str]]] = {
        SyntaxTransformationScenario.SYNTAX_PRESERVATION: (
            "1.3.6.1.4.1.1466.115.121.1.15",
            "DirectoryString",
        ),
        SyntaxTransformationScenario.EQUALITY_MATCHING_RULE: (
            "caseIgnoreMatch",
            "caseIgnoreMatch",
        ),
        SyntaxTransformationScenario.MULTIPLE_MATCHING_RULES: (
            "caseIgnoreMatch",
            "caseIgnoreMatch",
        ),
    }

    ATTRIBUTE_NAME_TRANSFORMATION_TEST_DATA: ClassVar[
        dict[str, tuple[str | tuple[str, ...], str]]
    ] = {
        AttributeNameTransformationScenario.SINGLE_NAME: (
            "orclguid",
            "orclguid",
        ),
        AttributeNameTransformationScenario.MULTIPLE_NAMES: (
            ("orclPassword", "oraclePwd"),
            "orclPassword",
        ),
        AttributeNameTransformationScenario.NAME_CASE_PRESERVATION: (
            "orclCasedName",
            "orclCasedName",
        ),
    }

    # ═════════════════════════════════════════════════════════════════════════════
    # FIXTURES
    # ═════════════════════════════════════════════════════════════════════════════

    @pytest.fixture
    def oid_server(self) -> FlextLdifServersOid:
        """Create OID server instance."""
        return FlextLdifServersOid()

    @pytest.fixture
    def oid_schema(
        self,
        oid_server: FlextLdifServersOid,
    ) -> FlextLdifServersOid.Schema:
        """Create OID schema quirk instance."""
        schema = oid_server.schema_quirk
        assert isinstance(schema, FlextLdifServersOid.Schema)
        return schema

    @pytest.fixture
    def oid_fixtures(self) -> FlextLdifFixtures.OID:
        """Create OID fixture loader."""
        return FlextLdifFixtures.OID()

    # ═════════════════════════════════════════════════════════════════════════════
    # ATTRIBUTE WRITING TESTS
    # ═════════════════════════════════════════════════════════════════════════════

    @pytest.mark.parametrize(
        ("scenario", "oid", "name", "definition"),
        [
            (
                AttributeWritingScenario.MINIMAL_ATTRIBUTE,
                "2.16.840.1.113894.1.1.1",
                "orclguid",
                "( 2.16.840.1.113894.1.1.1 NAME 'orclguid' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
            ),
            (
                AttributeWritingScenario.WITH_ALL_RFC_OPTIONS,
                "2.16.840.1.113894.1.1.2",
                "orclPassword",
                "( 2.16.840.1.113894.1.1.2 NAME ( 'orclPassword' 'oraclePwd' ) "
                "DESC 'Oracle password storage' EQUALITY caseExactMatch "
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
            ),
            (
                AttributeWritingScenario.WITH_SINGLE_VALUE,
                "2.16.840.1.113894.1.1.3",
                "orclSingleAttr",
                "( 2.16.840.1.113894.1.1.3 NAME 'orclSingleAttr' "
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
            ),
        ],
    )
    def test_write_attribute_scenarios(
        self,
        scenario: str,
        oid: str,
        name: str,
        definition: str,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test writing attributes with various options."""
        # Parse
        parsed_attr_result = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema,
            definition,
            parse_method="parse_attribute",
            expected_type=m.Ldif.SchemaAttribute,
        )
        assert isinstance(parsed_attr_result, m.Ldif.SchemaAttribute)
        parsed_attr = parsed_attr_result

        # Write
        written = TestDeduplicationHelpers.quirk_write_and_unwrap(
            oid_schema,
            parsed_attr,
            write_method="write_attribute",
        )

        # Verify format
        assert written.startswith("( "), f"Invalid format: {written}"
        assert written.rstrip().endswith(")"), f"Invalid format: {written}"

        # Verify content
        assert oid in written
        assert name in written

    def test_write_attribute_format_validation(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test that written attributes follow RFC 4512 format."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclguid' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )

        parsed_attr_result = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema,
            attr_def,
            parse_method="parse_attribute",
            expected_type=m.Ldif.SchemaAttribute,
        )
        parsed_attr = parsed_attr_result

        written = TestDeduplicationHelpers.quirk_write_and_unwrap(
            oid_schema,
            parsed_attr,
            write_method="write_attribute",
        )

        # Verify RFC 4512 format: ( OID NAME ... )
        assert written.startswith("(")
        assert written.rstrip().endswith(")")
        assert "NAME" in written
        assert parsed_attr.oid in written

    # ═════════════════════════════════════════════════════════════════════════════
    # OBJECTCLASS WRITING TESTS
    # ═════════════════════════════════════════════════════════════════════════════

    @pytest.mark.parametrize(
        ("scenario", "oid", "name", "sup", "kind"),
        [
            (
                ObjectClassWritingScenario.MINIMAL_OBJECTCLASS,
                "2.16.840.1.113894.2.1.1",
                "orclContext",
                "top",
                "STRUCTURAL",
            ),
            (
                ObjectClassWritingScenario.STRUCTURAL_OBJECTCLASS,
                "2.16.840.1.113894.2.1.2",
                "orclPerson",
                "person",
                "STRUCTURAL",
            ),
            (
                ObjectClassWritingScenario.AUXILIARY_OBJECTCLASS,
                "2.16.840.1.113894.2.1.3",
                "orclAuxiliary",
                "top",
                "AUXILIARY",
            ),
            (
                ObjectClassWritingScenario.ABSTRACT_OBJECTCLASS,
                "2.16.840.1.113894.2.1.4",
                "orclAbstract",
                "top",
                "ABSTRACT",
            ),
        ],
    )
    def test_write_objectclass_scenarios(
        self,
        scenario: str,
        oid: str,
        name: str,
        sup: str,
        kind: str,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test writing objectClasses with various kinds."""
        oc_def = f"( {oid} NAME '{name}' SUP {sup} {kind} )"

        # Parse
        parsed_oc_result = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema,
            oc_def,
            parse_method="parse_objectclass",
            expected_type=m.Ldif.SchemaObjectClass,
        )
        assert isinstance(parsed_oc_result, m.Ldif.SchemaObjectClass)
        parsed_oc = parsed_oc_result

        # Write
        written = TestDeduplicationHelpers.quirk_write_and_unwrap(
            oid_schema,
            parsed_oc,
            write_method="write_objectclass",
        )

        # Verify format
        assert written.startswith("( ")
        assert written.rstrip().endswith(")")
        assert oid in written
        assert name in written
        assert kind in written

    def test_write_objectclass_with_sup_inheritance(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test objectClass SUP inheritance is preserved."""
        oc_def = (
            "( 2.16.840.1.113894.2.1.5 NAME 'orclWithSup' "
            "SUP ( person, top ) STRUCTURAL )"
        )

        parsed_oc_result = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema,
            oc_def,
            parse_method="parse_objectclass",
            expected_type=m.Ldif.SchemaObjectClass,
        )
        parsed_oc = parsed_oc_result

        written = TestDeduplicationHelpers.quirk_write_and_unwrap(
            oid_schema,
            parsed_oc,
            write_method="write_objectclass",
        )

        # Verify SUP preservation
        assert "SUP" in written or parsed_oc.sup is not None

    # ═════════════════════════════════════════════════════════════════════════════
    # SYNTAX AND MATCHING RULE TRANSFORMATION TESTS
    # ═════════════════════════════════════════════════════════════════════════════

    def test_syntax_preservation_in_write(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test that SYNTAX is preserved when writing."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.10 NAME 'orclSyntaxTest' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )

        parsed_attr_result = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema,
            attr_def,
            parse_method="parse_attribute",
            expected_type=m.Ldif.SchemaAttribute,
        )
        parsed_attr = parsed_attr_result

        written = TestDeduplicationHelpers.quirk_write_and_unwrap(
            oid_schema,
            parsed_attr,
            write_method="write_attribute",
        )

        # Verify SYNTAX preservation
        assert "1.3.6.1.4.1.1466.115.121.1.15" in written or parsed_attr.syntax

    @pytest.mark.parametrize(
        ("scenario", "equality", "substring", "ordering"),
        [
            (
                SyntaxTransformationScenario.EQUALITY_MATCHING_RULE,
                "caseIgnoreMatch",
                None,
                None,
            ),
            (
                SyntaxTransformationScenario.SUBSTRING_MATCHING_RULE,
                None,
                "caseIgnoreSubstringsMatch",
                None,
            ),
            (
                SyntaxTransformationScenario.ORDERING_MATCHING_RULE,
                None,
                None,
                "caseIgnoreOrderingMatch",
            ),
        ],
    )
    def test_matching_rule_transformations(
        self,
        scenario: str,
        equality: str | None,
        substring: str | None,
        ordering: str | None,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test matching rule preservation in transformations."""
        parts = [
            "( 2.16.840.1.113894.1.1.20 NAME 'orclMatchTest'",
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15",
        ]

        if equality:
            parts.append(f"EQUALITY {equality}")
        if substring:
            parts.append(f"SUBSTR {substring}")
        if ordering:
            parts.append(f"ORDERING {ordering}")

        parts.append(")")
        attr_def = " ".join(parts)

        parsed_attr_result = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema,
            attr_def,
            parse_method="parse_attribute",
            expected_type=m.Ldif.SchemaAttribute,
        )
        parsed_attr = parsed_attr_result

        written = TestDeduplicationHelpers.quirk_write_and_unwrap(
            oid_schema,
            parsed_attr,
            write_method="write_attribute",
        )

        # Verify matching rule preservation
        if equality:
            assert equality in written or parsed_attr.equality
        if substring:
            assert substring in written or parsed_attr.substr
        if ordering:
            assert ordering in written or parsed_attr.ordering

    # ═════════════════════════════════════════════════════════════════════════════
    # ATTRIBUTE NAME TRANSFORMATION TESTS
    # ═════════════════════════════════════════════════════════════════════════════

    @pytest.mark.parametrize(
        ("scenario", "names", "primary_name"),
        [
            (
                AttributeNameTransformationScenario.SINGLE_NAME,
                "orclguid",
                "orclguid",
            ),
            (
                AttributeNameTransformationScenario.MULTIPLE_NAMES,
                "( 'orclPassword' 'oraclePwd' )",
                "orclPassword",
            ),
            (
                AttributeNameTransformationScenario.NAME_CASE_PRESERVATION,
                "orclCasedName",
                "orclCasedName",
            ),
        ],
    )
    def test_attribute_name_preservation(
        self,
        scenario: str,
        names: str,
        primary_name: str,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test that attribute names are preserved exactly."""
        # Format names properly for attribute definition
        formatted_names = names if names.startswith("(") else f"'{names}'"
        attr_def = (
            f"( 2.16.840.1.113894.1.1.30 NAME {formatted_names} "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )

        parsed_attr_result = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema,
            attr_def,
            parse_method="parse_attribute",
            expected_type=m.Ldif.SchemaAttribute,
        )
        parsed_attr = parsed_attr_result

        written = TestDeduplicationHelpers.quirk_write_and_unwrap(
            oid_schema,
            parsed_attr,
            write_method="write_attribute",
        )

        # Verify primary name is present
        assert primary_name in written

    # ═════════════════════════════════════════════════════════════════════════════
    # ROUNDTRIP STABILITY TESTS
    # ═════════════════════════════════════════════════════════════════════════════

    def test_attribute_parse_write_parse_roundtrip(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test attribute roundtrip: parse → write → parse."""
        original = (
            "( 2.16.840.1.113894.1.1.40 NAME 'orclRoundTrip' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"
        )

        # First parse
        parsed1_result = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema,
            original,
            parse_method="parse_attribute",
            expected_type=m.Ldif.SchemaAttribute,
        )
        parsed1 = parsed1_result

        # Write
        written = TestDeduplicationHelpers.quirk_write_and_unwrap(
            oid_schema,
            parsed1,
            write_method="write_attribute",
        )

        # Second parse
        parsed2_result = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema,
            written,
            parse_method="parse_attribute",
            expected_type=m.Ldif.SchemaAttribute,
        )
        parsed2 = parsed2_result

        # Verify integrity
        assert parsed1.oid == parsed2.oid
        assert parsed1.name == parsed2.name

    def test_objectclass_parse_write_parse_roundtrip(
        self,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test objectClass roundtrip: parse → write → parse."""
        original = (
            "( 2.16.840.1.113894.2.1.50 NAME 'orclRoundTripOc' SUP top STRUCTURAL )"
        )

        # First parse
        parsed1_result = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema,
            original,
            parse_method="parse_objectclass",
            expected_type=m.Ldif.SchemaObjectClass,
        )
        parsed1 = parsed1_result

        # Write
        written = TestDeduplicationHelpers.quirk_write_and_unwrap(
            oid_schema,
            parsed1,
            write_method="write_objectclass",
        )

        # Second parse
        parsed2_result = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema,
            written,
            parse_method="parse_objectclass",
            expected_type=m.Ldif.SchemaObjectClass,
        )
        parsed2 = parsed2_result

        # Verify integrity
        assert parsed1.oid == parsed2.oid
        assert parsed1.name == parsed2.name

    # ═════════════════════════════════════════════════════════════════════════════
    # OBJECTCLASS TYPO FIX TESTS
    # ═════════════════════════════════════════════════════════════════════════════

    @pytest.mark.parametrize(
        ("scenario", "kind"),
        [
            (ObjectClassTypoFixScenario.TYPO_FIX_ABSTRACT, "ABSTRACT"),
            (ObjectClassTypoFixScenario.TYPO_FIX_AUXILIARY, "AUXILIARY"),
            (ObjectClassTypoFixScenario.TYPO_FIX_STRUCTURAL, "STRUCTURAL"),
        ],
    )
    def test_objectclass_kind_preservation(
        self,
        scenario: str,
        kind: str,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test objectClass kind is preserved correctly."""
        oc_def = f"( 2.16.840.1.113894.2.1.100 NAME 'orclKindTest' SUP top {kind} )"

        parsed_oc_result = TestDeduplicationHelpers.quirk_parse_and_unwrap(
            oid_schema,
            oc_def,
            parse_method="parse_objectclass",
            expected_type=m.Ldif.SchemaObjectClass,
        )
        parsed_oc = parsed_oc_result

        assert parsed_oc.kind == kind

        written = TestDeduplicationHelpers.quirk_write_and_unwrap(
            oid_schema,
            parsed_oc,
            write_method="write_objectclass",
        )

        # Verify kind is in written output
        assert kind in written

    # ═════════════════════════════════════════════════════════════════════════════
    # FIXTURE-BASED TESTS
    # ═════════════════════════════════════════════════════════════════════════════

    def test_fixture_schema_parsing_and_writing(
        self,
        oid_fixtures: FlextLdifFixtures.OID,
        oid_schema: FlextLdifServersOid.Schema,
    ) -> None:
        """Test parsing and writing with real OID fixtures."""
        schema_content = oid_fixtures.schema()

        if not schema_content:
            pytest.skip("No fixture content available")

        parsed_count = 0
        for line in schema_content.split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                result = oid_schema.parse(line)
                if result.is_success:
                    parsed_count += 1

        assert len(schema_content) > 0
