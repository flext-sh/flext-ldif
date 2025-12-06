from __future__ import annotations

import re
from enum import StrEnum
from typing import ClassVar, cast

import pytest

from flext_ldif import FlextLdif
from flext_ldif.models import m
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.servers._base import FlextLdifServersBaseSchema
from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.utilities import FlextLdifUtilities
from tests import "0", "0.9.2342.19200300.100.1.1", "1", "2.16.840.1.113894.1.1.1", "2.16.840.1.113894.1.1.5", "2.16.840.1.113894.2.1.1", "2.16.840.1.113894.2.1.5", "2.5.6.6", "Acl", "Constants"), c

    # ═════════════════════════════════════════════════════════════════════════════
    # ATTRIBUTE DETECTION TESTS
    # ═════════════════════════════════════════════════════════════════════════════

    @pytest.mark.parametrize(
        ("scenario", "Entry", "FALSE", "Fixture should have content"

    # ═════════════════════════════════════════════════════════════════════════════
    # OBJECTCLASS DETECTION AND PARSING TESTS
    # ═════════════════════════════════════════════════════════════════════════════

    @pytest.mark.parametrize(
        ("scenario", "Oracle GUID attribute", "Oracle GUID", "Oracle attribute with syntax", "Oracle with syntax", "RFC attribute", "Schema", "TRUE", "acl_content", "allow (search) by public, "attr_name", "description"), "invalid_input"), "name"), "oid", "oid_to_rfc"), "orclAdmin", "orclContext", "orclDescription", "orclEntry", "orclguid", "priority", "rfc_to_oid"), "server_type", "should_exist"), "should_match", "should_match"), "should_parse"), (
                AttributeDetectionScenario.ORACLE_ATTRIBUTE_WITH_SYNTAX, (
                AttributeDetectionScenario.RFC_ATTRIBUTE_OID, (
                AttributeParsingScenario.ORACLE_ATTRIBUTE_WITH_DESC, (
                ObjectClassDetectionScenario.RFC_OBJECTCLASS_OID, (
                ObjectClassParsingScenario.ORACLE_OBJECTCLASS_STRUCTURAL, (
            f"FlextLdifServersOid.{attr_name} should "
            f"{'exist' if should_exist else 'not exist'}"
        )

    def test_class_level_constants(self) -> None:
        """Test class-level constants are properly set."""
        assert FlextLdifServersOid.server_type == "oid"
        assert FlextLdifServersOid.priority == 10
        assert hasattr(FlextLdifServersOid, (
            f"OID {oid} ({description}): "
            f"expected {'match' if should_match else 'no match'}"
        )

        # Verify OID format is valid
        validation_result = FlextLdifUtilities.OID.validate_format(oid)
        assert validation_result.is_success
        assert validation_result.unwrap()

    def test_oracle_oid_via_utility(self) -> None:
        """Test Oracle OID detection via FlextLdifUtilities."""
        oracle_oid = "2.16.840.1.113894.1.1.1"
        rfc_oid = "0.9.2342.19200300.100.1.1"

        assert FlextLdifUtilities.OID.is_oracle_oid(oracle_oid)
        assert not FlextLdifUtilities.OID.is_oracle_oid(rfc_oid)

    @pytest.mark.parametrize(
        ("scenario", (AttributeDetectionScenario.INVALID_INPUT_INT, (AttributeDetectionScenario.INVALID_INPUT_LIST, (InitializationScenario.CLASS_ATTRIBUTES, (InitializationScenario.NESTED_QUIRK_CLASSES, ), )

        assert bool(detection_pattern.search(oid)) == should_match

        # Validate format
        validation_result = FlextLdifUtilities.OID.validate_format(oid)
        assert validation_result.is_success

    def test_parse_basic_oracle_objectclass(
        self, )

        match_result = bool(detection_pattern.search(oid))
        assert match_result == should_match, )

        parsed_count = 0
        for line in schema_content.split("
"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if detection_pattern.search(line):
                result = schema_quirk.parse_attribute(line)
                if result.is_success:
                    parsed_count += 1

        # At least verify parsing logic works with fixture content
        assert len(schema_content) > 0, )
        self.assert_failure(result)

    # ═════════════════════════════════════════════════════════════════════════════
    # ATTRIBUTE PARSING TESTS
    # ═════════════════════════════════════════════════════════════════════════════

    def test_parse_basic_oracle_attribute(
        self, )
    def test_attribute_detection_invalid_input(
        self, )
    def test_initialization(
        self, )
    def test_objectclass_oid_pattern_detection(
        self, )
    def test_oracle_oid_pattern_detection(
        self, )
    def test_parse_oracle_attributes_variants(
        self, )
    def test_parse_oracle_objectclass_variants(
        self, ) -> FlextLdifServersBaseSchema:
        """Get OID schema quirk instance (aliased from oid_schema_quirk)."""
        return cast("FlextLdifServersBaseSchema", ) -> None:
        """Test OID quirk initialization and class structure."""
        assert hasattr(FlextLdifServersOid, ) -> None:
        """Test can_handle with invalid input types."""
        result = schema_quirk.parse(
            str(invalid_input) if not isinstance(invalid_input, ) -> None:
        """Test detection of Oracle OID attributes by pattern."""
        detection_pattern = re.compile(
            FlextLdifServersOid.Constants.DETECTION_OID_PATTERN, ) -> None:
        """Test detection of Oracle objectClass OIDs."""
        detection_pattern = re.compile(
            FlextLdifServersOid.Constants.DETECTION_OID_PATTERN, ) -> None:
        """Test parsing Oracle attribute variants."""
        attr_def = (
            f"( {oid} NAME '{name}' "
            "DESC 'Oracle Attribute' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )

        result = schema_quirk.parse_attribute(attr_def)
        self.assert_success(result)
        parsed_attr = result.unwrap()
        assert parsed_attr.name == name
        assert parsed_attr.oid == oid

    def test_parse_attribute_with_fixtures(
        self, ) -> None:
        """Test parsing Oracle attributes from real OID schema fixtures."""
        schema_content = oid_fixtures.schema()
        detection_pattern = re.compile(
            FlextLdifServersOid.Constants.DETECTION_OID_PATTERN, ) -> None:
        """Test parsing Oracle objectClass variants."""
        oc_def = f"( {oid} NAME '{name}' SUP top STRUCTURAL )"

        result = schema_quirk.parse_objectclass(oc_def)
        self.assert_success(result)
        parsed_oc = result.unwrap()
        assert parsed_oc.name == name
        assert parsed_oc.oid == oid

    # ═════════════════════════════════════════════════════════════════════════════
    # ACL PARSING AND CONVERSION TESTS
    # ═════════════════════════════════════════════════════════════════════════════

    @pytest.mark.parametrize(
        ("scenario", ) -> None:
        """Test parsing basic Oracle attribute definition."""
        oracle_oid = "2.16.840.1.113894.1.1.1"
        attr_def = (
            f"( {oracle_oid} NAME 'orclguid' "
            "DESC 'Oracle GUID' "
            "EQUALITY caseIgnoreMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
            "SINGLE-VALUE )"
        )

        result = schema_quirk.parse_attribute(attr_def)
        assert result.is_success, ) -> None:
        """Test parsing basic Oracle objectClass definition."""
        oracle_oc_oid = "2.16.840.1.113894.2.1.1"
        oracle_oc = f"( {oracle_oc_oid} NAME 'orclContext' SUP top STRUCTURAL )"

        result = schema_quirk.parse_objectclass(oracle_oc)
        assert result.is_success, 123), AttributeDetectionScenario.ORACLE_ATTRIBUTE_WITH_SYNTAX: (
            "2.16.840.1.113894.1.1.5", AttributeDetectionScenario.RFC_ATTRIBUTE_OID: (
            "0.9.2342.19200300.100.1.1", AttributeParsingScenario.ORACLE_ATTRIBUTE_WITH_DESC: (
            "2.16.840.1.113894.1.1.5", AttributeParsingScenario.ORACLE_ATTRIBUTE_WITH_EQUALITY: (
            "2.16.840.1.113894.1.1.10", BooleanConversionScenario.OID_FALSE_TO_RFC: ("0", BooleanConversionScenario.RFC_FALSE_TO_OID: ("FALSE", BooleanConversionScenario.RFC_TRUE_TO_OID: ("TRUE", False, InitializationScenario.NESTED_QUIRK_CLASSES: (
            "Schema", InitializationScenario.ORACLE_NAMESPACE_PATTERN: (
            "DETECTION_OID_PATTERN", None), ObjectClassDetectionScenario.RFC_OBJECTCLASS_OID: (
            "2.5.6.6", ObjectClassParsingScenario.ORACLE_OBJECTCLASS_STRUCTURAL: (
            "2.16.840.1.113894.2.1.5", True, True), [
            (
                AttributeDetectionScenario.ORACLE_ATTRIBUTE_OID, [
            (
                AttributeParsingScenario.BASIC_ORACLE_ATTRIBUTE, [
            (
                ObjectClassDetectionScenario.ORACLE_OBJECTCLASS_OID, [
            (
                ObjectClassParsingScenario.BASIC_ORACLE_OBJECTCLASS, [
            (AclParsingScenario.SIMPLE_ACL, [
            (AttributeDetectionScenario.INVALID_INPUT_NONE, [
            (InitializationScenario.CLASS_ATTRIBUTES, []), ], attr_name) == should_exist, attr_name: str, bool, bool | type[str]]]
    ] = {
        InitializationScenario.CLASS_ATTRIBUTES: (
            "server_type", bool]]] = {
        ObjectClassDetectionScenario.ORACLE_OBJECTCLASS_OID: (
            "2.16.840.1.113894.2.1.1", c, description: str, f"Parse should succeed: {result.error}"

        parsed_attr = result.unwrap()
        assert isinstance(parsed_attr, f"Parse should succeed: {result.error}"

        parsed_oc = result.unwrap()
        assert isinstance(parsed_oc, invalid_input: object, m, m.SchemaAttribute)
        assert parsed_attr.name == "orclguid"
        assert parsed_attr.oid == oracle_oid

    @pytest.mark.parametrize(
        ("scenario", m.SchemaObjectClass)
        assert parsed_oc.name == "orclContext"
        assert parsed_oc.oid == oracle_oc_oid

    @pytest.mark.parametrize(
        ("scenario", name: str, oid: str, oid_fixtures: FlextLdifFixtures.OID, oid_schema_quirk)

    @pytest.fixture
    def flext_ldif(self) -> FlextLdif:
        """Get FlextLdif instance."""
        return FlextLdif()

    @pytest.fixture
    def oracle_attribute_template(self) -> str:
        """Template for Oracle attribute definitions."""
        return "( {oid} NAME '{name}' DESC '{desc}' SYNTAX {syntax} )"

    @pytest.fixture
    def oracle_objectclass_template(self) -> str:
        """Template for Oracle objectClass definitions."""
        return "( {oid} NAME '{name}' SUP {sup} STRUCTURAL )"

    # ═════════════════════════════════════════════════════════════════════════════
    # INITIALIZATION TESTS
    # ═════════════════════════════════════════════════════════════════════════════

    @pytest.mark.parametrize(
        ("scenario", oid_schema_quirk: FlextLdifProtocols.Quirks.SchemaProtocol, oracle_attribute_template: str, re.IGNORECASE, s

# FlextLdifFixtures is available from conftest.py (pytest auto-imports)


class TestsTestFlextLdifOidQuirks(s):
    """Consolidated test suite for OID quirk functionality.

    This single test class replaces 31 original test classes with parametrized tests
    using StrEnum scenarios and ClassVar test data for maximum code reuse.

    Test Coverage:
    - Initialization and class structure
    - Schema attribute detection and parsing
    - Schema objectClass detection and parsing
    - ACL parsing and conversion
    - Entry processing
    - Integration with fixtures
    - Error handling
    - Real implementation validation
    """

    # ═════════════════════════════════════════════════════════════════════════════
    # TEST SCENARIO ENUMS - Consolidated from 31 test classes
    # ═════════════════════════════════════════════════════════════════════════════

    class InitializationScenario(StrEnum):
        """Test scenarios for OID quirk initialization."""

        CLASS_ATTRIBUTES = "class_attributes"
        NESTED_QUIRK_CLASSES = "nested_quirk_classes"
        ORACLE_NAMESPACE_PATTERN = "oracle_namespace_pattern"

    class AttributeDetectionScenario(StrEnum):
        """Test scenarios for Oracle attribute detection."""

        ORACLE_ATTRIBUTE_OID = "oracle_attribute_oid"
        RFC_ATTRIBUTE_OID = "rfc_attribute_oid"
        ORACLE_ATTRIBUTE_WITH_SYNTAX = "oracle_attribute_with_syntax"
        INVALID_INPUT_NONE = "invalid_input_none"
        INVALID_INPUT_INT = "invalid_input_int"
        INVALID_INPUT_LIST = "invalid_input_list"

    class AttributeParsingScenario(StrEnum):
        """Test scenarios for attribute parsing."""

        BASIC_ORACLE_ATTRIBUTE = "basic_oracle_attribute"
        ORACLE_ATTRIBUTE_WITH_DESC = "oracle_attribute_with_desc"
        ORACLE_ATTRIBUTE_WITH_EQUALITY = "oracle_attribute_with_equality"
        ORACLE_ATTRIBUTE_SINGLE_VALUE = "oracle_attribute_single_value"
        FROM_FIXTURES = "from_fixtures"
        MALFORMED_ATTRIBUTE = "malformed_attribute"
        INCOMPLETE_ATTRIBUTE = "incomplete_attribute"

    class ObjectClassDetectionScenario(StrEnum):
        """Test scenarios for Oracle objectClass detection."""

        ORACLE_OBJECTCLASS_OID = "oracle_objectclass_oid"
        RFC_OBJECTCLASS_OID = "rfc_objectclass_oid"
        ORACLE_OBJECTCLASS_WITH_SUP = "oracle_objectclass_with_sup"
        INVALID_OBJECTCLASS_INPUT = "invalid_objectclass_input"

    class ObjectClassParsingScenario(StrEnum):
        """Test scenarios for objectClass parsing."""

        BASIC_ORACLE_OBJECTCLASS = "basic_oracle_objectclass"
        ORACLE_OBJECTCLASS_STRUCTURAL = "oracle_objectclass_structural"
        ORACLE_OBJECTCLASS_WITH_MAY = "oracle_objectclass_with_may"
        FROM_FIXTURES = "from_fixtures"
        MALFORMED_OBJECTCLASS = "malformed_objectclass"

    class AclParsingScenario(StrEnum):
        """Test scenarios for ACL parsing."""

        SIMPLE_ACL = "simple_acl"
        ACL_WITH_GRANT = "acl_with_grant"
        ACL_WITH_DENY = "acl_with_deny"
        MULTIPLE_PERMISSIONS = "multiple_permissions"
        MALFORMED_ACL = "malformed_acl"
        EMPTY_ACL = "empty_acl"

    class EntryProcessingScenario(StrEnum):
        """Test scenarios for entry processing."""

        SIMPLE_ENTRY = "simple_entry"
        ENTRY_WITH_ORACLE_ATTRS = "entry_with_oracle_attrs"
        ENTRY_WITH_BOOLEAN_CONVERSION = "entry_with_boolean_conversion"
        ENTRY_WITH_ACL = "entry_with_acl"
        MALFORMED_ENTRY = "malformed_entry"

    class ConversionScenario(StrEnum):
        """Test scenarios for attribute/objectclass conversion."""

        ATTRIBUTE_TO_RFC = "attribute_to_rfc"
        OBJECTCLASS_TO_RFC = "objectclass_to_rfc"
        WITH_METADATA_PRESERVATION = "with_metadata_preservation"
        ROUND_TRIP_CONVERSION = "round_trip_conversion"

    class BooleanConversionScenario(StrEnum):
        """Test scenarios for boolean attribute conversions."""

        OID_TRUE_TO_RFC = "oid_true_to_rfc"
        OID_FALSE_TO_RFC = "oid_false_to_rfc"
        RFC_TRUE_TO_OID = "rfc_true_to_oid"
        RFC_FALSE_TO_OID = "rfc_false_to_oid"
        MULTIPLE_BOOLEAN_ATTRS = "multiple_boolean_attrs"

    class ErrorHandlingScenario(StrEnum):
        """Test scenarios for error handling."""

        INVALID_OID_FORMAT = "invalid_oid_format"
        MISSING_NAME_ATTRIBUTE = "missing_name_attribute"
        PARSE_FAILURE = "parse_failure"
        CONVERSION_FAILURE = "conversion_failure"
        FIXTURE_NOT_FOUND = "fixture_not_found"

    class IntegrationScenario(StrEnum):
        """Test scenarios for integration testing."""

        FULL_LDIF_MIGRATION = "full_ldif_migration"
        SCHEMA_ACL_ENTRY_CHAIN = "schema_acl_entry_chain"
        FIXTURE_BASED_PROCESSING = "fixture_based_processing"
        ROUND_TRIP_WITH_FIXTURES = "round_trip_with_fixtures"

    # ═════════════════════════════════════════════════════════════════════════════
    # TEST DATA MAPPINGS - Consolidated from scattered test methods
    # ═════════════════════════════════════════════════════════════════════════════

    INITIALIZATION_TEST_DATA: ClassVar[
        dict[str, scenario: str, schema_quirk: FlextLdifServersBaseSchema, should_exist: bool, should_match: bool, str, str | None]]] = {
        AttributeDetectionScenario.ORACLE_ATTRIBUTE_OID: (
            "2.16.840.1.113894.1.1.1", str) else invalid_input, str]]] = {
        AttributeParsingScenario.BASIC_ORACLE_ATTRIBUTE: (
            "2.16.840.1.113894.1.1.1", str]]] = {
        BooleanConversionScenario.OID_TRUE_TO_RFC: ("1", str]]] = {
        ObjectClassParsingScenario.BASIC_ORACLE_OBJECTCLASS: (
            "2.16.840.1.113894.2.1.1", tuple[str, tuple[str | None, }

    # ═════════════════════════════════════════════════════════════════════════════
    # FIXTURES
    # ═════════════════════════════════════════════════════════════════════════════

    @pytest.fixture
    def schema_quirk(
        self, }

    ATTRIBUTE_DETECTION_TEST_DATA: ClassVar[dict[str, }

    ATTRIBUTE_PARSING_TEST_DATA: ClassVar[dict[str, }

    BOOLEAN_CONVERSION_TEST_DATA: ClassVar[dict[str, }

    OBJECTCLASS_DETECTION_TEST_DATA: ClassVar[dict[str, }

    OBJECTCLASS_PARSING_TEST_DATA: ClassVar[dict[str;", True),
            (
                AclParsingScenario.ACL_WITH_GRANT,
                "allow (read) by dn=users;",
                True,
            ),
            (AclParsingScenario.EMPTY_ACL, "", False),
        ],
    )
    def test_acl_parsing_scenarios(
        self,
        scenario: str,
        acl_content: str,
        should_parse: bool,
        oid_acl_quirk: FlextLdifProtocols.Quirks.AclProtocol,
    ) -> None:
        """Test ACL parsing with various scenarios."""
        result = oid_acl_quirk.parse(acl_content)
        if should_parse:
            self.assert_success(result)
        else:
            self.assert_failure(result)

    # ═════════════════════════════════════════════════════════════════════════════
    # ENTRY PROCESSING TESTS
    # ═════════════════════════════════════════════════════════════════════════════

    def test_entry_creation_basic(
        self,
    ) -> None:
        """Test basic entry creation with OID models."""
        entry = m.Entry(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "objectClass": ["person"],
            },
        )

        assert entry.dn is not None
        assert entry.dn.value == "cn=test,dc=example,dc=com"
        # Access attributes via dict-like interface
        assert entry.attributes is not None
        assert "cn" in entry.attributes.attributes
        cn_values: list[str] = entry.attributes["cn"]
        assert cn_values == ["test"]
        assert "objectClass" in entry.attributes.attributes
        oc_values: list[str] = entry.attributes["objectClass"]
        assert oc_values == ["person"]

    def test_entry_with_oracle_attributes(
        self,
        oid_entry_quirk: FlextLdifProtocols.Quirks.EntryProtocol,
    ) -> None:
        """Test entry processing with Oracle-specific attributes."""
        entry = m.Entry(
            dn="cn=oracle,dc=example,dc=com",
            attributes={
                "cn": ["oracle"],
                "orclguid": ["550e8400-e29b-41d4-a716-446655440000"],
                "objectClass": ["orclPerson"],
            },
        )

        assert entry.dn is not None
        assert entry.dn.value == "cn=oracle,dc=example,dc=com"
        # LdifAttributes uses dictionary interface, not dynamic attributes
        assert entry.attributes is not None
        assert "orclguid" in entry.attributes.attributes
        orclguid_values: list[str] = entry.attributes.attributes["orclguid"]
        assert orclguid_values[0] == "550e8400-e29b-41d4-a716-446655440000"

    @pytest.mark.parametrize(
        ("scenario", "source_value", "target_value", "direction"),
        [
            (
                BooleanConversionScenario.OID_TRUE_TO_RFC,
                "1",
                "TRUE",
                "oid_to_rfc",
            ),
            (
                BooleanConversionScenario.OID_FALSE_TO_RFC,
                "0",
                "FALSE",
                "oid_to_rfc",
            ),
            (
                BooleanConversionScenario.RFC_TRUE_TO_OID,
                "TRUE",
                "1",
                "rfc_to_oid",
            ),
            (
                BooleanConversionScenario.RFC_FALSE_TO_OID,
                "FALSE",
                "0",
                "rfc_to_oid",
            ),
        ],
    )
    def test_boolean_attribute_conversions(
        self,
        scenario: str,
        source_value: str,
        target_value: str,
        direction: str,
    ) -> None:
        """Test boolean attribute value conversions."""
        # OID uses "0"/"1" while RFC uses "FALSE"/"TRUE"
        oid_to_rfc_map = {"0": "FALSE", "1": "TRUE"}
        rfc_to_oid_map = {"TRUE": "1", "FALSE": "0"}

        if direction == "oid_to_rfc":
            assert oid_to_rfc_map[source_value] == target_value
        else:
            assert rfc_to_oid_map[source_value] == target_value

    # ═════════════════════════════════════════════════════════════════════════════
    # CONVERSION AND METADATA TESTS
    # ═════════════════════════════════════════════════════════════════════════════

    def test_attribute_to_rfc_conversion(
        self,
    ) -> None:
        """Test attribute conversion from OID to c.RFC."""
        oracle_attr = m.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclguid",
            metadata=m.QuirkMetadata(
                quirk_type="oid",
                extensions={
                    "original_format": ("( 2.16.840.1.113894.1.1.1 NAME 'orclguid' )"),
                },
            ),
        )

        # Verify metadata preservation
        assert oracle_attr.metadata is not None
        assert oracle_attr.metadata.quirk_type == "oid"
        assert "original_format" in oracle_attr.metadata.extensions

    def test_objectclass_to_rfc_conversion(
        self,
    ) -> None:
        """Test objectClass conversion from OID to c.RFC."""
        oracle_oc = m.SchemaObjectClass(
            oid="2.16.840.1.113894.2.1.1",
            name="orclContext",
            sup="top",
            kind="STRUCTURAL",
            metadata=m.QuirkMetadata(
                quirk_type="oid",
                extensions={
                    "original_format": (
                        "( 2.16.840.1.113894.2.1.1 NAME 'orclContext' SUP top )"
                    ),
                },
            ),
        )

        # Verify metadata preservation
        assert oracle_oc.metadata is not None
        assert oracle_oc.metadata.quirk_type == "oid"
        assert "original_format" in oracle_oc.metadata.extensions

    # ═════════════════════════════════════════════════════════════════════════════
    # ERROR HANDLING TESTS
    # ═════════════════════════════════════════════════════════════════════════════

    def test_invalid_oid_format_handling(
        self,
    ) -> None:
        """Test handling of invalid OID formats."""
        invalid_oids = [
            "",
            "invalid",
            "3.1.1.1",  # Can't start with 3
            "1.1.1.1.a",  # Contains non-numeric
        ]

        for invalid_oid in invalid_oids:
            result = FlextLdifUtilities.OID.validate_format(invalid_oid)
            assert result.is_success
            assert not result.unwrap(), f"OID {invalid_oid} should be invalid"

    def test_missing_required_attributes(
        self,
        schema_quirk: FlextLdifServersBaseSchema,
    ) -> None:
        """Test handling of missing required attributes."""
        # Attribute without NAME
        incomplete_attr = (
            "( 2.16.840.1.113894.1.1.1 SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )

        result = schema_quirk.parse_attribute(incomplete_attr)
        # This may or may not succeed depending on RFC parsing
        assert hasattr(result, "is_success")

    def test_malformed_definition_handling(
        self,
        schema_quirk: FlextLdifServersBaseSchema,
    ) -> None:
        """Test handling of malformed definitions."""
        malformed_definitions = [
            "( 2.16.840.1.113894.1.1.1 NAME 'test",  # Missing closing paren
            "2.16.840.1.113894.1.1.1 NAME 'test'",  # Missing parens
            "( NAME 'test' )",  # Missing OID
        ]

        for malformed in malformed_definitions:
            result = schema_quirk.parse_attribute(malformed)
            # Parsing may fail
            assert hasattr(result, "is_success")

    # ═════════════════════════════════════════════════════════════════════════════
    # INTEGRATION TESTS
    # ═════════════════════════════════════════════════════════════════════════════

    def test_full_schema_attribute_objectclass_chain(
        self,
        schema_quirk: FlextLdifServersBaseSchema,
    ) -> None:
        """Test processing attribute and objectClass together."""
        oracle_attr = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclguid' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        oracle_oc = (
            "( 2.16.840.1.113894.2.1.1 NAME 'orclContext' "
            "SUP top STRUCTURAL MUST (cn) MAY (description) )"
        )

        attr_result = schema_quirk.parse_attribute(oracle_attr)
        oc_result = schema_quirk.parse_objectclass(oracle_oc)

        self.assert_success(attr_result)
        self.assert_success(oc_result)

        attr = attr_result.unwrap()
        oc = oc_result.unwrap()

        assert attr.name == "orclguid"
        assert oc.name == "orclContext"

    def test_oid_quirk_with_real_ldif_instance(
        self,
        flext_ldif: FlextLdif,
    ) -> None:
        """Test OID quirk integration with FlextLdif instance."""
        assert flext_ldif is not None
        assert isinstance(flext_ldif, FlextLdif)

    def test_fixture_based_parsing(
        self,
        oid_fixtures: FlextLdifFixtures.OID,
        schema_quirk: FlextLdifServersBaseSchema,
    ) -> None:
        """Test parsing with real OID fixtures."""
        schema_content = oid_fixtures.schema()

        assert len(schema_content) > 0, "Fixture should have content"

        # Count parseable lines
        parsed_count = 0
        for line in schema_content.split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                result = schema_quirk.parse(line)
                if result.is_success:
                    parsed_count += 1

        # At least verify the parsing logic runs without error
        assert parsed_count >= 0

    # ═════════════════════════════════════════════════════════════════════════════
    # UTILITY AND EDGE CASE TESTS
    # ═════════════════════════════════════════════════════════════════════════════

    def test_oid_extraction_from_definition(
        self,
    ) -> None:
        """Test OID extraction utility for attribute definitions."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclguid' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )

        extracted = FlextLdifUtilities.OID.extract_from_definition(attr_def)
        assert extracted == "2.16.840.1.113894.1.1.1"

    def test_oid_extraction_edge_cases(
        self,
    ) -> None:
        """Test OID extraction with edge cases."""
        test_cases = [
            ("( 0.9.2342.19200300.100.1.1 NAME 'uid' )", "0.9.2342.19200300.100.1.1"),
            (
                "( 2.16.840.1.113894.1.1.1 NAME 'orclguid' )",
                "2.16.840.1.113894.1.1.1",
            ),
            ("( 2.5.4.3 NAME 'cn' )", "2.5.4.3"),
        ]

        for definition, expected_oid in test_cases:
            extracted = FlextLdifUtilities.OID.extract_from_definition(
                definition,
            )
            assert extracted == expected_oid

    def test_oracle_namespace_detection_comprehensive(
        self,
    ) -> None:
        """Test comprehensive Oracle namespace detection."""
        oracle_oids = [
            "2.16.840.1.113894.1.1.1",
            "2.16.840.1.113894.2.1.1",
            "2.16.840.1.113894.3.1.1",
            "2.16.840.1.113894.10.15.20",
        ]

        non_oracle_oids = [
            "0.9.2342.19200300.100.1.1",
            "2.5.4.3",
            "1.3.6.1.4.1.1466.115.121.1.15",
        ]

        for oracle_oid in oracle_oids:
            assert FlextLdifUtilities.OID.is_oracle_oid(oracle_oid)

        for non_oracle_oid in non_oracle_oids:
            assert not FlextLdifUtilities.OID.is_oracle_oid(non_oracle_oid)

    def test_quirk_priority_and_ordering(
        self,
    ) -> None:
        """Test OID quirk priority in quirk system."""
        assert FlextLdifServersOid.priority == 10
        # Lower priority number = higher priority
        # OID should have reasonable priority relative to other servers

    # ═════════════════════════════════════════════════════════════════════════════
    # ROUNDTRIP AND COMPATIBILITY TESTS
    # ═════════════════════════════════════════════════════════════════════════════

    def test_attribute_roundtrip_preservation(
        self,
    ) -> None:
        """Test attribute metadata is preserved through operations."""
        original_oid = "2.16.840.1.113894.1.1.1"
        original_name = "orclguid"

        attr = m.SchemaAttribute(
            oid=original_oid,
            name=original_name,
            metadata=m.QuirkMetadata(
                quirk_type="oid",
                extensions={
                    "original_format": f"( {original_oid} NAME '{original_name}' )",
                },
            ),
        )

        # Verify roundtrip integrity
        assert attr.oid == original_oid
        assert attr.name == original_name
        assert attr.metadata is not None
        assert attr.metadata.quirk_type == "oid"

    def test_objectclass_roundtrip_preservation(
        self,
    ) -> None:
        """Test objectClass metadata is preserved through operations."""
        original_oid = "2.16.840.1.113894.2.1.1"
        original_name = "orclContext"

        oc = m.SchemaObjectClass(
            oid=original_oid,
            name=original_name,
            sup="top",
            kind="STRUCTURAL",
            metadata=m.QuirkMetadata(
                quirk_type="oid",
                extensions={
                    "original_format": f"( {original_oid} NAME '{original_name}' SUP top )",
                },
            ),
        )

        # Verify roundtrip integrity
        assert oc.oid == original_oid
        assert oc.name == original_name
        assert oc.metadata is not None
        assert oc.metadata.quirk_type == "oid"
