"""Consolidated tests for FlextLdif constants and configuration values.

This module consolidates all constant tests from tests/unit/constants/ into a single file.
Tests all FlextLdifConstants groups including format, processing, encoding, validation,
quality, and LDAP server constants, plus ACL attribute registry.
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar

import pytest

from flext_ldif import FlextLdifConstants
from flext_ldif.constants import c as lib_c
from tests import s


class TestsTestFlextLdifConstants(s):
    """Consolidated test suite for lib_c.

    Tests all constant groups: Format, Processing, Encoding, Validation,
    Quality, ObjectClasses, LdapServers, RfcCompliance, Enums, and Namespace.
    """

    class EnumType(StrEnum):
        """Enum types for testing."""

        PROCESSING_STAGE = "processing_stage"
        HEALTH_STATUS = "health_status"
        ENTRY_TYPE = "entry_type"
        ENTRY_MODIFICATION = "entry_modification"

    FORMAT_CONSTANTS: ClassVar[dict[str, object]] = {
        "DN_ATTRIBUTE": "dn",
        "ATTRIBUTE_SEPARATOR": ":",
        "DN_PREFIX": "dn:",
        "MAX_LINE_LENGTH": 78,
        "MIN_BUFFER_SIZE": 1024,
        "CONTENT_PREVIEW_LENGTH": 100,
        "MAX_ATTRIBUTES_DISPLAY": 10,
        "BASE64_PREFIX": "::",
        "COMMENT_PREFIX": "#",
        "VERSION_PREFIX": "version:",
        "CHANGE_TYPE_PREFIX": "changetype:",
        "ATTRIBUTE_OPTION_SEPARATOR": ";",
        "URL_PREFIX": "<",
        "URL_SUFFIX": ">",
        "LDIF_VERSION_1": "1",
    }

    PROCESSING_CONSTANTS: ClassVar[dict[str, object]] = {
        "LdifProcessing.MIN_WORKERS_FOR_PARALLEL": 2,
        "LdifProcessing.MAX_WORKERS_LIMIT": 16,
        "LdifProcessing.PERFORMANCE_MIN_WORKERS": 4,
        "LdifProcessing.PERFORMANCE_MIN_CHUNK_SIZE": 1000,
        "MIN_ANALYTICS_CACHE_SIZE": 100,
        "MAX_ANALYTICS_CACHE_SIZE": 10000,
        "MIN_ENTRIES": 1000,
        "MIN_MEMORY_MB": 64,
        "PERFORMANCE_MEMORY_MB_THRESHOLD": 512,
        "DEBUG_MAX_WORKERS": 2,
        "SMALL_ENTRY_COUNT_THRESHOLD": 100,
        "MEDIUM_ENTRY_COUNT_THRESHOLD": 1000,
        "MIN_ATTRIBUTE_PARTS": 2,
    }

    SUPPORTED_ENCODINGS: ClassVar[list[str]] = ["utf-8", "utf-16", "ascii"]

    VALIDATION_CONSTANTS: ClassVar[dict[str, object]] = {
        "LdifValidation.MIN_DN_COMPONENTS": 1,
        "LdifValidation.MAX_DN_LENGTH": 2048,
        "LdifValidation.MAX_ATTRIBUTES_PER_ENTRY": 1000,
        "LdifValidation.MAX_VALUES_PER_ATTRIBUTE": 100,
        "LdifValidation.MAX_ATTRIBUTE_VALUE_LENGTH": 10000,
        "LdifValidation.MIN_ATTRIBUTE_NAME_LENGTH": 1,
        "LdifValidation.MAX_ATTRIBUTE_NAME_LENGTH": 127,
        "LdifValidation.MIN_URL_LENGTH": 1,
        "LdifValidation.MAX_URL_LENGTH": 2048,
        "LdifValidation.MIN_ENCODING_LENGTH": 1,
        "LdifValidation.MAX_ENCODING_LENGTH": 50,
    }

    QUALITY_CONSTANTS: ClassVar[dict[str, object]] = {
        "QualityAnalysis.QUALITY_THRESHOLD_MEDIUM": 0.8,
        "QualityAnalysis.MIN_DN_COMPONENTS_FOR_BASE_PATTERN": 2,
    }

    LDAP_SERVERS: ClassVar[dict[str, str]] = {
        "ACTIVE_DIRECTORY": "ad",
        "OPENLDAP": "openldap",
        "ORACLE_OID": "oid",
        "ORACLE_OUD": "oud",
    }

    REQUIRED_FEATURES: ClassVar[list[str]] = [
        "base64_encoding",
        "line_continuation",
        "url_references",
        "comments",
        "change_records",
    ]

    OPTIONAL_FEATURES: ClassVar[list[str]] = [
        "language_tags",
        "large_entries",
        "binary_data",
    ]

    COMPLIANCE_MODES: ClassVar[dict[str, str]] = {
        "STRICT": "strict",
        "MODERATE": "moderate",
        "LENIENT": "lenient",
    }

    ENUM_TEST_CASES: ClassVar[list[tuple[str, str, str]]] = [
        ("PROCESSING_STAGE", "PARSING", "parsing"),
        ("PROCESSING_STAGE", "VALIDATION", "validation"),
        ("PROCESSING_STAGE", "ANALYTICS", "analytics"),
        ("PROCESSING_STAGE", "WRITING", "writing"),
        ("HEALTH_STATUS", "HEALTHY", "healthy"),
        ("HEALTH_STATUS", "DEGRADED", "degraded"),
        ("HEALTH_STATUS", "UNHEALTHY", "unhealthy"),
        ("ENTRY_TYPE", "PERSON", "person"),
        ("ENTRY_TYPE", "GROUP", "group"),
        ("ENTRY_TYPE", "ORGANIZATIONAL_UNIT", "organizationalunit"),
        ("ENTRY_TYPE", "DOMAIN", "domain"),
        ("ENTRY_TYPE", "OTHER", "other"),
        ("ENTRY_MODIFICATION", "ADD", "add"),
        ("ENTRY_MODIFICATION", "MODIFY", "modify"),
        ("ENTRY_MODIFICATION", "DELETE", "delete"),
        ("ENTRY_MODIFICATION", "MODRDN", "modrdn"),
    ]

    ENUM_CLASS_MAP: ClassVar[dict[str, type[object]]] = {
        "PROCESSING_STAGE": lib_c.Ldif.ProcessingStage,
        "HEALTH_STATUS": lib_c.Ldif.LdifHealthStatus,
        "ENTRY_TYPE": lib_c.Ldif.EntryType,
        "ENTRY_MODIFICATION": lib_c.Ldif.EntryModification,
    }

    NAMESPACE_GROUPS: ClassVar[list[str]] = [
        "Encoding",
        "Format",
        "Processing",
        "LdifGeneralValidation",
        "Acl",
        "Schema",
    ]

    @staticmethod
    def _get_constant_value(path: str) -> object:
        """Get constant value by path."""
        parts = path.split(".")
        value: object = FlextLdifConstants
        for part in parts:
            value = getattr(value, part)
        return value

    @pytest.mark.parametrize(
        ("name", "expected_value"),
        list(FORMAT_CONSTANTS.items()),
    )
    def test_format_constants(self, name: str, expected_value: object) -> None:
        """Test format constant value."""
        actual = getattr(lib_c.Ldif.Format, name)
        assert actual == expected_value

    def test_default_version_matches_version_1(self) -> None:
        """Test that LDIF formatting constants are properly defined."""
        assert lib_c.Ldif.LdifFormatting.DEFAULT_LINE_WIDTH == 78
        assert lib_c.Ldif.LdifFormatting.MAX_LINE_WIDTH == 199

    @pytest.mark.parametrize(
        ("path", "expected_value"),
        list(PROCESSING_CONSTANTS.items()),
    )
    def test_processing_constants(self, path: str, expected_value: object) -> None:
        """Test processing constant value."""
        actual = self._get_constant_value(path)
        assert actual == expected_value

    def test_debug_workers_less_than_max(self) -> None:
        """Test debug workers is less than max workers limit."""
        assert (
            lib_c.Ldif.DEBUG_MAX_WORKERS <= lib_c.Ldif.LdifProcessing.MAX_WORKERS_LIMIT
        )

    def test_performance_workers_less_than_max(self) -> None:
        """Test performance workers is less than max workers limit."""
        assert (
            lib_c.Ldif.LdifProcessing.PERFORMANCE_MIN_WORKERS
            <= lib_c.Ldif.LdifProcessing.MAX_WORKERS_LIMIT
        )

    def test_default_encoding_is_utf8(self) -> None:
        """Test default encoding is utf-8."""
        assert lib_c.Ldif.DEFAULT_ENCODING == "utf-8"

    def test_supported_encodings_is_frozenset(self) -> None:
        """Test supported encodings is a frozenset."""
        assert isinstance(lib_c.Ldif.SUPPORTED_ENCODINGS, frozenset)

    def test_default_in_supported_encodings(self) -> None:
        """Test default encoding is in supported encodings set."""
        assert lib_c.Ldif.DEFAULT_ENCODING in lib_c.Ldif.SUPPORTED_ENCODINGS

    @pytest.mark.parametrize("encoding", SUPPORTED_ENCODINGS)
    def test_supported_encodings_contains(self, encoding: str) -> None:
        """Test encoding is in supported encodings."""
        assert encoding in lib_c.Ldif.SUPPORTED_ENCODINGS

    @pytest.mark.parametrize(
        ("path", "expected_value"),
        list(VALIDATION_CONSTANTS.items()),
    )
    def test_validation_constants(self, path: str, expected_value: object) -> None:
        """Test validation constant value."""
        actual = self._get_constant_value(path)
        assert actual == expected_value

    @pytest.mark.parametrize(
        ("path", "expected_value"),
        list(QUALITY_CONSTANTS.items()),
    )
    def test_quality_constants(self, path: str, expected_value: object) -> None:
        """Test quality constant value."""
        actual = self._get_constant_value(path)
        assert actual == expected_value

    @pytest.mark.parametrize(
        "object_class",
        ["person", "organizationalPerson", "inetOrgPerson"],
    )
    def test_ldap_person_classes(self, object_class: str) -> None:
        """Test object class is in LDAP person classes."""
        assert object_class in lib_c.Ldif.ObjectClasses.LDAP_PERSON_CLASSES

    @pytest.mark.parametrize(
        "object_class",
        ["groupOfNames", "groupOfUniqueNames"],
    )
    def test_ldap_group_classes(self, object_class: str) -> None:
        """Test object class is in LDAP group classes."""
        assert object_class in lib_c.Ldif.ObjectClasses.LDAP_GROUP_CLASSES

    @pytest.mark.parametrize(
        ("attr_name", "expected_value"),
        list(LDAP_SERVERS.items()),
    )
    def test_ldap_server_constants(self, attr_name: str, expected_value: str) -> None:
        """Test LDAP server constant value."""
        actual = getattr(lib_c.Ldif.LdapServers, attr_name)
        assert actual == expected_value

    @pytest.mark.parametrize("feature", REQUIRED_FEATURES)
    def test_required_features(self, feature: str) -> None:
        """Test feature is in required features."""
        assert feature in lib_c.Ldif.RfcCompliance.REQUIRED_FEATURES

    @pytest.mark.parametrize("feature", OPTIONAL_FEATURES)
    def test_optional_features(self, feature: str) -> None:
        """Test feature is in optional features."""
        assert feature in lib_c.Ldif.RfcCompliance.OPTIONAL_FEATURES

    @pytest.mark.parametrize(
        ("attr_name", "expected_value"),
        list(COMPLIANCE_MODES.items()),
    )
    def test_compliance_modes(self, attr_name: str, expected_value: str) -> None:
        """Test RFC compliance mode constants."""
        actual = getattr(lib_c.Ldif.RfcCompliance, attr_name)
        assert actual == expected_value

    @pytest.mark.parametrize(
        ("enum_type", "member_name", "expected_value"),
        ENUM_TEST_CASES,
    )
    def test_enum_values(
        self,
        enum_type: str,
        member_name: str,
        expected_value: str,
    ) -> None:
        """Test enum member value."""
        enum_class = self.ENUM_CLASS_MAP[enum_type]
        enum_member = getattr(enum_class, member_name)
        assert enum_member.value == expected_value

    @pytest.mark.parametrize("group_name", NAMESPACE_GROUPS)
    def test_constant_groups_accessible(self, group_name: str) -> None:
        """Test constant group is accessible."""
        assert hasattr(FlextLdifConstants, group_name)

    @pytest.mark.parametrize("group_name", NAMESPACE_GROUPS)
    def test_constant_groups_are_classes(self, group_name: str) -> None:
        """Test constant group is a class."""
        group = getattr(FlextLdifConstants, group_name)
        assert isinstance(group, type)

    def test_constant_values_are_reasonable(self) -> None:
        """Test that constant values are within reasonable ranges."""
        assert lib_c.Ldif.DEFAULT_ENCODING in lib_c.Ldif.SUPPORTED_ENCODINGS
        assert 40 < lib_c.Ldif.LdifFormatting.MAX_LINE_WIDTH < 200
        assert lib_c.Ldif.LdifProcessing.MAX_WORKERS_LIMIT > 0
        assert (
            lib_c.Ldif.DEBUG_MAX_WORKERS <= lib_c.Ldif.LdifProcessing.MAX_WORKERS_LIMIT
        )
        assert lib_c.Ldif.LdifProcessing.PERFORMANCE_MIN_WORKERS > 0
        assert lib_c.Ldif.LdifGeneralValidation.NAME_LENGTH_MIN >= 0
        assert (
            lib_c.Ldif.LdifGeneralValidation.NAME_LENGTH_MAX
            > lib_c.Ldif.LdifGeneralValidation.NAME_LENGTH_MIN
        )


# =============================================================================
# ACL ATTRIBUTE REGISTRY TESTS
# =============================================================================


class GetAclAttributesServerType(StrEnum):
    """Server types for get_acl_attributes tests."""

    RFC = "rfc"
    OID = "oid"
    OUD = "oud"
    AD = "ad"
    GENERIC = "generic"
    UNKNOWN = "unknown_server"
    NONE = "none"


class IsAclAttributeType(StrEnum):
    """Is ACL attribute test scenarios."""

    VALID_RFC = "valid_rfc"
    VALID_SERVER_SPECIFIC = "valid_server_specific"
    INVALID = "invalid"
    CASE_INSENSITIVE = "case_insensitive"


@pytest.mark.unit
class TestsTestFlextLdifAclAttributeRegistry(s):
    """Test suite for AclAttributeRegistry."""

    GET_ACL_ATTRIBUTES_DATA: ClassVar[
        dict[str, tuple[GetAclAttributesServerType, str | None, list[str], list[str]]]
    ] = {
        "get_acl_attributes_rfc_foundation": (
            GetAclAttributesServerType.RFC,
            None,
            ["aci", "acl", "olcAccess", "aclRights", "aclEntry"],
            [],
        ),
        "get_acl_attributes_oid_quirks": (
            GetAclAttributesServerType.OID,
            "oid",
            ["orclaci", "orclentrylevelaci", "aci", "acl"],
            [],
        ),
        "get_acl_attributes_oud_quirks": (
            GetAclAttributesServerType.OUD,
            "oud",
            ["orclaci", "orclentrylevelaci", "aci"],
            [],
        ),
        "get_acl_attributes_ad_quirks": (
            GetAclAttributesServerType.AD,
            "ad",
            ["nTSecurityDescriptor", "aci"],
            [],
        ),
        "get_acl_attributes_generic": (
            GetAclAttributesServerType.GENERIC,
            "generic",
            ["aci", "acl"],
            ["orclaci", "nTSecurityDescriptor"],
        ),
        "get_acl_attributes_unknown": (
            GetAclAttributesServerType.UNKNOWN,
            "unknown_server",
            ["aci", "acl"],
            ["orclaci", "nTSecurityDescriptor"],
        ),
        "get_acl_attributes_none": (
            GetAclAttributesServerType.NONE,
            None,
            ["aci", "acl"],
            ["orclaci"],
        ),
    }

    IS_ACL_ATTRIBUTE_DATA: ClassVar[
        dict[str, tuple[IsAclAttributeType, str, str | None, bool]]
    ] = {
        "is_acl_attribute_rfc_aci": (IsAclAttributeType.VALID_RFC, "aci", None, True),
        "is_acl_attribute_rfc_acl": (IsAclAttributeType.VALID_RFC, "acl", None, True),
        "is_acl_attribute_rfc_olcAccess": (
            IsAclAttributeType.VALID_RFC,
            "olcAccess",
            None,
            True,
        ),
        "is_acl_attribute_oid_orclaci": (
            IsAclAttributeType.VALID_SERVER_SPECIFIC,
            "orclaci",
            "oid",
            True,
        ),
        "is_acl_attribute_oud_orclaci": (
            IsAclAttributeType.VALID_SERVER_SPECIFIC,
            "orclaci",
            "oud",
            True,
        ),
        "is_acl_attribute_invalid_cn": (IsAclAttributeType.INVALID, "cn", None, False),
        "is_acl_attribute_invalid_uid": (
            IsAclAttributeType.INVALID,
            "uid",
            None,
            False,
        ),
        "is_acl_attribute_case_insensitive_aci": (
            IsAclAttributeType.CASE_INSENSITIVE,
            "ACI",
            None,
            True,
        ),
        "is_acl_attribute_case_insensitive_acl": (
            IsAclAttributeType.CASE_INSENSITIVE,
            "Acl",
            None,
            True,
        ),
        "is_acl_attribute_case_insensitive_olcAccess": (
            IsAclAttributeType.CASE_INSENSITIVE,
            "OLCACCESS",
            None,
            True,
        ),
        "is_acl_attribute_case_insensitive_orclaci": (
            IsAclAttributeType.CASE_INSENSITIVE,
            "OrclAci",
            "oid",
            True,
        ),
    }

    @pytest.mark.parametrize(
        (
            "scenario",
            "server_type",
            "param_server_type",
            "required_attrs",
            "forbidden_attrs",
        ),
        [
            (name, data[0], data[1], data[2], data[3])
            for name, data in GET_ACL_ATTRIBUTES_DATA.items()
        ],
    )
    def test_get_acl_attributes(
        self,
        scenario: str,
        server_type: GetAclAttributesServerType,
        param_server_type: str | None,
        required_attrs: list[str],
        forbidden_attrs: list[str],
    ) -> None:
        """Parametrized test for get_acl_attributes."""
        attrs = lib_c.Ldif.AclAttributeRegistry.get_acl_attributes(
            param_server_type,
        )
        for required in required_attrs:
            assert required in attrs, f"{required} not in {scenario}"
        for forbidden in forbidden_attrs:
            assert forbidden not in attrs, f"{forbidden} should not be in {scenario}"

    @pytest.mark.parametrize(
        ("scenario", "test_type", "attr_name", "server_type", "expected_result"),
        [
            (name, data[0], data[1], data[2], data[3])
            for name, data in IS_ACL_ATTRIBUTE_DATA.items()
        ],
    )
    def test_is_acl_attribute(
        self,
        scenario: str,
        test_type: IsAclAttributeType,
        attr_name: str,
        server_type: str | None,
        expected_result: bool,
    ) -> None:
        """Parametrized test for is_acl_attribute."""
        registry = lib_c.Ldif.AclAttributeRegistry
        if server_type is not None:
            result = registry.is_acl_attribute(attr_name, server_type)
        else:
            result = registry.is_acl_attribute(attr_name)
        assert result == expected_result, f"{scenario} failed"

    def test_acl_registry_no_mutation(self) -> None:
        """get_acl_attributes should return new list each time."""
        attrs1 = list(lib_c.Ldif.AclAttributeRegistry.get_acl_attributes("oid"))
        attrs2 = list(lib_c.Ldif.AclAttributeRegistry.get_acl_attributes("oid"))
        assert attrs1 == attrs2
        assert attrs1 is not attrs2
        attrs1.append("test_attribute")
        assert "test_attribute" not in attrs2
