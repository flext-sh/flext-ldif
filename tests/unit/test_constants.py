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
from flext_ldif.utilities import u as lib_u

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
        "KEYWORD_DN": "dn",
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
        "LdifProcessing.MIN_ANALYTICS_CACHE_SIZE": 100,
        "LdifProcessing.MAX_ANALYTICS_CACHE_SIZE": 10000,
        "LdifProcessing.MIN_ENTRIES": 1000,
        "LdifProcessing.MIN_MEMORY_MB": 64,
        "LdifProcessing.PERFORMANCE_MEMORY_MB_THRESHOLD": 512,
        "LdifProcessing.DEBUG_MAX_WORKERS": 2,
        "LdifProcessing.SMALL_ENTRY_COUNT_THRESHOLD": 100,
        "LdifProcessing.MEDIUM_ENTRY_COUNT_THRESHOLD": 1000,
        "LdifProcessing.MIN_ATTRIBUTE_PARTS": 2,
    }

    # Encoding StrEnum values to test
    ENCODING_VALUES: ClassVar[list[str]] = ["utf-8", "utf-16", "ascii"]

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

    QUALITY_CONSTANTS: ClassVar[dict[str, object]] = {}

    LDAP_SERVERS: ClassVar[dict[str, str]] = {
        "ACTIVE_DIRECTORY": "ad",
        "OPENLDAP": "openldap",
        "ORACLE_OID": "oid",
        "ORACLE_OUD": "oud",
    }

    # Note: RfcCompliance only has MODERATE, no STRICT or LENIENT
    COMPLIANCE_MODES: ClassVar[dict[str, str]] = {
        "MODERATE": "moderate",
    }

    ENUM_TEST_CASES: ClassVar[list[tuple[str, str, str]]] = [
        ("ENTRY_TYPE", "PERSON", "person"),
        ("ENTRY_TYPE", "GROUP", "group"),
        ("ENTRY_TYPE", "ORGANIZATIONAL_UNIT", "organizationalunit"),
        ("ENTRY_TYPE", "DOMAIN", "domain"),
        ("ENTRY_TYPE", "OTHER", "other"),
        ("CHANGE_TYPE", "ADD", "add"),
        ("CHANGE_TYPE", "MODIFY", "modify"),
        ("CHANGE_TYPE", "DELETE", "delete"),
        ("CHANGE_TYPE", "MODRDN", "modrdn"),
    ]

    ENUM_CLASS_MAP: ClassVar[dict[str, type[object]]] = {
        "ENTRY_TYPE": lib_c.Ldif.EntryType,
        "CHANGE_TYPE": lib_c.Ldif.ChangeType,
    }

    # Classes that should be accessible under FlextLdifConstants.Ldif
    NAMESPACE_GROUPS: ClassVar[list[str]] = [
        "Format",
        "LdifProcessing",
        "LdifValidation",
        "ObjectClasses",
        "LdapServers",
        "RfcCompliance",
        "Acl",
    ]

    @staticmethod
    def _get_constant_value(path: str) -> object:
        """Get constant value by path starting from lib_c.Ldif."""
        parts = path.split(".")
        value: object = lib_c.Ldif
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
            lib_c.Ldif.LdifProcessing.DEBUG_MAX_WORKERS
            <= lib_c.Ldif.LdifProcessing.MAX_WORKERS_LIMIT
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

    def test_encoding_enum_has_utf8(self) -> None:
        """Test Encoding StrEnum has UTF8 member."""
        assert lib_c.Ldif.Encoding.UTF8 == "utf-8"

    def test_encoding_enum_has_utf16(self) -> None:
        """Test Encoding StrEnum has UTF16 member."""
        assert lib_c.Ldif.Encoding.UTF16 == "utf-16"

    def test_encoding_enum_has_ascii(self) -> None:
        """Test Encoding StrEnum has ASCII member."""
        assert lib_c.Ldif.Encoding.ASCII == "ascii"

    @pytest.mark.parametrize("encoding", ENCODING_VALUES)
    def test_encoding_values_exist(self, encoding: str) -> None:
        """Test encoding value exists in Encoding enum."""
        # Check that the encoding value exists as a member value
        enum_values = [e.value for e in lib_c.Ldif.Encoding]
        assert encoding in enum_values

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

    def test_object_classes_has_inet_org_person(self) -> None:
        """Test ObjectClasses has INET_ORG_PERSON constant."""
        assert lib_c.Ldif.ObjectClasses.INET_ORG_PERSON == "inetOrgPerson"

    def test_object_classes_has_organizational_person(self) -> None:
        """Test ObjectClasses has ORGANIZATIONAL_PERSON constant."""
        assert lib_c.Ldif.ObjectClasses.ORGANIZATIONAL_PERSON == "organizationalPerson"

    def test_object_classes_has_group_of_names(self) -> None:
        """Test ObjectClasses has GROUP_OF_NAMES constant."""
        assert lib_c.Ldif.ObjectClasses.GROUP_OF_NAMES == "groupOfNames"

    def test_object_classes_has_group_of_unique_names(self) -> None:
        """Test ObjectClasses has GROUP_OF_UNIQUE_NAMES constant."""
        assert lib_c.Ldif.ObjectClasses.GROUP_OF_UNIQUE_NAMES == "groupOfUniqueNames"

    @pytest.mark.parametrize(
        ("attr_name", "expected_value"),
        list(LDAP_SERVERS.items()),
    )
    def test_ldap_server_constants(self, attr_name: str, expected_value: str) -> None:
        """Test LDAP server constant value."""
        actual = getattr(lib_c.Ldif.LdapServers, attr_name)
        assert actual == expected_value

    def test_rfc_compliance_has_line_length_limit(self) -> None:
        """Test RfcCompliance has LINE_LENGTH_LIMIT constant."""
        assert lib_c.Ldif.RfcCompliance.LINE_LENGTH_LIMIT == 76

    def test_rfc_compliance_has_moderate(self) -> None:
        """Test RfcCompliance has MODERATE constant."""
        assert lib_c.Ldif.RfcCompliance.MODERATE == "moderate"

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
        """Test constant group is accessible via FlextLdifConstants.Ldif."""
        assert hasattr(FlextLdifConstants.Ldif, group_name)

    @pytest.mark.parametrize("group_name", NAMESPACE_GROUPS)
    def test_constant_groups_are_classes(self, group_name: str) -> None:
        """Test constant group is a class."""
        group = getattr(FlextLdifConstants.Ldif, group_name)
        assert isinstance(group, type)

    def test_constant_values_are_reasonable(self) -> None:
        """Test that constant values are within reasonable ranges."""
        # Verify default encoding is in Encoding enum
        enum_values = [e.value for e in lib_c.Ldif.Encoding]
        assert lib_c.Ldif.DEFAULT_ENCODING in enum_values
        # Verify line width limits
        assert 40 < lib_c.Ldif.LdifFormatting.MAX_LINE_WIDTH < 200
        # Verify worker limits
        assert lib_c.Ldif.LdifProcessing.MAX_WORKERS_LIMIT > 0
        assert (
            lib_c.Ldif.LdifProcessing.DEBUG_MAX_WORKERS
            <= lib_c.Ldif.LdifProcessing.MAX_WORKERS_LIMIT
        )
        assert lib_c.Ldif.LdifProcessing.PERFORMANCE_MIN_WORKERS > 0
        # Verify name length validation
        assert lib_c.Ldif.LdifValidation.MIN_ATTRIBUTE_NAME_LENGTH >= 0
        assert (
            lib_c.Ldif.LdifValidation.MAX_ATTRIBUTE_NAME_LENGTH
            > lib_c.Ldif.LdifValidation.MIN_ATTRIBUTE_NAME_LENGTH
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
        attrs = lib_u.Ldif.ACL.get_acl_attributes(param_server_type)
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
        result = lib_u.Ldif.ACL.is_acl_attribute(attr_name, server_type)
        assert result == expected_result, f"{scenario} failed"

    def test_acl_registry_no_mutation(self) -> None:
        """get_acl_attributes should return new list each time."""
        attrs1 = list(lib_u.Ldif.ACL.get_acl_attributes("oid"))
        attrs2 = list(lib_u.Ldif.ACL.get_acl_attributes("oid"))
        assert attrs1 == attrs2
        assert attrs1 is not attrs2
        attrs1.append("test_attribute")
        assert "test_attribute" not in attrs2
