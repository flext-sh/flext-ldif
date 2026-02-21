"""Tests for FlextLdif constants and configuration values.

This module tests all FlextLdifConstants groups including format,
processing, encoding, validation, quality, and LDAP server constants.
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar

import pytest
from flext_ldif import t
from flext_ldif import FlextLdifConstants
from flext_ldif.constants import c
from tests import s


class TestsTestFlextLdifConstants(s):
    """Consolidated test suite for c.

    Tests all constant groups: Format, Processing, Encoding, Validation,
    Quality, ObjectClasses, LdapServers, RfcCompliance, Enums, and Namespace.
    """

    # ════════════════════════════════════════════════════════════════════════
    # TEST DATA DEFINITIONS
    # ════════════════════════════════════════════════════════════════════════

    class EnumType(StrEnum):
        """Enum types for testing."""

        PROCESSING_STAGE = "processing_stage"
        HEALTH_STATUS = "health_status"
        ENTRY_TYPE = "entry_type"
        ENTRY_MODIFICATION = "entry_modification"

    FORMAT_CONSTANTS: ClassVar[dict[str, object]] = {
        "DN_ATTRIBUTE": "dn",
        "ATTRIBUTE_SEPARATOR": ":",
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
        "Ldif.LdifProcessing.MIN_WORKERS_FOR_PARALLEL": 2,
        "Ldif.LdifProcessing.MAX_WORKERS_LIMIT": 16,
        "Ldif.LdifProcessing.PERFORMANCE_MIN_WORKERS": 4,
        "Ldif.LdifProcessing.PERFORMANCE_MIN_CHUNK_SIZE": 1000,
        "Ldif.LdifProcessing.MIN_ANALYTICS_CACHE_SIZE": 100,
        "Ldif.LdifProcessing.MAX_ANALYTICS_CACHE_SIZE": 10000,
        "Ldif.LdifProcessing.MIN_ENTRIES": 1000,
        "Ldif.LdifProcessing.MIN_MEMORY_MB": 64,
        "Ldif.LdifProcessing.PERFORMANCE_MEMORY_MB_THRESHOLD": 512,
        "Ldif.LdifProcessing.DEBUG_MAX_WORKERS": 2,
        "Ldif.LdifProcessing.SMALL_ENTRY_COUNT_THRESHOLD": 100,
        "Ldif.LdifProcessing.MEDIUM_ENTRY_COUNT_THRESHOLD": 1000,
        "Ldif.LdifProcessing.MIN_ATTRIBUTE_PARTS": 2,
    }

    # SUPPORTED_ENCODINGS list removed - Encoding is a StrEnum
    ENCODING_MEMBERS: ClassVar[list[str]] = ["UTF8", "UTF16", "ASCII"]

    VALIDATION_CONSTANTS: ClassVar[dict[str, object]] = {
        "Ldif.LdifValidation.MIN_DN_COMPONENTS": 1,
        "Ldif.LdifValidation.MAX_DN_LENGTH": 2048,
        "Ldif.LdifValidation.MAX_ATTRIBUTES_PER_ENTRY": 1000,
        "Ldif.LdifValidation.MAX_VALUES_PER_ATTRIBUTE": 100,
        "Ldif.LdifValidation.MAX_ATTRIBUTE_VALUE_LENGTH": 10000,
        "Ldif.LdifValidation.MIN_ATTRIBUTE_NAME_LENGTH": 1,
        "Ldif.LdifValidation.MAX_ATTRIBUTE_NAME_LENGTH": 127,
        "Ldif.LdifValidation.MIN_URL_LENGTH": 1,
        "Ldif.LdifValidation.MAX_URL_LENGTH": 2048,
        "Ldif.LdifValidation.MIN_ENCODING_LENGTH": 1,
        "Ldif.LdifValidation.MAX_ENCODING_LENGTH": 50,
    }

    QUALITY_CONSTANTS: ClassVar[dict[str, object]] = {
        "Ldif.QualityAnalysis.QUALITY_THRESHOLD_MEDIUM": 0.8,
        "Ldif.QualityAnalysis.MIN_DN_COMPONENTS_FOR_BASE_PATTERN": 2,
    }

    LDAP_SERVERS: ClassVar[dict[str, str]] = {
        "ACTIVE_DIRECTORY": "ad",
        "OPENLDAP": "openldap",
        "ORACLE_OID": "oid",
        "ORACLE_OUD": "oud",
    }

    # REQUIRED_FEATURES and OPTIONAL_FEATURES removed - RfcCompliance doesn't have these
    # Only MODERATE exists in RfcCompliance

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
        "ENTRY_TYPE": c.Ldif.EntryType,
        "CHANGE_TYPE": c.Ldif.ChangeType,
    }

    NAMESPACE_GROUPS: ClassVar[list[str]] = [
        "Encoding",
        "Format",
        "LdifProcessing",
        "LdifValidation",
        "Acl",
        "LdifFormatting",
    ]

    # ════════════════════════════════════════════════════════════════════════
    # HELPER METHODS
    # ════════════════════════════════════════════════════════════════════════

    @staticmethod
    def _get_constant_value(path: str) -> t.GeneralValueType:
        """Get constant value by path."""
        parts = path.split(".")
        value: t.GeneralValueType = FlextLdifConstants  # type: ignore[assignment]
        for part in parts:
            value = getattr(value, part)
        return value

    # ════════════════════════════════════════════════════════════════════════
    # FORMAT CONSTANTS TESTS (2 tests)
    # ════════════════════════════════════════════════════════════════════════

    @pytest.mark.parametrize(
        ("name", "expected_value"),
        list(FORMAT_CONSTANTS.items()),
    )
    def test_format_constants(self, name: str, expected_value: object) -> None:
        """Test format constant value."""
        actual = getattr(c.Ldif.Format, name)
        assert actual == expected_value

    def test_default_version_matches_version_1(self) -> None:
        """Test that LDIF formatting constants are properly defined."""
        assert c.Ldif.LdifFormatting.DEFAULT_LINE_WIDTH == 78
        assert c.Ldif.LdifFormatting.MAX_LINE_WIDTH == 199

    # ════════════════════════════════════════════════════════════════════════
    # PROCESSING CONSTANTS TESTS (3 tests)
    # ════════════════════════════════════════════════════════════════════════

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
            c.Ldif.LdifProcessing.DEBUG_MAX_WORKERS
            <= c.Ldif.LdifProcessing.MAX_WORKERS_LIMIT
        )

    def test_performance_workers_less_than_max(self) -> None:
        """Test performance workers is less than max workers limit."""
        assert (
            c.Ldif.LdifProcessing.PERFORMANCE_MIN_WORKERS
            <= c.Ldif.LdifProcessing.MAX_WORKERS_LIMIT
        )

    # ════════════════════════════════════════════════════════════════════════
    # ENCODING CONSTANTS TESTS (3 tests)
    # ════════════════════════════════════════════════════════════════════════

    def test_default_encoding_is_utf8(self) -> None:
        """Test default encoding is utf-8."""
        assert c.Ldif.DEFAULT_ENCODING == "utf-8"

    def test_encoding_is_strenum(self) -> None:
        """Test Encoding is a StrEnum with expected members."""
        # Encoding is a StrEnum, not a set
        assert isinstance(c.Ldif.Encoding.UTF8, str)
        assert c.Ldif.Encoding.UTF8 == "utf-8"

    @pytest.mark.parametrize("encoding_name", ENCODING_MEMBERS)
    def test_encoding_members_exist(self, encoding_name: str) -> None:
        """Test encoding member exists in Encoding enum."""
        assert hasattr(c.Ldif.Encoding, encoding_name)

    # ════════════════════════════════════════════════════════════════════════
    # VALIDATION CONSTANTS TESTS (1 test)
    # ════════════════════════════════════════════════════════════════════════

    @pytest.mark.parametrize(
        ("path", "expected_value"),
        list(VALIDATION_CONSTANTS.items()),
    )
    def test_validation_constants(self, path: str, expected_value: object) -> None:
        """Test validation constant value."""
        actual = self._get_constant_value(path)
        assert actual == expected_value

    # ════════════════════════════════════════════════════════════════════════
    # QUALITY CONSTANTS TESTS (1 test)
    # ════════════════════════════════════════════════════════════════════════

    @pytest.mark.parametrize(
        ("path", "expected_value"),
        list(QUALITY_CONSTANTS.items()),
    )
    def test_quality_constants(self, path: str, expected_value: object) -> None:
        """Test quality constant value."""
        actual = self._get_constant_value(path)
        assert actual == expected_value

    # ════════════════════════════════════════════════════════════════════════
    # OBJECT CLASS CONSTANTS TESTS (2 tests)
    # ════════════════════════════════════════════════════════════════════════

    @pytest.mark.parametrize(
        ("attr_name", "expected_value"),
        [
            ("INET_ORG_PERSON", "inetOrgPerson"),
            ("ORGANIZATIONAL_PERSON", "organizationalPerson"),
        ],
    )
    def test_person_object_classes(self, attr_name: str, expected_value: str) -> None:
        """Test person object class constants."""
        assert getattr(c.Ldif.ObjectClasses, attr_name) == expected_value

    @pytest.mark.parametrize(
        ("attr_name", "expected_value"),
        [
            ("GROUP_OF_NAMES", "groupOfNames"),
            ("GROUP_OF_UNIQUE_NAMES", "groupOfUniqueNames"),
        ],
    )
    def test_group_object_classes(self, attr_name: str, expected_value: str) -> None:
        """Test group object class constants."""
        assert getattr(c.Ldif.ObjectClasses, attr_name) == expected_value

    # ════════════════════════════════════════════════════════════════════════
    # LDAP SERVER CONSTANTS TESTS (1 test)
    # ════════════════════════════════════════════════════════════════════════

    @pytest.mark.parametrize(
        ("attr_name", "expected_value"),
        list(LDAP_SERVERS.items()),
    )
    def test_ldap_server_constants(self, attr_name: str, expected_value: str) -> None:
        """Test LDAP server constant value."""
        actual = getattr(c.Ldif.LdapServers, attr_name)
        assert actual == expected_value

    # ════════════════════════════════════════════════════════════════════════
    # RFC COMPLIANCE CONSTANTS TESTS (1 test)
    # ════════════════════════════════════════════════════════════════════════

    @pytest.mark.parametrize(
        ("attr_name", "expected_value"),
        list(COMPLIANCE_MODES.items()),
    )
    def test_compliance_modes(self, attr_name: str, expected_value: str) -> None:
        """Test RFC compliance mode constants."""
        actual = getattr(c.Ldif.RfcCompliance, attr_name)
        assert actual == expected_value

    # ════════════════════════════════════════════════════════════════════════
    # ENUM VALUES TESTS (1 test)
    # ════════════════════════════════════════════════════════════════════════

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

    # ════════════════════════════════════════════════════════════════════════
    # NAMESPACE VALIDATION TESTS (4 tests)
    # ════════════════════════════════════════════════════════════════════════

    @pytest.mark.parametrize("group_name", NAMESPACE_GROUPS)
    def test_constant_groups_accessible(self, group_name: str) -> None:
        """Test constant group is accessible."""
        assert hasattr(c.Ldif, group_name)

    @pytest.mark.parametrize("group_name", NAMESPACE_GROUPS)
    def test_constant_groups_are_classes(self, group_name: str) -> None:
        """Test constant group is a class."""
        group = getattr(c.Ldif, group_name)
        assert isinstance(group, type)

    def test_constant_values_are_reasonable(self) -> None:
        """Test that constant values are within reasonable ranges."""
        # Encoding (Encoding is a StrEnum, not a set with SUPPORTED_ENCODINGS)
        assert c.Ldif.DEFAULT_ENCODING == "utf-8"
        assert c.Ldif.Encoding.UTF8 == "utf-8"

        # Format
        assert 40 < c.Ldif.LdifFormatting.MAX_LINE_WIDTH < 200

        # Processing
        assert c.Ldif.LdifProcessing.MAX_WORKERS_LIMIT > 0
        assert (
            c.Ldif.LdifProcessing.DEBUG_MAX_WORKERS
            <= c.Ldif.LdifProcessing.MAX_WORKERS_LIMIT
        )
        assert c.Ldif.LdifProcessing.PERFORMANCE_MIN_WORKERS > 0

        # Validation
        assert c.Ldif.LdifValidation.MIN_ATTRIBUTE_NAME_LENGTH >= 0
        assert (
            c.Ldif.LdifValidation.MAX_ATTRIBUTE_NAME_LENGTH
            > c.Ldif.LdifValidation.MIN_ATTRIBUTE_NAME_LENGTH
        )
