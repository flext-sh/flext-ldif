"""Test suite for FlextLdifConstants.

Modules tested: FlextLdifConstants (Format, Processing, QualityAnalysis,
LdifValidation, ObjectClasses, Encoding, LdapServers, RfcCompliance, enums)
Scope: Constant validation, enum values, namespace access, reasonable value ranges

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar

import pytest

from flext_ldif import FlextLdifConstants


class EnumType(StrEnum):
    """Enum types for testing."""

    PROCESSING_STAGE = "processing_stage"
    HEALTH_STATUS = "health_status"
    ENTRY_TYPE = "entry_type"
    ENTRY_MODIFICATION = "entry_modification"


class TestFormatConstants:
    """Test Format constants."""

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

    @pytest.mark.parametrize(
        ("name", "expected_value"),
        list(FORMAT_CONSTANTS.items()),
    )
    def test_format_constants(self, name: str, expected_value: object) -> None:
        """Test format constant value."""
        actual = getattr(FlextLdifConstants.Format, name)
        assert actual == expected_value

    def test_default_version_matches_version_1(self) -> None:
        """Test that default LDIF version matches version 1."""
        assert (
            FlextLdifConstants.Format.DEFAULT_LDIF_VERSION
            == FlextLdifConstants.Format.LDIF_VERSION_1
        )


class TestProcessingConstants:
    """Test processing and worker constants."""

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

    @staticmethod
    def _get_constant_value(path: str) -> object:
        """Get constant value by path."""
        parts = path.split(".")
        value: object = FlextLdifConstants
        for part in parts:
            value = getattr(value, part)
        return value

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
            FlextLdifConstants.DEBUG_MAX_WORKERS
            <= FlextLdifConstants.LdifProcessing.MAX_WORKERS_LIMIT
        )

    def test_performance_workers_less_than_max(self) -> None:
        """Test performance workers is less than max workers limit."""
        assert (
            FlextLdifConstants.LdifProcessing.PERFORMANCE_MIN_WORKERS
            <= FlextLdifConstants.LdifProcessing.MAX_WORKERS_LIMIT
        )


class TestEncodingConstants:
    """Test encoding constants."""

    SUPPORTED_ENCODINGS: ClassVar[list[str]] = ["utf-8", "utf-16", "ascii"]

    def test_default_encoding_is_utf8(self) -> None:
        """Test default encoding is utf-8."""
        assert FlextLdifConstants.DEFAULT_ENCODING == "utf-8"

    def test_supported_encodings_is_frozenset(self) -> None:
        """Test supported encodings is a frozenset."""
        assert isinstance(FlextLdifConstants.SUPPORTED_ENCODINGS, frozenset)

    def test_default_in_supported_encodings(self) -> None:
        """Test default encoding is in supported encodings set."""
        assert (
            FlextLdifConstants.DEFAULT_ENCODING
            in FlextLdifConstants.SUPPORTED_ENCODINGS
        )

    @pytest.mark.parametrize("encoding", SUPPORTED_ENCODINGS)
    def test_supported_encodings_contains(self, encoding: str) -> None:
        """Test encoding is in supported encodings."""
        assert encoding in FlextLdifConstants.SUPPORTED_ENCODINGS


class TestValidationConstants:
    """Test validation limit constants."""

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

    @staticmethod
    def _get_constant_value(path: str) -> object:
        """Get constant value by path."""
        parts = path.split(".")
        value: object = FlextLdifConstants
        for part in parts:
            value = getattr(value, part)
        return value

    @pytest.mark.parametrize(
        ("path", "expected_value"),
        list(VALIDATION_CONSTANTS.items()),
    )
    def test_validation_constants(self, path: str, expected_value: object) -> None:
        """Test validation constant value."""
        actual = self._get_constant_value(path)
        assert actual == expected_value


class TestQualityConstants:
    """Test quality analysis constants."""

    QUALITY_CONSTANTS: ClassVar[dict[str, object]] = {
        "QualityAnalysis.QUALITY_THRESHOLD_MEDIUM": 0.8,
        "QualityAnalysis.MIN_DN_COMPONENTS_FOR_BASE_PATTERN": 2,
    }

    @staticmethod
    def _get_constant_value(path: str) -> object:
        """Get constant value by path."""
        parts = path.split(".")
        value: object = FlextLdifConstants
        for part in parts:
            value = getattr(value, part)
        return value

    @pytest.mark.parametrize(
        ("path", "expected_value"),
        list(QUALITY_CONSTANTS.items()),
    )
    def test_quality_constants(self, path: str, expected_value: object) -> None:
        """Test quality constant value."""
        actual = self._get_constant_value(path)
        assert actual == expected_value


class TestObjectClassConstants:
    """Test ObjectClasses constants."""

    @pytest.mark.parametrize(
        "object_class",
        ["person", "organizationalPerson", "inetOrgPerson"],
    )
    def test_ldap_person_classes(self, object_class: str) -> None:
        """Test object class is in LDAP person classes."""
        assert object_class in FlextLdifConstants.ObjectClasses.LDAP_PERSON_CLASSES

    @pytest.mark.parametrize(
        "object_class",
        ["groupOfNames", "groupOfUniqueNames"],
    )
    def test_ldap_group_classes(self, object_class: str) -> None:
        """Test object class is in LDAP group classes."""
        assert object_class in FlextLdifConstants.ObjectClasses.LDAP_GROUP_CLASSES


class TestLdapServerConstants:
    """Test LdapServers constants."""

    LDAP_SERVERS: ClassVar[dict[str, str]] = {
        "ACTIVE_DIRECTORY": "active_directory",
        "OPENLDAP": "openldap",
        "ORACLE_OID": "oracle_oid",
        "ORACLE_OUD": "oracle_oud",
    }

    @pytest.mark.parametrize(
        ("attr_name", "expected_value"),
        list(LDAP_SERVERS.items()),
    )
    def test_ldap_server_constants(self, attr_name: str, expected_value: str) -> None:
        """Test LDAP server constant value."""
        actual = getattr(FlextLdifConstants.LdapServers, attr_name)
        assert actual == expected_value


class TestRfcComplianceConstants:
    """Test RfcCompliance constants."""

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

    @pytest.mark.parametrize("feature", REQUIRED_FEATURES)
    def test_required_features(self, feature: str) -> None:
        """Test feature is in required features."""
        assert feature in FlextLdifConstants.RfcCompliance.REQUIRED_FEATURES

    @pytest.mark.parametrize("feature", OPTIONAL_FEATURES)
    def test_optional_features(self, feature: str) -> None:
        """Test feature is in optional features."""
        assert feature in FlextLdifConstants.RfcCompliance.OPTIONAL_FEATURES

    @pytest.mark.parametrize(
        ("attr_name", "expected_value"),
        list(COMPLIANCE_MODES.items()),
    )
    def test_compliance_modes(self, attr_name: str, expected_value: str) -> None:
        """Test RFC compliance mode constants."""
        actual = getattr(FlextLdifConstants.RfcCompliance, attr_name)
        assert actual == expected_value


class TestEnumValues:
    """Test enum values."""

    ENUM_TEST_CASES: ClassVar[list[tuple[EnumType, str, str]]] = [
        (EnumType.PROCESSING_STAGE, "PARSING", "parsing"),
        (EnumType.PROCESSING_STAGE, "VALIDATION", "validation"),
        (EnumType.PROCESSING_STAGE, "ANALYTICS", "analytics"),
        (EnumType.PROCESSING_STAGE, "WRITING", "writing"),
        (EnumType.HEALTH_STATUS, "HEALTHY", "healthy"),
        (EnumType.HEALTH_STATUS, "DEGRADED", "degraded"),
        (EnumType.HEALTH_STATUS, "UNHEALTHY", "unhealthy"),
        (EnumType.ENTRY_TYPE, "PERSON", "person"),
        (EnumType.ENTRY_TYPE, "GROUP", "group"),
        (EnumType.ENTRY_TYPE, "ORGANIZATIONAL_UNIT", "organizationalunit"),
        (EnumType.ENTRY_TYPE, "DOMAIN", "domain"),
        (EnumType.ENTRY_TYPE, "OTHER", "other"),
        (EnumType.ENTRY_MODIFICATION, "ADD", "add"),
        (EnumType.ENTRY_MODIFICATION, "MODIFY", "modify"),
        (EnumType.ENTRY_MODIFICATION, "DELETE", "delete"),
        (EnumType.ENTRY_MODIFICATION, "MODRDN", "modrdn"),
    ]

    ENUM_CLASS_MAP: ClassVar[dict[EnumType, type[object]]] = {
        EnumType.PROCESSING_STAGE: FlextLdifConstants.ProcessingStage,
        EnumType.HEALTH_STATUS: FlextLdifConstants.LdifHealthStatus,
        EnumType.ENTRY_TYPE: FlextLdifConstants.EntryType,
        EnumType.ENTRY_MODIFICATION: FlextLdifConstants.EntryModification,
    }

    @pytest.mark.parametrize(
        ("enum_type", "member_name", "expected_value"),
        ENUM_TEST_CASES,
    )
    def test_enum_values(
        self, enum_type: EnumType, member_name: str, expected_value: str,
    ) -> None:
        """Test enum member value."""
        enum_class = self.ENUM_CLASS_MAP[enum_type]
        enum_member = getattr(enum_class, member_name)
        assert enum_member.value == expected_value


class TestNamespaceValidation:
    """Test FlextLdifConstants namespace access."""

    NAMESPACE_GROUPS: ClassVar[list[str]] = [
        "Encoding",
        "Format",
        "Processing",
        "LdifGeneralValidation",
        "Acl",
        "Schema",
    ]

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
        # Encoding
        assert (
            FlextLdifConstants.DEFAULT_ENCODING
            in FlextLdifConstants.SUPPORTED_ENCODINGS
        )

        # Format
        assert 40 < FlextLdifConstants.Format.MAX_LINE_LENGTH < 200

        # Processing
        assert FlextLdifConstants.LdifProcessing.MAX_WORKERS_LIMIT > 0
        assert (
            FlextLdifConstants.DEBUG_MAX_WORKERS
            <= FlextLdifConstants.LdifProcessing.MAX_WORKERS_LIMIT
        )
        assert FlextLdifConstants.LdifProcessing.PERFORMANCE_MIN_WORKERS > 0

        # Validation
        assert FlextLdifConstants.LdifGeneralValidation.NAME_LENGTH_MIN >= 0
        assert (
            FlextLdifConstants.LdifGeneralValidation.NAME_LENGTH_MAX
            > FlextLdifConstants.LdifGeneralValidation.NAME_LENGTH_MIN
        )
