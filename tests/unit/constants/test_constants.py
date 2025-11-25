"""Test suite for FlextLdifConstants.

Modules tested: FlextLdifConstants (Format, Processing, QualityAnalysis,
LdifValidation, ObjectClasses, Encoding, LdapServers, RfcCompliance, enums)
Scope: Constant validation, enum values, namespace access, reasonable value ranges

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import dataclasses
from enum import StrEnum

import pytest

from flext_ldif import FlextLdifConstants


# Test scenario enums
class ConstantGroup(StrEnum):
    """Constant groups for parametrized testing."""

    ENCODING = "encoding"
    FORMAT = "format"
    PROCESSING = "processing"
    VALIDATION = "validation"
    QUALITY = "quality"
    OBJECTCLASSES = "objectclasses"
    LDAPSERVERS = "ldapservers"
    RFCCOMPLIANCE = "rfccompliance"


class EnumType(StrEnum):
    """Enum types for testing."""

    PROCESSING_STAGE = "processing_stage"
    HEALTH_STATUS = "health_status"
    ENTRY_TYPE = "entry_type"
    ENTRY_MODIFICATION = "entry_modification"


# Test data structures
@dataclasses.dataclass(frozen=True)
class ConstantTestCase:
    """Constant test case."""

    constant_path: str
    expected_value: object
    expected_type: type


@dataclasses.dataclass(frozen=True)
class EnumTestCase:
    """Enum member test case."""

    enum_type: EnumType
    member_name: str
    expected_value: str


# Test data mapping for parametrization
FORMAT_CONSTANTS = {
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

PROCESSING_CONSTANTS = {
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

VALIDATION_CONSTANTS = {
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

QUALITY_CONSTANTS = {
    "QualityAnalysis.QUALITY_THRESHOLD_MEDIUM": 0.8,
    "QualityAnalysis.MIN_DN_COMPONENTS_FOR_BASE_PATTERN": 2,
}

ENUM_TEST_CASES = [
    EnumTestCase(EnumType.PROCESSING_STAGE, "PARSING", "parsing"),
    EnumTestCase(EnumType.PROCESSING_STAGE, "VALIDATION", "validation"),
    EnumTestCase(EnumType.PROCESSING_STAGE, "ANALYTICS", "analytics"),
    EnumTestCase(EnumType.PROCESSING_STAGE, "WRITING", "writing"),
    EnumTestCase(EnumType.HEALTH_STATUS, "HEALTHY", "healthy"),
    EnumTestCase(EnumType.HEALTH_STATUS, "DEGRADED", "degraded"),
    EnumTestCase(EnumType.HEALTH_STATUS, "UNHEALTHY", "unhealthy"),
    EnumTestCase(EnumType.ENTRY_TYPE, "PERSON", "person"),
    EnumTestCase(EnumType.ENTRY_TYPE, "GROUP", "group"),
    EnumTestCase(EnumType.ENTRY_TYPE, "ORGANIZATIONAL_UNIT", "organizationalunit"),
    EnumTestCase(EnumType.ENTRY_TYPE, "DOMAIN", "domain"),
    EnumTestCase(EnumType.ENTRY_TYPE, "OTHER", "other"),
    EnumTestCase(EnumType.ENTRY_MODIFICATION, "ADD", "add"),
    EnumTestCase(EnumType.ENTRY_MODIFICATION, "MODIFY", "modify"),
    EnumTestCase(EnumType.ENTRY_MODIFICATION, "DELETE", "delete"),
    EnumTestCase(EnumType.ENTRY_MODIFICATION, "MODRDN", "modrdn"),
]

NAMESPACE_GROUPS = [
    "Encoding",
    "Format",
    "Processing",
    "LdifGeneralValidation",
    "Acl",
    "Schema",
]


# Helper functions
def get_constant_value(path: str) -> object:
    """Get constant value by path."""
    parts = path.split(".")
    value = FlextLdifConstants
    for part in parts:
        value = getattr(value, part)
    return value


def get_enum_class(enum_type: EnumType) -> type[object]:
    """Get enum class by type."""
    mapping: dict[EnumType, type[object]] = {
        EnumType.PROCESSING_STAGE: FlextLdifConstants.ProcessingStage,
        EnumType.HEALTH_STATUS: FlextLdifConstants.LdifHealthStatus,
        EnumType.ENTRY_TYPE: FlextLdifConstants.EntryType,
        EnumType.ENTRY_MODIFICATION: FlextLdifConstants.EntryModification,
    }
    return mapping[enum_type]


# Parametrization functions
def get_format_constant_cases() -> list[tuple[str, object]]:
    """Generate format constant test cases."""
    return list(FORMAT_CONSTANTS.items())


def get_processing_constant_cases() -> list[tuple[str, object]]:
    """Generate processing constant test cases."""
    return list(PROCESSING_CONSTANTS.items())


def get_validation_constant_cases() -> list[tuple[str, object]]:
    """Generate validation constant test cases."""
    return list(VALIDATION_CONSTANTS.items())


def get_quality_constant_cases() -> list[tuple[str, object]]:
    """Generate quality constant test cases."""
    return list(QUALITY_CONSTANTS.items())


def get_enum_test_cases() -> list[EnumTestCase]:
    """Generate enum test cases."""
    return ENUM_TEST_CASES


class TestFormatConstants:
    """Test Format constants."""

    @pytest.mark.parametrize(
        ("name", "expected_value"),
        get_format_constant_cases(),
    )
    def test_format_constants(
        self,
        name: str,
        expected_value: object,
    ) -> None:
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

    @pytest.mark.parametrize(
        ("path", "expected_value"),
        get_processing_constant_cases(),
    )
    def test_processing_constants(
        self,
        path: str,
        expected_value: object,
    ) -> None:
        """Test processing constant value."""
        actual = get_constant_value(path)
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

    def test_default_encoding_is_utf8(self) -> None:
        """Test default encoding is utf-8."""
        assert FlextLdifConstants.DEFAULT_ENCODING == "utf-8"

    def test_supported_encodings_is_frozenset(self) -> None:
        """Test supported encodings is a frozenset."""
        assert isinstance(
            FlextLdifConstants.SUPPORTED_ENCODINGS,
            frozenset,
        )

    def test_default_in_supported_encodings(self) -> None:
        """Test default encoding is in supported encodings set."""
        assert (
            FlextLdifConstants.DEFAULT_ENCODING
            in FlextLdifConstants.SUPPORTED_ENCODINGS
        )

    def test_utf8_in_supported_encodings(self) -> None:
        """Test utf-8 is in supported encodings."""
        assert "utf-8" in FlextLdifConstants.SUPPORTED_ENCODINGS

    def test_utf16_in_supported_encodings(self) -> None:
        """Test utf-16 is in supported encodings."""
        assert "utf-16" in FlextLdifConstants.SUPPORTED_ENCODINGS

    def test_ascii_in_supported_encodings(self) -> None:
        """Test ascii is in supported encodings."""
        assert "ascii" in FlextLdifConstants.SUPPORTED_ENCODINGS


class TestValidationConstants:
    """Test validation limit constants."""

    @pytest.mark.parametrize(
        ("path", "expected_value"),
        get_validation_constant_cases(),
    )
    def test_validation_constants(
        self,
        path: str,
        expected_value: object,
    ) -> None:
        """Test validation constant value."""
        actual = get_constant_value(path)
        assert actual == expected_value


class TestQualityConstants:
    """Test quality analysis constants."""

    @pytest.mark.parametrize(
        ("path", "expected_value"),
        get_quality_constant_cases(),
    )
    def test_quality_constants(
        self,
        path: str,
        expected_value: object,
    ) -> None:
        """Test quality constant value."""
        actual = get_constant_value(path)
        assert actual == expected_value


class TestObjectClassConstants:
    """Test ObjectClasses constants."""

    def test_person_in_ldap_person_classes(self) -> None:
        """Test person is in LDAP person classes."""
        assert "person" in FlextLdifConstants.ObjectClasses.LDAP_PERSON_CLASSES

    def test_groupofnames_in_ldap_group_classes(self) -> None:
        """Test groupOfNames is in LDAP group classes."""
        assert "groupOfNames" in FlextLdifConstants.ObjectClasses.LDAP_GROUP_CLASSES


class TestLdapServerConstants:
    """Test LdapServers constants."""

    def test_active_directory_constant(self) -> None:
        """Test Active Directory constant."""
        assert FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY == "active_directory"

    def test_openldap_constant(self) -> None:
        """Test OpenLDAP constant."""
        assert FlextLdifConstants.LdapServers.OPENLDAP == "openldap"


class TestRfcComplianceConstants:
    """Test RfcCompliance constants."""

    def test_base64_encoding_in_required(self) -> None:
        """Test base64_encoding in required features."""
        assert "base64_encoding" in FlextLdifConstants.RfcCompliance.REQUIRED_FEATURES

    def test_language_tags_in_optional(self) -> None:
        """Test language_tags in optional features."""
        assert "language_tags" in FlextLdifConstants.RfcCompliance.OPTIONAL_FEATURES

    def test_compliance_modes(self) -> None:
        """Test RFC compliance mode constants."""
        assert FlextLdifConstants.RfcCompliance.STRICT == "strict"
        assert FlextLdifConstants.RfcCompliance.MODERATE == "moderate"
        assert FlextLdifConstants.RfcCompliance.LENIENT == "lenient"


class TestEnumValues:
    """Test enum values."""

    @pytest.mark.parametrize(
        "test_case",
        get_enum_test_cases(),
    )
    def test_enum_values(self, test_case: EnumTestCase) -> None:
        """Test enum member value."""
        enum_class = get_enum_class(test_case.enum_type)
        enum_member = getattr(enum_class, test_case.member_name)
        assert enum_member.value == test_case.expected_value


class TestNamespaceValidation:
    """Test FlextLdifConstants namespace access."""

    @pytest.mark.parametrize(
        "group_name",
        NAMESPACE_GROUPS,
    )
    def test_constant_groups_accessible(
        self,
        group_name: str,
    ) -> None:
        """Test constant group is accessible."""
        assert hasattr(FlextLdifConstants, group_name)

    @pytest.mark.parametrize(
        "group_name",
        NAMESPACE_GROUPS,
    )
    def test_constant_groups_are_classes(
        self,
        group_name: str,
    ) -> None:
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


__all__ = [
    "ConstantGroup",
    "ConstantTestCase",
    "EnumTestCase",
    "EnumType",
    "TestEncodingConstants",
    "TestEnumValues",
    "TestFormatConstants",
    "TestLdapServerConstants",
    "TestNamespaceValidation",
    "TestObjectClassConstants",
    "TestProcessingConstants",
    "TestQualityConstants",
    "TestRfcComplianceConstants",
    "TestValidationConstants",
]
