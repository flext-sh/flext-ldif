"""Tests for flext_ldif.constants module.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.constants import FlextLdifConstants


class TestFlextLdifConstants:
    """Test FlextLdifConstants values."""

    def test_format_constants(self) -> None:
        """Test Format constants."""
        assert FlextLdifConstants.Format.DN_ATTRIBUTE == "dn"
        assert FlextLdifConstants.Format.ATTRIBUTE_SEPARATOR == ":"
        assert FlextLdifConstants.Format.DN_PREFIX == "dn:"
        assert FlextLdifConstants.Format.MAX_LINE_LENGTH == 78
        assert FlextLdifConstants.Format.MIN_BUFFER_SIZE == 1024
        assert FlextLdifConstants.Format.CONTENT_PREVIEW_LENGTH == 100
        assert FlextLdifConstants.Format.MAX_ATTRIBUTES_DISPLAY == 10
        assert FlextLdifConstants.Format.BASE64_PREFIX == "::"
        assert FlextLdifConstants.Format.COMMENT_PREFIX == "#"
        assert FlextLdifConstants.Format.VERSION_PREFIX == "version:"
        assert FlextLdifConstants.Format.CHANGE_TYPE_PREFIX == "changetype:"
        assert FlextLdifConstants.Format.ATTRIBUTE_OPTION_SEPARATOR == ";"
        assert FlextLdifConstants.Format.URL_PREFIX == "<"
        assert FlextLdifConstants.Format.URL_SUFFIX == ">"
        assert FlextLdifConstants.Format.LDIF_VERSION_1 == "1"
        assert (
            FlextLdifConstants.Format.DEFAULT_LDIF_VERSION
            == FlextLdifConstants.Format.LDIF_VERSION_1
        )

    def test_processing_constants(self) -> None:
        """Test Processing constants."""
        assert FlextLdifConstants.Processing.MIN_WORKERS_FOR_PARALLEL == 2
        assert FlextLdifConstants.Processing.MAX_WORKERS_LIMIT == 16
        assert FlextLdifConstants.Processing.PERFORMANCE_MIN_WORKERS == 4
        assert FlextLdifConstants.Processing.PERFORMANCE_MIN_CHUNK_SIZE == 1000
        assert FlextLdifConstants.Processing.MIN_ANALYTICS_CACHE_SIZE == 100
        assert FlextLdifConstants.Processing.MAX_ANALYTICS_CACHE_SIZE == 10000
        assert FlextLdifConstants.Processing.MIN_PRODUCTION_ENTRIES == 1000
        assert FlextLdifConstants.Processing.MIN_MEMORY_MB == 64
        assert FlextLdifConstants.Processing.PERFORMANCE_MEMORY_MB_THRESHOLD == 512
        assert FlextLdifConstants.Processing.DEBUG_MAX_WORKERS == 2
        assert FlextLdifConstants.Processing.SMALL_ENTRY_COUNT_THRESHOLD == 100
        assert FlextLdifConstants.Processing.MEDIUM_ENTRY_COUNT_THRESHOLD == 1000
        assert FlextLdifConstants.Processing.MIN_ATTRIBUTE_PARTS == 2

    def test_quality_analysis_constants(self) -> None:
        """Test QualityAnalysis constants."""
        assert FlextLdifConstants.QualityAnalysis.QUALITY_THRESHOLD_MEDIUM == 0.8
        assert (
            FlextLdifConstants.QualityAnalysis.MIN_DN_COMPONENTS_FOR_BASE_PATTERN == 2
        )

    def test_ldif_validation_constants(self) -> None:
        """Test LdifValidation constants."""
        assert FlextLdifConstants.LdifValidation.MIN_DN_COMPONENTS == 1
        assert FlextLdifConstants.LdifValidation.MAX_DN_LENGTH == 255
        assert FlextLdifConstants.LdifValidation.MAX_ATTRIBUTES_PER_ENTRY == 1000
        assert FlextLdifConstants.LdifValidation.MAX_VALUES_PER_ATTRIBUTE == 100
        assert FlextLdifConstants.LdifValidation.MAX_ATTRIBUTE_VALUE_LENGTH == 10000
        assert FlextLdifConstants.LdifValidation.MIN_ATTRIBUTE_NAME_LENGTH == 1
        assert FlextLdifConstants.LdifValidation.MAX_ATTRIBUTE_NAME_LENGTH == 255
        assert FlextLdifConstants.LdifValidation.MIN_URL_LENGTH == 1
        assert FlextLdifConstants.LdifValidation.MAX_URL_LENGTH == 2048
        assert FlextLdifConstants.LdifValidation.MIN_ENCODING_LENGTH == 1
        assert FlextLdifConstants.LdifValidation.MAX_ENCODING_LENGTH == 50

    def test_object_classes_constants(self) -> None:
        """Test ObjectClasses constants."""
        assert "person" in FlextLdifConstants.ObjectClasses.LDAP_PERSON_CLASSES
        assert "groupofnames" in FlextLdifConstants.ObjectClasses.LDAP_GROUP_CLASSES

    def test_encoding_constants(self) -> None:
        """Test Encoding constants."""
        assert FlextLdifConstants.Encoding.UTF8 == "utf-8"
        assert FlextLdifConstants.Encoding.LATIN1 == "latin-1"
        assert FlextLdifConstants.Encoding.ASCII == "ascii"
        assert (
            FlextLdifConstants.Encoding.DEFAULT_ENCODING
            == FlextLdifConstants.Encoding.UTF8
        )
        assert (
            FlextLdifConstants.Encoding.UTF8
            in FlextLdifConstants.Encoding.SUPPORTED_ENCODINGS
        )

    def test_ldap_servers_constants(self) -> None:
        """Test LdapServers constants."""
        assert FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY == "active_directory"
        assert FlextLdifConstants.LdapServers.OPENLDAP == "openldap"
        assert "CN=" in FlextLdifConstants.LdapServers.AD_DN_PATTERNS
        assert "cn=" in FlextLdifConstants.LdapServers.OPENLDAP_DN_PATTERNS

    def test_rfc_compliance_constants(self) -> None:
        """Test RfcCompliance constants."""
        assert "base64_encoding" in FlextLdifConstants.RfcCompliance.REQUIRED_FEATURES
        assert "language_tags" in FlextLdifConstants.RfcCompliance.OPTIONAL_FEATURES
        assert FlextLdifConstants.RfcCompliance.STRICT == "strict"
        assert FlextLdifConstants.RfcCompliance.MODERATE == "moderate"
        assert FlextLdifConstants.RfcCompliance.LENIENT == "lenient"

    def test_processing_stages_enum(self) -> None:
        """Test ProcessingStage enum."""
        assert FlextLdifConstants.ProcessingStage.PARSING == "parsing"
        assert FlextLdifConstants.ProcessingStage.VALIDATION == "validation"
        assert FlextLdifConstants.ProcessingStage.ANALYTICS == "analytics"
        assert FlextLdifConstants.ProcessingStage.WRITING == "writing"

    def test_health_status_enum(self) -> None:
        """Test HealthStatus enum."""
        assert FlextLdifConstants.HealthStatus.HEALTHY == "healthy"
        assert FlextLdifConstants.HealthStatus.DEGRADED == "degraded"
        assert FlextLdifConstants.HealthStatus.UNHEALTHY == "unhealthy"

    def test_entry_type_enum(self) -> None:
        """Test EntryType enum."""
        assert FlextLdifConstants.EntryType.PERSON == "person"
        assert FlextLdifConstants.EntryType.GROUP == "group"
        assert FlextLdifConstants.EntryType.ORGANIZATIONAL_UNIT == "organizationalunit"
        assert FlextLdifConstants.EntryType.DOMAIN == "domain"
        assert FlextLdifConstants.EntryType.OTHER == "other"

    def test_entry_modification_enum(self) -> None:
        """Test EntryModification enum."""
        assert FlextLdifConstants.EntryModification.ADD == "add"
        assert FlextLdifConstants.EntryModification.MODIFY == "modify"
        assert FlextLdifConstants.EntryModification.DELETE == "delete"
        assert FlextLdifConstants.EntryModification.MODRDN == "modrdn"
