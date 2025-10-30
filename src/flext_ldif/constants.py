"""LDIF constants and enumerations.

This module defines constant values and enumerations used throughout the
LDIF library. Types, protocols, and models are defined in separate modules.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from enum import StrEnum
from typing import Final, Literal

from flext_core import FlextConstants


class LdapServerType(StrEnum):
    """LDAP server types supported by FLEXT ecosystem."""

    ACTIVE_DIRECTORY = "active_directory"
    OPENLDAP = "openldap"
    APACHE_DIRECTORY = "apache_directory"
    NOVELL_EDIRECTORY = "novell_edirectory"
    IBM_TIVOLI = "ibm_tivoli"
    GENERIC = "generic"
    ORACLE_OID = "oracle_oid"
    ORACLE_OUD = "oracle_oud"
    DS_389 = "389ds"


class FlextLdifConstants(FlextConstants):
    """LDIF domain constants extending flext-core FlextConstants.

    Contains ONLY constant values, no implementations.
    """

    # =============================================================================
    # FORMAT CONSTANTS
    # =============================================================================

    # Oracle OID namespace identifier
    ORACLE_OID_NAMESPACE: Final[str] = "2.16.840.1.113894."

    class Format:
        """LDIF format specifications."""

        DN_ATTRIBUTE: Final[str] = "dn"
        ATTRIBUTE_SEPARATOR: Final[str] = ":"
        DN_PREFIX: Final[str] = "dn:"  # Combined DN attribute with separator

        # LDIF ObjectClass constants
        LDIF_OBJECTCLASS_GROUPOFNAMES: Final[str] = "groupOfNames"

        # Line length constraints (RFC 2849 compliance)
        MIN_LINE_LENGTH: Final[int] = 40  # Minimum allowed line length
        MAX_LINE_LENGTH: Final[int] = 78  # RFC 2849 standard
        MAX_LINE_LENGTH_EXTENDED: Final[int] = 200  # Extended for non-strict mode

        MIN_BUFFER_SIZE: Final[int] = 1024
        CONTENT_PREVIEW_LENGTH: Final[int] = 100
        MAX_ATTRIBUTES_DISPLAY: Final[int] = 10

        # Filesystem constraints
        MAX_FILENAME_LENGTH: Final[int] = 255  # Common filesystem limit

        # RFC 2849 specific constants
        BASE64_PREFIX: Final[str] = "::"
        COMMENT_PREFIX: Final[str] = "#"
        VERSION_PREFIX: Final[str] = "version:"
        CHANGE_TYPE_PREFIX: Final[str] = "changetype:"
        LINE_CONTINUATION_CHARS: Final[frozenset[str]] = frozenset([" ", "\t"])
        ATTRIBUTE_OPTION_SEPARATOR: Final[str] = ";"
        URL_PREFIX: Final[str] = "<"
        URL_SUFFIX: Final[str] = ">"

        # LDIF version constants
        LDIF_VERSION_1: Final[str] = "1"
        DEFAULT_LDIF_VERSION: Final[str] = LDIF_VERSION_1

    # =============================================================================
    # PROCESSING CONSTANTS
    # =============================================================================

    # Processing constants organized in LdifProcessing class
    class LdifProcessing:
        """LDIF processing-related constants."""

        # Worker configuration
        MIN_WORKERS: Final[int] = 1  # Minimum workers allowed
        MIN_WORKERS_FOR_PARALLEL: Final[int] = 2  # Minimum for parallel processing
        MAX_WORKERS_LIMIT: Final[int] = 16  # Maximum allowed workers
        PERFORMANCE_MIN_WORKERS: Final[int] = 4  # Minimum workers for performance

        # Chunk size configuration
        MIN_CHUNK_SIZE: Final[int] = 100  # Minimum chunk size
        MAX_CHUNK_SIZE: Final[int] = 10000  # Maximum chunk size
        PERFORMANCE_MIN_CHUNK_SIZE: Final[int] = 1000  # Minimum for performance

    # Entry limits
    MIN_ENTRIES: Final[int] = 1000
    MAX_ENTRIES_ABSOLUTE: Final[int] = 10000000  # 10 million entry hard limit

    # Analytics configuration
    MIN_ANALYTICS_CACHE_SIZE: Final[int] = 100
    MAX_ANALYTICS_CACHE_SIZE: Final[int] = 10000
    MIN_SAMPLE_RATE: Final[float] = 0.0  # Minimum analytics sample rate
    MAX_SAMPLE_RATE: Final[float] = 1.0  # Maximum analytics sample rate (100%)
    MAX_ANALYTICS_ENTRIES_ABSOLUTE: Final[int] = 100000  # Maximum analytics entries

    # Memory configuration
    MIN_MEMORY_MB: Final[int] = 64  # Minimum memory limit in MB
    MAX_MEMORY_MB: Final[int] = 8192  # Maximum memory limit in MB

    # Other thresholds
    ENCODING_CONFIDENCE_THRESHOLD: Final[float] = 0.7  # Encoding detection confidence

    # Batch size configuration
    DEFAULT_BATCH_SIZE: Final[int] = 1000  # Must be >= PERFORMANCE_MIN_CHUNK_SIZE
    MIN_BATCH_SIZE: Final[int] = 1  # Minimum batch size
    MAX_BATCH_SIZE: Final[int] = 10000  # Maximum batch size

    # Additional constants for config validation
    PERFORMANCE_MEMORY_MB_THRESHOLD: Final[int] = (
        512  # Memory threshold for performance
    )
    DEBUG_MAX_WORKERS: Final[int] = 2  # Max workers in debug mode
    SMALL_ENTRY_COUNT_THRESHOLD: Final[int] = 100  # Threshold for small entry counts
    MEDIUM_ENTRY_COUNT_THRESHOLD: Final[int] = 1000  # Threshold for medium entry counts
    MIN_ATTRIBUTE_PARTS: Final[int] = 2  # Minimum parts for attribute parsing

    # Search configuration defaults
    DEFAULT_SEARCH_TIME_LIMIT: Final[int] = 30  # Default search time limit in seconds
    DEFAULT_SEARCH_SIZE_LIMIT: Final[int] = (
        0  # Default search size limit (0 = unlimited)
    )

    # Version constants (moved from version.py for FLEXT compliance)
    # Note: Cannot override parent VERSION (Final), use LDIF_VERSION instead
    LDIF_VERSION: Final[str] = "0.9.9"  # Current LDIF library version
    LDIF_VERSION_INFO: Final[tuple[int, int, int]] = (0, 9, 9)  # Version tuple

    # Client operation constants
    MAX_PATH_LENGTH_CHECK: Final[int] = 500  # Maximum path length for file operations
    MAX_LOGGED_ERRORS: Final[int] = 5  # Maximum number of errors to log in output

    # =============================================================================
    # CONFIGURATION DEFAULTS
    # =============================================================================

    class ConfigDefaults:
        """Default values for FlextLdifConfig fields.

        Zero Tolerance: All Field(default=...) values MUST be defined here.
        """

        # Format Configuration Defaults
        LDIF_SKIP_COMMENTS: Final[bool] = False
        LDIF_VALIDATE_DN_FORMAT: Final[bool] = True
        LDIF_STRICT_VALIDATION: Final[bool] = True
        LDIF_LINE_SEPARATOR: Final[str] = "\n"
        LDIF_VERSION_STRING: Final[str] = "version: 1"

        # Processing Configuration Defaults
        LDIF_MAX_ENTRIES: Final[int] = 1000000
        ENABLE_PERFORMANCE_OPTIMIZATIONS: Final[bool] = True
        ENABLE_PARALLEL_PROCESSING: Final[bool] = True

        # Analytics Configuration Defaults
        LDIF_ENABLE_ANALYTICS: Final[bool] = True
        LDIF_FAIL_ON_WARNINGS: Final[bool] = False
        LDIF_ANALYTICS_SAMPLE_RATE: Final[float] = 1.0
        LDIF_ANALYTICS_MAX_ENTRIES: Final[int] = 10000
        ANALYTICS_DETAIL_LEVEL_LOW: Final[str] = "low"
        ANALYTICS_DETAIL_LEVEL_MEDIUM: Final[str] = "medium"
        ANALYTICS_DETAIL_LEVEL_HIGH: Final[str] = "high"

        # Server Configuration Defaults
        LDIF_SERVER_SPECIFIC_QUIRKS: Final[bool] = True
        STRICT_RFC_COMPLIANCE: Final[bool] = True

        # Error Handling Defaults
        ERROR_RECOVERY_MODE_CONTINUE: Final[str] = "continue"

        # Development Defaults
        DEBUG_MODE: Final[bool] = False
        VERBOSE_LOGGING: Final[bool] = False

    # =============================================================================
    # QUALITY ANALYSIS CONSTANTS
    # =============================================================================

    class QualityAnalysis:
        """Quality analysis threshold constants."""

        # Quality thresholds for LDIF analysis
        QUALITY_THRESHOLD_MEDIUM: Final[float] = 0.8  # Medium quality threshold
        MIN_DN_COMPONENTS_FOR_BASE_PATTERN: Final[int] = (
            2  # Minimum DN components for base pattern analysis
        )

    # =============================================================================
    # UTILITY CONSTANTS
    # =============================================================================

    # Utilities constants are inherited from parent FlextConstants

    # =============================================================================
    # VALIDATION CONSTANTS
    # =============================================================================

    class LdifGeneralValidation:
        """General validation constants."""

        NAME_LENGTH_MIN: Final[int] = 1
        NAME_LENGTH_MAX: Final[int] = 255

    class LdifValidation:
        """LDIF-specific validation rules and constraints."""

        MIN_DN_COMPONENTS: Final[int] = 1

        # RFC 4514 DN length limit (increased from 255 to support real-world long DNs)
        MAX_DN_LENGTH: Final[int] = 2048

        # Reasonable limits for LDAP attributes
        MAX_ATTRIBUTES_PER_ENTRY: Final[int] = 1000
        MAX_VALUES_PER_ATTRIBUTE: Final[int] = 100
        MAX_ATTRIBUTE_VALUE_LENGTH: Final[int] = 10000

        # Attribute name constraints (RFC 4512)
        MIN_ATTRIBUTE_NAME_LENGTH: Final[int] = 1
        MAX_ATTRIBUTE_NAME_LENGTH: Final[int] = 255
        ATTRIBUTE_NAME_PATTERN: Final[str] = r"^[a-zA-Z][a-zA-Z0-9-]*$"

        # URL validation constraints
        MIN_URL_LENGTH: Final[int] = 1
        MAX_URL_LENGTH: Final[int] = 2048
        URL_PATTERN: Final[str] = r"^(https?|ldap)://[^\s/$.?#].[^\s]*$"
        SECURE_PROTOCOLS: Final[frozenset[str]] = frozenset(["https", "ldaps"])

        # Encoding constraints
        MIN_ENCODING_LENGTH: Final[int] = 1
        MAX_ENCODING_LENGTH: Final[int] = 50

        # LDIF line parsing constraints
        MIN_LDIF_LINE_PARTS: Final[int] = 2

    # =============================================================================
    # OBJECTCLASS CONSTANTS
    # =============================================================================

    class ObjectClasses:
        """LDAP object class name constants (RFC 4512 standard classes).

        Core LDIF-level object class definitions used across the FLEXT ecosystem.
        These are the fundamental LDAP schema object classes defined in RFC 4512
        and commonly used across all LDAP server implementations.
        """

        # Structural object classes (RFC 4512)
        TOP: Final[str] = "top"
        PERSON: Final[str] = "person"
        ORGANIZATIONAL_PERSON: Final[str] = "organizationalPerson"
        INET_ORG_PERSON: Final[str] = "inetOrgPerson"
        GROUP_OF_NAMES: Final[str] = "groupOfNames"
        GROUP_OF_UNIQUE_NAMES: Final[str] = "groupOfUniqueNames"
        POSIX_GROUP: Final[str] = "posixGroup"
        ORGANIZATIONAL_UNIT: Final[str] = "organizationalUnit"
        ORGANIZATION: Final[str] = "organization"
        DOMAIN: Final[str] = "domain"

        # Common auxiliary object classes
        USER: Final[str] = "user"
        GROUP: Final[str] = "group"
        COUNTRY: Final[str] = "country"
        LOCALITY: Final[str] = "locality"

        # Convenience sets for validation and filtering
        LDAP_PERSON_CLASSES: Final[frozenset[str]] = frozenset([
            PERSON,
            ORGANIZATIONAL_PERSON,
            INET_ORG_PERSON,
        ])

        LDAP_GROUP_CLASSES: Final[frozenset[str]] = frozenset([
            GROUP_OF_NAMES,
            GROUP_OF_UNIQUE_NAMES,
            POSIX_GROUP,
        ])

        # Standard structural hierarchy
        LDAP_STRUCTURAL_BASE: Final[frozenset[str]] = frozenset([
            TOP,
            PERSON,
            ORGANIZATIONAL_PERSON,
            INET_ORG_PERSON,
            GROUP_OF_NAMES,
            ORGANIZATIONAL_UNIT,
            ORGANIZATION,
            DOMAIN,
        ])

    # =============================================================================
    # ERROR MESSAGE CONSTANTS
    # =============================================================================

    class ErrorMessages:
        """Error message constants for validation."""

        # DN Errors
        DN_EMPTY_ERROR: Final[str] = "DN cannot be empty"
        DN_INVALID_FORMAT_ERROR: Final[str] = "DN has invalid format"
        DN_INVALID_CHARS_ERROR: Final[str] = "DN contains invalid characters"

        # Attribute Errors
        ATTRIBUTES_EMPTY_ERROR: Final[str] = "Attributes cannot be empty"
        ATTRIBUTES_TYPE_ERROR: Final[str] = "Attributes must be a dictionary"
        ATTRIBUTE_NAME_EMPTY_ERROR: Final[str] = "Attribute name cannot be empty"
        ATTRIBUTE_NAME_ERROR: Final[str] = "Attribute name must be a string"
        ATTRIBUTE_VALUES_ERROR: Final[str] = "Attribute values must be a list"
        ATTRIBUTE_VALUE_TYPE_ERROR: Final[str] = "Attribute values must be strings"

        # ObjectClass Errors
        OBJECTCLASS_EMPTY_ERROR: Final[str] = "ObjectClass list cannot be empty"

        # Entry Errors
        ENTRY_DN_EMPTY_ERROR: Final[str] = "Entry DN cannot be empty"
        ENTRIES_EMPTY_ERROR: Final[str] = "Entries cannot be empty"

        # Base DN Errors
        BASE_DN_EMPTY_ERROR: Final[str] = "Base DN cannot be empty"

        # Data Errors
        DATA_BATCH_EMPTY_ERROR: Final[str] = "Data batch cannot be empty"

        # URL Errors
        URL_EMPTY_ERROR: Final[str] = "URL cannot be empty"

        # Format Errors
        INVALID_LDIF_FORMAT_ERROR: Final[str] = "Invalid LDIF file format"

    # =============================================================================
    # ENUMS
    # =============================================================================

    class ProcessingStage(StrEnum):
        """Processing stages for LDIF operations."""

        PARSING = "parsing"
        VALIDATION = "validation"
        ANALYTICS = "analytics"
        WRITING = "writing"

    class LdifHealthStatus(StrEnum):
        """Health status for LDIF services."""

        HEALTHY = "healthy"
        DEGRADED = "degraded"
        UNHEALTHY = "unhealthy"

    class EntryType(StrEnum):
        """Types of LDIF entries."""

        PERSON = "person"
        GROUP = "group"
        ORGANIZATIONAL_UNIT = "organizationalunit"
        DOMAIN = "domain"
        OTHER = "other"

    class EntryModification(StrEnum):
        """LDIF entry modification types."""

        ADD = "add"
        MODIFY = "modify"
        DELETE = "delete"
        MODRDN = "modrdn"

    class ServerTypeEnum(StrEnum):
        """LDAP server types supported by FLEXT.

        Single source of truth for server type enumerations.
        Uses SHORT identifiers (oid, oud, etc.) which map to full names via
        ServerTypes.LONG_NAMES mapping.
        """

        OID = "oid"  # Oracle Internet Directory
        OUD = "oud"  # Oracle Unified Directory
        OPENLDAP = "openldap"  # Generic OpenLDAP
        OPENLDAP1 = "openldap1"  # OpenLDAP 1.x (slapd.conf)
        OPENLDAP2 = "openldap2"  # OpenLDAP 2.x (cn=config)
        ACTIVE_DIRECTORY = "active_directory"  # Microsoft Active Directory
        APACHE_DIRECTORY = "apache_directory"  # Apache Directory Server
        NOVELL_EDIRECTORY = "novell_edirectory"  # Novell eDirectory
        IBM_TIVOLI = "ibm_tivoli"  # IBM Tivoli Directory Server
        DS_389 = "389ds"  # Red Hat Directory Server (389ds)
        GENERIC = "generic"  # Generic/RFC-only LDAP
        RFC = "rfc"  # Pure RFC 2849 (no server-specific quirks)
        RELAXED = "relaxed"  # Relaxed mode for broken/non-compliant LDIF

    # =============================================================================
    # LITERAL TYPE CONSTANTS - All Literal types MUST be declared here
    # =============================================================================

    class LiteralTypes:
        """Literal type constants for type annotations."""

        # Processing stages
        PROCESSING_STAGES: Final[tuple[str, ...]] = (
            "parsing",
            "validation",
            "analytics",
            "writing",
        )

        # Health status
        HEALTH_STATUS: Final[tuple[str, ...]] = ("healthy", "degraded", "unhealthy")

        # Entry types
        ENTRY_TYPES: Final[tuple[str, ...]] = (
            "person",
            "group",
            "organizationalunit",
            "domain",
            "other",
        )

        # Modification types
        MODIFICATION_TYPES: Final[tuple[str, ...]] = (
            "add",
            "modify",
            "delete",
            "modrdn",
        )

        # Server types (includes short and long forms for compatibility)
        SERVER_TYPES: Final[tuple[str, ...]] = (
            # Short forms (primary - used in code)
            "oid",
            "oud",
            "openldap",
            "openldap1",
            "openldap2",
            "active_directory",
            "apache_directory",
            "generic",
            "rfc",
            "389ds",
            "relaxed",
            "novell_edirectory",
            "ibm_tivoli",
            # Long forms (for backward compatibility)
            "oracle_oid",
            "oracle_oud",
        )

        # Encoding types
        ENCODING_TYPES: Final[tuple[str, ...]] = (
            "utf-8",
            "latin-1",
            "ascii",
            "utf-16",
            "utf-32",
            "cp1252",
            "iso-8859-1",
        )

        # Search scopes
        SCOPE: Final[tuple[str, ...]] = (
            "base",
            "one",
            "onelevel",
            "sub",
            "subtree",
        )

        # Validation levels
        VALIDATION_LEVELS: Final[tuple[str, ...]] = ("strict", "moderate", "lenient")

        # Analytics detail levels
        ANALYTICS_DETAIL_LEVELS: Final[tuple[str, ...]] = ("low", "medium", "high")

        # Quirks detection modes
        DETECTION_MODES: Final[tuple[str, ...]] = ("auto", "manual", "disabled")

        # Error recovery modes
        ERROR_RECOVERY_MODES: Final[tuple[str, ...]] = ("continue", "stop", "skip")

        # Project types
        PROJECT_TYPES: Final[tuple[str, ...]] = (
            "library",
            "application",
            "service",
            "tool",
            "migration",
            "validation",
            "analysis",
        )

        # Processing stage literals

        # Health status literals
        HEALTH_STATUSES: Final[tuple[str, ...]] = ("healthy", "degraded", "unhealthy")

        # Entry type literals

        # Modification type literals

        # Server type literals

        # Encoding type literals

        # Validation level literals

        # LDIF-specific project types
        LDIF_PROJECT_TYPES: Final[tuple[str, ...]] = (
            "library",
            "application",
            "service",
            "ldif-processor",
            "directory-converter",
            "ldif-validator",
            "ldif-analyzer",
            "ldif-parser",
            "directory-migrator",
            "ldap-data-processor",
            "ldif-transformer",
            "directory-sync",
            "ldif-exporter",
            "ldif-importer",
            "data-migration",
            "ldif-etl",
            "directory-backup",
            "ldif-merger",
            "ldif-splitter",
            "directory-validator",
            "ldif-normalizer",
            "ldap-directory-tool",
        )

        # Literal type definitions for type annotations
        type ProcessingStage = Literal["parsing", "validation", "analytics", "writing"]
        type HealthStatus = Literal["healthy", "degraded", "unhealthy"]
        type EntryType = Literal[
            "person",
            "group",
            "organizationalunit",
            "domain",
            "other",
        ]
        type ModificationType = Literal["add", "modify", "delete", "modrdn"]
        type ServerType = Literal[
            # Short forms (primary - used in code)
            "oid",
            "oud",
            "openldap",
            "openldap1",
            "openldap2",
            "active_directory",
            "apache_directory",
            "generic",
            "rfc",
            "389ds",
            "relaxed",
            "novell_edirectory",
            "ibm_tivoli",
            # Long forms (for backward compatibility)
            "oracle_oid",
            "oracle_oud",
        ]
        type EncodingType = Literal[
            "utf-8",
            "latin-1",
            "ascii",
            "utf-16",
            "utf-32",
            "cp1252",
            "iso-8859-1",
        ]
        type ValidationLevel = Literal["strict", "moderate", "lenient"]
        type AnalyticsDetailLevel = Literal["low", "medium", "high"]
        type DetectionMode = Literal["auto", "manual", "disabled"]
        type ErrorRecoveryMode = Literal["continue", "stop", "skip"]
        type ProjectType = Literal[
            "library",
            "application",
            "service",
            "ldif-processor",
            "directory-converter",
            "ldif-validator",
            "ldif-analyzer",
            "ldif-parser",
            "directory-migrator",
            "ldap-data-processor",
            "ldif-transformer",
            "directory-sync",
            "ldif-exporter",
            "ldif-importer",
            "data-migration",
            "ldif-etl",
            "directory-backup",
            "ldif-merger",
            "ldif-splitter",
            "directory-validator",
            "ldif-normalizer",
            "ldap-directory-tool",
        ]

    # =============================================================================
    # ENCODING CONSTANTS
    # =============================================================================

    class Encoding:
        """Character encoding constants for LDIF processing."""

        UTF8: Final[str] = "utf-8"
        UTF16: Final[str] = "utf-16"
        UTF32: Final[str] = "utf-32"
        LATIN1: Final[str] = "latin-1"
        ASCII: Final[str] = "ascii"
        CP1252: Final[str] = "cp1252"
        ISO_8859_1: Final[str] = "iso-8859-1"
        DEFAULT_ENCODING: Final[str] = UTF8

        # Encoding detection constants
        MIN_BOM_LENGTH: Final[int] = 2
        MIN_UTF32_LENGTH: Final[int] = 4
        MIN_STATISTICAL_LENGTH: Final[int] = 10

        # Encoding detection thresholds
        UTF32_NULL_RATIO_THRESHOLD: Final[float] = 0.3
        UTF16_NULL_RATIO_THRESHOLD: Final[float] = 0.1
        CP1252_RATIO_THRESHOLD: Final[float] = 0.01  # 1% CP1252 chars
        HIGH_BYTES_RATIO_THRESHOLD: Final[float] = 0.05  # 5% high bytes

        # UTF-8 byte pattern constants (for statistical detection)
        UTF8_HIGH_BIT_MASK: Final[int] = 0x80
        UTF8_2BYTE_LEAD_MASK: Final[int] = 0xE0
        UTF8_2BYTE_LEAD_VALUE: Final[int] = 0xC0
        UTF8_3BYTE_LEAD_MASK: Final[int] = 0xF0
        UTF8_3BYTE_LEAD_VALUE: Final[int] = 0xE0
        UTF8_4BYTE_LEAD_MASK: Final[int] = 0xF8
        UTF8_4BYTE_LEAD_VALUE: Final[int] = 0xF0
        UTF8_CONTINUATION_MASK: Final[int] = 0xC0
        UTF8_CONTINUATION_VALUE: Final[int] = 0x80

        # Character range constants
        CP1252_RANGE_START: Final[int] = 0x80
        CP1252_RANGE_END: Final[int] = 0x9F
        ASCII_MAX: Final[int] = 127

        # Byte size for file sampling
        ENCODING_SAMPLE_SIZE: Final[int] = 1024

        # Supported encodings for LDIF processing
        SUPPORTED_ENCODINGS: Final[frozenset[str]] = frozenset([
            UTF8,
            LATIN1,
            ASCII,
            UTF16,
            UTF32,
            CP1252,
            ISO_8859_1,
        ])

    # =============================================================================
    # LDAP SERVER CONSTANTS
    # =============================================================================

    class LdapServers:
        """LDAP server implementation constants."""

        # Server types - using Literal types for ACL compatibility
        ACTIVE_DIRECTORY: Final = "active_directory"
        OPENLDAP: Final = "openldap"  # Legacy catch-all
        OPENLDAP_2: Final = "openldap2"  # Modern cn=config based
        OPENLDAP_1: Final = "openldap1"  # Legacy slapd.conf based
        APACHE_DIRECTORY: Final = "apache_directory"
        NOVELL_EDIRECTORY: Final = "novell_edirectory"
        IBM_TIVOLI: Final = "ibm_tivoli"
        GENERIC: Final = "generic"
        # Oracle server types
        ORACLE_OID: Final = "oracle_oid"
        ORACLE_OUD: Final = "oracle_oud"
        # Additional server types
        DS_389: Final = "389ds"

        # Supported server types list
        SUPPORTED_TYPES: Final[frozenset[str]] = frozenset([
            ACTIVE_DIRECTORY,
            OPENLDAP,
            OPENLDAP_2,
            OPENLDAP_1,
            APACHE_DIRECTORY,
            NOVELL_EDIRECTORY,
            IBM_TIVOLI,
            GENERIC,
            ORACLE_OID,
            ORACLE_OUD,
            DS_389,
            # Short forms for compatibility
            "novell_edirectory",
            "ibm_tivoli",
            "apache_directory",
            "389ds",
        ])

        # Server-specific DN patterns
        AD_DN_PATTERNS: Final[frozenset[str]] = frozenset([
            "CN=",
            "OU=",
            "DC=",
            "O=",
            "L=",
            "ST=",
            "C=",
        ])

        OPENLDAP_DN_PATTERNS: Final[frozenset[str]] = frozenset([
            "cn=",
            "ou=",
            "dc=",
            "o=",
            "l=",
            "st=",
            "c=",
            "uid=",
        ])

        # OpenLDAP 2.x detection patterns (cn=config based)
        OPENLDAP_2_ATTRIBUTES: Final[frozenset[str]] = frozenset([
            "olcAccess",
            "olcAttributeTypes",
            "olcObjectClasses",
            "olcDatabase",
            "olcBackend",
            "olcOverlay",
            "olcRootDN",
            "olcRootPW",
            "olcSuffix",
        ])

        OPENLDAP_2_OBJECTCLASSES: Final[frozenset[str]] = frozenset([
            "olcConfig",
            "olcDatabase",
            "olcBackendConfig",
            "olcOverlayConfig",
            "olcSchemaConfig",
        ])

        OPENLDAP_2_DN_PATTERNS: Final[frozenset[str]] = frozenset([
            "cn=config",
            "olcDatabase=",
            "olcOverlay=",
        ])

        # OpenLDAP 1.x detection patterns (traditional slapd.conf)
        OPENLDAP_1_ATTRIBUTES: Final[frozenset[str]] = frozenset([
            "attributetype",
            "objectclass",
            "access",
            "rootdn",
            "rootpw",
            "suffix",
        ])

        # Server-specific object classes
        AD_REQUIRED_CLASSES: Final[frozenset[str]] = frozenset([
            "top",
            "person",
            "organizationalPerson",
            "user",
        ])

        OPENLDAP_REQUIRED_CLASSES: Final[frozenset[str]] = frozenset([
            "top",
            "person",
            "organizationalPerson",
            "inetOrgPerson",
        ])

    # =============================================================================
    # RFC 2849 COMPLIANCE CONSTANTS
    # =============================================================================

    class RfcCompliance:
        """RFC 2849 compliance validation constants."""

        # RFC 2849 format constants
        LINE_LENGTH_LIMIT: Final[int] = 76
        LINE_WITH_NEWLINE: Final[int] = LINE_LENGTH_LIMIT + 1  # 77

        # Required RFC 2849 features
        REQUIRED_FEATURES: Final[frozenset[str]] = frozenset([
            "base64_encoding",
            "line_continuation",
            "change_records",
            "url_references",
            "attribute_options",
            "comments",
            "version_control",
        ])

        # Optional RFC 2849 features
        OPTIONAL_FEATURES: Final[frozenset[str]] = frozenset([
            "language_tags",
            "binary_data",
            "large_entries",
        ])

        # Validation strictness levels
        STRICT: Final[str] = "strict"
        MODERATE: Final[str] = "moderate"
        LENIENT: Final[str] = "lenient"

    class Acl:
        """ACL-related constants."""

        # ACL operation types
        GRANT: Final[str] = "grant"
        DENY: Final[str] = "deny"
        ALLOW: Final[str] = "allow"

        # ACL scope types
        SUBTREE: Final[str] = "subtree"
        ONELEVEL: Final[str] = "onelevel"
        BASE: Final[str] = "base"

        # ACL permissions
        READ: Final[str] = "read"
        WRITE: Final[str] = "write"
        SEARCH: Final[str] = "search"
        COMPARE: Final[str] = "compare"
        ADD: Final[str] = "add"
        DELETE: Final[str] = "delete"
        MODIFY: Final[str] = "modify"
        SELF_WRITE: Final[str] = "self_write"  # Self-modification permission (OUD)
        PROXY: Final[str] = "proxy"  # Proxy rights (OUD/OID)

        # Novell ACL parsing indices
        NOVELL_SEGMENT_INDEX_TRUSTEE: Final[int] = 2
        NOVELL_SEGMENT_INDEX_RIGHTS: Final[int] = 3

    class AclSubjectTypes:
        """ACL subject type identifiers for permission subjects.

        Used in ACL rules to identify what entity the permission applies to
        (user, group, role, self, everyone, etc.)
        """

        # Subject types for ACL permissions
        USER: Final[str] = "user"
        GROUP: Final[str] = "group"
        ROLE: Final[str] = "role"
        SELF: Final[str] = "self"  # Self (person modifying own entry)
        ALL: Final[str] = "all"  # Everyone
        PUBLIC: Final[str] = "public"  # Public access
        ANONYMOUS: Final[str] = "anonymous"  # Anonymous access
        AUTHENTICATED: Final[str] = "authenticated"  # Any authenticated user
        DN_PREFIX: Final[str] = "dn"  # DN prefix for specific DN subjects

    class Schema:
        """Schema-related constants."""

        # Schema object types
        OBJECTCLASS: Final[str] = "objectclass"
        ATTRIBUTE: Final[str] = "attribute"
        SYNTAX: Final[str] = "syntax"
        MATCHINGRULE: Final[str] = "matchingrule"

        # Schema validation levels
        STRICT: Final[str] = "strict"
        LENIENT: Final[str] = "lenient"

        # Schema status
        ACTIVE: Final[str] = "active"
        DEPRECATED: Final[str] = "deprecated"
        OBSOLETE: Final[str] = "obsolete"

        # Object class kinds (RFC 4512)
        STRUCTURAL: Final[str] = "STRUCTURAL"
        AUXILIARY: Final[str] = "AUXILIARY"
        ABSTRACT: Final[str] = "ABSTRACT"

    # =============================================================================
    # OPERATIONAL ATTRIBUTES - Server-generated read-only attributes
    # =============================================================================

    class OperationalAttributes:
        """Operational (server-generated) attributes by server type.

        These attributes MUST be stripped during migration to prevent:
        - OUD rejection (read-only attributes)
        - Inconsistent state (OUD generates its own)
        - Sync conflicts (timestamp mismatches)

        Zero Tolerance: All operational attribute names MUST be defined here.
        """

        # Common operational attributes across all LDAP servers
        # These are defined in RFC 4512 and generated by directory servers
        COMMON: Final[frozenset[str]] = frozenset([
            "createTimestamp",
            "modifyTimestamp",
            "creatorsName",
            "modifiersName",
            "entryUUID",
            "entryDN",
            "entryCSN",
            "subschemaSubentry",
            "hasSubordinates",
            "numSubordinates",
            "subordinateCount",
        ])

        # Oracle OID specific operational attributes
        OID_SPECIFIC: Final[frozenset[str]] = frozenset([
            "orclGUID",
            "orclOracleGUID",
            "orclPassword",
            "orclPasswordChangedTime",
            "orclIsEnabled",
        ])

        # Oracle OID boolean attributes (non-RFC compliant: use "0"/"1" instead of "TRUE"/"FALSE")
        # RFC 4517 Boolean syntax (OID 1.3.6.1.4.1.1466.115.121.1.7) requires "TRUE" or "FALSE"
        # OID quirks must convert "0"→"FALSE", "1"→"TRUE" during OID→RFC normalization
        OID_BOOLEAN_ATTRIBUTES: Final[frozenset[str]] = frozenset([
            # Oracle DAS (Directory Application Server) boolean attributes
            "orcldasenableproductlogo",
            "orcldasenablesubscriberlogo",
            "orcldasshowproductlogo",
            "orcldasenablebranding",
            "orcldasisenabled",
            "orcldasismandatory",
            "orcldasispersonal",
            "orcldassearchable",
            "orcldasselfmodifiable",
            "orcldasviewable",
            "orcldasREDACTED_LDAP_BIND_PASSWORDmodifiable",
            # Oracle password policy boolean attributes
            "pwdlockout",
            "pwdmustchange",
            "pwdallowuserchange",
        ])

        # Oracle OUD specific operational attributes
        OUD_SPECIFIC: Final[frozenset[str]] = frozenset([
            "ds-sync-hist",
            "ds-sync-state",
            "ds-pwp-account-disabled",
            "ds-cfg-backend-id",
            "entryUUID",  # OUD specific version
        ])

        # OpenLDAP specific operational attributes
        OPENLDAP_SPECIFIC: Final[frozenset[str]] = frozenset([
            "structuralObjectClass",
            "contextCSN",
            "entryCSN",
        ])

        # 389 Directory Server specific operational attributes
        DS_389_SPECIFIC: Final[frozenset[str]] = frozenset([
            "nsUniqueId",
            "nscpEntryDN",
            "nsds5ReplConflict",
        ])

        # Active Directory specific operational attributes
        AD_SPECIFIC: Final[frozenset[str]] = frozenset([
            "objectGUID",
            "objectSid",
            "whenCreated",
            "whenChanged",
            "uSNCreated",
            "uSNChanged",
            "dSCorePropagationData",
        ])

        # Novell eDirectory specific operational attributes
        NOVELL_SPECIFIC: Final[frozenset[str]] = frozenset([
            "GUID",
            "createTimestamp",
            "modifyTimestamp",
        ])

        # IBM Tivoli specific operational attributes
        IBM_TIVOLI_SPECIFIC: Final[frozenset[str]] = frozenset([
            "ibm-entryUUID",
            "ibm-entryChecksum",
        ])

    # =============================================================================
    # DICTIONARY KEYS - Standardize all dict[str, object] key strings
    # =============================================================================

    class DictKeys:
        """Standard dictionary keys used throughout flext-ldif.

        Zero Tolerance: All dict[str, object] key strings MUST be defined here.
        DO NOT use hard-coded strings as dict keys anywhere in the codebase.
        """

        # Server type keys
        SERVER_TYPE: Final[str] = "server_type"
        SOURCE_SERVER: Final[str] = "source_server"
        TARGET_SERVER: Final[str] = "target_server"
        FROM_SERVER: Final[str] = "from_server"
        TO_SERVER: Final[str] = "to_server"

        # Entry/Data keys
        DN: Final[str] = "dn"
        ATTRIBUTES: Final[str] = "attributes"
        OBJECTCLASS: Final[str] = "objectclass"
        ENTRIES: Final[str] = "entries"
        ENTRY: Final[str] = "entry"
        ENTRY_TYPES: Final[str] = "entry_types"

        # Schema keys
        SCHEMA: Final[str] = "schema"
        OBJECTCLASSES: Final[str] = "objectclasses"
        OID: Final[str] = "oid"
        NAME: Final[str] = "name"
        DESC: Final[str] = "desc"
        SUP: Final[str] = "sup"
        SYNTAX: Final[str] = "syntax"
        EQUALITY: Final[str] = "equality"
        ORDERING: Final[str] = "ordering"
        SUBSTR: Final[str] = "substr"
        MUST: Final[str] = "must"
        MAY: Final[str] = "may"
        KIND: Final[str] = "kind"
        SINGLE_VALUE: Final[str] = "single_value"
        # High-frequency schema field (8 occurrences)
        ALIASES: Final[str] = "aliases"

        # ACL keys
        ACL: Final[str] = "acl"
        ACL_FORMAT: Final[str] = "acl_format"
        ACL_ATTRIBUTE: Final[str] = "acl_attribute"
        ACI: Final[str] = "aci"
        ACCESS: Final[str] = "access"
        RAW: Final[str] = "raw"
        PARSED: Final[str] = "parsed"
        TYPE: Final[str] = "type"
        FORMAT: Final[str] = "format"
        DATA: Final[str] = "data"
        DEFINITION: Final[str] = "definition"
        SUBJECT: Final[str] = "subject"

        # Statistics/Analytics keys
        STATS: Final[str] = "stats"
        TOTAL_ENTRIES: Final[str] = "total_entries"
        TOTAL_CHANGES: Final[str] = "total_changes"
        TOTAL_COMMENTS: Final[str] = "total_comments"
        TOTAL_MIGRATED: Final[str] = "total_migrated"
        TOTAL_SCHEMA_ATTRIBUTES: Final[str] = "total_schema_attributes"
        TOTAL_SCHEMA_OBJECTCLASSES: Final[str] = "total_schema_objectclasses"
        ENTRIES_WRITTEN: Final[str] = "entries_written"
        LINES_WRITTEN: Final[str] = "lines_written"

        # Processing keys
        VALID: Final[str] = "valid"
        IS_VALID: Final[str] = "is_valid"
        READY: Final[str] = "ready"
        ISSUES: Final[str] = "issues"
        ERRORS: Final[str] = "errors"
        CHANGES: Final[str] = "changes"
        COMMENTS: Final[str] = "comments"

        # Configuration keys
        CONFIG: Final[str] = "config"
        DEFAULT_ENCODING: Final[str] = "utf-8"
        ENCODING: Final[str] = "encoding"
        DESCRIPTION: Final[str] = "description"
        QUIRK_REGISTRY: Final[str] = "quirk_registry"

        # Internal metadata and special pattern keys
        # High-frequency internal metadata tracking (16 occurrences)
        METADATA: Final[str] = "_metadata"
        # High-frequency wildcard pattern (15 occurrences)
        WILDCARD: Final[str] = "*"

        # File operation keys
        FILE_PATH: Final[str] = "file_path"
        INPUT_DIR: Final[str] = "input_dir"
        OUTPUT_DIR: Final[str] = "output_dir"
        OUTPUT_FILE: Final[str] = "output_file"
        OUTPUT_FILES: Final[str] = "output_files"
        APPEND: Final[str] = "append"
        CONTENT: Final[str] = "content"

        # Quirks keys
        SUPPORTS_OPERATIONAL_ATTRS: Final[str] = "supports_operational_attrs"
        SCHEMA_SUBENTRY: Final[str] = "schema_subentry"
        SOURCE_FORMAT: Final[str] = "source_format"
        TARGET_FORMAT: Final[str] = "target_format"
        RFC_GENERIC: Final[str] = "rfc_generic"

        # Service/Component keys
        SERVICES: Final[str] = "services"
        PARSER: Final[str] = "parser"
        WRITER: Final[str] = "writer"
        VALIDATOR: Final[str] = "validator"
        MIGRATION: Final[str] = "migration"
        INITIALIZED: Final[str] = "initialized"

        # Service names list
        SERVICE_NAMES: Final[list[str]] = [
            PARSER,
            WRITER,
            VALIDATOR,
            MIGRATION,
        ]

        # Process/Operations keys
        PROCESS_SCHEMA: Final[str] = "process_schema"
        PROCESS_ENTRIES: Final[str] = "process_entries"
        PARSE_CHANGES: Final[str] = "parse_changes"
        PARSE_ATTRIBUTES: Final[str] = "parse_attributes"
        PARSE_OBJECTCLASSES: Final[str] = "parse_objectclasses"
        ATTRIBUTES_COUNT: Final[str] = "attributes_count"
        OBJECTCLASSES_COUNT: Final[str] = "objectclasses_count"

        # OpenLDAP-specific keys
        OLCACCESS: Final[str] = "olcAccess"

        # 389 Directory Server-specific keys
        DS_PRIVILEGE_NAME: Final[str] = "ds-privilege-name"

        # Active Directory-specific keys
        NTSECURITYDESCRIPTOR: Final[str] = "nTSecurityDescriptor"
        WHAT: Final[str] = "what"
        BY_CLAUSES: Final[str] = "by_clauses"
        INDEX: Final[str] = "index"
        IS_CONFIG_ENTRY: Final[str] = "is_config_entry"
        IS_TRADITIONAL_DIT: Final[str] = "is_traditional_dit"

        # Oracle OID/OUD-specific keys
        ORCLACI: Final[str] = "orclaci"
        ORCLENTRYLEVELACI: Final[str] = "orclentrylevelaci"
        ENTRY_LEVEL: Final[str] = "entry_level"
        STANDARD: Final[str] = "standard"
        HAS_OID_ACLS: Final[str] = "has_oid_acls"
        MODEL_DUMP: Final[str] = "model_dump"

        # ACL attribute names (all servers)
        ACL_ATTRIBUTES: Final[frozenset[str]] = frozenset([
            ACI,
            ORCLACI,
            ORCLENTRYLEVELACI,
        ])

        # LDAP Attribute keys
        MEMBER: Final[str] = "member"
        UNIQUE_MEMBER: Final[str] = "uniqueMember"
        CN: Final[str] = "cn"
        SN: Final[str] = "sn"
        OU: Final[str] = "ou"
        DC: Final[str] = "dc"
        UID: Final[str] = "uid"
        MAIL: Final[str] = "mail"
        TELEPHONE_NUMBER: Final[str] = "telephoneNumber"
        SURNAME: Final[str] = "Surname"

        # ObjectClass values (deprecated - use FlextLdifConstants.ObjectClasses instead)
        # These are kept for backward compatibility but should be migrated to ObjectClasses.*
        TOP: Final[str] = "top"
        PERSON: Final[str] = "person"
        GROUP_OF_NAMES: Final[str] = "groupOfNames"
        GROUP_OF_UNIQUE_NAMES: Final[str] = "groupOfUniqueNames"
        ORGANIZATIONAL_UNIT: Final[str] = "organizationalUnit"

        # ACL service keys
        PATTERNS: Final[str] = "patterns"
        COMPOSITE: Final[str] = "composite"
        RULE_EVALUATION: Final[str] = "rule_evaluation"

        # Validation/Check keys
        HAS_DN: Final[str] = "has_dn"
        LENGTH: Final[str] = "length"
        BOOL: Final[str] = "bool"
        STR: Final[str] = "str"

        # Feature flags
        LDIF_FEATURES: Final[str] = "ldif_features"
        RFC_2849_PARSING: Final[str] = "rfc_2849_parsing"
        RFC_4512_COMPLIANCE: Final[str] = "rfc_4512_compliance"
        SERVER_QUIRKS: Final[str] = "server_quirks"
        GENERIC_MIGRATION: Final[str] = "generic_migration"
        SCHEMA_VALIDATION: Final[str] = "schema_validation"
        ACL_PROCESSING: Final[str] = "acl_processing"
        ENTRY_BUILDING: Final[str] = "entry_building"

        # Quirk types
        SCHEMA_QUIRK: Final[str] = "schema"
        ACL_QUIRK: Final[str] = "acl"
        ENTRY_QUIRK: Final[str] = "entry"
        QUIRK_TYPES: Final[frozenset[str]] = frozenset([
            SCHEMA_QUIRK,
            ACL_QUIRK,
            ENTRY_QUIRK,
        ])

        # Status/State keys
        UNKNOWN: Final[str] = "unknown"
        HIGH: Final[str] = "high"
        STOP: Final[str] = "stop"
        SKIP: Final[str] = "skip"
        AFTER: Final[str] = "after"
        MEDIUM: Final[str] = "medium"
        # High-frequency status tracking (21 occurrences)
        FAILED: Final[str] = "failed"
        # High-frequency status tracking (14 occurrences)
        SYNCED: Final[str] = "synced"
        # Medium-frequency status tracking (5 occurrences)
        SKIPPED: Final[str] = "skipped"
        # Medium-frequency status tracking (5 occurrences)
        RESOLVED: Final[str] = "resolved"
        # Status indicator for data loading
        LOADED: Final[str] = "loaded"
        # Medium-frequency ACL permissions (7 occurrences)
        PERMISSIONS: Final[str] = "permissions"
        # Medium-frequency ACL target (6 occurrences)
        TARGET: Final[str] = "target"
        # Medium-frequency schema constraint (6 occurrences)
        SYNTAX_LENGTH: Final[str] = "syntax_length"
        # Medium-frequency format tracking (6 occurrences)
        ORIGINAL_FORMAT: Final[str] = "original_format"
        # Medium-frequency metadata version (5 occurrences)
        VERSION: Final[str] = "version"
        # Medium-frequency metadata summary (5 occurrences)
        SUMMARY: Final[str] = "summary"

        # Class/Component name keys
        FLEXT_LDIF_QUIRKS_REGISTRY: Final[str] = "FlextLdifRegistry"
        FLEXT_LDIF_QUIRKS_MANAGER: Final[str] = "FlextLdifQuirksManager"
        FLEXT_LDIF_ACL_SERVICE: Final[str] = "FlextLdifAclService"
        FLEXT_LDIF_SCHEMA_BUILDER: Final[str] = "FlextLdifSchemaBuilder"

    # =============================================================================
    # DN PATTERNS - Standard DN patterns for schema and configuration
    # =============================================================================

    class DnPatterns:
        """Standard DN patterns used in LDAP/LDIF processing.

        Zero Tolerance: All DN pattern strings MUST be defined here.
        DO NOT use hard-coded DN strings anywhere in the codebase.
        """

        # Schema subentry DNs (server-specific)
        CN_SCHEMA: Final[str] = "cn=schema"
        CN_SUBSCHEMA: Final[str] = "cn=subschema"
        CN_SUBSCHEMA_SUBENTRY: Final[str] = "cn=subschemasubentry"
        CN_SCHEMA_CN_CONFIG: Final[str] = "cn=schema,cn=configuration"

        CN_SUBSCHEMASUBENTRY: Final[str] = "cn=subschemasubentry"

        CN_SCHEMA_CN_CONFIGURATION: Final[str] = "cn=schema,cn=configuration"

        # Configuration DNs
        CN_CONFIG: Final[str] = "cn=config"

        # Oracle-specific DNs
        CN_ORCL: Final[str] = "cn=orcl"
        OU_ORACLE: Final[str] = "ou=oracle"
        DC_ORACLE: Final[str] = "dc=oracle"

        # Oracle OID namespace
        ORACLE_OID_NAMESPACE: Final[str] = "2.16.840.1.113894."

        # DN component patterns
        DN_EQUALS: Final[str] = "="
        DN_COMMA: Final[str] = ","
        DN_PLUS: Final[str] = "+"

        # DN cleaning patterns (RFC 4514 normalization)
        DN_SPACES_AROUND_EQUALS: Final[str] = r"\s*=\s*"
        DN_TRAILING_BACKSLASH_SPACE: Final[str] = r"\\\s+,"
        DN_SPACES_AROUND_COMMA: Final[str] = r",\s+"
        DN_BACKSLASH_SPACE: Final[str] = r"\\\s+"
        DN_UNNECESSARY_ESCAPES: Final[str] = r'\\([^,+"\<>;\\# ])'
        DN_MULTIPLE_SPACES: Final[str] = r"\s+"

        # ACI DN reference patterns
        ACI_LDAP_URL_PATTERN: Final[str] = r"ldap:///([^\"]+?)"
        ACI_QUOTED_DN_PATTERN: Final[str] = (
            r'"((?:[a-zA-Z]+=[^,\";\)]+)(?:,[a-zA-Z]+=[^,\";\)]+)*)"'
        )

        # Schema parsing patterns
        SCHEMA_OID_EXTRACTION: Final[str] = r"\(\s*([\d.]+)"

        # Common DN prefix patterns
        CN_PREFIX: Final[str] = "cn="
        OU_PREFIX: Final[str] = "ou="
        DC_PREFIX: Final[str] = "dc="
        UID_PREFIX: Final[str] = "uid="
        O_PREFIX: Final[str] = "o="
        L_PREFIX: Final[str] = "l="
        ST_PREFIX: Final[str] = "st="
        C_PREFIX: Final[str] = "c="

        # OpenLDAP config-specific patterns
        OLCDATABASE_PREFIX: Final[str] = "olcDatabase="
        OLCOVERLAY_PREFIX: Final[str] = "olcOverlay="

        # All schema subentry patterns
        SCHEMA_SUBENTRY_PATTERNS: Final[frozenset[str]] = frozenset([
            CN_SCHEMA,
            CN_SUBSCHEMA,
            CN_SUBSCHEMA_SUBENTRY,
            CN_SCHEMA_CN_CONFIG,
        ])

        # All config DN patterns
        CONFIG_DN_PATTERNS: Final[frozenset[str]] = frozenset([
            CN_CONFIG,
            CN_SCHEMA_CN_CONFIG,
        ])

        # All Oracle DN patterns
        ORACLE_DN_PATTERNS: Final[frozenset[str]] = frozenset([
            CN_ORCL,
            OU_ORACLE,
            DC_ORACLE,
        ])

    # =============================================================================
    # ACL FORMATS - ACL format identifiers
    # =============================================================================

    class AclFormats:
        """ACL format identifier constants.

        Zero Tolerance: All ACL format strings MUST be defined here.
        """

        # OpenLDAP ACL formats
        OPENLDAP1_ACL: Final[str] = "openldap1_acl"
        OPENLDAP2_ACL: Final[str] = "openldap2_acl"
        OLCACCESS: Final[str] = "olcAccess"
        ACCESS: Final[str] = "access"

        # 389 Directory Server ACL format
        DS389_ACL: Final[str] = "ds389_acl"

        # Oracle ACL formats
        OID_ACL: Final[str] = "oracle_oid"
        OUD_ACL: Final[str] = "oracle_oud"
        OUD_DS_CFG: Final[str] = "ds-cfg"
        ORCLACI: Final[str] = "orclaci"

        # Generic/RFC ACL formats
        RFC_GENERIC: Final[str] = "rfc_generic"
        ACI: Final[str] = "aci"

        # Active Directory ACL format
        AD_ACL: Final[str] = "active_directory_acl"
        AD_NTSECURITY: Final[str] = "nTSecurityDescriptor"

        # Server type to ACL format mapping (CENTRALIZED - eliminate hardcoded maps)
        # Maps server types (short and long forms) to their ACL format constants
        SERVER_TYPE_TO_FORMAT: Final[dict[str, str]] = {
            # Short forms (primary)
            "oid": ORCLACI,
            "oud": ACI,
            "openldap": OLCACCESS,
            "openldap1": ACCESS,
            "openldap2": OPENLDAP2_ACL,
            "active_directory": AD_NTSECURITY,
            "389ds": ACI,
            "rfc": RFC_GENERIC,
            "relaxed": RFC_GENERIC,  # Relaxed mode uses RFC format
            # Long forms (backward compatibility)
            "oracle_oid": ORCLACI,
            "oracle_oud": ACI,
        }

    # =============================================================================
    # SERVER TYPE SHORTCUTS - Short server type identifiers
    # =============================================================================

    class ServerTypes:
        """Server type identifiers - Single source of truth for all server types.

        Zero Tolerance: All server type identifier strings MUST be defined here.
        Uses SHORT identifiers for code usage. Use LONG_NAMES mapping to get full names.
        Internal note: LdapServers class provides server-specific detection patterns,
        but all server type strings MUST be defined here first.
        """

        # Short identifiers (used in code, configuration, and processing)
        # PRIMARY SOURCE: Use these in all code
        OID: Final[str] = "oid"
        OUD: Final[str] = "oud"
        OPENLDAP: Final[str] = "openldap"
        OPENLDAP1: Final[str] = "openldap1"
        OPENLDAP2: Final[str] = "openldap2"
        AD: Final[str] = "active_directory"
        APACHE: Final[str] = "apache_directory"
        GENERIC: Final[str] = "generic"
        RFC: Final[str] = "rfc"
        DS_389: Final[str] = "389ds"
        RELAXED: Final[str] = "relaxed"
        NOVELL: Final[str] = "novell_edirectory"
        IBM_TIVOLI: Final[str] = "ibm_tivoli"

        # Mapping from short forms to long forms (for backward compatibility)
        LONG_NAMES: Final[dict[str, str]] = {
            OID: "oracle_oid",
            OUD: "oracle_oud",
            OPENLDAP: "openldap",
            OPENLDAP1: "openldap1",
            OPENLDAP2: "openldap2",
            AD: "active_directory",
            APACHE: "apache_directory",
            GENERIC: "generic",
            RFC: "rfc",
            DS_389: "389ds",
            RELAXED: "relaxed",
            NOVELL: "novell_edirectory",
            IBM_TIVOLI: "ibm_tivoli",
        }

        # Reverse mapping from long forms to short forms
        FROM_LONG: Final[dict[str, str]] = {v: k for k, v in LONG_NAMES.items()}

        # Server type variants (for compatibility checks)
        ORACLE_OID_VARIANTS: Final[frozenset[str]] = frozenset(["oid", "oracle_oid"])
        ORACLE_OUD_VARIANTS: Final[frozenset[str]] = frozenset(["oud", "oracle_oud"])
        OPENLDAP_VARIANTS: Final[frozenset[str]] = frozenset([
            "openldap",
            "openldap1",
            "openldap2",
        ])

    # =============================================================================
    # OPERATION CONSTANTS - Filter types, modes, categories, data types
    # =============================================================================

    class FilterTypes:
        """Filter type identifier constants.

        Zero Tolerance: All filter type strings MUST be defined here.
        Used throughout filtering operations to avoid hardcoded strings.
        """

        OBJECTCLASS: Final[str] = "objectclass"
        DN_PATTERN: Final[str] = "dn_pattern"
        ATTRIBUTES: Final[str] = "attributes"
        SCHEMA_OID: Final[str] = "schema_oid"
        OID_PATTERN: Final[str] = "oid_pattern"
        ATTRIBUTE: Final[str] = "attribute"

        # Python 3.13 type alias from constants
        type Type = Literal[
            "objectclass",
            "dn_pattern",
            "attributes",
            "schema_oid",
            "oid_pattern",
            "attribute",
        ]

    class Modes:
        """Operation mode constants.

        Zero Tolerance: All mode strings MUST be defined here.
        Used for filter modes, detection modes, and operation modes.
        """

        INCLUDE: Final[str] = "include"
        EXCLUDE: Final[str] = "exclude"
        AUTO: Final[str] = "auto"
        MANUAL: Final[str] = "manual"
        DISABLED: Final[str] = "disabled"

        # Python 3.13 type alias from constants
        type Mode = Literal["include", "exclude", "auto", "manual", "disabled"]

    class Categories:
        """Entry category constants.

        Zero Tolerance: All category strings MUST be defined here.
        Used for LDIF entry categorization in pipelines.
        """

        USERS: Final[str] = "users"
        GROUPS: Final[str] = "groups"
        HIERARCHY: Final[str] = "hierarchy"
        SCHEMA: Final[str] = "schema"
        ACL: Final[str] = "acl"
        REJECTED: Final[str] = "rejected"

        # Python 3.13 type alias from constants
        type Category = Literal[
            "users",
            "groups",
            "hierarchy",
            "schema",
            "acl",
            "rejected",
        ]

    class Categorization:
        """Attribute categorization constants for server-specific filtering.

        Zero Tolerance: All attribute categorizations MUST be defined here.
        Used for filtering attributes during server migration and quirks handling.
        """

        OID_SPECIFIC_ATTRIBUTES: Final[frozenset[str]] = frozenset([
            "orcloid",  # Oracle OID identifier
            "orclguid",  # Oracle GUID
            "orclpassword",  # Oracle password attribute
            "orclaci",  # Oracle ACL attribute
            "orclentrylevelaci",  # Oracle entry-level ACL
            "orcldaslov",  # Oracle DASLOV configuration
        ])

    class DataTypes:
        """Data type identifier constants.

        Zero Tolerance: All data type strings MUST be defined here.
        Used in quirks conversion matrix and data processing.
        """

        ATTRIBUTE: Final[str] = "attribute"
        OBJECTCLASS: Final[str] = "objectclass"
        ACL: Final[str] = "acl"
        ENTRY: Final[str] = "entry"
        SCHEMA: Final[str] = "schema"

        # Python 3.13 type alias from constants
        type DataType = Literal["attribute", "objectclass", "acl", "entry", "schema"]

    class RuleTypes:
        """ACL rule type constants.

        Zero Tolerance: All rule type strings MUST be defined here.
        Used in ACL service for rule type identification.
        """

        BASE: Final[str] = "base"
        COMPOSITE: Final[str] = "composite"
        PERMISSION: Final[str] = "permission"
        SUBJECT: Final[str] = "subject"
        TARGET: Final[str] = "target"

        # Python 3.13 type alias from constants
        type RuleType = Literal["base", "composite", "permission", "subject", "target"]

    class EntryTypes:
        """Entry type identifier constants.

        Zero Tolerance: All entry type strings MUST be defined here.
        Used in entry builder and API for entry type identification.
        """

        PERSON: Final[str] = "person"
        GROUP: Final[str] = "group"
        OU: Final[str] = "ou"
        ORGANIZATIONAL_UNIT: Final[str] = "organizationalunit"
        CUSTOM: Final[str] = "custom"

        # Python 3.13 type alias from constants
        type EntryType = Literal[
            "person",
            "group",
            "ou",
            "organizationalunit",
            "custom",
        ]

    class ConversionTypes:
        """Conversion type identifier constants.

        Zero Tolerance: All conversion type strings MUST be defined here.
        Used in API for data conversion operations.
        """

        ENTRY_TO_DICT: Final[str] = "entry_to_dict"
        ENTRIES_TO_DICTS: Final[str] = "entries_to_dicts"
        DICTS_TO_ENTRIES: Final[str] = "dicts_to_entries"
        ENTRIES_TO_JSON: Final[str] = "entries_to_json"
        JSON_TO_ENTRIES: Final[str] = "json_to_entries"

        # Python 3.13 type alias from constants
        type ConversionType = Literal[
            "entry_to_dict",
            "entries_to_dicts",
            "dicts_to_entries",
            "entries_to_json",
            "json_to_entries",
        ]

    class ProcessorTypes:
        """Processor type identifier constants.

        Zero Tolerance: All processor type strings MUST be defined here.
        Used in API for processor selection.
        """

        TRANSFORM: Final[str] = "transform"
        VALIDATE: Final[str] = "validate"

        # Python 3.13 type alias from constants
        type ProcessorType = Literal["transform", "validate"]

    class MatchTypes:
        """Match type constants for filtering.

        Zero Tolerance: All match type strings MUST be defined here.
        """

        ALL: Final[str] = "all"
        ANY: Final[str] = "any"

        # Python 3.13 type alias from constants
        type MatchType = Literal["all", "any"]

    class Scopes:
        """LDAP search scope constants.

        Zero Tolerance: All scope strings MUST be defined here.
        """

        BASE: Final[str] = "base"
        ONE: Final[str] = "one"
        ONELEVEL: Final[str] = "onelevel"
        SUB: Final[str] = "sub"
        SUBTREE: Final[str] = "subtree"
        SUBORDINATE: Final[str] = "subordinate"

        # Python 3.13 type alias from constants
        type Scope = Literal["base", "one", "onelevel", "sub", "subtree", "subordinate"]

    class Parameters:
        """Parameter name constants.

        Zero Tolerance: All parameter name strings MUST be defined here.
        Used for function/method parameter naming consistency.
        """

        FILE_PATH: Final[str] = "file_path"
        CONTENT: Final[str] = "content"
        PARSE_CHANGES: Final[str] = "parse_changes"
        PARSE_ATTRIBUTES: Final[str] = "parse_attributes"
        PARSE_OBJECTCLASSES: Final[str] = "parse_objectclasses"

        # Python 3.13 type alias from constants
        type Parameter = Literal[
            "file_path",
            "content",
            "parse_changes",
            "parse_attributes",
            "parse_objectclasses",
        ]

    # =============================================================================
    # REGEX PATTERNS - All regex patterns centralized
    # =============================================================================

    class LdifPatterns:
        """Regex pattern constants for LDIF processing.

        Zero Tolerance: ALL regex patterns MUST be defined here.
        NO re.compile() or pattern strings outside this namespace.
        """

        # Encoding detection patterns (from utilities.py)
        XML_ENCODING: Final[str] = r'<\?xml[^>]*encoding=["\']([^"\']+)["\']'
        HTML_CHARSET: Final[str] = r'<meta[^>]*charset=["\']([^"\']+)["\']'
        PYTHON_CODING: Final[str] = r"#.*-\*-.*coding:\s*([^\s;]+)"
        LDIF_ENCODING: Final[str] = r"#\s*encoding:\s*([^\s\n]+)"

        # DN validation patterns
        DN_COMPONENT: Final[str] = r"^[a-zA-Z][a-zA-Z0-9-]*="
        DN_SEPARATOR: Final[str] = r"(?<!\\),"

        # LDAP filter pattern (RFC 4515)
        LDAP_FILTER: Final[str] = r"^\(.*\)$"

        # Object class name pattern (similar to attribute names but allowing uppercase)
        OBJECTCLASS_NAME: Final[str] = r"^[a-zA-Z][a-zA-Z0-9-]*$"

        # Attribute name patterns (RFC 4512)
        ATTRIBUTE_NAME: Final[str] = r"^[a-zA-Z][a-zA-Z0-9-]*$"
        ATTRIBUTE_OPTION: Final[str] = r";[a-zA-Z][a-zA-Z0-9-]*"

        # OID patterns
        OID_NUMERIC: Final[str] = r"^\d+(\.\d+)*$"
        OID_DESCRIPTOR: Final[str] = r"^[a-zA-Z][a-zA-Z0-9-]*$"

        # Schema parsing patterns
        SCHEMA_OID: Final[str] = r"^\s*\(\s*([\d.]+)"
        SCHEMA_OID_EXTRACTION: Final[str] = (
            r"\(\s*([\d.]+)"  # For re.search() without ^ anchor
        )
        SCHEMA_NAME: Final[str] = r"NAME\s+\(?\s*'([^']+)'"
        SCHEMA_DESC: Final[str] = r"DESC\s+'([^']+)'"
        SCHEMA_SYNTAX: Final[str] = r"SYNTAX\s+([\d.]+)"
        SCHEMA_EQUALITY: Final[str] = r"EQUALITY\s+([^\s)]+)"
        SCHEMA_SINGLE_VALUE: Final[str] = r"\bSINGLE-VALUE\b"
        SCHEMA_SUP: Final[str] = r"SUP\s+(\w+)"
        SCHEMA_MUST: Final[str] = r"MUST\s+\(([^)]+)\)"
        SCHEMA_MAY: Final[str] = r"MAY\s+\(([^)]+)\)"

        # Server detection patterns moved to ServerDetection class below

    # =============================================================================
    # SERVER DETECTION - Comprehensive server type detection patterns and weights
    # =============================================================================

    class ServerDetection:
        """Server type detection patterns and weights for LDIF content analysis.

        Comprehensive patterns for identifying LDAP server types from LDIF content.
        Higher weight values indicate more specific patterns.
        """

        # Detection score weights (higher = more specific)
        ORACLE_OID_PATTERN: Final[str] = r"2\.16\.840\.1\.113894\."
        ORACLE_OID_ATTRIBUTES: Final[frozenset[str]] = frozenset([
            "orclOID",
            "orclGUID",
            "orclPassword",
            "orclaci",
            "orclentrylevelaci",
            "orcldaslov",
        ])
        ORACLE_OID_WEIGHT: Final[int] = 10

        ORACLE_OUD_PATTERN: Final[str] = r"(ds-sync-|ds-pwp-|ds-cfg-)"
        ORACLE_OUD_ATTRIBUTES: Final[frozenset[str]] = frozenset([
            "ds-sync-hist",
            "ds-sync-state",
            "ds-pwp-account-disabled",
            "ds-cfg-backend-id",
            "entryUUID",
        ])
        ORACLE_OUD_WEIGHT: Final[int] = 10

        OPENLDAP_PATTERN: Final[str] = r"\b(olc[A-Z][a-zA-Z]+|cn=config)\b"
        OPENLDAP_ATTRIBUTES: Final[frozenset[str]] = frozenset([
            "olcDatabase",
            "olcAccess",
            "olcOverlay",
            "olcModule",
        ])
        OPENLDAP_WEIGHT: Final[int] = 8

        ACTIVE_DIRECTORY_PATTERN: Final[str] = r"1\.2\.840\.113556\."
        ACTIVE_DIRECTORY_ATTRIBUTES: Final[frozenset[str]] = frozenset([
            "objectGUID",
            "samAccountName",
            "sIDHistory",
            "nTSecurityDescriptor",
        ])
        ACTIVE_DIRECTORY_WEIGHT: Final[int] = 8

        NOVELL_EDIR_PATTERN: Final[str] = (
            r"\b(GUID|Modifiers|nrpDistributionPassword)\b"
        )
        NOVELL_EDIR_WEIGHT: Final[int] = 6

        IBM_TIVOLI_PATTERN: Final[str] = r"\b(ibm|tivoli|ldapdb)\b"
        IBM_TIVOLI_WEIGHT: Final[int] = 6

        APACHE_DS_PATTERN: Final[str] = r"\b(apacheDS|apache-.*)\b"
        APACHE_DS_WEIGHT: Final[int] = 6

        DS_389_PATTERN: Final[str] = r"\b(389ds|redhat-ds|dirsrv)\b"
        DS_389_WEIGHT: Final[int] = 6

        # Detection thresholds
        DETECTION_THRESHOLD: Final[int] = 5
        CONFIDENCE_THRESHOLD: Final[float] = 0.6

        # Detection scoring
        ATTRIBUTE_MATCH_SCORE: Final[int] = (
            2  # Points awarded for matching server-specific attributes
        )

        # Detection performance limits
        DEFAULT_MAX_LINES: Final[int] = 1000

        # ObjectClass schema field names (RFC 4512)
        SCHEMA_FIELD_SUPERIOR: Final[str] = "superior"
        SCHEMA_FIELD_REQUIRED_ATTRIBUTES: Final[str] = "required_attributes"
        SCHEMA_FIELD_OPTIONAL_ATTRIBUTES: Final[str] = "optional_attributes"
        SCHEMA_FIELD_STRUCTURAL: Final[str] = "structural"

        # Schema parsing constants
        SCHEMA_SUBENTRY_DN: Final[str] = "cn=subschemasubentry"
        ATTRIBUTE_TYPES_PREFIX: Final[str] = "attributetypes:"
        OBJECT_CLASSES_PREFIX: Final[str] = "objectclasses:"
        ATTRIBUTE_TYPES_PREFIX_LENGTH: Final[int] = len(ATTRIBUTE_TYPES_PREFIX)
        OBJECT_CLASSES_PREFIX_LENGTH: Final[int] = len(OBJECT_CLASSES_PREFIX)

        # LDIF parsing constants
        CONTENT_PARAMETER: Final[str] = "content"
        PARSE_CHANGES_PARAMETER: Final[str] = "parse_changes"
        DEFAULT_PARSE_CHANGES: Final[bool] = False

        # Error message templates
        ERROR_UNSUPPORTED_ENTRY_TYPE: Final[str] = "Unsupported entry type"
        ERROR_LDIF_WRITE_FAILED: Final[str] = "LDIF write failed"
        ERROR_FAILED_TO_WRITE: Final[str] = "Failed to write"

        # Parser message templates
        MSG_PARSING_LDIF_CONTENT: Final[str] = (
            "Parsing LDIF content string (RFC 2849 via ldif3)"
        )
        MSG_PARSING_LDIF_FILE: Final[str] = "Parsing LDIF file (RFC 2849 via ldif3)"
        MSG_LDIF_CONTENT_PARSED: Final[str] = "LDIF content parsed successfully"
        MSG_LDIF_PARSED_SUCCESS: Final[str] = "LDIF parsed successfully"
        MSG_FAILED_EXECUTE_PARSER: Final[str] = "Failed to execute RFC LDIF parser"
        MSG_FAILED_PARSE_LDIF3: Final[str] = "Failed to parse LDIF with ldif3"
        MSG_EITHER_CONTENT_OR_PATH_REQUIRED: Final[str] = (
            "Either content or file_path must be provided"
        )

        # Writer message templates
        MSG_LDIF_FILE_WRITTEN: Final[str] = "LDIF file written"
        MSG_LDIF_CONTENT_GENERATED: Final[str] = "LDIF content generated"
        MSG_AT_LEAST_ONE_REQUIRED: Final[str] = (
            "At least one of entries, schema, or acls must be provided"
        )

        # ACL utility constants
        ACL_WILDCARD_DN: Final[str] = "*"
        ACL_WILDCARD_TYPE: Final[str] = "*"
        ACL_WILDCARD_VALUE: Final[str] = "*"
        LDIF_FILE_EXTENSION: Final[str] = ".ldif"

        # Schema builder constants
        DEFAULT_ENTRY_COUNT: Final[int] = 0
        DEFAULT_SINGLE_VALUE: Final[bool] = False

        # Change type patterns
        CHANGETYPE: Final[str] = r"^changetype:\s*(add|delete|modify|modrdn)$"

        # Comment patterns
        COMMENT_LINE: Final[str] = r"^\s*#"
        VERSION_LINE: Final[str] = r"^version:\s*\d+"

    # =============================================================================
    # VALIDATION RULES - Validation logic constants
    # =============================================================================

    class ValidationRules:
        """Validation rule constants.

        Zero Tolerance: All validation logic constants MUST be defined here.
        NO hard-coded validation strings in validators.
        """

        # String validation rules
        VALID_ENCODINGS_RULE: Final[frozenset[str]] = frozenset([
            "utf-8",
            "latin-1",
            "ascii",
            "utf-16",
            "utf-32",
            "cp1252",
            "iso-8859-1",
        ])

        VALID_VALIDATION_LEVELS_RULE: Final[frozenset[str]] = frozenset([
            "strict",
            "moderate",
            "lenient",
        ])

        VALID_SERVER_TYPES_RULE: Final[frozenset[str]] = frozenset([
            "active_directory",
            "openldap",
            "apache_directory",
            "novell_edirectory",
            "ibm_tivoli",
            "generic",
            "oracle_oid",
            "oracle_oud",
            "389ds",
        ])

        VALID_ANALYTICS_LEVELS_RULE: Final[frozenset[str]] = frozenset([
            "low",
            "medium",
            "high",
        ])

        VALID_ERROR_MODES_RULE: Final[frozenset[str]] = frozenset([
            "continue",
            "stop",
            "skip",
        ])

        # Numeric validation rules
        MIN_WORKERS_PERFORMANCE_RULE: Final[int] = 4
        MIN_CHUNK_SIZE_PERFORMANCE_RULE: Final[int] = 1000
        MAX_WORKERS_DEBUG_RULE: Final[int] = 2
        MIN_ANALYTICS_CACHE_RULE: Final[int] = 1
        MIN_PARALLEL_THRESHOLD_RULE: Final[int] = 1

        # Validation limits
        DEFAULT_MAX_ATTR_VALUE_LENGTH: Final[int] = 1048576  # 1MB default
        TYPICAL_ATTR_NAME_LENGTH_LIMIT: Final[int] = 127  # RFC 4512 typical limit


__all__ = [
    "FlextLdifConstants",
]
