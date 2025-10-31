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


class FlextLdifConstants(FlextConstants):
    """LDIF domain constants extending flext-core FlextConstants.

    Contains ONLY constant values, no implementations.
    """

    # FORMAT CONSTANTS
    # =============================================================================

    # Oracle OID namespace identifier
    ORACLE_OID_NAMESPACE: Final[str] = "2.16.840.1.113894."

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

    class DictKeys:
        """Dictionary keys used throughout flext-ldif for consistent data access."""

        # Core entry keys
        DN: Final[str] = "dn"
        ATTRIBUTES: Final[str] = "attributes"
        OBJECTCLASS: Final[str] = "objectClass"
        CN: Final[str] = "cn"
        OID: Final[str] = "oid"

        # Service and initialization keys
        SERVICE_NAMES: Final[str] = "service_names"
        INITIALIZED: Final[str] = "initialized"
        DATA: Final[str] = "data"

        # Server-specific keys
        SERVER_TYPE: Final[str] = "server_type"
        IS_CONFIG_ENTRY: Final[str] = "is_config_entry"
        IS_TRADITIONAL_DIT: Final[str] = "is_traditional_dit"

        # ACL-related keys
        ACL_ATTRIBUTE: Final[str] = "acl"
        ACI: Final[str] = "aci"
        ACCESS: Final[str] = "access"
        OLCACCESS: Final[str] = "olcAccess"
        NTSECURITYDESCRIPTOR: Final[str] = "nTSecurityDescriptor"
        HAS_OID_ACLS: Final[str] = "has_oid_acls"

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
            "orcldasadminmodifiable",
            # Oracle password policy boolean attributes
            "pwdlockout",
            "pwdmustchange",
            "pwdallowuserchange",
        ])

        # Oracle OUD boolean attributes (RFC 4517 compliant: use "TRUE"/"FALSE")
        # OUD password policy attributes require TRUE/FALSE format (not 0/1)
        OUD_BOOLEAN_ATTRIBUTES: Final[frozenset[str]] = frozenset([
            "pwdlockout",
            "pwdmustchange",
            "pwdallowuserchange",
            "pwdexpirewarning",
            "pwdgraceauthnlimit",
            "pwdlockoutduration",
            "pwdmaxfailure",
            "pwdminage",
            "pwdmaxage",
            "pwdmaxlength",
            "pwdminlength",
            # Oracle OID/OUD directory server attributes that require TRUE/FALSE format
            "orcldasselfmodifiable",
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

        # Common operational attributes to filter from ALL entries
        # These are always filtered regardless of entry type
        FILTER_FROM_ALL_ENTRIES: Final[frozenset[str]] = frozenset([
            # "createtimestamp",
            # "creatorsname",
            # "modifytimestamp",
            # "modifiersname",
            # "entrycsn",
            # "entryuuid",
            # "structuralobjectclass",
            # "hassubordinates",
            # "1.1",
            # "+",
            # "*",
            # "aci",
            # "aclrights",
        ])

        # Schema-related operational attributes to filter from NON-SCHEMA entries only
        # These are preserved in schema entries (cn=schema, cn=subschemasubentry, etc.)
        # as they contain the actual schema content
        FILTER_FROM_NON_SCHEMA_ENTRIES: Final[frozenset[str]] = frozenset([
            # "attributetypes",
            # "objectclasses",
            # "ldapsyntaxes",
            # "matchingrules",
            # "ditcontentrules",
            # "ditstructurerules",
            # "nameformsrules",
            # "matchingruleuse",
        ])

    class SchemaFields:
        """LDIF schema structure field names (case-sensitive).

        Consolidates all schema dictionary key names used throughout parsing.
        Critical for consistency when parsing RFC 2849 schema declarations.
        """

        # Primary schema field names (RFC 2849 section 5)
        ATTRIBUTE_TYPES: Final[str] = "attributeTypes"  # RFC 4512 attribute definitions
        OBJECT_CLASSES: Final[str] = (
            "objectClasses"  # RFC 4512 object class definitions
        )
        MATCHING_RULES: Final[str] = "matchingRules"  # RFC 4512 matching rules
        MATCHING_RULE_USE: Final[str] = "matchingRuleUse"  # RFC 4512 matching rule use
        DIT_CONTENT_RULES: Final[str] = "dITContentRules"  # RFC 4512 DIT content rules
        DIT_STRUCTURE_RULES: Final[str] = (
            "dITStructureRules"  # RFC 4512 DIT structure rules
        )
        NAME_FORMS: Final[str] = "nameForms"  # RFC 4512 name forms
        LDAP_SYNTAXES: Final[str] = "ldapSyntaxes"  # RFC 4512 LDAP syntaxes

        # Schema field names (lowercase variants for compatibility with some servers)
        ATTRIBUTE_TYPES_LOWER: Final[str] = "attributetypes"
        OBJECT_CLASSES_LOWER: Final[str] = "objectclasses"

        # ObjectClass field name (camelCase - used in entry attributes)
        OBJECT_CLASS_CAMEL: Final[str] = "objectClass"

        # All schema field names as frozenset for membership testing
        ALL_SCHEMA_FIELDS: Final[frozenset[str]] = frozenset([
            ATTRIBUTE_TYPES,
            OBJECT_CLASSES,
            MATCHING_RULES,
            MATCHING_RULE_USE,
            DIT_CONTENT_RULES,
            DIT_STRUCTURE_RULES,
            NAME_FORMS,
            LDAP_SYNTAXES,
        ])

    # =============================================================================
    # ACL ATTRIBUTES - ACL attribute names consolidated by server type
    # =============================================================================

    class AclAttributes:
        """ACL attribute names used across different LDAP servers.

        Consolidates all ACL attribute references to prevent duplication
        and ensure consistent ACL detection across the codebase.
        """

        # Oracle Internet Directory (OID) ACL attributes
        ORCLACI: Final[str] = "orclaci"  # Standard OID entry-level ACL
        ORCL_ENTRY_LEVEL_ACI: Final[str] = (
            "orclentrylevelaci"  # OID entry-level variant
        )

        # Oracle Unified Directory (OUD) and RFC 4876 standard
        ACI: Final[str] = "aci"  # RFC 4876 ACI attribute

        # OpenLDAP ACL attributes
        OLC_ACCESS: Final[str] = "olcAccess"  # OpenLDAP cn=config ACL

        # Additional ACL-related attributes for filtering
        ACLRIGHTS: Final[str] = "aclrights"  # Generic ACL rights attribute
        ACLENTRY: Final[str] = "aclentry"  # Generic ACL entry attribute
        ACCESS_CONTROL_LIST: Final[str] = (
            "accessControlList"  # Active Directory ACL attribute
        )

        # Set of all known ACL attributes for quick membership testing
        ALL_ACL_ATTRIBUTES: Final[frozenset[str]] = frozenset([
            ORCLACI,
            ORCL_ENTRY_LEVEL_ACI,
            ACI,
            OLC_ACCESS,
            ACLRIGHTS,
            ACLENTRY,
            ACCESS_CONTROL_LIST,
        ])

        # ACL attributes to filter/detect during migration
        # NOTE: All values are commented and list is empty - values should be added as needed
        FILTER_ACL_ATTRIBUTES: Final[frozenset[str]] = frozenset([
            # "aci",
            # "orclaci",
            # "aclrights",
            # "aclentry",
        ])

        # Grouped by server type for server-specific processing
        OID_ACL_ATTRS: Final[frozenset[str]] = frozenset([
            ORCLACI,
            ORCL_ENTRY_LEVEL_ACI,
        ])
        OUD_ACL_ATTRS: Final[frozenset[str]] = frozenset([ACI])
        OPENLDAP_ACL_ATTRS: Final[frozenset[str]] = frozenset([OLC_ACCESS])

    # =============================================================================
    # DN-VALUED ATTRIBUTES - Attributes that contain DN values
    # =============================================================================

    class DnValuedAttributes:
        """Attributes that contain Distinguished Names as values.

        Consolidated list of all attributes that hold DN references across
        all supported LDAP servers. Used for DN consistency validation during
        server-to-server migrations and conversions.

        These attributes require special handling during DN normalization
        and case preservation (especially for OUD compatibility).
        """

        # Member/ownership attributes (point to user/group DNs)
        MEMBER: Final[str] = "member"  # RFC 4512 group members
        UNIQUE_MEMBER: Final[str] = "uniqueMember"  # RFC 4512 unique members
        OWNER: Final[str] = "owner"  # Entry owner DN
        MANAGED_BY: Final[str] = "managedBy"  # Active Directory manager
        MANAGER: Final[str] = "manager"  # inetOrgPerson manager
        SECRETARY: Final[str] = "secretary"  # inetOrgPerson secretary
        SEES_ALSO: Final[str] = "seeAlso"  # See also reference

        # Parent/hierarchy attributes
        PARENT: Final[str] = "parent"  # Parent entry reference
        REFERS_TO: Final[str] = "refersTo"  # Generic reference

        # Group/role attributes (point to group/role DNs)
        MEMBER_OF: Final[str] = "memberOf"  # Active Directory member of groups
        GROUPS: Final[str] = "groups"  # Generic group membership

        # Authorization/delegation attributes
        AUTHORIZED_TO: Final[str] = "authorizedTo"  # Delegation target
        HAS_SUBORDINATES: Final[str] = "hasSubordinates"  # RFC 3673 operational
        SUBORDINATE_DN: Final[str] = "subordinateDn"  # Subordinate reference

        # All DN-valued attributes as frozenset for membership testing
        ALL_DN_VALUED: Final[frozenset[str]] = frozenset([
            MEMBER,
            UNIQUE_MEMBER,
            OWNER,
            MANAGED_BY,
            MANAGER,
            SECRETARY,
            SEES_ALSO,
            PARENT,
            REFERS_TO,
            MEMBER_OF,
            GROUPS,
            AUTHORIZED_TO,
            HAS_SUBORDINATES,
            SUBORDINATE_DN,
        ])

    # =============================================================================
    # DN PATTERNS - Standard DN patterns for schema and configuration
    # =============================================================================

    # =============================================================================
    # PERMISSION NAMES - ACL Permission Type Identifiers
    # =============================================================================

    class PermissionNames:
        """ACL permission type identifiers (magic strings representing permission types).

        Used across OID, OUD, OpenLDAP, and other LDAP server ACL definitions.
        These are different from actions (add/delete/modify in changetype).

        Zero Tolerance: All permission name strings (read, write, etc.) MUST be here.
        DO NOT hard-code permission names in servers/*.py
        """

        # Standard LDAP ACL permissions
        READ: Final[str] = "read"
        WRITE: Final[str] = "write"
        ADD: Final[str] = "add"
        DELETE: Final[str] = "delete"
        SEARCH: Final[str] = "search"
        COMPARE: Final[str] = "compare"

        # Extended permissions
        SELF_WRITE: Final[str] = "self_write"
        SELFWRITE: Final[str] = "selfwrite"  # Oracle variant
        PROXY: Final[str] = "proxy"
        BROWSE: Final[str] = "browse"
        ALL: Final[str] = "all"
        NONE: Final[str] = "none"

        # Permission aliases/mappings
        PERMISSION_MAPPINGS: Final[dict[str, list[str]]] = {
            "browse": ["read", "search"],
            "selfwrite": ["write"],
            "proxy": ["proxy"],
        }

        # All permission names for validation
        ALL_PERMISSIONS: Final[frozenset[str]] = frozenset([
            READ,
            WRITE,
            ADD,
            DELETE,
            SEARCH,
            COMPARE,
            SELF_WRITE,
            SELFWRITE,
            PROXY,
            BROWSE,
            ALL,
            NONE,
        ])

    # =============================================================================
    # BOOLEAN FORMATS - Server-Specific Boolean Representations
    # =============================================================================

    class BooleanFormats:
        """Boolean value representations and conversions across LDAP servers.

        Different servers use different boolean formats:
        - RFC 4517 compliant: "TRUE" / "FALSE"
        - Oracle OID: "1" / "0"
        - Legacy formats: "true" / "false", "yes" / "no"

        Zero Tolerance: Boolean conversions MUST use these constants.
        DO NOT hard-code boolean strings like "TRUE" or "1" in servers/*.py
        """

        # RFC 4517 compliant (OUD, modern servers)
        TRUE_RFC: Final[str] = "TRUE"
        FALSE_RFC: Final[str] = "FALSE"

        # Legacy variants (case-insensitive)
        TRUE_LOWER: Final[str] = "true"
        FALSE_LOWER: Final[str] = "false"

        # Oracle OID format (non-RFC compliant)
        ONE_OID: Final[str] = "1"
        ZERO_OID: Final[str] = "0"

        # Boolean conversion mappings
        OID_TO_RFC: Final[dict[str, str]] = {
            "1": TRUE_RFC,
            "0": FALSE_RFC,
            "true": TRUE_RFC,
            "false": FALSE_RFC,
        }

        RFC_TO_OID: Final[dict[str, str]] = {
            TRUE_RFC: ONE_OID,
            FALSE_RFC: ZERO_OID,
            TRUE_LOWER: ONE_OID,
            FALSE_LOWER: ZERO_OID,
        }

        # Universal boolean check
        RFC_TRUE_VALUES: Final[frozenset[str]] = frozenset([TRUE_RFC, TRUE_LOWER])
        RFC_FALSE_VALUES: Final[frozenset[str]] = frozenset([FALSE_RFC, FALSE_LOWER])
        OID_TRUE_VALUES: Final[frozenset[str]] = frozenset([
            ONE_OID,
            "true",
            "True",
            "TRUE",
        ])
        OID_FALSE_VALUES: Final[frozenset[str]] = frozenset([
            ZERO_OID,
            "false",
            "False",
            "FALSE",
        ])

    # =============================================================================
    # METADATA KEYS - Quirk Processing and Entry Extension Metadata
    # =============================================================================

    class MetadataKeys:
        """Metadata extension keys used in quirk processing and entry transformations.

        Used in _metadata dictionaries and extension fields within Entry/ACL/Schema models.

        Zero Tolerance: All metadata key strings MUST be defined here.
        DO NOT use hard-coded keys like metadata["proxy_permissions"] in servers/*.py
        """

        # =========================
        # OID-Specific Metadata
        # =========================

        PROXY_PERMISSIONS: Final[str] = "proxy_permissions"
        ORIGINAL_OID_PERMS: Final[str] = "original_oid_perms"
        SELF_WRITE_TO_WRITE: Final[str] = "self_write_to_write"
        OID_SPECIFIC_RIGHTS: Final[str] = "oid_specific_rights"
        OID_TO_OUD_TRANSFORMED: Final[str] = "oid_to_oud_transformed"

        # =========================
        # Schema Extension Metadata
        # =========================

        SYNTAX_OID_VALID: Final[str] = "syntax_oid_valid"
        SYNTAX_VALIDATION_ERROR: Final[str] = "syntax_validation_error"
        X_ORIGIN: Final[str] = "x_origin"  # RFC 2252 X-ORIGIN extension
        OBSOLETE: Final[str] = "obsolete"  # RFC 4512 OBSOLETE flag
        COLLECTIVE: Final[str] = "collective"  # RFC 2876 COLLECTIVE flag
        ORIGINAL_FORMAT: Final[str] = (
            "original_format"  # Source format before conversion
        )
        ORIGINAL_SOURCE: Final[str] = (
            "original_source"  # Source server type that generated
        )

        # =========================
        # ACL/Permission Metadata
        # =========================

        VERSION: Final[str] = "version"  # ACL version/format number
        LINE_BREAKS: Final[str] = "line_breaks"  # Whether ACL uses line breaks
        IS_MULTILINE: Final[str] = "is_multiline"  # ACL spans multiple lines
        DN_SPACES: Final[str] = "dn_spaces"  # Whether DN has spaces around delimiters
        TARGETSCOPE: Final[str] = (
            "targetscope"  # ACL target scope (base, one, sub, etc)
        )
        ATTRIBUTE_ORDER: Final[str] = (
            "attribute_order"  # Order of attributes in original
        )
        SUBJECT_BINDING: Final[str] = "subject_binding"  # Subject binding type

        # =========================
        # Entry Extension Metadata
        # =========================

        BASE64_ATTRS: Final[str] = "_base64_attrs"  # Attributes encoded in base64
        MODIFY_ADD_ATTRIBUTETYPES: Final[str] = (
            "_modify_add_attributetypes"  # New attribute types in changetype: modify
        )
        MODIFY_ADD_OBJECTCLASSES: Final[str] = (
            "_modify_add_objectclasses"  # New object classes in changetype: modify
        )
        ORACLE_OBJECTCLASSES: Final[str] = (
            "oracle_objectclasses"  # Oracle-specific objectClasses
        )
        SKIPPED_ATTRIBUTES: Final[str] = (
            "_skipped_attributes"  # Attributes removed during conversion
        )
        CONVERTED_ATTRIBUTES: Final[str] = (
            "_converted_attributes"  # Attribute names that changed
        )

        # =========================
        # Processing Metadata
        # =========================

        METADATA: Final[str] = "_metadata"  # Root metadata container
        ACL_ATTRIBUTES: Final[str] = (
            "_acl_attributes"  # ACL-related attributes in entry
        )
        HAS_SYNTAX_EXTENSIONS: Final[str] = (
            "_has_syntax_extensions"  # Custom SYNTAX extensions
        )
        REQUIRES_RFC_TRANSLATION: Final[str] = (
            "_requires_rfc_translation"  # Needs RFC conversion
        )
        IS_RELAXED_PARSED: Final[str] = (
            "_is_relaxed_parsed"  # Parsed using relaxed mode
        )

        # =========================
        # All Metadata Keys Registry
        # =========================

        ALL_OID_KEYS: Final[frozenset[str]] = frozenset([
            PROXY_PERMISSIONS,
            ORIGINAL_OID_PERMS,
            SELF_WRITE_TO_WRITE,
            OID_SPECIFIC_RIGHTS,
            OID_TO_OUD_TRANSFORMED,
        ])

        ALL_SCHEMA_KEYS: Final[frozenset[str]] = frozenset([
            X_ORIGIN,
            OBSOLETE,
            COLLECTIVE,
            ORIGINAL_FORMAT,
            ORIGINAL_SOURCE,
        ])

        ALL_ACL_KEYS: Final[frozenset[str]] = frozenset([
            VERSION,
            LINE_BREAKS,
            IS_MULTILINE,
            DN_SPACES,
            TARGETSCOPE,
            ATTRIBUTE_ORDER,
            SUBJECT_BINDING,
        ])

        ALL_ENTRY_KEYS: Final[frozenset[str]] = frozenset([
            BASE64_ATTRS,
            MODIFY_ADD_ATTRIBUTETYPES,
            MODIFY_ADD_OBJECTCLASSES,
            ORACLE_OBJECTCLASSES,
            SKIPPED_ATTRIBUTES,
            CONVERTED_ATTRIBUTES,
        ])

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
        # Regex pattern for extracting OID from schema definitions (with start anchor)
        SCHEMA_OID_EXTRACTION_START: Final[str] = (
            r"^\s*\(\s*([0-9.]+)"  # For re.search() with ^ anchor (common use case)
        )
        SCHEMA_NAME: Final[str] = r"NAME\s+\(?\s*'([^']+)'"
        SCHEMA_DESC: Final[str] = r"DESC\s+'([^']+)'"
        SCHEMA_SYNTAX: Final[str] = r"SYNTAX\s+([\d.]+)"
        SCHEMA_EQUALITY: Final[str] = r"EQUALITY\s+([^\s)]+)"
        SCHEMA_SUBSTR: Final[str] = r"SUBSTR\s+([^\s)]+)"
        SCHEMA_ORDERING: Final[str] = r"ORDERING\s+([^\s)]+)"
        SCHEMA_SUP: Final[str] = r"SUP\s+(\w+)"
        SCHEMA_USAGE: Final[str] = r"USAGE\s+(\w+)"
        SCHEMA_X_ORIGIN: Final[str] = r"X-ORIGIN\s+'([^']+)'"
        SCHEMA_SYNTAX_LENGTH: Final[str] = r"SYNTAX\s+([0-9.]+)(?:\{(\d+)\})?"
        SCHEMA_SINGLE_VALUE: Final[str] = r"\bSINGLE-VALUE\b"
        SCHEMA_COLLECTIVE: Final[str] = r"\bCOLLECTIVE\b"
        SCHEMA_NO_USER_MODIFICATION: Final[str] = r"\bNO-USER-MODIFICATION\b"
        SCHEMA_OBSOLETE: Final[str] = r"\bOBSOLETE\b"

        # ObjectClass specific schema parsing patterns
        SCHEMA_OBJECTCLASS_KIND: Final[str] = r"\b(ABSTRACT|STRUCTURAL|AUXILIARY)\b"
        SCHEMA_OBJECTCLASS_SUP: Final[str] = r"SUP\s+\(?\s*([\w$ ]+?)\s*\)?"
        SCHEMA_OBJECTCLASS_MUST: Final[str] = r"MUST\s+\(?\s*([\w$ ]+?)\s*\)?"
        SCHEMA_OBJECTCLASS_MAY: Final[str] = r"MAY\s+\(?\s*([\w$ ]+?)\s*\)?"

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

    # Change type enum
    class ChangeType(StrEnum):
        """LDIF change types for entry operations."""

        ADD = "add"
        DELETE = "delete"
        MODIFY = "modify"
        MODRDN = "modrdn"

        # Comment patterns
        COMMENT_LINE = r"^\s*#"
        VERSION_LINE = r"^version:\s*\d+"

    # LDAP SERVERS - Server-specific detection patterns
    # =============================================================================

    class LdapServerDetection:
        """Server-specific detection patterns and markers for LDAP servers.

        Centralizes all OID patterns, attribute prefixes, objectClass names,
        and DN markers used for server detection across all quirk implementations.

        Zero Tolerance: All server detection constants MUST be defined here,
        NO hardcoding in server implementations.
        """

        # ===== ACTIVE DIRECTORY (Microsoft) =====
        AD_OID_PATTERN: Final[str] = r"1\.2\.840\.113556\."
        AD_ATTRIBUTE_NAMES: Final[frozenset[str]] = frozenset([
            "samaccountname",
            "objectguid",
            "objectsid",
            "userprincipalname",
            "unicodepwd",
            "useraccountcontrol",
            "primarygroupid",
            "logonhours",
            "lockouttime",
            "pwdlastset",
            "memberof",
            "msds-supportedencryptiontypes",
            "serviceprincipalname",
            "distinguishedname",
        ])
        AD_OBJECTCLASS_NAMES: Final[frozenset[str]] = frozenset([
            "user",
            "computer",
            "group",
            "organizationalunit",
            "organizationalperson",
            "person",
            "domain",
            "domainpolicy",
            "foreignsecurityprincipal",
            "msds-groupmanagedserviceaccount",
            "msds-managedserviceaccount",
        ])
        AD_DN_MARKERS: Final[frozenset[str]] = frozenset([
            "cn=users",
            "cn=computers",
            "cn=configuration",
            "cn=system",
            "ou=domain controllers",
        ])
        AD_ATTRIBUTE_MARKERS: Final[frozenset[str]] = frozenset([
            "objectguid",
            "objectsid",
            "samaccountname",
            "userprincipalname",
            "ntsecuritydescriptor",
            "useraccountcontrol",
            "serviceprincipalname",
            "lastlogontimestamp",
            "pwdlastset",
        ])

        # ===== APACHE DIRECTORY SERVER =====
        APACHE_OID_PATTERN: Final[str] = r"1\.3\.6\.1\.4\.1\.18060\."
        APACHE_ATTRIBUTE_PREFIXES: Final[frozenset[str]] = frozenset([
            "ads-",
            "apacheds",
        ])
        APACHE_OBJECTCLASS_NAMES: Final[frozenset[str]] = frozenset([
            "ads-directoryservice",
            "ads-base",
            "ads-server",
            "ads-partition",
            "ads-interceptor",
        ])
        APACHE_DN_MARKERS: Final[frozenset[str]] = frozenset([
            "ou=config",
            "ou=services",
            "ou=system",
            "ou=partitions",
        ])

        # ===== 389 DIRECTORY SERVER (Red Hat) =====
        DS389_OID_PATTERN: Final[str] = r"2\.16\.840\.1\.113730\."
        DS389_ATTRIBUTE_PREFIXES: Final[frozenset[str]] = frozenset([
            "nsslapd-",
            "nsds",
            "nsuniqueid",
        ])
        DS389_OBJECTCLASS_NAMES: Final[frozenset[str]] = frozenset([
            "nscontainer",
            "nsperson",
            "nsds5replica",
            "nsds5replicationagreement",
        ])
        DS389_DN_MARKERS: Final[frozenset[str]] = frozenset([
            "cn=config",
            "cn=monitor",
            "cn=changelog",
        ])

        # ===== NOVELL eDIRECTORY =====
        NOVELL_OID_PATTERN: Final[str] = r"2\.16\.840\.1\.113719\."
        NOVELL_ATTRIBUTE_PREFIXES: Final[frozenset[str]] = frozenset([
            "nspm",
            "login",
            "dirxml-",
        ])
        NOVELL_OBJECTCLASS_NAMES: Final[frozenset[str]] = frozenset([
            "ndsperson",
            "nspmpasswordpolicy",
            "ndsserver",
            "ndstree",
            "ndsloginproperties",
        ])
        NOVELL_DN_MARKERS: Final[frozenset[str]] = frozenset([
            "ou=services",
            "ou=apps",
            "ou=system",
        ])
        NOVELL_ATTRIBUTE_MARKERS: Final[frozenset[str]] = frozenset([
            "nspmpasswordpolicy",
            "nspmpasswordpolicydn",
            "logindisabled",
            "loginexpirationtime",
        ])
        # Novell ACL segment indices
        NOVELL_SEGMENT_INDEX_SCOPE: Final[int] = 0
        NOVELL_SEGMENT_INDEX_TRUSTEE: Final[int] = 1
        NOVELL_SEGMENT_INDEX_RIGHTS: Final[int] = 2

        # ===== IBM TIVOLI DIRECTORY SERVER =====
        TIVOLI_OID_PATTERN: Final[str] = r"1\.3\.18\."
        TIVOLI_ATTRIBUTE_PREFIXES: Final[frozenset[str]] = frozenset([
            "ibm-",
            "ids-",
        ])
        TIVOLI_OBJECTCLASS_NAMES: Final[frozenset[str]] = frozenset([
            "ibm-slapdaccesscontrolsubentry",
            "ibm-ldapserver",
            "ibm-filterentry",
        ])
        TIVOLI_DN_MARKERS: Final[frozenset[str]] = frozenset([
            "cn=ibm",
            "cn=configuration",
            "cn=schema",
        ])
        TIVOLI_ATTRIBUTE_MARKERS: Final[frozenset[str]] = frozenset([
            "ibm-entryuuid",
            "ibm-slapdaccesscontrol",
            "ibm-replicationchangecount",
        ])

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

    class RfcSyntaxOids:
        """RFC 4517 LDAP Attribute Syntax OIDs.

        Standard LDAP attribute syntax definitions per RFC 4517.
        OID format: 1.3.6.1.4.1.1466.115.121.1.X
        """

        # RFC 4517 Syntax OIDs (base: 1.3.6.1.4.1.1466.115.121.1)
        BASE: Final[str] = "1.3.6.1.4.1.1466.115.121.1"

        # Basic syntaxes
        ACI: Final[str] = "1.3.6.1.4.1.1466.115.121.1.1"  # ACI Item
        ACCESS_POINT: Final[str] = "1.3.6.1.4.1.1466.115.121.1.2"  # Access Point
        ATTRIBUTE_TYPE_DESCRIPTION: Final[str] = (
            "1.3.6.1.4.1.1466.115.121.1.3"  # Attribute Type Description
        )
        AUDIO: Final[str] = "1.3.6.1.4.1.1466.115.121.1.4"  # Audio
        BINARY: Final[str] = "1.3.6.1.4.1.1466.115.121.1.5"  # Binary
        BIT_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.6"  # Bit String
        BOOLEAN: Final[str] = "1.3.6.1.4.1.1466.115.121.1.7"  # Boolean
        CERTIFICATE: Final[str] = (
            "1.3.6.1.4.1.1466.115.121.1.8"  # Certificate (DER encoded)
        )
        CERTIFICATE_LIST: Final[str] = (
            "1.3.6.1.4.1.1466.115.121.1.9"  # Certificate List (DER encoded)
        )
        CERTIFICATE_PAIR: Final[str] = (
            "1.3.6.1.4.1.1466.115.121.1.10"  # Certificate Pair (DER encoded)
        )
        COUNTRY_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.11"  # Country String
        DN: Final[str] = "1.3.6.1.4.1.1466.115.121.1.12"  # Distinguished Name (DN)
        DATA_QUALITY_SYNTAX: Final[str] = (
            "1.3.6.1.4.1.1466.115.121.1.13"  # Data Quality Syntax
        )
        DELIVERY_METHOD: Final[str] = "1.3.6.1.4.1.1466.115.121.1.14"  # Delivery Method
        DIRECTORY_STRING: Final[str] = (
            "1.3.6.1.4.1.1466.115.121.1.15"  # Directory String
        )
        DIT_CONTENT_RULE_DESCRIPTION: Final[str] = (
            "1.3.6.1.4.1.1466.115.121.1.16"  # DIT Content Rule Description
        )
        DIT_STRUCTURE_RULE_DESCRIPTION: Final[str] = (
            "1.3.6.1.4.1.1466.115.121.1.17"  # DIT Structure Rule Description
        )
        DLEXP_TIME: Final[str] = "1.3.6.1.4.1.1466.115.121.1.18"  # DLEXP Time
        DN_WITH_BINARY: Final[str] = "1.3.6.1.4.1.1466.115.121.1.19"  # DN With Binary
        DN_WITH_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.20"  # DN With String

        # String-based syntaxes
        DIRECTORY_STRING_21: Final[str] = (
            "1.3.6.1.4.1.1466.115.121.1.21"  # Directory String
        )
        ENHANCED_GUIDE: Final[str] = "1.3.6.1.4.1.1466.115.121.1.22"  # Enhanced Guide
        FACSIMILE_TELEPHONE_NUMBER: Final[str] = (
            "1.3.6.1.4.1.1466.115.121.1.23"  # Facsimile Telephone Number
        )
        FAX: Final[str] = "1.3.6.1.4.1.1466.115.121.1.24"  # Fax
        GENERALIZED_TIME: Final[str] = (
            "1.3.6.1.4.1.1466.115.121.1.25"  # Generalized Time
        )
        GUIDE: Final[str] = "1.3.6.1.4.1.1466.115.121.1.26"  # Guide
        IA5_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.27"  # IA5 String (ASCII)
        INTEGER_RFC: Final[str] = "2.5.5.5"  # INTEGER (RFC 2252/4517 standard)
        JPEG: Final[str] = "1.3.6.1.4.1.1466.115.121.1.28"  # JPEG Image
        LDAP_SYNTAX_DESCRIPTION: Final[str] = (
            "1.3.6.1.4.1.1466.115.121.1.29"  # LDAP Syntax Description
        )

        # Numeric and structured syntaxes
        MATCHING_RULE_DESCRIPTION: Final[str] = (
            "1.3.6.1.4.1.1466.115.121.1.30"  # Matching Rule Description
        )
        MATCHING_RULE_USE_DESCRIPTION: Final[str] = (
            "1.3.6.1.4.1.1466.115.121.1.31"  # Matching Rule Use Description
        )
        MHS_OR_ADDRESS: Final[str] = "1.3.6.1.4.1.1466.115.121.1.32"  # MHS OR Address
        MODIFY_INCREMENT: Final[str] = (
            "1.3.6.1.4.1.1466.115.121.1.33"  # Modify Increment
        )
        NAME_AND_OPTIONAL_UID: Final[str] = (
            "1.3.6.1.4.1.1466.115.121.1.34"  # Name and Optional UID
        )
        NAME_FORM_DESCRIPTION: Final[str] = (
            "1.3.6.1.4.1.1466.115.121.1.35"  # Name Form Description
        )
        NUMERIC_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.36"  # Numeric String
        OBJECT_CLASS_DESCRIPTION: Final[str] = (
            "1.3.6.1.4.1.1466.115.121.1.37"  # Object Class Description
        )
        OID: Final[str] = "1.3.6.1.4.1.1466.115.121.1.38"  # OID
        OCTET_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.39"  # Octet String

        # Additional standard syntaxes
        OTHER_MAILBOX: Final[str] = "1.3.6.1.4.1.1466.115.121.1.40"  # Other Mailbox
        OCTET_STRING_40: Final[str] = (
            "1.3.6.1.4.1.1466.115.121.1.40"  # Octet String (same as 39)
        )
        POSTAL_ADDRESS: Final[str] = "1.3.6.1.4.1.1466.115.121.1.41"  # Postal Address
        PROTOCOL_INFORMATION: Final[str] = (
            "1.3.6.1.4.1.1466.115.121.1.42"  # Protocol Information
        )
        PRESENTATION_ADDRESS: Final[str] = (
            "1.3.6.1.4.1.1466.115.121.1.43"  # Presentation Address
        )
        PRINTABLE_STRING: Final[str] = (
            "1.3.6.1.4.1.1466.115.121.1.44"  # Printable String
        )
        SUBSTRING_ASSERTION: Final[str] = (
            "1.3.6.1.4.1.1466.115.121.1.58"  # Substring Assertion
        )
        TELEPHONE_NUMBER: Final[str] = (
            "1.3.6.1.4.1.1466.115.121.1.50"  # Telephone Number
        )
        TELETEX_TERMINAL_IDENTIFIER: Final[str] = (
            "1.3.6.1.4.1.1466.115.121.1.51"  # Teletex Terminal Identifier
        )
        TELEX_NUMBER: Final[str] = "1.3.6.1.4.1.1466.115.121.1.52"  # Telex Number
        TIME_OF_DAY: Final[str] = "1.3.6.1.4.1.1466.115.121.1.53"  # Time of Day
        UTCTIME: Final[str] = "1.3.6.1.4.1.1466.115.121.1.54"  # UTC Time
        LDAP_SYNTAX: Final[str] = "1.3.6.1.4.1.1466.115.121.1.54"  # LDAP Syntax (alias)
        UTF8_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.55"  # UTF-8 String
        UNICODE_STRING: Final[str] = (
            "1.3.6.1.4.1.1466.115.121.1.56"  # Unicode String (also UCS-2)
        )
        UUI: Final[str] = (
            "1.3.6.1.4.1.1466.115.121.1.57"  # UUI (User-defined attribute)
        )

        # Mapping of OID to human-readable name
        OID_TO_NAME: Final[dict[str, str]] = {
            "2.5.5.5": "integer",  # INTEGER (RFC 2252/4517 standard)
            "1.3.6.1.4.1.1466.115.121.1.1": "aci",
            "1.3.6.1.4.1.1466.115.121.1.2": "access_point",
            "1.3.6.1.4.1.1466.115.121.1.3": "attribute_type_description",
            "1.3.6.1.4.1.1466.115.121.1.4": "audio",
            "1.3.6.1.4.1.1466.115.121.1.5": "binary",
            "1.3.6.1.4.1.1466.115.121.1.6": "bit_string",
            "1.3.6.1.4.1.1466.115.121.1.7": "boolean",
            "1.3.6.1.4.1.1466.115.121.1.8": "certificate",
            "1.3.6.1.4.1.1466.115.121.1.9": "certificate_list",
            "1.3.6.1.4.1.1466.115.121.1.10": "certificate_pair",
            "1.3.6.1.4.1.1466.115.121.1.11": "country_string",
            "1.3.6.1.4.1.1466.115.121.1.12": "dn",
            "1.3.6.1.4.1.1466.115.121.1.13": "data_quality_syntax",
            "1.3.6.1.4.1.1466.115.121.1.14": "delivery_method",
            "1.3.6.1.4.1.1466.115.121.1.15": "directory_string",
            "1.3.6.1.4.1.1466.115.121.1.16": "dit_content_rule_description",
            "1.3.6.1.4.1.1466.115.121.1.17": "dit_structure_rule_description",
            "1.3.6.1.4.1.1466.115.121.1.18": "dlexp_time",
            "1.3.6.1.4.1.1466.115.121.1.19": "dn_with_binary",
            "1.3.6.1.4.1.1466.115.121.1.20": "dn_with_string",
            "1.3.6.1.4.1.1466.115.121.1.21": "directory_string",
            "1.3.6.1.4.1.1466.115.121.1.22": "enhanced_guide",
            "1.3.6.1.4.1.1466.115.121.1.23": "facsimile_telephone_number",
            "1.3.6.1.4.1.1466.115.121.1.24": "fax",
            "1.3.6.1.4.1.1466.115.121.1.25": "generalized_time",
            "1.3.6.1.4.1.1466.115.121.1.26": "guide",
            "1.3.6.1.4.1.1466.115.121.1.27": "ia5_string",
            "1.3.6.1.4.1.1466.115.121.1.28": "jpeg",
            "1.3.6.1.4.1.1466.115.121.1.29": "ldap_syntax_description",
            "1.3.6.1.4.1.1466.115.121.1.30": "matching_rule_description",
            "1.3.6.1.4.1.1466.115.121.1.31": "matching_rule_use_description",
            "1.3.6.1.4.1.1466.115.121.1.32": "mhs_or_address",
            "1.3.6.1.4.1.1466.115.121.1.33": "modify_increment",
            "1.3.6.1.4.1.1466.115.121.1.34": "name_and_optional_uid",
            "1.3.6.1.4.1.1466.115.121.1.35": "name_form_description",
            "1.3.6.1.4.1.1466.115.121.1.36": "numeric_string",
            "1.3.6.1.4.1.1466.115.121.1.37": "object_class_description",
            "1.3.6.1.4.1.1466.115.121.1.38": "oid",
            "1.3.6.1.4.1.1466.115.121.1.39": "octet_string",
            "1.3.6.1.4.1.1466.115.121.1.40": "other_mailbox",
            "1.3.6.1.4.1.1466.115.121.1.41": "postal_address",
            "1.3.6.1.4.1.1466.115.121.1.42": "protocol_information",
            "1.3.6.1.4.1.1466.115.121.1.43": "presentation_address",
            "1.3.6.1.4.1.1466.115.121.1.44": "printable_string",
            "1.3.6.1.4.1.1466.115.121.1.50": "telephone_number",
            "1.3.6.1.4.1.1466.115.121.1.51": "teletex_terminal_identifier",
            "1.3.6.1.4.1.1466.115.121.1.52": "telex_number",
            "1.3.6.1.4.1.1466.115.121.1.53": "time_of_day",
            "1.3.6.1.4.1.1466.115.121.1.54": "utctime",
            "1.3.6.1.4.1.1466.115.121.1.55": "utf8_string",
            "1.3.6.1.4.1.1466.115.121.1.56": "unicode_string",
            "1.3.6.1.4.1.1466.115.121.1.57": "uui",
            "1.3.6.1.4.1.1466.115.121.1.58": "substring_assertion",
        }

        # Mapping of human-readable name to OID
        NAME_TO_OID: Final[dict[str, str]] = {v: k for k, v in OID_TO_NAME.items()}

        # Commonly used syntaxes
        COMMON_SYNTAXES: Final[frozenset[str]] = frozenset([
            "1.3.6.1.4.1.1466.115.121.1.7",  # Boolean
            "1.3.6.1.4.1.1466.115.121.1.12",  # DN
            "1.3.6.1.4.1.1466.115.121.1.15",  # Directory String
            "1.3.6.1.4.1.1466.115.121.1.27",  # IA5 String
            "1.3.6.1.4.1.1466.115.121.1.39",  # Octet String
            "1.3.6.1.4.1.1466.115.121.1.55",  # UTF-8 String
        ])

        # Mapping of syntax names to type categories
        NAME_TO_TYPE_CATEGORY: Final[dict[str, str]] = {
            "boolean": "boolean",
            "integer": "integer",
            "dn": "dn",
            "distinguished_name": "dn",
            "generalized_time": "time",
            "utc_time": "time",
            "utctime": "time",
            "time_of_day": "time",
            "dlexp_time": "time",
            "audio": "binary",
            "binary": "binary",
            "certificate": "binary",
            "certificate_list": "binary",
            "certificate_pair": "binary",
            "fax": "binary",
            "jpeg": "binary",
            "octet_string": "binary",
            "directory_string": "string",
            "ia5_string": "string",
            "printable_string": "string",
            "utf8_string": "string",
            "unicode_string": "string",
            "teletex_terminal_identifier": "string",
            "telephone_number": "string",
            "facsimile_telephone_number": "string",
            "guide": "string",
            "enhanced_guide": "string",
            "access_point": "string",
            "attribute_type_description": "string",
            "country_string": "string",
            "dn_with_binary": "string",
            "dn_with_string": "string",
            "ldap_syntax_description": "string",
            "matching_rule_description": "string",
            "matching_rule_use_description": "string",
            "name_and_optional_uid": "string",
            "name_form_description": "string",
            "numeric_string": "string",
            "object_class_description": "string",
            "oid": "string",
            "other_mailbox": "string",
            "postal_address": "string",
            "protocol_information": "string",
            "presentation_address": "string",
            "telex_number": "string",
            "teletex_number": "string",
            "uui": "string",
            "substring_assertion": "string",
            "mhs_or_address": "string",
            "aci": "string",
            "delivery_method": "string",
            "data_quality_syntax": "string",
            "dit_content_rule_description": "string",
            "dit_structure_rule_description": "string",
            "modify_increment": "integer",
            "bit_string": "string",
        }

        # Service and initialization keys
        SERVICE_NAMES: Final[str] = "service_names"
        DATA: Final[str] = "data"

    class Encoding:
        """Encoding constants for LDIF processing.

        Defines encoding-related constants used throughout the LDIF processing system.
        """

        # Default encoding for LDIF files
        DEFAULT_ENCODING: Final[str] = "utf-8"

        # Supported encodings for LDIF processing
        SUPPORTED_ENCODINGS: Final[frozenset[str]] = frozenset([
            "utf-8",
            "utf-16",
            "ascii",
        ])

    class LdifFormat:
        """LDIF formatting constants.

        Defines constants for LDIF formatting options including line width
        and other formatting preferences.
        """

        # Default line width for LDIF folding (RFC 2849 recommends 76)
        DEFAULT_LINE_WIDTH: Final[int] = 76

        # Maximum allowed line width
        MAX_LINE_WIDTH: Final[int] = 1000

        # Minimum allowed line width
        MIN_LINE_WIDTH: Final[int] = 10

    # =============================================================================
    # CONVERSION STRATEGY - RFC as Canonical Format (Adapter Pattern)
    # =============================================================================

    class ConversionStrategy:
        """Server conversion strategy using RFC as canonical intermediate format.

        **Architecture**: Adapter Pattern with RFC as Hub

        **Algorithm**:
        1. Any→RFC: source.normalize_to_rfc() → RFC canonical format + metadata
        2. RFC→Any: target.denormalize_from_rfc() → target format (metadata guides conversion)
        3. Any→Any: source.normalize_to_rfc() → target.denormalize_from_rfc()

        **Benefits**:
        - Eliminates N×N complexity (N servers = N² direct conversions)
        - Reduces to 2N conversions (N to RFC + N from RFC)
        - Metadata in RFC format preserves original for round-trip fidelity
        - Single source of truth (RFC) for validation and compliance

        **Example**:
            OID → OUD:
              1. oid_entry.normalize_to_rfc() → rfc_entry (with oid metadata)
              2. oud.denormalize_from_rfc(rfc_entry) → oud_entry

        **Required Methods**:
        All server quirks MUST implement:
        - normalize_entry_to_rfc(entry: Entry) → FlextResult[Entry]
        - denormalize_entry_from_rfc(entry: Entry) → FlextResult[Entry]
        - normalize_attribute_to_rfc(attr: SchemaAttribute) → FlextResult[SchemaAttribute]
        - denormalize_attribute_from_rfc(attr: SchemaAttribute) → FlextResult[SchemaAttribute]
        - normalize_objectclass_to_rfc(oc: SchemaObjectClass) → FlextResult[SchemaObjectClass]
        - denormalize_objectclass_from_rfc(oc: SchemaObjectClass) → FlextResult[SchemaObjectClass]
        - normalize_acl_to_rfc(acl: Acl) → FlextResult[Acl]
        - denormalize_acl_from_rfc(acl: Acl) → FlextResult[Acl]
        """

        # Canonical format - all conversions pass through this
        CANONICAL_FORMAT: Final[str] = "rfc"

        # Conversion algorithm type
        ALGORITHM: Final[str] = "adapter_pattern_with_rfc_hub"

        # Complexity: O(2N) instead of O(N²)
        CONVERSION_COMPLEXITY: Final[str] = "2N"  # vs "N²" for direct conversions

        # All conversions MUST go through RFC - no direct server-to-server
        ENFORCE_RFC_INTERMEDIATE: Final[bool] = True

        # Preserve original format in metadata for round-trip
        PRESERVE_SOURCE_METADATA: Final[bool] = True

        # Conversion direction constants
        DIRECTION_TO_RFC: Final[str] = "normalize"
        DIRECTION_FROM_RFC: Final[str] = "denormalize"

        # Metadata keys for tracking conversions
        METADATA_ORIGINAL_SERVER: Final[str] = "original_server_type"
        METADATA_CONVERSION_PATH: Final[str] = "conversion_path"
        METADATA_INTERMEDIATE_FORMAT: Final[str] = "rfc_intermediate"

    class AclSubjectTransformations:
        """Subject transformation mappings for ACL conversions.

        Maps (source_server, target_server, subject_type) → (new_type, value_template)
        Wildcard "*" matches any server for generic transformations.
        """

        # Subject type transformations for OID → OUD via RFC
        OID_TO_RFC_SUBJECTS: Final[dict[str, tuple[str, str]]] = {
            "dynamic_group_dnattr": ("group_membership", 'memberOf="{value}"'),
            "dynamic_group_guidattr": ("user_attribute", 'guidattr="{value}"'),
            "dynamic_group_attr": ("group_attribute", 'groupattr="{value}"'),
        }

        RFC_TO_OUD_SUBJECTS: Final[dict[str, tuple[str, str]]] = {
            "group_membership": ("bind_rules", 'userattr="{value}#LDAPURL"'),
            "user_attribute": ("bind_rules", 'userattr="{value}#USERDN"'),
            "group_attribute": ("bind_rules", 'userattr="{value}#GROUPDN"'),
        }

        # Reverse: OUD → RFC → OID
        OUD_TO_RFC_SUBJECTS: Final[dict[str, tuple[str, str]]] = {
            "bind_rules": ("group_membership", "{value}"),
        }

        RFC_TO_OID_SUBJECTS: Final[dict[str, tuple[str, str]]] = {
            "group_membership": ("group_dn", 'group="{value}"'),
        }

        # 389DS transformations via RFC
        DS389_TO_RFC_SUBJECTS: Final[dict[str, tuple[str, str]]] = {
            "groupdn": ("group_dn", "{value}"),
            "userdn": ("user_dn", "{value}"),
        }

        # Generic transformations (preserved across all servers)
        UNIVERSAL_SUBJECTS: Final[dict[str, tuple[str, str]]] = {
            "anonymous": ("anonymous", "*"),
            "self": ("self", "self"),
            "all": ("all", "*"),
        }

    class AclPermissionCompatibility:
        """Permission compatibility matrix for server types.

        Defines which permissions each server type supports.
        Used for validation and alternative suggestion during conversion.
        """

        # Permission support matrix
        SUPPORTED_PERMISSIONS: Final[dict[str, frozenset[str]]] = {
            "rfc": frozenset(["read", "write", "add", "delete", "search", "compare"]),
            "oid": frozenset([
                "read",
                "write",
                "add",
                "delete",
                "search",
                "compare",
                "self_write",
                "proxy",
                "browse",
                "auth",
                "all",
                "none",
            ]),
            "oracle_oid": frozenset([
                "read",
                "write",
                "add",
                "delete",
                "search",
                "compare",
                "self_write",
                "proxy",
                "browse",
                "auth",
                "all",
                "none",
            ]),
            "oud": frozenset([
                "read",
                "write",
                "add",
                "delete",
                "search",
                "compare",
                "all",
            ]),
            "oracle_oud": frozenset([
                "read",
                "write",
                "add",
                "delete",
                "search",
                "compare",
                "all",
            ]),
            "389ds": frozenset([
                "read",
                "write",
                "add",
                "delete",
                "search",
                "compare",
                "proxy",
                "all",
            ]),
            "openldap": frozenset([
                "read",
                "write",
                "add",
                "delete",
                "search",
                "compare",
                "auth",
            ]),
            "active_directory": frozenset([
                "read",
                "write",
                "add",
                "delete",
                "search",
                "compare",
                "control_access",
            ]),
        }

        # Permission alternatives when converting to servers with limited support
        PERMISSION_ALTERNATIVES: Final[dict[tuple[str, str], list[str]]] = {
            # When converting to OUD, these OID permissions map to alternatives
            ("self_write", "oud"): ["write"],
            ("self_write", "oracle_oud"): ["write"],
            ("proxy", "oud"): [],  # No equivalent - will be documented in comments
            ("proxy", "oracle_oud"): [],
            ("browse", "oud"): ["read", "search"],
            ("browse", "oracle_oud"): ["read", "search"],
            ("auth", "oud"): ["compare"],
            ("auth", "oracle_oud"): ["compare"],
            # When converting to RFC (canonical), simplify extended permissions
            ("self_write", "rfc"): ["write"],
            ("proxy", "rfc"): [],
            ("browse", "rfc"): ["read", "search"],
            ("auth", "rfc"): ["compare"],
            # When converting to 389DS
            ("self_write", "389ds"): ["write"],
            ("browse", "389ds"): ["read", "search"],
            # When converting to OpenLDAP
            ("self_write", "openldap"): ["write"],
            ("proxy", "openldap"): [],
            ("browse", "openldap"): ["read", "search"],
        }

    class SchemaConversionMappings:
        """Schema attribute and objectClass conversion mappings.

        Defines server-specific schema quirks and how to normalize/denormalize them.
        All mappings use RFC-as-hub strategy.
        """

        # Attribute fields that are server-specific and need special handling
        SERVER_SPECIFIC_ATTRIBUTE_FIELDS: Final[dict[str, frozenset[str]]] = {
            "oid": frozenset(["usage", "x_origin"]),
            "oud": frozenset(["x_origin"]),
            "openldap": frozenset(["x_origin", "ordering"]),
            "389ds": frozenset(["x_origin", "x_ds_use"]),
            "rfc": frozenset([]),  # RFC is canonical - no special fields
        }

        # ObjectClass kinds that require special handling per server
        OBJECTCLASS_KIND_REQUIREMENTS: Final[dict[str, dict[str, bool]]] = {
            "rfc": {
                "requires_sup_for_auxiliary": True,
                "allows_multiple_sup": False,
                "requires_explicit_structural": False,
            },
            "oid": {
                "requires_sup_for_auxiliary": True,
                "allows_multiple_sup": True,
                "requires_explicit_structural": False,
            },
            "oud": {
                "requires_sup_for_auxiliary": True,
                "allows_multiple_sup": False,
                "requires_explicit_structural": True,
            },
            "openldap": {
                "requires_sup_for_auxiliary": True,
                "allows_multiple_sup": False,
                "requires_explicit_structural": False,
            },
        }

        # Matching rule normalizations (moved from utilities)
        MATCHING_RULE_NORMALIZATIONS: Final[dict[str, str]] = {
            "caseIgnoreIA5SubstringsMatch": "caseIgnoreIA5Match",
            "caseIgnoreOrdinalMatch": "caseIgnoreMatch",
        }

        # Attribute name transformations via RFC (OID→RFC→OUD strategy)
        ATTRIBUTE_TRANSFORMATION_OID_TO_RFC: Final[dict[str, str]] = {
            "orclguid": "entryUUID",
            "orclobjectguid": "entryUUID",
            "createTimestamp": "createTimestamp",  # Preserved
            "modifyTimestamp": "modifyTimestamp",  # Preserved
        }

        ATTRIBUTE_TRANSFORMATION_RFC_TO_OUD: Final[dict[str, str]] = {
            "entryUUID": "entryUUID",  # Same in OUD
        }

        ATTRIBUTE_TRANSFORMATION_OUD_TO_RFC: Final[dict[str, str]] = {
            "entryUUID": "entryUUID",  # Already RFC
        }

        ATTRIBUTE_TRANSFORMATION_RFC_TO_OID: Final[dict[str, str]] = {
            "entryUUID": "orclguid",
        }

        # Attribute aliases (multiple names for same semantic attribute)
        ATTRIBUTE_ALIASES: Final[dict[str, dict[str, list[str]]]] = {
            "oud": {
                "cn": ["commonName"],
                "sn": ["surname"],
                "givenName": ["gn"],
                "mail": ["rfc822Mailbox", "emailAddress"],
                "telephoneNumber": ["phone"],
                "uid": ["userid", "username"],
            },
            "oid": {"cn": ["commonName"], "mail": ["rfc822Mailbox"], "uid": ["userid"]},
        }

    class OperationalAttributeMappings:
        """Operational attribute definitions per server type.

        Operational attributes are maintained by the server and typically
        read-only. Important for filtering during migrations.
        """

        OPERATIONAL_ATTRIBUTES: Final[dict[str, frozenset[str]]] = {
            "oid": frozenset({
                "createTimestamp",
                "modifyTimestamp",
                "creatorsName",
                "modifiersName",
                "orclguid",
                "orclobjectguid",
                "orclentryid",
                "orclaccount",
                "pwdChangedTime",
                "pwdHistory",
                "pwdFailureTime",
            }),
            "oracle_oid": frozenset({
                "createTimestamp",
                "modifyTimestamp",
                "creatorsName",
                "modifiersName",
                "orclguid",
                "orclobjectguid",
                "orclentryid",
                "orclaccount",
                "pwdChangedTime",
                "pwdHistory",
                "pwdFailureTime",
            }),
            "oud": frozenset({
                "createTimestamp",
                "modifyTimestamp",
                "creatorsName",
                "modifiersName",
                "entryUUID",
                "entryDN",
                "subschemaSubentry",
                "hasSubordinates",
                "pwdChangedTime",
                "pwdHistory",
                "pwdFailureTime",
                "ds-sync-hist",
            }),
            "oracle_oud": frozenset({
                "createTimestamp",
                "modifyTimestamp",
                "creatorsName",
                "modifiersName",
                "entryUUID",
                "entryDN",
                "subschemaSubentry",
                "hasSubordinates",
                "pwdChangedTime",
                "pwdHistory",
                "pwdFailureTime",
                "ds-sync-hist",
            }),
            "active_directory": frozenset({
                "objectGUID",
                "objectSid",
                "whenCreated",
                "whenChanged",
                "uSNCreated",
                "uSNChanged",
                "distinguishedName",
                "canonicalName",
                "lastLogon",
                "logonCount",
                "badPwdCount",
                "pwdLastSet",
            }),
            "389ds": frozenset({
                "createTimestamp",
                "modifyTimestamp",
                "creatorsName",
                "modifiersName",
                "nsUniqueId",
                "entryid",
                "dncomp",
                "parentid",
                "passwordExpirationTime",
                "passwordHistory",
            }),
            "openldap": frozenset({
                "createTimestamp",
                "modifyTimestamp",
                "creatorsName",
                "modifiersName",
                "entryUUID",
                "entryCSN",
                "contextCSN",
                "hasSubordinates",
                "subschemaSubentry",
                "structuralObjectClass",
            }),
            "rfc": frozenset({
                "createTimestamp",
                "modifyTimestamp",
                "creatorsName",
                "modifiersName",
                "subschemaSubentry",
                "structuralObjectClass",
            }),
        }

        # Operational attributes to preserve during migration
        PRESERVE_ON_MIGRATION: Final[dict[str, frozenset[str]]] = {
            "oid": frozenset({"createTimestamp", "modifyTimestamp"}),
            "oracle_oid": frozenset({"createTimestamp", "modifyTimestamp"}),
            "oud": frozenset({"createTimestamp", "modifyTimestamp", "pwdChangedTime"}),
            "oracle_oud": frozenset({
                "createTimestamp",
                "modifyTimestamp",
                "pwdChangedTime",
            }),
            "active_directory": frozenset({"whenCreated", "whenChanged"}),
            "389ds": frozenset({"createTimestamp", "modifyTimestamp"}),
            "openldap": frozenset({"createTimestamp", "modifyTimestamp"}),
        }


__all__ = [
    "FlextLdifConstants",
]
