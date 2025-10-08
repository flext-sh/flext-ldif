"""FLEXT LDIF Constants - Constants and enums ONLY.

Contains ONLY:
- Final constants (literals, strings, numbers)
- Enum and StrEnum definitions
- Frozenset constants

NO types (→ typings.py)
NO protocols (→ protocols.py)
NO models (→ models.py)
NO exceptions (→ exceptions.py)

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

    # =============================================================================
    # FORMAT CONSTANTS
    # =============================================================================

    # LDIF format constants (moved from models.py for proper organization)
    RFC_FORMAT: Final[str] = "rfc"
    OID_FORMAT: Final[str] = "oid"
    AUTO_FORMAT: Final[str] = "auto"
    OUD_FORMAT: Final[str] = "oud"

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

    # Client operation constants
    MAX_PATH_LENGTH_CHECK: Final[int] = 500  # Maximum path length for file operations

    # =============================================================================
    # CONFIGURATION DEFAULTS
    # =============================================================================

    class ConfigDefaults:
        """Default values for FlextLdifConfig fields.

        ZERO TOLERANCE: All Field(default=...) values MUST be defined here.
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

        # RFC 4514 DN length limit
        MAX_DN_LENGTH: Final[int] = 255

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
        """LDAP object class definitions."""

        LDAP_PERSON_CLASSES: Final[frozenset[str]] = frozenset([
            "person",
            "organizationalperson",
            "inetorgperson",
        ])

        LDAP_GROUP_CLASSES: Final[frozenset[str]] = frozenset([
            "groupofnames",
            "groupofuniquenames",
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

        # Server types
        SERVER_TYPES: Final[tuple[str, ...]] = (
            "active_directory",
            "openldap",
            "openldap2",
            "openldap1",
            "apache_directory",
            "novell_edirectory",
            "ibm_tivoli",
            "generic",
            "oracle_oid",
            "oracle_oud",
            "389ds",
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

        # Validation levels
        VALIDATION_LEVELS: Final[tuple[str, ...]] = ("strict", "moderate", "lenient")

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
            "person", "group", "organizationalunit", "domain", "other"
        ]
        type ModificationType = Literal["add", "modify", "delete", "modrdn"]
        type ServerType = Literal[
            "active_directory",
            "openldap",
            "openldap2",
            "openldap1",
            "apache_directory",
            "novell_edirectory",
            "ibm_tivoli",
            "generic",
            "oracle_oid",
            "oracle_oud",
            "389ds",
        ]
        type EncodingType = Literal[
            "utf-8", "latin-1", "ascii", "utf-16", "utf-32", "cp1252", "iso-8859-1"
        ]
        type ValidationLevel = Literal["strict", "moderate", "lenient"]
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

        # Server types
        ACTIVE_DIRECTORY: Final[str] = "active_directory"
        OPENLDAP: Final[str] = "openldap"  # Legacy catch-all
        OPENLDAP_2: Final[str] = "openldap2"  # Modern cn=config based
        OPENLDAP_1: Final[str] = "openldap1"  # Legacy slapd.conf based
        APACHE_DIRECTORY: Final[str] = "apache_directory"
        NOVELL_EDIRECTORY: Final[str] = "novell_edirectory"
        IBM_TIVOLI: Final[str] = "ibm_tivoli"
        GENERIC: Final[str] = "generic"
        # Oracle server types
        ORACLE_OID: Final[str] = "oracle_oid"
        ORACLE_OUD: Final[str] = "oracle_oud"
        # Additional server types
        DS_389: Final[str] = "389ds"

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

        # Novell ACL parsing indices
        NOVELL_SEGMENT_INDEX_TRUSTEE: Final[int] = 2
        NOVELL_SEGMENT_INDEX_RIGHTS: Final[int] = 3

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

    # =============================================================================
    # DICTIONARY KEYS - Standardize all dict key strings
    # =============================================================================

    class DictKeys:
        """Standard dictionary keys used throughout flext-ldif.

        ZERO TOLERANCE: All dict key strings MUST be defined here.
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
        OBJECTCLASS: Final[str] = "objectClass"
        ENTRIES: Final[str] = "entries"
        ENTRY: Final[str] = "entry"
        ENTRY_TYPES: Final[str] = "entry_types"

        # Schema keys
        SCHEMA: Final[str] = "schema"
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
        DEFAULT_ENCODING: Final[str] = "default_encoding"
        ENCODING: Final[str] = "encoding"
        DESCRIPTION: Final[str] = "description"
        QUIRK_REGISTRY: Final[str] = "quirk_registry"

        # File operation keys
        FILE_PATH: Final[str] = "file_path"
        INPUT_DIR: Final[str] = "input_dir"
        OUTPUT_DIR: Final[str] = "output_dir"
        OUTPUT_FILE: Final[str] = "output_file"

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
        INITIALIZED: Final[str] = "initialized"

        # Process/Operations keys
        PROCESS_SCHEMA: Final[str] = "process_schema"
        PROCESS_ENTRIES: Final[str] = "process_entries"
        PARSE_CHANGES: Final[str] = "parse_changes"
        PARSE_ATTRIBUTES: Final[str] = "parse_attributes"

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

        # ObjectClass values
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

        # Status/State keys
        UNKNOWN: Final[str] = "unknown"
        HIGH: Final[str] = "high"
        STOP: Final[str] = "stop"
        SKIP: Final[str] = "skip"
        AFTER: Final[str] = "after"
        MEDIUM: Final[str] = "medium"

        # Class/Component name keys
        FLEXT_LDIF_QUIRKS_REGISTRY: Final[str] = "FlextLdifQuirksRegistry"
        FLEXT_LDIF_QUIRKS_MANAGER: Final[str] = "FlextLdifQuirksManager"
        FLEXT_LDIF_ACL_SERVICE: Final[str] = "FlextLdifAclService"
        FLEXT_LDIF_SCHEMA_BUILDER: Final[str] = "FlextLdifSchemaBuilder"

    # =============================================================================
    # DN PATTERNS - Standard DN patterns for schema and configuration
    # =============================================================================

    class DnPatterns:
        """Standard DN patterns used in LDAP/LDIF processing.

        ZERO TOLERANCE: All DN pattern strings MUST be defined here.
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

        # DN component patterns
        DN_EQUALS: Final[str] = "="
        DN_COMMA: Final[str] = ","
        DN_PLUS: Final[str] = "+"

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

        ZERO TOLERANCE: All ACL format strings MUST be defined here.
        """

        # OpenLDAP ACL formats
        OPENLDAP1_ACL: Final[str] = "openldap1_acl"
        OPENLDAP2_ACL: Final[str] = "openldap2_acl"

        # 389 Directory Server ACL format
        DS389_ACL: Final[str] = "ds389_acl"

        # Oracle ACL formats
        OID_ACL: Final[str] = "oracle_oid"
        OUD_ACL: Final[str] = "oracle_oud"
        OUD_DS_CFG: Final[str] = "ds-cfg"

        # Generic/RFC ACL formats
        RFC_GENERIC: Final[str] = "rfc_generic"
        ACI: Final[str] = "aci"

        # Active Directory ACL format
        AD_ACL: Final[str] = "active_directory_acl"
        AD_NTSECURITY: Final[str] = "nTSecurityDescriptor"

    # =============================================================================
    # SERVER TYPE SHORTCUTS - Short server type identifiers
    # =============================================================================

    class ServerTypes:
        """Server type identifiers (short forms).

        ZERO TOLERANCE: All server type identifier strings MUST be defined here.
        These are the SHORT identifiers used in quirks, config, and processing.
        Long names are in LdapServers class.
        """

        # Short identifiers (used in code)
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
        ORACLE: Final[str] = "oracle"

        # Mapping between short and long server types
        ORACLE_OID_VARIANTS: Final[frozenset[str]] = frozenset(["oid", "oracle_oid"])
        ORACLE_OUD_VARIANTS: Final[frozenset[str]] = frozenset(["oud", "oracle_oud"])
        OPENLDAP_VARIANTS: Final[frozenset[str]] = frozenset([
            "openldap",
            "openldap1",
            "openldap2",
        ])

    # =============================================================================
    # REGEX PATTERNS - All regex patterns centralized
    # =============================================================================

    class LdifPatterns:
        """Regex pattern constants for LDIF processing.

        ZERO TOLERANCE: ALL regex patterns MUST be defined here.
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

        # Attribute name patterns (RFC 4512)
        ATTRIBUTE_NAME: Final[str] = r"^[a-zA-Z][a-zA-Z0-9-]*$"
        ATTRIBUTE_OPTION: Final[str] = r";[a-zA-Z][a-zA-Z0-9-]*"

        # OID patterns
        OID_NUMERIC: Final[str] = r"^\d+(\.\d+)*$"
        OID_DESCRIPTOR: Final[str] = r"^[a-zA-Z][a-zA-Z0-9-]*$"

        # Schema parsing patterns
        SCHEMA_OID: Final[str] = r"^\s*\(\s*([\d.]+)"
        SCHEMA_NAME: Final[str] = r"NAME\s+\(?\s*'([^']+)'"
        SCHEMA_DESC: Final[str] = r"DESC\s+'([^']+)'"
        SCHEMA_SYNTAX: Final[str] = r"SYNTAX\s+([\d.]+)"
        SCHEMA_EQUALITY: Final[str] = r"EQUALITY\s+([^\s)]+)"
        SCHEMA_SINGLE_VALUE: Final[str] = r"\bSINGLE-VALUE\b"
        SCHEMA_SUP: Final[str] = r"SUP\s+(\w+)"
        SCHEMA_MUST: Final[str] = r"MUST\s+\(([^)]+)\)"
        SCHEMA_MAY: Final[str] = r"MAY\s+\(([^)]+)\)"

        # Oracle OID/OUD patterns
        ORACLE_OID_PATTERN: Final[str] = r"\b1\.2\.840\.113556\."
        ORACLE_OUD_PATTERN: Final[str] = r"\boracle[_-]?oud\b"

        # OpenLDAP patterns
        OPENLDAP_OLC: Final[str] = r"\bolc[A-Z][a-zA-Z]+\b"
        OPENLDAP_CONFIG_DN: Final[str] = r"\bcn=config\b"

        # Active Directory patterns
        AD_OID: Final[str] = r"\b1\.2\.840\.113556\."
        AD_ATTRIBUTE: Final[str] = r"\b(samAccountName|objectGUID|objectSid)\b"

        # URL patterns
        URL_SCHEME: Final[str] = r"^(https?|ldaps?)://"
        URL_FULL: Final[str] = r"^(https?|ldap)://[^\s/$.?#].[^\s]*$"

        # Base64 detection
        BASE64_CHARS: Final[str] = r"^[A-Za-z0-9+/=\s]+$"

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

        ZERO TOLERANCE: All validation logic constants MUST be defined here.
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


__all__ = [
    "FlextLdifConstants",
]
