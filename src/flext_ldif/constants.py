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
from typing import Final

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
        MAX_LINE_LENGTH: Final[int] = 78
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

    class Processing:
        """Processing behavior configuration constants."""

        MIN_WORKERS_FOR_PARALLEL: Final[int] = 2
        MAX_WORKERS_LIMIT: Final[int] = 16  # Maximum allowed workers
        PERFORMANCE_MIN_WORKERS: Final[int] = (
            4  # Minimum workers for performance optimization
        )
        PERFORMANCE_MIN_CHUNK_SIZE: Final[int] = (
            1000  # Minimum chunk size for performance
        )
        MIN_ANALYTICS_CACHE_SIZE: Final[int] = 100
        MAX_ANALYTICS_CACHE_SIZE: Final[int] = 10000
        MIN_PRODUCTION_ENTRIES: Final[int] = 1000
        MIN_MEMORY_MB: Final[int] = 64  # Minimum memory limit in MB
        ENCODING_CONFIDENCE_THRESHOLD: Final[float] = (
            0.7  # Minimum confidence for encoding detection
        )

        DEFAULT_BATCH_SIZE: Final[int] = 100
        MAX_BATCH_SIZE: Final[int] = 10000

        # Additional constants for config validation
        PERFORMANCE_MEMORY_MB_THRESHOLD: Final[int] = (
            512  # Memory threshold for performance
        )
        DEBUG_MAX_WORKERS: Final[int] = 2  # Max workers in debug mode
        SMALL_ENTRY_COUNT_THRESHOLD: Final[int] = (
            100  # Threshold for small entry counts
        )
        MEDIUM_ENTRY_COUNT_THRESHOLD: Final[int] = (
            1000  # Threshold for medium entry counts
        )
        MIN_ATTRIBUTE_PARTS: Final[int] = 2  # Minimum parts for attribute parsing

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

    # =============================================================================
    # ENCODING CONSTANTS
    # =============================================================================

    class Encoding:
        """Character encoding constants for LDIF processing."""

        UTF8: Final[str] = "utf-8"
        LATIN1: Final[str] = "latin-1"
        ASCII: Final[str] = "ascii"
        DEFAULT_ENCODING: Final[str] = UTF8

        # Supported encodings for LDIF processing
        SUPPORTED_ENCODINGS: Final[frozenset[str]] = frozenset([
            UTF8,
            LATIN1,
            ASCII,
            "utf-16",
            "utf-32",
            "cp1252",
            "iso-8859-1",
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


__all__ = [
    "FlextLdifConstants",
]
