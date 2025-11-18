"""LDIF constants and enumerations.

This module defines constant values and enumerations used throughout the
LDIF library. Types, protocols, and models are defined in separate modules.

ACL Attribute Detection Strategy
================================
Uses HIERARCHY pattern with RFC foundation + server quirks
- RFC Foundation: aci, acl, olcAccess (all LDAP servers)
- Server Quirks: Added per server type (OID, OUD, AD)
- Override: categorization_rules parameter can override completely

This allows:
1. Auto-detection: acl_attrs = AclAttributeRegistry.get_acl_attributes("oid")
2. Override: acl_attrs = categorization_rules["acl_attributes"]
3. Type-safe: AclAttributeRegistry.is_acl_attribute(attr, "oud")

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

    # NOTE: ORACLE_OID_NAMESPACE removed - server-specific constants belong in quirks
    # OID-specific constants should be defined in src/flext_ldif/servers/oid.py

    # NOTE: LdapServerType removed - use ServerTypes instead (canonical source)
    # LdapServerType was duplicate of ServerTypeEnum - consolidated to ServerTypes

    class SortStrategy(StrEnum):
        """Valid sorting strategies for LDIF entries (V2 type-safe enum)."""

        HIERARCHY = "hierarchy"
        DN = "dn"
        ALPHABETICAL = "alphabetical"
        SCHEMA = "schema"
        CUSTOM = "custom"

    class SortTarget(StrEnum):
        """What to sort in LDIF data (V2 type-safe enum)."""

        ENTRIES = "entries"
        ATTRIBUTES = "attributes"
        ACL = "acl"
        SCHEMA = "schema"
        COMBINED = "combined"

    # ===== RFC 4876 ACL PERMISSION ENUMS (Type-Safe) =====
    class RfcAclPermission(StrEnum):
        """RFC 4876 standard ACL permissions (type-safe enum).

        Base permissions supported by all RFC-compliant LDAP servers.
        Server-specific extensions defined in respective server Constants classes:
        - OUD: FlextLdifServersOud.Constants.OudPermission
        - Other servers: Check respective server Constants classes
        """

        READ = "read"
        WRITE = "write"
        ADD = "add"
        DELETE = "delete"
        SEARCH = "search"
        COMPARE = "compare"
        ALL = "all"
        NONE = "none"

    # ===== CHARACTER ENCODING ENUMS (Type-Safe) =====
    class Encoding(StrEnum):
        """Standard character encodings used in LDIF processing.

        Maps to Python codec names for encoding/decoding operations.
        Server-specific encodings (if any) defined in respective server Constants.
        """

        UTF8 = "utf-8"
        UTF16LE = "utf-16-le"
        UTF16 = "utf-16"
        UTF32 = "utf-32"
        ASCII = "ascii"
        LATIN1 = "latin-1"
        CP1252 = "cp1252"
        ISO8859_1 = "iso-8859-1"

    # Encoding constants (referenced by tests and code)
    DEFAULT_ENCODING: Final[str] = "utf-8"
    SUPPORTED_ENCODINGS: Final[frozenset[str]] = frozenset({
        "utf-8",
        "utf-16-le",
        "utf-16",
        "utf-32",
        "ascii",
        "latin-1",
        "cp1252",
        "iso-8859-1",
    })

    # ===== RFC 2849 LDIF FORMAT CONSTANTS =====
    class LdifFormat(StrEnum):
        """RFC 2849 LDIF format indicators for attribute value encoding.

        - REGULAR: Single colon (:) for regular text values
        - BASE64: Double colon (::) for base64-encoded values (UTF-8, binary, special chars)
        - URL: Less than and colon (:<) for URL-referenced values

        Per RFC 2849 Section 2:
        - Use :: when value contains non-ASCII, leading/trailing space, or special chars
        - Base64 encoding preserves exact byte sequence for round-trip
        """

        REGULAR = ":"
        BASE64 = "::"
        URL = ":<"

    # LDIF format detection constants
    LDIF_BASE64_INDICATOR: Final[str] = "::"
    LDIF_REGULAR_INDICATOR: Final[str] = ":"
    LDIF_URL_INDICATOR: Final[str] = ":<"
    LDIF_DEFAULT_ENCODING: Final[str] = "utf-8"

    # ===== ACL SUBJECT TYPE ENUMS (Type-Safe) =====
    class AclSubjectType(StrEnum):
        """ACL subject/who types for permission subjects.

        Identifies what entity the ACL permission applies to.
        Server-specific extensions in respective server Constants.
        """

        USER = "user"
        GROUP = "group"
        ROLE = "role"
        SELF = "self"
        ALL = "all"
        PUBLIC = "public"
        ANONYMOUS = "anonymous"
        AUTHENTICATED = "authenticated"
        DN = "dn"

    class DictKeys:
        """Dictionary keys for LDIF entry data access - CORE KEYS ONLY per SRP.

        IMPORTANT: This class contains ONLY core LDIF/entry keys.
        Server-specific keys → QuirkMetadataKeys
        ACL keys → AclKeys
        """

        # Core entry and LDIF keys (63+ usages)
        DN: Final[str] = "dn"
        ATTRIBUTES: Final[str] = "attributes"
        OBJECTCLASS: Final[str] = "objectClass"
        CN: Final[str] = "cn"
        OID: Final[str] = "oid"

        # NOTE: Removed server-specific keys (use QuirkMetadataKeys instead):
        # SERVER_TYPE, IS_CONFIG_ENTRY, IS_TRADITIONAL_DIT

        # NOTE: Removed ACL keys (use AclKeys instead):
        # ACL_ATTRIBUTE, ACI, ACCESS, OLCACCESS, NTSECURITYDESCRIPTOR, HAS_OID_ACLS

        # NOTE: Removed service keys (use local constants in respective modules):
        # SERVICE_NAMES, INITIALIZED, DATA

    class QuirkMetadataKeys:
        """Dictionary keys for quirk metadata and server-specific entry properties.

        Used in Entry.metadata.extensions for server-specific attributes.
        Consolidates server-specific entry properties per SRP.
        """

        # Quirk metadata keys (20 usages across server quirks)
        SERVER_TYPE: Final[str] = "server_type"
        IS_CONFIG_ENTRY: Final[str] = "is_config_entry"
        IS_TRADITIONAL_DIT: Final[str] = "is_traditional_dit"

    class AclKeys:
        """Dictionary keys for ACL-related attributes and operations.

        Used in ACL parsing, writing, and entry processing across server quirks.
        Consolidates ACL-specific keys per SRP.
        """

        # ACL attribute keys (11 usages across server ACL quirks)
        ACL_ATTRIBUTE: Final[str] = "acl"
        ACI: Final[str] = "aci"
        ACCESS: Final[str] = "access"
        # NOTE: Server-specific ACL attributes moved to their Constants:
        # - OLCACCESS → FlextLdifServersOpenldap.Constants.ACL_ATTRIBUTE_NAME
        # - NTSECURITYDESCRIPTOR → FlextLdifServersAd.Constants.ACL_ATTRIBUTE_NAME

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

    # Text and Binary Processing constants (RFC 2849 § 2)
    ASCII_SPACE_CHAR: Final[int] = 32  # ASCII code for space (first printable char)
    ASCII_TILDE_CHAR: Final[int] = 126  # ASCII code for tilde (last printable char)
    DN_TRUNCATE_LENGTH: Final[int] = 100  # Maximum DN length for error messages
    DN_LOG_PREVIEW_LENGTH: Final[int] = 80  # DN preview length in logging

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
        LDIF_SERVER_SPECIFICS: Final[bool] = True
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

        # Attribute name constraints (RFC 4512 - max 127 chars)
        MIN_ATTRIBUTE_NAME_LENGTH: Final[int] = 1
        MAX_ATTRIBUTE_NAME_LENGTH: Final[int] = 127
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

    class RfcBinaryAttributes:
        """RFC 4517 Binary attribute names that typically require ;binary option.

        These attributes are defined as binary in LDAP schemas and SHOULD use
        the ;binary transfer option when transmitted in LDIF format (RFC 4522).

        Common binary attributes from RFC standards and practical LDAP usage.
        """

        # RFC 4523 - X.509 Certificate attributes
        USER_CERTIFICATE: Final[str] = "usercertificate"
        CA_CERTIFICATE: Final[str] = "cacertificate"
        CERTIFICATE_REVOCATION_LIST: Final[str] = "certificaterevocationlist"
        AUTHORITY_REVOCATION_LIST: Final[str] = "authorityrevocationlist"
        CROSS_CERTIFICATE_PAIR: Final[str] = "crosscertificatepair"

        # RFC 4524 - Common multimedia attributes
        PHOTO: Final[str] = "photo"
        JPEG_PHOTO: Final[str] = "jpegphoto"
        AUDIO: Final[str] = "audio"

        # PKCS#12 and other security attributes
        USER_PKCS12: Final[str] = "userpkcs12"
        USER_SMIME_CERTIFICATE: Final[str] = "usersmimecertificate"

        # Microsoft Active Directory binary attributes
        THUMBNAIL_PHOTO: Final[str] = "thumbnailphoto"
        THUMBNAIL_LOGO: Final[str] = "thumbnaillogo"
        OBJECT_GUID: Final[str] = "objectguid"
        OBJECT_SID: Final[str] = "objectsid"

        # Convenience set for validation
        BINARY_ATTRIBUTE_NAMES: Final[frozenset[str]] = frozenset([
            USER_CERTIFICATE,
            CA_CERTIFICATE,
            CERTIFICATE_REVOCATION_LIST,
            AUTHORITY_REVOCATION_LIST,
            CROSS_CERTIFICATE_PAIR,
            PHOTO,
            JPEG_PHOTO,
            AUDIO,
            USER_PKCS12,
            USER_SMIME_CERTIFICATE,
            THUMBNAIL_PHOTO,
            THUMBNAIL_LOGO,
            OBJECT_GUID,
            OBJECT_SID,
        ])

    class ServerValidationRules:
        """Server-specific validation rules for Entry model validators.

        Defines how different LDAP servers handle RFC compliance variations.
        Used by Entry.validate_entry_consistency to apply server-specific rules
        while maintaining RFC baseline.

        Design Pattern: RFC baseline + server-specific extensions
        - All servers get RFC validation
        - Server-specific rules add/modify checks based on server_type
        - Violations captured in metadata for round-trip conversions
        """

        # =============================================================================
        # OBJECTCLASS REQUIREMENTS
        # =============================================================================

        # Servers that REQUIRE objectClass attribute (stricter than RFC SHOULD)
        OBJECTCLASS_REQUIRED_SERVERS: Final[frozenset[str]] = frozenset([
            "oud",  # Oracle Unified Directory - strict schema enforcement
            "ad",  # Active Directory - requires objectClass for all entries
        ])

        # Servers that allow missing objectClass (lenient mode)
        OBJECTCLASS_OPTIONAL_SERVERS: Final[frozenset[str]] = frozenset([
            "oid",  # Oracle Internet Directory - allows schema-less entries
            "openldap",  # OpenLDAP - flexible objectClass handling
            "openldap1",  # OpenLDAP 1.x - legacy lenient mode
            "relaxed",  # Relaxed mode - best-effort parsing
        ])

        # =============================================================================
        # SCHEMA ENTRY DETECTION PATTERNS
        # =============================================================================

        # Schema entry DN patterns per server (case-insensitive)
        SCHEMA_ENTRY_PATTERNS: Final[dict[str, list[str]]] = {
            "rfc": ["cn=schema"],  # RFC 4512 standard
            "oid": ["cn=schema", "cn=subschema"],  # OID uses both
            "oud": ["cn=schema"],  # OUD follows RFC
            "openldap": ["cn=schema", "cn=subschema"],  # OpenLDAP flexible
            "openldap1": ["cn=schema"],  # OpenLDAP 1.x
            "ad": ["cn=schema", "cn=aggregate"],  # AD schema container
            "389ds": ["cn=schema"],  # 389 DS
            "apache_directory": ["ou=schema"],  # Apache DS uses ou=schema
            "novell_edirectory": ["cn=schema"],  # Novell
            "ibm_tivoli": ["cn=schema"],  # IBM Tivoli
            "relaxed": ["cn=schema", "cn=subschema", "ou=schema"],  # Accept all
        }

        # =============================================================================
        # NAMING ATTRIBUTE (RDN) REQUIREMENTS
        # =============================================================================

        # Servers that REQUIRE naming attribute in entry (stricter than RFC SHOULD)
        NAMING_ATTR_REQUIRED_SERVERS: Final[frozenset[str]] = frozenset([
            "oud",  # OUD enforces naming attribute presence
            "ad",  # AD requires RDN attribute in entry
        ])

        # Servers that allow missing naming attribute (lenient mode)
        NAMING_ATTR_OPTIONAL_SERVERS: Final[frozenset[str]] = frozenset([
            "oid",  # OID allows missing RDN attribute
            "openldap",  # OpenLDAP flexible
            "openldap1",  # OpenLDAP 1.x legacy
            "relaxed",  # Relaxed mode
        ])

        # =============================================================================
        # BINARY ATTRIBUTE HANDLING
        # =============================================================================

        # Servers that REQUIRE ;binary option for binary attributes
        BINARY_OPTION_REQUIRED_SERVERS: Final[frozenset[str]] = frozenset([
            "oud",  # OUD strict ;binary enforcement
            "openldap",  # OpenLDAP 2.x requires ;binary
        ])

        # Servers that make ;binary optional (auto-detect or lenient)
        BINARY_OPTION_OPTIONAL_SERVERS: Final[frozenset[str]] = frozenset([
            "oid",  # OID auto-detects binary
            "openldap1",  # OpenLDAP 1.x no ;binary support
            "ad",  # AD auto-detects binary attributes
            "relaxed",  # Relaxed mode
        ])

        # Server-specific binary attributes (in addition to RFC standard)
        SERVER_BINARY_ATTRIBUTES: Final[dict[str, frozenset[str]]] = {
            "oid": frozenset([
                "orclguid",  # Oracle GUID
                "userpassword",  # OID may store binary passwords
            ]),
            "oud": frozenset([
                "ds-sync-hist",  # OUD synchronization history
                "ds-sync-state",  # OUD sync state
            ]),
            "ad": frozenset([
                "objectguid",  # AD GUID (already in RFC list but emphasizing)
                "objectsid",  # AD Security ID
                "msexchmailboxguid",  # Exchange mailbox GUID
                "msexchmailboxsecuritydescriptor",  # Exchange security
            ]),
            "openldap": frozenset([
                "entryuuid",  # OpenLDAP entry UUID (binary format)
            ]),
        }

        # =============================================================================
        # SPECIAL ATTRIBUTES PER SERVER
        # =============================================================================

        # Operational attributes that may be missing and should not trigger warnings
        OPERATIONAL_ATTRIBUTES: Final[dict[str, frozenset[str]]] = {
            "oid": frozenset([
                "orclguid",
                "createtimestamp",
                "modifytimestamp",
                "creatorsname",
                "modifiersname",
            ]),
            "oud": frozenset([
                "entryuuid",
                "ds-sync-generation-id",
                "ds-sync-state",
                "createtimestamp",
                "modifytimestamp",
            ]),
            "ad": frozenset([
                "objectguid",
                "objectsid",
                "whencreated",
                "whenchanged",
                "usnchanged",
                "usncreated",
            ]),
            "openldap": frozenset([
                "entryuuid",
                "entrycsn",
                "createtimestamp",
                "modifytimestamp",
                "creatorsname",
                "modifiersname",
            ]),
        }

    # NOTE: ErrorMessages class removed (removed unused error message constants)
    # Error messages are now defined in appropriate validation modules

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

    # ═══════════════════════════════════════════════════════════════════════
    # STATISTICS TRACKING ENUMS (For EntryStatistics & DNStatistics models)
    # ═══════════════════════════════════════════════════════════════════════

    class TransformationType(StrEnum):
        """Types of transformations applied to entries.

        Used in EntryStatistics to track what conversions were applied.
        Follows FLEXT pattern of using constants instead of hard-coded strings.
        """

        # DN transformations
        DN_CLEANED = "dn_cleaned"
        DN_NORMALIZED = "dn_normalized"
        TAB_NORMALIZED = "tab_normalized"
        SPACE_CLEANED = "space_cleaned"
        UTF8_DECODED = "utf8_decoded"
        BASE64_DECODED = "base64_decoded"
        TRAILING_SPACE_REMOVED = "trailing_space_removed"
        ESCAPE_NORMALIZED = "escape_normalized"

        # Attribute transformations
        BOOLEAN_CONVERTED = "boolean_converted"
        ACL_CONVERTED = "acl_converted"
        ATTRIBUTE_REMOVED = "attribute_removed"
        ATTRIBUTE_ADDED = "attribute_added"
        ATTRIBUTE_RENAMED = "attribute_renamed"

        # Schema transformations
        MATCHING_RULE_REPLACED = "matching_rule_replaced"
        SYNTAX_OID_REPLACED = "syntax_oid_replaced"
        OBJECTCLASS_FILTERED = "objectclass_filtered"

    class FilterType(StrEnum):
        """Types of filters applied to entries.

        Used in EntryStatistics to track filtering decisions.
        """

        BASE_DN_FILTER = "base_dn_filter"
        SCHEMA_WHITELIST = "schema_whitelist"
        FORBIDDEN_ATTRIBUTES = "forbidden_attributes"
        FORBIDDEN_OBJECTCLASSES = "forbidden_objectclasses"
        OPERATIONAL_ATTRIBUTES = "operational_attributes"
        ACL_EXTRACTION = "acl_extraction"
        SCHEMA_ENTRY = "schema_entry"

    class ValidationStatus(StrEnum):
        """Entry validation status levels.

        Used in EntryStatistics to indicate validation result.
        """

        VALID = "valid"
        WARNING = "warning"
        ERROR = "error"
        REJECTED = "rejected"

    class RejectionCategory(StrEnum):
        """Categories for entry rejection.

        Used in EntryStatistics to classify why entry was rejected.
        """

        INVALID_DN = "invalid_dn"
        BASE_DN_FILTER = "base_dn_filter"
        SCHEMA_VIOLATION = "schema_violation"
        FORBIDDEN_ATTRIBUTE = "forbidden_attribute"
        FORBIDDEN_OBJECTCLASS = "forbidden_objectclass"
        CATEGORIZATION_FAILED = "categorization_failed"
        NO_CATEGORY_MATCH = "no_category_match"
        PARSING_ERROR = "parsing_error"
        CONVERSION_ERROR = "conversion_error"

    class ErrorCategory(StrEnum):
        """Categories of errors that can occur during processing.

        Used in EntryStatistics to categorize errors.
        """

        PARSING = "parsing"
        VALIDATION = "validation"
        CONVERSION = "conversion"
        SYNC = "sync"
        SCHEMA = "schema"
        ACL = "acl"
        MODRDN = "modrdn"

    # NOTE: ServerTypeEnum removed - use ServerTypes instead (canonical source)
    # ServerTypeEnum was duplicate of LdapServerType - consolidated to ServerTypes

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

        # NOTE: SERVER_TYPES removed - use ServerTypes class for identifiers
        # All server types (short forms: oid, oud, openldap, etc.) in ServerTypes

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
        type MigrationMode = Literal["simple", "categorized", "structured"]
        type ParserInputSource = Literal["string", "file", "ldap3"]
        type WriterOutputTarget = Literal["string", "file", "ldap3", "model"]
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

        # NOTE: Server-specific DN patterns, attributes, and object classes have been migrated:
        # - AD_DN_PATTERNS → FlextLdifServersAd.Constants.AD_DN_PATTERNS
        # - AD_REQUIRED_CLASSES → FlextLdifServersAd.Constants.AD_REQUIRED_CLASSES
        # - OPENLDAP_DN_PATTERNS → FlextLdifServersOpenldap.Constants.OPENLDAP_DN_PATTERNS
        # - OPENLDAP_2_ATTRIBUTES → FlextLdifServersOpenldap.Constants.OPENLDAP_2_ATTRIBUTES
        # - OPENLDAP_2_DN_PATTERNS → FlextLdifServersOpenldap.Constants.OPENLDAP_2_DN_PATTERNS
        # - OPENLDAP_1_ATTRIBUTES → FlextLdifServersOpenldap1.Constants.OPENLDAP_1_ATTRIBUTES
        # - OPENLDAP_REQUIRED_CLASSES → (if needed, add to FlextLdifServersOpenldap.Constants)
        # All server-specific constants should be defined in their respective server Constants classes

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
        """ACL-related constants - RFC 4876 baseline ONLY.

        NOTE: Extended permissions (OUD SELF_WRITE, PROXY, etc.) moved to server-specific Constants.
        """

        # ACL operation types
        GRANT: Final[str] = "grant"
        DENY: Final[str] = "deny"
        ALLOW: Final[str] = "allow"

        # ACL scope types
        SUBTREE: Final[str] = "subtree"
        ONELEVEL: Final[str] = "onelevel"
        BASE: Final[str] = "base"

        # RFC 4876 ACL permissions (baseline only - no extensions)
        READ: Final[str] = "read"
        WRITE: Final[str] = "write"
        SEARCH: Final[str] = "search"
        COMPARE: Final[str] = "compare"
        ADD: Final[str] = "add"
        DELETE: Final[str] = "delete"
        MODIFY: Final[str] = "modify"

        # Extended permissions (used by OID, OUD, etc.)
        # NOTE: Also defined in server-specific Constants for server-specific use
        SELF_WRITE: Final[str] = "self_write"
        PROXY: Final[str] = "proxy"

        # NOTE: Server-specific permissions may have additional definitions:
        # - SELF_WRITE variations in FlextLdifServersOud.Constants.OudPermission
        # - PROXY variations in FlextLdifServersOud.Constants.OudPermission
        # - BROWSE → Server-specific Constants
        # NOTE: Novell ACL parsing indices migrated to FlextLdifServersNovell.Constants:
        # - NOVELL_SEGMENT_INDEX_TRUSTEE → FlextLdifServersNovell.Constants.NOVELL_SEGMENT_INDEX_TRUSTEE
        # - NOVELL_SEGMENT_INDEX_RIGHTS → FlextLdifServersNovell.Constants.NOVELL_SEGMENT_INDEX_RIGHTS

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

        # NOTE: Server-specific operational attributes have been migrated to their respective server Constants classes:
        # - OID_SPECIFIC → FlextLdifServersOid.Constants.OPERATIONAL_ATTRIBUTES
        # - OID_BOOLEAN_ATTRIBUTES → FlextLdifServersOid.Constants.BOOLEAN_ATTRIBUTES
        # - OUD_SPECIFIC → FlextLdifServersOud.Constants.OPERATIONAL_ATTRIBUTES
        # - OPENLDAP_SPECIFIC → FlextLdifServersOpenldap.Constants.OPERATIONAL_ATTRIBUTES
        # - DS_389_SPECIFIC → FlextLdifServersDs389.Constants.OPERATIONAL_ATTRIBUTES / DS_389_SPECIFIC
        # - AD_SPECIFIC → FlextLdifServersAd.Constants.OPERATIONAL_ATTRIBUTES
        # - NOVELL_SPECIFIC → FlextLdifServersNovell.Constants.OPERATIONAL_ATTRIBUTES / NOVELL_SPECIFIC
        # - IBM_TIVOLI_SPECIFIC → FlextLdifServersTivoli.Constants.OPERATIONAL_ATTRIBUTES / IBM_TIVOLI_SPECIFIC
        # All server-specific constants should be defined in their respective server Constants classes

        # Common operational attributes to filter from ALL entries
        # These are always filtered regardless of entry type
        FILTER_FROM_ALL_ENTRIES: Final[frozenset[str]] = frozenset([
            "createtimestamp",
            "creatorsname",
            "modifytimestamp",
            "modifiersname",
            "entrycsn",
            "entryuuid",
            "structuralobjectclass",
            "hassubordinates",
            "numsubordinates",
            "subordinatecount",
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
        """RFC baseline ACL attribute names for LDAP.

        Consolidates RFC-standard ACL attributes for universal detection.
        Server-specific ACL attributes defined in respective server Constants classes:
        - OID: ORCLACI, ORCL_ENTRY_LEVEL_ACI → FlextLdifServersOid.Constants
        - AD: nTSecurityDescriptor → FlextLdifServersAd.Constants
        - Apache DS: ads-aci → FlextLdifServersApache.Constants
        - Tivoli: ibm-slapdaccesscontrol → FlextLdifServersTivoli.Constants
        - Other servers: Check respective server Constants classes
        """

        # RFC 4876 standard
        ACI: Final[str] = "aci"  # RFC 4876 ACI attribute (OUD, 389 DS standard)

        # Common ACL-related attributes for filtering
        ACLRIGHTS: Final[str] = "aclrights"  # Generic ACL rights attribute
        ACLENTRY: Final[str] = "aclentry"  # Generic ACL entry attribute

        # Set of RFC baseline ACL attributes for quick membership testing
        # NOTE: Server-specific attributes (e.g., orclaci, nTSecurityDescriptor, ads-aci)
        # are defined in their respective server Constants classes
        ALL_ACL_ATTRIBUTES: Final[frozenset[str]] = frozenset([
            ACI,  # RFC 4876 standard (OUD, 389 DS)
            ACLRIGHTS,
            ACLENTRY,
            # Server-specific attributes moved to respective Constants:
            # - "olcAccess" (OpenLDAP) → FlextLdifServersOpenldap.Constants
            # - "orclaci", "orclentrylevelaci" (OID) → FlextLdifServersOid.Constants
            # - "nTSecurityDescriptor" (AD) → FlextLdifServersAd.Constants
            # - "ads-aci" (Apache DS) → FlextLdifServersApache.Constants
            # - "ibm-slapdaccesscontrol" (Tivoli) → FlextLdifServersTivoli.Constants
            # - Custom ACL attributes (various) → Respective server Constants
        ])

        # ACL attributes to filter/detect during migration
        # NOTE: All values commented, list empty - add as needed
        FILTER_ACL_ATTRIBUTES: Final[frozenset[str]] = frozenset([
            # "aci",
            # "orclaci",
            # "aclrights",
            # "aclentry",
        ])

        # NOTE: Server-specific ACL attribute sets should be defined in
        # their respective server Constants classes:
        # - OID: FlextLdifServersOid.Constants.ORCLACI, ORCL_ENTRY_LEVEL_ACI
        # - OUD: FlextLdifServersOud.Constants.ACL_ATTRIBUTE_NAME ("aci")
        # - OpenLDAP: FlextLdifServersOpenldap.Constants.ACL_ATTRIBUTE_NAME ("olcAccess")

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
        """RFC 4876 ACL permission type identifiers (magic strings).

        DEPRECATED: Use FlextLdifConstants.RfcAclPermission (StrEnum) instead for type safety.
        This class maintained for backward compatibility only.

        Standard LDAP ACL permissions (RFC baseline).
        Server-specific permissions defined in respective server Constants classes:
        - OUD: FlextLdifServersOud.Constants.OudPermission
        - OID: FlextLdifServersOid.Constants (if any extensions)
        - Others: Server-specific Constants classes

        Note: These are different from actions (add/delete/modify in changetype).
        """

        # Standard LDAP ACL permissions (RFC 4876)
        READ: Final[str] = "read"
        WRITE: Final[str] = "write"
        ADD: Final[str] = "add"
        DELETE: Final[str] = "delete"
        SEARCH: Final[str] = "search"
        COMPARE: Final[str] = "compare"
        ALL: Final[str] = "all"
        NONE: Final[str] = "none"

        # NOTE: Server-specific permissions migrated to respective Constants classes:
        # - SELF_WRITE (OUD) → FlextLdifServersOud.Constants.OudPermission.SELF_WRITE
        # - SELFWRITE (Oracle) → FlextLdifServersOud.Constants.OudPermission.SELFWRITE
        # - PROXY (OUD/OID) → FlextLdifServersOud.Constants.OudPermission.PROXY
        # - BROWSE → Server-specific Constants
        # NOTE: PERMISSION_MAPPINGS migrated to server-specific Constants classes
        # - OUD mappings → FlextLdifServersOud.Constants.PERMISSION_NORMALIZATION_MAP
        # - Other mappings → Respective server Constants

        # All permission names for validation (RFC baseline only)
        ALL_PERMISSIONS: Final[frozenset[str]] = frozenset([
            READ,
            WRITE,
            ADD,
            DELETE,
            SEARCH,
            COMPARE,
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
        - Legacy formats: "true" / "false", "yes" / "no"

        Zero Tolerance: Boolean conversions MUST use these constants.
        DO NOT hard-code boolean strings like "TRUE" or "1" in servers/*.py

        NOTE: Server-specific boolean formats (e.g., Oracle OID "1"/"0") are defined
        in their respective server Constants classes:
        - OID: FlextLdifServersOid.Constants.ONE_OID, ZERO_OID, OID_TO_RFC, RFC_TO_OID
        - OUD: Uses RFC 4517 compliant format (TRUE/FALSE)
        """

        # RFC 4517 compliant (OUD, modern servers)
        TRUE_RFC: Final[str] = "TRUE"
        FALSE_RFC: Final[str] = "FALSE"

        # Legacy variants (case-insensitive)
        TRUE_LOWER: Final[str] = "true"
        FALSE_LOWER: Final[str] = "false"

        # Universal boolean check (RFC-compliant values only)
        RFC_TRUE_VALUES: Final[frozenset[str]] = frozenset([TRUE_RFC, TRUE_LOWER])
        RFC_FALSE_VALUES: Final[frozenset[str]] = frozenset([FALSE_RFC, FALSE_LOWER])

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
        SELF_WRITE_TO_WRITE: Final[str] = "self_write_to_write"
        # NOTE: OID metadata keys moved to FlextLdifServersOid.Constants:
        # - ORIGINAL_OID_PERMS → FlextLdifServersOid.Constants.ORIGINAL_OID_PERMS
        # - OID_SPECIFIC_RIGHTS → FlextLdifServersOid.Constants.OID_SPECIFIC_RIGHTS
        # - RFC_NORMALIZED → FlextLdifServersOid.Constants.RFC_NORMALIZED (generic RFC transformation tracking)
        # Server-specific metadata keys should be defined in their respective server Constants classes

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
        # Conversion/Migration Metadata
        # =========================

        CONVERTED_FROM_SERVER: Final[str] = (
            "converted_from_server"  # Source server type for conversion
        )
        CONVERSION_COMMENTS: Final[str] = (
            "conversion_comments"  # Comments about conversion process
        )
        ORIGINAL_ENTRY: Final[str] = (
            "original_entry"  # Original entry before conversion
        )
        REMOVED_ATTRIBUTES: Final[str] = (
            "removed_attributes"  # Attributes removed/commented during processing
        )
        REMOVED_ATTRIBUTES_WITH_VALUES: Final[str] = (
            "removed_attributes_with_values"  # Attributes with values for RFC writer
        )
        WRITE_OPTIONS: Final[str] = (
            "_write_options"  # Write format options for LDIF output
        )

        # =========================
        # All Metadata Keys Registry
        # =========================

        # NOTE: ALL_OID_KEYS moved to FlextLdifServersOid.Constants.ALL_OID_KEYS
        # Use FlextLdifServersOid.Constants for OID-specific metadata keys

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

        # NOTE: Oracle-specific DNs moved to FlextLdifServersOid.Constants:
        # - CN_ORCL → FlextLdifServersOid.Constants.CN_ORCL
        # - OU_ORACLE → FlextLdifServersOid.Constants.OU_ORACLE
        # - DC_ORACLE → FlextLdifServersOid.Constants.DC_ORACLE
        # - ORACLE_DN_PATTERNS → FlextLdifServersOid.Constants.ORACLE_DN_PATTERNS

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

        # NOTE: OpenLDAP config-specific patterns moved to server Constants:
        # - OLCDATABASE_PREFIX → FlextLdifServersOpenldap.Constants.OLCDATABASE_PREFIX
        # - OLCOVERLAY_PREFIX → FlextLdifServersOpenldap.Constants.OLCOVERLAY_PREFIX

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

        # NOTE: ORACLE_DN_PATTERNS moved to FlextLdifServersOid.Constants.ORACLE_DN_PATTERNS

    # =============================================================================
    # ACL FORMATS - ACL format identifiers
    # =============================================================================

    class AclFormats:
        """ACL format identifier constants.

        NOTE: Server-specific ACL formats are now defined in their respective server Constants classes.
        This class retains only generic/RFC ACL format constants.

        Server-specific constants location:
        - OID: FlextLdifServersOid.Constants.ACL_FORMAT ("orclaci")
        - OUD: FlextLdifServersOud.Constants.ACL_FORMAT ("aci")
        - OpenLDAP: FlextLdifServersOpenldap.Constants.ACL_FORMAT ("olcAccess")
        - OpenLDAP1: FlextLdifServersOpenldap1.Constants.ACL_FORMAT ("access")
        - AD: FlextLdifServersAd.Constants.ACL_FORMAT ("nTSecurityDescriptor")
        - DS389: FlextLdifServersDs389.Constants.ACL_FORMAT ("aci")
        - Apache: FlextLdifServersApache.Constants.ACL_FORMAT ("aci")
        - Novell: FlextLdifServersNovell.Constants.ACL_FORMAT ("aci")
        - Tivoli: FlextLdifServersTivoli.Constants.ACL_FORMAT ("aci")
        - RFC: FlextLdifServersRfc.Constants.ACL_FORMAT ("rfc_generic")
        - Relaxed: FlextLdifServersRelaxed.Constants.ACL_FORMAT ("rfc_generic")

        Use FlextLdifModels.Acl.get_acl_format() to get the correct ACL format for a server type.
        It automatically queries the server Constants via registry.
        """

        # Generic/RFC ACL formats (only generic constants remain)
        RFC_GENERIC: Final[str] = "rfc_generic"
        ACI: Final[str] = (
            "aci"  # RFC 4876 standard ACI attribute (used by multiple servers)
        )

        # RFC Baseline defaults (for core modules that cannot access services/*)
        DEFAULT_ACL_FORMAT: Final[str] = ACI
        DEFAULT_ACL_ATTRIBUTE_NAME: Final[str] = ACI

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

        # Backward compatibility aliases (deprecated, use OID/OUD instead)
        ORACLE_OID: Final[str] = OID  # Alias for backward compatibility
        ORACLE_OUD: Final[str] = OUD  # Alias for backward compatibility

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

        # Common short aliases (used in tests and user input)
        ALIASES: Final[dict[str, str]] = {
            "ad": AD,  # active_directory
            "ds389": DS_389,  # 389ds
            "389": DS_389,  # 389ds
            "apache": APACHE,  # apache_directory
            "novell": NOVELL,  # novell_edirectory
            "tivoli": IBM_TIVOLI,  # ibm_tivoli
            "oracle_oid": OID,  # backward compat
            "oracle_oud": OUD,  # backward compat
        }

        # Server type variants (for compatibility checks)
        ORACLE_OID_VARIANTS: Final[frozenset[str]] = frozenset(["oid", "oracle_oid"])
        ORACLE_OUD_VARIANTS: Final[frozenset[str]] = frozenset(["oud", "oracle_oud"])
        OPENLDAP_VARIANTS: Final[frozenset[str]] = frozenset([
            "openldap",
            "openldap1",
            "openldap2",
        ])

        @staticmethod
        def normalize(server_type: str) -> str:
            """Normalize server type aliases to canonical form.

            Converts aliases like 'oracle_oid' → 'oid', 'ad' → 'active_directory'.

            Handles:
            - Short aliases (ad → active_directory, ds389 → 389ds)
            - Long to short (oracle_oid → oid)
            - Already canonical forms (returns as-is)

            Args:
                server_type: Server type string (may be alias)

            Returns:
                Canonical server type

            Example:
                >>> ServerTypes.normalize("ad")
                'active_directory'
                >>> ServerTypes.normalize("oracle_oid")
                'oid'
                >>> ServerTypes.normalize("oid")
                'oid'

            """
            # First try short aliases (ad → active_directory)
            if server_type in FlextLdifConstants.ServerTypes.ALIASES:
                return FlextLdifConstants.ServerTypes.ALIASES[server_type]
            # Then try long to short (oracle_oid → oid)
            return FlextLdifConstants.ServerTypes.FROM_LONG.get(
                server_type,
                server_type,
            )

        @staticmethod
        def matches(server_type: str, *canonical_types: str) -> bool:
            """Check if server_type matches any of the canonical types (handles aliases).

            Args:
                server_type: Server type to check
                *canonical_types: Canonical type(s) to match against

            Returns:
                True if server_type (or its canonical form) matches any canonical_type

            Example:
                >>> ServerTypes.matches("oracle_oid", "oid", "oud")
                True
                >>> ServerTypes.matches("rfc", "oid", "oud")
                False

            """
            normalized = FlextLdifConstants.ServerTypes.normalize(server_type)
            return normalized in canonical_types or server_type in canonical_types

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

        # NOTE: OID_SPECIFIC_ATTRIBUTES moved to FlextLdifServersOid.Constants.OID_SPECIFIC_ATTRIBUTES
        # Server-specific attribute categorizations should be defined in their respective server Constants classes

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

        # =====================================================================
        # QUIRK OPERATION TYPES
        # =====================================================================
        type QuirkOperation = Literal["parse", "write"]
        type SchemaParseOperation = Literal["parse"]
        type AclWriteOperation = Literal["write"]

        # =====================================================================
        # SERVICE OPERATION TYPES
        # =====================================================================
        type ParserInputSource = Literal["string", "file", "ldap3"]
        type WriterOutputTarget = Literal["string", "file", "ldap3", "model"]

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

        # DN validation patterns (RFC 4514)
        # attribute=value where attribute starts with letter, value can be anything (including escaped chars)
        # This pattern ensures each component has both attribute and = sign
        # Full validation happens in DistinguishedName validator which parses escaped characters
        DN_COMPONENT: Final[str] = r"^[a-zA-Z][a-zA-Z0-9-]*=(?:[^\\,]|\\.)*$"
        DN_SEPARATOR: Final[str] = r"(?<!\\),"

        # LDAP filter pattern (RFC 4515)
        LDAP_FILTER: Final[str] = r"^\(.*\)$"

        # Object class name pattern (similar to attribute names but allowing uppercase)
        OBJECTCLASS_NAME: Final[str] = r"^[a-zA-Z][a-zA-Z0-9-]*$"

        # Attribute name patterns (RFC 4512 § 2.5)
        # Base attribute name: starts with letter, followed by letters/digits/hyphens
        ATTRIBUTE_NAME: Final[str] = r"^[a-zA-Z][a-zA-Z0-9-]*$"
        # RFC 4512 constraint: attribute names must not exceed 127 characters
        MAX_ATTRIBUTE_NAME_LENGTH: Final[int] = 127
        # Attribute option: RFC 4512 § 2.5 + RFC 3066 (language tags with underscore)
        # Examples: lang-ar, binary, lang-es_es (es_ES = Spanish Spain)
        ATTRIBUTE_OPTION: Final[str] = r";[a-zA-Z][a-zA-Z0-9-_]*"

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
        SCHEMA_NAME: Final[str] = r"(?i)NAME\s+\(?\s*'([^']+)'"
        SCHEMA_DESC: Final[str] = r"DESC\s+'([^']+)'"
        SCHEMA_SYNTAX: Final[str] = r"SYNTAX\s+([\d.]+)"
        SCHEMA_EQUALITY: Final[str] = r"EQUALITY\s+([^\s)]+)"
        SCHEMA_SUBSTR: Final[str] = r"SUBSTR\s+([^\s)]+)"
        SCHEMA_ORDERING: Final[str] = r"ORDERING\s+([^\s)]+)"
        SCHEMA_SUP: Final[str] = r"SUP\s+(\w+)"
        SCHEMA_USAGE: Final[str] = r"USAGE\s+(\w+)"
        SCHEMA_X_ORIGIN: Final[str] = r"X-ORIGIN\s+'([^']+)'"
        SCHEMA_SYNTAX_LENGTH: Final[str] = (
            r"SYNTAX\s+(?:')?([0-9.]+)(?:')?(?:\{(\d+)\})?"
        )
        SCHEMA_SINGLE_VALUE: Final[str] = r"\bSINGLE-VALUE\b"
        SCHEMA_COLLECTIVE: Final[str] = r"\bCOLLECTIVE\b"
        SCHEMA_NO_USER_MODIFICATION: Final[str] = r"\bNO-USER-MODIFICATION\b"
        SCHEMA_OBSOLETE: Final[str] = r"\bOBSOLETE\b"

        # ObjectClass specific schema parsing patterns
        SCHEMA_OBJECTCLASS_KIND: Final[str] = r"\b(ABSTRACT|STRUCTURAL|AUXILIARY)\b"
        SCHEMA_OBJECTCLASS_SUP: Final[str] = r"SUP\s+(?:\(\s*([^)]+)\s*\)|(\w+))"
        SCHEMA_OBJECTCLASS_MUST: Final[str] = r"MUST\s+(?:\(\s*([^)]+)\s*\)|(\w+))"
        SCHEMA_OBJECTCLASS_MAY: Final[str] = r"MAY\s+(?:\(\s*([^)]+)\s*\)|(\w+))"

        # Server detection patterns moved to ServerDetection class below

    # =============================================================================
    # SERVER DETECTION - Comprehensive server type detection patterns and weights
    # =============================================================================

    class ServerDetection:
        """Server type detection patterns and weights for LDIF content analysis.

        Comprehensive patterns for identifying LDAP server types from LDIF content.
        Higher weight values indicate more specific patterns.
        """

        # NOTE: Server-specific detection patterns have been moved to their respective server Constants classes:
        # - ORACLE_OID_PATTERN, ORACLE_OID_ATTRIBUTES, ORACLE_OID_WEIGHT → FlextLdifServersOid.Constants.DETECTION_*
        # - ORACLE_OUD_PATTERN, ORACLE_OUD_ATTRIBUTES, ORACLE_OUD_WEIGHT → FlextLdifServersOud.Constants.DETECTION_*
        # - OPENLDAP_PATTERN, OPENLDAP_ATTRIBUTES, OPENLDAP_WEIGHT → FlextLdifServersOpenldap.Constants.DETECTION_*
        # - ACTIVE_DIRECTORY_PATTERN, ACTIVE_DIRECTORY_ATTRIBUTES, ACTIVE_DIRECTORY_WEIGHT → FlextLdifServersAd.Constants.DETECTION_*
        # - NOVELL_EDIR_PATTERN, NOVELL_EDIR_WEIGHT → FlextLdifServersNovell.Constants.DETECTION_*
        # - IBM_TIVOLI_PATTERN, IBM_TIVOLI_WEIGHT → FlextLdifServersTivoli.Constants.DETECTION_*
        # - DS_389_PATTERN, DS_389_WEIGHT → FlextLdifServersDs389.Constants.DETECTION_*

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

        # NOTE: Server-specific detection constants migrated to their respective server Constants classes:
        # - AD: FlextLdifServersAd.Constants (DETECTION_OID_PATTERN, DETECTION_ATTRIBUTE_NAMES, DETECTION_OBJECTCLASS_NAMES, DETECTION_DN_MARKERS, DETECTION_ATTRIBUTE_MARKERS)
        # - Apache: FlextLdifServersApache.Constants (DETECTION_OID_PATTERN, DETECTION_ATTRIBUTE_PREFIXES, DETECTION_OBJECTCLASS_NAMES, DETECTION_DN_MARKERS)
        # - Novell: FlextLdifServersNovell.Constants (DETECTION_ATTRIBUTE_MARKERS, DETECTION_OBJECTCLASS_NAMES, DETECTION_DN_MARKERS)
        # - Tivoli: FlextLdifServersTivoli.Constants (DETECTION_ATTRIBUTE_MARKERS, DETECTION_OBJECTCLASS_NAMES, DETECTION_DN_MARKERS)
        # - OID: FlextLdifServersOid.Constants (DETECTION_OID_PATTERN, DETECTION_ATTRIBUTE_PREFIXES, DETECTION_OBJECTCLASS_NAMES, DETECTION_DN_MARKERS)
        # - OUD: FlextLdifServersOud.Constants (DETECTION_OID_PATTERN, DETECTION_ATTRIBUTE_PREFIXES, DETECTION_OBJECTCLASS_NAMES, DETECTION_DN_MARKERS)
        # - OpenLDAP: FlextLdifServersOpenldap.Constants (DETECTION_OID_PATTERN, DETECTION_ATTRIBUTE_PREFIXES, DETECTION_OBJECTCLASS_NAMES, DETECTION_DN_MARKERS)
        # - DS389: FlextLdifServersDs389.Constants (DETECTION_OID_PATTERN, DETECTION_ATTRIBUTE_PREFIXES, DETECTION_OBJECTCLASS_NAMES, DETECTION_DN_MARKERS)
        # All server-specific constants should be defined in their respective server Constants classes

    # =============================================================================
    # VALIDATION RULES - Validation logic constants
    # =============================================================================

    class ValidationRules:
        """Validation rule constants.

        Zero Tolerance: All validation logic constants MUST be defined here.
        NO hard-coded validation strings in validators.

        NOTE: Server-specific validation rules belong in servers/* modules,
        NOT here. This class contains only RFC-generic validation constants.
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

    class LdifFormatting:
        """LDIF formatting constants (line width, folding).

        Defines constants for LDIF formatting options including line width
        and other formatting preferences. Different from LdifFormat which
        defines RFC 2849 value indicators (::, :, :<).
        """

        # Default line width for LDIF folding (RFC 2849 recommends 76)
        DEFAULT_LINE_WIDTH: Final[int] = 76

        # Maximum allowed line width
        MAX_LINE_WIDTH: Final[int] = 1000

        # Minimum allowed line width
        MIN_LINE_WIDTH: Final[int] = 10

    class CommentFormats:
        """LDIF comment formatting constants for documentation.

        Provides standardized comment formats for documenting entry modifications,
        rejections, and transformations in LDIF output. These formats support
        bidirectional conversion and audit trails.
        """

        # Comment separator lines
        SEPARATOR_DOUBLE: Final[str] = "# " + ("═" * 51)
        SEPARATOR_SINGLE: Final[str] = "# " + ("─" * 51)
        SEPARATOR_EMPTY: Final[str] = "#"

        # Comment headers
        HEADER_REJECTION_REASON: Final[str] = "# REJECTION REASON"
        HEADER_REMOVED_ATTRIBUTES: Final[str] = "# REMOVED ATTRIBUTES (Original Values)"

        # Comment prefixes
        PREFIX_COMMENT: Final[str] = "# "

    class MigrationHeaders:
        """Migration header templates for LDIF output.

        Provides default templates for migration headers that can be customized
        via WriteFormatOptions.migration_header_template.
        """

        # Default migration header template (Python f-string format)
        DEFAULT_TEMPLATE: Final[str] = """# Migration Phase: {phase}
# Timestamp: {timestamp}
# Source Server: {source_server}
# Target Server: {target_server}
# Base DN: {base_dn}
# Total Entries: {total_entries}
# Processed: {processed_entries} ({processed_percentage:.1f}%)
# Rejected: {rejected_entries} ({rejected_percentage:.1f}%)
#
"""

        # Minimal header template
        MINIMAL_TEMPLATE: Final[
            str
        ] = """# Phase: {phase} | {timestamp} | Entries: {total_entries}
#
"""

        # Detailed header template
        DETAILED_TEMPLATE: Final[
            str
        ] = """# ============================================================================
# LDIF MIGRATION - {phase_name}
# ============================================================================
# Migration Phase: {phase}
# Timestamp: {timestamp}
#
# SOURCE & TARGET:
#   Source Server: {source_server}
#   Target Server: {target_server}
#   Base DN: {base_dn}
#
# STATISTICS:
#   Total Entries: {total_entries}
#   Processed: {processed_entries} ({processed_percentage:.1f}%)
#   Rejected: {rejected_entries} ({rejected_percentage:.1f}%)
#
# ============================================================================
#
"""

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

        **Conversion Strategy**:
        RFC is the universal intermediate format - no normalization/denormalization needed.
        All conversions use: Source → RFC (via source quirks) → Target (via target quirks).
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

        # NOTE: Server-specific ACL subject transformations moved to respective server Constants:
        # - OID_TO_RFC_SUBJECTS → FlextLdifServersOid.Constants.OID_TO_RFC_SUBJECTS
        # - RFC_TO_OID_SUBJECTS → FlextLdifServersOid.Constants.RFC_TO_OID_SUBJECTS
        # - RFC_TO_OUD_SUBJECTS → FlextLdifServersOud.Constants.RFC_TO_OUD_SUBJECTS
        # - OUD_TO_RFC_SUBJECTS → FlextLdifServersOud.Constants.OUD_TO_RFC_SUBJECTS

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

        NOTE: Server-specific constants (SUPPORTED_PERMISSIONS, PERMISSION_ALTERNATIVES)
        have been migrated to each server's Constants class:
        - OID: FlextLdifServersOid.Constants.SUPPORTED_PERMISSIONS, PERMISSION_ALTERNATIVES
        - OUD: FlextLdifServersOud.Constants.SUPPORTED_PERMISSIONS
        - RFC: FlextLdifServersRfc.Constants.SUPPORTED_PERMISSIONS
        - OpenLDAP: FlextLdifServersOpenldap.Constants.SUPPORTED_PERMISSIONS
        - AD: FlextLdifServersAd.Constants.SUPPORTED_PERMISSIONS
        - 389DS: FlextLdifServersDs389.Constants.SUPPORTED_PERMISSIONS
        - Novell: FlextLdifServersNovell.Constants.SUPPORTED_PERMISSIONS
        - Tivoli: FlextLdifServersTivoli.Constants.SUPPORTED_PERMISSIONS
        - Apache: FlextLdifServersApache.Constants.SUPPORTED_PERMISSIONS
        - OpenLDAP1: FlextLdifServersOpenldap1.Constants.SUPPORTED_PERMISSIONS

        This class is kept for backward compatibility but should not be used for new code.
        Use the server-specific Constants classes instead.
        """

    class SchemaConversionMappings:
        """Schema attribute and objectClass conversion mappings.

        Defines server-specific schema quirks and how to normalize/denormalize them.
        All mappings use RFC-as-hub strategy.
        """

        # NOTE: SERVER_SPECIFIC_ATTRIBUTE_FIELDS and OBJECTCLASS_KIND_REQUIREMENTS have been removed.
        # These constants have been migrated to each server's Constants class:
        # - ATTRIBUTE_FIELDS → Each server's Constants.ATTRIBUTE_FIELDS
        # - OBJECTCLASS_REQUIREMENTS → Each server's Constants.OBJECTCLASS_REQUIREMENTS
        # - OID: FlextLdifServersOid.Constants.ATTRIBUTE_FIELDS, OBJECTCLASS_REQUIREMENTS
        # - OUD: FlextLdifServersOud.Constants.ATTRIBUTE_FIELDS, OBJECTCLASS_REQUIREMENTS
        # - OpenLDAP: FlextLdifServersOpenldap.Constants.ATTRIBUTE_FIELDS, OBJECTCLASS_REQUIREMENTS
        # - 389DS: FlextLdifServersDs389.Constants.ATTRIBUTE_FIELDS, OBJECTCLASS_REQUIREMENTS
        # - RFC: FlextLdifServersRfc.Constants.ATTRIBUTE_FIELDS, OBJECTCLASS_REQUIREMENTS
        # - AD, Novell, Tivoli, Apache, OpenLDAP1: Inherit RFC baseline (empty ATTRIBUTE_FIELDS, RFC OBJECTCLASS_REQUIREMENTS)
        # Use the server-specific Constants classes instead.

        # Matching rule normalizations (moved from utilities)
        MATCHING_RULE_NORMALIZATIONS: Final[dict[str, str]] = {
            "caseIgnoreIA5SubstringsMatch": "caseIgnoreIA5Match",
            "caseIgnoreOrdinalMatch": "caseIgnoreMatch",
        }

        # NOTE: Server-specific attribute transformations moved to respective server Constants:
        # - ATTRIBUTE_TRANSFORMATION_OID_TO_RFC → FlextLdifServersOid.Constants.ATTRIBUTE_TRANSFORMATION_OID_TO_RFC
        # - ATTRIBUTE_TRANSFORMATION_RFC_TO_OID → FlextLdifServersOid.Constants.ATTRIBUTE_TRANSFORMATION_RFC_TO_OID
        # - ATTRIBUTE_TRANSFORMATION_RFC_TO_OUD → FlextLdifServersOud.Constants.ATTRIBUTE_TRANSFORMATION_RFC_TO_OUD
        # - ATTRIBUTE_TRANSFORMATION_OUD_TO_RFC → FlextLdifServersOud.Constants.ATTRIBUTE_TRANSFORMATION_OUD_TO_RFC

        # NOTE: Server-specific attribute aliases have been migrated to each server's Constants class:
        # - OID: FlextLdifServersOid.Constants.ATTRIBUTE_ALIASES
        # - OUD: FlextLdifServersOud.Constants.ATTRIBUTE_ALIASES
        # Other servers have empty ATTRIBUTE_ALIASES (use RFC standard)
        # This comment is kept for reference but the constant has been removed.

    # NOTE: OperationalAttributeMappings class has been removed.
    # Server-specific constants (OPERATIONAL_ATTRIBUTES, PRESERVE_ON_MIGRATION)
    # have been migrated to each server's Constants class:
    # - OID: FlextLdifServersOid.Constants.OPERATIONAL_ATTRIBUTES, PRESERVE_ON_MIGRATION
    # - OUD: FlextLdifServersOud.Constants.OPERATIONAL_ATTRIBUTES, PRESERVE_ON_MIGRATION
    # - RFC: FlextLdifServersRfc.Constants.OPERATIONAL_ATTRIBUTES, PRESERVE_ON_MIGRATION
    # - OpenLDAP: FlextLdifServersOpenldap.Constants.OPERATIONAL_ATTRIBUTES, PRESERVE_ON_MIGRATION
    # - AD: FlextLdifServersAd.Constants.OPERATIONAL_ATTRIBUTES, PRESERVE_ON_MIGRATION
    # - 389DS: FlextLdifServersDs389.Constants.OPERATIONAL_ATTRIBUTES, PRESERVE_ON_MIGRATION
    # - Novell: FlextLdifServersNovell.Constants.OPERATIONAL_ATTRIBUTES, PRESERVE_ON_MIGRATION
    # - Tivoli: FlextLdifServersTivoli.Constants.OPERATIONAL_ATTRIBUTES, PRESERVE_ON_MIGRATION
    # - Apache: FlextLdifServersApache.Constants.OPERATIONAL_ATTRIBUTES, PRESERVE_ON_MIGRATION
    # - OpenLDAP1: FlextLdifServersOpenldap1.Constants.OPERATIONAL_ATTRIBUTES, PRESERVE_ON_MIGRATION
    # Use the server-specific Constants classes instead.

    class AclAttributeRegistry:
        """LDAP Server-specific ACL attributes with RFC foundation.

        Implements HIERARCHY pattern:
        - RFC Foundation: aci, acl, olcAccess (all servers)
        - Server Quirks: Incremental additions per server type
        - Override: categorization_rules can override completely
        """

        # RFC Foundation - Standard LDAP (all servers)
        RFC_FOUNDATION: Final[list[str]] = [
            "aci",  # Standard LDAP ACL
            "acl",  # Alternative ACL format
            "olcAccess",  # OpenLDAP Access Control
            "aclRights",  # Generic ACL Rights
            "aclEntry",  # ACL Entry reference
        ]

        # Server-specific additions (incremental over RFC)
        SERVER_QUIRKS: Final[dict[str, list[str]]] = {
            "oid": [
                "orclaci",  # Oracle Internet Directory ACI
                "orclentrylevelaci",  # OID entry-level ACI
                "orclContainerLevelACL",  # OID container ACL
            ],
            "oud": [
                "orclaci",  # Oracle Unified Directory ACI
                "orclentrylevelaci",  # OUD entry-level ACI
            ],
            "ad": [
                "nTSecurityDescriptor",  # Active Directory security descriptor
            ],
            "generic": [],  # No additions, just RFC
        }

        @classmethod
        def get_acl_attributes(cls, server_type: str | None = None) -> list[str]:
            """Get ACL attributes with RFC foundation + server quirks.

            Args:
                server_type: 'oid', 'oud', 'ad', 'generic', or None
                    (defaults to generic)

            Returns:
                List of ACL attribute names (RFC + server-specific)

            """
            base = cls.RFC_FOUNDATION.copy()

            # Add server-specific quirks if provided
            if server_type and server_type in cls.SERVER_QUIRKS:
                base.extend(cls.SERVER_QUIRKS[server_type])

            return base

        @classmethod
        def is_acl_attribute(
            cls,
            attribute_name: str,
            server_type: str | None = None,
        ) -> bool:
            """Check if attribute is an ACL attribute for given server."""
            acl_attrs = cls.get_acl_attributes(server_type)
            return attribute_name.lower() in [a.lower() for a in acl_attrs]


__all__ = [
    "FlextLdifConstants",
]
