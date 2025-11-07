"""FlextLdif Constants - Complete Rewrite with Python 3.13 Type System.

MODERNIZATION:
- StrEnum for type-safe enumerations (ServerTypes, EntryTypes, ChangeTypes, Encoding)
- Literal for compile-time string validation
- Mapping for immutable dictionaries
- Final for all constants
- Removed 27 unused classes (0 references)

ORGANIZATION:
- Top-level constants (26 items)
- CORE (>10 refs): DictKeys, ServerTypes, ServerDetection
- DOMAIN (5-10 refs): QuirkMetadataKeys, ObjectClasses
- PROCESSING: LdifProcessing, ConfigDefaults, Format
- VALIDATION: LdifValidation, ValidationRules
- ACL: AclSubjectTypes, AclAttributes, Acl, PermissionNames
- SCHEMA: Schema, SchemaFields, OperationalAttributes
- PATTERNS: DnPatterns, LdifPatterns, RfcSyntaxOids
- TYPES: EntryTypes, ChangeTypes, SortStrategy, Encoding
- SPECIALIZED: ProcessorTypes, DnValuedAttributes

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from flext_core import FlextConstants


def _frozen(d: dict) -> Mapping:
    """Convert dict to immutable Mapping (Python 3.13 compatible)."""
    return MappingProxyType(d)


# ==================== MAIN CLASS ====================


class FlextLdifConstants(FlextConstants):
    """FlextLdif Constants with Python 3.13 type system.

    All constants are immutable and type-safe.
    Uses StrEnum for enumerations, Literal for single values, Mapping for dicts.
    """

    # ========== TOP-LEVEL CONSTANTS (26 items) ==========

    LDIF_VERSION: Final[str] = "0.9.9"
    LDIF_VERSION_INFO: Final[tuple[int, int, int]] = (0, 9, 9)

    DEFAULT_ENCODING: Final = "utf-8"
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

    # Format limits
    DEFAULT_LINE_LENGTH: Final[int] = 79
    MAX_LINE_LENGTH: Final[int] = 76
    MIN_LINE_LENGTH: Final[int] = 40

    # Buffer and processing
    MIN_BUFFER_SIZE: Final[int] = 1024
    DEFAULT_BATCH_SIZE: Final[int] = 1000
    MIN_BATCH_SIZE: Final[int] = 1
    MAX_BATCH_SIZE: Final[int] = 10000

    # Entry limits
    MIN_ENTRIES: Final[int] = 1000
    MAX_ENTRIES_ABSOLUTE: Final[int] = 10000000
    MAX_ATTRIBUTES_PER_ENTRY: Final[int] = 1000
    MAX_VALUES_PER_ATTRIBUTE: Final[int] = 100

    # Worker and performance
    MIN_WORKERS: Final[int] = 1
    MIN_WORKERS_FOR_PARALLEL: Final[int] = 2
    MAX_WORKERS_LIMIT: Final[int] = 16
    DEBUG_MAX_WORKERS: Final[int] = 2

    # Chunk sizes
    MIN_CHUNK_SIZE: Final[int] = 100
    MAX_CHUNK_SIZE: Final[int] = 10000
    PERFORMANCE_MIN_CHUNK_SIZE: Final[int] = 1000

    # Analytics
    MIN_ANALYTICS_CACHE_SIZE: Final[int] = 100
    MAX_ANALYTICS_CACHE_SIZE: Final[int] = 10000
    MIN_SAMPLE_RATE: Final[float] = 0.0
    MAX_SAMPLE_RATE: Final[float] = 1.0
    MAX_ANALYTICS_ENTRIES_ABSOLUTE: Final[int] = 100000
    ENCODING_CONFIDENCE_THRESHOLD: Final[float] = 0.7

    # Memory
    MIN_MEMORY_MB: Final[int] = 64
    MAX_MEMORY_MB: Final[int] = 8192
    PERFORMANCE_MEMORY_MB_THRESHOLD: Final[int] = 512

    # Thresholds
    SMALL_ENTRY_COUNT_THRESHOLD: Final[int] = 100
    MEDIUM_ENTRY_COUNT_THRESHOLD: Final[int] = 1000

    # Search
    DEFAULT_SEARCH_TIME_LIMIT: Final[int] = 30
    DEFAULT_SEARCH_SIZE_LIMIT: Final[int] = 0

    # Error handling
    MAX_LOGGED_ERRORS: Final[int] = 5

    # Detection
    DETECTION_THRESHOLD: Final[int] = 5
    CONFIDENCE_THRESHOLD: Final[float] = 0.6

    # ========== CORE CLASSES (>10 refs) ==========

    class DictKeys:
        """Entry dictionary keys (43 refs) - Core LDIF keys only."""

        DN: Final = "dn"
        ATTRIBUTES: Final = "attributes"
        OBJECTCLASS: Final = "objectClass"
        CN: Final = "cn"
        OID: Final = "oid"

    class ServerTypes(StrEnum):
        """Server type identifiers (66 refs) - Python 3.13 StrEnum."""

        OID = "oid"
        OUD = "oud"
        AD = "active_directory"
        OPENLDAP = "openldap"
        OPENLDAP1 = "openldap1"
        OPENLDAP2 = "openldap2"
        DS389 = "389ds"
        NOVELL = "novell_edirectory"
        TIVOLI = "ibm_tivoli"
        APACHE = "apache_directory"
        RELAXED = "relaxed"
        RFC = "rfc"
        GENERIC = "generic"

        @classmethod
        def is_valid(cls, value: str) -> bool:
            """Type-safe server type validation."""
            try:
                cls(value)
                return True
            except ValueError:
                return False

        @classmethod
        def from_string(cls, value: str) -> ServerTypes:
            """Convert string to ServerTypes with validation."""
            try:
                return cls(value.lower())
            except ValueError:
                msg = f"Invalid server type: {value}"
                raise ValueError(msg) from None

    class ServerDetection:
        """Server detection configuration (~15 refs)."""

        # Thresholds as immutable Mapping
        THRESHOLDS: Final[Mapping[str, int]] = _frozen({
            "min_oid_matches": 3,
            "min_attribute_matches": 5,
            "min_objectclass_matches": 2,
            "min_dn_matches": 2,
            "confidence_threshold": 75,
        })

        # Priority for detection
        DETECTION_PRIORITY: Final[Mapping[str, int]] = _frozen({
            "oid": 1,
            "oud": 2,
            "ad": 3,
            "ds389": 4,
            "novell": 5,
            "tivoli": 6,
            "apache": 7,
            "openldap": 8,
            "openldap1": 9,
            "rfc": 10,
            "generic": 11,
        })

        # Error messages
        ERROR_NO_DETECTION: Final[str] = "No server type detected"
        ERROR_LOW_CONFIDENCE: Final[str] = "Low confidence detection"
        ERROR_AMBIGUOUS: Final[str] = "Ambiguous server detection"

    # ========== DOMAIN SPECIFIC (5-10 refs) ==========

    class QuirkMetadataKeys:
        """Server metadata keys (7 refs)."""

        SERVER_TYPE: Final = "server_type"
        IS_CONFIG_ENTRY: Final = "is_config_entry"
        IS_TRADITIONAL_DIT: Final = "is_traditional_dit"
        CONFIDENCE: Final = "confidence"
        DETECTION_METHOD: Final = "detection_method"
        OID_MATCHES: Final = "oid_matches"
        ATTRIBUTE_MATCHES: Final = "attribute_matches"

    class ObjectClasses:
        """Common ObjectClass constants (5 refs)."""

        TOP: Final = "top"
        PERSON: Final = "person"
        ORGANIZATIONAL_PERSON: Final = "organizationalPerson"
        INET_ORG_PERSON: Final = "inetOrgPerson"
        ORGANIZATIONAL_UNIT: Final = "organizationalUnit"
        ORGANIZATION: Final = "organization"
        DOMAIN: Final = "domain"
        GROUP_OF_NAMES: Final = "groupOfNames"
        GROUP_OF_UNIQUE_NAMES: Final = "groupOfUniqueNames"
        POSIX_GROUP: Final = "posixGroup"
        USER: Final = "user"
        GROUP: Final = "group"
        COUNTRY: Final = "country"
        LOCALITY: Final = "locality"

        LDAP_PERSON_CLASSES: Final[frozenset[str]] = frozenset([
            "person",
            "organizationalPerson",
            "inetOrgPerson",
        ])
        LDAP_GROUP_CLASSES: Final[frozenset[str]] = frozenset([
            "groupOfNames",
            "groupOfUniqueNames",
            "posixGroup",
        ])
        LDAP_STRUCTURAL_BASE: Final[frozenset[str]] = frozenset([
            "top",
            "person",
            "organizationalPerson",
            "inetOrgPerson",
            "groupOfNames",
            "organizationalUnit",
            "organization",
            "domain",
        ])

    # ========== PROCESSING ==========

    class LdifProcessing:
        """Processing configuration (~10 refs)."""

        MIN_WORKERS: Final[int] = 1
        MIN_WORKERS_FOR_PARALLEL: Final[int] = 2
        MAX_WORKERS_LIMIT: Final[int] = 16
        PERFORMANCE_MIN_WORKERS: Final[int] = 4
        MIN_CHUNK_SIZE: Final[int] = 100
        MAX_CHUNK_SIZE: Final[int] = 10000
        PERFORMANCE_MIN_CHUNK_SIZE: Final[int] = 1000

    class ConfigDefaults:
        """Default configuration values (~20 refs)."""

        LDIF_SKIP_COMMENTS: Final[bool] = False
        LDIF_VALIDATE_DN_FORMAT: Final[bool] = True
        LDIF_STRICT_VALIDATION: Final[bool] = True
        LDIF_LINE_SEPARATOR: Final = "\n"
        LDIF_VERSION_STRING: Final = "version: 1"
        LDIF_MAX_ENTRIES: Final[int] = 1000000
        ENABLE_PERFORMANCE_OPTIMIZATIONS: Final[bool] = True
        ENABLE_PARALLEL_PROCESSING: Final[bool] = True
        LDIF_ENABLE_ANALYTICS: Final[bool] = True
        LDIF_FAIL_ON_WARNINGS: Final[bool] = False
        LDIF_ANALYTICS_SAMPLE_RATE: Final[float] = 1.0
        LDIF_ANALYTICS_MAX_ENTRIES: Final[int] = 10000
        LDIF_SERVER_SPECIFICS: Final[bool] = True
        STRICT_RFC_COMPLIANCE: Final[bool] = True
        ERROR_RECOVERY_MODE_CONTINUE: Final = "continue"
        DEBUG_MODE: Final[bool] = False
        VERBOSE_LOGGING: Final[bool] = False

    class Format:
        """LDIF format specifications (~8 refs)."""

        DN_ATTRIBUTE: Final = "dn"
        ATTRIBUTE_SEPARATOR: Final = ":"
        DN_PREFIX: Final = "dn:"
        LDIF_OBJECTCLASS_GROUPOFNAMES: Final = "groupOfNames"
        MIN_LINE_LENGTH: Final[int] = 40
        MAX_LINE_LENGTH: Final[int] = 78
        MAX_LINE_LENGTH_EXTENDED: Final[int] = 200
        MIN_BUFFER_SIZE: Final[int] = 1024
        CONTENT_PREVIEW_LENGTH: Final[int] = 100
        MAX_ATTRIBUTES_DISPLAY: Final[int] = 10
        MAX_FILENAME_LENGTH: Final[int] = 255
        BASE64_PREFIX: Final = "::"
        COMMENT_PREFIX: Final = "#"
        VERSION_PREFIX: Final = "version:"
        CHANGE_TYPE_PREFIX: Final = "changetype:"
        LINE_CONTINUATION_CHARS: Final[frozenset[str]] = frozenset([" ", "\t"])
        ATTRIBUTE_OPTION_SEPARATOR: Final = ";"
        URL_PREFIX: Final = "<"
        URL_SUFFIX: Final = ">"
        LDIF_VERSION_1: Final = "1"
        DEFAULT_LDIF_VERSION: Final = "1"

    # ========== VALIDATION ==========

    class LdifValidation:
        """Validation rules (3 refs)."""

        MIN_DN_COMPONENTS: Final[int] = 1
        MAX_DN_LENGTH: Final[int] = 2048
        MAX_ATTRIBUTES_PER_ENTRY: Final[int] = 1000
        MAX_VALUES_PER_ATTRIBUTE: Final[int] = 100
        MAX_ATTRIBUTE_VALUE_LENGTH: Final[int] = 10000
        MIN_ATTRIBUTE_NAME_LENGTH: Final[int] = 1
        MAX_ATTRIBUTE_NAME_LENGTH: Final[int] = 255
        ATTRIBUTE_NAME_PATTERN: Final[str] = r"^[a-zA-Z][a-zA-Z0-9-]*$"
        MIN_URL_LENGTH: Final[int] = 1
        MAX_URL_LENGTH: Final[int] = 2048
        URL_PATTERN: Final[str] = r"^(https?|ldap)://[^\s/$.?#].[^\s]*$"
        SECURE_PROTOCOLS: Final[frozenset[str]] = frozenset(["https", "ldaps"])
        MIN_ENCODING_LENGTH: Final[int] = 1
        MAX_ENCODING_LENGTH: Final[int] = 50
        MIN_LDIF_LINE_PARTS: Final[int] = 2

    class ValidationRules:
        """Validation rule constants."""

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
        MIN_WORKERS_PERFORMANCE_RULE: Final[int] = 4
        MIN_CHUNK_SIZE_PERFORMANCE_RULE: Final[int] = 1000
        MAX_WORKERS_DEBUG_RULE: Final[int] = 2
        DEFAULT_MAX_ATTR_VALUE_LENGTH: Final[int] = 1048576
        TYPICAL_ATTR_NAME_LENGTH_LIMIT: Final[int] = 127

    # ========== ACL DOMAIN ==========

    class AclSubjectTypes(StrEnum):
        """ACL subject types (3 refs) - Python 3.13 StrEnum."""

        USER = "user"
        GROUP = "group"
        ROLE = "role"
        SELF = "self"
        ALL = "all"
        PUBLIC = "public"
        ANONYMOUS = "anonymous"
        AUTHENTICATED = "authenticated"
        DN = "dn"

    class AclAttributes:
        """ACL attribute names (3 refs)."""

        ACI: Final = "aci"
        ACLRIGHTS: Final = "aclrights"
        ACLENTRY: Final = "aclentry"
        ALL_ACL_ATTRIBUTES: Final[frozenset[str]] = frozenset([
            "aci",
            "aclrights",
            "aclentry",
        ])
        FILTER_ACL_ATTRIBUTES: Final[frozenset[str]] = frozenset()

    class Acl:
        """ACL constants."""

        GRANT: Final = "grant"
        DENY: Final = "deny"
        ALLOW: Final = "allow"
        SUBTREE: Final = "subtree"
        ONELEVEL: Final = "onelevel"
        BASE: Final = "base"
        READ: Final = "read"
        WRITE: Final = "write"
        SEARCH: Final = "search"
        COMPARE: Final = "compare"
        ADD: Final = "add"
        DELETE: Final = "delete"
        MODIFY: Final = "modify"
        SELF_WRITE: Final = "self_write"
        PROXY: Final = "proxy"

    class PermissionNames:
        """RFC 4876 ACL permission type identifiers."""

        READ: Final = "read"
        WRITE: Final = "write"
        ADD: Final = "add"
        DELETE: Final = "delete"
        SEARCH: Final = "search"
        COMPARE: Final = "compare"
        ALL: Final = "all"
        NONE: Final = "none"
        ALL_PERMISSIONS: Final[frozenset[str]] = frozenset([
            "read",
            "write",
            "add",
            "delete",
            "search",
            "compare",
            "all",
            "none",
        ])

    # ========== SCHEMA & LDAP ==========

    class Schema:
        """Schema-related constants."""

        OBJECTCLASS: Final = "objectclass"
        ATTRIBUTE: Final = "attribute"
        SYNTAX: Final = "syntax"
        MATCHINGRULE: Final = "matchingrule"
        STRICT: Final = "strict"
        LENIENT: Final = "lenient"
        ACTIVE: Final = "active"
        DEPRECATED: Final = "deprecated"
        OBSOLETE: Final = "obsolete"
        STRUCTURAL: Final = "STRUCTURAL"
        AUXILIARY: Final = "AUXILIARY"
        ABSTRACT: Final = "ABSTRACT"

    class SchemaFields:
        """LDIF schema structure field names (case-sensitive)."""

        ATTRIBUTE_TYPES: Final = "attributeTypes"
        OBJECT_CLASSES: Final = "objectClasses"
        MATCHING_RULES: Final = "matchingRules"
        MATCHING_RULE_USE: Final = "matchingRuleUse"
        DIT_CONTENT_RULES: Final = "dITContentRules"
        DIT_STRUCTURE_RULES: Final = "dITStructureRules"
        NAME_FORMS: Final = "nameForms"
        LDAP_SYNTAXES: Final = "ldapSyntaxes"
        ATTRIBUTE_TYPES_LOWER: Final = "attributetypes"
        OBJECT_CLASSES_LOWER: Final = "objectclasses"
        OBJECT_CLASS_CAMEL: Final = "objectClass"
        ALL_SCHEMA_FIELDS: Final[frozenset[str]] = frozenset([
            "attributeTypes",
            "objectClasses",
            "matchingRules",
            "matchingRuleUse",
            "dITContentRules",
            "dITStructureRules",
            "nameForms",
            "ldapSyntaxes",
        ])

    class OperationalAttributes:
        """Operational (server-generated) attributes (3 refs)."""

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
        FILTER_FROM_NON_SCHEMA_ENTRIES: Final[frozenset[str]] = frozenset()

    # ========== PATTERNS & MATCHING ==========

    class DnPatterns:
        """DN regex patterns."""

        CN_SCHEMA: Final = "cn=schema"
        CN_SUBSCHEMA: Final = "cn=subschema"
        CN_SUBSCHEMA_SUBENTRY: Final = "cn=subschemasubentry"
        CN_SCHEMA_CN_CONFIG: Final = "cn=schema,cn=configuration"
        CN_CONFIG: Final = "cn=config"

        DN_EQUALS: Final = "="
        DN_COMMA: Final = ","
        DN_PLUS: Final = "+"

        DN_SPACES_AROUND_EQUALS: Final[str] = r"\s*=\s*"
        DN_TRAILING_BACKSLASH_SPACE: Final[str] = r"\\\s+,"
        DN_SPACES_AROUND_COMMA: Final[str] = r",\s+"
        DN_BACKSLASH_SPACE: Final[str] = r"\\\s+"
        DN_UNNECESSARY_ESCAPES: Final[str] = r'\\([^,+"\<>;\\# ])'
        DN_MULTIPLE_SPACES: Final[str] = r"\s+"

        ACI_LDAP_URL_PATTERN: Final[str] = r"ldap:///([^\"]+?)"
        ACI_QUOTED_DN_PATTERN: Final[str] = (
            r'"((?:[a-zA-Z]+=[^,\";\)]+)(?:,[a-zA-Z]+=[^,\";\)]+)*)"'
        )

        SCHEMA_OID_EXTRACTION: Final[str] = r"\(\s*([\d.]+)"

        CN_PREFIX: Final = "cn="
        OU_PREFIX: Final = "ou="
        DC_PREFIX: Final = "dc="
        UID_PREFIX: Final = "uid="
        O_PREFIX: Final = "o="
        L_PREFIX: Final = "l="
        ST_PREFIX: Final = "st="
        C_PREFIX: Final = "c="

        SCHEMA_SUBENTRY_PATTERNS: Final[frozenset[str]] = frozenset([
            "cn=schema",
            "cn=subschema",
            "cn=subschemasubentry",
            "cn=schema,cn=configuration",
        ])
        CONFIG_DN_PATTERNS: Final[frozenset[str]] = frozenset([
            "cn=config",
            "cn=schema,cn=configuration",
        ])

    class LdifPatterns:
        """LDIF regex patterns."""

        XML_ENCODING: Final[str] = r'<\?xml[^>]*encoding=["\']([^"\']+)["\']'
        HTML_CHARSET: Final[str] = r'<meta[^>]*charset=["\']([^"\']+)["\']'
        PYTHON_CODING: Final[str] = r"#.*-\*-.*coding:\s*([^\s;]+)"
        LDIF_ENCODING: Final[str] = r"#\s*encoding:\s*([^\s\n]+)"

        DN_COMPONENT: Final[str] = r"^[a-zA-Z][a-zA-Z0-9-]*=(?:[^\\,]|\\.)*$"
        DN_SEPARATOR: Final[str] = r"(?<!\\),"

        LDAP_FILTER: Final[str] = r"^\(.*\)$"

        OBJECTCLASS_NAME: Final[str] = r"^[a-zA-Z][a-zA-Z0-9-]*$"
        ATTRIBUTE_NAME: Final[str] = r"^[a-zA-Z][a-zA-Z0-9-]*$"
        ATTRIBUTE_OPTION: Final[str] = r";[a-zA-Z][a-zA-Z0-9-]*"

        OID_NUMERIC: Final[str] = r"^\d+(\.\d+)*$"
        OID_DESCRIPTOR: Final[str] = r"^[a-zA-Z][a-zA-Z0-9-]*$"

        SCHEMA_OID: Final[str] = r"^\s*\(\s*([\d.]+)"
        SCHEMA_OID_EXTRACTION: Final[str] = r"\(\s*([\d.]+)"
        SCHEMA_OID_EXTRACTION_START: Final[str] = r"^\s*\(\s*([0-9.]+)"
        SCHEMA_NAME: Final[str] = r"NAME\s+\(?\s*'([^']+)'"
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

        SCHEMA_OBJECTCLASS_KIND: Final[str] = r"\b(ABSTRACT|STRUCTURAL|AUXILIARY)\b"
        SCHEMA_OBJECTCLASS_SUP: Final[str] = r"SUP\s+(?:\(\s*([^)]+)\s*\)|(\w+))"
        SCHEMA_OBJECTCLASS_MUST: Final[str] = r"MUST\s+(?:\(\s*([^)]+)\s*\)|(\w+))"
        SCHEMA_OBJECTCLASS_MAY: Final[str] = r"MAY\s+(?:\(\s*([^)]+)\s*\)|(\w+))"

    class RfcSyntaxOids:
        """RFC 4517 LDAP Attribute Syntax OIDs."""

        BASE: Final[str] = "1.3.6.1.4.1.1466.115.121.1"
        BOOLEAN: Final[str] = "1.3.6.1.4.1.1466.115.121.1.7"
        INTEGER_RFC: Final[str] = "2.5.5.5"
        DN: Final[str] = "1.3.6.1.4.1.1466.115.121.1.12"
        DIRECTORY_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.15"
        OCTET_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.39"
        OID: Final[str] = "1.3.6.1.4.1.1466.115.121.1.38"

    # ========== TYPE ENUMERATIONS ==========

    class EntryTypes(StrEnum):
        """Entry types enumeration (1 ref) - Python 3.13 StrEnum."""

        PERSON = "person"
        GROUP = "group"
        OU = "ou"
        ORGANIZATIONAL_UNIT = "organizationalunit"
        CUSTOM = "custom"

    class ChangeTypes(StrEnum):
        """LDIF change types - Python 3.13 StrEnum."""

        ADD = "add"
        DELETE = "delete"
        MODIFY = "modify"
        MODRDN = "modrdn"

    class SortStrategy(StrEnum):
        """Sort strategy enumeration."""

        HIERARCHY = "hierarchy"
        DN = "dn"
        ALPHABETICAL = "alphabetical"
        SCHEMA = "schema"
        CUSTOM = "custom"

    class SortTarget(StrEnum):
        """Sort target enumeration."""

        ENTRIES = "entries"
        ATTRIBUTES = "attributes"
        ACL = "acl"
        SCHEMA = "schema"
        COMBINED = "combined"

    class Encoding(StrEnum):
        """Encoding types (3 refs) - Python 3.13 StrEnum."""

        UTF8 = "utf-8"
        UTF16LE = "utf-16-le"
        UTF16 = "utf-16"
        UTF32 = "utf-32"
        ASCII = "ascii"
        LATIN1 = "latin-1"
        CP1252 = "cp1252"
        ISO8859_1 = "iso-8859-1"

    class RfcAclPermission(StrEnum):
        """RFC 4876 standard ACL permissions (type-safe enum)."""

        READ = "read"
        WRITE = "write"
        ADD = "add"
        DELETE = "delete"
        SEARCH = "search"
        COMPARE = "compare"
        ALL = "all"
        NONE = "none"

    # ========== SPECIAL CLASSES ==========

    class DnValuedAttributes:
        """Attributes that contain DN values."""

        MEMBER: Final = "member"
        UNIQUE_MEMBER: Final = "uniqueMember"
        OWNER: Final = "owner"
        MANAGED_BY: Final = "managedBy"
        MANAGER: Final = "manager"
        SECRETARY: Final = "secretary"
        SEES_ALSO: Final = "seeAlso"
        PARENT: Final = "parent"
        REFERS_TO: Final = "refersTo"
        MEMBER_OF: Final = "memberOf"
        GROUPS: Final = "groups"
        AUTHORIZED_TO: Final = "authorizedTo"
        HAS_SUBORDINATES: Final = "hasSubordinates"
        SUBORDINATE_DN: Final = "subordinateDn"

        ALL_DN_VALUED: Final[frozenset[str]] = frozenset([
            "member",
            "uniqueMember",
            "owner",
            "managedBy",
            "manager",
            "secretary",
            "seeAlso",
            "parent",
            "refersTo",
            "memberOf",
            "groups",
            "authorizedTo",
            "hasSubordinates",
            "subordinateDn",
        ])

    class ProcessorTypes:
        """FLEXT processor types (2 refs)."""

        LDIF_PARSER: Final = "ldif_parser"
        LDIF_WRITER: Final = "ldif_writer"
        LDIF_VALIDATOR: Final = "ldif_validator"
        LDIF_CONVERTER: Final = "ldif_converter"

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

    class FilterTypes:
        """Filter type identifier constants."""

        OBJECTCLASS: Final = "objectclass"
        DN_PATTERN: Final = "dn_pattern"
        ATTRIBUTES: Final = "attributes"
        SCHEMA_OID: Final = "schema_oid"
        OID_PATTERN: Final = "oid_pattern"
        ATTRIBUTE: Final = "attribute"

    class Categories:
        """Entry category constants."""

        USERS: Final = "users"
        GROUPS: Final = "groups"
        HIERARCHY: Final = "hierarchy"
        SCHEMA: Final = "schema"
        ACL: Final = "acl"
        REJECTED: Final = "rejected"

    class BooleanFormats:
        """Boolean value representations."""

        TRUE_RFC: Final = "TRUE"
        FALSE_RFC: Final = "FALSE"
        TRUE_LOWER: Final = "true"
        FALSE_LOWER: Final = "false"
        RFC_TRUE_VALUES: Final[frozenset[str]] = frozenset(["TRUE", "true"])
        RFC_FALSE_VALUES: Final[frozenset[str]] = frozenset(["FALSE", "false"])

    class MetadataKeys:
        """Metadata extension keys for quirk processing."""

        SYNTAX_OID_VALID: Final = "syntax_oid_valid"
        SYNTAX_VALIDATION_ERROR: Final = "syntax_validation_error"
        X_ORIGIN: Final = "x_origin"
        OBSOLETE: Final = "obsolete"
        COLLECTIVE: Final = "collective"
        ORIGINAL_FORMAT: Final = "original_format"
        ORIGINAL_SOURCE: Final = "original_source"
        VERSION: Final = "version"
        LINE_BREAKS: Final = "line_breaks"
        IS_MULTILINE: Final = "is_multiline"
        DN_SPACES: Final = "dn_spaces"
        TARGETSCOPE: Final = "targetscope"
        ATTRIBUTE_ORDER: Final = "attribute_order"
        SUBJECT_BINDING: Final = "subject_binding"
        BASE64_ATTRS: Final = "_base64_attrs"

    class AclFormats:
        """ACL format identifier constants."""

        RFC_GENERIC: Final = "rfc_generic"
        ACI: Final = "aci"

    class ConversionStrategy:
        """Server conversion strategy using RFC as canonical intermediate format."""

        CANONICAL_FORMAT: Final = "rfc"
        ALGORITHM: Final = "adapter_pattern_with_rfc_hub"
        CONVERSION_COMPLEXITY: Final = "2N"
        ENFORCE_RFC_INTERMEDIATE: Final[bool] = True
        PRESERVE_SOURCE_METADATA: Final[bool] = True
        DIRECTION_TO_RFC: Final = "normalize"
        DIRECTION_FROM_RFC: Final = "denormalize"

    class LdifFormat:
        """LDIF formatting constants."""

        DEFAULT_LINE_WIDTH: Final[int] = 76
        MAX_LINE_WIDTH: Final[int] = 1000
        MIN_LINE_WIDTH: Final[int] = 10

    class RfcCompliance:
        """RFC 2849 compliance validation constants."""

        LINE_LENGTH_LIMIT: Final[int] = 76
        LINE_WITH_NEWLINE: Final[int] = 77
        STRICT: Final = "strict"
        MODERATE: Final = "moderate"
        LENIENT: Final = "lenient"


__all__ = ["FlextLdifConstants"]
