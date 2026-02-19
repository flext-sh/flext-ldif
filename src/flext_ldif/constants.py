"""LDIF constants and enumerations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import StrEnum
from types import MappingProxyType
from typing import ClassVar, Final, Literal

from flext_core import FlextConstants

type ValidationLevelLiteral = Literal["strict", "moderate", "lenient"]


class FlextLdifConstants(FlextConstants):
    """LDIF domain constants extending flext-core FlextConstants."""

    class Ldif:
        """LDIF domain constants namespace."""

        class SortStrategy(StrEnum):
            """Valid sorting strategies for LDIF entries (V2 type-safe enum)."""

            HIERARCHY = "hierarchy"
            DN = "dn"
            ALPHABETICAL = "alphabetical"
            SCHEMA = "schema"
            CUSTOM = "custom"

        class SortingStrategyType(StrEnum):
            """Sorting strategy types for metadata tracking."""

            ALPHABETICAL_CASE_SENSITIVE = "alphabetical_case_sensitive"
            ALPHABETICAL_CASE_INSENSITIVE = "alphabetical_case_insensitive"
            CUSTOM_ORDER = "custom_order"

        class SortTarget(StrEnum):
            """What to sort in LDIF data (V2 type-safe enum)."""

            ENTRIES = "entries"
            ATTRIBUTES = "attributes"
            ACL = "acl"
            SCHEMA = "schema"
            COMBINED = "combined"

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

        class AclPermission(StrEnum):
            """Comprehensive ACL permissions covering all server types (type-safe enum)."""

            READ = "read"
            WRITE = "write"
            ADD = "add"
            DELETE = "delete"
            SEARCH = "search"
            COMPARE = "compare"
            ALL = "all"
            NONE = "none"

            AUTH = "auth"
            CREATE = "create"
            CONTROL_ACCESS = "control_access"

        class AclAction(StrEnum):
            """ACL action types for all server implementations (type-safe enum)."""

            ALLOW = "allow"
            DENY = "deny"

        class Encoding(StrEnum):
            """Standard character encodings used in LDIF processing."""

            UTF8 = "utf-8"
            UTF16LE = "utf-16-le"
            UTF16 = "utf-16"
            UTF32 = "utf-32"
            ASCII = "ascii"
            LATIN1 = "latin-1"
            CP1252 = "cp1252"
            ISO8859_1 = "iso-8859-1"

        DEFAULT_ENCODING: Final[str] = FlextConstants.Utilities.DEFAULT_ENCODING

        class LdifFormat(StrEnum):
            """RFC 2849 LDIF format indicators for attribute value encoding."""

            REGULAR = ":"
            BASE64 = "::"
            URL = ":<"

        LDIF_BASE64_INDICATOR: Final[str] = LdifFormat.BASE64.value
        LDIF_REGULAR_INDICATOR: Final[str] = LdifFormat.REGULAR.value
        LDIF_URL_INDICATOR: Final[str] = LdifFormat.URL.value

        LDIF_DEFAULT_ENCODING: Final[str] = FlextConstants.Utilities.DEFAULT_ENCODING

        class AclSubjectType(StrEnum):
            """ACL subject/who types for permission subjects."""

            USER = "user"
            GROUP = "group"
            ROLE = "role"
            SELF = "self"
            ALL = "all"
            PUBLIC = "public"
            ANONYMOUS = "anonymous"
            AUTHENTICATED = "authenticated"
            SDDL = "sddl"
            DN = "dn"

        class DictKeys(StrEnum):
            """Dictionary keys for LDIF entry data access - CORE KEYS ONLY per SRP."""

            DN = "dn"
            ATTRIBUTES = "attributes"
            OBJECTCLASS = "objectClass"
            CN = "cn"
            OID = "oid"

        class Domain(FlextConstants.Domain):
            """Domain constants extending FlextConstants.Domain."""

            class ServerType(StrEnum):
                """Server type values for LDIF processing."""

                OUD = "oud"
                OID = "oid"
                RFC = "rfc"
                AD = "ad"
                OPENLDAP = "openldap"
                OPENLDAP1 = "openldap1"
                OPENLDAP2 = "openldap2"
                DS389 = "ds389"
                APACHE = "apache"
                NOVELL = "novell"
                IBM_TIVOLI = "tivoli"
                RELAXED = "relaxed"

            class OutputFormat(StrEnum):
                """Output format options."""

                LDIF = "ldif"
                JSON = "json"
                CSV = "csv"
                YAML = "yaml"

            class ValidationStatus(StrEnum):
                """Validation status values for LDIF entries."""

                VALID = "valid"
                INVALID = "invalid"
                WARNING = "warning"

            class CaseFoldOption(StrEnum):
                """Case folding options for DN normalization."""

                NONE = "none"
                LOWER = "lower"
                UPPER = "upper"

            class QuirkMetadataKeys(StrEnum):
                """Dictionary keys for quirk metadata and server-specific entry properties."""

                SERVER_TYPE = "server_type"
                IS_CONFIG_ENTRY = "is_config_entry"
                IS_TRADITIONAL_DIT = "is_traditional_dit"

            class AclKeys(StrEnum):
                """Dictionary keys for ACL-related attributes and operations."""

                ACL_ATTRIBUTE = "acl"
                ACI = "aci"
                ACCESS = "access"

        class Format:
            """LDIF format specifications."""

            DN_ATTRIBUTE: Final[str] = "dn"
            ATTRIBUTE_SEPARATOR: Final[str] = ":"

            LDIF_OBJECTCLASS_GROUPOFNAMES: Final[str] = "groupOfNames"

            MIN_LINE_LENGTH: Final[int] = 40
            MAX_LINE_LENGTH: Final[int] = 78
            MAX_LINE_LENGTH_EXTENDED: Final[int] = 200

            MIN_TUPLE_SIZE: Final[int] = 2

            MIN_BUFFER_SIZE: Final[int] = 1024
            CONTENT_PREVIEW_LENGTH: Final[int] = 100
            MINIMAL_DIFF_PREVIEW_LENGTH: Final[int] = 50
            MAX_ATTRIBUTES_DISPLAY: Final[int] = 10

            MAX_FILENAME_LENGTH: Final[int] = 255

            BASE64_PREFIX: Final[str] = "::"
            COMMENT_PREFIX: Final[str] = "#"
            VERSION_PREFIX: Final[str] = "version:"
            CHANGE_TYPE_PREFIX: Final[str] = "changetype:"
            ATTRIBUTE_OPTION_SEPARATOR: Final[str] = ";"
            URL_PREFIX: Final[str] = "<"
            URL_SUFFIX: Final[str] = ">"

            LDIF_VERSION_1: Final[str] = "1"
            DEFAULT_LDIF_VERSION: Final[str] = LDIF_VERSION_1

            class Rfc:
                """RFC 2849/4512/4514 Standard Constants."""

            SAFE_CHAR_MIN: Final[int] = 0x01
            SAFE_CHAR_MAX: Final[int] = 0x7F
            SAFE_CHAR_EXCLUDE: Final[frozenset[int]] = frozenset({0x00, 0x0A, 0x0D})

            SAFE_INIT_CHAR_EXCLUDE: Final[frozenset[int]] = frozenset({
                0x00,
                0x0A,
                0x0D,
                0x20,
                0x3A,
                0x3C,
            })

            BASE64_CHARS: Final[frozenset[str]] = frozenset(
                "+/0123456789=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            )

            class Base64StartChar(StrEnum):
                """RFC 2849 §2 - Characters requiring base64 encoding at value start."""

                SPACE = " "
                LANGLE = "<"
                COLON = ":"

            BASE64_START_CHARS: Final[frozenset[str]] = frozenset({
                Base64StartChar.SPACE,
                Base64StartChar.LANGLE,
                Base64StartChar.COLON,
            })

            LINE_FOLD_WIDTH: Final[int] = 76
            LINE_CONTINUATION_SPACE: Final[str] = " "
            LINE_SEPARATOR: Final[str] = "\n"

            ENTRY_SEPARATOR: Final[str] = "\n\n"
            ATTR_SEPARATOR: Final[str] = ":"
            BASE64_SEPARATOR: Final[str] = "::"
            URL_SEPARATOR: Final[str] = ":<"

            KEYWORD_DN: Final[str] = "dn"
            KEYWORD_CHANGETYPE: Final[str] = "changetype"
            KEYWORD_CONTROL: Final[str] = "control"
            KEYWORD_NEWRDN: Final[str] = "newrdn"
            KEYWORD_DELETEOLDRDN: Final[str] = "deleteoldrdn"
            KEYWORD_NEWSUPERIOR: Final[str] = "newsuperior"

            SCHEMA_WSP: Final[str] = " "
            SCHEMA_SPACE: Final[str] = " "

            SCHEMA_LPAREN: Final[str] = "("
            SCHEMA_RPAREN: Final[str] = ")"
            SCHEMA_SQUOTE: Final[str] = "'"
            SCHEMA_DQUOTE: Final[str] = '"'
            SCHEMA_LCURLY: Final[str] = "{"
            SCHEMA_RCURLY: Final[str] = "}"
            SCHEMA_DOLLAR: Final[str] = "$"

            SCHEMA_EXTENSION_PREFIX: Final[str] = "X-"

            SCHEMA_KW_OBSOLETE: Final[str] = "OBSOLETE"
            SCHEMA_KW_SUP: Final[str] = "SUP"
            SCHEMA_KW_EQUALITY: Final[str] = "EQUALITY"
            SCHEMA_KW_ORDERING: Final[str] = "ORDERING"
            SCHEMA_KW_SUBSTR: Final[str] = "SUBSTR"
            SCHEMA_KW_SYNTAX: Final[str] = "SYNTAX"
            SCHEMA_KW_SINGLE_VALUE: Final[str] = "SINGLE-VALUE"
            SCHEMA_KW_COLLECTIVE: Final[str] = "COLLECTIVE"
            SCHEMA_KW_NO_USER_MODIFICATION: Final[str] = "NO-USER-MODIFICATION"
            SCHEMA_KW_USAGE: Final[str] = "USAGE"
            SCHEMA_KW_MUST: Final[str] = "MUST"
            SCHEMA_KW_MAY: Final[str] = "MAY"
            SCHEMA_KW_APPLIES: Final[str] = "APPLIES"
            SCHEMA_KW_AUX: Final[str] = "AUX"
            SCHEMA_KW_NOT: Final[str] = "NOT"
            SCHEMA_KW_OC: Final[str] = "OC"
            SCHEMA_KW_FORM: Final[str] = "FORM"

            ATTR_CREATORS_NAME: Final[str] = "creatorsName"
            ATTR_CREATE_TIMESTAMP: Final[str] = "createTimestamp"
            ATTR_MODIFIERS_NAME: Final[str] = "modifiersName"
            ATTR_MODIFY_TIMESTAMP: Final[str] = "modifyTimestamp"
            ATTR_STRUCTURAL_OBJECTCLASS: Final[str] = "structuralObjectClass"
            ATTR_GOVERNING_STRUCTURE_RULE: Final[str] = "governingStructureRule"
            ATTR_SUBSCHEMA_SUBENTRY: Final[str] = "subschemaSubentry"
            ATTR_ENTRY_DN: Final[str] = "entryDN"

            class OperationalAttribute(StrEnum):
                """RFC 4512 §4.2.1 - Standard operational attributes."""

                CREATORS_NAME = "creatorsName"
                CREATE_TIMESTAMP = "createTimestamp"
                MODIFIERS_NAME = "modifiersName"
                MODIFY_TIMESTAMP = "modifyTimestamp"
                STRUCTURAL_OBJECTCLASS = "structuralObjectClass"
                GOVERNING_STRUCTURE_RULE = "governingStructureRule"
                SUBSCHEMA_SUBENTRY = "subschemaSubentry"
                ENTRY_DN = "entryDN"

            OPERATIONAL_ATTRIBUTES: Final[frozenset[str]] = frozenset({
                OperationalAttribute.CREATORS_NAME,
                OperationalAttribute.CREATE_TIMESTAMP,
                OperationalAttribute.MODIFIERS_NAME,
                OperationalAttribute.MODIFY_TIMESTAMP,
                OperationalAttribute.STRUCTURAL_OBJECTCLASS,
                OperationalAttribute.GOVERNING_STRUCTURE_RULE,
                OperationalAttribute.SUBSCHEMA_SUBENTRY,
                OperationalAttribute.ENTRY_DN,
            })

            ATTR_OBJECTCLASSES: Final[str] = "objectClasses"
            ATTR_ATTRIBUTETYPES: Final[str] = "attributeTypes"
            ATTR_MATCHINGRULES: Final[str] = "matchingRules"
            ATTR_MATCHINGRULEUSE: Final[str] = "matchingRuleUse"
            ATTR_LDAPSYNTAXES: Final[str] = "ldapSyntaxes"
            ATTR_DITCONTENTRULES: Final[str] = "dITContentRules"
            ATTR_DITSTRUCTURERULES: Final[str] = "dITStructureRules"
            ATTR_NAMEFORMS: Final[str] = "nameForms"

            DN_LUTF1_EXCLUDE: Final[frozenset[int]] = frozenset({
                0x00,
                0x20,
                0x22,
                0x23,
                0x2B,
                0x2C,
                0x3B,
                0x3C,
                0x3E,
                0x5C,
            })

            DN_TUTF1_EXCLUDE: Final[frozenset[int]] = frozenset({
                0x00,
                0x20,
                0x22,
                0x2B,
                0x2C,
                0x3B,
                0x3C,
                0x3E,
                0x5C,
            })

            DN_SUTF1_EXCLUDE: Final[frozenset[int]] = frozenset({
                0x00,
                0x22,
                0x2B,
                0x2C,
                0x3B,
                0x3C,
                0x3E,
                0x5C,
            })

            class DnEscapeChar(StrEnum):
                """RFC 4514 §2.4 - Characters always requiring escape in DN values."""

                DQUOTE = '"'
                PLUS = "+"
                COMMA = ","
                SEMICOLON = ";"
                LANGLE = "<"
                RANGLE = ">"
                BACKSLASH = "\\"

            DN_ESCAPE_CHARS: Final[frozenset[str]] = frozenset({
                DnEscapeChar.DQUOTE,
                DnEscapeChar.PLUS,
                DnEscapeChar.COMMA,
                DnEscapeChar.SEMICOLON,
                DnEscapeChar.LANGLE,
                DnEscapeChar.RANGLE,
                DnEscapeChar.BACKSLASH,
            })

            class DnEscapeAtStart(StrEnum):
                """RFC 4514 §2.4 - Characters requiring escape at DN value start."""

                SPACE = " "
                SHARP = "#"

            class DnEscapeAtEnd(StrEnum):
                """RFC 4514 §2.4 - Characters requiring escape at DN value end."""

                SPACE = " "

            DN_ESCAPE_AT_START: Final[frozenset[str]] = frozenset({
                DnEscapeAtStart.SPACE,
                DnEscapeAtStart.SHARP,
            })
            DN_ESCAPE_AT_END: Final[frozenset[str]] = frozenset({
                DnEscapeAtEnd.SPACE,
            })

            DN_ATTR_CN: Final[str] = "CN"
            DN_ATTR_L: Final[str] = "L"
            DN_ATTR_ST: Final[str] = "ST"
            DN_ATTR_O: Final[str] = "O"
            DN_ATTR_OU: Final[str] = "OU"
            DN_ATTR_C: Final[str] = "C"
            DN_ATTR_STREET: Final[str] = "STREET"
            DN_ATTR_DC: Final[str] = "DC"
            DN_ATTR_UID: Final[str] = "UID"

            DN_ATTRIBUTE_TYPES: Final[MappingProxyType[str, str]] = MappingProxyType({
                "CN": "2.5.4.3",
                "L": "2.5.4.7",
                "ST": "2.5.4.8",
                "O": "2.5.4.10",
                "OU": "2.5.4.11",
                "C": "2.5.4.6",
                "STREET": "2.5.4.9",
                "DC": "0.9.2342.19200300.100.1.25",
                "UID": "0.9.2342.19200300.100.1.1",
            })

            DN_RDN_SEPARATOR: Final[str] = ","
            DN_RDN_SEPARATOR_ALT: Final[str] = ";"
            DN_MULTIVALUE_SEPARATOR: Final[str] = "+"
            DN_ATTR_VALUE_SEPARATOR: Final[str] = "="

            MIN_DN_LENGTH: Final[int] = 2

            ASCII_PRINTABLE_MIN: Final[int] = 0x20
            ASCII_PRINTABLE_MAX: Final[int] = 0x7E

            MIN_BASE64_LENGTH: Final[int] = 8

            SYNTAX_DIRECTORY_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.15"
            SYNTAX_OCTET_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.40"
            SYNTAX_INTEGER: Final[str] = "1.3.6.1.4.1.1466.115.121.1.27"
            SYNTAX_BOOLEAN: Final[str] = "1.3.6.1.4.1.1466.115.121.1.7"
            SYNTAX_DN: Final[str] = "1.3.6.1.4.1.1466.115.121.1.12"
            SYNTAX_GENERALIZED_TIME: Final[str] = "1.3.6.1.4.1.1466.115.121.1.24"
            SYNTAX_OID: Final[str] = "1.3.6.1.4.1.1466.115.121.1.38"
            SYNTAX_BIT_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.6"
            SYNTAX_JPEG: Final[str] = "1.3.6.1.4.1.1466.115.121.1.28"

            MATCH_CASE_IGNORE: Final[str] = "2.5.13.2"
            MATCH_CASE_EXACT: Final[str] = "2.5.13.5"
            MATCH_DISTINGUISHED_NAME: Final[str] = "2.5.13.1"
            MATCH_INTEGER: Final[str] = "2.5.13.14"
            MATCH_GENERALIZED_TIME: Final[str] = "2.5.13.27"
            MATCH_OID: Final[str] = "2.5.13.0"

            META_RFC_VERSION: Final[str] = "_rfc_version"
            META_RFC_LINE_FOLDING: Final[str] = "_rfc_line_folding"
            META_RFC_BASE64_ENCODED: Final[str] = "_rfc_base64"
            META_RFC_URL_REFERENCE: Final[str] = "_rfc_url_ref"
            META_RFC_CHANGETYPE: Final[str] = "_rfc_changetype"
            META_RFC_CONTROLS: Final[str] = "_rfc_controls"

            META_SCHEMA_EXTENSIONS: Final[str] = "_schema_extensions"
            META_SCHEMA_ORIGIN: Final[str] = "_schema_origin"
            META_SCHEMA_OBSOLETE: Final[str] = "_schema_obsolete"

            META_DN_ORIGINAL: Final[str] = "_dn_original"
            META_DN_WAS_BASE64: Final[str] = "_dn_was_base64"
            META_DN_ESCAPES_APPLIED: Final[str] = "_dn_escapes"

            META_TRANSFORMATION_SOURCE: Final[str] = "_transform_source"
            META_TRANSFORMATION_TARGET: Final[str] = "_transform_target"
            META_TRANSFORMATION_TIMESTAMP: Final[str] = "_transform_ts"

        class FeatureCapabilities:
            """Feature capability definitions for cross-server translation."""

            ACL_READ: Final[str] = "acl:read"
            ACL_WRITE: Final[str] = "acl:write"
            ACL_ADD: Final[str] = "acl:add"
            ACL_DELETE: Final[str] = "acl:delete"
            ACL_SEARCH: Final[str] = "acl:search"
            ACL_COMPARE: Final[str] = "acl:compare"

            ACL_SUBJECT_USER_DN: Final[str] = "acl:subject:user_dn"
            ACL_SUBJECT_GROUP_DN: Final[str] = "acl:subject:group_dn"
            ACL_SUBJECT_SELF: Final[str] = "acl:subject:self"
            ACL_SUBJECT_ANONYMOUS: Final[str] = "acl:subject:anonymous"
            ACL_SUBJECT_ALL: Final[str] = "acl:subject:all"

            ACL_TARGET_ENTRY: Final[str] = "acl:target:entry"
            ACL_TARGET_ATTRS: Final[str] = "acl:target:attrs"
            ACL_TARGET_DN: Final[str] = "acl:target:dn"

            SCHEMA_ATTR_SYNTAX: Final[str] = "schema:attr:syntax"
            SCHEMA_ATTR_MATCHING: Final[str] = "schema:attr:matching"
            SCHEMA_ATTR_SINGLE_VALUE: Final[str] = "schema:attr:single_value"
            SCHEMA_OC_SUP: Final[str] = "schema:oc:sup"
            SCHEMA_OC_KIND: Final[str] = "schema:oc:kind"

            ENTRY_DN: Final[str] = "entry:dn"
            ENTRY_CHANGETYPE: Final[str] = "entry:changetype"
            ENTRY_CONTROLS: Final[str] = "entry:controls"

            ACL_SELF_WRITE: Final[str] = "acl:vendor:self_write"

            ACL_PROXY_AUTH: Final[str] = "acl:vendor:proxy_auth"

            ACL_BROWSE_PERMISSION: Final[str] = "acl:vendor:browse"

            ACL_AUTH_PERMISSION: Final[str] = "acl:vendor:auth"

            ACL_ALL_PERMISSIONS: Final[str] = "acl:vendor:all"

            ACL_NEGATIVE_PERMISSIONS: Final[str] = "acl:vendor:negative"

            ACL_DNATTR_SUBJECT: Final[str] = "acl:vendor:dnattr"

            ACL_GUIDATTR_SUBJECT: Final[str] = "acl:vendor:guidattr"

            ACL_BIND_IP: Final[str] = "acl:vendor:bind_ip"

            ACL_BIND_TIME: Final[str] = "acl:vendor:bind_time"

            ACL_BIND_AUTHMETHOD: Final[str] = "acl:vendor:bind_authmethod"

            ACL_BIND_SSF: Final[str] = "acl:vendor:bind_ssf"

            ACL_TARGET_FILTER: Final[str] = "acl:vendor:target_filter"

            SCHEMA_X_ORIGIN: Final[str] = "schema:vendor:x_origin"

            SCHEMA_X_SCHEMA_FILE: Final[str] = "schema:vendor:x_schema_file"

            SCHEMA_CUSTOM_SYNTAX: Final[str] = "schema:vendor:custom_syntax"

            ENTRY_OPERATIONAL_ATTRS: Final[str] = "entry:vendor:operational"

            ENTRY_VENDOR_CONTROLS: Final[str] = "entry:vendor:controls"

            RFC_FALLBACKS: Final[MappingProxyType[str, str | None]] = MappingProxyType({
                ACL_SELF_WRITE: "write",
                ACL_BROWSE_PERMISSION: "read,search",
                ACL_PROXY_AUTH: None,
                ACL_AUTH_PERMISSION: None,
                ACL_ALL_PERMISSIONS: "read,write,add,delete,search,compare",
                ACL_DNATTR_SUBJECT: None,
                ACL_GUIDATTR_SUBJECT: None,
                ACL_NEGATIVE_PERMISSIONS: None,
                ACL_BIND_IP: None,
                ACL_BIND_TIME: None,
                ACL_BIND_AUTHMETHOD: None,
                ACL_BIND_SSF: None,
                ACL_TARGET_FILTER: None,
            })

            META_UNSUPPORTED_FEATURES: Final[str] = "_unsupported_features"
            META_FEATURE_SOURCE: Final[str] = "_feature_source_server"
            META_FEATURE_ORIGINAL_VALUE: Final[str] = "_feature_original_value"
            META_FEATURE_FALLBACK_USED: Final[str] = "_feature_fallback_used"
            META_FEATURE_EXPANSION_APPLIED: Final[str] = "_feature_expansion_applied"

        class LdifProcessing:
            """LDIF processing-related constants."""

            MIN_WORKERS: Final[int] = 1
            MIN_WORKERS_FOR_PARALLEL: Final[int] = 2
            MAX_WORKERS_LIMIT: Final[int] = 16
            PERFORMANCE_MIN_WORKERS: Final[int] = 4

            MIN_CHUNK_SIZE: Final[int] = 100
            MAX_CHUNK_SIZE: Final[int] = 10000
            PERFORMANCE_MIN_CHUNK_SIZE: Final[int] = 1000

            HIGH_FAILURE_RATE_THRESHOLD: Final[float] = 50.0

            MIN_ENTRIES: Final[int] = 1000
            MAX_ENTRIES_ABSOLUTE: Final[int] = 10000000

            MIN_ANALYTICS_CACHE_SIZE: Final[int] = 100
            MAX_ANALYTICS_CACHE_SIZE: Final[int] = 10000
            MIN_SAMPLE_RATE: Final[float] = 0.0
            MAX_SAMPLE_RATE: Final[float] = 1.0
            MAX_ANALYTICS_ENTRIES_ABSOLUTE: Final[int] = 100000

            MIN_MEMORY_MB: Final[int] = 64
            MAX_MEMORY_MB: Final[int] = 8192

            ENCODING_CONFIDENCE_THRESHOLD: Final[float] = 0.7

            MIN_BATCH_SIZE: Final[int] = 1
            MAX_BATCH_SIZE: Final[int] = (
                FlextConstants.Performance.BatchProcessing.MAX_ITEMS
            )

            PERFORMANCE_MEMORY_MB_THRESHOLD: Final[int] = 512
            DEBUG_MAX_WORKERS: Final[int] = 2
            SMALL_ENTRY_COUNT_THRESHOLD: Final[int] = 100
            MEDIUM_ENTRY_COUNT_THRESHOLD: Final[int] = 1000
            MIN_ATTRIBUTE_PARTS: Final[int] = 2

            ASCII_SPACE_CHAR: Final[int] = 32
            ASCII_TILDE_CHAR: Final[int] = 126
            ASCII_DEL_CHAR: Final[int] = 127
            ASCII_NON_ASCII_START: Final[int] = 128
            DN_TRUNCATE_LENGTH: Final[int] = 100
            DN_LOG_PREVIEW_LENGTH: Final[int] = 80
            ACI_PREVIEW_LENGTH: Final[int] = 200
            ACI_LIST_PREVIEW_LIMIT: Final[int] = 3

            DEFAULT_SEARCH_TIME_LIMIT: Final[int] = 30
            DEFAULT_SEARCH_SIZE_LIMIT: Final[int] = 0

            LDIF_VERSION: Final[str] = "0.9.9"
            LDIF_VERSION_INFO: Final[tuple[int, int, int]] = (0, 9, 9)

            MAX_PATH_LENGTH_CHECK: Final[int] = 500
            MAX_LOGGED_ERRORS: Final[int] = 5

        class ConfigDefaults:
            """Default values for FlextLdifSettings fields."""

            LDIF_SKIP_COMMENTS: Final[bool] = False
            LDIF_VALIDATE_DN_FORMAT: Final[bool] = True
            LDIF_STRICT_VALIDATION: Final[bool] = True
            LDIF_LINE_SEPARATOR: Final[str] = "\n"
            LDIF_VERSION_STRING: Final[str] = "version: 1"

            LDIF_DEFAULT_ENCODING: Final[str] = (
                FlextConstants.Utilities.DEFAULT_ENCODING
            )

            LDIF_MAX_ENTRIES: Final[int] = 1000000
            ENABLE_PERFORMANCE_OPTIMIZATIONS: Final[bool] = True
            ENABLE_PARALLEL_PROCESSING: Final[bool] = True

            LDIF_ENABLE_ANALYTICS: Final[bool] = True
            LDIF_FAIL_ON_WARNINGS: Final[bool] = False
            LDIF_ANALYTICS_SAMPLE_RATE: Final[float] = 1.0
            LDIF_ANALYTICS_MAX_ENTRIES: Final[int] = 10000
            ANALYTICS_DETAIL_LEVEL_LOW: Final[str] = "low"
            ANALYTICS_DETAIL_LEVEL_MEDIUM: Final[str] = "medium"
            ANALYTICS_DETAIL_LEVEL_HIGH: Final[str] = "high"

            LDIF_SERVER_SPECIFICS: Final[bool] = True
            STRICT_RFC_COMPLIANCE: Final[bool] = True

            ERROR_RECOVERY_MODE_CONTINUE: Final[str] = "continue"

            DEBUG_MODE: Final[bool] = False
            VERBOSE_LOGGING: Final[bool] = False

        class QualityAnalysis:
            """Quality analysis threshold constants."""

            QUALITY_THRESHOLD_MEDIUM: Final[float] = 0.8
            MIN_DN_COMPONENTS_FOR_BASE_PATTERN: Final[int] = 2

        class LdifGeneralValidation:
            """General validation constants."""

            NAME_LENGTH_MIN: Final[int] = 1
            NAME_LENGTH_MAX: Final[int] = 255

        class LdifValidation:
            """LDIF-specific validation rules and constraints."""

            MIN_DN_COMPONENTS: Final[int] = 1

            MAX_DN_LENGTH: Final[int] = 2048

            MAX_ATTRIBUTES_PER_ENTRY: Final[int] = 1000
            MAX_VALUES_PER_ATTRIBUTE: Final[int] = 100
            MAX_ATTRIBUTE_VALUE_LENGTH: Final[int] = 10000

            MIN_ATTRIBUTE_NAME_LENGTH: Final[int] = 1
            MAX_ATTRIBUTE_NAME_LENGTH: Final[int] = 127
            ATTRIBUTE_NAME_PATTERN: Final[str] = r"^[a-zA-Z][a-zA-Z0-9-]*$"

            MIN_URL_LENGTH: Final[int] = 1
            MAX_URL_LENGTH: Final[int] = 2048
            URL_PATTERN: Final[str] = r"^(https?|ldap)://[^\s/$.?#].[^\s]*$"

            MIN_ENCODING_LENGTH: Final[int] = 1
            MAX_ENCODING_LENGTH: Final[int] = 50

            MIN_LDIF_LINE_PARTS: Final[int] = 2

        class ObjectClasses:
            """LDAP object class name constants (RFC 4512 standard classes)."""

            TOP: Final[str] = "top"
            ORGANIZATIONAL_PERSON: Final[str] = "organizationalPerson"
            INET_ORG_PERSON: Final[str] = "inetOrgPerson"
            GROUP_OF_NAMES: Final[str] = "groupOfNames"
            GROUP_OF_UNIQUE_NAMES: Final[str] = "groupOfUniqueNames"
            POSIX_GROUP: Final[str] = "posixGroup"
            ORGANIZATION: Final[str] = "organization"
            DOMAIN: Final[str] = "domain"

            COUNTRY: Final[str] = "country"
            LOCALITY: Final[str] = "locality"

        class RfcBinaryAttributes:
            """RFC 4517 Binary attribute names that typically require ;binary option."""

            USER_CERTIFICATE: Final[str] = "usercertificate"
            CA_CERTIFICATE: Final[str] = "cacertificate"
            CERTIFICATE_REVOCATION_LIST: Final[str] = "certificaterevocationlist"
            AUTHORITY_REVOCATION_LIST: Final[str] = "authorityrevocationlist"
            CROSS_CERTIFICATE_PAIR: Final[str] = "crosscertificatepair"

            PHOTO: Final[str] = "photo"
            JPEG_PHOTO: Final[str] = "jpegphoto"

            USER_PKCS12: Final[str] = "userpkcs12"
            USER_SMIME_CERTIFICATE: Final[str] = "usersmimecertificate"

            THUMBNAIL_PHOTO: Final[str] = "thumbnailphoto"
            THUMBNAIL_LOGO: Final[str] = "thumbnaillogo"
            OBJECT_GUID: Final[str] = "objectguid"
            OBJECT_SID: Final[str] = "objectsid"

            class BinaryAttribute(StrEnum):
                """RFC 4517/4523/4524 - Binary attributes requiring ;binary option."""

                USER_CERTIFICATE = "usercertificate"
                CA_CERTIFICATE = "cacertificate"
                CERTIFICATE_REVOCATION_LIST = "certificaterevocationlist"
                AUTHORITY_REVOCATION_LIST = "authorityrevocationlist"
                CROSS_CERTIFICATE_PAIR = "crosscertificatepair"
                PHOTO = "photo"
                JPEG_PHOTO = "jpegphoto"
                AUDIO = "audio"
                USER_PKCS12 = "userpkcs12"
                USER_SMIME_CERTIFICATE = "usersmimecertificate"
                THUMBNAIL_PHOTO = "thumbnailphoto"
                THUMBNAIL_LOGO = "thumbnaillogo"
                OBJECT_GUID = "objectguid"
                OBJECT_SID = "objectsid"

            BINARY_ATTRIBUTE_NAMES: Final[frozenset[str]] = frozenset([
                BinaryAttribute.USER_CERTIFICATE,
                BinaryAttribute.CA_CERTIFICATE,
                BinaryAttribute.CERTIFICATE_REVOCATION_LIST,
                BinaryAttribute.AUTHORITY_REVOCATION_LIST,
                BinaryAttribute.CROSS_CERTIFICATE_PAIR,
                BinaryAttribute.PHOTO,
                BinaryAttribute.JPEG_PHOTO,
                BinaryAttribute.AUDIO,
                BinaryAttribute.USER_PKCS12,
                BinaryAttribute.USER_SMIME_CERTIFICATE,
                BinaryAttribute.THUMBNAIL_PHOTO,
                BinaryAttribute.THUMBNAIL_LOGO,
                BinaryAttribute.OBJECT_GUID,
                BinaryAttribute.OBJECT_SID,
            ])

        class ServerValidationRules:
            """Server-specific validation rules for Entry model validators."""

            OBJECTCLASS_REQUIRED_SERVERS: ClassVar[frozenset[str]] = frozenset([
                "oid",
                "oud",
                "ad",
                "389ds",
                "novell_edirectory",
                "ibm_tivoli",
            ])

            NAMING_ATTR_REQUIRED_SERVERS: ClassVar[frozenset[str]] = frozenset([
                "oid",
                "oud",
                "ad",
            ])

            BINARY_OPTION_REQUIRED_SERVERS: ClassVar[frozenset[str]] = frozenset([
                "openldap",
                "oid",
                "oud",
            ])

            SCHEMA_ENTRY_PATTERNS: ClassVar[Mapping[str, Sequence[str]]] = (
                MappingProxyType({
                    "rfc": ("cn=schema",),
                    "oid": ("cn=schema", "cn=subschema"),
                    "oud": ("cn=schema",),
                    "openldap": ("cn=schema", "cn=subschema"),
                    "openldap1": ("cn=schema",),
                    "ad": ("cn=schema", "cn=aggregate"),
                    "389ds": ("cn=schema",),
                    "apache_directory": ("ou=schema",),
                    "novell_edirectory": ("cn=schema",),
                    "ibm_tivoli": ("cn=schema",),
                    "relaxed": (
                        "cn=schema",
                        "cn=subschema",
                        "ou=schema",
                    ),
                })
            )

            SERVER_BINARY_ATTRIBUTES: ClassVar[Mapping[str, frozenset[str]]] = (
                MappingProxyType({
                    "oid": frozenset(
                        [
                            "orclguid",
                            "userpassword",
                        ],
                    ),
                    "oud": frozenset(
                        [
                            "ds-sync-hist",
                            "ds-sync-state",
                        ],
                    ),
                    "ad": frozenset(
                        [
                            "objectguid",
                            "objectsid",
                            "msexchmailboxguid",
                            "msexchmailboxsecuritydescriptor",
                        ],
                    ),
                    "openldap": frozenset(
                        [
                            "entryuuid",
                        ],
                    ),
                })
            )

            OPERATIONAL_ATTRIBUTES: ClassVar[Mapping[str, frozenset[str]]] = (
                MappingProxyType({
                    "oid": frozenset(
                        [
                            "orclguid",
                            "createtimestamp",
                            "modifytimestamp",
                            "creatorsname",
                            "modifiersname",
                        ],
                    ),
                    "oud": frozenset(
                        [
                            "entryuuid",
                            "ds-sync-generation-id",
                            "ds-sync-state",
                            "createtimestamp",
                            "modifytimestamp",
                        ],
                    ),
                    "ad": frozenset(
                        [
                            "objectguid",
                            "objectsid",
                            "whencreated",
                            "whenchanged",
                            "usnchanged",
                            "usncreated",
                        ],
                    ),
                    "openldap": frozenset(
                        [
                            "entryuuid",
                            "entrycsn",
                            "createtimestamp",
                            "modifytimestamp",
                            "creatorsname",
                            "modifiersname",
                        ],
                    ),
                })
            )

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

        class TransformationType(StrEnum):
            """Types of transformations applied to entries."""

            DN_CLEANED = "dn_cleaned"
            DN_NORMALIZED = "dn_normalized"
            TAB_NORMALIZED = "tab_normalized"
            SPACE_CLEANED = "space_cleaned"
            UTF8_DECODED = "utf8_decoded"
            BASE64_DECODED = "base64_decoded"
            TRAILING_SPACE_REMOVED = "trailing_space_removed"
            ESCAPE_NORMALIZED = "escape_normalized"

            BOOLEAN_CONVERTED = "boolean_converted"
            ACL_CONVERTED = "acl_converted"
            ATTRIBUTE_REMOVED = "attribute_removed"
            ATTRIBUTE_ADDED = "attribute_added"
            ATTRIBUTE_RENAMED = "attribute_renamed"
            MODIFIED = "modified"

            MATCHING_RULE_REPLACED = "matching_rule_replaced"
            SYNTAX_OID_REPLACED = "syntax_oid_replaced"
            OBJECTCLASS_FILTERED = "objectclass_filtered"

        class FilterType(StrEnum):
            """Types of filters applied to entries."""

            BASE_DN_FILTER = "base_dn_filter"
            SCHEMA_WHITELIST = "schema_whitelist"
            FORBIDDEN_ATTRIBUTES = "forbidden_attributes"
            FORBIDDEN_OBJECTCLASSES = "forbidden_objectclasses"
            OPERATIONAL_ATTRIBUTES = "operational_attributes"
            ACL_EXTRACTION = "acl_extraction"
            SCHEMA_ENTRY = "schema_entry"

        class ValidationStatus(StrEnum):
            """Entry validation status levels."""

            VALID = "valid"
            WARNING = "warning"
            ERROR = "error"
            REJECTED = "rejected"

        class RejectionCategory(StrEnum):
            """Categories for entry rejection."""

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
            """Categories of errors that can occur during processing."""

            PARSING = "parsing"
            VALIDATION = "validation"
            CONVERSION = "conversion"
            SYNC = "sync"
            SCHEMA = "schema"
            ACL = "acl"
            MODRDN = "modrdn"

        class AttributeMarkerStatus(StrEnum):
            """Marker status for attribute processing in metadata."""

            NORMAL = "normal"

            MARKED_FOR_REMOVAL = "marked_for_removal"

            FILTERED = "filtered"

            OPERATIONAL = "operational"

            HIDDEN = "hidden"

            RENAMED = "renamed"

        class ServerTypes(StrEnum):
            """Server type identifiers - Single source of truth for all server types."""

            OID = "oid"
            OUD = "oud"
            OPENLDAP = "openldap"
            OPENLDAP1 = "openldap1"
            OPENLDAP2 = "openldap2"
            AD = "ad"
            APACHE = "apache"
            DS389 = "ds389"
            RFC = "rfc"
            RELAXED = "relaxed"
            NOVELL = "novell"
            IBM_TIVOLI = "ibm_tivoli"
            GENERIC = "generic"

        class LiteralTypes:
            """Literal type constants for type annotations."""

            PROCESSING_STAGES: Final[tuple[str, ...]] = (
                "parsing",
                "validation",
                "analytics",
                "writing",
            )

            HEALTH_STATUS: Final[tuple[str, ...]] = ("healthy", "degraded", "unhealthy")

            ENTRY_TYPES: Final[tuple[str, ...]] = (
                "person",
                "group",
                "organizationalunit",
                "domain",
                "other",
            )

            MODIFICATION_TYPES: Final[tuple[str, ...]] = (
                "add",
                "modify",
                "delete",
                "modrdn",
            )

            ENCODING_TYPES: Final[tuple[str, ...]] = (
                "utf-8",
                "utf-16-le",
                "utf-16",
                "utf-32",
                "ascii",
                "latin-1",
                "cp1252",
                "iso-8859-1",
            )

            SCOPE: Final[tuple[str, ...]] = (
                "base",
                "one",
                "onelevel",
                "sub",
                "subtree",
            )

            VALIDATION_LEVELS: Final[tuple[str, ...]] = (
                "strict",
                "moderate",
                "lenient",
            )

            ANALYTICS_DETAIL_LEVELS: Final[tuple[str, ...]] = ("low", "medium", "high")

            DETECTION_MODES: Final[tuple[str, ...]] = ("auto", "manual", "disabled")

            ERROR_RECOVERY_MODES: Final[tuple[str, ...]] = ("continue", "stop", "skip")

            ATTRIBUTE_OUTPUT_MODES: Final[tuple[str, ...]] = ("show", "hide", "comment")

            ATTRIBUTE_MARKER_STATUSES: Final[tuple[str, ...]] = (
                "normal",
                "marked_for_removal",
                "filtered",
                "operational",
                "hidden",
                "renamed",
            )

            PROJECT_TYPES: Final[tuple[str, ...]] = (
                "library",
                "application",
                "service",
                "tool",
                "migration",
                "validation",
                "analysis",
            )

            HEALTH_STATUSES: Final[tuple[str, ...]] = (
                "healthy",
                "degraded",
                "unhealthy",
            )

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

            type ServerTypeLiteral = Literal[
                "oid",
                "oud",
                "openldap",
                "openldap1",
                "openldap2",
                "ad",
                "apache",
                "ds389",
                "rfc",
                "relaxed",
                "novell",
                "ibm_tivoli",
                "generic",
            ]

            type TransformationTypeLiteral = Literal[
                "dn_cleaned",
                "dn_normalized",
                "tab_normalized",
                "space_cleaned",
                "utf8_decoded",
                "base64_decoded",
                "trailing_space_removed",
                "escape_normalized",
                "boolean_converted",
                "acl_converted",
                "attribute_removed",
                "attribute_added",
                "attribute_renamed",
                "modified",
                "matching_rule_replaced",
                "syntax_oid_replaced",
                "objectclass_filtered",
                "removed",
                "renamed",
                "basedn_transform",
            ]

            type EncodingLiteral = Literal[
                "utf-8",
                "utf-16-le",
                "utf-16",
                "utf-32",
                "ascii",
                "latin-1",
                "cp1252",
                "iso-8859-1",
            ]

            type ChangeTypeLiteral = Literal[
                "add",
                "delete",
                "modify",
                "modrdn",
                "moddn",
            ]

            type ModifyOperationLiteral = Literal["add", "delete", "replace"]

            type AclSubjectTypeLiteral = Literal[
                "user",
                "group",
                "role",
                "self",
                "all",
                "public",
                "anonymous",
                "authenticated",
                "sddl",
                "dn",
            ]

            type AttributeMarkerStatusLiteral = Literal[
                "normal",
                "marked_for_removal",
                "filtered",
                "operational",
                "hidden",
                "renamed",
            ]

            type AnalyticsDetailLevelLiteral = Literal["low", "medium", "high"]

            type CategoryLiteral = Literal[
                "all",
                "users",
                "groups",
                "hierarchy",
                "schema",
                "acl",
                "rejected",
            ]

            type DetectionModeLiteral = Literal["auto", "manual", "disabled"]

            type ErrorRecoveryModeLiteral = Literal["continue", "stop", "skip"]

            type ValidationLevelLiteral = Literal["strict", "moderate", "lenient"]

        class LdapServers:
            """LDAP server implementation constants."""

            ACTIVE_DIRECTORY: Final = "ad"
            OPENLDAP: Final = "openldap"
            OPENLDAP_2: Final = "openldap2"
            OPENLDAP_1: Final = "openldap1"
            APACHE_DIRECTORY: Final = "apache"
            NOVELL_EDIRECTORY: Final = "novell"
            IBM_TIVOLI: Final = "ibm_tivoli"
            GENERIC: Final = "generic"
            ORACLE_OID: Final = "oid"
            ORACLE_OUD: Final = "oud"
            DS_389: Final = "ds389"

        class RfcCompliance:
            """RFC 2849 compliance validation constants."""

            LINE_LENGTH_LIMIT: Final[int] = 76
            LINE_WITH_NEWLINE: Final[int] = LINE_LENGTH_LIMIT + 1

            MODERATE: Final[str] = "moderate"

        class Acl:
            """ACL-related constants - RFC 4876 baseline ONLY."""

            SPECIAL_MATCH_MIN_SIZE: Final[int] = 2

            GRANT: Final[str] = "grant"
            DENY: Final[str] = "deny"
            ALLOW: Final[str] = "allow"

            READ: Final[str] = "read"
            WRITE: Final[str] = "write"
            SEARCH: Final[str] = "search"
            COMPARE: Final[str] = "compare"
            ADD: Final[str] = "add"
            DELETE: Final[str] = "delete"
            MODIFY: Final[str] = "modify"

            SELF_WRITE: Final[str] = "self_write"
            PROXY: Final[str] = "proxy"

        class AclSubjectTypes:
            """ACL subject type identifiers for permission subjects."""

            ROLE: Final[str] = "role"
            SELF: Final[str] = "self"
            PUBLIC: Final[str] = "public"
            ANONYMOUS: Final[str] = "anonymous"
            AUTHENTICATED: Final[str] = "authenticated"

            class Schema:
                """Schema-related constants."""

            OBJECTCLASS: Final[str] = "objectclass"
            ATTRIBUTE: Final[str] = "attribute"
            SYNTAX: Final[str] = "syntax"
            MATCHINGRULE: Final[str] = "matchingrule"

            ACTIVE: Final[str] = "active"
            DEPRECATED: Final[str] = "deprecated"

            STRUCTURAL: Final[str] = "STRUCTURAL"
            AUXILIARY: Final[str] = "AUXILIARY"
            ABSTRACT: Final[str] = "ABSTRACT"

        class OperationalAttributes:
            """Operational (server-generated) attributes by server type."""

        class SchemaFields:
            """LDIF schema structure field names (case-sensitive)."""

            ATTRIBUTE_TYPES: Final[str] = "attributeTypes"
            OBJECT_CLASSES: Final[str] = "objectClasses"
            MATCHING_RULES: Final[str] = "matchingRules"
            MATCHING_RULE_USE: Final[str] = "matchingRuleUse"
            DIT_CONTENT_RULES: Final[str] = "dITContentRules"
            DIT_STRUCTURE_RULES: Final[str] = "dITStructureRules"
            NAME_FORMS: Final[str] = "nameForms"
            LDAP_SYNTAXES: Final[str] = "ldapSyntaxes"

            ATTRIBUTE_TYPES_LOWER: Final[str] = "attributetypes"
            OBJECT_CLASSES_LOWER: Final[str] = "objectclasses"

            OBJECT_CLASS_CAMEL: Final[str] = "objectClass"

        class AclAttributes:
            """RFC baseline ACL attribute names for LDAP."""

            ACLRIGHTS: Final[str] = "aclrights"
            ACLENTRY: Final[str] = "aclentry"

            DEFAULT_ACL_ATTRIBUTES: Final[list[str]] = [
                "acl",
                "aci",
                "olcAccess",
            ]

        class DnValuedAttributes:
            """Attributes that contain Distinguished Names as values."""

            MEMBER: Final[str] = "member"
            UNIQUE_MEMBER: Final[str] = "uniqueMember"
            OWNER: Final[str] = "owner"
            MANAGED_BY: Final[str] = "managedBy"
            MANAGER: Final[str] = "manager"
            SECRETARY: Final[str] = "secretary"
            SEES_ALSO: Final[str] = "seeAlso"

            PARENT: Final[str] = "parent"
            REFERS_TO: Final[str] = "refersTo"

            MEMBER_OF: Final[str] = "memberOf"
            GROUPS: Final[str] = "groups"

            AUTHORIZED_TO: Final[str] = "authorizedTo"
            HAS_SUBORDINATES: Final[str] = "hasSubordinates"
            SUBORDINATE_DN: Final[str] = "subordinateDn"

            class DnValuedAttribute(StrEnum):
                """Attributes that contain Distinguished Names as values."""

                MEMBER = "member"
                UNIQUE_MEMBER = "uniqueMember"
                OWNER = "owner"
                MANAGED_BY = "managedBy"
                MANAGER = "manager"
                SECRETARY = "secretary"
                SEES_ALSO = "seeAlso"
                PARENT = "parent"
                REFERS_TO = "refersTo"
                MEMBER_OF = "memberOf"
                GROUPS = "groups"
                AUTHORIZED_TO = "authorizedTo"
                HAS_SUBORDINATES = "hasSubordinates"
                SUBORDINATE_DN = "subordinateDn"

            ALL_DN_VALUED: Final[frozenset[str]] = frozenset([
                DnValuedAttribute.MEMBER,
                DnValuedAttribute.UNIQUE_MEMBER,
                DnValuedAttribute.OWNER,
                DnValuedAttribute.MANAGED_BY,
                DnValuedAttribute.MANAGER,
                DnValuedAttribute.SECRETARY,
                DnValuedAttribute.SEES_ALSO,
                DnValuedAttribute.PARENT,
                DnValuedAttribute.REFERS_TO,
                DnValuedAttribute.MEMBER_OF,
                DnValuedAttribute.GROUPS,
                DnValuedAttribute.AUTHORIZED_TO,
                DnValuedAttribute.HAS_SUBORDINATES,
                DnValuedAttribute.SUBORDINATE_DN,
            ])

        class BooleanFormats:
            """Boolean value representations and conversions across LDAP servers."""

            TRUE_RFC: Final[str] = "TRUE"
            FALSE_RFC: Final[str] = "FALSE"

            TRUE_LOWER: Final[str] = "true"
            FALSE_LOWER: Final[str] = "false"

        class MetadataKeys:
            """Metadata extension keys used in quirk processing and entry transformations."""

            PROXY_PERMISSIONS: Final[str] = "proxy_permissions"
            SELF_WRITE_TO_WRITE: Final[str] = "self_write_to_write"

            SCHEMA_ORIGINAL_FORMAT: Final[str] = "schema_original_format"
            SCHEMA_ORIGINAL_STRING_COMPLETE: Final[str] = (
                "schema_original_string_complete"
            )
            SCHEMA_SOURCE_SERVER: Final[str] = "schema_source_server"

            SCHEMA_SYNTAX_QUOTES: Final[str] = "schema_syntax_quotes"
            SCHEMA_SYNTAX_SPACING: Final[str] = "schema_syntax_spacing"
            SCHEMA_SYNTAX_SPACING_BEFORE: Final[str] = "schema_syntax_spacing_before"
            SCHEMA_ATTRIBUTE_CASE: Final[str] = "schema_attribute_case"
            SCHEMA_OBJECTCLASS_CASE: Final[str] = "schema_objectclass_case"
            SCHEMA_NAME_FORMAT: Final[str] = "schema_name_format"
            SCHEMA_NAME_VALUES: Final[str] = "schema_name_values"
            SCHEMA_X_ORIGIN_PRESENCE: Final[str] = "schema_x_origin_presence"
            SCHEMA_X_ORIGIN_VALUE: Final[str] = "schema_x_origin_value"
            SCHEMA_OBSOLETE_PRESENCE: Final[str] = "schema_obsolete_presence"
            SCHEMA_OBSOLETE_POSITION: Final[str] = "schema_obsolete_position"
            OBSOLETE: Final[str] = "obsolete"
            SCHEMA_FIELD_ORDER: Final[str] = "schema_field_order"
            SCHEMA_SPACING_BETWEEN_FIELDS: Final[str] = "schema_spacing_between_fields"
            SCHEMA_TRAILING_SPACES: Final[str] = "schema_trailing_spaces"
            SCHEMA_SOURCE_SYNTAX_OID: Final[str] = "schema_source_syntax_oid"
            SCHEMA_TARGET_SYNTAX_OID: Final[str] = "schema_target_syntax_oid"
            SCHEMA_SOURCE_MATCHING_RULES: Final[str] = "schema_source_matching_rules"
            SCHEMA_TARGET_MATCHING_RULES: Final[str] = "schema_target_matching_rules"
            SCHEMA_SOURCE_ATTRIBUTE_NAME: Final[str] = "schema_source_attribute_name"
            SCHEMA_TARGET_ATTRIBUTE_NAME: Final[str] = "schema_target_attribute_name"

            SYNTAX_OID_VALID: Final[str] = "syntax_oid_valid"
            SYNTAX_VALIDATION_ERROR: Final[str] = "syntax_validation_error"
            X_ORIGIN: Final[str] = "x_origin"
            COLLECTIVE: Final[str] = "collective"

            ENTRY_ORIGINAL_FORMAT: Final[str] = "entry_original_format"
            ENTRY_SOURCE_SERVER: Final[str] = "entry_source_server"
            ENTRY_SOURCE_ATTRIBUTES: Final[str] = "entry_source_attributes"
            ENTRY_TARGET_ATTRIBUTES: Final[str] = "entry_target_attributes"
            ENTRY_SOURCE_OBJECTCLASSES: Final[str] = "entry_source_objectclasses"
            ENTRY_TARGET_OBJECTCLASSES: Final[str] = "entry_target_objectclasses"
            ENTRY_SOURCE_OPERATIONAL_ATTRS: Final[str] = (
                "entry_source_operational_attrs"
            )
            ENTRY_TARGET_OPERATIONAL_ATTRS: Final[str] = (
                "entry_target_operational_attrs"
            )
            ENTRY_SOURCE_DN_CASE: Final[str] = "entry_source_dn_case"
            ENTRY_TARGET_DN_CASE: Final[str] = "entry_target_dn_case"

            BASE64_ATTRS: Final[str] = "_base64_attrs"
            MODIFY_ADD_ATTRIBUTETYPES: Final[str] = "_modify_add_attributetypes"
            MODIFY_ADD_OBJECTCLASSES: Final[str] = "_modify_add_objectclasses"
            SKIPPED_ATTRIBUTES: Final[str] = "_skipped_attributes"
            CONVERTED_ATTRIBUTES: Final[str] = "converted_attributes"

            ACL_ORIGINAL_FORMAT: Final[str] = "original_format"
            ACL_SOURCE_SERVER: Final[str] = "source_server"
            ACL_SOURCE_SUBJECT_TYPE: Final[str] = "source_subject_type"
            ACL_TARGET_SUBJECT_TYPE: Final[str] = "target_subject_type"
            ACL_ORIGINAL_SUBJECT_VALUE: Final[str] = "original_subject_value"
            ACL_SOURCE_PERMISSIONS: Final[str] = "source_permissions"
            ACL_TARGET_PERMISSIONS: Final[str] = "target_permissions"
            ACL_ACTION_TYPE: Final[str] = "action_type"
            ACL_NEGATIVE_PERMISSIONS: Final[str] = "negative_permissions"

            ACL_FILTER: Final[str] = "filter"
            ACL_CONSTRAINT: Final[str] = "added_object_constraint"
            ACL_BINDMODE: Final[str] = "bindmode"
            ACL_DENY_GROUP_OVERRIDE: Final[str] = "deny_group_override"
            ACL_APPEND_TO_ALL: Final[str] = "append_to_all"
            ACL_BIND_IP_FILTER: Final[str] = "bind_ip_filter"
            ACL_BIND_IP: Final[str] = ACL_BIND_IP_FILTER
            ACL_CONSTRAIN_TO_ADDED_OBJECT: Final[str] = "constrain_to_added_object"

            ACL_DN_ATTR: Final[str] = "dn_attr"
            ACL_GUID_ATTR: Final[str] = "guid_attr"
            ACL_GROUP_ATTR: Final[str] = "group_attr"

            ACL_BROWSE_EXPANDED: Final[str] = "browse_expanded"
            ACL_SELFWRITE_NORMALIZED: Final[str] = "selfwrite_normalized"

            ACL_TARGETSCOPE: Final[str] = "targetscope"
            ACL_VERSION: Final[str] = "version"
            ACL_DN_SPACES: Final[str] = "dn_spaces"
            ACL_LINE_BREAKS: Final[str] = "line_breaks"
            ACL_IS_MULTILINE: Final[str] = "is_multiline"

            ACL_NUMBERING: Final[str] = "numbering"
            ACL_SSFS: Final[str] = "ssfs"

            ACL_TARGETATTR_FILTERS: Final[str] = "targattrfilters"
            ACL_TARGET_CONTROL: Final[str] = "targetcontrol"
            ACL_EXTOP: Final[str] = "extop"
            ACL_BIND_DNS: Final[str] = "bind_dns"
            ACL_BIND_DAYOFWEEK: Final[str] = "bind_dayofweek"
            ACL_BIND_TIMEOFDAY: Final[str] = "bind_timeofday"
            ACL_AUTHMETHOD: Final[str] = "authmethod"
            ACL_SSF: Final[str] = "ssf"

            ACL_NAME_SANITIZED: Final[str] = "name_sanitized"
            ACL_ORIGINAL_NAME_RAW: Final[str] = "original_name_raw"

            ACL_SDDL: Final[str] = "sddl"
            ACL_BINARY_SD: Final[str] = "binary_sd"

            CONVERTED_FROM_SERVER: Final[str] = "converted_from_server"
            CONVERSION_COMMENTS: Final[str] = "conversion_comments"

            ORIGINAL_FORMAT: Final[str] = "original_format"
            ORIGINAL_SOURCE: Final[str] = "original_source"

            VERSION: Final[str] = "version"
            LINE_BREAKS: Final[str] = "line_breaks"
            IS_MULTILINE: Final[str] = "is_multiline"
            DN_SPACES: Final[str] = "dn_spaces"
            TARGETSCOPE: Final[str] = "targetscope"
            ATTRIBUTE_ORDER: Final[str] = "attribute_order"
            SUBJECT_BINDING: Final[str] = "subject_binding"

            SORTING_NEW_ATTRIBUTE_ORDER: Final[str] = "sorting_new_attribute_order"
            SORTING_STRATEGY: Final[str] = "sorting_strategy"
            SORTING_CUSTOM_ORDER: Final[str] = "sorting_custom_order"
            SORTING_ORDERED_ATTRIBUTES: Final[str] = "sorting_ordered_attributes"
            SORTING_REMAINING_ATTRIBUTES: Final[str] = "sorting_remaining_attributes"
            SORTING_ACL_ATTRIBUTES: Final[str] = "sorting_acl_attributes"
            SORTING_ACL_SORTED: Final[str] = "sorting_acl_sorted"

            PARSED_TIMESTAMP: Final[str] = "parsed_timestamp"
            SOURCE_FILE: Final[str] = "source_file"
            HIDDEN_ATTRIBUTES: Final[str] = "hidden_attributes"

            METADATA: Final[str] = "_metadata"
            ACL_ATTRIBUTES: Final[str] = "_acl_attributes"
            HAS_SYNTAX_EXTENSIONS: Final[str] = "_has_syntax_extensions"
            REQUIRES_RFC_TRANSLATION: Final[str] = "_requires_rfc_translation"
            IS_RELAXED_PARSED: Final[str] = "_is_relaxed_parsed"

            OID_SUBJECT_TYPE: Final[str] = "oid_subject_type"
            OUD_SUBJECT_TYPE: Final[str] = "oud_subject_type"
            RFC_SUBJECT_TYPE: Final[str] = "rfc_subject_type"
            ORIGINAL_SUBJECT_VALUE: Final[str] = "original_subject_value"
            ORIGINAL_ENTRY: Final[str] = "original_entry"
            REMOVED_ATTRIBUTES: Final[str] = "removed_attributes"
            REMOVED_ATTRIBUTES_WITH_VALUES: Final[str] = (
                "removed_attributes_with_values"
            )

            MINIMAL_DIFFERENCES_DN: Final[str] = "minimal_differences_dn"
            MINIMAL_DIFFERENCES_ATTRIBUTES: Final[str] = (
                "minimal_differences_attributes"
            )
            HAS_DIFFERENCES: Final[str] = "has_differences"
            ORIGINAL_DN_COMPLETE: Final[str] = "original_dn_complete"
            ORIGINAL_ATTRIBUTES_COMPLETE: Final[str] = "original_attributes_complete"
            ORIGINAL_DN_LINE_COMPLETE: Final[str] = "original_dn_line_complete"
            ORIGINAL_ATTR_LINES_COMPLETE: Final[str] = "original_attr_lines_complete"

            WRITE_OPTIONS: Final[str] = "_write_options"

            CONVERSION_BOOLEAN_CONVERSIONS: Final[str] = "boolean_conversions"
            CONVERSION_ATTRIBUTE_NAME_CONVERSIONS: Final[str] = (
                "attribute_name_conversions"
            )
            CONVERSION_CONVERTED_ATTRIBUTE_NAMES: Final[str] = (
                "converted_attribute_names"
            )
            CONVERSION_ORIGINAL_VALUE: Final[str] = "original"
            CONVERSION_CONVERTED_VALUE: Final[str] = "converted"

            LEGACY_OID_BOOLEAN_CONVERSIONS_KEY: Final[str] = "oid_boolean_conversions"

        class DnPatterns:
            """Standard DN patterns used in LDAP/LDIF processing."""

            CN_SCHEMA: Final[str] = "cn=schema"
            CN_SUBSCHEMA: Final[str] = "cn=subschema"
            CN_SUBSCHEMA_SUBENTRY: Final[str] = "cn=subschemasubentry"
            CN_SCHEMA_CN_CONFIG: Final[str] = "cn=schema,cn=configuration"

            CN_SUBSCHEMASUBENTRY: Final[str] = "cn=subschemasubentry"

            CN_SCHEMA_CN_CONFIGURATION: Final[str] = "cn=schema,cn=configuration"

            CN_CONFIG: Final[str] = "cn=config"

            DN_EQUALS: Final[str] = "="
            DN_COMMA: Final[str] = ","
            DN_PLUS: Final[str] = "+"

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

            CN_PREFIX: Final[str] = "cn="
            OU_PREFIX: Final[str] = "ou="
            DC_PREFIX: Final[str] = "dc="
            UID_PREFIX: Final[str] = "uid="
            O_PREFIX: Final[str] = "o="
            L_PREFIX: Final[str] = "l="
            ST_PREFIX: Final[str] = "st="
            C_PREFIX: Final[str] = "c="

        class AclFormats:
            """ACL format identifier constants."""

            RFC_GENERIC: Final[str] = "rfc_generic"
            ACI: Final[str] = "aci"

            DEFAULT_ACL_FORMAT: Final[str] = ACI
            DEFAULT_ACL_ATTRIBUTE_NAME: Final[str] = ACI

        class ServerTypesMappings:
            """Server type mappings and aliases (separate from enum to avoid conflicts)."""

            _LONG_NAMES_DICT: ClassVar[dict[str, str]] = {
                "oid": "oid",
                "oud": "oud",
                "openldap": "openldap",
                "openldap1": "openldap1",
                "openldap2": "openldap2",
                "ad": "ad",
                "apache": "apache",
                "generic": "generic",
                "rfc": "rfc",
                "ds389": "ds389",
                "relaxed": "relaxed",
                "novell": "novell",
                "ibm_tivoli": "ibm_tivoli",
            }
            LONG_NAMES: Final[Mapping[str, str]] = MappingProxyType(_LONG_NAMES_DICT)

            _FROM_LONG_DICT: ClassVar[dict[str, str]] = {
                v: k for k, v in _LONG_NAMES_DICT.items()
            }
            FROM_LONG: Final[Mapping[str, str]] = MappingProxyType(_FROM_LONG_DICT)

            _ALIASES_DICT: ClassVar[dict[str, str]] = {
                "ad": "ad",
                "389": "ds389",
                "389ds": "ds389",
                "apache": "apache",
                "novell": "novell",
                "tivoli": "ibm_tivoli",
                "openldap": "openldap2",
                "active_directory": "ad",
                "apache_directory": "apache",
                "novell_edirectory": "novell",
                "ibm_tivoli": "ibm_tivoli",
                "oracle_oid": "oid",
                "oracle_oud": "oud",
            }
            ALIASES: Final[Mapping[str, str]] = MappingProxyType(_ALIASES_DICT)

        class ValidationMappings:
            """Immutable validation mappings using collections.abc.Mapping."""

            LDIF_FORMAT_VALIDATION_MAP: Final[Mapping[str, str]] = MappingProxyType({
                "RFC2849": "RFC2849",
                "EXTENDED": "EXTENDED",
                "CUSTOM": "CUSTOM",
            })

            SERVER_TYPE_VALIDATION_MAP: Final[Mapping[str, str]] = MappingProxyType({
                "oid": "oid",
                "oud": "oud",
                "openldap": "openldap",
                "openldap1": "openldap1",
                "openldap2": "openldap2",
                "active_directory": "active_directory",
                "apache_directory": "apache_directory",
                "generic": "generic",
                "rfc": "rfc",
                "389ds": "389ds",
                "relaxed": "relaxed",
                "novell_edirectory": "novell_edirectory",
                "ibm_tivoli": "ibm_tivoli",
            })

        class FilterTypes(StrEnum):
            """Filter type identifier constants."""

            OBJECTCLASS = "objectclass"
            DN_PATTERN = "dn_pattern"
            ATTRIBUTES = "attributes"
            SCHEMA_OID = "schema_oid"
            OID_PATTERN = "oid_pattern"
            ATTRIBUTE = "attribute"

        class Modes(StrEnum):
            """Operation mode constants."""

            INCLUDE = "include"
            EXCLUDE = "exclude"
            AUTO = "auto"
            MANUAL = "manual"
            DISABLED = "disabled"

        class DataTypes(StrEnum):
            """Data type identifier constants."""

            ATTRIBUTE = "attribute"
            OBJECTCLASS = "objectclass"
            ACL = "acl"
            ENTRY = "entry"
            SCHEMA = "schema"

        class RuleTypes:
            """ACL rule type constants."""

            COMPOSITE: Final[str] = "composite"
            PERMISSION: Final[str] = "permission"
            SUBJECT: Final[str] = "subject"
            TARGET: Final[str] = "target"

        class EntryTypes:
            """Entry type identifier constants."""

            OU: Final[str] = "ou"
            CUSTOM: Final[str] = "custom"

        class ConversionTypes:
            """Conversion type identifier constants."""

            ENTRY_TO_DICT: Final[str] = "entry_to_dict"
            ENTRIES_TO_DICTS: Final[str] = "entries_to_dicts"
            DICTS_TO_ENTRIES: Final[str] = "dicts_to_entries"
            ENTRIES_TO_JSON: Final[str] = "entries_to_json"
            JSON_TO_ENTRIES: Final[str] = "json_to_entries"

        class ProcessorTypes:
            """Processor type identifier constants."""

            TRANSFORM: Final[str] = "transform"
            VALIDATE: Final[str] = "validate"

        class MatchTypes:
            """Match type constants for filtering."""

            ANY: Final[str] = "any"

        class Scopes:
            """LDAP search scope constants."""

            ONE: Final[str] = "one"
            SUB: Final[str] = "sub"
            SUBORDINATE: Final[str] = "subordinate"

        class Parameters:
            """Parameter name constants."""

            FILE_PATH: Final[str] = "file_path"
            CONTENT: Final[str] = "content"
            PARSE_CHANGES: Final[str] = "parse_changes"
            PARSE_ATTRIBUTES: Final[str] = "parse_attributes"
            PARSE_OBJECTCLASSES: Final[str] = "parse_objectclasses"

        class LdifPatterns:
            """Regex pattern constants for LDIF processing."""

            XML_ENCODING: Final[str] = r'<\?xml[^>]*encoding=["\']([^"\']+)["\']'
            HTML_CHARSET: Final[str] = r'<meta[^>]*charset=["\']([^"\']+)["\']'
            PYTHON_CODING: Final[str] = r"#.*-\*-.*coding:\s*([^\s;]+)"
            LDIF_ENCODING: Final[str] = r"#\s*encoding:\s*([^\s\n]+)"

            DN_COMPONENT: Final[str] = r"^[a-zA-Z][a-zA-Z0-9-]*=(?:[^\\,]|\\.)*$"
            DN_SEPARATOR: Final[str] = r"(?<!\\),"

            LDAP_FILTER: Final[str] = r"^\(.*\)$"

            OBJECTCLASS_NAME: Final[str] = r"^[a-zA-Z][a-zA-Z0-9-]*$"

            ATTRIBUTE_NAME: Final[str] = r"^[a-zA-Z][a-zA-Z0-9-]*$"

            MAX_ATTRIBUTE_NAME_LENGTH: Final[int] = 127

            ATTRIBUTE_OPTION: Final[str] = r";[a-zA-Z][a-zA-Z0-9-_]*"

            OID_NUMERIC: Final[str] = r"^\d+(\.\d+)*$"
            OID_DESCRIPTOR: Final[str] = r"^[a-zA-Z][a-zA-Z0-9-]*$"

            SCHEMA_OID: Final[str] = r"^\s*\(\s*([\d.]+)"
            SCHEMA_OID_EXTRACTION: Final[str] = r"\(\s*([\d.]+)"

            SCHEMA_OID_EXTRACTION_START: Final[str] = r"^\s*\(\s*([0-9.]+)"
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

            SCHEMA_OBJECTCLASS_KIND: Final[str] = r"\b(ABSTRACT|STRUCTURAL|AUXILIARY)\b"
            SCHEMA_OBJECTCLASS_SUP: Final[str] = r"SUP\s+(?:\(\s*([^)]+)\s*\)|(\w+))"
            SCHEMA_OBJECTCLASS_MUST: Final[str] = r"MUST\s+(?:\(\s*([^)]+)\s*\)|(\w+))"
            SCHEMA_OBJECTCLASS_MAY: Final[str] = r"MAY\s+(?:\(\s*([^)]+)\s*\)|(\w+))"

        class ServerDetection:
            """Server type detection patterns and weights for LDIF content analysis."""

            DETECTION_THRESHOLD: Final[int] = 5
            CONFIDENCE_THRESHOLD: Final[float] = 0.6

            ATTRIBUTE_MATCH_SCORE: Final[int] = 2

            DEFAULT_MAX_LINES: Final[int] = 1000

            SCHEMA_FIELD_SUPERIOR: Final[str] = "superior"
            SCHEMA_FIELD_REQUIRED_ATTRIBUTES: Final[str] = "required_attributes"
            SCHEMA_FIELD_OPTIONAL_ATTRIBUTES: Final[str] = "optional_attributes"
            SCHEMA_FIELD_STRUCTURAL: Final[str] = "structural"

            SCHEMA_SUBENTRY_DN: Final[str] = "cn=subschemasubentry"
            ATTRIBUTE_TYPES_PREFIX: Final[str] = "attributetypes:"
            OBJECT_CLASSES_PREFIX: Final[str] = "objectclasses:"
            ATTRIBUTE_TYPES_PREFIX_LENGTH: Final[int] = len(ATTRIBUTE_TYPES_PREFIX)
            OBJECT_CLASSES_PREFIX_LENGTH: Final[int] = len(OBJECT_CLASSES_PREFIX)

            CONTENT_PARAMETER: Final[str] = "content"
            PARSE_CHANGES_PARAMETER: Final[str] = "parse_changes"
            DEFAULT_PARSE_CHANGES: Final[bool] = False

            ERROR_UNSUPPORTED_ENTRY_TYPE: Final[str] = "Unsupported entry type"
            ERROR_LDIF_WRITE_FAILED: Final[str] = "LDIF write failed"
            ERROR_FAILED_TO_WRITE: Final[str] = "Failed to write"

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

            MSG_LDIF_FILE_WRITTEN: Final[str] = "LDIF file written"
            MSG_LDIF_CONTENT_GENERATED: Final[str] = "LDIF content generated"
            MSG_AT_LEAST_ONE_REQUIRED: Final[str] = (
                "At least one of entries, schema, or acls must be provided"
            )

            ACL_WILDCARD_DN: Final[str] = "*"
            LDIF_FILE_EXTENSION: Final[str] = ".ldif"

            DEFAULT_ENTRY_COUNT: Final[int] = 0
            DEFAULT_SINGLE_VALUE: Final[bool] = False

            CHANGETYPE: Final[str] = r"^changetype:\s*(add|delete|modify|modrdn|moddn)$"

        class ChangeType(StrEnum):
            """LDIF change types for entry operations."""

            ADD = "add"
            DELETE = "delete"
            MODIFY = "modify"
            MODRDN = "modrdn"
            MODDN = "moddn"

        class ModifyOperation(StrEnum):
            """LDIF modify operation types."""

            ADD = "add"
            DELETE = "delete"
            REPLACE = "replace"

        class SchemaUsage(StrEnum):
            """RFC 4512 attribute usage types."""

            USER_APPLICATIONS = "userApplications"
            DIRECTORY_OPERATION = "directoryOperation"
            DISTRIBUTED_OPERATION = "distributedOperation"
            DSA_OPERATION = "dSAOperation"

        class SchemaKind(StrEnum):
            """RFC 4512 objectClass kind types."""

            ABSTRACT = "ABSTRACT"
            STRUCTURAL = "STRUCTURAL"
            AUXILIARY = "AUXILIARY"

        class LdapServerDetection:
            """Server-specific detection patterns and markers for LDAP servers."""

        class ValidationRules:
            """Validation rule constants."""

            MIN_WORKERS_PERFORMANCE_RULE: Final[int] = 4
            MIN_CHUNK_SIZE_PERFORMANCE_RULE: Final[int] = 1000
            MAX_WORKERS_DEBUG_RULE: Final[int] = 2
            MIN_ANALYTICS_CACHE_RULE: Final[int] = 1
            MIN_PARALLEL_THRESHOLD_RULE: Final[int] = 1

            DEFAULT_MAX_ATTR_VALUE_LENGTH: Final[int] = 1048576
            TYPICAL_ATTR_NAME_LENGTH_LIMIT: Final[int] = 127

        class RfcSyntaxOids:
            """RFC 4517 LDAP Attribute Syntax OIDs."""

            ACCESS_POINT: Final[str] = "1.3.6.1.4.1.1466.115.121.1.2"
            ATTRIBUTE_TYPE_DESCRIPTION: Final[str] = "1.3.6.1.4.1.1466.115.121.1.3"
            BINARY: Final[str] = "1.3.6.1.4.1.1466.115.121.1.5"
            BIT_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.6"
            BOOLEAN: Final[str] = "1.3.6.1.4.1.1466.115.121.1.7"
            CERTIFICATE: Final[str] = "1.3.6.1.4.1.1466.115.121.1.8"
            CERTIFICATE_LIST: Final[str] = "1.3.6.1.4.1.1466.115.121.1.9"
            CERTIFICATE_PAIR: Final[str] = "1.3.6.1.4.1.1466.115.121.1.10"
            COUNTRY_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.11"
            DN: Final[str] = "1.3.6.1.4.1.1466.115.121.1.12"
            DATA_QUALITY_SYNTAX: Final[str] = "1.3.6.1.4.1.1466.115.121.1.13"
            DELIVERY_METHOD: Final[str] = "1.3.6.1.4.1.1466.115.121.1.14"
            DIRECTORY_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.15"
            DIT_CONTENT_RULE_DESCRIPTION: Final[str] = "1.3.6.1.4.1.1466.115.121.1.16"
            DIT_STRUCTURE_RULE_DESCRIPTION: Final[str] = "1.3.6.1.4.1.1466.115.121.1.17"
            DLEXP_TIME: Final[str] = "1.3.6.1.4.1.1466.115.121.1.18"
            DN_WITH_BINARY: Final[str] = "1.3.6.1.4.1.1466.115.121.1.19"
            DN_WITH_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.20"

            DIRECTORY_STRING_21: Final[str] = "1.3.6.1.4.1.1466.115.121.1.21"
            ENHANCED_GUIDE: Final[str] = "1.3.6.1.4.1.1466.115.121.1.22"
            FACSIMILE_TELEPHONE_NUMBER: Final[str] = "1.3.6.1.4.1.1466.115.121.1.23"
            FAX: Final[str] = "1.3.6.1.4.1.1466.115.121.1.24"
            GENERALIZED_TIME: Final[str] = "1.3.6.1.4.1.1466.115.121.1.25"
            GUIDE: Final[str] = "1.3.6.1.4.1.1466.115.121.1.26"
            IA5_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.27"
            INTEGER_RFC: Final[str] = "2.5.5.5"
            JPEG: Final[str] = "1.3.6.1.4.1.1466.115.121.1.28"
            LDAP_SYNTAX_DESCRIPTION: Final[str] = "1.3.6.1.4.1.1466.115.121.1.29"

            MATCHING_RULE_DESCRIPTION: Final[str] = "1.3.6.1.4.1.1466.115.121.1.30"
            MATCHING_RULE_USE_DESCRIPTION: Final[str] = "1.3.6.1.4.1.1466.115.121.1.31"
            MHS_OR_ADDRESS: Final[str] = "1.3.6.1.4.1.1466.115.121.1.32"
            MODIFY_INCREMENT: Final[str] = "1.3.6.1.4.1.1466.115.121.1.33"
            NAME_AND_OPTIONAL_UID: Final[str] = "1.3.6.1.4.1.1466.115.121.1.34"
            NAME_FORM_DESCRIPTION: Final[str] = "1.3.6.1.4.1.1466.115.121.1.35"
            NUMERIC_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.36"
            OBJECT_CLASS_DESCRIPTION: Final[str] = "1.3.6.1.4.1.1466.115.121.1.37"
            OID: Final[str] = "1.3.6.1.4.1.1466.115.121.1.38"
            OCTET_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.39"

            OTHER_MAILBOX: Final[str] = "1.3.6.1.4.1.1466.115.121.1.40"
            OCTET_STRING_40: Final[str] = "1.3.6.1.4.1.1466.115.121.1.40"
            POSTAL_ADDRESS: Final[str] = "1.3.6.1.4.1.1466.115.121.1.41"
            PROTOCOL_INFORMATION: Final[str] = "1.3.6.1.4.1.1466.115.121.1.42"
            PRESENTATION_ADDRESS: Final[str] = "1.3.6.1.4.1.1466.115.121.1.43"
            PRINTABLE_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.44"
            SUBSTRING_ASSERTION: Final[str] = "1.3.6.1.4.1.1466.115.121.1.58"
            TELEPHONE_NUMBER: Final[str] = "1.3.6.1.4.1.1466.115.121.1.50"
            TELETEX_TERMINAL_IDENTIFIER: Final[str] = "1.3.6.1.4.1.1466.115.121.1.51"
            TELEX_NUMBER: Final[str] = "1.3.6.1.4.1.1466.115.121.1.52"
            TIME_OF_DAY: Final[str] = "1.3.6.1.4.1.1466.115.121.1.53"
            UTCTIME: Final[str] = "1.3.6.1.4.1.1466.115.121.1.54"
            LDAP_SYNTAX: Final[str] = "1.3.6.1.4.1.1466.115.121.1.54"
            UTF8_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.55"
            UNICODE_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.56"
            UUI: Final[str] = "1.3.6.1.4.1.1466.115.121.1.57"

            OID_TO_NAME: ClassVar[Mapping[str, str]] = MappingProxyType({
                "2.5.5.5": "integer",
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
            })

            NAME_TO_OID: Final[dict[str, str]] = {v: k for k, v in OID_TO_NAME.items()}

            NAME_TO_TYPE_CATEGORY: Final[dict[str, str]] = {
                "integer": "integer",
                "boolean": "boolean",
                "distinguished_name": "dn",
                "dn": "dn",
                "generalized_time": "time",
                "utc_time": "time",
                "binary": "binary",
                "octet_string": "binary",
                "directory_string": "string",
                "ia5_string": "string",
                "printable_string": "string",
                "numeric_string": "string",
                "telephone_number": "string",
                "mail_preference": "string",
                "other_mailbox": "string",
                "postal_address": "string",
                "country_string": "string",
                "dn_qualifier": "string",
                "certificate": "binary",
                "certificate_list": "binary",
                "certificate_pair": "binary",
                "supported_algorithm": "binary",
                "dsa_quality": "string",
                "data_quality_syntax": "binary",
                "dsi_mods": "binary",
                "entry_information_information": "binary",
                "facsimile_telephone_number": "string",
                "fax": "binary",
                "jpeg": "binary",
                "master_and_shadow_access_points": "dn",
                "name_and_optional_uid": "string",
                "name_forms": "string",
                "nis_netgroup_triple": "string",
                "object_class_description": "string",
                "oid": "string",
                "presentation_address": "binary",
                "protocol_information": "binary",
                "substring_assertion": "string",
                "teletex_terminal_identifier": "string",
                "telex_number": "string",
                "unique_member": "dn",
                "user_password": "binary",
                "user_certificate": "binary",
                "ca_certificate": "binary",
                "authority_revocation_list": "binary",
                "certificate_revocation_list": "binary",
                "cross_certificate_pair": "binary",
                "delta_revocation_list": "binary",
                "dit_content_rule_description": "string",
                "dit_structure_rule_description": "string",
                "dse_type": "string",
                "ldap_syntax_description": "string",
                "matching_rule_description": "string",
                "matching_rule_use_description": "string",
                "name_form_description": "string",
                "subschema": "binary",
                "access_point": "dn",
                "attribute_type_description": "string",
                "audio": "binary",
                "bit_string": "string",
                "aci": "string",
                "utf8_string": "string",
                "unicode_string": "string",
                "uui": "string",
            }

            COMMON_SYNTAXES: Final[frozenset[str]] = frozenset({
                "1.3.6.1.4.1.1466.115.121.1.7",
                "1.3.6.1.4.1.1466.115.121.1.12",
                "1.3.6.1.4.1.1466.115.121.1.15",
                "1.3.6.1.4.1.1466.115.121.1.24",
                "1.3.6.1.4.1.1466.115.121.1.26",
                "1.3.6.1.4.1.1466.115.121.1.27",
                "1.3.6.1.4.1.1466.115.121.1.36",
                "1.3.6.1.4.1.1466.115.121.1.38",
                "1.3.6.1.4.1.1466.115.121.1.40",
                "1.3.6.1.4.1.1466.115.121.1.44",
                "1.3.6.1.4.1.1466.115.121.1.50",
            })

            SERVICE_NAMES: Final[str] = "service_names"
            DATA: Final[str] = "data"

        class LdifFormatting:
            """LDIF formatting constants (line width, folding)."""

            DEFAULT_LINE_WIDTH: Final[int] = 78

            MAX_LINE_WIDTH: Final[int] = 199

            MIN_LINE_WIDTH: Final[int] = 10

        class CommentFormats:
            """LDIF comment formatting constants for documentation."""

            SEPARATOR_DOUBLE: Final[str] = "# " + ("═" * 51)
            SEPARATOR_SINGLE: Final[str] = "# " + ("─" * 51)
            SEPARATOR_EMPTY: Final[str] = "#"

            HEADER_REJECTION_REASON: Final[str] = "# REJECTION REASON"
            HEADER_REMOVED_ATTRIBUTES: Final[str] = (
                "# REMOVED ATTRIBUTES (Original Values)"
            )

            PREFIX_COMMENT: Final[str] = "# "

        class MigrationHeaders:
            """Migration header templates for LDIF output."""

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

            MINIMAL_TEMPLATE: Final[
                str
            ] = """# Phase: {phase} | {timestamp} | Entries: {total_entries}
#
"""

            DETAILED_TEMPLATE: Final[
                str
            ] = """# ============================================================
# LDIF MIGRATION - {phase_name}
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
#
"""

        class ConversionStrategy:
            """Server conversion strategy using RFC as canonical intermediate format."""

            CANONICAL_FORMAT: Final[str] = "rfc"

            ALGORITHM: Final[str] = "adapter_pattern_with_rfc_hub"

            CONVERSION_COMPLEXITY: Final[str] = "2N"

            ENFORCE_RFC_INTERMEDIATE: Final[bool] = True

            PRESERVE_SOURCE_METADATA: Final[bool] = True

            DIRECTION_TO_RFC: Final[str] = "normalize"
            DIRECTION_FROM_RFC: Final[str] = "denormalize"

            METADATA_ORIGINAL_SERVER: Final[str] = "original_server_type"
            METADATA_CONVERSION_PATH: Final[str] = "conversion_path"
            METADATA_INTERMEDIATE_FORMAT: Final[str] = "rfc_intermediate"

        class AclSubjectTransformations:
            """Subject transformation mappings for ACL conversions."""

            DS389_TO_RFC_SUBJECTS: Final[dict[str, tuple[str, str]]] = {
                "groupdn": ("group_dn", "{value}"),
                "userdn": ("user_dn", "{value}"),
            }

            UNIVERSAL_SUBJECTS: Final[dict[str, tuple[str, str]]] = {
                "anonymous": ("anonymous", "*"),
                "self": ("self", "self"),
                "all": ("all", "*"),
            }

        class AclPermissionCompatibility:
            """Permission compatibility matrix for server types."""

        class SchemaConversionMappings:
            """Schema attribute and objectClass conversion mappings."""

            MATCHING_RULE_NORMALIZATIONS: Final[dict[str, str]] = {
                "caseIgnoreIA5SubstringsMatch": "caseIgnoreIA5Match",
                "caseIgnoreOrdinalMatch": "caseIgnoreMatch",
            }

        class AclAttributeRegistry:
            """LDAP Server-specific ACL attributes with RFC foundation."""

            RFC_FOUNDATION: Final[list[str]] = [
                "aci",
                "acl",
                "olcAccess",
                "aclRights",
                "aclEntry",
            ]

            SERVER_QUIRKS: Final[dict[str, list[str]]] = {
                "oid": [
                    "orclaci",
                    "orclentrylevelaci",
                    "orclContainerLevelACL",
                ],
                "oud": [
                    "orclaci",
                    "orclentrylevelaci",
                ],
                "ad": [
                    "nTSecurityDescriptor",
                ],
                "generic": [],
            }

        class ServiceType(StrEnum):
            """Service types for internal management."""

            PARSER = "parser"
            ACL = "acl"
            WRITER = "writer"
            ENTRIES = "entries"
            ANALYSIS = "analysis"
            PROCESSING = "processing"
            DETECTOR = "detector"
            FILTERS = "filters"
            CATEGORIZATION = "categorization"
            CONVERSION = "conversion"
            VALIDATION = "validation"
            SYNTAX = "syntax"

        class CaseFoldOption(StrEnum):
            """Case folding options for DN normalization."""

            NONE = "none"
            LOWER = "lower"
            UPPER = "upper"

        class SpaceHandlingOption(StrEnum):
            """Space handling options for DN normalization."""

            PRESERVE = "preserve"
            TRIM = "trim"
            NORMALIZE = "normalize"

        class EscapeHandlingOption(StrEnum):
            """Escape sequence handling options."""

            PRESERVE = "preserve"
            UNESCAPE = "unescape"
            NORMALIZE = "normalize"

        class SortOption(StrEnum):
            """Sorting options for attribute ordering."""

            NONE = "none"
            ALPHABETICAL = "alphabetical"
            HIERARCHICAL = "hierarchical"

        class ObsoleteField(StrEnum):
            """Obsolete field constants."""

            OBSOLETE = "obsolete"

        class Categories(StrEnum):
            """Entry category constants."""

            ALL = "all"
            USERS = "users"
            GROUPS = "groups"
            HIERARCHY = "hierarchy"
            SCHEMA = "schema"
            ACL = "acl"
            REJECTED = "rejected"

    class DnPrefixField(StrEnum):
        """Dn_Prefix field constants."""

        PREFIX = "dn:"
        PREFIX_SHORT = "dn"

    class SchemaKwField(StrEnum):
        """Schema_Kw field constants."""

        NAME = "NAME"
        DESC = "DESC"

    class AclBindIpField(StrEnum):
        """Acl_Bind_Ip field constants."""

        IP_FULL = "acl:vendor:bind_ip"
        IP = "bind_ip"

    class PersonField(StrEnum):
        """Person field constants."""

        PERSON = "person"

    class OrganizationalUnitField(StrEnum):
        """Organizational_Unit field constants."""

        UNIT = "organizationalUnit"
        UNIT_LOWER = "organizationalunit"

    class UserField(StrEnum):
        """User field constants."""

        USER = "user"

    class GroupField(StrEnum):
        """Group field constants."""

        GROUP = "group"

    class AudioField(StrEnum):
        """Audio field constants."""

        AUDIO = "audio"
        AUDIO_OID = "1.3.6.1.4.1.1466.115.121.1.4"

    class StrictField(StrEnum):
        """Strict field constants."""

        STRICT = "strict"

    class LenientField(StrEnum):
        """Lenient field constants."""

        LENIENT = "lenient"

    class SubtreeField(StrEnum):
        """Subtree field constants."""

        SUBTREE = "subtree"

    class OnelevelField(StrEnum):
        """Onelevel field constants."""

        ONELEVEL = "onelevel"

    class BaseField(StrEnum):
        """Base field constants."""

        BASE = "base"
        BASE_OID = "1.3.6.1.4.1.1466.115.121.1"

    class AllField(StrEnum):
        """All field constants."""

        ALL = "all"

    class AciField(StrEnum):
        """Aci field constants."""

        ACI = "aci"
        ACI_OID = "1.3.6.1.4.1.1466.115.121.1.1"

    class AclWildcardField(StrEnum):
        """Acl_Wildcard field constants."""

        TYPE = "all"
        VALUE = "*"


c = FlextLdifConstants

__all__ = [
    "FlextLdifConstants",
    "c",
]
