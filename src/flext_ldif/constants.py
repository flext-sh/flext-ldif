"""LDIF constants and enumerations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import StrEnum, unique
from types import MappingProxyType
from typing import ClassVar, Final, Literal

from flext_core import FlextConstants, FlextLogger

type ValidationLevelLiteral = Literal["strict", "moderate", "lenient"]


class FlextLdifConstants(FlextConstants):
    """LDIF domain constants extending flext-core FlextConstants."""

    class Ldif:
        """LDIF domain constants namespace."""

        @unique
        class Category(StrEnum):
            """LDIF entry categories — single source of truth."""

            USERS = "users"
            GROUPS = "groups"
            HIERARCHY = "hierarchy"
            SCHEMA = "schema"
            ACL = "acl"
            REJECTED = "rejected"

        @unique
        class SortStrategy(StrEnum):
            """Valid sorting strategies for LDIF entries (V2 type-safe enum)."""

            HIERARCHY = "hierarchy"
            DN = "dn"
            ALPHABETICAL = "alphabetical"
            SCHEMA = "schema"
            CUSTOM = "custom"

        @unique
        class SortingStrategyType(StrEnum):
            """Sorting strategy types for metadata tracking."""

            ALPHABETICAL_CASE_SENSITIVE = "alphabetical_case_sensitive"
            ALPHABETICAL_CASE_INSENSITIVE = "alphabetical_case_insensitive"
            CUSTOM_ORDER = "custom_order"

        @unique
        class SortTarget(StrEnum):
            """What to sort in LDIF data (V2 type-safe enum)."""

            ENTRIES = "entries"
            ATTRIBUTES = "attributes"
            ACL = "acl"
            SCHEMA = "schema"
            COMBINED = "combined"

        @unique
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

        @unique
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

        @unique
        class AclAction(StrEnum):
            """ACL action types for all server implementations (type-safe enum)."""

            ALLOW = "allow"
            DENY = "deny"

        @unique
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

        @unique
        class LdifFormat(StrEnum):
            """RFC 2849 LDIF format indicators for attribute value encoding."""

            REGULAR = ":"
            BASE64 = "::"
            URL = ":<"

        LDIF_BASE64_INDICATOR: Final[str] = LdifFormat.BASE64.value
        LDIF_REGULAR_INDICATOR: Final[str] = LdifFormat.REGULAR.value
        LDIF_DEFAULT_ENCODING: Final[str] = FlextConstants.Utilities.DEFAULT_ENCODING

        @unique
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

        @unique
        class DictKeys(StrEnum):
            """Dictionary keys for LDIF entry data access - CORE KEYS ONLY per SRP."""

            DN = "dn"
            ATTRIBUTES = "attributes"
            OBJECTCLASS = "objectClass"
            CN = "cn"
            OID = "oid"

        class Domain(FlextConstants.Domain):
            """Domain constants extending FlextConstants.Domain."""

            @unique
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

            @unique
            class OutputFormat(StrEnum):
                """Output format options."""

                LDIF = "ldif"
                JSON = "json"
                CSV = "csv"
                YAML = "yaml"

            @unique
            class ValidationStatus(StrEnum):
                """Validation status values for LDIF entries."""

                VALID = "valid"
                INVALID = "invalid"
                WARNING = "warning"

            @unique
            class CaseFoldOption(StrEnum):
                """Case folding options for DN normalization."""

                NONE = "none"
                LOWER = "lower"
                UPPER = "upper"

            @unique
            class QuirkMetadataKeys(StrEnum):
                """Dictionary keys for quirk metadata and server-specific entry properties."""

                SERVER_TYPE = "server_type"
                IS_CONFIG_ENTRY = "is_config_entry"
                IS_TRADITIONAL_DIT = "is_traditional_dit"

            @unique
            class AclKeys(StrEnum):
                """Dictionary keys for ACL-related attributes and operations."""

                ACL_ATTRIBUTE = "acl"
                ACI = "aci"
                ACCESS = "access"

        class Format:
            """LDIF format specifications."""

            MAX_LINE_LENGTH: Final[int] = 78

            class Rfc:
                """RFC 2849/4512/4514 Standard Constants."""

            SAFE_CHAR_MIN: Final[int] = 1
            SAFE_CHAR_MAX: Final[int] = 127
            SAFE_CHAR_EXCLUDE: Final[frozenset[int]] = frozenset({0, 10, 13})
            SAFE_INIT_CHAR_EXCLUDE: Final[frozenset[int]] = frozenset({
                0,
                10,
                13,
                32,
                58,
                60,
            })

            @unique
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

            @unique
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

            DN_LUTF1_EXCLUDE: Final[frozenset[int]] = frozenset({
                0,
                32,
                34,
                35,
                43,
                44,
                59,
                60,
                62,
                92,
            })
            DN_TUTF1_EXCLUDE: Final[frozenset[int]] = frozenset({
                0,
                32,
                34,
                43,
                44,
                59,
                60,
                62,
                92,
            })
            DN_SUTF1_EXCLUDE: Final[frozenset[int]] = frozenset({
                0,
                34,
                43,
                44,
                59,
                60,
                62,
                92,
            })

            @unique
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

            @unique
            class DnEscapeAtStart(StrEnum):
                """RFC 4514 §2.4 - Characters requiring escape at DN value start."""

                SPACE = " "
                SHARP = "#"

            @unique
            class DnEscapeAtEnd(StrEnum):
                """RFC 4514 §2.4 - Characters requiring escape at DN value end."""

                SPACE = " "

            MIN_DN_LENGTH: Final[int] = 2
            META_TRANSFORMATION_TIMESTAMP: Final[str] = "_transform_ts"

        class FeatureCapabilities:
            """Feature capability definitions for cross-server translation."""

        class LdifProcessing:
            """LDIF processing-related constants."""

            MAX_BATCH_SIZE: Final[int] = (
                FlextConstants.Performance.BatchProcessing.MAX_ITEMS
            )
            ASCII_SPACE_CHAR: Final[int] = 32
            ASCII_TILDE_CHAR: Final[int] = 126

        class ConfigDefaults:
            """Default values for FlextLdifSettings fields."""

            LDIF_DEFAULT_ENCODING: Final[str] = (
                FlextConstants.Utilities.DEFAULT_ENCODING
            )
            DEBUG_MODE: Final[bool] = False

        class QualityAnalysis:
            """Quality analysis threshold constants."""

        class LdifGeneralValidation:
            """General validation constants."""

        class LdifValidation:
            """LDIF-specific validation rules and constraints."""

            MIN_ATTRIBUTE_NAME_LENGTH: Final[int] = 1
            MAX_ATTRIBUTE_NAME_LENGTH: Final[int] = 127
            MAX_URL_LENGTH: Final[int] = 2048
            RFC4512_DESCRIPTOR_PATTERN: Final[str] = "^[A-Za-z][A-Za-z0-9-]{0,126}$"
            RFC4514_DN_COMPONENT_PATTERN: Final[str] = (
                "^(?:[A-Za-z][A-Za-z0-9-]{0,126})=(?:[^\\\\,]|\\\\.)*$"
            )

        class ObjectClasses:
            """LDAP object class name constants (RFC 4512 standard classes)."""

        class RfcBinaryAttributes:
            """RFC 4517 Binary attribute names that typically require ;binary option."""

            @unique
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
                    "relaxed": ("cn=schema", "cn=subschema", "ou=schema"),
                })
            )
            SERVER_BINARY_ATTRIBUTES: ClassVar[Mapping[str, frozenset[str]]] = (
                MappingProxyType({
                    "oid": frozenset(["orclguid", "userpassword"]),
                    "oud": frozenset(["ds-sync-hist", "ds-sync-state"]),
                    "ad": frozenset([
                        "objectguid",
                        "objectsid",
                        "msexchmailboxguid",
                        "msexchmailboxsecuritydescriptor",
                    ]),
                    "openldap": frozenset(["entryuuid"]),
                })
            )

        @unique
        class ProcessingStage(StrEnum):
            """Processing stages for LDIF operations."""

            PARSING = "parsing"
            VALIDATION = "validation"
            ANALYTICS = "analytics"
            WRITING = "writing"

        @unique
        class LdifHealthStatus(StrEnum):
            """Health status for LDIF services."""

            HEALTHY = "healthy"
            DEGRADED = "degraded"
            UNHEALTHY = "unhealthy"

        @unique
        class EntryType(StrEnum):
            """Types of LDIF entries."""

            PERSON = "person"
            GROUP = "group"
            ORGANIZATIONAL_UNIT = "organizationalunit"
            DOMAIN = "domain"
            OTHER = "other"

        @unique
        class EntryModification(StrEnum):
            """LDIF entry modification types."""

            ADD = "add"
            MODIFY = "modify"
            DELETE = "delete"
            MODRDN = "modrdn"

        @unique
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

        @unique
        class FilterType(StrEnum):
            """Types of filters applied to entries."""

            BASE_DN_FILTER = "base_dn_filter"
            SCHEMA_WHITELIST = "schema_whitelist"
            FORBIDDEN_ATTRIBUTES = "forbidden_attributes"
            FORBIDDEN_OBJECTCLASSES = "forbidden_objectclasses"
            OPERATIONAL_ATTRIBUTES = "operational_attributes"
            ACL_EXTRACTION = "acl_extraction"
            SCHEMA_ENTRY = "schema_entry"

        @unique
        class ValidationStatus(StrEnum):
            """Entry validation status levels."""

            VALID = "valid"
            WARNING = "warning"
            ERROR = "error"
            REJECTED = "rejected"

        @unique
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

        @unique
        class ErrorCategory(StrEnum):
            """Categories of errors that can occur during processing."""

            PARSING = "parsing"
            VALIDATION = "validation"
            CONVERSION = "conversion"
            SYNC = "sync"
            SCHEMA = "schema"
            ACL = "acl"
            MODRDN = "modrdn"

        @unique
        class AttributeMarkerStatus(StrEnum):
            """Marker status for attribute processing in metadata."""

            NORMAL = "normal"
            MARKED_FOR_REMOVAL = "marked_for_removal"
            FILTERED = "filtered"
            OPERATIONAL = "operational"
            HIDDEN = "hidden"
            RENAMED = "renamed"

        @unique
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

            SCOPE: Final[tuple[str, ...]] = (
                "base",
                "one",
                "onelevel",
                "sub",
                "subtree",
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

            OPENLDAP: Final = "openldap"
            IBM_TIVOLI: Final = "ibm_tivoli"
            GENERIC: Final = "generic"

        class RfcCompliance:
            """RFC 2849 compliance validation constants."""

        class Acl:
            """ACL-related constants - RFC 4876 baseline ONLY."""

            READ: Final[str] = "read"
            WRITE: Final[str] = "write"
            SEARCH: Final[str] = "search"
            COMPARE: Final[str] = "compare"
            ADD: Final[str] = "add"
            DELETE: Final[str] = "delete"
            MODIFY: Final[str] = "modify"

        class AclSubjectTypes:
            """ACL subject type identifiers for permission subjects."""

            SELF: Final[str] = "self"
            PUBLIC: Final[str] = "public"
            ANONYMOUS: Final[str] = "anonymous"

            class Schema:
                """Schema-related constants."""

            OBJECTCLASS: Final[str] = "objectclass"
            ACTIVE: Final[str] = "active"
            STRUCTURAL: Final[str] = "STRUCTURAL"
            AUXILIARY: Final[str] = "AUXILIARY"

        class OperationalAttributes:
            """Operational (server-generated) attributes by server type."""

        class SchemaFields:
            """LDIF schema structure field names (case-sensitive)."""

            ATTRIBUTE_TYPES: Final[str] = "attributeTypes"
            OBJECT_CLASSES: Final[str] = "objectClasses"

        class AclAttributes:
            """RFC baseline ACL attribute names for LDAP."""

            DEFAULT_ACL_ATTRIBUTES: Final[list[str]] = ["acl", "aci", "olcAccess"]

        class DnValuedAttributes:
            """Attributes that contain Distinguished Names as values."""

            MANAGER: Final[str] = "manager"
            GROUPS: Final[str] = "groups"

            @unique
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

        class MetadataKeys:
            """Metadata extension keys used in quirk processing and entry transformations."""

            SCHEMA_ORIGINAL_FORMAT: Final[str] = "schema_original_format"
            SCHEMA_ORIGINAL_STRING_COMPLETE: Final[str] = (
                "schema_original_string_complete"
            )
            SCHEMA_SOURCE_SERVER: Final[str] = "schema_source_server"
            OBSOLETE: Final[str] = "obsolete"
            SCHEMA_SOURCE_SYNTAX_OID: Final[str] = "schema_source_syntax_oid"
            SCHEMA_TARGET_SYNTAX_OID: Final[str] = "schema_target_syntax_oid"
            SCHEMA_SOURCE_MATCHING_RULES: Final[str] = "schema_source_matching_rules"
            SCHEMA_TARGET_MATCHING_RULES: Final[str] = "schema_target_matching_rules"
            SCHEMA_TARGET_ATTRIBUTE_NAME: Final[str] = "schema_target_attribute_name"
            SYNTAX_OID_VALID: Final[str] = "syntax_oid_valid"
            SYNTAX_VALIDATION_ERROR: Final[str] = "syntax_validation_error"
            X_ORIGIN: Final[str] = "x_origin"
            COLLECTIVE: Final[str] = "collective"
            ENTRY_ORIGINAL_FORMAT: Final[str] = "entry_original_format"
            ENTRY_SOURCE_DN_CASE: Final[str] = "entry_source_dn_case"
            ENTRY_TARGET_DN_CASE: Final[str] = "entry_target_dn_case"
            ACL_ORIGINAL_FORMAT: Final[str] = "original_format"
            ACL_SOURCE_SUBJECT_TYPE: Final[str] = "source_subject_type"
            ACL_FILTER: Final[str] = "filter"
            ACL_CONSTRAINT: Final[str] = "added_object_constraint"
            ACL_BINDMODE: Final[str] = "bindmode"
            ACL_DENY_GROUP_OVERRIDE: Final[str] = "deny_group_override"
            ACL_APPEND_TO_ALL: Final[str] = "append_to_all"
            ACL_BIND_IP_FILTER: Final[str] = "bind_ip_filter"
            ACL_CONSTRAIN_TO_ADDED_OBJECT: Final[str] = "constrain_to_added_object"
            ACL_BIND_TIMEOFDAY: Final[str] = "bind_timeofday"
            ACL_SSF: Final[str] = "ssf"
            ORIGINAL_FORMAT: Final[str] = "original_format"
            VERSION: Final[str] = "version"
            ATTRIBUTE_ORDER: Final[str] = "attribute_order"
            SORTING_NEW_ATTRIBUTE_ORDER: Final[str] = "sorting_new_attribute_order"
            SORTING_STRATEGY: Final[str] = "sorting_strategy"
            SORTING_CUSTOM_ORDER: Final[str] = "sorting_custom_order"
            SORTING_ORDERED_ATTRIBUTES: Final[str] = "sorting_ordered_attributes"
            SORTING_REMAINING_ATTRIBUTES: Final[str] = "sorting_remaining_attributes"
            SORTING_ACL_ATTRIBUTES: Final[str] = "sorting_acl_attributes"
            SORTING_ACL_SORTED: Final[str] = "sorting_acl_sorted"
            SOURCE_FILE: Final[str] = "source_file"
            HIDDEN_ATTRIBUTES: Final[str] = "hidden_attributes"
            ORIGINAL_DN_COMPLETE: Final[str] = "original_dn_complete"
            ORIGINAL_ATTRIBUTES_COMPLETE: Final[str] = "original_attributes_complete"
            WRITE_OPTIONS: Final[str] = "_write_options"
            CONVERSION_BOOLEAN_CONVERSIONS: Final[str] = "boolean_conversions"
            CONVERSION_ATTRIBUTE_NAME_CONVERSIONS: Final[str] = (
                "attribute_name_conversions"
            )
            CONVERSION_ORIGINAL_VALUE: Final[str] = "original"
            CONVERSION_CONVERTED_VALUE: Final[str] = "converted"

        class DnPatterns:
            """Standard DN patterns used in LDAP/LDIF processing."""

            DN_COMMA: Final[str] = ","
            DN_TRAILING_BACKSLASH_SPACE: Final[str] = "\\\\\\s+,"
            DN_SPACES_AROUND_COMMA: Final[str] = ",\\s+"
            DN_UNNECESSARY_ESCAPES: Final[str] = '\\\\([^,+"\\<>;\\\\# ])'
            DN_MULTIPLE_SPACES: Final[str] = "\\s+"

        class AclFormats:
            """ACL format identifier constants."""

            DEFAULT_ACL_FORMAT: Final[str] = ACI

        class ServerTypesMappings:
            """Server type mappings and aliases (separate from enum to avoid conflicts)."""

            _CANONICAL_SERVER_NAMES: ClassVar[tuple[str, ...]] = (
                "oid",
                "oud",
                "openldap",
                "openldap1",
                "openldap2",
                "ad",
                "apache",
                "generic",
                "rfc",
                "ds389",
                "relaxed",
                "novell",
                "ibm_tivoli",
            )
            _LONG_NAMES_DICT: ClassVar[Mapping[str, str]] = {
                name: name for name in _CANONICAL_SERVER_NAMES
            }
            _FROM_LONG_DICT: ClassVar[Mapping[str, str]] = {
                v: k for k, v in _LONG_NAMES_DICT.items()
            }
            FROM_LONG: Final[Mapping[str, str]] = MappingProxyType(_FROM_LONG_DICT)
            _SELF_ALIASES: ClassVar[tuple[str, ...]] = ("ad", "apache", "novell")
            _ALIASES_DICT: ClassVar[Mapping[str, str]] = {
                name: name for name in _SELF_ALIASES
            } | {
                "389": "ds389",
                "389ds": "ds389",
                "tivoli": "ibm_tivoli",
                "openldap": "openldap2",
                "active_directory": "ad",
                "apache_directory": "apache",
                "novell_edirectory": "novell",
                "ibm_tivoli": "ibm_tivoli",
                "oracle_oid": "oid",
                "oracle_oud": "oud",
            }

        class ValidationMappings:
            """Immutable validation mappings using collections.abc.Mapping."""

        @unique
        class FilterTypes(StrEnum):
            """Filter type identifier constants."""

            OBJECTCLASS = "objectclass"
            DN_PATTERN = "dn_pattern"
            ATTRIBUTES = "attributes"
            SCHEMA_OID = "schema_oid"
            OID_PATTERN = "oid_pattern"
            ATTRIBUTE = "attribute"

        @unique
        class Modes(StrEnum):
            """Operation mode constants."""

            INCLUDE = "include"
            EXCLUDE = "exclude"
            AUTO = "auto"
            MANUAL = "manual"
            DISABLED = "disabled"

        @unique
        class DataTypes(StrEnum):
            """Data type identifier constants."""

            ATTRIBUTE = "attribute"
            OBJECTCLASS = "objectclass"
            ACL = "acl"
            ENTRY = "entry"
            SCHEMA = "schema"

        class RuleTypes:
            """ACL rule type constants."""

            TARGET: Final[str] = "target"

        class EntryTypes:
            """Entry type identifier constants."""

            CUSTOM: Final[str] = "custom"

        class ConversionTypes:
            """Conversion type identifier constants."""

        class ProcessorTypes:
            """Processor type identifier constants."""

            VALIDATE: Final[str] = "validate"

        class MatchTypes:
            """Match type constants for filtering."""

        class Scopes:
            """LDAP search scope constants."""

        class Parameters:
            """Parameter name constants."""

            CONTENT: Final[str] = "content"

        class LdifPatterns:
            """Regex pattern constants for LDIF processing."""

            DN_COMPONENT: Final[str] = "^[a-zA-Z][a-zA-Z0-9-]*=(?:[^\\\\,]|\\\\.)*$"
            ATTRIBUTE_NAME: Final[str] = "^[a-zA-Z][a-zA-Z0-9-]*$"
            MAX_ATTRIBUTE_NAME_LENGTH: Final[int] = 127
            ATTRIBUTE_OPTION: Final[str] = ";[a-zA-Z][a-zA-Z0-9-_]*"
            SCHEMA_NAME: Final[str] = "(?i)NAME\\s+\\(?\\s*'([^']+)'"
            SCHEMA_DESC: Final[str] = "DESC\\s+'([^']+)'"
            SCHEMA_EQUALITY: Final[str] = "EQUALITY\\s+([^\\s)]+)"
            SCHEMA_SUBSTR: Final[str] = "SUBSTR\\s+([^\\s)]+)"
            SCHEMA_ORDERING: Final[str] = "ORDERING\\s+([^\\s)]+)"
            SCHEMA_SUP: Final[str] = "SUP\\s+(\\w+)"
            SCHEMA_USAGE: Final[str] = "USAGE\\s+(\\w+)"
            SCHEMA_SYNTAX_LENGTH: Final[str] = (
                "SYNTAX\\s+(?:')?([0-9.]+)(?:')?(?:\\{(\\d+)\\})?"
            )
            SCHEMA_SINGLE_VALUE: Final[str] = "\\bSINGLE-VALUE\\b"
            SCHEMA_NO_USER_MODIFICATION: Final[str] = "\\bNO-USER-MODIFICATION\\b"
            SCHEMA_OBJECTCLASS_KIND: Final[str] = (
                "\\b(ABSTRACT|STRUCTURAL|AUXILIARY)\\b"
            )
            SCHEMA_OBJECTCLASS_SUP: Final[str] = (
                "SUP\\s+(?:\\(\\s*([^)]+)\\s*\\)|(\\w+))"
            )
            SCHEMA_OBJECTCLASS_MUST: Final[str] = (
                "MUST\\s+(?:\\(\\s*([^)]+)\\s*\\)|(\\w+))"
            )
            SCHEMA_OBJECTCLASS_MAY: Final[str] = (
                "MAY\\s+(?:\\(\\s*([^)]+)\\s*\\)|(\\w+))"
            )

        class ServerDetection:
            """Server type detection patterns and weights for LDIF content analysis."""

            CONFIDENCE_THRESHOLD: Final[float] = 0.6
            ATTRIBUTE_MATCH_SCORE: Final[int] = 2
            DEFAULT_MAX_LINES: Final[int] = 1000
            CHANGETYPE: Final[str] = "^changetype:\\s*(add|delete|modify|modrdn|moddn)$"

        @unique
        class ChangeType(StrEnum):
            """LDIF change types — single source of truth."""

            ADDED = "added"
            REMOVED = "removed"
            MODIFIED = "modified"
            FILTERED = "filtered"

        @unique
        class ModifyOperation(StrEnum):
            """LDIF modify operation types."""

            ADD = "add"
            DELETE = "delete"
            REPLACE = "replace"

        @unique
        class SchemaUsage(StrEnum):
            """RFC 4512 attribute usage types."""

            USER_APPLICATIONS = "userApplications"
            DIRECTORY_OPERATION = "directoryOperation"
            DISTRIBUTED_OPERATION = "distributedOperation"
            DSA_OPERATION = "dSAOperation"

        @unique
        class SchemaKind(StrEnum):
            """RFC 4512 objectClass kind types."""

            ABSTRACT = "ABSTRACT"
            STRUCTURAL = "STRUCTURAL"
            AUXILIARY = "AUXILIARY"

        class LdapServerDetection:
            """Server-specific detection patterns and markers for LDAP servers."""

        class ValidationRules:
            """Validation rule constants."""

            DEFAULT_MAX_ATTR_VALUE_LENGTH: Final[int] = 1048576

        class RfcSyntaxOids:
            """RFC 4517 LDAP Attribute Syntax OIDs."""

            BINARY: Final[str] = "1.3.6.1.4.1.1466.115.121.1.5"
            DN: Final[str] = "1.3.6.1.4.1.1466.115.121.1.12"
            OID: Final[str] = "1.3.6.1.4.1.1466.115.121.1.38"
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
            NAME_TO_OID: Final[Mapping[str, str]] = {
                v: k for k, v in OID_TO_NAME.items()
            }
            NAME_TO_TYPE_CATEGORY: Final[Mapping[str, str]] = {
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
            SYNTAX_VALID_BOOLEAN_VALUES: Final[frozenset[str]] = frozenset({
                "TRUE",
                "FALSE",
            })
            SYNTAX_TIME_PATTERN: Final[str] = "^\\d{14}(\\.\\d+)?Z$"

        class LdifFormatting:
            """LDIF formatting constants (line width, folding)."""

            DEFAULT_LINE_WIDTH: Final[int] = 78
            MAX_LINE_WIDTH: Final[int] = 199

        class CommentFormats:
            """LDIF comment formatting constants for documentation."""

        class MigrationHeaders:
            """Migration header templates for LDIF output."""

        class ConversionStrategy:
            """Server conversion strategy using RFC as canonical intermediate format."""

        class AclSubjectTransformations:
            """Subject transformation mappings for ACL conversions."""

        @unique
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

        @unique
        class CaseFoldOption(StrEnum):
            """Case folding options for DN normalization."""

            NONE = "none"
            LOWER = "lower"
            UPPER = "upper"

        @unique
        class SpaceHandlingOption(StrEnum):
            """Space handling options for DN normalization."""

            PRESERVE = "preserve"
            TRIM = "trim"
            NORMALIZE = "normalize"

        @unique
        class EscapeHandlingOption(StrEnum):
            """Escape sequence handling options."""

            PRESERVE = "preserve"
            UNESCAPE = "unescape"
            NORMALIZE = "normalize"

        @unique
        class SortOption(StrEnum):
            """Sorting options for attribute ordering."""

            NONE = "none"
            ALPHABETICAL = "alphabetical"
            HIERARCHICAL = "hierarchical"

        @unique
        class ObsoleteField(StrEnum):
            """Obsolete field constants."""

            OBSOLETE = "obsolete"

        @unique
        class Categories(StrEnum):
            """Entry category constants."""

            ALL = "all"
            USERS = "users"
            GROUPS = "groups"
            HIERARCHY = "hierarchy"
            SCHEMA = "schema"
            ACL = "acl"
            REJECTED = "rejected"

    @unique
    class DnPrefixField(StrEnum):
        """Dn_Prefix field constants."""

        PREFIX = "dn:"
        PREFIX_SHORT = "dn"

    @unique
    class SchemaKwField(StrEnum):
        """Schema_Kw field constants."""

        NAME = "NAME"
        DESC = "DESC"

    @unique
    class AclBindIpField(StrEnum):
        """Acl_Bind_Ip field constants."""

        IP_FULL = "acl:vendor:bind_ip"
        IP = "bind_ip"

    @unique
    class PersonField(StrEnum):
        """Person field constants."""

        PERSON = "person"

    @unique
    class OrganizationalUnitField(StrEnum):
        """Organizational_Unit field constants."""

        UNIT = "organizationalUnit"
        UNIT_LOWER = "organizationalunit"

    @unique
    class UserField(StrEnum):
        """User field constants."""

        USER = "user"

    @unique
    class GroupField(StrEnum):
        """Group field constants."""

        GROUP = "group"

    @unique
    class AudioField(StrEnum):
        """Audio field constants."""

        AUDIO = "audio"
        AUDIO_OID = "1.3.6.1.4.1.1466.115.121.1.4"

    @unique
    class StrictField(StrEnum):
        """Strict field constants."""

        STRICT = "strict"

    @unique
    class LenientField(StrEnum):
        """Lenient field constants."""

        LENIENT = "lenient"

    @unique
    class SubtreeField(StrEnum):
        """Subtree field constants."""

        SUBTREE = "subtree"

    @unique
    class OnelevelField(StrEnum):
        """Onelevel field constants."""

        ONELEVEL = "onelevel"

    @unique
    class BaseField(StrEnum):
        """Base field constants."""

        BASE = "base"
        BASE_OID = "1.3.6.1.4.1.1466.115.121.1"

    @unique
    class AllField(StrEnum):
        """All field constants."""

        ALL = "all"

    @unique
    class AciField(StrEnum):
        """Aci field constants."""

        ACI = "aci"
        ACI_OID = "1.3.6.1.4.1.1466.115.121.1.1"

    @unique
    class AclWildcardField(StrEnum):
        """Acl_Wildcard field constants."""

        TYPE = "all"
        VALUE = "*"

    @unique
    class ProcessingMode(StrEnum):
        """Processing mode enumeration."""

        STRICT = "strict"
        RELAXED = "relaxed"
        AUTO = "auto"

    @unique
    class ValidationLevel(StrEnum):
        """Validation level enumeration."""

        NONE = "none"
        BASIC = "basic"
        FULL = "full"

    @unique
    class ConversionTargetType(StrEnum):
        """Conversion target type enumeration."""

        STR = "str"
        INT = "int"
        FLOAT = "float"
        BOOL = "bool"
        LIST = "list"
        TUPLE = "tuple"
        DICT = "dict"


__all__ = ["FlextLdifConstants", "c"]

c = FlextLdifConstants
