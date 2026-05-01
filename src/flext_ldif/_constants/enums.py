"""FlextLdifConstantsEnums - LDIF enumeration constants.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum, unique


class FlextLdifConstantsEnums:
    """LDIF enumeration types (StrEnum-based)."""

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
        """Valid sorting strategies for LDIF entries."""

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
        """What to sort in LDIF data."""

        ENTRIES = "entries"
        ATTRIBUTES = "attributes"
        ACL = "acl"
        SCHEMA = "schema"
        COMBINED = "combined"

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

    @unique
    class LdifFormat(StrEnum):
        """RFC 2849 LDIF format indicators for attribute value encoding."""

        REGULAR = ":"
        BASE64 = "::"
        URL = ":<"

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
    class RfcAclPermission(StrEnum):
        """RFC 4876 standard ACL permissions."""

        READ = "read"
        WRITE = "write"
        ADD = "add"
        DELETE = "delete"
        SEARCH = "search"
        COMPARE = "compare"
        ALL = "all"
        NONE = "none"

    @unique
    class CaseFoldOption(StrEnum):
        """Case folding options for DN normalization."""

        NONE = "none"
        LOWER = "lower"
        UPPER = "upper"

    @unique
    class Base64StartChar(StrEnum):
        """RFC 2849 §2 - Characters requiring base64 encoding at value start."""

        SPACE = " "
        LANGLE = "<"
        COLON = ":"

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

    @unique
    class ChangeType(StrEnum):
        """LDIF change types — single source of truth."""

        ADDED = "added"
        REMOVED = "removed"
        MODIFIED = "modified"
        FILTERED = "filtered"

    @unique
    class ChangeOperation(StrEnum):
        """RFC 2849 modify operation names."""

        ADD = "add"
        DELETE = "delete"
        REPLACE = "replace"
        INCREMENT = "increment"

    @unique
    class LdifChangeType(StrEnum):
        """RFC 2849 changetype names."""

        ADD = "add"
        DELETE = "delete"
        MODIFY = "modify"
        MODDN = "moddn"
        MODRDN = "modrdn"

    @unique
    class RecordKind(StrEnum):
        """High-level LDIF record kinds preserved in Entry."""

        CONTENT = "content"
        CHANGE = "change"

    @unique
    class ValueOrigin(StrEnum):
        """Original LDIF value encoding/source markers."""

        PLAIN = "plain"
        BASE64 = "base64"
        URL = "url"
        FILE = "file"

    @unique
    class SchemaKind(StrEnum):
        """RFC 4512 objectClass kind types."""

        ABSTRACT = "ABSTRACT"
        STRUCTURAL = "STRUCTURAL"
        AUXILIARY = "AUXILIARY"

    @unique
    class SpaceHandlingOption(StrEnum):
        """Space handling options for DN normalization."""

        PRESERVE = "preserve"
        TRIM = "trim"
        NORMALIZE = "normalize"

    @unique
    class ObsoleteField(StrEnum):
        """Obsolete field constants."""

        OBSOLETE = "obsolete"

    @unique
    class DictKeys(StrEnum):
        """Dictionary keys for LDIF entry data access."""

        DN = "dn"
        ATTRIBUTES = "attributes"
        OBJECTCLASS = "objectClass"
        CN = "cn"
        OID = "oid"

    @unique
    class ServerMetadataKeys(StrEnum):
        """Dictionary keys for server metadata and server-specific entry properties."""

        SERVER_TYPE = "server_type"
        IS_CONFIG_ENTRY = "is_config_entry"
        IS_TRADITIONAL_DIT = "is_traditional_dit"

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
