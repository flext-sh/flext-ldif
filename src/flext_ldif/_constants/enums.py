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
    class Encoding(StrEnum):
        """Standard character encodings used in LDIF processing."""

        UTF8 = "utf-8"
        UTF16 = "utf-16"
        ASCII = "ascii"
        LATIN1 = "latin-1"

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
    class TransformationType(StrEnum):
        """Types of transformations applied to entries."""

        TAB_NORMALIZED = "tab_normalized"
        SPACE_CLEANED = "space_cleaned"
        ESCAPE_NORMALIZED = "escape_normalized"
        ATTRIBUTE_RENAMED = "attribute_renamed"
        MODIFIED = "modified"

    @unique
    class RejectionCategory(StrEnum):
        """Categories for entry rejection."""

        INVALID_DN = "invalid_dn"
        BASE_DN_FILTER = "base_dn_filter"
        NO_CATEGORY_MATCH = "no_category_match"

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
