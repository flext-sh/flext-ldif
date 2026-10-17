"""Constants family base parts for flext-ldif.

Enumerations and the OUD-output ACL taxonomy the ``_constants`` family base
and its sibling parts consume without importing another family module.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_constants/_base_parts
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum, unique
from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from collections.abc import Mapping

    from flext_core import t


class FlextLdifConstantsBaseParts:
    """LDIF base constant family parts composed into ``c.Ldif``."""

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
        class RejectionTrackerKey(StrEnum):
            """Internal rejection tracker buckets."""

            INVALID_DN_RFC4514 = "invalid_dn_rfc4514"
            BASE_DN_FILTER = "base_dn_filter"
            CATEGORIZATION_REJECTED = "categorization_rejected"

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

        SERVER_TYPE_ALIASES: ClassVar[Mapping[str, ServerTypes]] = MappingProxyType({
            "active_directory": ServerTypes.AD,
            "activedirectory": ServerTypes.AD,
            "oracle_oid": ServerTypes.OID,
            "oracleoid": ServerTypes.OID,
            "oracle_oud": ServerTypes.OUD,
            "oracleoud": ServerTypes.OUD,
            "openldap": ServerTypes.OPENLDAP2,
            "openldap1": ServerTypes.OPENLDAP1,
            "openldap2": ServerTypes.OPENLDAP2,
            "ibm_tivoli": ServerTypes.IBM_TIVOLI,
            "ibmtivoli": ServerTypes.IBM_TIVOLI,
            "tivoli": ServerTypes.IBM_TIVOLI,
            "novell_edirectory": ServerTypes.NOVELL,
            "novelledirectory": ServerTypes.NOVELL,
            "edirectory": ServerTypes.NOVELL,
            "apache_directory": ServerTypes.APACHE,
            "apachedirectory": ServerTypes.APACHE,
            "apacheds": ServerTypes.APACHE,
            "389ds": ServerTypes.DS389,
            "389directory": ServerTypes.DS389,
        })

        @unique
        class ChangeOperation(StrEnum):
            """RFC 2849 modify operation names."""

            ADD = "add"
            DELETE = "delete"
            REPLACE = "replace"
            INCREMENT = "increment"

        @unique
        class ChangeType(StrEnum):
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
        class EntryCriteriaMode(StrEnum):
            """Matching strategy for entry criteria evaluation."""

            ANY = "any"
            ALL = "all"

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

    class FlextLdifConstantsAclConvertOud:
        """OUD-output ACL conversion constants (one flat namespace; into c.Ldif)."""

        @unique
        class OudSubjectType(StrEnum):
            """OUD aci bind-rule keywords."""

            GROUPDN = "groupdn"
            USERDN = "userdn"
            USERATTR = "userattr"

        @unique
        class UserAttrSuffix(StrEnum):
            """OUD ``userattr`` value suffixes."""

            USERDN = "#USERDN"
            GROUPDN = "#GROUPDN"

        ACL_SCOPE_BASE: ClassVar[str] = "base"
        "OUD targetscope value for entry-level / anyone-scoped rules."
        DIRECTORY_MANAGER_DN: ClassVar[str] = "cn=Directory Manager"
        "OUD root account that OID ``SuperUser`` maps to."
        LDAP_PREFIX: ClassVar[str] = "ldap:///"
        "URL prefix wrapping a DN inside a ``groupdn``/``userdn`` bind-rule."
        SUBJECT_SELF: ClassVar[str] = "self"
        SUBJECT_ANYONE: ClassVar[str] = "anyone"
        OUD_ATTR_OR: ClassVar[str] = "||"
        "OUD ``targetattr`` multi-attribute OR separator (``cn||sn||mail``)."
        OUD_ATTR_NEGATION: ClassVar[str] = "!="
        "OUD ``targetattr`` negation operator (``targetattr!=...``)."
        ACI_PREFIX: ClassVar[str] = "aci: "
        ACI_ATTR_NAME: ClassVar[str] = "aci"
        "OUD ACL attribute name (replaces OID orclaci/orclentrylevelaci)."
        ACI_VERSION: ClassVar[str] = "version 3.0"
        ACI_VERSION_NUMBER: ClassVar[str] = "3.0"
        ACI_ALLOW: ClassVar[str] = "allow"
        BIND_OR: ClassVar[str] = " or "
        "Separator joining same-permission bind-rules inside one ``allow`` clause."
        UNKNOWN_CONTAINER: ClassVar[str] = "Unknown"
        "acl-name container fallback when the DN has no ``cn=`` RDN."
        ACL_NAME_ENTRY: ClassVar[str] = "Entry"
        ACL_NAME_ATTRS: ClassVar[str] = "Attrs"
        PERM_NONE: ClassVar[str] = "none"
        "OID permission token denying all access (``by X (none)``)."
        PERM_ALL: ClassVar[str] = "all"
        "OID/OUD permission token granting all rights."

        # OID permission → OUD permission(s); None = negation/deny (dropped).
        ENTRY_PERM_MAP: ClassVar[Mapping[str, str | None]] = MappingProxyType({
            "all": "all",
            "browse": "read, search",
            "add": "add",
            "delete": "delete",
            "proxy": "proxy",
            "noadd": None,
            "nodelete": None,
            "noproxy": None,
            "nobrowse": None,
            "none": None,
        })
        ATTR_PERM_MAP: ClassVar[Mapping[str, str | None]] = MappingProxyType({
            "all": "all",
            "read": "read",
            "search": "search",
            "write": "write",
            "selfwrite": "selfwrite",
            "compare": "compare",
            "noread": None,
            "nosearch": None,
            "nowrite": None,
            "noselfwrite": None,
            "nocompare": None,
            "none": None,
        })
        # OID ``noX`` negation token → its base permission (for complement computation).
        NEGATION_TO_BASE: ClassVar[Mapping[str, str]] = MappingProxyType({
            "noread": "read",
            "nosearch": "search",
            "nowrite": "write",
            "noselfwrite": "selfwrite",
            "nocompare": "compare",
            "noadd": "add",
            "nodelete": "delete",
            "noproxy": "proxy",
            "nobrowse": "browse",
        })
        ALL_ENTRY_PERMS: ClassVar[frozenset[str]] = frozenset({
            "browse",
            "add",
            "delete",
            "proxy",
        })
        ALL_ATTR_PERMS: ClassVar[frozenset[str]] = frozenset({
            "read",
            "search",
            "write",
            "selfwrite",
            "compare",
        })
        # OUD perms that are security-sensitive when granted to anyone (review flag).
        SENSITIVE_PERMS: ClassVar[frozenset[str]] = frozenset({
            "proxy",
            "write",
            "delete",
            "add",
            "selfwrite",
        })
        # Canonical OUD permission ordering for deterministic aci assembly.
        PERM_ORDERED: ClassVar[t.VariadicTuple[str]] = (
            "all",
            "read",
            "search",
            "write",
            "selfwrite",
            "compare",
            "add",
            "delete",
            "proxy",
        )
        # DN suffixes (relative to base) treated as high-level containers (filter anyone).
        HIGH_LEVEL_CONTAINER_SUFFIXES: ClassVar[t.VariadicTuple[str]] = (
            "",
            "dc=network,",
            "cn=users,dc=network,",
            "cn=groups,dc=network,",
            "cn=perfis,dc=network,",
        )


__all__: list[str] = [
    "FlextLdifConstantsAclConvertOud",
    "FlextLdifConstantsBaseParts",
    "FlextLdifConstantsEnums",
]
