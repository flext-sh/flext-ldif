"""RFC 4512 Compliant Server Servers - Base LDAP Schema/ACL/Entry Implementation."""

from __future__ import annotations

from types import MappingProxyType
from typing import ClassVar

from flext_ldif import c, t

from .._base.constants import FlextLdifServersBaseConstants


class FlextLdifServersRfcConstants(FlextLdifServersBaseConstants):
    """RFC baseline constants (RFC 4512 compliant)."""

    SERVER_TYPE: ClassVar[str] = c.Ldif.ServerTypes.RFC.value
    PRIORITY: ClassVar[int] = 100
    DEFAULT_PORT: ClassVar[int] = 389
    DEFAULT_SSL_PORT: ClassVar[int] = 636
    DEFAULT_PAGE_SIZE: ClassVar[int] = 1000
    CANONICAL_NAME: ClassVar[str] = "rfc"
    ALIASES: ClassVar[frozenset[str]] = frozenset(["rfc", "generic"])
    CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["rfc"])
    CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["rfc"])
    ACL_FORMAT: ClassVar[str] = "rfc_generic"
    ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"
    PERMISSION_READ: ClassVar[str] = "read"
    PERMISSION_WRITE: ClassVar[str] = "write"
    PERMISSION_DELETE: ClassVar[str] = "delete"
    PERMISSION_SEARCH: ClassVar[str] = "search"
    PERMISSION_COMPARE: ClassVar[str] = "compare"
    PERMISSION_ADMIN: ClassVar[str] = "admin"
    PERMISSION_IMPORT: ClassVar[str] = "import"
    PERMISSION_EXPORT: ClassVar[str] = "export"
    PERMISSION_SELF_WRITE: ClassVar[str] = "self_write"
    PERMISSION_PROXY: ClassVar[str] = "proxy"
    PERMISSION_AUTH: ClassVar[str] = "auth"
    PERMISSION_ALL: ClassVar[str] = "all"
    RFC_ACL_ATTRIBUTES: ClassVar[t.StrSequence] = (
        "aci",
        "acl",
        "olcAccess",
        "aclRights",
        "aclEntry",
    )
    DETECTION_PATTERN: ClassVar[str] = ""
    DETECTION_WEIGHT: ClassVar[int] = 0
    DETECTION_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset()
    DETECTION_OID_PATTERN: ClassVar[str] = ""
    DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset()
    DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset()
    DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset()
    ACL_PERMISSION_KEYS: ClassVar[t.StrSequence] = (
        "read",
        "write",
        "add",
        "delete",
        "search",
        "compare",
        "self_write",
        "proxy",
        "auth",
        "all",
    )
    ATTRIBUTE_FIELDS: ClassVar[frozenset[str]] = frozenset()
    ATTRIBUTE_ALIASES: ClassVar[t.StrSequenceMapping] = MappingProxyType({})
    OPERATIONAL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset()
    PRESERVE_ON_MIGRATION: ClassVar[frozenset[str]] = frozenset()
    OBJECTCLASS_REQUIREMENTS: ClassVar[t.BoolMapping] = MappingProxyType({})
    CATEGORIZATION_PRIORITY: ClassVar[t.StrSequence] = ()
    CATEGORY_OBJECTCLASSES: ClassVar[t.FrozensetMapping] = MappingProxyType({})
    HIERARCHY_PRIORITY_OBJECTCLASSES: ClassVar[frozenset[str]] = frozenset()
    CATEGORIZATION_ACL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset()
    MIME_OID_ENCODING: ClassVar[str] = "1.2.840.113556"
    LDAP_SYNTAXES: ClassVar[t.StrSequence] = (
        "1.3.6.1.4.1.1466.115.121.1.12",
        "1.3.6.1.4.1.1466.115.121.1.15",
        "1.3.6.1.4.1.1466.115.121.1.27",
        "1.3.6.1.4.1.1466.115.121.1.44",
        "1.3.6.1.4.1.1466.115.121.1.50",
        "1.3.6.1.4.1.1466.115.121.1.51",
        "1.3.6.1.4.1.1466.115.121.1.34",
        "1.3.6.1.4.1.1466.115.121.1.44",
    )
    LDIF_NEWLINE: ClassVar[str] = "\n"
    MATCHING_RULE_TO_RFC: ClassVar[t.StrMapping] = MappingProxyType({})
    SYNTAX_OID_TO_RFC: ClassVar[t.StrMapping] = MappingProxyType({})
    ATTRIBUTE_CASE_MAP: ClassVar[t.StrMapping] = MappingProxyType({})
    BOOLEAN_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset()
    ACL_DEFAULT_VERSION: ClassVar[str] = "version 3.0"
    ACL_SELF_SUBJECT: ClassVar[str] = "ldap:///self"
    ACL_ANONYMOUS_SUBJECT: ClassVar[str] = "ldap:///anyone"
    ACL_DEFAULT_ENTRY_ID: ClassVar[str] = "0.0.0.0"
    ACL_DEFAULT_ENTRY_RDN: ClassVar[str] = ""
    ACL_DEFAULT_ENTRY_OBSOLETE: ClassVar[str] = ""


c = FlextLdifServersRfcConstants
s = FlextLdifServersRfcConstants

__all__: list[str] = ["FlextLdifServersRfcConstants"]
