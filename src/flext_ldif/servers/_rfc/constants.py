"""RFC 4512 Compliant Server Servers - Base LDAP Schema/ACL/Entry Implementation."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar

from flext_ldif import c
from flext_ldif.servers._base.constants import FlextLdifServersBaseConstants

if TYPE_CHECKING:
    from flext_ldif import t


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
    PERMISSION_ADD: ClassVar[str] = "add"
    PERMISSION_DELETE: ClassVar[str] = "delete"
    PERMISSION_SEARCH: ClassVar[str] = "search"
    PERMISSION_COMPARE: ClassVar[str] = "compare"
    SUPPORTED_PERMISSIONS: ClassVar[frozenset[str]] = frozenset([
        PERMISSION_READ,
        PERMISSION_WRITE,
        PERMISSION_ADD,
        PERMISSION_DELETE,
        PERMISSION_SEARCH,
        PERMISSION_COMPARE,
    ])
    SCHEMA_DN: ClassVar[str] = "cn=schema"
    SCHEMA_SUP_SEPARATOR: ClassVar[str] = "$"
    ATTRIBUTE_FIELDS: ClassVar[frozenset[str]] = frozenset([])
    OBJECTCLASS_REQUIREMENTS: ClassVar[t.BoolMapping] = MappingProxyType({
        "requires_sup_for_auxiliary": True,
        "allows_multiple_sup": False,
        "requires_explicit_structural": False,
    })
    ATTRIBUTE_ALIASES: ClassVar[t.StrSequenceMapping] = MappingProxyType({})
    OPERATIONAL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset([
        "createTimestamp",
        "modifyTimestamp",
        "creatorsName",
        "modifiersName",
        "subschemaSubentry",
        "structuralObjectClass",
    ])
    PRESERVE_ON_MIGRATION: ClassVar[frozenset[str]] = frozenset([
        "createTimestamp",
        "modifyTimestamp",
    ])
    CATEGORIZATION_PRIORITY: ClassVar[t.StrSequence] = (
        "users",
        "hierarchy",
        "groups",
        "acl",
    )
    CATEGORY_OBJECTCLASSES: ClassVar[t.FrozensetMapping] = MappingProxyType({
        "users": frozenset([
            "person",
            "inetOrgPerson",
            "organizationalPerson",
            "residentialPerson",
        ]),
        "hierarchy": frozenset([
            "organizationalUnit",
            "organization",
            "locality",
            "country",
        ]),
        "groups": frozenset(["groupOfNames", "groupOfUniqueNames", "posixGroup"]),
    })
    CATEGORIZATION_ACL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(["aci", "acl"])
    DETECTION_OID_PATTERN: ClassVar[str] = ".*"
    DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset([])
    DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset([])
    DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset([])
    ENCODING_UTF8: ClassVar[str] = c.Ldif.DEFAULT_ENCODING
    ENCODING_UTF16LE: ClassVar[str] = "utf-16-le"
    ENCODING_ERROR_IGNORE: ClassVar[str] = "ignore"
    LDIF_DN_PREFIX: ClassVar[str] = "dn: "
    LDIF_ATTR_SEPARATOR: ClassVar[str] = ": "
    LDIF_NEWLINE: ClassVar[str] = "\n"
    MATCHING_RULE_TO_RFC: ClassVar[t.StrMapping] = MappingProxyType({})
    SYNTAX_OID_TO_RFC: ClassVar[t.StrMapping] = MappingProxyType({})
    ATTRIBUTE_CASE_MAP: ClassVar[t.StrMapping] = MappingProxyType({})
    BOOLEAN_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset()
    ACL_DEFAULT_VERSION: ClassVar[str] = "version 3.0"
    ACL_SELF_SUBJECT: ClassVar[str] = "ldap:///self"
    ACL_ANONYMOUS_SUBJECT: ClassVar[str] = "ldap:///anyone"


c = FlextLdifServersRfcConstants
