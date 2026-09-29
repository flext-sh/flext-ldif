"""RFC 4512 Compliant Server Servers - Base LDAP Schema/ACL/Entry Implementation."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar

from ..._constants.servers import FlextLdifConstantsServers
from .._base.server_constants import FlextLdifServersBaseConstants

if TYPE_CHECKING:
    from flext_ldif import t


class FlextLdifServersRfcConstants(
    FlextLdifConstantsServers.Rfc, FlextLdifServersBaseConstants
):
    """RFC baseline constants (RFC 4512 compliant)."""

    DEFAULT_SSL_PORT: ClassVar[int] = 636
    DEFAULT_PAGE_SIZE: ClassVar[int] = 1000
    CANONICAL_NAME: ClassVar[str] = "rfc"
    ALIASES: ClassVar[frozenset[str]] = frozenset(["rfc", "generic"])
    CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["rfc"])
    CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["rfc"])
    ACL_FORMAT: ClassVar[str] = "rfc_generic"
    ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"
    PERMISSION_SELF_WRITE: ClassVar[str] = "self_write"
    PERMISSION_PROXY: ClassVar[str] = "proxy"
    PERMISSION_ALL: ClassVar[str] = "all"
    SUPPORTED_PERMISSIONS: ClassVar[frozenset[str]] = frozenset([
        PERMISSION_READ,
        PERMISSION_WRITE,
        PERMISSION_ADD,
        PERMISSION_DELETE,
        PERMISSION_SEARCH,
        PERMISSION_COMPARE,
    ])
    DETECTION_PATTERN: ClassVar[str] = ""
    DETECTION_WEIGHT: ClassVar[int] = 0
    DETECTION_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset()
    DETECTION_OID_PATTERN: ClassVar[str] = ""
    DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset()
    DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset()
    DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset()
    ATTRIBUTE_FIELDS: ClassVar[frozenset[str]] = frozenset()
    ATTRIBUTE_ALIASES: ClassVar[t.StrSequenceMapping] = MappingProxyType({})
    OPERATIONAL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset()
    PRESERVE_ON_MIGRATION: ClassVar[frozenset[str]] = frozenset()
    OBJECTCLASS_REQUIREMENTS: ClassVar[t.BoolMapping] = MappingProxyType({})
    CATEGORIZATION_PRIORITY: ClassVar[t.StrSequence] = ()
    CATEGORY_OBJECTCLASSES: ClassVar[t.FrozensetMapping] = MappingProxyType({})
    HIERARCHY_PRIORITY_OBJECTCLASSES: ClassVar[frozenset[str]] = frozenset()
    CATEGORIZATION_ACL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset()
    MATCHING_RULE_TO_RFC: ClassVar[t.StrMapping] = MappingProxyType({})
    SYNTAX_OID_TO_RFC: ClassVar[t.StrMapping] = MappingProxyType({})
    ATTRIBUTE_CASE_MAP: ClassVar[t.StrMapping] = MappingProxyType({})
    BOOLEAN_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset()
    ACL_DEFAULT_VERSION: ClassVar[str] = "version 3.0"
    ACL_SELF_SUBJECT: ClassVar[str] = "ldap:///self"
    ACL_ANONYMOUS_SUBJECT: ClassVar[str] = "ldap:///anyone"


__all__: list[str] = ["FlextLdifServersRfcConstants"]
