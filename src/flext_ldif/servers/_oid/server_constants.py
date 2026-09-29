"""Oracle Internet Directory (OID) Servers."""

from __future__ import annotations

from enum import StrEnum, unique
from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar

from flext_ldif import c
from flext_ldif.servers.rfc import FlextLdifServersRfc

from ..._constants.servers import FlextLdifConstantsServers

if TYPE_CHECKING:
    from flext_ldif import t


class FlextLdifServersOidConstants(
    FlextLdifConstantsServers.Oid, FlextLdifServersRfc.Constants
):
    """Oracle Internet Directory (OID) constants for LDIF processing."""

    ACL_FORMAT: ClassVar[str] = "orclaci"
    ACL_ATTRIBUTE_NAME: ClassVar[str] = "orclaci"
    OPERATIONAL_ATTRIBUTES: ClassVar[frozenset[str]] = (
        FlextLdifServersRfc.Constants.OPERATIONAL_ATTRIBUTES
        | frozenset([
            "orclguid",
            "orclobjectguid",
            "orclentryid",
            "orclaccount",
            "pwdChangedTime",
            "pwdHistory",
            "pwdFailureTime",
        ])
    )
    DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset([
        "orcl",
        "orclguid",
    ])
    DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset([
        "orcldirectory",
        "orcldomain",
        "orcldirectoryserverconfig",
        "orclcontainer",
    ])
    DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset([
        "cn=orcl",
        "cn=subscriptions",
        "cn=oracle context",
    ])
    ATTRIBUTE_FIELDS: ClassVar[frozenset[str]] = frozenset(["usage", "x_origin"])
    OBJECTCLASS_REQUIREMENTS: ClassVar[t.BoolMapping] = MappingProxyType({
        "requires_sup_for_auxiliary": True,
        "allows_multiple_sup": True,
        "requires_explicit_structural": False,
    })
    CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset({
        c.Ldif.ServerTypes.OID,
        c.Ldif.ServerTypes.RFC,
    })
    DETECTION_PATTERN: ClassVar[str] = "2\\.16\\.840\\.1\\.113894\\.|orcl"
    DETECTION_OID_PATTERN: ClassVar[str] = "2\\.16\\.840\\.1\\.113894\\.|orcl"
    DETECTION_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset([
        "orclOID",
        "orclGUID",
        "orclPassword",
        "orclaci",
        "orclentrylevelaci",
        "orcldaslov",
    ])
    DETECTION_WEIGHT: ClassVar[int] = 12
    CATEGORIZATION_PRIORITY: ClassVar[t.StrSequence] = (
        c.Ldif.Category.ACL,
        c.Ldif.Category.USERS,
        c.Ldif.Category.HIERARCHY,
        c.Ldif.Category.GROUPS,
    )
    CATEGORY_OBJECTCLASSES: ClassVar[t.FrozensetMapping] = MappingProxyType({
        c.Ldif.Category.USERS: frozenset({
            "person",
            "inetOrgPerson",
            "orclUser",
            "orclUserV2",
        }),
        c.Ldif.Category.HIERARCHY: frozenset({
            "organizationalUnit",
            "organization",
            "domain",
            "country",
            "locality",
            "orclContainer",
            "orclContainerOC",
            "orclContext",
            "orclApplicationEntity",
            "orclConfigSet",
            "orclDASAttrCategory",
            "orclDASOperationURL",
            "orclDASConfigPublicGroup",
        }),
        c.Ldif.Category.GROUPS: frozenset({
            "groupOfNames",
            "groupOfUniqueNames",
            "orclGroup",
            "orclPrivilegeGroup",
        }),
    })
    HIERARCHY_PRIORITY_OBJECTCLASSES: ClassVar[frozenset[str]] = frozenset([
        "orclContainer",
        "organizationalUnit",
        "organization",
        "domain",
    ])
    CATEGORIZATION_ACL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset([
        "aci",
        "orclaci",
        "orclentrylevelaci",
    ])

    @unique
    class OidAclSubjectType(StrEnum):
        """Canonical OID ACL subject-type tokens."""

        SELF = "self"
        ANONYMOUS = "*"
        USER_DN = "user_dn"
        GROUP_DN = "group_dn"
        DN_ATTR = "dn_attr"
        GUID_ATTR = "guid_attr"
        GROUP_ATTR = "group_attr"

    @unique
    class OidAclSubjectSuffix(StrEnum):
        """Canonical suffix tokens for OID special subject mappings."""

        LDAPURL = "LDAPURL"
        USERDN = "USERDN"
        GROUPDN = "GROUPDN"
