"""Oracle Unified Directory (OUD) Servers."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar

from flext_ldif import c
from flext_ldif.servers.rfc import FlextLdifServersRfc

from ..._constants.servers import FlextLdifConstantsServers

if TYPE_CHECKING:
    from flext_ldif import t


class FlextLdifServersOudConstants(
    FlextLdifConstantsServers.Oud, FlextLdifServersRfc.Constants
):
    """Oracle Unified Directory-specific constants using Python 3.13 patterns."""

    CANONICAL_NAME: ClassVar[str] = c.Ldif.ServerTypes.OUD
    ALIASES: ClassVar[frozenset[str]] = frozenset({
        c.Ldif.ServerTypes.OUD,
        *(
            alias
            for alias, server_type in c.Ldif.SERVER_TYPE_ALIASES.items()
            if server_type == c.Ldif.ServerTypes.OUD
        ),
    })
    CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset({
        c.Ldif.ServerTypes.OUD,
        c.Ldif.ServerTypes.RFC,
    })
    CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset({
        c.Ldif.ServerTypes.OUD,
        c.Ldif.ServerTypes.RFC,
    })
    ACL_FORMAT: ClassVar[str] = "aci"
    ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"
    SUPPORTED_PERMISSIONS: ClassVar[frozenset[str]] = (
        FlextLdifServersRfc.Constants.SUPPORTED_PERMISSIONS
        | frozenset([PERMISSION_SELFWRITE, PERMISSION_PROXY, PERMISSION_ALL])
    )
    SCHEMA_DN: ClassVar[str] = "cn=schema"
    SCHEMA_FILTERABLE_FIELDS: ClassVar[frozenset[str]] = frozenset([
        SCHEMA_FIELD_ATTRIBUTE_TYPES,
        SCHEMA_FIELD_OBJECT_CLASSES,
        SCHEMA_FIELD_MATCHING_RULES,
        SCHEMA_FIELD_LDAP_SYNTAXES,
    ])
    ATTRIBUTE_FIELDS: ClassVar[frozenset[str]] = frozenset(["x_origin"])
    OBJECTCLASS_REQUIREMENTS: ClassVar[t.BoolMapping] = MappingProxyType({
        "requires_sup_for_auxiliary": True,
        "allows_multiple_sup": False,
        "requires_explicit_structural": True,
    })
    OPERATIONAL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset([
        "createTimestamp",
        "modifyTimestamp",
        "creatorsName",
        "modifiersName",
        "entryUUID",
        "entryDN",
        "subschemaSubentry",
        "hasSubordinates",
        "pwdChangedTime",
        "pwdHistory",
        "pwdFailureTime",
        "ds-sync-hist",
        "ds-sync-state",
        "ds-pwp-account-disabled",
        "ds-cfg-backend-id",
    ])
    PRESERVE_ON_MIGRATION: ClassVar[frozenset[str]] = (
        FlextLdifServersRfc.Constants.PRESERVE_ON_MIGRATION
        | frozenset(["pwdChangedTime"])
    )
    BOOLEAN_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset([
        "pwdlockout",
        "pwdmustchange",
        "pwdallowuserchange",
        "pwdexpirewarning",
        "pwdgraceauthnlimit",
        "pwdlockoutduration",
        "pwdmaxfailure",
        "pwdminage",
        "pwdmaxage",
        "pwdmaxlength",
        "pwdminlength",
    ])
    ATTRIBUTE_ALIASES: ClassVar[t.StrSequenceMapping] = MappingProxyType({
        "cn": ("commonName",),
        "sn": ("surname",),
        "givenName": ("gn",),
        "mail": ("rfc822Mailbox", "emailAddress"),
        "telephoneNumber": ("phone",),
        "uid": ("userid", "username"),
    })
    INVALID_SUBSTR_RULES: ClassVar[t.OptionalStrMapping] = MappingProxyType({
        "caseIgnoreMatch": "caseIgnoreSubstringsMatch",
        "distinguishedNameMatch": None,
        "caseIgnoreOrderingMatch": None,
        "numericStringMatch": "numericStringSubstringsMatch",
    })
    MATCHING_RULE_TO_RFC: ClassVar[t.StrMapping] = MappingProxyType({
        "distinguishedNAMEMatch": "distinguishedNameMatch",
        "DistinguishedNameMatch": "distinguishedNameMatch",
        "caseIgnoreSubstringMatch": "caseIgnoreSubstringsMatch",
        "CaseIgnoreMatch": "caseIgnoreMatch",
        "CaseExactMatch": "caseExactMatch",
    })
    CATEGORY_OBJECTCLASSES: ClassVar[t.FrozensetMapping] = MappingProxyType({
        "users": frozenset(["person", "inetOrgPerson", "organizationalPerson"]),
        "hierarchy": frozenset([
            "organizationalUnit",
            "organization",
            "domain",
            "country",
            "locality",
        ]),
        "groups": frozenset(["groupOfNames", "groupOfUniqueNames"]),
    })
    HIERARCHY_PRIORITY_OBJECTCLASSES: ClassVar[frozenset[str]] = frozenset([
        "organizationalUnit",
        "organization",
        "domain",
    ])
    CATEGORIZATION_ACL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(["aci"])
    CATEGORIZATION_PRIORITY: ClassVar[t.StrSequence] = (
        "schema",
        "acl",
        "users",
        "hierarchy",
        "groups",
        "rejected",
    )
    DETECTION_PATTERN: ClassVar[str] = "(?i)(ds-sync-|ds-pwp-|ds-cfg-|root dns)"
    DETECTION_OID_PATTERN: ClassVar[str] = DETECTION_PATTERN
    DETECTION_WEIGHT: ClassVar[int] = 14
    DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset([
        "ds-",
        "ds-sync",
        "ds-pwp",
        "ds-cfg",
    ])
    DETECTION_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset([
        "ds-sync-hist",
        "ds-sync-state",
        "ds-pwp-account-disabled",
        "ds-cfg-backend-id",
        "ds-privilege-name",
        "entryUUID",
    ])
    DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset([
        "ds-root-dse",
        "ds-root-dn-user",
        "ds-unbound-id-settings",
        "ds-cfg-backend",
    ])
    DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset([
        "cn=settings",
        "cn=tasks",
        "cn=monitor",
    ])
