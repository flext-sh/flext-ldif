"""Oracle Internet Directory (OID) Servers."""

from __future__ import annotations

import re
from enum import StrEnum, unique
from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar

from flext_ldif import c
from flext_ldif.servers.rfc import FlextLdifServersRfc

if TYPE_CHECKING:
    from flext_ldif import t


class FlextLdifServersOidConstants(FlextLdifServersRfc.Constants):
    """Oracle Internet Directory (OID) constants for LDIF processing."""

    SERVER_TYPE: ClassVar[str] = c.Ldif.ServerTypes.OID
    PRIORITY: ClassVar[int] = 10
    MAX_LOG_LINE_LENGTH: ClassVar[int] = 200
    ORCLACI: ClassVar[str] = "orclaci"
    ORCLENTRYLEVELACI: ClassVar[str] = "orclentrylevelaci"
    ORCL_CONTAINER_LEVEL_ACL: ClassVar[str] = "orclContainerLevelACL"
    OID_ACL_ATTRIBUTES: ClassVar[t.StrSequence] = (
        ORCLACI,
        ORCLENTRYLEVELACI,
        ORCL_CONTAINER_LEVEL_ACL,
    )
    ACL_FORMAT: ClassVar[str] = "orclaci"
    ACL_ATTRIBUTE_NAME: ClassVar[str] = "orclaci"
    MATCHING_RULE_TO_RFC: ClassVar[t.StrMapping] = MappingProxyType({
        "caseIgnoreSubStringsMatch": "caseIgnoreSubstringsMatch",
        "accessDirectiveMatch": "caseIgnoreMatch",
        "distinguishedNAMEMatch": "distinguishedNameMatch",
        "DistinguishedNameMatch": "distinguishedNameMatch",
        "caseIgnoreSubstringMatch": "caseIgnoreSubstringsMatch",
        "CaseIgnoreMatch": "caseIgnoreMatch",
        "CaseExactMatch": "caseExactMatch",
    })
    MATCHING_RULE_RFC_TO_OID: ClassVar[t.StrMapping] = MappingProxyType({
        "caseIgnoreSubstringsMatch": "caseIgnoreSubStringsMatch",
    })
    SYNTAX_OID_TO_RFC: ClassVar[t.StrMapping] = MappingProxyType({
        "1.3.6.1.4.1.1466.115.121.1.1": "1.3.6.1.4.1.1466.115.121.1.15",
    })
    ATTR_NAME_CASE_MAP: ClassVar[t.StrMapping] = MappingProxyType({
        "middlename": "middleName",
    })
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
    SCHEMA_FILTERABLE_FIELDS: ClassVar[frozenset[str]] = frozenset([
        "attributetypes",
        "objectclasses",
        "matchingrules",
        "ldapsyntaxes",
    ])
    SCHEMA_DN_SERVER: ClassVar[str] = "cn=subschemasubentry"
    BOOLEAN_ATTRIBUTES: ClassVar[frozenset[str]] = c.Ldif.OID_BOOLEAN_ATTRIBUTES
    ATTRIBUTE_FIELDS: ClassVar[frozenset[str]] = frozenset(["usage", "x_origin"])
    OBJECTCLASS_REQUIREMENTS: ClassVar[t.BoolMapping] = MappingProxyType({
        "requires_sup_for_auxiliary": True,
        "allows_multiple_sup": True,
        "requires_explicit_structural": False,
    })
    CANONICAL_NAME: ClassVar[str] = c.Ldif.ServerTypes.OID
    ALIASES: ClassVar[frozenset[str]] = frozenset({
        c.Ldif.ServerTypes.OID,
        *(
            alias
            for alias, server_type in c.Ldif.SERVER_TYPE_ALIASES.items()
            if server_type == c.Ldif.ServerTypes.OID
        ),
    })
    CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset({c.Ldif.ServerTypes.OID})
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
    OID_SPECIFIC_RIGHTS: ClassVar[str] = "oid_specific_rights"
    RFC_NORMALIZED: ClassVar[str] = "rfc_normalized"
    ORIGINAL_OID_PERMS: ClassVar[str] = "original_oid_perms"
    OID_ACL_SOURCE_TARGET: ClassVar[str] = "acl_source_target"
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
    CN_ORCL: ClassVar[str] = "cn=orcl"
    OU_ORACLE: ClassVar[str] = "ou=oracle"
    DC_ORACLE: ClassVar[str] = "dc=oracle"
    ACL_SUBJECT_TYPE_USER: ClassVar[str] = c.Ldif.AclSubjectType.USER
    ACL_SUBJECT_TYPE_GROUP: ClassVar[str] = c.Ldif.AclSubjectType.GROUP
    ACL_SUBJECT_TYPE_SELF: ClassVar[str] = c.Ldif.AclSubjectType.SELF
    ACL_SUBJECT_TYPE_ANONYMOUS: ClassVar[str] = c.Ldif.AclSubjectType.ANONYMOUS

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

    ACL_TARGET_PATTERN: ClassVar[str] = "access to (entry | attr=\\(([^)]+)\\))"
    ACL_FILTER_PATTERN: ClassVar[str] = "filter=(\\([^)]*(?:\\([^)]*\\)[^)]*)*\\))"
    ACL_CONSTRAINT_PATTERN: ClassVar[str] = "added_object_constraint=\\(([^)]+)\\)"
    ACL_BINDMODE_PATTERN: ClassVar[str] = "(?i)bindmode\\s*=\\s*\\(([^)]+)\\)"
    ACL_DENY_GROUP_OVERRIDE_PATTERN: ClassVar[str] = "DenyGroupOverride"
    ACL_APPEND_TO_ALL_PATTERN: ClassVar[str] = "AppendToAll"
    ACL_BIND_IP_FILTER_PATTERN: ClassVar[str] = "(?i)bindipfilter\\s*=\\s*\\(([^)]+)\\)"
    ACL_CONSTRAIN_TO_ADDED_PATTERN: ClassVar[str] = (
        "(?i)constraintonaddedobject\\s*=\\s*\\(([^)]+)\\)"
    )
    ACL_TARGET_DN_EXTRACT: ClassVar[str] = 'target\\s*=\\s*"([^"]*)"'
    ACL_TARGET_ATTR_OID_EXTRACT: ClassVar[str] = "attr\\s*=\\s*\\(([^)]+)\\)"
    ACL_PERMS_EXTRACT_OID: ClassVar[str] = (
        "\\s\\(([^()]+)\\)(?:\\s*(?:filter=|added_object | bindmode|Deny | Append|bindip | constrain|$))"
    )
    ACL_TARGET_DN_EXTRACT_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
        ACL_TARGET_DN_EXTRACT,
        re.IGNORECASE,
    )
    ACL_TARGET_ATTR_OID_EXTRACT_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
        ACL_TARGET_ATTR_OID_EXTRACT,
        re.IGNORECASE,
    )
    ACL_PERMS_EXTRACT_OID_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
        ACL_PERMS_EXTRACT_OID,
        re.IGNORECASE,
    )
    ONE_OID: ClassVar[str] = c.Ldif.OID_TRUE
    ZERO_OID: ClassVar[str] = c.Ldif.OID_FALSE
    RFC_TO_OID: ClassVar[t.StrMapping] = c.Ldif.RFC_TO_OID_BOOL
    INVALID_SUBSTR_RULES: ClassVar[t.OptionalStrMapping] = MappingProxyType({
        "caseIgnoreMatch": "caseIgnoreSubstringsMatch",
        "caseExactMatch": "caseExactSubstringsMatch",
        "distinguishedNameMatch": None,
        "integerMatch": None,
        "numericStringMatch": "numericStringSubstringsMatch",
    })
    ACL_ACCESS_TO: ClassVar[str] = "access to"
    ACL_BY: ClassVar[str] = "by"
    ACL_SUBJECT_PATTERNS: ClassVar[t.MappingKV[str, tuple[str | None, str, str]]] = (
        MappingProxyType({
            " by self ": (None, OidAclSubjectType.SELF, "ldap:///self"),
            " by self)": (None, OidAclSubjectType.SELF, "ldap:///self"),
            " by * ": (None, OidAclSubjectType.ANONYMOUS, OidAclSubjectType.ANONYMOUS),
            " by *(": (None, OidAclSubjectType.ANONYMOUS, OidAclSubjectType.ANONYMOUS),
            ' by "': ('by\\s+"([^"]+)"', OidAclSubjectType.USER_DN, "ldap:///{0}"),
            " by group=": (
                'by\\s+group\\s*=\\s*"([^"]+)"',
                OidAclSubjectType.GROUP_DN,
                "ldap:///{0}",
            ),
            " by dnattr=": (
                "by\\s+dnattr\\s*=\\s*\\(([^)]+)\\)",
                OidAclSubjectType.DN_ATTR,
                "{0}#" + OidAclSubjectSuffix.LDAPURL,
            ),
            " by guidattr=": (
                "by\\s+guidattr\\s*=\\s*\\(([^)]+)\\)",
                OidAclSubjectType.GUID_ATTR,
                "{0}#" + OidAclSubjectSuffix.USERDN,
            ),
            " by groupattr=": (
                "by\\s+groupattr\\s*=\\s*\\(([^)]+)\\)",
                OidAclSubjectType.GROUP_ATTR,
                "{0}#" + OidAclSubjectSuffix.GROUPDN,
            ),
        })
    )
    ACL_PERMISSION_MAPPING: ClassVar[t.StrSequenceMapping] = MappingProxyType({
        "all": ("read", "write", "add", "delete", "search", "compare", "proxy"),
        "browse": ("read", "search"),
        "read": ("read",),
        "write": ("write",),
        "add": ("add",),
        "delete": ("delete",),
        "search": ("search",),
        "compare": ("compare",),
        "selfwrite": ("self_write",),
        "proxy": ("proxy",),
        "auth": ("auth",),
        "nowrite": ("no_write",),
        "noadd": ("no_add",),
        "nodelete": ("no_delete",),
        "nobrowse": ("no_browse",),
        "noselfwrite": ("no_self_write",),
    })
    ACL_PERMISSION_NAMES: ClassVar[t.StrMapping] = MappingProxyType({
        "read": "read",
        "write": "write",
        "add": "add",
        "delete": "delete",
        "search": "search",
        "compare": "compare",
        "self_write": "selfwrite",
        "proxy": "proxy",
        "browse": "browse",
        "auth": "auth",
        "all": "all",
        "no_write": "nowrite",
        "no_add": "noadd",
        "no_delete": "nodelete",
        "no_browse": "nobrowse",
        "no_self_write": "noselfwrite",
    })
    SUPPORTED_PERMISSIONS: ClassVar[frozenset[str]] = frozenset({
        *c.Ldif.ACL_PERMISSION_KEYS,
        c.Ldif.RfcAclPermission.NONE,
        "no_write",
        "no_add",
        "no_delete",
        "no_browse",
        "no_self_write",
    })
    ATTRIBUTE_TRANSFORMATION_OID_TO_RFC: ClassVar[t.StrMapping] = (
        c.Ldif.ATTRIBUTE_TRANSFORMATION_OID_TO_RFC
    )
    ATTRIBUTE_TRANSFORMATION_RFC_TO_OID: ClassVar[t.StrMapping] = (
        c.Ldif.ATTRIBUTE_TRANSFORMATION_RFC_TO_OID
    )


c = FlextLdifServersOidConstants
