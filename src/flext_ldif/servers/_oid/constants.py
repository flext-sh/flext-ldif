"""Oracle Internet Directory (OID) Quirks."""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

from flext_core import FlextLogger

from flext_ldif.servers.rfc import FlextLdifServersRfc

logger = FlextLogger(__name__)


class FlextLdifServersOidConstants(FlextLdifServersRfc.Constants):
    """Oracle Internet Directory (OID) constants for LDIF processing."""

    SERVER_TYPE: ClassVar[str] = "oid"
    PRIORITY: ClassVar[int] = 10

    MAX_LOG_LINE_LENGTH: ClassVar[int] = 200

    ORCLACI: ClassVar[str] = "orclaci"
    ORCLENTRYLEVELACI: ClassVar[str] = "orclentrylevelaci"
    ACL_FORMAT: ClassVar[str] = "orclaci"
    ACL_ATTRIBUTE_NAME: ClassVar[str] = "orclaci"

    MATCHING_RULE_TO_RFC: ClassVar[dict[str, str]] = {
        "caseIgnoreSubStringsMatch": "caseIgnoreSubstringsMatch",
        "accessDirectiveMatch": "caseIgnoreMatch",
    }

    MATCHING_RULE_RFC_TO_OID: ClassVar[dict[str, str]] = {
        "caseIgnoreSubstringsMatch": "caseIgnoreSubStringsMatch",
        "caseIgnoreMatch": "accessDirectiveMatch",
    }

    SYNTAX_OID_TO_RFC: ClassVar[dict[str, str]] = {
        "1.3.6.1.4.1.1466.115.121.1.1": ("1.3.6.1.4.1.1466.115.121.1.15"),
    }

    SYNTAX_RFC_TO_OID: ClassVar[dict[str, str]] = {
        "1.3.6.1.4.1.1466.115.121.1.15": "1.3.6.1.4.1.1466.115.121.1.1",
    }

    ATTR_NAME_CASE_MAP: ClassVar[dict[str, str]] = {
        "middlename": "middleName",
    }

    OPERATIONAL_ATTRIBUTES: ClassVar[frozenset[str]] = (
        FlextLdifServersRfc.Constants.OPERATIONAL_ATTRIBUTES
        | frozenset(
            [
                "orclguid",
                "orclobjectguid",
                "orclentryid",
                "orclaccount",
                "pwdChangedTime",
                "pwdHistory",
                "pwdFailureTime",
            ],
        )
    )

    DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset(
        [
            "orcl",
            "orclguid",
        ],
    )
    DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset(
        [
            "orcldirectory",
            "orcldomain",
            "orcldirectoryserverconfig",
            "orclcontainer",
        ],
    )
    DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset(
        [
            "cn=orcl",
            "cn=subscriptions",
            "cn=oracle context",
        ],
    )

    SCHEMA_FILTERABLE_FIELDS: ClassVar[frozenset[str]] = frozenset(
        [
            "attributetypes",
            "objectclasses",
            "matchingrules",
            "ldapsyntaxes",
        ],
    )

    SCHEMA_DN_QUIRK: ClassVar[str] = "cn=subschemasubentry"

    BOOLEAN_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
        [
            "orclisenabled",
            "orclaccountlocked",
            "orclpwdmustchange",
            "orclpasswordverify",
            "orclisvisible",
            "orclsamlenable",
            "orclsslenable",
            "orcldasenableproductlogo",
            "orcldasenablesubscriberlogo",
            "orcldasshowproductlogo",
            "orcldasenablebranding",
            "orcldasisenabled",
            "orcldasismandatory",
            "orcldasispersonal",
            "orcldassearchable",
            "orcldasselfmodifiable",
            "orcldasviewable",
            "orcldasREDACTED_LDAP_BIND_PASSWORDmodifiable",
            "pwdlockout",
            "pwdmustchange",
            "pwdallowuserchange",
        ],
    )

    ATTRIBUTE_FIELDS: ClassVar[frozenset[str]] = frozenset(["usage", "x_origin"])

    OBJECTCLASS_REQUIREMENTS: ClassVar[Mapping[str, bool]] = {
        "requires_sup_for_auxiliary": True,
        "allows_multiple_sup": True,
        "requires_explicit_structural": False,
    }

    OID_SPECIFIC_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
        [
            "orclaci",
            "orclentrylevelaci",
            "orclguid",
            "orcloid",
            "orclpassword",
            "orcldaslov",
            "orclmailaddr",
            "orcluseractivefrom",
            "orcluserinactivefrom",
        ],
    )

    CANONICAL_NAME: ClassVar[str] = "oid"
    ALIASES: ClassVar[frozenset[str]] = frozenset(["oid", "oracle_oid"])
    CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["oid"])
    CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["oid", "rfc"])

    DETECTION_PATTERN: ClassVar[str] = r"2\.16\.840\.1\.113894\.|orcl"

    DETECTION_OID_PATTERN: ClassVar[str] = r"2\.16\.840\.1\.113894\.|orcl"
    DETECTION_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
        [
            "orclOID",
            "orclGUID",
            "orclPassword",
            "orclaci",
            "orclentrylevelaci",
            "orcldaslov",
        ],
    )

    DETECTION_WEIGHT: ClassVar[int] = 12

    OID_SPECIFIC_RIGHTS: ClassVar[str] = "oid_specific_rights"
    RFC_NORMALIZED: ClassVar[str] = "rfc_normalized"
    ORIGINAL_OID_PERMS: ClassVar[str] = "original_oid_perms"

    OID_ACL_SOURCE_TARGET: ClassVar[str] = "acl_source_target"

    ALL_OID_KEYS: ClassVar[frozenset[str]] = frozenset(
        [
            OID_SPECIFIC_RIGHTS,
            RFC_NORMALIZED,
            ORIGINAL_OID_PERMS,
            OID_ACL_SOURCE_TARGET,
        ],
    )

    CATEGORIZATION_PRIORITY: ClassVar[list[str]] = [
        "acl",
        "users",
        "hierarchy",
        "groups",
    ]

    CATEGORY_OBJECTCLASSES: ClassVar[dict[str, frozenset[str]]] = {
        "users": frozenset(
            [
                "person",
                "inetOrgPerson",
                "orclUser",
                "orclUserV2",
            ],
        ),
        "hierarchy": frozenset(
            [
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
            ],
        ),
        "groups": frozenset(
            [
                "groupOfNames",
                "groupOfUniqueNames",
                "orclGroup",
                "orclPrivilegeGroup",
            ],
        ),
    }

    HIERARCHY_PRIORITY_OBJECTCLASSES: ClassVar[frozenset[str]] = frozenset(
        [
            "orclContainer",
            "organizationalUnit",
            "organization",
            "domain",
        ],
    )

    CATEGORIZATION_ACL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
        [
            "aci",
            "orclaci",
            "orclentrylevelaci",
        ],
    )

    CN_ORCL: ClassVar[str] = "cn=orcl"
    OU_ORACLE: ClassVar[str] = "ou=oracle"
    DC_ORACLE: ClassVar[str] = "dc=oracle"

    ORACLE_DN_PATTERNS: ClassVar[frozenset[str]] = frozenset(
        [
            CN_ORCL,
            OU_ORACLE,
            DC_ORACLE,
        ],
    )

    ACL_SUBJECT_TYPE_USER: ClassVar[str] = "user"
    ACL_SUBJECT_TYPE_GROUP: ClassVar[str] = "group"
    ACL_SUBJECT_TYPE_ROLE: ClassVar[str] = "role"
    ACL_SUBJECT_TYPE_SELF: ClassVar[str] = "self"
    ACL_SUBJECT_TYPE_ANONYMOUS: ClassVar[str] = "anonymous"

    ACL_TYPE_PATTERN: ClassVar[str] = r"^(orclaci | orclentrylevelaci):"
    ACL_TARGET_PATTERN: ClassVar[str] = r"access to (entry | attr=\(([^)]+)\))"
    ACL_SUBJECT_PATTERN: ClassVar[str] = (
        r"by\s+(group=\"[^\"]+\"|dnattr=\([^)]+\)|guidattr=\([^)]+\"|groupattr=\([^)]+\"|\"[^\"]+\"|self|\*)"
    )
    ACL_PERMISSIONS_PATTERN: ClassVar[str] = r"\(([^)]+)\)(?:\s*$)"
    ACL_FILTER_PATTERN: ClassVar[str] = r"filter=(\([^)]*(?:\([^)]*\)[^)]*)*\))"
    ACL_CONSTRAINT_PATTERN: ClassVar[str] = r"added_object_constraint=\(([^)]+)\)"

    ACL_BINDMODE_PATTERN: ClassVar[str] = r"(?i)bindmode\s*=\s*\(([^)]+)\)"
    ACL_DENY_GROUP_OVERRIDE_PATTERN: ClassVar[str] = r"DenyGroupOverride"
    ACL_APPEND_TO_ALL_PATTERN: ClassVar[str] = r"AppendToAll"
    ACL_BIND_IP_FILTER_PATTERN: ClassVar[str] = r"(?i)bindipfilter\s*=\s*\(([^)]+)\)"
    ACL_CONSTRAIN_TO_ADDED_PATTERN: ClassVar[str] = (
        r"(?i)constraintonaddedobject\s*=\s*\(([^)]+)\)"
    )

    ACL_TARGET_DN_EXTRACT: ClassVar[str] = r'target\s*=\s*"([^"]*)"'
    ACL_TARGET_ATTR_EXTRACT: ClassVar[str] = r'targetattr\s*=\s*"([^"]*)"'

    ACL_TARGET_ATTR_OID_EXTRACT: ClassVar[str] = r"attr\s*=\s*\(([^)]+)\)"

    ACL_SUBJECT_USER_DETECT: ClassVar[str] = r'subject\s*=\s*"[^"]*userdn'
    ACL_SUBJECT_GROUP_DETECT: ClassVar[str] = r'subject\s*=\s*"[^"]*groupdn'
    ACL_SUBJECT_ROLE_DETECT: ClassVar[str] = r'subject\s*=\s*"[^"]*roledn'

    ACL_ALLOW_PERMS_EXTRACT: ClassVar[str] = r"\(allow\s+\(([^)]*)\)"
    ACL_DENY_PERMS_EXTRACT: ClassVar[str] = r"\(deny\s+\(([^)]*)\)"

    ACL_PERMS_EXTRACT_OID: ClassVar[str] = (
        r"\s\(([^()]+)\)(?:\s*(?:filter=|added_object | bindmode|Deny | Append|bindip | constrain|$))"
    )

    ACL_PATTERN_KEY_TYPE: ClassVar[str] = "acl_type"
    ACL_PATTERN_KEY_TARGET: ClassVar[str] = "target"
    ACL_PATTERN_KEY_SUBJECT: ClassVar[str] = "subject"
    ACL_PATTERN_KEY_PERMISSIONS: ClassVar[str] = "permissions"
    ACL_PATTERN_KEY_FILTER: ClassVar[str] = "filter"
    ACL_PATTERN_KEY_CONSTRAINT: ClassVar[str] = "constraint"

    ONE_OID: ClassVar[str] = "1"
    ZERO_OID: ClassVar[str] = "0"

    OID_TO_RFC: ClassVar[dict[str, str]] = {
        ONE_OID: "TRUE",
        ZERO_OID: "FALSE",
        "true": "TRUE",
        "false": "FALSE",
    }

    RFC_TO_OID: ClassVar[dict[str, str]] = {
        "TRUE": ONE_OID,
        "FALSE": ZERO_OID,
        "true": ONE_OID,
        "false": ZERO_OID,
    }

    OID_TRUE_VALUES: ClassVar[frozenset[str]] = frozenset(
        [
            ONE_OID,
            "true",
            "True",
            "TRUE",
        ],
    )
    OID_FALSE_VALUES: ClassVar[frozenset[str]] = frozenset(
        [
            ZERO_OID,
            "false",
            "False",
            "FALSE",
        ],
    )

    INVALID_SUBSTR_RULES: ClassVar[dict[str, str | None]] = {
        "caseIgnoreMatch": "caseIgnoreSubstringsMatch",
        "caseExactMatch": "caseExactSubstringsMatch",
        "distinguishedNameMatch": None,
        "integerMatch": None,
        "numericStringMatch": "numericStringSubstringsMatch",
    }

    ACL_ACCESS_TO: ClassVar[str] = "access to"
    ACL_BY: ClassVar[str] = "by"
    ACL_FORMAT_DEFAULT: ClassVar[str] = "default"
    ACL_FORMAT_ONELINE: ClassVar[str] = "oneline"
    ACL_NAME: ClassVar[str] = "OID ACL"

    ACL_SUBJECT_PATTERNS: ClassVar[dict[str, tuple[str | None, str, str]]] = {
        " by self ": (None, "self", "ldap:///self"),
        " by self)": (None, "self", "ldap:///self"),
        " by * ": (None, "*", "*"),
        " by *(": (None, "*", "*"),
        ' by "': (r'by\s+"([^"]+)"', "user_dn", "ldap:///{0}"),
        " by group=": (r'by\s+group\s*=\s*"([^"]+)"', "group_dn", "ldap:///{0}"),
        " by dnattr=": (r"by\s+dnattr\s*=\s*\(([^)]+)\)", "dn_attr", "{0}#LDAPURL"),
        " by guidattr=": (
            r"by\s+guidattr\s*=\s*\(([^)]+)\)",
            "guid_attr",
            "{0}#USERDN",
        ),
        " by groupattr=": (
            r"by\s+groupattr\s*=\s*\(([^)]+)\)",
            "group_attr",
            "{0}#GROUPDN",
        ),
    }

    ACL_SUBJECT_FORMATTERS: ClassVar[dict[str, tuple[str, bool]]] = {
        "self": ("self", False),
        "user_dn": ('"{0}"', True),
        "group_dn": ('group="{0}"', True),
        "group": (
            'group="{0}"',
            True,
        ),
        "dn_attr": ("dnattr=({0})", False),
        "guid_attr": ("guidattr=({0})", False),
        "group_attr": ("groupattr=({0})", False),
    }

    ACL_PERMISSION_MAPPING: ClassVar[dict[str, list[str]]] = {
        "all": ["read", "write", "add", "delete", "search", "compare", "proxy"],
        "browse": ["read", "search"],
        "read": ["read"],
        "write": ["write"],
        "add": ["add"],
        "delete": ["delete"],
        "search": ["search"],
        "compare": ["compare"],
        "selfwrite": ["self_write"],
        "proxy": ["proxy"],
        "auth": ["auth"],
        "nowrite": ["no_write"],
        "noadd": ["no_add"],
        "nodelete": ["no_delete"],
        "nobrowse": ["no_browse"],
        "noselfwrite": ["no_self_write"],
    }

    ACL_PERMISSION_NAMES: ClassVar[dict[str, str]] = {
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
    }

    SUPPORTED_PERMISSIONS: ClassVar[frozenset[str]] = frozenset(
        [
            "read",
            "write",
            "add",
            "delete",
            "search",
            "compare",
            "self_write",
            "proxy",
            "browse",
            "auth",
            "all",
            "none",
            "no_write",
            "no_add",
            "no_delete",
            "no_browse",
            "no_self_write",
        ],
    )

    ATTRIBUTE_TRANSFORMATION_OID_TO_RFC: ClassVar[Mapping[str, str]] = {
        "orclguid": "entryUUID",
        "orclaci": "aci",
        "orclentrylevelaci": "aci",
    }

    ATTRIBUTE_TRANSFORMATION_RFC_TO_OID: ClassVar[Mapping[str, str]] = {
        "entryUUID": "orclguid",
        "aci": "orclaci",
    }
