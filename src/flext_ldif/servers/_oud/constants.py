"""Oracle Unified Directory (OUD) Quirks."""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

from flext_core import FlextLogger

from flext_ldif.servers.rfc import FlextLdifServersRfc

logger = FlextLogger(__name__)


class FlextLdifServersOudConstants(FlextLdifServersRfc.Constants):
    """Oracle Unified Directory-specific constants using Python 3.13 patterns."""

    SERVER_TYPE: ClassVar[str] = "oud"
    PRIORITY: ClassVar[int] = 10

    DEFAULT_PORT: ClassVar[int] = 1389
    DEFAULT_SSL_PORT: ClassVar[int] = 1636
    DEFAULT_PAGE_SIZE: ClassVar[int] = 1000

    MAX_LOG_LINE_LENGTH: ClassVar[int] = 200

    CANONICAL_NAME: ClassVar[str] = "oud"
    ALIASES: ClassVar[frozenset[str]] = frozenset([
        "oud",
        "oracle_oud",
    ])

    CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset([
        "oud",
        "rfc",
    ])
    CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset([
        "oud",
        "rfc",
    ])

    ACL_FORMAT: ClassVar[str] = "aci"
    ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"

    PERMISSION_SELFWRITE: ClassVar[str] = "selfwrite"
    PERMISSION_SELF_WRITE: ClassVar[str] = "self_write"
    PERMISSION_PROXY: ClassVar[str] = "proxy"
    PERMISSION_ALL: ClassVar[str] = "all"

    SUPPORTED_PERMISSIONS: ClassVar[frozenset[str]] = frozenset(
        [
            "read",
            "write",
            "add",
            "delete",
            "search",
            "compare",
            "selfwrite",
            "proxy",
            "all",
        ],
    )

    ACL_DEFAULT_NAME: ClassVar[str] = "OUD ACL"
    ACL_DEFAULT_TARGETATTR: ClassVar[str] = "*"
    ACL_DEFAULT_VERSION: ClassVar[str] = "version 3.0"
    ACL_VERSION_PREFIX: ClassVar[str] = "(version 3.0"
    ACL_ALLOW_PREFIX: ClassVar[str] = "allow ("
    ACL_ACI_PREFIX: ClassVar[str] = "aci:"
    ACL_DS_CFG_PREFIX: ClassVar[str] = "ds-cfg-"

    ACL_TARGETATTR_PREFIX: ClassVar[str] = "targetattr="
    ACL_TARGETSCOPE_PREFIX: ClassVar[str] = "targetscope="
    ACL_LDAP_URL_PREFIX: ClassVar[str] = "ldap:///"

    ACL_SELF_SUBJECT: ClassVar[str] = "ldap:///self"
    ACL_ANONYMOUS_SUBJECT: ClassVar[str] = "ldap:///anyone"
    ACL_ANONYMOUS_SUBJECT_ALT: ClassVar[str] = "ldap:///*"

    ACL_NEWLINE_SEPARATOR: ClassVar[str] = "\n"
    ACL_OPS_SEPARATOR: ClassVar[str] = ","
    ACL_ACTION_ALLOW: ClassVar[str] = "allow"
    ACL_ACTION_DENY: ClassVar[str] = "deny"
    ACL_BIND_RULE_KEY_TYPE: ClassVar[str] = "type"
    ACL_BIND_RULE_KEY_VALUE: ClassVar[str] = "value"
    ACL_SUBJECT_TYPE_BIND_RULES: ClassVar[str] = "bind_rules"

    ACL_BIND_RULE_TYPE_USERDN: ClassVar[str] = "userdn"
    ACL_BIND_RULE_TYPE_GROUPDN: ClassVar[str] = "groupdn"

    ACL_USERDN_PATTERN: ClassVar[str] = r'userdn\s*=\s*"ldap:///([^"]+)"'
    ACL_GROUPDN_PATTERN: ClassVar[str] = r'groupdn\s*=\s*"ldap:///([^"]+)"'
    ACL_TARGETATTR_PATTERN: ClassVar[str] = r'\(targetattr\s*(!?=)\s*"([^"]+)"\)'
    ACL_TARGETSCOPE_PATTERN: ClassVar[str] = r'\(targetscope\s*=\s*"([^"]+)"\)'
    ACL_VERSION_ACL_PATTERN: ClassVar[str] = r'version\s+([\d.]+);\s*acl\s+"([^"]+)"'
    ACL_ALLOW_DENY_PATTERN: ClassVar[str] = r"(allow|deny)\s+\(([^)]+)\)"
    ACL_BY_GROUP_PATTERN: ClassVar[str] = r"by\s+group=\"[^\"]+\""
    ACL_BY_STAR_PATTERN: ClassVar[str] = r"by\s+\*"

    ACL_TARGATTRFILTERS_PATTERN: ClassVar[str] = r'\(targattrfilters\s*=\s*"([^"]+)"\)'
    ACL_TARGETCONTROL_PATTERN: ClassVar[str] = r'\(targetcontrol\s*=\s*"([^"]+)"\)'
    ACL_EXTOP_PATTERN: ClassVar[str] = r'\(extop\s*=\s*"([^"]+)"\)'
    ACL_IP_PATTERN: ClassVar[str] = r'ip\s*=\s*"([^"]+)"'
    ACL_DNS_PATTERN: ClassVar[str] = r'dns\s*=\s*"([^"]+)"'
    ACL_DAYOFWEEK_PATTERN: ClassVar[str] = r'dayofweek\s*=\s*"([^"]+)"'
    ACL_TIMEOFDAY_PATTERN: ClassVar[str] = r'timeofday\s*([<>=!]+)\s*"?(\d+)"?'
    ACL_AUTHMETHOD_PATTERN: ClassVar[str] = r'authmethod\s*=\s*"?(\w+)"?'
    ACL_SSF_PATTERN: ClassVar[str] = r'ssf\s*([<>=!]+)\s*"?(\d+)"?'

    ACL_BIND_RULE_TUPLE_LENGTH: ClassVar[int] = 2

    ACL_BIND_RULES_CONFIG: ClassVar[list[tuple[str, str, str | None]]] = [
        ("bind_ip", 'ip="{value}"', None),
        ("bind_dns", 'dns="{value}"', None),
        ("bind_dayofweek", 'dayofweek="{value}"', None),
        ("bind_timeofday", 'timeofday {operator} "{value}"', "="),
        ("authmethod", 'authmethod = "{value}"', None),
        ("ssf", 'ssf {operator} "{value}"', ">="),
    ]

    ACL_TARGET_EXTENSIONS_CONFIG: ClassVar[list[tuple[str, str]]] = [
        ("targattrfilters", '(targattrfilters="{value}")'),
        ("targetcontrol", '(targetcontrol="{value}")'),
        ("extop", '(extop="{value}")'),
    ]

    ACL_BIND_PATTERNS: ClassVar[Mapping[str, str]] = {
        ACL_BIND_RULE_TYPE_USERDN: ACL_USERDN_PATTERN,
        ACL_BIND_RULE_TYPE_GROUPDN: ACL_GROUPDN_PATTERN,
    }

    ACL_NORMALIZE_DNS_IN_VALUES: ClassVar[bool] = False

    DS_PRIVILEGE_NAME_KEY: ClassVar[str] = "ds_privilege_name"
    FORMAT_TYPE_KEY: ClassVar[str] = "format_type"
    FORMAT_TYPE_DS_PRIVILEGE: ClassVar[str] = "ds-privilege-name"

    SCHEMA_DN: ClassVar[str] = "cn=schema"

    SCHEMA_FIELD_ATTRIBUTE_TYPES: ClassVar[str] = "attributetypes"
    SCHEMA_FIELD_OBJECT_CLASSES: ClassVar[str] = "objectclasses"
    SCHEMA_FIELD_MATCHING_RULES: ClassVar[str] = "matchingrules"
    SCHEMA_FIELD_LDAP_SYNTAXES: ClassVar[str] = "ldapsyntaxes"

    SCHEMA_FILTERABLE_FIELDS: ClassVar[frozenset[str]] = frozenset(
        [
            SCHEMA_FIELD_ATTRIBUTE_TYPES,
            SCHEMA_FIELD_OBJECT_CLASSES,
            SCHEMA_FIELD_MATCHING_RULES,
            SCHEMA_FIELD_LDAP_SYNTAXES,
        ],
    )

    ATTRIBUTE_FIELDS: ClassVar[frozenset[str]] = frozenset(["x_origin"])

    OBJECTCLASS_REQUIREMENTS: ClassVar[Mapping[str, bool]] = {
        "requires_sup_for_auxiliary": True,
        "allows_multiple_sup": False,
        "requires_explicit_structural": True,
    }

    ATTRIBUTE_UNDERSCORE_TO_DASH: ClassVar[str] = "_"
    ATTRIBUTE_DASH_REPLACEMENT: ClassVar[str] = "-"

    DEFAULT_ENCODING: ClassVar[str] = "utf-8"
    ALLOWED_ENCODINGS: ClassVar[tuple[str, ...]] = ("utf-8", "utf-16", "ascii")
    DN_PRESERVE_CASE: ClassVar[bool] = False
    DN_NORMALIZE_TO: ClassVar[str] = "lowercase"
    ACL_REQUIRES_TARGET: ClassVar[bool] = True
    ACL_REQUIRES_SUBJECT: ClassVar[bool] = True
    TRACK_DELETIONS: ClassVar[bool] = True
    TRACK_MODIFICATIONS: ClassVar[bool] = True
    TRACK_CONVERSIONS: ClassVar[bool] = True

    OPERATIONAL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
        [
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
        ],
    )

    OUD_SPECIFIC: ClassVar[frozenset[str]] = frozenset(
        [
            "ds-sync-hist",
            "ds-sync-state",
            "ds-pwp-account-disabled",
            "ds-cfg-backend-id",
            "entryUUID",
        ],
    )

    PRESERVE_ON_MIGRATION: ClassVar[frozenset[str]] = (
        FlextLdifServersRfc.Constants.PRESERVE_ON_MIGRATION
        | frozenset(["pwdChangedTime"])
    )

    BOOLEAN_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
        [
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
        ],
    )

    ATTRIBUTE_CASE_MAP: ClassVar[dict[str, str]] = {
        "uniquemember": "uniqueMember",
        "displayname": "displayName",
        "distinguishedname": "distinguishedName",
        "objectclass": "objectClass",
        "memberof": "memberOf",
        "seealsodescription": "seeAlsoDescription",
        "acl": "aci",
    }

    ATTRIBUTE_TRANSFORMATION_OUD_TO_RFC: ClassVar[Mapping[str, str]] = {
        "ds-sync-hist": "dsyncHist",
        "ds-pwp-account-disabled": "accountDisabled",
        "entryUUID": "entryUUID",
    }

    ATTRIBUTE_TRANSFORMATION_RFC_TO_OUD: ClassVar[Mapping[str, str]] = {
        "dsyncHist": "ds-sync-hist",
        "accountDisabled": "ds-pwp-account-disabled",
        "entryUUID": "entryUUID",
    }

    ATTRIBUTE_ALIASES: ClassVar[Mapping[str, list[str]]] = {
        "cn": ["commonName"],
        "sn": ["surname"],
        "givenName": ["gn"],
        "mail": ["rfc822Mailbox", "emailAddress"],
        "telephoneNumber": ["phone"],
        "uid": ["userid", "username"],
    }

    RFC_TO_OUD_SUBJECTS: ClassVar[Mapping[str, tuple[str, str]]] = {
        "group_membership": ("bind_rules", 'userattr="{value}#LDAPURL"'),
        "user_attribute": ("bind_rules", 'userattr="{value}#USERDN"'),
        "group_attribute": ("bind_rules", 'userattr="{value}#GROUPDN"'),
    }

    OUD_TO_RFC_SUBJECTS: ClassVar[Mapping[str, tuple[str, str]]] = {
        "bind_rules": ("group_membership", "{value}"),
    }

    INVALID_SUBSTR_RULES: ClassVar[Mapping[str, str | None]] = {
        "caseIgnoreMatch": "caseIgnoreSubstringsMatch",
        "distinguishedNameMatch": None,
        "caseIgnoreOrderingMatch": None,
        "numericStringMatch": "numericStringSubstringsMatch",
    }

    MATCHING_RULE_REPLACEMENTS: ClassVar[Mapping[str, str]] = {
        "caseIgnoreMatch": "caseIgnoreMatch",
        "caseIgnoreSubstringsMatch": "caseIgnoreSubstringsMatch",
    }

    CATEGORY_OBJECTCLASSES: ClassVar[dict[str, frozenset[str]]] = {
        "users": frozenset(
            [
                "person",
                "inetOrgPerson",
                "organizationalPerson",
            ],
        ),
        "hierarchy": frozenset(
            [
                "organizationalUnit",
                "organization",
                "domain",
                "country",
                "locality",
            ],
        ),
        "groups": frozenset(
            [
                "groupOfNames",
                "groupOfUniqueNames",
            ],
        ),
    }

    HIERARCHY_PRIORITY_OBJECTCLASSES: ClassVar[frozenset[str]] = frozenset(
        [
            "organizationalUnit",
            "organization",
            "domain",
        ],
    )

    CATEGORIZATION_ACL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
        [
            "aci",
        ],
    )

    CATEGORIZATION_PRIORITY: ClassVar[list[str]] = [
        "schema",
        "acl",
        "users",
        "hierarchy",
        "groups",
        "rejected",
    ]

    DN_PREFIX_CN_CONFIG: ClassVar[str] = "cn=config"
    DN_PREFIX_CN_SCHEMA: ClassVar[str] = "cn=schema"
    DN_PREFIX_CN_DIRECTORY: ClassVar[str] = "cn=directory"
    DN_PREFIX_CN_DS: ClassVar[str] = "cn=ds"

    DN_DETECTION_PATTERNS: ClassVar[tuple[tuple[str, ...], ...]] = (
        ("cn=config", "cn=schema"),
        ("cn=config", "cn=directory"),
        ("cn=config", "cn=ds"),
    )

    KEYWORD_PATTERNS: ClassVar[tuple[str, ...]] = ("pwd", "password")

    DETECTION_PATTERN: ClassVar[str] = r"(?i)(ds-sync-|ds-pwp-|ds-cfg-|root dns)"

    DETECTION_OID_PATTERN: ClassVar[str] = DETECTION_PATTERN
    DETECTION_WEIGHT: ClassVar[int] = 14
    DETECTION_ACL_PREFIX: ClassVar[str] = "ds-cfg-"

    DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset(
        [
            "ds-",
            "ds-sync",
            "ds-pwp",
            "ds-cfg",
        ],
    )

    DETECTION_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
        [
            "ds-sync-hist",
            "ds-sync-state",
            "ds-pwp-account-disabled",
            "ds-cfg-backend-id",
            "ds-privilege-name",
            "entryUUID",
        ],
    )

    DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset(
        [
            "ds-root-dse",
            "ds-root-dn-user",
            "ds-unbound-id-config",
            "ds-cfg-backend",
        ],
    )

    DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset(
        [
            "cn=config",
            "cn=tasks",
            "cn=monitor",
        ],
    )
