"""Oracle Unified Directory (OUD) Servers."""

from __future__ import annotations

import re
from types import MappingProxyType
from typing import ClassVar

from flext_ldif import FlextLdifServersRfc, c, t


class FlextLdifServersOudConstants(FlextLdifServersRfc.Constants):
    """Oracle Unified Directory-specific constants using Python 3.13 patterns."""

    SERVER_TYPE: ClassVar[str] = c.Ldif.ServerTypes.OUD
    PRIORITY: ClassVar[int] = 10
    DEFAULT_PORT: ClassVar[int] = 1389
    DEFAULT_SSL_PORT: ClassVar[int] = 1636
    DEFAULT_PAGE_SIZE: ClassVar[int] = 1000
    MAX_LOG_LINE_LENGTH: ClassVar[int] = 200
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
    PERMISSION_SELFWRITE: ClassVar[str] = "selfwrite"
    PERMISSION_SELF_WRITE: ClassVar[str] = "self_write"
    PERMISSION_PROXY: ClassVar[str] = "proxy"
    PERMISSION_ALL: ClassVar[str] = "all"
    SUPPORTED_PERMISSIONS: ClassVar[frozenset[str]] = (
        FlextLdifServersRfc.Constants.SUPPORTED_PERMISSIONS
        | frozenset([
            PERMISSION_SELFWRITE,
            PERMISSION_PROXY,
            PERMISSION_ALL,
        ])
    )
    ACL_DEFAULT_NAME: ClassVar[str] = "OUD ACL"
    ACL_DEFAULT_VERSION: ClassVar[str] = "version 3.0"
    ACL_VERSION_PREFIX: ClassVar[str] = "(version 3.0"
    ACL_ALLOW_PREFIX: ClassVar[str] = "allow ("
    ACL_ACI_PREFIX: ClassVar[str] = "aci:"
    ACL_DS_CFG_PREFIX: ClassVar[str] = "ds-cfg-"
    ACL_TARGETATTR_PREFIX: ClassVar[str] = "targetattr="
    ACL_TARGETSCOPE_PREFIX: ClassVar[str] = "targetscope="
    ACL_SELF_SUBJECT: ClassVar[str] = "ldap:///self"
    ACL_ANONYMOUS_SUBJECT: ClassVar[str] = "ldap:///anyone"
    ACL_OPS_SEPARATOR: ClassVar[str] = ","
    ACL_SUBJECT_TYPE_BIND_RULES: ClassVar[str] = "bind_rules"
    ACL_BIND_RULE_TYPE_USERDN: ClassVar[str] = "userdn"
    ACL_BIND_RULE_TYPE_GROUPDN: ClassVar[str] = "groupdn"
    ACL_USERDN_PATTERN: ClassVar[str] = 'userdn\\s*=\\s*"ldap:///([^"]+)"'
    ACL_GROUPDN_PATTERN: ClassVar[str] = 'groupdn\\s*=\\s*"ldap:///([^"]+)"'
    ACL_TARGETATTR_PATTERN: ClassVar[str] = '\\(targetattr\\s*(!?=)\\s*"([^"]+)"\\)'
    ACL_TARGETSCOPE_PATTERN: ClassVar[str] = '\\(targetscope\\s*=\\s*"([^"]+)"\\)'
    ACL_VERSION_ACL_PATTERN: ClassVar[str] = 'version\\s+([\\d.]+);\\s*acl\\s+"([^"]+)"'
    ACL_ALLOW_DENY_PATTERN: ClassVar[str] = "(allow|deny)\\s+\\(([^)]+)\\)"
    ACL_TARGATTRFILTERS_PATTERN: ClassVar[str] = (
        '\\(targattrfilters\\s*=\\s*"([^"]+)"\\)'
    )
    ACL_TARGETCONTROL_PATTERN: ClassVar[str] = '\\(targetcontrol\\s*=\\s*"([^"]+)"\\)'
    ACL_EXTOP_PATTERN: ClassVar[str] = '\\(extop\\s*=\\s*"([^"]+)"\\)'
    ACL_IP_PATTERN: ClassVar[str] = 'ip\\s*=\\s*"([^"]+)"'
    ACL_DNS_PATTERN: ClassVar[str] = 'dns\\s*=\\s*"([^"]+)"'
    ACL_DAYOFWEEK_PATTERN: ClassVar[str] = 'dayofweek\\s*=\\s*"([^"]+)"'
    ACL_TIMEOFDAY_PATTERN: ClassVar[str] = 'timeofday\\s*([<>=!]+)\\s*"?(\\d+)"?'
    ACL_AUTHMETHOD_PATTERN: ClassVar[str] = 'authmethod\\s*=\\s*"?(\\w+)"?'
    ACL_SSF_PATTERN: ClassVar[str] = 'ssf\\s*([<>=!]+)\\s*"?(\\d+)"?'
    ACL_TIMEOFDAY_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
        ACL_TIMEOFDAY_PATTERN,
    )
    ACL_SSF_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
        ACL_SSF_PATTERN,
    )
    ACL_BIND_RULE_TUPLE_LENGTH: ClassVar[int] = 2
    ACL_BIND_RULES_CONFIG: ClassVar[tuple[tuple[str, str, str | None], ...]] = (
        ("bind_ip", 'ip="{value}"', None),
        ("bind_dns", 'dns="{value}"', None),
        ("bind_dayofweek", 'dayofweek="{value}"', None),
        ("bind_timeofday", 'timeofday {operator} "{value}"', "="),
        ("authmethod", 'authmethod = "{value}"', None),
        ("ssf", 'ssf {operator} "{value}"', ">="),
    )
    ACL_TARGET_EXTENSIONS_CONFIG: ClassVar[tuple[tuple[str, str], ...]] = (
        ("targattrfilters", '(targattrfilters="{value}")'),
        ("targetcontrol", '(targetcontrol="{value}")'),
        ("extop", '(extop="{value}")'),
    )
    ACL_BIND_PATTERNS: ClassVar[t.StrMapping] = MappingProxyType({
        ACL_BIND_RULE_TYPE_USERDN: ACL_USERDN_PATTERN,
        ACL_BIND_RULE_TYPE_GROUPDN: ACL_GROUPDN_PATTERN,
    })
    ACL_NORMALIZE_DNS_IN_VALUES: ClassVar[bool] = False
    DS_PRIVILEGE_NAME_KEY: ClassVar[str] = "ds_privilege_name"
    FORMAT_TYPE_KEY: ClassVar[str] = "format_type"
    FORMAT_TYPE_DS_PRIVILEGE: ClassVar[str] = "ds-privilege-name"
    OUD_ACL_ATTRIBUTES: ClassVar[t.StrSequence] = (FORMAT_TYPE_DS_PRIVILEGE,)
    SCHEMA_DN: ClassVar[str] = "cn=schema"
    SCHEMA_FIELD_ATTRIBUTE_TYPES: ClassVar[str] = "attributetypes"
    SCHEMA_FIELD_OBJECT_CLASSES: ClassVar[str] = "objectclasses"
    SCHEMA_FIELD_MATCHING_RULES: ClassVar[str] = "matchingrules"
    SCHEMA_FIELD_LDAP_SYNTAXES: ClassVar[str] = "ldapsyntaxes"
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
    DEFAULT_ENCODING: ClassVar[str] = c.Ldif.DEFAULT_ENCODING
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
    ATTRIBUTE_CASE_MAP: ClassVar[t.StrMapping] = MappingProxyType({
        "uniquemember": "uniqueMember",
        "displayname": "displayName",
        "distinguishedname": "distinguishedName",
        "objectclass": "objectClass",
        "memberof": "memberOf",
        "seealsodescription": "seeAlsoDescription",
        "acl": "aci",
    })
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
    DN_DETECTION_PATTERNS: ClassVar[tuple[t.StrSequence, ...]] = (
        ("cn=settings", "cn=schema"),
        ("cn=settings", "cn=directory"),
        ("cn=settings", "cn=ds"),
    )
    KEYWORD_PATTERNS: ClassVar[t.StrSequence] = ("pwd", "password")
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


c = FlextLdifServersOudConstants
