from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar

from flext_core.lazy import build_lazy_import_map, install_lazy_exports
from flext_ldif.typings import t

# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Constants package."""


if TYPE_CHECKING:
    from .acl_convert import FlextLdifConstantsAclConvert
    from .acl_convert_oud import FlextLdifConstantsAclConvertOud
    from .base import FlextLdifConstantsBase
    from .enums import FlextLdifConstantsEnums
    from .servers import FlextLdifConstantsServers


__all__: tuple[str, ...] = (
    "FlextLdifConstantsAclConvert",
    "FlextLdifConstantsAclConvertOud",
    "FlextLdifConstantsBase",
    "FlextLdifConstantsEnums",
    "FlextLdifConstantsServers",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".acl_convert": ("FlextLdifConstantsAclConvert",),
            ".acl_convert_oud": ("FlextLdifConstantsAclConvertOud",),
            ".base": ("FlextLdifConstantsBase",),
            ".enums": ("FlextLdifConstantsEnums",),
            ".servers": ("FlextLdifConstantsServers",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)

SERVER_TYPE: ClassVar[str]

PRIORITY: ClassVar[int]

CAN_DENORMALIZE_TO: frozenset[str] = frozenset()

ACL_FORMAT: str = ""

ACL_ATTRIBUTE_NAME: str = ""

SCHEMA_DN: str = ""

SCHEMA_SUP_SEPARATOR: str = "$"

RFC_ACL_ATTRIBUTES: t.StrSequence = c.Ldif.RFC_ACL_ATTRIBUTES

ATTRIBUTE_FIELDS: frozenset[str] = frozenset()

ATTRIBUTE_ALIASES: t.StrSequenceMapping = MappingProxyType({})

OPERATIONAL_ATTRIBUTES: frozenset[str] = frozenset()

PRESERVE_ON_MIGRATION: frozenset[str] = frozenset()

OBJECTCLASS_REQUIREMENTS: t.BoolMapping = MappingProxyType({})

CATEGORIZATION_PRIORITY: t.StrSequence = ()

CATEGORY_OBJECTCLASSES: t.FrozensetMapping = MappingProxyType({})

HIERARCHY_PRIORITY_OBJECTCLASSES: frozenset[str] = frozenset()

CATEGORIZATION_ACL_ATTRIBUTES: frozenset[str] = frozenset()

DETECTION_PATTERN: str | t.Ldif.RegexPattern = ""

DETECTION_WEIGHT: int = 0

DETECTION_ATTRIBUTES: frozenset[str] = frozenset()

DETECTION_OID_PATTERN: str = ""

DETECTION_ATTRIBUTE_PREFIXES: frozenset[str] = frozenset()

DETECTION_OBJECTCLASS_NAMES: frozenset[str] = frozenset()

DETECTION_DN_MARKERS: frozenset[str] = frozenset()

ORCLACI: str = "orclaci"

ORCLENTRYLEVELACI: str = "orclentrylevelaci"

ORCL_CONTAINER_LEVEL_ACL: str = "orclContainerLevelACL"

OID_ACL_ATTRIBUTES: t.StrSequence = (
    ORCLACI,
    ORCLENTRYLEVELACI,
    ORCL_CONTAINER_LEVEL_ACL,
)

MATCHING_RULE_TO_RFC: t.StrMapping = MappingProxyType({
    "caseIgnoreSubStringsMatch": "caseIgnoreSubstringsMatch",
    "accessDirectiveMatch": "caseIgnoreMatch",
    "distinguishedNAMEMatch": "distinguishedNameMatch",
    "DistinguishedNameMatch": "distinguishedNameMatch",
    "caseIgnoreSubstringMatch": "caseIgnoreSubstringsMatch",
    "CaseIgnoreMatch": "caseIgnoreMatch",
    "CaseExactMatch": "caseExactMatch",
})

MATCHING_RULE_RFC_TO_OID: t.StrMapping = MappingProxyType({
    "caseIgnoreSubstringsMatch": "caseIgnoreSubStringsMatch"
})

SYNTAX_OID_TO_RFC: t.StrMapping = MappingProxyType({
    "1.3.6.1.4.1.1466.115.121.1.1": "1.3.6.1.4.1.1466.115.121.1.15"
})

ATTR_NAME_CASE_MAP: t.StrMapping = MappingProxyType({"middlename": "middleName"})

SCHEMA_FILTERABLE_FIELDS: frozenset[str] = frozenset([
    "attributetypes",
    "objectclasses",
    "matchingrules",
    "ldapsyntaxes",
])

SCHEMA_DN_SERVER: str = "cn=subschemasubentry"

BOOLEAN_ATTRIBUTES: frozenset[str] = c.Ldif.OID_BOOLEAN_ATTRIBUTES

CANONICAL_NAME: str = c.Ldif.ServerTypes.OID

ALIASES: frozenset[str] = frozenset({
    c.Ldif.ServerTypes.OID,
    *(
        alias
        for alias, server_type in c.Ldif.SERVER_TYPE_ALIASES.items()
        if server_type == c.Ldif.ServerTypes.OID
    ),
})

CAN_NORMALIZE_FROM: frozenset[str] = frozenset({c.Ldif.ServerTypes.OID})

OID_SPECIFIC_RIGHTS: str = "oid_specific_rights"

RFC_NORMALIZED: str = "rfc_normalized"

ORIGINAL_OID_PERMS: str = "original_oid_perms"

OID_ACL_SOURCE_TARGET: str = "acl_source_target"

CN_ORCL: str = "cn=orcl"

OU_ORACLE: str = "ou=oracle"

DC_ORACLE: str = "dc=oracle"

ACL_SUBJECT_TYPE_USER: str = c.Ldif.AclSubjectType.USER

ACL_SUBJECT_TYPE_GROUP: str = c.Ldif.AclSubjectType.GROUP

ACL_SUBJECT_TYPE_SELF: str = c.Ldif.AclSubjectType.SELF

ACL_SUBJECT_TYPE_ANONYMOUS: str = c.Ldif.AclSubjectType.ANONYMOUS

ACL_TARGET_PATTERN: str = "access to (entry | attr=\\(([^)]+)\\))"

ACL_FILTER_PATTERN: str = "filter=(\\([^)]*(?:\\([^)]*\\)[^)]*)*\\))"

ACL_CONSTRAINT_PATTERN: str = "added_object_constraint=\\(([^)]+)\\)"

ACL_BINDMODE_PATTERN: str = "(?i)bindmode\\s*=\\s*\\(([^)]+)\\)"

ACL_DENY_GROUP_OVERRIDE_PATTERN: str = "DenyGroupOverride"

ACL_APPEND_TO_ALL_PATTERN: str = "AppendToAll"

ACL_BIND_IP_FILTER_PATTERN: str = "(?i)bindipfilter\\s*=\\s*\\(([^)]+)\\)"

ACL_CONSTRAIN_TO_ADDED_PATTERN: str = (
    "(?i)constraintonaddedobject\\s*=\\s*\\(([^)]+)\\)"
)

ACL_TARGET_DN_EXTRACT: str = 'target\\s*=\\s*"([^"]*)"'

ACL_TARGET_ATTR_OID_EXTRACT: str = "attr\\s*=\\s*\\(([^)]+)\\)"

ACL_PERMS_EXTRACT_OID: str = "\\s\\(([^()]+)\\)(?:\\s*(?:filter=|added_object | bindmode|Deny | Append|bindip | constrain|$))"

ACL_TARGET_DN_EXTRACT_RE: t.Ldif.RegexPattern = re.compile(
    ACL_TARGET_DN_EXTRACT, re.IGNORECASE
)

ACL_TARGET_ATTR_OID_EXTRACT_RE: t.Ldif.RegexPattern = re.compile(
    ACL_TARGET_ATTR_OID_EXTRACT, re.IGNORECASE
)

ACL_PERMS_EXTRACT_OID_RE: t.Ldif.RegexPattern = re.compile(
    ACL_PERMS_EXTRACT_OID, re.IGNORECASE
)

ONE_OID: str = c.Ldif.OID_TRUE

ZERO_OID: str = c.Ldif.OID_FALSE

RFC_TO_OID: t.StrMapping = c.Ldif.RFC_TO_OID_BOOL

INVALID_SUBSTR_RULES: t.OptionalStrMapping = MappingProxyType({
    "caseIgnoreMatch": "caseIgnoreSubstringsMatch",
    "caseExactMatch": "caseExactSubstringsMatch",
    "distinguishedNameMatch": None,
    "integerMatch": None,
    "numericStringMatch": "numericStringSubstringsMatch",
})

ACL_ACCESS_TO: str = "access to"

ACL_BY: str = "by"

ACL_SUBJECT_PATTERNS: t.MappingKV[str, tuple[str | None, str, str]] = MappingProxyType({
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

ACL_PERMISSION_MAPPING: t.StrSequenceMapping = MappingProxyType({
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

ACL_PERMISSION_NAMES: t.StrMapping = MappingProxyType({
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

SUPPORTED_PERMISSIONS: frozenset[str] = frozenset({
    *c.Ldif.ACL_PERMISSION_KEYS,
    c.Ldif.RfcAclPermission.NONE,
    "no_write",
    "no_add",
    "no_delete",
    "no_browse",
    "no_self_write",
})

ATTRIBUTE_TRANSFORMATION_OID_TO_RFC: t.StrMapping = (
    c.Ldif.ATTRIBUTE_TRANSFORMATION_OID_TO_RFC
)

ATTRIBUTE_TRANSFORMATION_RFC_TO_OID: t.StrMapping = (
    c.Ldif.ATTRIBUTE_TRANSFORMATION_RFC_TO_OID
)

DEFAULT_SSL_PORT: int = 1636

DEFAULT_PAGE_SIZE: int = 1000

MAX_LOG_LINE_LENGTH: int = 200

PERMISSION_SELFWRITE: str = "selfwrite"

PERMISSION_SELF_WRITE: str = "self_write"

PERMISSION_PROXY: str = "proxy"

PERMISSION_ALL: str = "all"

ACL_DEFAULT_NAME: str = "OUD ACL"

ACL_DEFAULT_VERSION: str = "version 3.0"

ACL_VERSION_PREFIX: str = "(version 3.0"

ACL_ALLOW_PREFIX: str = "allow ("

ACL_ACI_PREFIX: str = "aci:"

ACL_DS_CFG_PREFIX: str = "ds-cfg-"

ACL_TARGETATTR_PREFIX: str = "targetattr="

ACL_TARGETSCOPE_PREFIX: str = "targetscope="

ACL_SELF_SUBJECT: str = "ldap:///self"

ACL_ANONYMOUS_SUBJECT: str = "ldap:///anyone"

ACL_OPS_SEPARATOR: str = ","

ACL_SUBJECT_TYPE_BIND_RULES: str = "bind_rules"

ACL_BIND_RULE_TYPE_USERDN: str = "userdn"

ACL_BIND_RULE_TYPE_GROUPDN: str = "groupdn"

ACL_USERDN_PATTERN: str = 'userdn\\s*=\\s*"ldap:///([^"]+)"'

ACL_GROUPDN_PATTERN: str = 'groupdn\\s*=\\s*"ldap:///([^"]+)"'

ACL_TARGETATTR_PATTERN: str = '\\(targetattr\\s*(!?=)\\s*"([^"]+)"\\)'

ACL_TARGETSCOPE_PATTERN: str = '\\(targetscope\\s*=\\s*"([^"]+)"\\)'

ACL_VERSION_ACL_PATTERN: str = 'version\\s+([\\d.]+);\\s*acl\\s+"([^"]+)"'

ACL_ALLOW_DENY_PATTERN: str = "(allow|deny)\\s+\\(([^)]+)\\)"

ACL_TARGATTRFILTERS_PATTERN: str = '\\(targattrfilters\\s*=\\s*"([^"]+)"\\)'

ACL_TARGETCONTROL_PATTERN: str = '\\(targetcontrol\\s*=\\s*"([^"]+)"\\)'

ACL_EXTOP_PATTERN: str = '\\(extop\\s*=\\s*"([^"]+)"\\)'

ACL_IP_PATTERN: str = 'ip\\s*=\\s*"([^"]+)"'

ACL_DNS_PATTERN: str = 'dns\\s*=\\s*"([^"]+)"'

ACL_DAYOFWEEK_PATTERN: str = 'dayofweek\\s*=\\s*"([^"]+)"'

ACL_TIMEOFDAY_PATTERN: str = 'timeofday\\s*([<>=!]+)\\s*"?(\\d+)"?'

ACL_AUTHMETHOD_PATTERN: str = 'authmethod\\s*=\\s*"?(\\w+)"?'

ACL_SSF_PATTERN: str = 'ssf\\s*([<>=!]+)\\s*"?(\\d+)"?'

ACL_TIMEOFDAY_RE: t.Ldif.RegexPattern = re.compile(ACL_TIMEOFDAY_PATTERN)

ACL_SSF_RE: t.Ldif.RegexPattern = re.compile(ACL_SSF_PATTERN)

ACL_BIND_RULE_TUPLE_LENGTH: int = 2

ACL_BIND_RULES_CONFIG: tuple[tuple[str, str, str | None], ...] = (
    ("bind_ip", 'ip="{value}"', None),
    ("bind_dns", 'dns="{value}"', None),
    ("bind_dayofweek", 'dayofweek="{value}"', None),
    ("bind_timeofday", 'timeofday {operator} "{value}"', "="),
    ("authmethod", 'authmethod = "{value}"', None),
    ("ssf", 'ssf {operator} "{value}"', ">="),
)

ACL_TARGET_EXTENSIONS_CONFIG: t.StrPairTuple = (
    ("targattrfilters", '(targattrfilters="{value}")'),
    ("targetcontrol", '(targetcontrol="{value}")'),
    ("extop", '(extop="{value}")'),
)

ACL_BIND_PATTERNS: t.StrMapping = MappingProxyType({
    ACL_BIND_RULE_TYPE_USERDN: ACL_USERDN_PATTERN,
    ACL_BIND_RULE_TYPE_GROUPDN: ACL_GROUPDN_PATTERN,
})

ACL_NORMALIZE_DNS_IN_VALUES: bool = False

DS_PRIVILEGE_NAME_KEY: str = "ds_privilege_name"

FORMAT_TYPE_KEY: str = "format_type"

FORMAT_TYPE_DS_PRIVILEGE: str = "ds-privilege-name"

SCHEMA_FIELD_ATTRIBUTE_TYPES: str = "attributetypes"

SCHEMA_FIELD_OBJECT_CLASSES: str = "objectclasses"

SCHEMA_FIELD_MATCHING_RULES: str = "matchingrules"

SCHEMA_FIELD_LDAP_SYNTAXES: str = "ldapsyntaxes"

DEFAULT_ENCODING: str = c.Ldif.DEFAULT_ENCODING

ATTRIBUTE_CASE_MAP: t.StrMapping = MappingProxyType({
    "uniquemember": "uniqueMember",
    "displayname": "displayName",
    "distinguishedname": "distinguishedName",
    "objectclass": "objectClass",
    "memberof": "memberOf",
    "seealsodescription": "seeAlsoDescription",
    "acl": "aci",
})

DN_DETECTION_PATTERNS: tuple[t.StrSequence, ...] = (
    ("cn=settings", "cn=schema"),
    ("cn=settings", "cn=directory"),
    ("cn=settings", "cn=ds"),
)

KEYWORD_PATTERNS: t.StrSequence = ("pwd", "password")

PERMISSION_READ: str = "read"

PERMISSION_WRITE: str = "write"

PERMISSION_ADD: str = "add"

PERMISSION_DELETE: str = "delete"

PERMISSION_SEARCH: str = "search"

PERMISSION_COMPARE: str = "compare"

PERMISSION_ADMIN: str = "admin"

PERMISSION_IMPORT: str = "import"

PERMISSION_EXPORT: str = "export"

PERMISSION_AUTH: str = "auth"

ACL_PERMISSION_KEYS: t.StrSequence = (
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

MIME_OID_ENCODING: str = "1.2.840.113556"

LDAP_SYNTAXES: t.StrSequence = (
    "1.3.6.1.4.1.1466.115.121.1.12",
    "1.3.6.1.4.1.1466.115.121.1.15",
    "1.3.6.1.4.1.1466.115.121.1.27",
    "1.3.6.1.4.1.1466.115.121.1.44",
    "1.3.6.1.4.1.1466.115.121.1.50",
    "1.3.6.1.4.1.1466.115.121.1.51",
    "1.3.6.1.4.1.1466.115.121.1.34",
    "1.3.6.1.4.1.1466.115.121.1.44",
)

LDIF_NEWLINE: str = "\n"
