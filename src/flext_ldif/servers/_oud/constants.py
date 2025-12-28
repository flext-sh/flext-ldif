"""Oracle Unified Directory (OUD) Quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides OUD-specific quirks for schema, ACL, and entry processing.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

from flext_core import FlextLogger

from flext_ldif.servers.rfc import FlextLdifServersRfc

logger = FlextLogger(__name__)


class FlextLdifServersOudConstants(FlextLdifServersRfc.Constants):
    """Oracle Unified Directory-specific constants using Python 3.13 patterns.

    Organizes OUD-specific constants using advanced Python 3.13 features:
    - Type aliases for semantic grouping
    - Frozen immutable collections
    - Advanced mapping patterns for zero-cost abstractions
    - Consolidated patterns to reduce code duplication

    All configuration including SERVER_TYPE and PRIORITY are defined here
    following the standardized pattern used across all server implementations.
    """

    # Server identity and priority (defined at Constants level)
    SERVER_TYPE: ClassVar[str] = "oud"
    PRIORITY: ClassVar[int] = 10  # High priority (OUD is well-known server)

    # LDAP Connection Defaults (RFC 4511 §4.1)
    DEFAULT_PORT: ClassVar[int] = 1389  # OUD default port (non-standard)
    DEFAULT_SSL_PORT: ClassVar[int] = 1636  # OUD default SSL port (non-standard)
    DEFAULT_PAGE_SIZE: ClassVar[int] = 1000  # RFC 2696 Simple Paged Results default

    # Logging and debug constants
    MAX_LOG_LINE_LENGTH: ClassVar[int] = 200  # Maximum length for log line excerpts

    # =====================================================================
    # CORE IDENTITY - Server identification and metadata
    # =====================================================================
    CANONICAL_NAME: ClassVar[str] = "oud"
    ALIASES: ClassVar[frozenset[str]] = frozenset([
        "oud",
        "oracle_oud",  # Backward compatibility alias
    ])

    # =====================================================================
    # CONVERSION CAPABILITIES
    # =====================================================================
    CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset([
        "oud",
        "rfc",
    ])
    CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset([
        "oud",
        "rfc",
    ])

    # =====================================================================
    # ACL CONFIGURATION
    # =====================================================================
    ACL_FORMAT: ClassVar[str] = "aci"  # RFC 4876 ACI attribute
    ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"  # OUD uses standard ACI

    # === ACL METADATA KEYS (Standardized for cross-server conversion) ===
    # Use centralized constants from c.MetadataKeys
    # Servers MUST NOT know about each other - only communicate via
    # standardized metadata
    # All metadata keys are defined in c.MetadataKeys
    # for consistency

    # === ACL PERMISSIONS (OUD extends RFC) ===
    PERMISSION_SELFWRITE: ClassVar[str] = "selfwrite"
    PERMISSION_SELF_WRITE: ClassVar[str] = "self_write"
    PERMISSION_PROXY: ClassVar[str] = "proxy"
    PERMISSION_ALL: ClassVar[str] = "all"

    # OUD Supported Permissions (extends RFC baseline)
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

    # === ACL CONSTANTS (Python 3.13 mapping) ===
    ACL_DEFAULT_NAME: ClassVar[str] = "OUD ACL"
    ACL_DEFAULT_TARGETATTR: ClassVar[str] = "*"
    ACL_DEFAULT_VERSION: ClassVar[str] = "version 3.0"
    ACL_VERSION_PREFIX: ClassVar[str] = "(version 3.0"
    ACL_ALLOW_PREFIX: ClassVar[str] = "allow ("
    ACL_ACI_PREFIX: ClassVar[str] = "aci:"
    ACL_DS_CFG_PREFIX: ClassVar[str] = "ds-cfg-"

    # === ACL PREFIX CONSTANTS ===
    ACL_TARGETATTR_PREFIX: ClassVar[str] = "targetattr="
    ACL_TARGETSCOPE_PREFIX: ClassVar[str] = "targetscope="
    ACL_LDAP_URL_PREFIX: ClassVar[str] = "ldap:///"

    # === ACL SUBJECT CONSTANTS ===
    ACL_SELF_SUBJECT: ClassVar[str] = "ldap:///self"
    ACL_ANONYMOUS_SUBJECT: ClassVar[str] = "ldap:///anyone"
    ACL_ANONYMOUS_SUBJECT_ALT: ClassVar[str] = "ldap:///*"

    # === ACL PARSING CONSTANTS (Python 3.13 Mapping) ===
    ACL_NEWLINE_SEPARATOR: ClassVar[str] = "\n"
    ACL_OPS_SEPARATOR: ClassVar[str] = ","
    ACL_ACTION_ALLOW: ClassVar[str] = "allow"
    ACL_ACTION_DENY: ClassVar[str] = "deny"
    ACL_BIND_RULE_KEY_TYPE: ClassVar[str] = "type"
    ACL_BIND_RULE_KEY_VALUE: ClassVar[str] = "value"
    ACL_SUBJECT_TYPE_BIND_RULES: ClassVar[str] = "bind_rules"

    # === ACL BIND RULE TYPES ===
    ACL_BIND_RULE_TYPE_USERDN: ClassVar[str] = "userdn"
    ACL_BIND_RULE_TYPE_GROUPDN: ClassVar[str] = "groupdn"

    # === ACL REGEX PATTERNS (Consolidated) ===
    ACL_USERDN_PATTERN: ClassVar[str] = r'userdn\s*=\s*"ldap:///([^"]+)"'
    ACL_GROUPDN_PATTERN: ClassVar[str] = r'groupdn\s*=\s*"ldap:///([^"]+)"'
    ACL_TARGETATTR_PATTERN: ClassVar[str] = r'\(targetattr\s*(!?=)\s*"([^"]+)"\)'
    ACL_TARGETSCOPE_PATTERN: ClassVar[str] = r'\(targetscope\s*=\s*"([^"]+)"\)'
    ACL_VERSION_ACL_PATTERN: ClassVar[str] = r'version\s+([\d.]+);\s*acl\s+"([^"]+)"'
    ACL_ALLOW_DENY_PATTERN: ClassVar[str] = r"(allow|deny)\s+\(([^)]+)\)"
    ACL_BY_GROUP_PATTERN: ClassVar[str] = r"by\s+group=\"[^\"]+\""
    ACL_BY_STAR_PATTERN: ClassVar[str] = r"by\s+\*"

    # === ACL ADVANCED PATTERNS ===
    # (RFC 4876 extensions validated against Oracle OUD documentation)
    ACL_TARGATTRFILTERS_PATTERN: ClassVar[str] = r'\(targattrfilters\s*=\s*"([^"]+)"\)'
    ACL_TARGETCONTROL_PATTERN: ClassVar[str] = r'\(targetcontrol\s*=\s*"([^"]+)"\)'
    ACL_EXTOP_PATTERN: ClassVar[str] = r'\(extop\s*=\s*"([^"]+)"\)'
    ACL_IP_PATTERN: ClassVar[str] = r'ip\s*=\s*"([^"]+)"'
    ACL_DNS_PATTERN: ClassVar[str] = r'dns\s*=\s*"([^"]+)"'
    ACL_DAYOFWEEK_PATTERN: ClassVar[str] = r'dayofweek\s*=\s*"([^"]+)"'
    ACL_TIMEOFDAY_PATTERN: ClassVar[str] = r'timeofday\s*([<>=!]+)\s*"?(\d+)"?'
    ACL_AUTHMETHOD_PATTERN: ClassVar[str] = r'authmethod\s*=\s*"?(\w+)"?'
    ACL_SSF_PATTERN: ClassVar[str] = r'ssf\s*([<>=!]+)\s*"?(\d+)"?'

    # === ACL BIND RULE TUPLE CONSTANTS ===
    ACL_BIND_RULE_TUPLE_LENGTH: ClassVar[int] = (
        2  # Expected length for (operator, value) tuples
    )

    # === ACL WRITE CONFIGURATIONS (for utility consolidation) ===
    # Bind rules config: (extension_key, format_template, operator_default)
    # extension_key must match c.MetadataKeys values
    ACL_BIND_RULES_CONFIG: ClassVar[list[tuple[str, str, str | None]]] = [
        ("bind_ip", 'ip="{value}"', None),
        ("bind_dns", 'dns="{value}"', None),
        ("bind_dayofweek", 'dayofweek="{value}"', None),
        ("bind_timeofday", 'timeofday {operator} "{value}"', "="),
        ("authmethod", 'authmethod = "{value}"', None),
        ("ssf", 'ssf {operator} "{value}"', ">="),
    ]

    # Target extensions config: (extension_key, format_template)
    # extension_key must match c.MetadataKeys values
    ACL_TARGET_EXTENSIONS_CONFIG: ClassVar[list[tuple[str, str]]] = [
        ("targattrfilters", '(targattrfilters="{value}")'),
        ("targetcontrol", '(targetcontrol="{value}")'),
        ("extop", '(extop="{value}")'),
    ]

    # NOTE: Alternative ACL format patterns
    # (ACL_FILTER_PATTERN, ACL_CONSTRAINT_PATTERN) REMOVED
    # OUD only handles RFC 4876 ACI format - Alternative format data comes
    # pre-converted via RFC Entry Model

    # === ACL BIND PATTERNS MAPPING (Python 3.13) ===
    ACL_BIND_PATTERNS: ClassVar[Mapping[str, str]] = {
        ACL_BIND_RULE_TYPE_USERDN: ACL_USERDN_PATTERN,
        ACL_BIND_RULE_TYPE_GROUPDN: ACL_GROUPDN_PATTERN,
    }

    # === ACL NORMALIZATION CONTROL ===
    # OUD accepts both "cn=Group,cn=Context" and "cn=Group, cn=Context" formats
    # No normalization needed for roundtrip - preserves original values
    ACL_NORMALIZE_DNS_IN_VALUES: ClassVar[bool] = False

    # === OUD-SPECIFIC METADATA KEYS ===
    # These are OUD-only extension keys (not in c.MetadataKeys)
    # For generic/cross-server keys, use c.MetadataKeys instead
    DS_PRIVILEGE_NAME_KEY: ClassVar[str] = "ds_privilege_name"
    FORMAT_TYPE_KEY: ClassVar[str] = "format_type"
    FORMAT_TYPE_DS_PRIVILEGE: ClassVar[str] = "ds-privilege-name"

    # =====================================================================
    # SCHEMA CONFIGURATION
    # =====================================================================
    SCHEMA_DN: ClassVar[str] = "cn=schema"

    # === SCHEMA FIELD NAMES ===
    SCHEMA_FIELD_ATTRIBUTE_TYPES: ClassVar[str] = "attributetypes"
    SCHEMA_FIELD_OBJECT_CLASSES: ClassVar[str] = "objectclasses"
    SCHEMA_FIELD_MATCHING_RULES: ClassVar[str] = "matchingrules"
    SCHEMA_FIELD_LDAP_SYNTAXES: ClassVar[str] = "ldapsyntaxes"

    # Schema fields that should be processed with OUD filtering
    SCHEMA_FILTERABLE_FIELDS: ClassVar[frozenset[str]] = frozenset(
        [
            SCHEMA_FIELD_ATTRIBUTE_TYPES,
            SCHEMA_FIELD_OBJECT_CLASSES,
            SCHEMA_FIELD_MATCHING_RULES,
            SCHEMA_FIELD_LDAP_SYNTAXES,
        ],
    )

    # Schema attribute fields that are server-specific
    ATTRIBUTE_FIELDS: ClassVar[frozenset[str]] = frozenset(["x_origin"])

    # ObjectClass requirements specific to OUD
    OBJECTCLASS_REQUIREMENTS: ClassVar[Mapping[str, bool]] = {
        "requires_sup_for_auxiliary": True,
        "allows_multiple_sup": False,
        "requires_explicit_structural": True,
    }

    # Schema attribute transformation constants
    ATTRIBUTE_UNDERSCORE_TO_DASH: ClassVar[str] = "_"
    ATTRIBUTE_DASH_REPLACEMENT: ClassVar[str] = "-"

    # =====================================================================
    # VALIDATION CONFIGURATION - Server-specific validation rules
    # =====================================================================
    DEFAULT_ENCODING: ClassVar[str] = "utf-8"
    ALLOWED_ENCODINGS: ClassVar[tuple[str, ...]] = ("utf-8", "utf-16", "ascii")
    DN_PRESERVE_CASE: ClassVar[bool] = False
    DN_NORMALIZE_TO: ClassVar[str] = "lowercase"
    ACL_REQUIRES_TARGET: ClassVar[bool] = True
    ACL_REQUIRES_SUBJECT: ClassVar[bool] = True
    TRACK_DELETIONS: ClassVar[bool] = True
    TRACK_MODIFICATIONS: ClassVar[bool] = True
    TRACK_CONVERSIONS: ClassVar[bool] = True

    # =====================================================================
    # OPERATIONAL ATTRIBUTES
    # =====================================================================
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

    # OUD specific operational attributes (subset of OPERATIONAL_ATTRIBUTES)
    OUD_SPECIFIC: ClassVar[frozenset[str]] = frozenset(
        [
            "ds-sync-hist",
            "ds-sync-state",
            "ds-pwp-account-disabled",
            "ds-cfg-backend-id",
            "entryUUID",
        ],
    )

    # Extends RFC PRESERVE_ON_MIGRATION with OUD-specific timestamps
    PRESERVE_ON_MIGRATION: ClassVar[frozenset[str]] = (
        FlextLdifServersRfc.Constants.PRESERVE_ON_MIGRATION
        | frozenset(["pwdChangedTime"])
    )

    # === BOOLEAN ATTRIBUTES (OUD-specific) ===
    # NOTE: orcldasselfmodifiable is OID-specific (Oracle DAS), NOT OUD native
    # OID→OUD conversion handles this via RFC Entry Model metadata
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

    # =====================================================================
    # ATTRIBUTE TRANSFORMATIONS (Python 3.13 Mapping)
    # =====================================================================

    # === ATTRIBUTE CASE MAPPING ===
    # lowercase source → proper OUD camelCase
    # NOTE: OUD has ZERO knowledge of OID formats (orclaci, orclentrylevelaci)
    # OID→OUD conversion goes through RFC Entry Model metadata
    ATTRIBUTE_CASE_MAP: ClassVar[dict[str, str]] = {
        "uniquemember": "uniqueMember",
        "displayname": "displayName",
        "distinguishedname": "distinguishedName",
        "objectclass": "objectClass",
        "memberof": "memberOf",
        "seealsodescription": "seeAlsoDescription",
        "acl": "aci",  # Generic ACL → OUD RFC ACI (matches ACL_ATTRIBUTE_NAME)
    }

    # === ATTRIBUTE NAME TRANSFORMATIONS ===
    # OUD→RFC attribute name transformations
    ATTRIBUTE_TRANSFORMATION_OUD_TO_RFC: ClassVar[Mapping[str, str]] = {
        "ds-sync-hist": "dsyncHist",  # OUD proprietary
        "ds-pwp-account-disabled": "accountDisabled",  # OUD password policy
        "entryUUID": "entryUUID",  # Standard RFC, OUD version
    }

    # RFC→OUD attribute name transformations (for reverse mapping)
    ATTRIBUTE_TRANSFORMATION_RFC_TO_OUD: ClassVar[Mapping[str, str]] = {
        "dsyncHist": "ds-sync-hist",
        "accountDisabled": "ds-pwp-account-disabled",
        "entryUUID": "entryUUID",
    }

    # === OUD ATTRIBUTE ALIASES ===
    # Attribute aliases for OUD (multiple names for same semantic attribute)
    ATTRIBUTE_ALIASES: ClassVar[Mapping[str, list[str]]] = {
        "cn": ["commonName"],
        "sn": ["surname"],
        "givenName": ["gn"],
        "mail": ["rfc822Mailbox", "emailAddress"],
        "telephoneNumber": ["phone"],
        "uid": ["userid", "username"],
    }

    # =====================================================================
    # ACL SUBJECT TRANSFORMATIONS (Python 3.13 Mapping)
    # =====================================================================

    # Subject type transformations from RFC format to OUD format
    RFC_TO_OUD_SUBJECTS: ClassVar[Mapping[str, tuple[str, str]]] = {
        "group_membership": ("bind_rules", 'userattr="{value}#LDAPURL"'),
        "user_attribute": ("bind_rules", 'userattr="{value}#USERDN"'),
        "group_attribute": ("bind_rules", 'userattr="{value}#GROUPDN"'),
    }

    # Subject type transformations from OUD format back to RFC format
    OUD_TO_RFC_SUBJECTS: ClassVar[Mapping[str, tuple[str, str]]] = {
        "bind_rules": ("group_membership", "{value}"),
    }

    # =====================================================================
    # MATCHING RULE VALIDATIONS & REPLACEMENTS (Python 3.13 Mapping)
    # =====================================================================

    # Matching rules that are invalid for SUBSTR operations
    INVALID_SUBSTR_RULES: ClassVar[Mapping[str, str | None]] = {
        "caseIgnoreMatch": "caseIgnoreSubstringsMatch",  # Common SUBSTR mistake
        "distinguishedNameMatch": None,  # No valid SUBSTR replacement
        "caseIgnoreOrderingMatch": None,  # No SUBSTR variant
        "numericStringMatch": "numericStringSubstringsMatch",  # Corrected
    }

    # Matching rules that need replacement for OUD compatibility
    MATCHING_RULE_REPLACEMENTS: ClassVar[Mapping[str, str]] = {
        "caseIgnoreMatch": "caseIgnoreMatch",  # Keep as-is in OUD
        "caseIgnoreSubstringsMatch": "caseIgnoreSubstringsMatch",  # Standard
    }

    # =====================================================================
    # CATEGORIZATION RULES - OUD-specific entry categorization
    # =====================================================================
    # OUD categorization uses standard RFC objectClasses
    # Priority: users → hierarchy → groups → acl
    # ObjectClasses for each category (RFC-compliant)
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

    # OUD hierarchy priority (RFC standard containers)
    HIERARCHY_PRIORITY_OBJECTCLASSES: ClassVar[frozenset[str]] = frozenset(
        [
            "organizationalUnit",
            "organization",
            "domain",
        ],
    )

    # ACL attributes for OUD
    CATEGORIZATION_ACL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
        [
            "aci",  # RFC 4876 ACI
        ],
    )

    # Categorization priority order for OUD
    # Schema first (always), then acl (OUD-specific ACL attributes), then users, hierarchy, groups, rejected
    CATEGORIZATION_PRIORITY: ClassVar[list[str]] = [
        "schema",
        "acl",
        "users",
        "hierarchy",
        "groups",
        "rejected",
    ]

    # =====================================================================
    # DETECTION PATTERNS - Server type detection rules
    # =====================================================================

    # === DN PREFIXES (used in Entry.can_handle) ===
    DN_PREFIX_CN_CONFIG: ClassVar[str] = "cn=config"
    DN_PREFIX_CN_SCHEMA: ClassVar[str] = "cn=schema"
    DN_PREFIX_CN_DIRECTORY: ClassVar[str] = "cn=directory"
    DN_PREFIX_CN_DS: ClassVar[str] = "cn=ds"

    # DN detection patterns for can_handle - tuple of pattern tuples (OR of ANDs)
    DN_DETECTION_PATTERNS: ClassVar[tuple[tuple[str, ...], ...]] = (
        ("cn=config", "cn=schema"),
        ("cn=config", "cn=directory"),
        ("cn=config", "cn=ds"),
    )

    # Keyword patterns for attribute name detection
    KEYWORD_PATTERNS: ClassVar[tuple[str, ...]] = ("pwd", "password")

    # === DETECTION PATTERNS ===
    # Case-insensitive pattern ((?i) flag) because detector searches in
    # lowercase content
    # NOTE: Renamed from DETECTION_OID_PATTERN to avoid confusion with Oracle Internet Directory (OID)
    # This pattern detects OUD (Oracle Unified Directory) specific attributes
    DETECTION_PATTERN: ClassVar[str] = (
        r"(?i)(ds-sync-|ds-pwp-|ds-cfg-|root dns)"  # OUD-specific attributes
    )
    # Pattern used by detector service for OUD namespace matching
    DETECTION_OID_PATTERN: ClassVar[str] = DETECTION_PATTERN
    DETECTION_WEIGHT: ClassVar[int] = (
        14  # Detection confidence weight (increased to overcome
        # OpenLDAP cn=config ambiguity)
    )
    DETECTION_ACL_PREFIX: ClassVar[str] = "ds-cfg-"  # OUD configuration ACL prefix

    # === DETECTION COLLECTIONS (Python 3.13 frozenset) ===
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

    # === NESTED STRENUM DEFINITIONS ===
    # StrEnum definitions for type-safe permission, action, and encoding handling

    # === ACL AND ENCODING CONSTANTS (Centralized) ===
    # Use centralized StrEnums from c directly
    # No duplicate nested StrEnums - use c.AclPermission,
    # c.AclAction, and c.Encoding directly

    # NOTE: get_parser_config() method moved to utilities.py
    # Use: FlextLdifServersOudUtilities.get_parser_config()
