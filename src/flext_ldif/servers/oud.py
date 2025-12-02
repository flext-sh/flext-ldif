"""Oracle Unified Directory (OUD) Quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides OUD-specific quirks for schema, ACL, and entry processing.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from typing import ClassVar, cast

from flext_core import FlextLogger, FlextResult, FlextRuntime
from flext_core.typings import FlextTypes

from flext_ldif._models.config import FlextLdifModelsConfig
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities

logger = FlextLogger(__name__)


class FlextLdifServersOud(FlextLdifServersRfc):
    """Oracle Unified Directory (OUD) Server Implementation.

    Extends RFC baseline (RFC 2849/4512) with Oracle OUD-specific features.
    OUD implements RFC 4876 Access Control Model with significant extensions.

    RFC vs OUD Differences Summary
    ==============================

    **ACI Format (RFC 4876 vs OUD Extensions)**:

    RFC defines basic ACI structure, OUD extends with:

    - **Syntax**: ``aci: (target)(version 3.0;acl "name";permissionBindRules;)``
    - **Targets**: target, targetattr, targetfilter, targetscope, targattrfilters,
      targetcontrol, extop
    - **Permissions**: read, write, add, delete, search, compare, selfwrite, proxy,
      import, export, all (RFC only has read, write, add, delete, search, compare)
    - **Bind Rules**: userdn, groupdn, roledn, ip, dns, timeofday, dayofweek,
      authmethod, ssf (RFC only defines userdn, groupdn)

    **Schema Extensions (RFC 4512 vs OUD)**:

    - RFC 4512 defines attributeTypes and objectClasses syntax
    - OUD adds X-* extensions: X-ORIGIN, X-SCHEMA-FILE, X-PATTERN, X-ENUM
    - OUD allows non-numeric OIDs with ``-oid`` suffix
    - OUD uses namespace ``1.3.6.1.4.1.26027.*`` for custom schemas

    **Entry Extensions**:

    - OUD uses operational attributes: ds-cfg-*, ds-sync-*, ds-privilege-name
    - OUD uses DN case preservation (case-insensitive but case-preserving)
    - OUD supports multi-line ACIs with continuation (space + content)

    Example OUD ACI (from Oracle Docs)
    ----------------------------------

    Single permission::

        aci: (targetattr="*")(version 3.0; acl "OracleContext accessible by Admins";
             allow (all) groupdn="ldap:///cn=OracleContextAdmins,cn=groups,dc=example,dc=com";)

    Multiple bind rules::

        aci: (targetattr="*")(version 3.0; acl "Multi-group access";
             allow (read,search,write,selfwrite,compare)
             groupdn="ldap:///cn=OracleDASUserPriv,cn=Groups,cn=OracleContext";
             allow (read,search,compare) userdn="ldap:///anyone";)

    Attribute exclusion::

        aci: (targetattr!="userpassword||authpassword||aci")
             (version 3.0; acl "Anonymous read access"; allow (read,search,compare)
             userdn="ldap:///anyone";)

    Inheritance Hierarchy
    ---------------------

    ``FlextLdifServersBase (ABC)`` → ``FlextLdifServersRfc`` → ``FlextLdifServersOud``

    Hooks System (from base.py)
    ---------------------------

    - ``_hook_post_parse_attribute()`` - OUD X-* extension handling
    - ``_hook_post_parse_objectclass()`` - OUD objectClass extensions
    - ``_hook_post_parse_acl()`` - OUD ACI format normalization
    - ``_hook_validate_entry_raw()`` - OUD entry validation
    - ``_hook_post_parse_entry()`` - OUD operational attribute handling
    - ``_hook_pre_write_entry()`` - OUD LDIF formatting

    Official Documentation
    ----------------------

    - ACI Syntax: https://docs.oracle.com/cd/E22289_01/html/821-1277/aci-syntax.html
    - Managing ACIs: https://docs.oracle.com/cd/E22289_01/html/821-1273/managing-acis-with-ldapmodify.html
    - Schema: https://docs.oracle.com/en/middleware/idm/unified-directory/14.1.2/oudag/managing-directory-schema.html

    """

    # =========================================================================
    # STANDARDIZED CONSTANTS FOR AUTO-DISCOVERY
    # =========================================================================
    class Constants(FlextLdifServersRfc.Constants):
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
        SERVER_TYPE: ClassVar[FlextLdifConstants.LiteralTypes.ServerTypeLiteral] = "oud"
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
        CANONICAL_NAME: ClassVar[str] = FlextLdifConstants.ServerTypes.OUD.value
        ALIASES: ClassVar[frozenset[str]] = frozenset([
            FlextLdifConstants.ServerTypes.OUD.value,
            "oracle_oud",  # Backward compatibility alias
        ])

        # =====================================================================
        # CONVERSION CAPABILITIES
        # =====================================================================
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset([
            FlextLdifConstants.ServerTypes.OUD.value,
            FlextLdifConstants.ServerTypes.RFC.value,
        ])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset([
            FlextLdifConstants.ServerTypes.OUD.value,
            FlextLdifConstants.ServerTypes.RFC.value,
        ])

        # =====================================================================
        # ACL CONFIGURATION
        # =====================================================================
        ACL_FORMAT: ClassVar[str] = "aci"  # RFC 4876 ACI attribute
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"  # OUD uses standard ACI

        # === ACL METADATA KEYS (Standardized for cross-server conversion) ===
        # Use centralized constants from FlextLdifConstants.MetadataKeys
        # Servers MUST NOT know about each other - only communicate via
        # standardized metadata
        # All metadata keys are defined in FlextLdifConstants.MetadataKeys
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
        ACL_VERSION_ACL_PATTERN: ClassVar[str] = (
            r'version\s+([\d.]+);\s*acl\s+"([^"]+)"'
        )
        ACL_ALLOW_DENY_PATTERN: ClassVar[str] = r"(allow|deny)\s+\(([^)]+)\)"
        ACL_BY_GROUP_PATTERN: ClassVar[str] = r"by\s+group=\"[^\"]+\""
        ACL_BY_STAR_PATTERN: ClassVar[str] = r"by\s+\*"

        # === ACL ADVANCED PATTERNS ===
        # (RFC 4876 extensions validated against Oracle OUD documentation)
        ACL_TARGATTRFILTERS_PATTERN: ClassVar[str] = (
            r'\(targattrfilters\s*=\s*"([^"]+)"\)'
        )
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
        # extension_key must match FlextLdifConstants.MetadataKeys values
        ACL_BIND_RULES_CONFIG: ClassVar[list[tuple[str, str, str | None]]] = [
            ("bind_ip", 'ip="{value}"', None),
            ("bind_dns", 'dns="{value}"', None),
            ("bind_dayofweek", 'dayofweek="{value}"', None),
            ("bind_timeofday", 'timeofday {operator} "{value}"', "="),
            ("authmethod", 'authmethod = "{value}"', None),
            ("ssf", 'ssf {operator} "{value}"', ">="),
        ]

        # Target extensions config: (extension_key, format_template)
        # extension_key must match FlextLdifConstants.MetadataKeys values
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
        # These are OUD-only extension keys (not in FlextLdifConstants.MetadataKeys)
        # For generic/cross-server keys, use FlextLdifConstants.MetadataKeys instead
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
            FlextLdifConstants.DictKeys.OBJECTCLASS.lower(): (
                FlextLdifConstants.DictKeys.OBJECTCLASS
            ),
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
        # Use centralized StrEnums from FlextLdifConstants directly
        # No duplicate nested StrEnums - use FlextLdifConstants.AclPermission,
        # FlextLdifConstants.AclAction, and FlextLdifConstants.Encoding directly

        # === PARSER CONFIG FACTORY ===
        @staticmethod
        def get_parser_config() -> FlextLdifModelsConfig.AciParserConfig:
            """Create AciParserConfig for OUD ACL parsing.

            Returns:
                AciParserConfig with OUD-specific patterns from Constants.

            """
            constants = FlextLdifServersOud.Constants
            return FlextLdifModels.AciParserConfig(
                server_type="oud",  # Use literal string for ServerTypeLiteral compatibility
                aci_prefix="aci:",
                version_acl_pattern=constants.ACL_VERSION_ACL_PATTERN,
                targetattr_pattern=constants.ACL_TARGETATTR_PATTERN,
                allow_deny_pattern=constants.ACL_ALLOW_DENY_PATTERN,
                bind_patterns=dict(constants.ACL_BIND_PATTERNS),
                extra_patterns={
                    "targetscope": constants.ACL_TARGETSCOPE_PATTERN,
                    "targattrfilters": constants.ACL_TARGATTRFILTERS_PATTERN,
                    "targetcontrol": constants.ACL_TARGETCONTROL_PATTERN,
                    "extop": constants.ACL_EXTOP_PATTERN,
                    "ip": constants.ACL_IP_PATTERN,
                    "dns": constants.ACL_DNS_PATTERN,
                    "dayofweek": constants.ACL_DAYOFWEEK_PATTERN,
                    "timeofday": constants.ACL_TIMEOFDAY_PATTERN,
                    "authmethod": constants.ACL_AUTHMETHOD_PATTERN,
                    "ssf": constants.ACL_SSF_PATTERN,
                },
            )

    # =========================================================================
    # Server identification - accessed via Constants via properties in base.py
    # =========================================================================
    # NOTE: server_type and priority are accessed via properties in base.py
    # which read from Constants.SERVER_TYPE and Constants.PRIORITY

    # === PUBLIC INTERFACE FOR SCHEMA CONFIGURATION ===

    # =========================================================================
    # SHARED HELPER METHODS - Used by both Schema and Entry nested classes
    # =========================================================================

    class Schema(FlextLdifServersRfc.Schema):
        """Oracle OUD Schema Implementation (RFC 4512 + OUD Extensions).

        Extends RFC 4512 schema parsing with Oracle OUD-specific features.

        RFC vs OUD Schema Differences
        =============================

        **RFC 4512 Baseline**:

        - ``attributeTypes``: OID, NAME, DESC, EQUALITY, ORDERING, SUBSTR, SYNTAX, SINGLE-VALUE, USAGE
        - ``objectClasses``: OID, NAME, DESC, SUP, STRUCTURAL/AUXILIARY/ABSTRACT, MUST, MAY
        - OIDs must be strictly numeric (e.g., ``2.5.4.3``)

        **OUD Extensions** (Oracle-specific):

        1. **Extended OID Formats**:

           - Non-numeric OIDs: ``X-oid`` suffix (e.g., ``custom-cn-oid``)
           - Oracle namespace: ``1.3.6.1.4.1.26027.*`` (OUD-specific)
           - Legacy OID: ``9.9.9.9.*`` (Oracle extended)

        2. **X-* Extensions** (Oracle-specific):

           - ``X-ORIGIN 'source'``: Origin of the attribute (e.g., ``'RFC 4519'``, ``'Oracle OUD'``)
           - ``X-SCHEMA-FILE 'file.ldif'``: File where schema is defined
           - ``X-PATTERN 'regex'``: Validation pattern for attribute values
           - ``X-ENUM 'value1' 'value2'``: Enumerated allowed values
           - ``X-SUBST 'type'``: Substring matching rule
           - ``X-APPROX 'type'``: Approximate matching rule

        3. **Operational Attributes** (OUD-specific):

           - ``ds-cfg-*``: Configuration attributes
           - ``ds-sync-*``: Replication synchronization
           - ``ds-pwp-*``: Password policy
           - ``orclaci``: Oracle ACI (different from ``aci``)

        4. **DN Case Handling**:

           - OUD preserves DN case (case-insensitive comparison, case-preserving storage)
           - DN components normalized to canonical form
           - Spaces after commas normalized

        Real Examples (from fixtures)
        -----------------------------

        **AttributeType with X-ORIGIN**::

            attributeTypes: ( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' )
                EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch
                SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} X-ORIGIN 'RFC 4519' )

        **ObjectClass with SUP**::

            objectClasses: ( 0.9.2342.19200300.100.4.5 NAME 'account' SUP top
                STRUCTURAL MUST uid MAY ( description $ seeAlso $ l $ o $ ou $ host )
                X-ORIGIN 'RFC 4524' )

        **Oracle-specific Schema**::

            attributeTypes: ( 1.3.6.1.4.1.26027.1.1.1 NAME 'ds-cfg-enabled'
                EQUALITY booleanMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.7
                SINGLE-VALUE X-ORIGIN 'Oracle Unified Directory' )

        Official Documentation
        ----------------------

        - Schema Management: https://docs.oracle.com/en/middleware/idm/unified-directory/14.1.2/oudag/managing-directory-schema.html
        - RFC 4512 (base): https://tools.ietf.org/html/rfc4512

        Example Usage
        -------------

        ::

            quirk = FlextLdifServersOud()
            if quirk.schema.can_handle_attribute(attr_def):
                result = quirk.schema.parse(attr_def)
                if result.is_success:
                    parsed_attr = result.unwrap()
                    # X-ORIGIN available in parsed_attr.x_origin

        """

        def __init__(
            self,
            schema_service: FlextLdifTypes.Services.SchemaService | None = None,
            **kwargs: str | float | bool | None,
        ) -> None:
            """Initialize OUD schema quirk.

            OUD extends RFC baseline with Oracle-specific enhancements.

            Args:
                schema_service: Injected FlextLdifSchema service (optional)
                **kwargs: Additional arguments passed to parent

            """
            # Business Rule: Filter _parent_quirk from kwargs to avoid type errors
            # Implication: _parent_quirk is handled separately, not via Pydantic fields
            # Business Rule: _schema_service is NOT a GeneralValueType, so it cannot be
            # passed to FlextService.__init__ which expects only GeneralValueType kwargs.
            # Implication: _schema_service must be passed explicitly to Schema.__init__
            # Business Rule: Only pass GeneralValueType (str | float | bool | None) to super().__init__
            # Implication: Filter kwargs to ensure type safety (int is not GeneralValueType, only str/float/bool/None)
            filtered_kwargs: dict[str, str | float | bool | None] = {
                k: v
                for k, v in kwargs.items()
                if k not in ("_parent_quirk", "_schema_service")
                and isinstance(v, (str, float, bool, type(None)))
            }
            # Business Rule: _schema_service is NOT a GeneralValueType, so it cannot be
            # passed to FlextService.__init__ which expects only GeneralValueType kwargs.
            # Implication: _schema_service must be stored directly on the instance after
            # super().__init__() using object.__setattr__.
            # Call parent RFC.Schema.__init__ without _schema_service (it's not GeneralValueType)
            # Use explicit FlextService.__init__ call to avoid type checker confusion
            from flext_core.service import FlextService

            FlextService.__init__(self, **filtered_kwargs)
            # Store _schema_service after initialization (not a Pydantic field)
            if schema_service is not None:
                object.__setattr__(self, "_schema_service", schema_service)
            # Note: _parent_quirk is handled separately if needed

        def _validate_attribute_oid(
            self,
            oid: str,
        ) -> FlextResult[bool]:
            """Validate attribute OID format for OUD.

            Args:
                oid: OID string to validate

            Returns:
                FlextResult with boolean indicating validity

            """
            oid_validation_result = FlextLdifUtilities.OID.validate_format(oid)
            if oid_validation_result.is_failure:
                return FlextResult[bool].fail(
                    f"OID validation failed: {oid_validation_result.error}",
                )

            is_valid_basic_oid = oid_validation_result.unwrap()

            # OUD allows OID format extensions: numeric OID or ending with -oid suffix
            is_valid_oud_oid = is_valid_basic_oid
            if not is_valid_oud_oid and oid.endswith("-oid"):
                # Check if base OID (without -oid suffix) is valid
                base_oid = oid[:-4]
                base_validation = FlextLdifUtilities.OID.validate_format(base_oid)
                if base_validation.is_success:
                    is_valid_oud_oid = base_validation.unwrap()

            if not is_valid_oud_oid:
                return FlextResult[bool].fail(
                    f"Invalid OUD OID format: {oid} (must be numeric RFC OID or end with -oid suffix)",
                )

            return FlextResult[bool].ok(is_valid_oud_oid)

        def _collect_attribute_extensions(
            self,
            attr: FlextLdifModels.SchemaAttribute,
        ) -> list[str]:
            """Collect OUD X-* extensions from attribute.

            Args:
                attr: Parsed SchemaAttribute

            Returns:
                List of detected X-* extension names

            """
            extensions = []
            if attr.x_origin:
                extensions.append("X-ORIGIN")
            if attr.x_file_ref:
                extensions.append("X-FILE-REF")
            if attr.x_name:
                extensions.append("X-NAME")
            if attr.x_alias:
                extensions.append("X-ALIAS")
            if attr.x_oid:
                extensions.append("X-OID")
            return extensions

        def _hook_post_parse_attribute(
            self,
            attr: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Hook: Validate OUD-specific attribute features after RFC parsing.

            RFC vs OUD Behavior Differences
            ================================

            **RFC Baseline** (in rfc.py):
            - No post-parse hook (passes attribute through unchanged)
            - Standard RFC 4512 attribute parsing only
            - No OID format extensions

            **OUD Override** (this method):
            - Validates OUD-specific OID format extensions
            - Detects and logs OUD X-* extension usage
            - Applies OUD-specific validation rules

            OUD Schema Extensions (beyond RFC 4512)
            ---------------------------------------

            **OID Format Extensions**:
            - RFC requires numeric OIDs (e.g., ``1.3.6.1.4.1.26027.1.1.42``)
            - OUD allows non-numeric suffix (e.g., ``1.3.6.1-oid``)

            **X-* Extensions** (Oracle-specific metadata):

            - ``X-ORIGIN`` - Source/origin of the attribute definition::

                X-ORIGIN 'Oracle Unified Directory Server'

            - ``X-SCHEMA-FILE`` - Schema file where attribute is defined::

                X-SCHEMA-FILE '99-user.ldif'

            - ``X-PATTERN`` - Regular expression pattern for value validation::

                X-PATTERN '^[a-zA-Z0-9]+$'

            - ``X-ENUM`` - Enumerated allowed values::

                X - ENUM("value1value2value3")

            - ``X-NAME`` - Alternative name for the attribute
            - ``X-ALIAS`` - Alias names for the attribute
            - ``X-OID`` - Alternative OID reference
            - ``X-FILE-REF`` - External file reference

            Validation Rules
            ----------------

            1. OIDs must be numeric or end with ``-oid`` suffix
            2. X-* extensions must be well-formed (structure check)
            3. SYNTAX must reference valid OID (format check)

            Args:
                attr: Parsed SchemaAttribute from RFC parser

            Returns:
                FlextResult[SchemaAttribute] - validated and metadata-enriched attribute

            References:
                - RFC 4512: LDAP Directory Information Models (Schema)
                - Oracle OUD Schema Management: https://docs.oracle.com/en/middleware/idm/unified-directory/14.1.2/oudag/managing-directory-schema.html

            """
            if not attr or not attr.oid:
                return FlextResult[FlextLdifModels.SchemaAttribute].ok(attr)

            oid = str(attr.oid)

            # Validate OID format
            oid_validation = self._validate_attribute_oid(oid)
            if oid_validation.is_failure:
                return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                    oid_validation.error or "OID validation failed",
                )

            is_valid_oud_oid = oid_validation.unwrap()

            # Store OID validation metadata in attribute metadata for tracking
            existing_metadata = attr.metadata
            if not existing_metadata:
                existing_metadata = FlextLdifModels.QuirkMetadata.create_for("oud")

            # Get existing extensions or create new dict
            current_extensions = (
                dict(existing_metadata.extensions)
                if existing_metadata.extensions
                else {}
            )

            # Track OID validation status using standardized MetadataKeys
            current_extensions[FlextLdifConstants.MetadataKeys.SYNTAX_OID_VALID] = (
                is_valid_oud_oid
            )

            # Track if OID uses OUD extension format (-oid suffix)
            if oid.endswith("-oid"):
                current_extensions["oid_format_extension"] = True

            # Update attribute with metadata including extensions
            attr = attr.model_copy(
                update={
                    "metadata": existing_metadata.model_copy(
                        update={"extensions": current_extensions},
                    ),
                },
            )

            # Log if OUD-specific X-* extensions detected
            oud_extensions = self._collect_attribute_extensions(attr)
            if oud_extensions:
                logger.debug(
                    "Attribute has OUD X-* extensions",
                    attribute_name=attr.name,
                    attribute_oid=attr.oid,
                    extensions=oud_extensions,
                    extension_count=len(oud_extensions),
                )

            return FlextResult[FlextLdifModels.SchemaAttribute].ok(attr)

        def _validate_objectclass_sup(
            self,
            oc: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[bool]:
            """Validate objectClass SUP constraint for OUD.

            Args:
                oc: SchemaObjectClass to validate

            Returns:
                FlextResult indicating validation success or failure

            """
            sup = oc.sup
            if sup:
                sup_str = str(sup)
                # Check for multiple SUPs (RFC uses $ as separator)
                if "$" in sup_str:
                    return FlextResult[bool].fail(
                        f"OUD objectClass '{oc.name}' has multiple SUPs: "
                        f"{sup_str}. "
                        "OUD only allows single SUP (use AUXILIARY classes "
                        "for additional features).",
                    )
            return FlextResult[bool].ok(True)

        def _validate_objectclass_oid_and_sup(
            self,
            oc: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Validate ObjectClass OID and SUP OID formats.

            Args:
                oc: SchemaObjectClass to validate

            Returns:
                FlextResult with validated objectClass or error

            """
            # Validate ObjectClass OID format
            if oc and oc.oid:
                oid_str = str(oc.oid)
                oid_validation = self._validate_attribute_oid(oid_str)
                if oid_validation.is_failure:
                    return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                        f"ObjectClass OID validation failed: {oid_validation.error}",
                    )

                is_valid_oud_oid = oid_validation.unwrap()

                # Track OID validation in metadata
                existing_oc_metadata = oc.metadata
                if not existing_oc_metadata:
                    existing_oc_metadata = FlextLdifModels.QuirkMetadata.create_for(
                        "oud",
                    )

                oc_extensions = (
                    dict(existing_oc_metadata.extensions)
                    if existing_oc_metadata.extensions
                    else {}
                )

                oc_extensions[FlextLdifConstants.MetadataKeys.SYNTAX_OID_VALID] = (
                    is_valid_oud_oid
                )

                if oid_str.endswith("-oid"):
                    oc_extensions["oid_format_extension"] = True

                oc = oc.model_copy(
                    update={
                        "metadata": existing_oc_metadata.model_copy(
                            update={"extensions": oc_extensions},
                        ),
                    },
                )

            # Validate SUP OID if it's an OID format
            sup = oc.sup
            if sup:
                sup_str = str(sup)
                if sup_str and "." in sup_str and sup_str[0].isdigit():
                    sup_validation = self._validate_attribute_oid(sup_str)
                    if sup_validation.is_failure:
                        return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                            f"ObjectClass SUP OID validation failed: {sup_validation.error}",
                        )

            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(oc)

        def _hook_post_parse_objectclass(
            self,
            oc: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Hook: Validate OUD-specific objectClass features after RFC parsing.

            RFC vs OUD Behavior Differences
            ================================

            **RFC Baseline** (in rfc.py):
            - No post-parse hook (passes objectClass through unchanged)
            - Allows multiple superiors (SUP class1 $ class2)
            - Standard RFC 4512 objectClass parsing only

            **OUD Override** (this method):
            - Enforces OUD SingleSUP constraint
            - Validates OUD-specific objectClass rules
            - Logs validation results for debugging

            OUD ObjectClass Constraints
            ---------------------------

            **SingleSUP Constraint** (OUD-specific restriction):

            - **RFC 4512 allows**: ``SUP person $ inetOrgPerson`` (multiple superiors)
            - **OUD requires**: ``SUP person`` (single superior only)

            This is because OUD uses a stricter inheritance model. To add
            functionality from multiple classes, use AUXILIARY classes::

                # RFC allows (OUD rejects):
                objectClasses: ( 1.2.3.4 NAME 'myClass'
                  SUP person $ organizationalPerson
                  STRUCTURAL ... )

                # OUD requires:
                objectClasses: ( 1.2.3.4 NAME 'myClass'
                  SUP person
                  AUXILIARY ( organizationalPerson )
                  STRUCTURAL ... )

            **X-* Extensions** (Oracle-specific metadata):

            - ``X-ORIGIN`` - Source/origin of the objectClass definition
            - ``X-SCHEMA-FILE`` - Schema file where objectClass is defined
            - ``X-ENUM`` - Enumerated allowed values for attributes
            - ``X-PATTERN`` - Validation patterns

            **No Multiple Structural Chains**:

            OUD enforces that each entry can only have one structural objectClass
            chain. This is validated at schema load time, not during parsing.

            Validation Rules
            ----------------

            1. SUP must be single (not multiple separated by ``$``)
            2. X-* extensions must be well-formed
            3. MUST/MAY attributes validated in ``validate_objectclass_dependencies``

            Args:
                oc: Parsed SchemaObjectClass from RFC parser

            Returns:
                FlextResult[SchemaObjectClass] - validated objectClass

            References:
                - RFC 4512: LDAP Directory Information Models (Schema)
                - Oracle OUD Schema Management: https://docs.oracle.com/en/middleware/idm/unified-directory/14.1.2/oudag/managing-directory-schema.html

            """
            if not oc:
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    "ObjectClass is None or empty",
                )

            # Validate SingleSUP constraint (OUD restriction)
            sup_validation = self._validate_objectclass_sup(oc)
            if sup_validation.is_failure:
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    sup_validation.error or "SUP validation failed",
                )

            # Validate ObjectClass OID and SUP OID formats
            oid_and_sup_validation = self._validate_objectclass_oid_and_sup(oc)
            if oid_and_sup_validation.is_failure:
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    oid_and_sup_validation.error or "OID validation failed",
                )

            oc = oid_and_sup_validation.unwrap()

            # Log validation success
            logger.debug(
                "ObjectClass validated: SingleSUP constraint OK",
                objectclass_name=oc.name,
                objectclass_oid=oc.oid,
                sup_value=oc.sup,
            )

            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(oc)

        def _apply_attribute_matching_rule_transforms(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> tuple[str | None, str | None]:
            """Apply OUD-specific matching rule transformations.

            Args:
                attr_data: SchemaAttribute with original matching rules

            Returns:
                Tuple of (fixed_equality, fixed_substr)

            """
            fixed_equality = attr_data.equality
            fixed_substr = attr_data.substr

            # OUD QUIRK: caseIgnoreSubstringsMatch must be SUBSTR, not EQUALITY
            if fixed_equality == "caseIgnoreSubstringsMatch":
                logger.warning(
                    "Moved caseIgnoreSubstringsMatch from EQUALITY to SUBSTR",
                    attribute_name=attr_data.name,
                )
                fixed_substr = "caseIgnoreSubstringsMatch"
                fixed_equality = None

            # OUD QUIRK: Remove redundant EQUALITY when SUBSTR is caseIgnoreSubstringsMatch
            if (
                fixed_substr == "caseIgnoreSubstringsMatch"
                and fixed_equality == "caseIgnoreMatch"
            ):
                logger.warning(
                    "OUD QUIRK: FOUND REDUNDANT EQUALITY+SUBSTR - Removing redundant EQUALITY",
                    attribute_name=attr_data.name,
                    attribute_oid=attr_data.oid,
                    original_equality=fixed_equality,
                    original_substr=fixed_substr,
                    new_equality=None,
                    new_substr="caseIgnoreSubstringsMatch",
                    redundant_equality="caseIgnoreMatch",
                )
                fixed_equality = None

            # Apply invalid SUBSTR rule replacements
            original_substr = fixed_substr
            fixed_substr = FlextLdifUtilities.Schema.replace_invalid_substr_rule(
                fixed_substr,
                FlextLdifServersOud.Constants.INVALID_SUBSTR_RULES,
            )
            if fixed_substr != original_substr:
                logger.warning(
                    "Replaced invalid SUBSTR rule",
                    attribute_name=attr_data.name,
                    attribute_oid=attr_data.oid,
                    original_substr=original_substr,
                    replacement_substr=fixed_substr,
                )

            return fixed_equality, fixed_substr

        def _apply_attribute_oid_metadata(
            self,
            attr: FlextLdifModels.SchemaAttribute,
        ) -> FlextLdifModels.SchemaAttribute:
            """Apply OID validation and tracking metadata to attribute.

            Args:
                attr: SchemaAttribute to update with OID metadata

            Returns:
                Updated attribute with OID validation metadata

            """
            if not attr or not attr.oid:
                return attr

            oid_str = str(attr.oid)
            oid_validation = self._validate_attribute_oid(oid_str)
            if oid_validation.is_failure:
                return attr  # Return unchanged if validation fails

            is_valid_oud_oid = oid_validation.unwrap()

            # Track OID validation in metadata
            existing_metadata = attr.metadata
            if not existing_metadata:
                existing_metadata = FlextLdifModels.QuirkMetadata.create_for("oud")

            current_extensions = (
                dict(existing_metadata.extensions)
                if existing_metadata.extensions
                else {}
            )

            current_extensions[FlextLdifConstants.MetadataKeys.SYNTAX_OID_VALID] = (
                is_valid_oud_oid
            )

            if oid_str.endswith("-oid"):
                current_extensions["oid_format_extension"] = True

            return attr.model_copy(
                update={
                    "metadata": existing_metadata.model_copy(
                        update={"extensions": current_extensions},
                    ),
                },
            )

        def _transform_attribute_for_write(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextLdifModels.SchemaAttribute:
            """Apply OUD-specific attribute transformations before writing.

            RFC vs OUD Behavior Differences
            ================================

            **RFC Baseline** (in rfc.py ``_transform_attribute_for_write``):
            - Returns attribute unchanged (no transformation)
            - No matching rule validation or correction

            **OUD Override** (this method):
            - Validates and corrects matching rule assignments
            - Applies OUD-specific EQUALITY/SUBSTR rule fixes
            - Handles invalid SUBSTR rule replacements
            - Tracks boolean attributes for special handling

            OUD Matching Rule Quirks
            ------------------------

            **QUIRK 1: caseIgnoreSubstringsMatch in EQUALITY**

            Some source servers (e.g., OID) incorrectly place ``caseIgnoreSubstringsMatch``
            in the EQUALITY position. OUD requires it in SUBSTR::

                # Source (invalid for OUD):
                EQUALITY caseIgnoreSubstringsMatch SUBSTR caseIgnoreSubstringsMatch

                # Transformed (OUD-compatible):
                SUBSTR caseIgnoreSubstringsMatch

            **QUIRK 2: Redundant EQUALITY + SUBSTR**

            OUD rejects redundant ``caseIgnoreMatch`` EQUALITY when ``caseIgnoreSubstringsMatch``
            SUBSTR is present. This affects 135+ attributes exported from OID::

                # Source (rejected by OUD):
                EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch

                # Transformed (accepted by OUD):
                SUBSTR caseIgnoreSubstringsMatch

            **QUIRK 3: Invalid SUBSTR Rules**

            Some SUBSTR rules are not supported by OUD and must be replaced
            or removed. See ``Constants.INVALID_SUBSTR_RULES`` for mappings.

            **Boolean Attribute Tracking**

            Boolean attributes (defined in ``Constants.BOOLEAN_ATTRIBUTES``) are
            tracked for special handling during schema write operations.

            Args:
                attr_data: Parsed SchemaAttribute model

            Returns:
                Transformed SchemaAttribute with OUD-specific fixes applied

            References:
                - Oracle OUD Schema Management: https://docs.oracle.com/en/middleware/idm/unified-directory/14.1.2/oudag/managing-directory-schema.html

            """
            # Apply matching rule transformations
            fixed_equality, fixed_substr = (
                self._apply_attribute_matching_rule_transforms(attr_data)
            )

            # Check if this is a boolean attribute for special handling
            is_boolean = FlextLdifUtilities.Schema.is_boolean_attribute(
                attr_data.name,
                set(FlextLdifServersOud.Constants.BOOLEAN_ATTRIBUTES),
            )
            if is_boolean:
                logger.debug(
                    "Identified boolean attribute",
                    attribute_name=attr_data.name,
                    attribute_oid=attr_data.oid,
                )

            # Update attribute with transformed matching rules
            updated_attr = attr_data.model_copy(
                update={
                    "equality": fixed_equality,
                    "substr": fixed_substr,
                },
            )

            # Apply OID validation metadata
            return self._apply_attribute_oid_metadata(updated_attr)

        def extract_schemas_from_ldif(
            self,
            ldif_content: str,
            *,
            validate_dependencies: bool = True,  # OUD defaults to True (needs validation)
        ) -> FlextResult[
            dict[
                str,
                list[FlextLdifModelsDomains.SchemaAttribute]
                | list[FlextLdifModelsDomains.SchemaObjectClass],
            ]
        ]:
            """Extract and parse all schema definitions from LDIF content.

            OUD-specific implementation: Uses base template method with dependency
            validation enabled by default. The template method handles attribute
            extraction, available_attributes set building, and objectClass extraction.

            Strategy pattern: OUD requires dependency validation to ensure all
            attributes referenced in objectClass MUST/MAY lists are available.

            Filters only Oracle internal objectClasses that OUD already provides built-in.
            All custom objectClasses pass through, including those with unresolved
            dependencies (OUD will validate at startup).

            Args:
                ldif_content: Raw LDIF content containing schema definitions
                validate_dependencies: Enable dependency validation (default: True for OUD)

            Returns:
                FlextResult with dict containing schema data
                (ATTRIBUTES and objectclasses lists)

            """
            # Use base template method with OUD's dependency validation
            # This replaces 66 lines of duplicated code with a 3-line call
            return super().extract_schemas_from_ldif(
                ldif_content,
                validate_dependencies=validate_dependencies,
            )

    class Acl(FlextLdifServersRfc.Acl):
        """Oracle OUD ACL Implementation (RFC 4876 ACI Format).

        Extends RFC baseline with Oracle OUD-specific Access Control Instruction (ACI) format.
        OUD implements RFC 4876 with significant vendor extensions.

        RFC vs OUD ACI Differences
        ==========================

        **RFC Baseline** (RFC 4876):

        - Basic ACI structure: ``(target)(version;acl "name";permission subject;)``
        - Limited permissions: read, write, add, delete, search, compare
        - Basic bind rules: userdn, groupdn

        **OUD Extensions** (Oracle Docs):

        1. **Extended Permissions** (Oracle-specific):

           - ``selfwrite``: Add/delete own DN from DN-valued attributes (group membership)
           - ``proxy``: Access resources with another entry's rights (impersonation)
           - ``import``: Import entries from another server during modRDN
           - ``export``: Export entries to another server during modRDN
           - ``all``: Grants read, write, search, delete, compare, selfwrite (NOT proxy/import/export)

        2. **Extended Targets** (Oracle-specific):

           - ``targetscope``: base|onelevel|subtree|subordinate (limits ACI scope)
           - ``targattrfilters``: Attribute value filtering ``add=attr:(filter);delete=attr:(filter)``
           - ``targetcontrol``: LDAP control OIDs for extended operations
           - ``extop``: Extended operation OIDs (StartTLS, Password Modify, etc.)

        3. **Extended Bind Rules** (Oracle-specific):

           - ``ip="192.168.1.0/24"``: Source IP address/CIDR filtering
           - ``dns="*.example.com"``: DNS domain-based restrictions
           - ``timeofday="0800-1700"``: Time-of-day restrictions (24h format HHMM-HHMM)
           - ``dayofweek="Mon,Tue,Wed"``: Day-of-week restrictions
           - ``authmethod="simple|ssl|sasl"``: Authentication method requirements
           - ``ssf="40"``: Security Strength Factor (minimum encryption key size)
           - ``roledn``: Role-based access control

        4. **Special Subjects** (Oracle-specific):

           - ``userdn="ldap:///self"``: The authenticated user themselves
           - ``userdn="ldap:///anyone"``: Any user (including anonymous)
           - ``userdn="ldap:///all"``: All authenticated users

        5. **Multi-line ACI Format** (Oracle-specific):

           OUD supports multi-line ACIs with continuation (leading whitespace)::

               aci: (targetattr="*")(version 3.0; acl "Multi-permission";
                    allow (read,search,write,selfwrite,compare)
                    groupdn="ldap:///cn=Group1,dc=example,dc=com";
                    allow (read,search,compare) userdn="ldap:///anyone";)

        ACI Syntax Reference
        --------------------

        Complete OUD ACI format::

            aci: (target)(version 3.0;acl "name";permissionBindRules;)

        Where:
        - ``target``: Optional. Entry scope ``(target="ldap:///dn")``
        - ``targetattr``: Optional. Attributes ``(targetattr="cn || sn")`` or ``(targetattr="*")``
        - ``targetfilter``: Optional. LDAP filter ``(targetfilter="(objectClass=person)")``
        - ``version 3.0``: Required. Fixed version string
        - ``acl "name"``: Required. Human-readable ACL name
        - ``permission``: Required. ``allow|deny (rights)``
        - ``bindRules``: Required. Subject specification

        Real Examples (from fixtures)
        -----------------------------

        **Single Group Permission**::

            aci: (targetattr="*")(version 3.0; acl "OracleContext accessible by Admins";
                 allow (all) groupdn="ldap:///cn=OracleContextAdmins,cn=groups,dc=example,dc=com";)

        **Attribute Exclusion** (``!=`` syntax)::

            aci: (targetattr!="userpassword||authpassword||aci")
                 (version 3.0; acl "Anonymous read"; allow (read,search,compare)
                 userdn="ldap:///anyone";)

        **Multiple Permissions per ACI**::

            aci: (targetattr="*")(version 3.0; acl "DAS Group Access";
                 allow (read,search,write,selfwrite,compare)
                 groupdn="ldap:///cn=OracleDASUserPriv,cn=Groups,cn=OracleContext";
                 allow (read,search,compare) userdn="ldap:///anyone";)

        Official Documentation
        ----------------------

        - ACI Syntax: https://docs.oracle.com/cd/E22289_01/html/821-1277/aci-syntax.html
        - Access Control Model: https://docs.oracle.com/en/middleware/idm/unified-directory/12.2.1.3/oudag/understanding-access-control-model-oracle-unified-directory.html

        Example Usage
        -------------

        ::

            quirk = FlextLdifServersOud.Acl()
            if quirk.can_handle(acl_line):
                result = quirk.parse(acl_line)
                if result.is_success:
                    acl_model = result.unwrap()
                    # Access OUD-specific fields via metadata.extensions

        """

        # =====================================================================
        # PROTOCOL IMPLEMENTATION: FlextLdifProtocols.ServerAclProtocol
        # =====================================================================

        # RFC Foundation - Standard LDAP attributes (all servers start here)
        RFC_ACL_ATTRIBUTES: ClassVar[list[str]] = [
            "aci",  # Standard LDAP (RFC 4876)
            "acl",  # Alternative format
            "olcAccess",  # OpenLDAP
            "aclRights",  # Generic rights
            "aclEntry",  # ACL entry
        ]

        # OUD-specific ACL extensions
        # Oracle ACI compatibility (alternative ACL format support)
        OUD_ACL_ATTRIBUTES: ClassVar[list[str]] = [
            "ds-privilege-name",  # OUD privilege system - native OUD attribute
        ]

        def get_acl_attributes(self) -> list[str]:
            """Get RFC + OUD extensions.

            Returns:
                List of ACL attribute names (RFC foundation + OUD-specific)

            """
            return self.RFC_ACL_ATTRIBUTES + self.OUD_ACL_ATTRIBUTES

        # is_acl_attribute inherited from base class (uses set for O(1) lookup)

        # OVERRIDDEN METHODS (from FlextLdifServersBase.Acl)
        # These methods override the base class with Oracle OUD-specific logic:
        # - can_handle(): Detects OUD ACL formats
        # - parse(): Normalizes Oracle OUD ACL to RFC-compliant internal model
        # - write(): Serializes RFC-compliant model to OUD ACI format
        # - get_attribute_name(): Returns "aci" (OUD-specific, overridden)

        # Oracle OUD server configuration defaults

        def __init__(
            self,
            acl_service: FlextLdifTypes.Services.AclService | None = None,
            _parent_quirk: FlextLdifServersBase | None = None,
            **kwargs: str | float | bool | None,
        ) -> None:
            """Initialize OUD ACL quirk.

            Args:
                acl_service: Injected FlextLdifAcl service (optional)
                _parent_quirk: Reference to parent FlextLdifServersBase (optional)
                **kwargs: Additional arguments passed to parent

            """
            # Business Rule: Filter _parent_quirk from kwargs to avoid type errors
            # Implication: _parent_quirk is handled separately, not via Pydantic fields
            # Business Rule: Only pass GeneralValueType (str | float | bool | None) to super().__init__
            # Implication: Filter kwargs to ensure type safety (int is not GeneralValueType, only str/float/bool/None)
            filtered_kwargs: dict[str, str | float | bool | None] = {
                k: v
                for k, v in kwargs.items()
                if k != "_parent_quirk"
                and isinstance(v, (str, float, bool, type(None)))
            }
            # Business Rule: Acl.__init__ accepts acl_service and _parent_quirk
            # Implication: Call parent __init__ directly, parent handles FlextService call
            super().__init__(
                acl_service=acl_service,
                _parent_quirk=_parent_quirk,
                **filtered_kwargs,
            )
            # NOTE: Hook registration was removed - AclConverter was moved to services/acl.py
            # Use FlextLdifAcl instead for ACL conversion operations

        # NOTE: Obsolete method removed - hook registration pattern changed
        # AclConverter was moved to services/acl.py as FlextLdifAcl
        # Use FlextLdifAcl for ACL format conversions (RFC → server-specific format)

        def can_handle(self, acl_line: FlextLdifTypes.AclOrString) -> bool:
            """Check if this is an Oracle OUD ACL (public method).

            Args:
                acl_line: ACL line string or Acl model to check.

            Returns:
                True if this is Oracle OUD ACL format

            """
            return self.can_handle_acl(acl_line)

        def can_handle_acl(self, acl_line: FlextLdifTypes.AclOrString) -> bool:
            """Check if this is an Oracle OUD ACL line (implements abstract method from base.py).

            RFC vs OUD Behavior Differences
            ================================

            **RFC Baseline** (in rfc.py):
            - Returns ``True`` for ALL ACL lines (catch-all fallback)
            - Does not inspect ACL format or content
            - RFC is the universal fallback when no server-specific handler matches

            **OUD Override** (this method):
            - Returns ``True`` ONLY for OUD-specific ACL formats
            - Detects ACL format by inspecting content patterns
            - Allows RFC fallback for non-OUD formats

            Detects Oracle OUD ACL by checking if the line starts with:

            - ``aci:`` - RFC 4876 compliant ACI attribute prefix
            - ``targetattr=`` - Inline ACI format (attribute target)
            - ``targetscope=`` - Inline ACI format (scope target)
            - ``version 3.0`` - ACI version marker (OUD uses version 3.0)
            - ``ds-cfg-`` - OUD configuration ACL (server config attributes)

            Also handles ``ds-privilege-name`` format: Simple privilege names without
            parentheses or equals signs (e.g., "config-read", "password-reset").

            Args:
                acl_line: Raw ACL line string or Acl model from LDIF

            Returns:
                True if this is Oracle OUD ACL format

            References:
                - RFC 4876: Access Control Instruction (ACI) Format
                - Oracle OUD 14.1.2: https://docs.oracle.com/en/middleware/idm/unified-directory/14.1.2/oudag/understanding-access-control-model-oracle-unified-directory.html

            """
            # Handle Acl model: check metadata quirk type or attribute name
            if isinstance(acl_line, FlextLdifModels.Acl):
                if acl_line.metadata and acl_line.metadata.quirk_type:
                    return str(acl_line.metadata.quirk_type) == self._get_server_type()
                return (
                    bool(acl_line.name)
                    and (
                        FlextLdifUtilities.Schema.normalize_attribute_name(
                            acl_line.name,
                        )
                        == FlextLdifUtilities.Schema.normalize_attribute_name(
                            FlextLdifServersOud.Constants.ACL_ATTRIBUTE_NAME,
                        )
                    )
                    if acl_line.name
                    else False
                )

            # Handle string: empty string check (type narrowed after Acl check above)
            if not isinstance(acl_line, str) or not (normalized := acl_line.strip()):
                return False

            # Check for OUD ACL patterns using constants
            normalized_lower = normalized.lower()
            oud_prefixes = (
                FlextLdifServersOud.Constants.ACL_ACI_PREFIX,
                FlextLdifServersOud.Constants.ACL_TARGETATTR_PREFIX,
                FlextLdifServersOud.Constants.ACL_TARGETSCOPE_PREFIX,
                FlextLdifServersOud.Constants.ACL_DEFAULT_VERSION,
            )

            # RFC 4876 ACI format OR OUD config ACL
            if normalized.startswith(oud_prefixes) or "ds-cfg-" in normalized_lower:
                return True

            # ds-privilege-name format: simple privilege names without prohibited patterns
            return not any(
                pattern in normalized_lower
                for pattern in ["access to", "(", ")", "=", ":"]
            )

        def _parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse Oracle OUD ACL string to RFC-compliant internal model.

            RFC vs OUD Behavior Differences
            ================================

            **RFC Baseline** (in rfc.py):
            - Simple passthrough: stores raw ACL line in ``raw_acl`` field
            - No parsing of ACL structure (target, permissions, subject)
            - Model fields (name, target, permissions, subject) remain None

            **OUD Override** (this method):
            - Full parsing of OUD ACI format into structured model
            - Extracts and populates: name, target, permissions, subject
            - Handles OUD-specific extensions: timeofday, dayofweek, ip, dns, ssf, authmethod
            - Stores OUD-specific data in metadata.extensions

            Supported OUD ACL Formats
            -------------------------

            1. **RFC 4876 ACI format** (primary OUD format)::

                aci: (targetattr="cn || sn")(version 3.0; acl "Allow Read"; allow (read) userdn="ldap:///self";)

            2. **ds-privilege-name format** (OUD REDACTED_LDAP_BIND_PASSWORDistrative privileges)::

                config - read
                password - reset
                bypass - acl

            OUD ACI Syntax (RFC 4876 + Oracle Extensions)
            ---------------------------------------------

            ::

                aci: (target)(version 3.0;acl "name";permissionBindRules;)

            **Target Types**:
            - ``target`` - Entry DN scope (e.g., ``target="ldap:///ou=people,dc=example,dc=com"``)
            - ``targetattr`` - Attribute filter (e.g., ``targetattr="cn || sn || mail"``)
            - ``targetfilter`` - LDAP filter (e.g., ``targetfilter="(objectClass=person)"``)
            - ``targetscope`` - Scope (base|onelevel|subtree|subordinate)
            - ``targattrfilters`` - Attribute filters for add/delete operations
            - ``targetcontrol`` - Control OID restrictions
            - ``extop`` - Extended operation OID restrictions

            **Permissions**: read, write, add, delete, search, compare, selfwrite, proxy,
            import, export, all

            **Bind Rules**:
            - ``userdn`` - User DN match (ldap:///self, ldap:///anyone, ldap:///all)
            - ``groupdn`` - Group membership
            - ``roledn`` - Role-based access (OUD uses groups, not roles)
            - ``userattr`` - Value matching between user and target attributes
            - ``ip`` - IP address/CIDR range
            - ``dns`` - DNS domain pattern
            - ``timeofday`` - Time restriction (HHMM-HHMM)
            - ``dayofweek`` - Day restriction (Mon,Tue,Wed,...)
            - ``authmethod`` - Authentication method (simple|ssl|sasl)
            - ``ssf`` - Security strength factor

            Note: OUD does NOT parse Oracle Internet Directory (OID) formats directly.
            If receiving OID data, it must be pre-converted via RFC Entry Model first.

            Args:
                acl_line: ACL definition line (ACI format or ds-privilege-name)

            Returns:
                FlextResult with OUD ACL Pydantic model

            References:
                - RFC 4876: Access Control Instruction (ACI) Format
                - Oracle OUD ACI Syntax: https://docs.oracle.com/cd/E22289_01/html/821-1277/aci-syntax.html

            """
            # Type guard: ensure acl_line is a string
            if not isinstance(acl_line, str):
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"ACL line must be a string, got {type(acl_line).__name__}",
                )
            normalized = acl_line.strip()

            # Detect format: RFC 4876 ACI or ds-privilege-name
            # OUD ONLY handles OUD-native formats - Alternative format data comes pre-converted via RFC Entry Model
            if normalized.startswith(FlextLdifServersOud.Constants.ACL_ACI_PREFIX):
                # RFC 4876 ACI format (OUD native format)
                return self._parse_aci_format(acl_line)

            # Try RFC parser first for other non-ACI formats
            # This handles cases where RFC Entry Model data needs to be parsed
            rfc_result = super()._parse_acl(acl_line)
            if rfc_result.is_success:
                # RFC parser succeeded - check if it has a valid name
                # If name is empty and line doesn't look like RFC format, try ds-privilege-name
                acl_model = rfc_result.unwrap()
                if acl_model.name or normalized.startswith("aci:"):
                    # RFC parser returned valid result with name or recognized format
                    return rfc_result

            # If RFC parser fails or returned empty name, try ds-privilege-name format
            # OUD-specific simple privilege names (config-read, password-reset, etc.)
            return self._parse_ds_privilege_name(normalized)

        def _parse_aci_format(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse RFC 4876 ACI format using utility with OUD-specific config.

            RFC vs OUD Behavior Differences
            ================================

            **RFC Baseline**:
            - No dedicated ACI parser (RFC stores raw ACL in passthrough mode)
            - RFC 4876 defines the ACI format but not all servers implement it

            **OUD Implementation** (this method):
            - Full RFC 4876 ACI parser with Oracle OUD extensions
            - Parses target types, version, name, permissions, bind rules
            - Handles OUD-specific multi-group patterns (timeofday, ssf with operators)
            - Stores parsed components in structured model fields

            ACI Format Parsed
            -----------------

            ::

                aci: (targetattr="*")(version 3.0; acl "ACL Name"; allow (read,search) userdn="ldap:///self";)

            **Parsed Components**:

            1. **Target clause**: ``(targetattr="*")`` → ``target.attributes``
            2. **Version**: ``version 3.0`` → validated (OUD uses version 3.0)
            3. **ACL name**: ``acl "ACL Name"`` → ``name``
            4. **Permission**: ``allow (read,search)`` → ``permissions.read``, ``permissions.search``
            5. **Bind rules**: ``userdn="ldap:///self"`` → ``subject.subject_type``, ``subject.subject_value``

            **OUD-Specific Extensions in metadata.extensions**:

            - ``bind_timeofday`` - Time-based access control (e.g., ">=0800" AND "<=1700")
            - ``ssf`` - Security strength factor (e.g., ">=128")
            - ``bind_ip`` - IP-based restrictions
            - ``bind_dns`` - DNS-based restrictions
            - ``bind_dayofweek`` - Day-of-week restrictions
            - ``bind_authmethod`` - Authentication method restrictions

            Implementation Pattern
            ----------------------

            **Constants Used** (from ``FlextLdifServersOud.Constants``):

            - ``ACL_TIMEOFDAY_PATTERN`` - Regex for timeofday bind rule extraction
            - ``ACL_SSF_PATTERN`` - Regex for SSF bind rule extraction
            - ``ACL_ACI_PREFIX`` - Prefix to identify ACI format ("aci:")

            **MetadataKeys** (stored in ``metadata.extensions``):

            - Extensions follow ``FlextLdifConstants.MetadataKeys.ACL_*`` pattern
            - OUD-specific: bind_timeofday, ssf, bind_ip, bind_dns, bind_dayofweek

            **Utilities Used**:

            - ``FlextLdifUtilities.ACL.parse_aci()`` - Core ACI parsing
            - ``FlextLdifServersOud.Constants.get_parser_config()`` - OUD parser config

            **RFC Override**: This method extends RFC behavior (RFC has no ACI parser).

            Args:
                acl_line: ACL definition line with 'aci:' prefix

            Returns:
                FlextResult with OUD ACL Pydantic model

            References:
                - RFC 4876: Access Control Instruction (ACI) Format
                - Oracle OUD ACI Syntax: https://docs.oracle.com/cd/E22289_01/html/821-1277/aci-syntax.html

            """
            config = FlextLdifServersOud.Constants.get_parser_config()
            result = FlextLdifUtilities.ACL.parse_aci(acl_line, config)

            if not result.is_success:
                return result

            # Post-process for OUD-specific multi-group patterns (timeofday, ssf)
            acl = result.unwrap()
            aci_content = acl_line.split(":", 1)[1].strip() if ":" in acl_line else ""
            # Preserve all extensions from parse_aci (including targattrfilters, targetcontrol, etc.)
            extensions = (
                dict(acl.metadata.extensions)
                if acl.metadata and acl.metadata.extensions
                else {}
            )

            # Handle bind_timeofday (captures operator + value)
            # Uses FlextLdifConstants.MetadataKeys.ACL_BIND_TIMEOFDAY for consistency
            timeofday_match = re.search(
                FlextLdifServersOud.Constants.ACL_TIMEOFDAY_PATTERN,
                aci_content,
            )
            if timeofday_match:
                extensions[FlextLdifConstants.MetadataKeys.ACL_BIND_TIMEOFDAY] = (
                    f"{timeofday_match.group(1)}{timeofday_match.group(2)}"
                )

            # Handle SSF (captures operator + value)
            # Uses FlextLdifConstants.MetadataKeys.ACL_SSF for consistency
            ssf_match = re.search(
                FlextLdifServersOud.Constants.ACL_SSF_PATTERN,
                aci_content,
            )
            if ssf_match:
                extensions[FlextLdifConstants.MetadataKeys.ACL_SSF] = (
                    f"{ssf_match.group(1)}{ssf_match.group(2)}"
                )

            # Always update metadata to ensure extensions are preserved
            # (even if timeofday/ssf weren't found, we need to preserve parse_aci extensions)
            # Business Rule: config.server_type must be valid ServerTypeLiteral
            # Implication: Type narrowing required - config is AciParserConfig with server_type field
            server_type_value = config.server_type if config else "oud"
            new_metadata = FlextLdifModels.QuirkMetadata.create_for(
                server_type_value,
                extensions=extensions,
            )
            acl = acl.model_copy(update={"metadata": new_metadata})

            return FlextResult[FlextLdifModels.Acl].ok(acl)

        def _parse_ds_privilege_name(
            self,
            privilege_name: str,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Parse OUD ds-privilege-name format (simple privilege names).

            RFC vs OUD Behavior Differences
            ================================

            **RFC Baseline**:
            - No concept of ds-privilege-name (this is OUD-specific)
            - RFC would store this as raw ACL passthrough

            **OUD Implementation** (this method):
            - Parses OUD-specific REDACTED_LDAP_BIND_PASSWORDistrative privilege names
            - Creates minimal ACL model with privilege stored in metadata
            - Used for OUD server configuration and REDACTED_LDAP_BIND_PASSWORDistrative access control

            OUD ds-privilege-name Format
            ----------------------------

            Oracle OUD uses simple privilege names (not full ACI format) for
            REDACTED_LDAP_BIND_PASSWORDistrative access control. These are typically found in the
            ``ds-privilege-name`` attribute on user entries.

            **Common Privilege Names**:

            - ``bypass-acl`` - Bypass all ACL checks (SECURITY CRITICAL)
            - ``modify-acl`` - Modify access control rules
            - ``proxied-auth`` - Use LDAP Proxied Authorization Control
            - ``config-read`` - Read server configuration
            - ``config-write`` - Write server configuration
            - ``config-delete`` - Delete configuration objects
            - ``password-reset`` - Reset user passwords
            - ``password-change`` - Change own password
            - ``bypass-lockdown`` - Bypass lockdown mode
            - ``ldif-import`` - Import LDIF data
            - ``ldif-export`` - Export LDIF data
            - ``backend-backup`` - Backup backend data
            - ``backend-restore`` - Restore backend data
            - ``server-shutdown`` - Shutdown server
            - ``server-restart`` - Restart server
            - ``disconnect-client`` - Disconnect LDAP clients
            - ``cancel-request`` - Cancel in-progress requests
            - ``unindexed-search`` - Perform unindexed searches
            - ``subentry-write`` - Write subentries (ACIs, etc.)

            **Security Note**: Never combine ``bypass-acl`` with ``proxied-auth``
            as this allows proxied users to bypass ACI evaluation.

            Model Mapping
            -------------

            - ``name`` → privilege_name (e.g., "config-read")
            - ``target`` → None (no target in ds-privilege-name)
            - ``subject`` → None (no subject in ds-privilege-name)
            - ``permissions`` → None (implicit based on privilege)
            - ``metadata.extensions[DS_PRIVILEGE_NAME_KEY]`` → privilege_name
            - ``metadata.extensions[FORMAT_TYPE_KEY]`` → FORMAT_TYPE_DS_PRIVILEGE

            Implementation Pattern
            ----------------------

            **Constants Used** (from ``FlextLdifServersOud.Constants``):

            - ``SERVER_TYPE`` - Server identifier ("oud")
            - ``DS_PRIVILEGE_NAME_KEY`` - Metadata key for privilege name
            - ``FORMAT_TYPE_KEY`` - Metadata key for format type
            - ``FORMAT_TYPE_DS_PRIVILEGE`` - Format type value ("ds-privilege-name")

            **MetadataKeys** (stored in ``metadata.extensions``):

            - Uses OUD-specific Constants keys (not generic FlextLdifConstants.MetadataKeys)

            **Model Factory**:

            - Uses ``FlextLdifModels.Acl()`` directly with minimal fields
            - Uses ``FlextLdifModels.QuirkMetadata()`` for server-specific metadata

            **RFC Override**: This is OUD-only (RFC has no ds-privilege-name concept).

            Args:
                privilege_name: Simple privilege name (e.g., "config-read")

            Returns:
                FlextResult with OUD ACL Pydantic model

            References:
                - Oracle OUD Administrative Privileges: https://docs.oracle.com/en/middleware/idm/unified-directory/12.2.1.3/oudag/understanding-access-control-model-oracle-unified-directory.html

            """
            try:
                # Build minimal ACL model for ds-privilege-name
                # This format doesn't have traditional target/subject/permissions
                acl_model = FlextLdifModels.Acl(
                    name=privilege_name,  # Use privilege name as ACL name
                    target=None,  # No target in ds-privilege-name format
                    subject=None,  # No subject in ds-privilege-name format
                    permissions=None,  # No traditional read/write/add permissions
                    server_type=FlextLdifServersOud.Constants.SERVER_TYPE,  # OUD server type from Constants
                    raw_line=privilege_name,  # Original line
                    raw_acl=privilege_name,  # Raw ACL string
                    validation_violations=[],  # No validation issues
                    metadata=FlextLdifModels.QuirkMetadata(
                        quirk_type=FlextLdifServersOud.Constants.SERVER_TYPE,  # OUD quirk type from Constants
                        extensions=FlextLdifModels.DynamicMetadata(**{
                            # Use Constants for metadata keys instead of hardcoded strings
                            FlextLdifServersOud.Constants.DS_PRIVILEGE_NAME_KEY: privilege_name,
                            FlextLdifServersOud.Constants.FORMAT_TYPE_KEY: (
                                FlextLdifServersOud.Constants.FORMAT_TYPE_DS_PRIVILEGE
                            ),
                        }),
                    ),
                )

                return FlextResult[FlextLdifModels.Acl].ok(acl_model)

            except Exception as e:
                logger.exception(
                    "Failed to parse OUD ds-privilege-name",
                )
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"Failed to parse OUD ds-privilege-name: {e}",
                )

        def _should_use_raw_acl(self, acl_data: FlextLdifModels.Acl) -> bool:
            """Check if raw_acl should be used as-is.

            Args:
                acl_data: ACL model instance

            Returns:
                True if raw_acl should be used (only if already in proper OUD format)

            """
            if not acl_data.raw_acl:
                return False

            # Use raw_acl ONLY if already in OUD format (aci: prefix)
            # All other formats (OID, etc.) must be converted
            return acl_data.raw_acl.startswith(
                FlextLdifServersOud.Constants.ACL_ACI_PREFIX,
            )

        def _build_aci_target(self, acl_data: FlextLdifModels.Acl) -> str:
            """Build ACI target clause from ACL model.

            RFC vs OUD Behavior Differences
            ================================

            **RFC Baseline**:
            - No target clause building (RFC uses raw passthrough)
            - No structured target serialization

            **OUD Implementation** (this method):
            - Builds ``(targetattr="...")`` from ``target.attributes``
            - Uses ``||`` separator for multiple attributes (OUD-specific format)
            - Falls back to metadata if model fields are empty

            OUD Target Clause Format
            ------------------------

            ::

                (targetattr="cn || sn || mail")
                (target="ldap:///ou=people,dc=example,dc=com")

            **Attribute Separator**: OUD uses ``||`` (double pipe) to separate
            multiple target attributes, unlike some servers that use commas.

            Args:
                acl_data: ACL model containing target information

            Returns:
                Formatted target clause string (e.g., '(targetattr="cn || sn")')

            References:
                - Oracle OUD ACI Target Keywords: https://docs.oracle.com/cd/E22289_01/html/821-1277/aci-syntax.html#aci-target-keywords

            """
            # Extract target from model or metadata
            target = acl_data.target
            if not target and acl_data.metadata:
                target_dict = acl_data.metadata.extensions.get("acl_target_target")
                # Business Rule: target_dict may be GeneralValueType or MetadataAttributeValue.
                # We need MetadataDictMutable (dict[str, MetadataAttributeValue]) for type safety.
                # Implication: Convert and validate types explicitly.
                if FlextRuntime.is_dict_like(target_dict):
                    # Type narrowing: target_dict is dict-like, convert to dict
                    if isinstance(target_dict, dict):
                        # Business Rule: Filter values to ensure MetadataAttributeValue compatibility.
                        # GeneralValueType may include nested Mappings, but MetadataDictMutable doesn't.
                        # Implication: Convert values to MetadataAttributeValue-compatible types.
                        # Type narrowing: Filter to only ScalarValue or Sequence[ScalarValue] types.
                        from typing import cast

                        target_data = cast(
                            "FlextLdifTypes.MetadataDictMutable",
                            {
                                k: v
                                for k, v in target_dict.items()
                                if not isinstance(v, Mapping)  # Exclude nested mappings
                                and isinstance(
                                    v, (str, int, float, bool, type(None), list)
                                )
                            },
                        )
                    else:
                        target_data = {}
                else:
                    target_data = {}
                    # Business Rule: Extract attributes and target_dn from target_data.
                    # Values are MetadataAttributeValue, so we need type narrowing for list[str].
                    # Implication: Validate types before using in AclTarget constructor.
                    attrs_raw = target_data.get("attributes")
                    dn_raw = target_data.get("target_dn")
                    # Type narrowing: Convert to expected types for AclTarget
                    attrs: list[str] = (
                        list(attrs_raw)
                        if isinstance(attrs_raw, list)
                        and all(isinstance(item, str) for item in attrs_raw)
                        else []
                    )
                    dn: str = str(dn_raw) if isinstance(dn_raw, str) else "*"
                    target = FlextLdifModels.AclTarget(
                        target_dn=dn,
                        attributes=attrs,
                    )

            # CONSOLIDATED: Use utility for formatting
            return FlextLdifUtilities.ACL.build_aci_target_clause(
                target_attributes=target.attributes if target else None,
                target_dn=target.target_dn if target else None,
                separator=" || ",
            )

        def _build_aci_permissions(
            self,
            acl_data: FlextLdifModels.Acl,
        ) -> FlextResult[str]:
            """Build ACI permissions clause from ACL model.

            RFC vs OUD Behavior Differences
            ================================

            **RFC Baseline**:
            - No permission clause building (RFC uses raw passthrough)
            - No structured permission serialization

            **OUD Implementation** (this method):
            - Builds ``allow (perm1,perm2)`` from ``permissions.*`` booleans
            - Filters to OUD-supported permissions only
            - Stores unsupported permissions in metadata for tracking
            - Handles ``selfwrite`` to ``write`` promotion via metadata bridge

            OUD Permissions Format
            ----------------------

            ::

                allow(read, search, compare)
                deny(write, delete)

            **OUD-Supported Permissions** (RFC 4876 + Oracle extensions):

            - ``read`` - Read entry attributes
            - ``write`` - Modify entry attributes
            - ``add`` - Add new entries
            - ``delete`` - Delete entries
            - ``search`` - Search for entries
            - ``compare`` - Compare attribute values
            - ``selfwrite`` - Add/delete own DN from DN-valued attributes (OUD extension)
            - ``proxy`` - Access entries as another user (OUD extension)

            **Special "all" Permission**: In OUD, ``all`` grants all permissions
            except ``proxy``, ``import``, and ``export``.

            **Unsupported Permissions**: Vendor-specific permissions from source
            servers (e.g., OID's ``browse``, ``obliterate``) are stored in metadata
            but not included in the ACI output.

            Args:
                acl_data: ACL model instance

            Returns:
                FlextResult with formatted permissions string (e.g., 'allow (read,search)')

            References:
                - Oracle OUD ACI Permissions: https://docs.oracle.com/cd/E22289_01/html/821-1277/aci-syntax.html#aci-permissions

            """
            # Get permissions from model field or metadata
            perms = acl_data.permissions

            if not perms and acl_data.metadata:
                # Reconstruct permissions from ACL_TARGET_PERMISSIONS metadata
                # This is set during conversion from source server (e.g., OID→OUD)
                target_perms_dict = acl_data.metadata.extensions.get(
                    FlextLdifConstants.MetadataKeys.ACL_TARGET_PERMISSIONS,
                )
                # Business Rule: target_perms_dict may be GeneralValueType or MetadataAttributeValue.
                # We need MetadataDictMutable (dict[str, MetadataAttributeValue]) for type safety.
                # Implication: Convert and validate types explicitly.
                if FlextRuntime.is_dict_like(target_perms_dict):
                    # Type narrowing: ensure dict has correct types
                    # Filter to only MetadataAttributeValue-compatible types
                    from typing import cast

                    perms_data = cast(
                        "FlextLdifTypes.MetadataDictMutable",
                        {
                            k: v
                            for k, v in (
                                target_perms_dict.items()
                                if isinstance(target_perms_dict, dict)
                                else []
                            )
                            if not isinstance(v, Mapping)  # Exclude nested mappings
                            and isinstance(v, (str, int, float, bool, type(None), list))
                        },
                    )
                else:
                    perms_data = {}
                    # Extract boolean fields with type guards - only use fields that exist in AclPermissions
                    perms = FlextLdifModels.AclPermissions(
                        read=bool(perms_data.get("read")),
                        write=bool(perms_data.get("write")),
                        add=bool(perms_data.get("add")),
                        delete=bool(perms_data.get("delete")),
                        search=bool(perms_data.get("search")),
                        compare=bool(perms_data.get("compare")),
                        self_write=bool(
                            perms_data.get("self_write") or perms_data.get("selfwrite"),
                        ),
                        proxy=bool(perms_data.get("proxy")),
                    )

            if not perms:
                return FlextResult[str].fail("ACL model has no permissions object")

            # Extract permission names from boolean fields directly
            ops: list[str] = [
                field_name
                for field_name in (
                    "read",
                    "write",
                    "add",
                    "delete",
                    "search",
                    "compare",
                    "self_write",
                    "proxy",
                )
                if getattr(perms, field_name, False)
            ]

            # Normalize permission names: self_write → selfwrite to match SUPPORTED_PERMISSIONS
            permission_normalization = {
                "self_write": "selfwrite",
            }
            normalized_ops = [permission_normalization.get(op, op) for op in ops]

            # Filter to only OUD-supported rights using utility
            filtered_ops = FlextLdifUtilities.ACL.filter_supported_permissions(
                normalized_ops,
                FlextLdifServersOud.Constants.SUPPORTED_PERMISSIONS,
            )

            # Check metadata bridge for self_write promotion
            if (
                acl_data.metadata
                and acl_data.metadata.extensions.get("self_write_to_write")
                and FlextLdifServersOud.Constants.PERMISSION_SELF_WRITE in ops
                and "write" not in filtered_ops
            ):
                filtered_ops.append("write")

            if not filtered_ops:
                return FlextResult[str].fail(
                    f"ACL model has no OUD-supported permissions (all were unsupported vendor-specific permissions like {FlextLdifServersOud.Constants.PERMISSION_SELF_WRITE}, stored in metadata)",
                )

            ops_str = ",".join(filtered_ops)
            return FlextResult[str].ok(
                f"{FlextLdifServersOud.Constants.ACL_ALLOW_PREFIX}{ops_str})",
            )

        def _extract_and_resolve_acl_subject(
            self,
            acl_data: FlextLdifModels.Acl,
        ) -> tuple[str | None, str, str]:
            """Extract metadata and resolve subject type and value in one pass.

            Returns:
                Tuple of (base_dn, subject_type_for_format, subject_value_str)

            """
            # Extract metadata with type guards in compact form
            ext = (
                acl_data.metadata.extensions
                if acl_data.metadata and hasattr(acl_data.metadata, "extensions")
                else None
            )
            base_dn = (
                (
                    base_dn_val
                    if isinstance(base_dn_val := ext.get("base_dn"), str)
                    else None
                )
                if ext
                else None
            )
            source_subject_type = (
                (
                    sst
                    if isinstance(
                        sst := ext.get(
                            FlextLdifConstants.MetadataKeys.ACL_SOURCE_SUBJECT_TYPE,
                        ),
                        str,
                    )
                    else None
                )
                if ext
                else None
            )

            # Determine subject type using single pass logic
            # Priority: source_subject_type (for attribute-based types) > acl_data.subject.subject_type > "self"
            # If source_subject_type is an attribute-based type, use it directly
            if source_subject_type in {"dn_attr", "guid_attr", "group_attr"}:
                subject_type = source_subject_type
            else:
                subject_type = (
                    acl_data.subject.subject_type
                    if acl_data.subject
                    else source_subject_type
                ) or "self"

            # Map bind_rules to actual subject type using metadata
            if subject_type == "bind_rules":
                if source_subject_type in {"dn_attr", "guid_attr", "group_attr"}:
                    subject_type = source_subject_type
                elif source_subject_type == "group_dn" or (
                    acl_data.subject
                    and acl_data.subject.subject_value
                    and any(
                        kw in acl_data.subject.subject_value.lower()
                        for kw in ("group=", "groupdn")
                    )
                ):
                    subject_type = "group"

            # Resolve subject value from ACL data or stored metadata
            subject_value = (
                acl_data.subject.subject_value if acl_data.subject else None
            ) or (
                sv
                if ext
                and isinstance(
                    sv := ext.get(
                        FlextLdifConstants.MetadataKeys.ACL_ORIGINAL_SUBJECT_VALUE,
                    ),
                    str,
                )
                else None
            )

            # Default self values
            if not subject_value and subject_type == "self":
                subject_value = FlextLdifServersOud.Constants.ACL_SELF_SUBJECT
            if not subject_value:
                subject_value = ""

            return base_dn, subject_type, subject_value

        def _build_aci_subject(self, acl_data: FlextLdifModels.Acl) -> str:
            """Build ACI bind rules (subject) clause from ACL model.

            RFC vs OUD Behavior Differences
            ================================

            **RFC Baseline**:
            - No bind rules clause building (RFC uses raw passthrough)
            - No structured subject serialization

            **OUD Implementation** (this method):
            - Builds bind rules from ``subject.subject_type`` and ``subject.subject_value``
            - Maps subject types to OUD bind operators (userdn, groupdn, roledn)
            - Handles special "self" subject type with ``ldap:///self``
            - Handles attribute-based subject types (dn_attr, guid_attr, group_attr)
            - Filters base_dn from subject value to avoid redundancy

            OUD Bind Rules Format
            ---------------------

            ::

                userdn = "ldap:///self"
                userdn = "ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
                groupdn = "ldap:///cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com"
                roledn = "ldap:///cn=dir-REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
                userattr = "attribute#USERDN"
                userattr = "attribute#GROUPDN"
                userattr = "attribute#LDAPURL"

            **Bind Rule Operators** (RFC 4876 + Oracle extensions):

            - ``userdn`` - User DN match (most common)
            - ``groupdn`` - Group membership check
            - ``roledn`` - Role-based access control (OUD extension)
            - ``userattr`` - Attribute-based subject matching with suffix specifier
            - ``ip`` - IP address/CIDR restriction (stored in metadata)
            - ``dns`` - DNS domain pattern (stored in metadata)
            - ``timeofday`` - Time restriction HHMM-HHMM (stored in metadata)
            - ``dayofweek`` - Day restriction (stored in metadata)
            - ``authmethod`` - Auth method restriction (stored in metadata)
            - ``ssf`` - Security strength factor (stored in metadata)

            **Special Subject Types**:

            - ``self`` → ``userdn="ldap:///self";`` (user accessing own entry)
            - ``anyone`` → ``userdn="ldap:///anyone";`` (anonymous access)
            - ``all`` → ``userdn="ldap:///all";`` (all authenticated users)
            - ``dn_attr`` → ``userattr="attribute#LDAPURL";`` (DN from attribute)
            - ``guid_attr`` → ``userattr="attribute#USERDN";`` (GUID from attribute)
            - ``group_attr`` → ``userattr="attribute#GROUPDN";`` (Group DN from attribute)

            Args:
                acl_data: ACL model containing subject information

            Returns:
                Formatted bind rules clause (e.g., 'userdn="ldap:///self";)')

            References:
                - Oracle OUD ACI Bind Rules: https://docs.oracle.com/cd/E22289_01/html/821-1277/aci-syntax.html#aci-bind-rules

            """
            # Extract and resolve in one pass
            base_dn, subject_type, subject_value = (
                self._extract_and_resolve_acl_subject(
                    acl_data,
                )
            )

            # Default to self if no subject type
            if not subject_type or subject_type == "self":
                return f'userdn="{FlextLdifServersOud.Constants.ACL_SELF_SUBJECT}";)'

            # Handle attribute-based subject types (from OID conversion)
            # These need userattr format with suffix specifier
            attr_suffix_map = {
                "dn_attr": "LDAPURL",
                "guid_attr": "USERDN",
                "group_attr": "GROUPDN",
            }

            if subject_type in attr_suffix_map:
                suffix = attr_suffix_map[subject_type]
                return f'userattr="{subject_value}#{suffix}";)'

            # Filter base_dn from subject value if present
            filtered_value = (
                subject_value[: -len(base_dn)].rstrip(",")
                if (base_dn and subject_value.endswith(base_dn))
                else subject_value
            )

            # Map subject type to bind operator and format
            bind_operator = {
                "user": "userdn",
                "group": "groupdn",
                "role": "roledn",
            }.get(
                subject_type,
                "userdn",
            )
            return FlextLdifUtilities.ACL.format_aci_subject(
                subject_type,
                filtered_value,
                bind_operator,
            )

        def _write_acl(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write RFC-compliant ACL model to OUD ACI string format (protected internal method).

            This is the server-specific ACL serialization implementation for Oracle Unified Directory (OUD).
            It implements RFC 4876 ACI (Access Control Instruction) format with OUD-specific extensions.

            RFC vs OUD Behavior Differences
            ================================

            **RFC Baseline** (in rfc.py ``_write_acl``):
            - Simple passthrough: returns ``raw_acl`` field unchanged
            - Falls back to ``name:`` format if raw_acl is empty
            - No structured serialization of ACL components

            **OUD Override** (this method):
            - Full RFC 4876 ACI serialization from structured model
            - Builds target clause from ``target.attributes``, ``target.target_dn``
            - Builds permissions from ``permissions.*`` boolean fields
            - Builds bind rules from ``subject.subject_type``, ``subject.subject_value``
            - Includes OUD-specific extensions from metadata
            - Generates conversion comments for cross-server migrations

            Output ACI Format
            -----------------

            ::

                aci: (targetattr="cn || sn")(version 3.0; acl "ACL Name"; allow (read,search) userdn="ldap:///self";)

            **ACI Components Built**:

            1. **Target clause** (from ``_build_aci_target``):
               - ``(targetattr="attr1 || attr2")`` from ``target.attributes``
               - ``(target="ldap:///dn")`` from ``target.target_dn``

            2. **Target extensions** (from metadata.extensions via Constants):
               - ``(targetscope="subtree")``
               - ``(targetfilter="(objectClass=person)")``
               - ``(targattrfilters="...")``
               - ``(targetcontrol="oid")``
               - ``(extop="oid")``

            3. **Version and name**:
               - ``(version 3.0; acl "Name";`` (always version 3.0 for OUD)

            4. **Permissions** (from ``_build_aci_permissions``):
               - ``allow (read,write,search)`` from ``permissions.*`` booleans
               - OUD-supported: read, write, add, delete, search, compare, selfwrite, proxy
               - Unsupported permissions stored in metadata for tracking

            5. **Bind rules** (from ``_build_aci_subject``):
               - ``userdn="ldap:///self"`` for self access
               - ``userdn="ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"`` for user DN
               - ``groupdn="ldap:///cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com"`` for group
               - ``roledn="ldap:///cn=role,dc=example,dc=com"`` for role-based access
               - Additional bind rules from metadata: ip, dns, timeofday, dayofweek, authmethod, ssf

            **Cross-Server Migration Comments**:

            When converting from other servers (e.g., OID→OUD), comments are generated
            to track unsupported features::

                # Converted from: oid
                # Original ACL preserved in metadata for reference
                aci: (targetattr="*")(version 3.0; acl "Test"; allow (read) userdn="ldap:///self";)

            Args:
                acl_data: RFC-compliant ACL Pydantic model

            Returns:
                FlextResult with OUD ACI formatted string including conversion comments

            Example:
                >>> acl = FlextLdifModels.Acl(
                ...     name="Allow Self Read",
                ...     target=FlextLdifModels.AclTarget(attributes=["cn", "sn"]),
                ...     permissions=FlextLdifModels.AclPermissions(
                ...         read=True, search=True
                ...     ),
                ...     subject=FlextLdifModels.AclSubject(subject_type="self"),
                ... )
                >>> result = oud_acl._write_acl(acl)
                >>> # Output: 'aci: (targetattr="cn || sn")(version 3.0; acl "Allow Self Read"; allow (read,search) userdn="ldap:///self";)'

            References:
                - RFC 4876: Access Control Instruction (ACI) Format
                - Oracle OUD ACI Syntax: https://docs.oracle.com/cd/E22289_01/html/821-1277/aci-syntax.html

            """
            try:
                c = FlextLdifServersOud.Constants
                extensions: dict[str, FlextTypes.MetadataAttributeValue] | None = (
                    acl_data.metadata.extensions.model_dump()
                    if acl_data.metadata and acl_data.metadata.extensions
                    else None
                )

                # CONSOLIDATED: Conversion comments via utility (DRY)
                # Use FlextLdifConstants.MetadataKeys for standardized key names
                aci_output_lines = FlextLdifUtilities.ACL.format_conversion_comments(
                    extensions,
                    FlextLdifConstants.MetadataKeys.CONVERTED_FROM_SERVER,
                    FlextLdifConstants.MetadataKeys.CONVERSION_COMMENTS,
                )

                # Check if we should use raw_acl as-is
                if self._should_use_raw_acl(acl_data):
                    aci_output_lines.append(acl_data.raw_acl)
                    return FlextResult[str].ok("\n".join(aci_output_lines))

                # Build ACI parts
                aci_parts = [self._build_aci_target(acl_data)]

                # CONSOLIDATED: Target extensions via utility (DRY)
                aci_parts.extend(
                    FlextLdifUtilities.ACL.extract_target_extensions(
                        extensions,
                        c.ACL_TARGET_EXTENSIONS_CONFIG,
                    ),
                )

                # Version and ACL name
                acl_name = acl_data.name or c.ACL_DEFAULT_NAME
                aci_parts.append(f'({c.ACL_DEFAULT_VERSION}; acl "{acl_name}";')

                # Permissions
                perms_result = self._build_aci_permissions(acl_data)
                if perms_result.is_failure:
                    return FlextResult[str].fail(perms_result.error or "Unknown error")

                # Subject
                subject_str = self._build_aci_subject(acl_data)
                if not subject_str:
                    return FlextResult[str].fail("ACL subject DN was filtered out")

                # CONSOLIDATED: Bind rules via utility (DRY)
                bind_rules = FlextLdifUtilities.ACL.extract_bind_rules_from_extensions(
                    extensions,
                    c.ACL_BIND_RULES_CONFIG,
                    tuple_length=c.ACL_BIND_RULE_TUPLE_LENGTH,
                )
                if bind_rules:
                    subject_str = subject_str.rstrip(";)")
                    subject_str = f"{subject_str} and {' and '.join(bind_rules)};)"

                aci_parts.extend([perms_result.unwrap(), subject_str])

                # Build final ACI string
                aci_string = f"{c.ACL_ACI_PREFIX} {' '.join(aci_parts)}"
                aci_output_lines.append(aci_string)

                return FlextResult[str].ok("\n".join(aci_output_lines))

            except Exception as e:
                logger.exception(
                    "Failed to write ACL to OUD ACI format",
                )
                return FlextResult[str].fail(
                    f"Failed to write ACL to OUD ACI format: {e}",
                )

        @staticmethod
        def _is_aci_start(line: str) -> bool:
            """Check if line starts an ACI definition.

            Args:
                line: Stripped line to check

            Returns:
                True if line starts with 'aci:' (case-insensitive)

            """
            return line.lower().startswith(
                FlextLdifServersOud.Constants.ACL_ACI_PREFIX.lower(),
            )

        @staticmethod
        def _is_ds_cfg_acl(line: str) -> bool:
            """Check if line is a ds-cfg ACL format.

            Args:
                line: Stripped line to check

            Returns:
                True if line starts with 'ds-cfg-' (case-insensitive)

            """
            return line.lower().startswith(
                FlextLdifServersOud.Constants.ACL_DS_CFG_PREFIX.lower(),
            )

        def _finalize_aci(
            self,
            current_aci: list[str],
            acls: list[FlextLdifModels.Acl],
        ) -> None:
            """Parse and add accumulated ACI to ACL list.

            Args:
                current_aci: List of accumulated ACI lines
                acls: Target list to append parsed ACL

            """
            if current_aci:
                aci_text = "\n".join(current_aci)
                result = self.parse(aci_text)
                if result.is_success:
                    acls.append(result.unwrap())

    class Entry(FlextLdifServersRfc.Entry):
        """Oracle OUD Entry Implementation (RFC 2849 + OUD Extensions).

        Extends RFC 2849 LDIF entry processing with Oracle OUD-specific features.

        RFC vs OUD Entry Differences
        ============================

        **RFC 2849 Baseline**:

        - Entry format: ``dn: <distinguished-name>`` followed by attributes
        - Attributes: ``<attribute-name>: <value>`` (colon-space-value)
        - Base64 encoding: ``<attribute-name>:: <base64-value>`` (double colon)
        - Multi-valued: Multiple lines with same attribute name
        - Continuation: Long lines wrapped with leading space
        - Changetype: add, delete, modify, modrdn

        **OUD Extensions** (Oracle-specific):

        1. **Operational Attributes** (OUD-specific prefixes):

           - ``ds-cfg-*``: Server configuration attributes
           - ``ds-sync-*``: Replication and synchronization state
           - ``ds-pwp-*``: Password policy attributes
           - ``ds-privilege-name``: Privilege assignments (root-dse-read, modify-acl, etc.)
           - ``createTimestamp``, ``modifyTimestamp``: Creation/modification time
           - ``creatorsName``, ``modifiersName``: Creator/modifier DN

        2. **DN Handling** (OUD-specific):

           - Case-insensitive comparison but case-preserving storage
           - Spaces after commas in DN allowed: ``cn=User, dc=example, dc=com``
           - Escaped characters: backslash-comma, backslash-plus, backslash-quote
           - DN normalization for comparison

        3. **Multi-line ACIs** (OUD-specific):

           - ACIs can span multiple lines with continuation (leading whitespace)
           - Multiple ACIs per entry (multi-valued ``aci`` attribute)
           - Complex ACIs with multiple bind rules

        4. **ObjectClass Handling** (OUD-specific):

           - Mixed case objectClass names accepted: ``groupOfUniqueNames`` = ``GROUPOFUNIQUENAMES``
           - Oracle-specific objectClasses: ``orclContext``, ``orclContainer``, ``orclGroup``
           - OUD supports both STRUCTURAL and AUXILIARY classes

        5. **Attribute Value Handling**:

           - Binary attributes auto-detected and base64 encoded
           - Multi-byte UTF-8 properly handled
           - Sensitive attributes (``userPassword``) handled specially

        Real Examples (from fixtures)
        -----------------------------

        **Basic Entry**::

            dn: cn=OracleContext,dc=example,dc=com
            cn: OracleContext
            objectclass: top
            objectclass: orclContext
            objectclass: orclContextAux82
            orclVersion: 90600

        **Entry with Multi-valued Attributes**::

            dn: cn=OracleDASGroupPriv, cn=Groups,cn=OracleContext
            objectclass: groupOfUniqueNames
            uniquemember: cn=orclREDACTED_LDAP_BIND_PASSWORD
            uniqueMember: cn=OracleDASAdminGroup, cn=Groups,cn=OracleContext
            displayname: DAS Group Privilege

        **Entry with Complex ACI** (multi-line)::

            dn: cn=Groups,cn=OracleContext
            aci: (targetattr="*")(version 3.0; acl "Multi-group access";
                 allow (read,search,write,selfwrite,compare)
                 groupdn="ldap:///cn=OracleDASUserPriv,cn=Groups,cn=OracleContext";
                 allow (read,search,compare) userdn="ldap:///anyone";)

        Conversion Pipeline
        -------------------

        OUD has ZERO knowledge of OID (or other server) formats. All conversions
        go through RFC Entry Model as intermediate format::

            OID Entry → RFC Entry Model → OUD Entry
            OUD Entry → RFC Entry Model → OpenLDAP Entry

        This decoupling ensures servers don't need to know about each other.

        Official Documentation
        ----------------------

        - LDIF Format: https://docs.oracle.com/cd/E22289_01/html/821-1273/understanding-ldif-files.html
        - RFC 2849 (base): https://tools.ietf.org/html/rfc2849

        Example Usage
        -------------

        ::

            quirk = FlextLdifServersOud.Entry()
            if quirk.can_handle_entry(entry):
                result = quirk.parse_entry(entry.dn.value, entry.attributes.attributes)
                if result.is_success:
                    parsed_entry = result.unwrap()
                    # Access OUD-specific operational attributes

        """

        def __init__(
            self,
            entry_service: FlextLdifTypes.Services.EntryService | None = None,
            _parent_quirk: FlextLdifServersBase | None = None,
            **kwargs: str | float | bool | None,
        ) -> None:
            """Initialize OUD entry quirk.

            Args:
                entry_service: Injected FlextLdifEntry service (optional)
                _parent_quirk: Reference to parent FlextLdifServersBase (optional)
                **kwargs: Additional arguments passed to parent

            """
            # Business Rule: Filter _parent_quirk from kwargs to avoid type errors
            # Implication: _parent_quirk is handled separately, not via Pydantic fields
            # Business Rule: Only pass GeneralValueType (str | float | bool | None) to super().__init__
            # Implication: Filter kwargs to ensure type safety (int is not GeneralValueType, only str/float/bool/None)
            filtered_kwargs: dict[str, str | float | bool | None] = {
                k: v
                for k, v in kwargs.items()
                if k != "_parent_quirk"
                and isinstance(v, (str, float, bool, type(None)))
            }
            # Business Rule: Entry.__init__ accepts entry_service and _parent_quirk
            # Implication: Call parent __init__ directly, parent handles FlextService call
            super().__init__(
                entry_service=entry_service,
                _parent_quirk=_parent_quirk,
                **filtered_kwargs,
            )

        # OVERRIDDEN METHODS (from FlextLdifServersBase.Entry)
        # These methods override the base class with Oracle OUD-specific logic:
        # - can_handle(): Detects OUD entries by DN/attributes (PRIVATE)
        # - _parse_entry(): Normalizes OUD entries with metadata during parsing (PRIVATE)
        # - _write_entry(): Writes OUD entries with proper formatting (PRIVATE)

        def can_handle(
            self,
            entry_dn: str,
            attributes: FlextLdifTypes.CommonDict.AttributeDictGeneric,
        ) -> bool:
            """Check if OUD should handle this entry using pattern matching.

            RFC vs OUD Behavior Differences
            ================================

            **RFC Baseline** (in rfc.py):
            - Returns ``True`` for ALL entries (catch-all fallback)
            - Does not inspect DN patterns or attribute names
            - RFC is the universal fallback when no server-specific handler matches

            **OUD Override** (this method):
            - Returns ``True`` ONLY for OUD-specific entries
            - Detects entries by DN patterns, attribute prefixes, and keywords
            - Allows RFC fallback for non-OUD entries

            OUD Detection Patterns
            ----------------------

            **DN Patterns** (from ``Constants.DN_DETECTION_PATTERNS``):
            - ``cn=OracleContext`` - Oracle context entries
            - ``dc=oracleContext`` - Oracle domain context
            - ``ou=OracleContext`` - Oracle org unit context

            **Attribute Prefixes** (from ``Constants.DETECTION_ATTRIBUTE_PREFIXES``):
            - ``ds-cfg-`` - OUD server configuration attributes
            - ``ds-sync-`` - OUD replication attributes
            - ``ds-pwp-`` - OUD password policy attributes
            - ``orcl`` - Oracle-specific attributes (orclVersion, orclContext, etc.)

            **Attribute Names** (from ``Constants.BOOLEAN_ATTRIBUTES``):
            - OUD-specific boolean operational attributes

            **Keyword Patterns** (from ``Constants.KEYWORD_PATTERNS``):
            - Oracle-specific values within attributes

            Implementation Pattern
            ----------------------

            **Constants Used** (from ``FlextLdifServersOud.Constants``):

            - ``DN_DETECTION_PATTERNS`` - DN patterns for OUD detection
            - ``DETECTION_ATTRIBUTE_PREFIXES`` - Attribute prefixes (ds-cfg-, orcl, etc.)
            - ``BOOLEAN_ATTRIBUTES`` - OUD-specific boolean attrs
            - ``KEYWORD_PATTERNS`` - Keyword detection patterns

            **Utilities Used**:

            - ``FlextLdifUtilities.Entry.matches_server_patterns()`` - Pattern matching

            **RFC Override**: Extends RFC (RFC returns True for all entries as fallback).

            Args:
                entry_dn: Entry DN string
                attributes: Entry attributes dictionary

            Returns:
                True if this quirk should handle the entry

            References:
                - Oracle OUD LDIF Format: https://docs.oracle.com/cd/E22289_01/html/821-1273/understanding-ldif-files.html

            """
            c = FlextLdifServersOud.Constants
            return (
                FlextLdifUtilities.Entry.matches_server_patterns(
                    entry_dn,
                    attributes,
                    dn_patterns=c.DN_DETECTION_PATTERNS,
                    attr_prefixes=c.DETECTION_ATTRIBUTE_PREFIXES,
                    attr_names=c.BOOLEAN_ATTRIBUTES,
                    keyword_patterns=c.KEYWORD_PATTERNS,
                )
                or FlextLdifConstants.DictKeys.OBJECTCLASS.lower() in attributes
            )

        # ===== _parse_entry - SIMPLIFIED VIA HOOK-BASED ARCHITECTURE =====
        # NOTE: _process_oud_attributes REMOVED - RFC base + hooks handles this
        # NOTE: _build_and_populate_roundtrip_metadata REMOVED - RFC base handles this
        # NOTE: _analyze_oud_entry_differences REMOVED - use FlextLdifUtilities.Entry.analyze_differences
        # NOTE: _store_oud_minimal_differences REMOVED - use FlextLdifUtilities.Metadata.store_minimal_differences
        # NOTE: parse_entry now calls RFC base + populates OUD metadata (2025-01)

        def parse_entry(
            self,
            entry_dn: str,
            entry_attrs: (
                FlextLdifTypes.CommonDict.AttributeDictGeneric | FlextLdifModels.Entry
            ),
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Parse entry with OUD-specific metadata population.

            RFC vs OUD Behavior Differences
            ================================

            **RFC Baseline** (in rfc.py ``parse_entry``):
            - Creates Entry model with RFC defaults
            - Metadata has quirk_type='rfc'
            - No server-specific format tracking

            **OUD Override** (this method):
            - Calls RFC base parse_entry for Entry creation
            - Populates OUD-specific metadata for round-trip support
            - Tracks original DN, transform source, and attribute case

            Metadata Populated
            ------------------

            **original_format_details** (from ``FlextLdifConstants.Rfc``):
            - ``_transform_source``: "oud" (server type identifier)
            - ``_dn_original``: Original DN before any normalization
            - ``_dn_was_base64``: Whether DN was base64 encoded

            **original_attribute_case** (for round-trip):
            - Maps normalized attribute names to original case
            - Example: {"objectclass": "objectClass"}

            Implementation Pattern
            ----------------------

            **Utilities Used**:
            - ``FlextLdifUtilities.Metadata.build_entry_parse_metadata()`` - Metadata creation

            **RFC Override**: Extends RFC (RFC creates Entry, OUD adds metadata).

            Args:
                entry_dn: Entry distinguished name
                entry_attrs: Entry attributes mapping

            Returns:
                FlextResult[Entry] with OUD-specific metadata populated

            References:
                - Oracle OUD LDIF Format: https://docs.oracle.com/cd/E22289_01/html/821-1273/understanding-ldif-files.html

            """
            # Business Rule: parse_entry expects dict[str, list[str]]
            # Implication: Convert entry_attrs to expected format
            # Type narrowing: convert Mapping to dict[str, list[str]]
            entry_attrs_dict: dict[str, list[str]] = {}
            if isinstance(entry_attrs, dict):
                for key, values in entry_attrs.items():
                    if isinstance(values, list):
                        entry_attrs_dict[key] = [str(v) for v in values]
                    elif isinstance(values, (str, bytes)):
                        entry_attrs_dict[key] = [str(values)]
                    else:
                        entry_attrs_dict[key] = [str(values)]
            elif isinstance(entry_attrs, FlextLdifModels.Entry):
                # If Entry model passed, extract attributes
                if entry_attrs.attributes and entry_attrs.attributes.attributes:
                    entry_attrs_dict = {
                        k: [str(v) for v in (vs if isinstance(vs, list) else [vs])]
                        for k, vs in entry_attrs.attributes.attributes.items()
                    }
            # Call RFC base parse_entry for Entry creation
            result = super().parse_entry(entry_dn, entry_attrs_dict)
            if result.is_failure:
                return result

            entry = result.unwrap()

            # Build OUD-specific metadata
            original_attribute_case: dict[str, str] = {}
            if isinstance(entry_attrs, Mapping):
                for attr_name in entry_attrs:
                    if isinstance(attr_name, str):
                        # Track original case for round-trip support
                        original_attribute_case[attr_name.lower()] = attr_name

            # Create OUD metadata using utility
            metadata = FlextLdifUtilities.Metadata.build_entry_parse_metadata(
                quirk_type="oud",
                original_entry_dn=entry_dn,
                cleaned_dn=entry.dn.value if entry.dn else entry_dn,
                original_dn_line=f"dn: {entry_dn}",
                original_attr_lines=[],
                dn_was_base64=False,
                original_attribute_case=original_attribute_case,
            )

            # Update entry with OUD metadata
            entry.metadata = metadata

            return FlextResult.ok(entry)

        def _is_schema_entry(self, entry: FlextLdifModels.Entry) -> bool:
            """Check if entry is a schema entry - delegate to utility."""
            return FlextLdifUtilities.Entry.is_schema_entry(entry, strict=False)

        def _add_original_entry_comments(
            self,
            entry_data: FlextLdifModels.Entry,
            write_options: FlextLdifModels.WriteFormatOptions | None,
        ) -> list[str]:
            """Add original entry as commented LDIF block.

            RFC vs OUD Behavior Differences
            ================================

            **RFC Baseline**:
            - No original entry commenting support
            - Writes only the current entry format

            **OUD Override** (this method):
            - Writes original source entry as commented LDIF block
            - Helps debug migration issues by showing source format
            - Enables auditing of OID → OUD conversions

            Output Format
            -------------

            When enabled, output includes both original and converted entry::

                # ======================================================================
                # ORIGINAL Entry (alternative format) (commented)
                # ======================================================================
                # dn: cn=user, dc=example, dc=com
                # objectclass: person
                # cn: user
                #
                # ======================================================================
                # CONVERTED OUD Entry (active)
                # ======================================================================
                dn: cn=user,dc=example,dc=com
                objectClass: person
                cn: user

            Configuration
            -------------

            Controlled via ``WriteFormatOptions``:
            - ``write_original_entry_as_comment: True`` - Enable original entry comments
            - Original entry stored in ``metadata.write_options["_original_entry"]``

            Args:
                entry_data: Entry with metadata containing original entry
                write_options: Write options with write_original_entry_as_comment flag

            Returns:
                List of LDIF comment lines (empty if feature disabled)

            """
            if not (write_options and write_options.write_original_entry_as_comment):
                return []

            # RFC Compliance: Check metadata.write_options
            if not (entry_data.metadata and entry_data.metadata.write_options):
                return []

            # WriteOptions can be a Pydantic model or dict
            write_opts = entry_data.metadata.write_options
            if hasattr(write_opts, "model_dump"):
                write_opts_dict = write_opts.model_dump()
            elif isinstance(write_opts, dict):
                write_opts_dict = write_opts
            else:
                write_opts_dict = {}
            original_entry_obj = write_opts_dict.get(
                FlextLdifConstants.MetadataKeys.ORIGINAL_ENTRY,
            )
            if not (
                original_entry_obj
                and isinstance(original_entry_obj, FlextLdifModels.Entry)
            ):
                return []

            ldif_parts: list[str] = []
            ldif_parts.extend(
                [
                    "# " + "=" * 70,
                    "# ORIGINAL Entry (alternative format) (commented)",
                    "# " + "=" * 70,
                ],
            )

            original_result = self._write_entry_as_comment(original_entry_obj)
            if original_result.is_success:
                ldif_parts.append(original_result.unwrap())

            ldif_parts.extend(
                [
                    "",
                    "# " + "=" * 70,
                    "# CONVERTED OUD Entry (active)",
                    "# " + "=" * 70,
                ],
            )

            return ldif_parts

        def _apply_phase_aware_acl_handling(
            self,
            entry_data: FlextLdifModels.Entry,
            write_options: FlextLdifModels.WriteFormatOptions | None,
        ) -> FlextLdifModels.Entry:
            """Apply phase-aware ACL attribute commenting.

            RFC vs OUD Behavior Differences
            ================================

            **RFC Baseline**:
            - No phase-aware ACL handling
            - ACL attributes written directly without modification

            **OUD Override** (this method):
            - Comments out ACL attributes during non-ACL migration phases
            - Enables phased migration: entries first, ACLs later
            - Prevents ACL application before referenced entries exist

            OUD Migration Phases
            --------------------

            **Phase-Aware ACL Strategy**:

            ::

                Phase 01 (Groups):    ACL attributes → commented (# aci: ...)
                Phase 02 (Users):     ACL attributes → commented (# aci: ...)
                Phase 03 (Contexts):  ACL attributes → commented (# aci: ...)
                Phase 04 (ACL):       ACL attributes → written normally (aci: ...)

            **Why Phase-Aware ACLs?**:
            - ACIs reference entries by DN (userdn, groupdn)
            - Referenced entries must exist before ACI can be applied
            - Applying ACIs too early causes errors

            Configuration
            -------------

            Controlled via ``WriteFormatOptions``:
            - ``comment_acl_in_non_acl_phases: True`` - Enable phase awareness
            - ``entry_category``: Current phase (``"group"``, ``"user"``, ``"acl"``)
            - ``acl_attribute_names``: List of ACL attribute names to comment

            Args:
                entry_data: Entry to process
                write_options: Write options with ACL phase settings

            Returns:
                Entry with ACL attributes commented if applicable

            """
            if not (write_options and write_options.comment_acl_in_non_acl_phases):
                return entry_data

            category = write_options.entry_category
            acl_attrs = write_options.acl_attribute_names

            if not (category and category != "acl" and acl_attrs):
                return entry_data

            # Comment out ACL attributes in non-ACL phases (01/02/03)
            # Use utility to comment ACL attributes - CRITICAL for client-a-oud-mig phase-aware handling
            # Convert to list if needed (acl_attrs can be frozenset, set, or list)
            acl_attrs_list = (
                list(acl_attrs)
                if isinstance(acl_attrs, (frozenset, set))
                else acl_attrs
                if isinstance(acl_attrs, list)
                else []
            )
            return self._comment_acl_attributes(entry_data, acl_attrs_list)

        @staticmethod
        def extract_and_remove_acl_attributes(
            attributes_dict: dict[str, list[str]],
            acl_attribute_names: list[str],
        ) -> tuple[dict[str, list[str]], dict[str, list[str]], set[str]]:
            """Extract ACL attributes and remove from active dict.

            Args:
                attributes_dict: Current attributes dictionary
                acl_attribute_names: Names of ACL attributes to process

            Returns:
                Tuple of (new_attributes_dict, commented_acl_values, hidden_attrs)

            """
            new_attrs: dict[str, list[str]] = dict(attributes_dict)
            commented_vals: dict[str, list[str]] = {}
            hidden_attrs = set()

            for acl_attr in acl_attribute_names:
                if acl_attr in new_attrs:
                    acl_values = new_attrs[acl_attr]
                    if isinstance(acl_values, list):
                        commented_vals[acl_attr] = list(acl_values)
                    else:
                        commented_vals[acl_attr] = [str(acl_values)]

                    del new_attrs[acl_attr]
                    hidden_attrs.add(acl_attr.lower())

            return new_attrs, commented_vals, hidden_attrs

        @staticmethod
        def update_metadata_with_commented_acls(
            metadata: FlextLdifModels.QuirkMetadata
            | FlextLdifModelsDomains.QuirkMetadata,
            acl_attribute_names: list[str],
            commented_acl_values: dict[str, list[str]],
            hidden_attrs: set[str],
            entry_attributes_dict: dict[str, list[str]],
        ) -> FlextLdifModels.QuirkMetadata | FlextLdifModelsDomains.QuirkMetadata:
            """Update metadata with commented ACL information.

            Args:
                metadata: Existing metadata
                acl_attribute_names: List of ACL attribute names
                commented_acl_values: Dictionary of commented ACL values
                hidden_attrs: Set of hidden attribute names
                entry_attributes_dict: Original attributes dict for checking

            Returns:
                Updated metadata with ACL information

            """
            current_extensions: dict[str, FlextTypes.MetadataAttributeValue] = (
                dict(metadata.extensions) if metadata.extensions else {}
            )

            # Business Rule: metadata is frozen, must use model_copy to update
            # Implication: Create new metadata instance with updated write_options
            write_opts = metadata.write_options
            new_write_options: FlextLdifModelsDomains.WriteOptions

            if not write_opts:
                new_write_options = FlextLdifModelsDomains.WriteOptions()
            else:
                # Update hidden attributes
                hidden_attrs_raw = getattr(write_opts, "hidden_attrs", [])
                hidden_attrs_set = (
                    set(hidden_attrs_raw)
                    if isinstance(hidden_attrs_raw, (list, tuple, frozenset, set))
                    else set()
                )
                hidden_attrs_set.update(hidden_attrs)
                # Handle both Pydantic model and dict
                if hasattr(write_opts, "model_copy"):
                    new_write_options = write_opts.model_copy(
                        update={"hidden_attrs": list(hidden_attrs_set)},
                    )
                elif isinstance(write_opts, dict):
                    # If it's a dict, extract only WriteOptions fields
                    # Extract only valid WriteOptions fields
                    write_opts_dict = {
                        "hidden_attrs": list(hidden_attrs_set),
                    }
                    # Copy other valid WriteOptions fields if present
                    for field in ["line_width", "indent", "sort_attributes"]:
                        if field in write_opts:
                            write_opts_dict[field] = write_opts[field]
                    new_write_options = (
                        FlextLdifModelsDomains.WriteOptions.model_validate(
                            write_opts_dict
                        )
                    )
                elif hasattr(write_opts, "model_dump"):
                    # If it's a Pydantic model (WriteFormatOptions), extract only WriteOptions fields
                    write_opts_dict = write_opts.model_dump()
                    # Extract only valid WriteOptions fields
                    filtered_dict = {
                        "hidden_attrs": list(hidden_attrs_set),
                    }
                    # Copy other valid WriteOptions fields if present
                    for field in ["line_width", "indent", "sort_attributes"]:
                        if field in write_opts_dict:
                            filtered_dict[field] = write_opts_dict[field]
                    new_write_options = (
                        FlextLdifModelsDomains.WriteOptions.model_validate(
                            filtered_dict
                        )
                    )
                else:
                    # Create new WriteOptions if write_options is None or invalid
                    new_write_options = FlextLdifModelsDomains.WriteOptions(
                        hidden_attrs=list(hidden_attrs_set),
                    )

            # Create new metadata instance with updated write_options
            metadata = metadata.model_copy(update={"write_options": new_write_options})

            # Store commented ACL values
            if commented_acl_values:
                converted_attrs: list[str] = list(commented_acl_values.keys())
                current_extensions[
                    FlextLdifConstants.MetadataKeys.CONVERTED_ATTRIBUTES
                ] = converted_attrs
                # Business Rule: extensions expects MetadataAttributeValue (ScalarValue)
                # Implication: Convert dict to JSON string for storage
                current_extensions["commented_attribute_values"] = json.dumps(
                    commented_acl_values
                )

            # Track in extensions - type narrow for list[str] using comprehension
            commented_attrs_raw = current_extensions.get("acl_commented_attributes", [])
            commented_attrs: list[str] = (
                [str(x) for x in commented_attrs_raw]
                if isinstance(commented_attrs_raw, list)
                else []
            )

            for acl_attr in acl_attribute_names:
                if (
                    acl_attr in entry_attributes_dict
                    and acl_attr not in commented_attrs
                ):
                    commented_attrs.append(acl_attr)

            if commented_attrs:
                current_extensions["acl_commented_attributes"] = commented_attrs

            # Business Rule: metadata is frozen, must use model_copy to update both extensions and write_options
            # Implication: Combine both updates in a single model_copy call
            return metadata.model_copy(
                update={
                    "extensions": current_extensions,
                    "write_options": new_write_options,
                },
            )

        @staticmethod
        def _comment_acl_attributes(
            entry_data: FlextLdifModels.Entry,
            acl_attribute_names: list[str],
        ) -> FlextLdifModels.Entry:
            """Comment out ACL attributes by removing them from attributes dict and storing in metadata.

            CRITICAL for client-a-oud-mig phase-aware ACL handling.
            Removes ACL attributes from active attributes dict and stores values in metadata
            for later comment generation with [TRANSFORMED] and [SKIP TO 04] tags.

            Args:
                entry_data: Entry with ACL attributes
                acl_attribute_names: List of ACL attribute names to comment

            Returns:
                Entry with ACL attributes removed from attributes dict and stored in metadata

            """
            if not entry_data.attributes or not acl_attribute_names:
                return entry_data

            # Ensure metadata exists
            existing_metadata = entry_data.metadata
            if not existing_metadata:
                existing_metadata = FlextLdifModels.QuirkMetadata.create_for("oud")

            # Extract and remove ACL attributes from active dict
            # Note: Using class-based call for staticmethod
            new_attributes_dict, commented_acl_values, hidden_attrs = (
                FlextLdifServersOud.Entry.extract_and_remove_acl_attributes(
                    entry_data.attributes.attributes,
                    acl_attribute_names,
                )
            )

            # Update metadata with commented ACL information
            updated_metadata = (
                FlextLdifServersOud.Entry.update_metadata_with_commented_acls(
                    existing_metadata,
                    acl_attribute_names,
                    commented_acl_values,
                    hidden_attrs,
                    entry_data.attributes.attributes,
                )
            )

            # Return updated entry with new attributes dict (without ACLs)
            return entry_data.model_copy(
                update={
                    "attributes": FlextLdifModels.LdifAttributes(
                        attributes=new_attributes_dict,
                        attribute_metadata=entry_data.attributes.attribute_metadata,
                        metadata=entry_data.attributes.metadata,
                    ),
                    "metadata": updated_metadata,
                },
            )

        def _normalize_aci_value(
            self,
            aci_value: str,
            _base_dn: str | None,
            _dn_registry: FlextLdifModels.DnRegistry | None,
        ) -> tuple[str, bool]:
            """Normalize ACI value DNs (already RFC canonical, no changes needed)."""
            # ACI values are already normalized during RFC parsing
            return aci_value, False

        def _extract_acl_metadata(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> tuple[str | None, FlextLdifModels.DnRegistry | None]:
            """Extract base_dn and dn_registry from entry metadata for ACL processing.

            Args:
                entry_data: Entry with potential metadata

            Returns:
                Tuple of (base_dn, dn_registry)

            """
            base_dn: str | None = None
            dn_registry: FlextLdifModels.DnRegistry | None = None

            if entry_data.metadata and entry_data.metadata.write_options:
                # Try write_options first
                base_dn_value = getattr(
                    entry_data.metadata.write_options,
                    "base_dn",
                    None,
                )
                if isinstance(base_dn_value, str):
                    base_dn = base_dn_value

                # Get dn_registry from write_options
                dn_registry_value = getattr(
                    entry_data.metadata.write_options,
                    "dn_registry",
                    None,
                )
                if isinstance(dn_registry_value, FlextLdifModels.DnRegistry):
                    dn_registry = dn_registry_value

            # Try extensions if write_options doesn't have base_dn
            if (
                base_dn is None
                and entry_data.metadata
                and entry_data.metadata.extensions
            ):
                extensions = entry_data.metadata.extensions
                # DynamicMetadata has .get() method for extra field access
                base_dn_ext = extensions.get("base_dn")
                if isinstance(base_dn_ext, str):
                    base_dn = base_dn_ext
                dn_registry_ext = extensions.get("dn_registry")
                if isinstance(dn_registry_ext, FlextLdifModels.DnRegistry):
                    dn_registry = dn_registry_ext

            return base_dn, dn_registry

        def _normalize_acl_dns(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextLdifModels.Entry:
            r"""Normalize and filter DNs in ACL attribute values (userdn/groupdn inside ACL strings).

            RFC vs OUD Behavior Differences
            ================================

            **RFC Baseline**:
            - No ACL DN normalization in RFC base
            - ACLs stored as raw strings without processing

            **OUD Override** (this method):
            - Normalizes DNs within ACI values (userdn, groupdn patterns)
            - Removes spaces after commas in embedded DNs
            - Optionally filters DNs by base_dn scope
            - Preserves DN case while normalizing whitespace

            ACI DN Normalization
            --------------------

            **Patterns Processed**:
            - ``userdn="ldap:///cn=user, dc=example, dc=com"`` → normalized DN
            - ``groupdn="ldap:///cn=group, dc=example, dc=com"`` → normalized DN
            - ``roledn="ldap:///cn=role, dc=example, dc=com"`` → normalized DN

            **Normalization Rules**:
            - Remove spaces after commas: ``cn=user, dc=example`` → ``cn=user,dc=example``
            - Preserve attribute case: ``CN=User`` stays as ``CN=User``
            - Handle escaped characters: ``cn=user\, name`` preserved

            **Base DN Filtering** (when configured):
            - Filter out ACIs referencing DNs outside base_dn scope
            - Helps migration by excluding irrelevant ACIs

            Args:
                entry_data: Entry with potential ACL attributes

            Returns:
                Entry with normalized/filtered ACL values

            """
            if not entry_data.attributes or not entry_data.attributes.attributes:
                return entry_data

            # Extract base_dn and dn_registry from metadata
            base_dn, dn_registry = self._extract_acl_metadata(entry_data)

            # Process aci attribute values
            attrs = entry_data.attributes.attributes
            if "aci" not in attrs:
                return entry_data

            aci_values = attrs["aci"]
            if not aci_values:
                return entry_data

            # Normalize each ACL value string
            normalized_aci_values: list[str] = []
            for aci in aci_values:
                aci_str = aci if isinstance(aci, str) else str(aci)
                normalized_aci, was_filtered = self._normalize_aci_value(
                    aci_str,
                    base_dn,
                    dn_registry,
                )

                # Only add if no DN was filtered out (ACL is still valid)
                if not was_filtered and normalized_aci:
                    normalized_aci_values.append(normalized_aci)

            # Update entry with normalized ACL values
            if normalized_aci_values != aci_values:
                new_attrs = dict(entry_data.attributes.attributes)
                new_attrs["aci"] = normalized_aci_values
                entry_data.attributes.attributes = new_attrs

            return entry_data

        def _restore_entry_from_metadata(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextLdifModels.Entry:
            """Restore original DN and attributes using generic utilities.

            RFC vs OUD Behavior Differences
            ================================

            **RFC Baseline** (in rfc.py ``_restore_entry_from_metadata``):
            - Basic restoration of DN and attributes
            - Uses metadata.extensions for stored values
            - Simple case mapping restoration

            **OUD Override** (this method):
            - Full roundtrip restoration using OUD-specific metadata
            - Restores DN with original spacing (spaces after commas)
            - Restores attribute names with original case
            - Restores attribute values to original format

            Restoration Process
            -------------------

            **1. DN Restoration** (if differences detected):
               - Checks ``minimal_differences_dn.has_differences``
               - Uses ``original_dn_complete`` from extensions
               - Restores DN with original spacing quirks

            **2. Attribute Restoration** (if case mapping available):
               - Uses ``original_attribute_case`` mapping
               - Uses ``original_attributes_complete`` dictionary
               - Restores each attribute with original case

            Example Restoration
            -------------------

            ::

                # Original OID entry:
                objectclass: groupOfUniqueNames
                uniquemember: cn = user1

                # Normalized for OUD:
                objectClass: groupOfUniqueNames
                uniqueMember: cn = user1

                # Restored for roundtrip (with preserve_original=True):
                objectclass: groupOfUniqueNames
                uniquemember: cn = user1

            """
            if not (entry_data.metadata and entry_data.metadata.extensions):
                return entry_data
            ext = entry_data.metadata.extensions

            # Restore DN if differences detected
            # Uses FlextLdifConstants.MetadataKeys for consistent key access
            mk = FlextLdifConstants.MetadataKeys
            if (
                (original_dn := ext.get(mk.ORIGINAL_DN_COMPLETE))
                and isinstance(original_dn, str)
                and entry_data.dn
            ):
                dn_diff = ext.get(mk.MINIMAL_DIFFERENCES_DN, {})
                if FlextRuntime.is_dict_like(dn_diff) and dn_diff.get(
                    mk.HAS_DIFFERENCES,
                ):
                    entry_data = entry_data.model_copy(
                        update={
                            "dn": FlextLdifModels.DistinguishedName(value=original_dn),
                        },
                    )

            # Restore attributes if case mapping available
            original_case_map = (
                entry_data.metadata.original_attribute_case
                if entry_data.metadata
                else None
            )
            if (
                entry_data.attributes
                and original_case_map
                and isinstance(original_case_map, dict)
                and (orig_attrs := ext.get(mk.ORIGINAL_ATTRIBUTES_COMPLETE))
                and FlextRuntime.is_dict_like(orig_attrs)
            ):
                # Business Rule: Restore original attribute case from metadata.
                # orig_case is str (from original_case_map.get()), but pyright may infer
                # it as MetadataAttributeValue. We use explicit type narrowing.
                # Implication: Ensure orig_case is always str for dict key access.
                restored: dict[str, list[str]] = {}
                for attr_name, attr_values in entry_data.attributes.attributes.items():
                    # Business Rule: original_case_map.get() returns str (the original case).
                    # Type narrowing: Ensure orig_case is str for type safety.
                    orig_case_raw = original_case_map.get(
                        attr_name.lower(),
                        attr_name,
                    )
                    orig_case: str = str(orig_case_raw) if orig_case_raw else attr_name
                    # Business Rule: orig_attrs is dict-like (DynamicMetadata), accessed via str keys.
                    # Implication: Use str(orig_case) for type safety even though runtime is correct.
                    if orig_case in orig_attrs:
                        val = orig_attrs[orig_case]
                        restored[orig_case] = (
                            [str(i) for i in val]
                            if FlextRuntime.is_list_like(val)
                            else [str(val)]
                        )
                    else:
                        restored[orig_case] = (
                            [str(i) for i in attr_values]
                            if isinstance(attr_values, list)
                            else [str(attr_values)]
                        )

                if restored:
                    entry_data = entry_data.model_copy(
                        update={
                            "attributes": FlextLdifModels.LdifAttributes(
                                attributes=restored,
                                attribute_metadata=entry_data.attributes.attribute_metadata,
                                metadata=entry_data.attributes.metadata,
                            ),
                        },
                    )

            return entry_data

        def _write_entry(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextResult[str]:
            """Write Entry to LDIF with OUD-specific formatting + phase-aware ACL handling.

            RFC vs OUD Behavior Differences
            ================================

            **RFC Baseline** (in rfc.py ``_write_entry``):
            - Basic RFC 2849 compliant LDIF output
            - Writes ``dn: <value>`` line followed by attributes
            - Uses ``:`` for normal values, ``::`` for base64
            - Optional ``changetype: modify`` format for schema updates
            - Basic metadata restoration (DN, attributes)

            **OUD Override** (this method):
            - Full OUD-specific formatting with roundtrip preservation
            - Pre-write hook application for OUD-specific normalization
            - Phase-aware ACL handling (comment ACLs in non-ACL phases)
            - Original entry commenting (write source as commented LDIF)
            - DN normalization in ACL values (userdn, groupdn patterns)
            - Restores original OUD formatting from metadata

            OUD-Specific Features
            ---------------------

            **1. Pre-Write Normalization** (OUD requirement):
               - Applies _hook_pre_write_entry() for attribute normalization
               - Converts to OUD-expected camelCase (objectclass → objectClass)
               - Converts boolean values to TRUE/FALSE format

            **2. Roundtrip Preservation** (OUD requirement):
               - Restores original DN (spaces after commas)
               - Restores original attribute case (``objectClass`` vs ``objectclass``)
               - Preserves original attribute order
               - Uses metadata.extensions for stored original values

            **3. Phase-Aware ACL Handling** (OUD migration):
               - In phases 01/02/03: Comments out ACL attributes
               - In phase 04 (ACL): Writes ACL attributes normally
               - Prevents ACL application before entries exist

            **4. Original Entry Commenting** (OUD migration):
               - When ``write_original_entry_as_comment=True``
               - Writes source entry as commented LDIF block
               - Helps with migration debugging and auditing

            **5. ACL DN Normalization** (OUD ACI requirement):
               - Normalizes DNs in ACI values (userdn, groupdn)
               - Removes spaces after commas in DN references
               - Preserves case but normalizes whitespace

            Migration Phase Flow
            --------------------

            ::

                Phase 01 (Groups):    [ACL commented] → ``# aci: (target...)``
                Phase 02 (Users):     [ACL commented] → ``# aci: (target...)``
                Phase 03 (Contexts):  [ACL commented] → ``# aci: (target...)``
                Phase 04 (ACL):       [ACL active]    → ``aci: (target...)``

            Args:
                entry_data: Entry model to write (with complete metadata)

            Returns:
                FlextResult with LDIF string (with original formatting restored when possible)

            References:
                - Oracle OUD LDIF Format: https://docs.oracle.com/cd/E22289_01/html/821-1273/understanding-ldif-files.html
                - RFC 2849: LDIF Specification

            """
            # Step 1: Apply pre-write hook for OUD-specific normalization (attribute case, boolean conversion)
            hook_result = self._hook_pre_write_entry(entry_data)
            if hook_result.is_failure:
                return FlextResult[str].fail(
                    f"Pre-write hook failed: {hook_result.error}",
                )
            normalized_entry = hook_result.unwrap()

            # Step 2: Restore original formatting from metadata
            entry_to_write = self._restore_entry_from_metadata(normalized_entry)

            # Extract write options (uses utility)
            write_options = FlextLdifUtilities.Metadata.extract_write_options(
                entry_to_write,
            )

            # Build LDIF output
            ldif_parts: list[str] = []
            ldif_parts.extend(
                self._add_original_entry_comments(entry_data, write_options),
            )

            # Apply phase-aware ACL handling
            entry_data = self._apply_phase_aware_acl_handling(entry_data, write_options)

            # Normalize DNs in ACL values if enabled
            if FlextLdifServersOud.Constants.ACL_NORMALIZE_DNS_IN_VALUES:
                entry_data = self._normalize_acl_dns(entry_data)

            # Write entry in appropriate format (RFC handles both schema and standard entries)
            result = super()._write_entry(entry_data)

            if result.is_failure:
                return result

            ldif_parts.append(result.unwrap())
            # Use utilities for finalization (SRP: delegate to writer)
            ldif_str = FlextLdifUtilities.Writer.finalize_ldif_text(ldif_parts)
            return FlextResult[str].ok(ldif_str)

        def _write_entry_as_comment(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextResult[str]:
            """Write entry as commented LDIF (each line prefixed with '# ').

            Args:
                entry_data: Entry to write as comment

            Returns:
                FlextResult with commented LDIF string

            """
            # Use RFC write method to get LDIF representation
            result = super()._write_entry(entry_data)
            if result.is_failure:
                return result

            # Prefix each line with '# '
            ldif_text = result.unwrap()
            commented_lines = [f"# {line}" for line in ldif_text.split("\n")]
            return FlextResult[str].ok("\n".join(commented_lines))

        def _add_transformation_comments(
            self,
            comment_lines: list[str],
            entry: FlextLdifModels.Entry,
            format_options: FlextLdifModels.WriteFormatOptions | None = None,
        ) -> None:
            """Add transformation comments for attribute changes, including OUD-specific ACL handling.

            OUD Override of RFC's _add_transformation_comments to handle OID→OUD transformations:
            - [TRANSFORMED] for original ACL values (orclaci)
            - [SKIP TO 04] for new ACL values (aci) in phases 01-03

            Uses generic utilities with hooks/parameters for extensibility.
            Attributes are sorted using the same ordering logic as normal attributes.

            Args:
                comment_lines: List to append comments to
                entry: Entry with transformation metadata
                format_options: Write format options for attribute ordering

            """
            if not entry.metadata:
                return

            # Handle OUD-specific ACL comments for phases 01-03
            # Pass format_options to ensure ACL comments are sorted correctly
            acl_attr_names_to_skip = self._add_oud_acl_comments(
                comment_lines,
                entry,
                format_options,
            )

            # Process attribute_transformations (primary source)
            processed_attrs: set[str] = set()
            if entry.metadata.attribute_transformations:
                # Collect attribute names and sort them using the same logic as normal attributes
                attr_names = [
                    attr_name
                    for attr_name in entry.metadata.attribute_transformations
                    if attr_name.lower() not in acl_attr_names_to_skip
                ]
                ordered_attr_names = self._determine_attribute_order(
                    attr_names,
                    format_options,
                )

                # Iterate over sorted attribute names instead of dictionary directly
                for attr_name in ordered_attr_names:
                    transformation = entry.metadata.attribute_transformations[attr_name]
                    transformation_type = transformation.transformation_type.upper()
                    # Map types: MODIFIED → TRANSFORMED for comments
                    comment_type = (
                        "TRANSFORMED"
                        if transformation_type in {"MODIFIED", "TRANSFORMED"}
                        else transformation_type
                    )
                    self._add_attribute_transformation_comments(
                        comment_lines,
                        attr_name,
                        transformation,
                        comment_type,
                    )
                    processed_attrs.add(attr_name.lower())

            # Also check removed_attributes field for legacy compatibility
            # This ensures all removed attributes are shown, even if not tracked as transformations
            if (
                format_options
                and format_options.write_removed_attributes_as_comments
                and entry.metadata.removed_attributes
            ):
                # removed_attributes is a DynamicMetadata, iterate over model_dump keys
                removed_attrs_dict = entry.metadata.removed_attributes.model_dump()
                removed_attr_names: list[str] = [
                    str(attr_name)
                    for attr_name in removed_attrs_dict
                    if isinstance(attr_name, str)
                    and attr_name.lower() not in acl_attr_names_to_skip
                ]
                ordered_removed_attrs = self._determine_attribute_order(
                    removed_attr_names,
                    format_options,
                )

                for attr_name in ordered_removed_attrs:
                    # Skip if already processed as transformation or ACL
                    if attr_name.lower() in processed_attrs:
                        continue

                    removed_values = entry.metadata.removed_attributes[attr_name]
                    if isinstance(removed_values, list):
                        comment_lines.extend(
                            f"# [REMOVED] {attr_name}: {value}"
                            for value in removed_values
                        )
                    else:
                        comment_lines.append(
                            f"# [REMOVED] {attr_name}: {removed_values}",
                        )

            if comment_lines:
                comment_lines.append("")  # Separator

        def _collect_acl_from_transformations(
            self,
            entry: FlextLdifModels.Entry,
            acl_comments_dict: dict[str, list[str]],
            acl_attr_names_to_skip: set[str],
        ) -> None:
            """Collect ACL comments from attribute_transformations with SKIP_TO_04."""
            if not entry.metadata or not entry.metadata.attribute_transformations:
                return

            acl_attr_set = {"aci", "orclaci", "orclentrylevelaci"}
            for (
                attr_name,
                transformation,
            ) in entry.metadata.attribute_transformations.items():
                is_skip_to_04 = (
                    transformation.reason
                    and "SKIP_TO_04" in transformation.reason.upper()
                )
                if is_skip_to_04 and attr_name.lower() in acl_attr_set:
                    acl_attr_names_to_skip.add(attr_name.lower())
                    if attr_name not in acl_comments_dict:
                        acl_comments_dict[attr_name] = []
                    for acl_value in transformation.original_values:
                        acl_comments_dict[attr_name].extend([
                            f"# [REMOVED] {attr_name}: {acl_value}",
                            f"# [SKIP_TO_04] {attr_name}: {acl_value}",
                        ])

        def _collect_acl_from_extensions(
            self,
            entry: FlextLdifModels.Entry,
            acl_comments_dict: dict[str, list[str]],
            acl_attr_names_to_skip: set[str],
        ) -> None:
            """Collect ACL comments from extensions.commented_attribute_values."""
            if not entry.metadata or not entry.metadata.extensions:
                return

            commented_acl_values_raw = entry.metadata.extensions.get(
                "commented_attribute_values",
            )
            if not commented_acl_values_raw:
                return
            # Parse JSON string if needed (stored as json.dumps)
            if isinstance(commented_acl_values_raw, str):
                import json

                commented_acl_values = json.loads(commented_acl_values_raw)
            elif isinstance(commented_acl_values_raw, dict):
                commented_acl_values = commented_acl_values_raw
            else:
                return

            original_acl_attr = self._get_original_acl_attr(entry)
            for acl_attr_name, acl_values_raw in commented_acl_values.items():
                if acl_attr_name.lower() in acl_attr_names_to_skip:
                    continue
                acl_attr_names_to_skip.add(acl_attr_name.lower())
                sort_key = original_acl_attr or acl_attr_name
                if sort_key not in acl_comments_dict:
                    acl_comments_dict[sort_key] = []
                # Business Rule: acl_values_raw is MetadataAttributeValue (ScalarValue)
                # Implication: Convert to expected type (list[str] | str | Acl) for _add_acl_value_comments
                # Type narrowing: Convert ScalarValue to expected type
                if isinstance(acl_values_raw, str):
                    acl_values: list[str] | str | FlextLdifModels.Acl = acl_values_raw
                elif isinstance(acl_values_raw, list):
                    # Convert list[ScalarValue] to list[str]
                    acl_values = [str(v) for v in acl_values_raw]
                elif isinstance(acl_values_raw, FlextLdifModels.Acl):
                    acl_values = acl_values_raw
                else:
                    # Fallback: convert to string
                    acl_values = str(acl_values_raw)
                self._add_acl_value_comments(
                    acl_comments_dict[sort_key],
                    original_acl_attr,
                    acl_attr_name,
                    acl_values,
                )

        def _add_acl_value_comments(
            self,
            comments: list[str],
            original_attr: str,
            attr_name: str,
            acl_values: list[str] | str | FlextLdifModels.Acl,
        ) -> None:
            """Add TRANSFORMED and SKIP_TO_04 comments for ACL values."""
            if isinstance(acl_values, list):
                for acl_value in acl_values:
                    comments.extend([
                        f"# [TRANSFORMED] {original_attr}: {acl_value}",
                        f"# [SKIP_TO_04] {attr_name}: {acl_value}",
                    ])
            else:
                acl_val_str = str(acl_values)
                comments.extend([
                    f"# [TRANSFORMED] {original_attr}: {acl_val_str}",
                    f"# [SKIP_TO_04] {attr_name}: {acl_val_str}",
                ])

        def _add_oud_acl_comments(
            self,
            comment_lines: list[str],
            entry: FlextLdifModels.Entry,
            format_options: FlextLdifModels.WriteFormatOptions | None = None,
        ) -> set[str]:
            """Add OUD-specific ACL comments for phases 01-03.

            Checks both attribute_transformations and extensions.commented_attribute_values.
            Returns set of ACL attribute names to skip in regular processing.

            """
            acl_attr_names_to_skip: set[str] = set()
            if not entry.metadata:
                return acl_attr_names_to_skip

            acl_comments_dict: dict[str, list[str]] = {}

            self._collect_acl_from_transformations(
                entry,
                acl_comments_dict,
                acl_attr_names_to_skip,
            )
            self._collect_acl_from_extensions(
                entry,
                acl_comments_dict,
                acl_attr_names_to_skip,
            )

            if acl_comments_dict:
                acl_attr_names = list(acl_comments_dict.keys())
                ordered_acl_attrs = self._determine_attribute_order(
                    acl_attr_names,
                    format_options,
                )
                for attr_name in ordered_acl_attrs:
                    if attr_name in acl_comments_dict:
                        comment_lines.extend(acl_comments_dict[attr_name])

            return acl_attr_names_to_skip

        def _get_original_acl_attr(self, entry: FlextLdifModels.Entry) -> str:
            """Get original ACL attribute name (orclaci) from transformations or metadata."""
            if entry.metadata and entry.metadata.attribute_transformations:
                for (
                    attr_name,
                    transformation,
                ) in entry.metadata.attribute_transformations.items():
                    if (
                        attr_name.lower() in {"aci", "orclaci"}
                        and transformation.target_name
                        and transformation.target_name.lower() == "aci"
                    ):
                        return attr_name

            # Try to find original ACL attribute name from metadata
            if entry.metadata and entry.metadata.extensions:
                acl_original_format = entry.metadata.extensions.get(
                    FlextLdifConstants.MetadataKeys.ACL_ORIGINAL_FORMAT,
                )
                if acl_original_format and "orclaci:" in str(acl_original_format):
                    return "orclaci"

            # Default to "orclaci" if we can't determine the original name
            return "orclaci"

        def generate_entry_comments(
            self,
            entry: FlextLdifModels.Entry,
            format_options: FlextLdifModels.WriteFormatOptions | None = None,
        ) -> str:
            """Generate LDIF comments for transformations, including OUD-specific ACL handling.

            OUD Override of RFC's generate_entry_comments to add phase-aware ACL comments.
            Delegates to _add_transformation_comments() for OID→OUD specific handling.

            Args:
                entry: Entry to generate comments for
                format_options: Write format options controlling comment generation (optional)

            Returns:
                String containing comment lines (with trailing newline if non-empty)

            """
            # Return empty if no format_options provided
            if not format_options:
                return ""

            comment_lines: list[str] = []

            # Add transformation comments if enabled (includes OUD-specific ACL handling)
            if format_options.write_transformation_comments:
                self._add_transformation_comments(comment_lines, entry, format_options)

            # Add rejection reason comments if enabled
            if format_options.write_rejection_reasons:
                self._add_rejection_reason_comments(comment_lines, entry)

            return "\n".join(comment_lines) + "\n" if comment_lines else ""

        def _hook_post_parse_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Hook: Validate OUD ACI macros after parsing Entry.

            RFC vs OUD Behavior Differences
            ================================

            **RFC Baseline** (in rfc.py ``_hook_post_parse_entry``):
            - Default implementation returns entry unchanged
            - No macro validation or processing
            - No entry post-processing hooks

            **OUD Override** (this method):
            - Validates OUD ACI macro syntax when present
            - Detects and validates macro patterns in ACIs
            - Preserves macros for OUD directory server expansion
            - Adds metadata notes when macros detected

            OUD ACI Macro Types
            -------------------

            **1. DN Substring Macro** ``($dn)``:
               - Used for substring matching/substitution
               - Example: ``userdn="ldap:///$($dn)"``

            **2. Hierarchical DN Macro** ``[$dn]``:
               - Used for hierarchical substitution
               - Example: ``userdn="ldap:///[$dn]"``

            **3. Attribute Value Macro** ``($attr.attrName)``:
               - Substitutes attribute value at runtime
               - Example: ``userdn="ldap:///($attr.manager)"``

            Validation Rules
            ----------------

            - Macros must be well-formed (balanced parentheses/brackets)
            - Attribute macros must reference valid attribute names
            - Macros are NOT expanded here (OUD server does that at runtime)

            Implementation Pattern
            ----------------------

            **Constants Used** (from ``FlextLdifServersOud.Constants``):

            - ``MAX_LOG_LINE_LENGTH`` - Truncation limit for log messages

            **MetadataKeys** (from ``FlextLdifConstants``):

            - ``ACI_LIST_PREVIEW_LIMIT`` - Max ACIs to log in preview

            **Hooks**:

            - This IS a hook method (``_hook_post_parse_entry``)
            - Calls ``_validate_aci_macros()`` for syntax validation

            **RFC Override**: Extends RFC (RFC returns entry unchanged).

            Args:
                entry: Entry parsed from OUD LDIF (in RFC canonical format)

            Returns:
                FlextResult[Entry] - validated entry, unchanged if valid

            References:
                - Oracle OUD ACI Macros: https://docs.oracle.com/cd/E22289_01/html/821-1277/aci-syntax.html

            """
            # Extract attributes dict with None check for type safety
            attrs_dict = (
                entry.attributes.attributes if entry.attributes is not None else {}
            )

            # Validate ACI macros if present
            aci_attrs = attrs_dict.get("aci")
            if aci_attrs and FlextRuntime.is_list_like(aci_attrs):
                has_macros = False
                for aci_value in aci_attrs:
                    if isinstance(aci_value, str):
                        # Check if macros present
                        if re.search(r"\(\$dn\)|\[\$dn\]|\(\$attr\.", aci_value):
                            has_macros = True

                        # Validate macro rules
                        validation_result = self._validate_aci_macros(aci_value)
                        if validation_result.is_failure:
                            return FlextResult[FlextLdifModels.Entry].fail(
                                f"ACI macro validation failed: {validation_result.error}",
                            )

                # Log if macros were found (metadata is immutable - just log)
                if has_macros:
                    max_len = FlextLdifServersOud.Constants.MAX_LOG_LINE_LENGTH
                    aci_list = (
                        list(aci_attrs)
                        if FlextRuntime.is_list_like(aci_attrs)
                        else [str(aci_attrs)]
                    )
                    logger.debug(
                        "Entry contains OUD ACI macros - preserved for runtime expansion",
                        entry_dn=entry.dn.value if entry.dn else None,
                        aci_count=len(aci_list),
                        aci_preview=[
                            s[:max_len]
                            for s in aci_list[
                                : FlextLdifConstants.ACI_LIST_PREVIEW_LIMIT
                            ]
                            if isinstance(s, str)
                        ],
                    )

            # Entry is RFC-canonical - return unchanged
            return FlextResult[FlextLdifModels.Entry].ok(entry)

        def _validate_aci_macros(self, _aci_value: str) -> FlextResult[bool]:
            """Validate OUD ACI macro consistency rules (no-op)."""
            # ACI syntax is validated at parse time
            return FlextResult[bool].ok(True)

        @staticmethod
        def _hook_pre_write_entry_static(
            entry: FlextLdifModels.Entry,
            validate_aci_macros: Callable[[str], FlextResult[bool]],
            correct_rfc_syntax_in_attributes: Callable[
                [FlextLdifTypes.CommonDict.AttributeDict],
                FlextResult[FlextLdifTypes.CommonDict.AttributeDict],
            ],
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Hook: Validate and CORRECT RFC syntax issues before writing Entry - static helper.

            This hook ensures that Entry data with RFC-valid syntax is properly
            formatted for OUD LDIF output. It does NOT alter data structure
            (attributes, objectClasses, etc.) - only corrects syntax/formatting.

            Args:
                entry: RFC Entry (already canonical, with aci: attributes)
                validate_aci_macros: Function to validate ACI macros
                correct_rfc_syntax_in_attributes: Function to correct RFC syntax

            Returns:
                FlextResult[Entry] - entry with corrected syntax, fail() if syntax errors

            """
            # INLINED: _extract_attributes_dict (only used once)
            attrs_dict_raw = entry.attributes.attributes if entry.attributes else {}
            attrs_dict: FlextLdifTypes.CommonDict.AttributeDict = dict(
                attrs_dict_raw.items(),
            )
            aci_validation_error = (
                FlextLdifServersOud.Entry.validate_aci_macros_in_entry(
                    attrs_dict,
                    validate_aci_macros,
                )
            )
            if aci_validation_error:
                return FlextResult[FlextLdifModels.Entry].fail(aci_validation_error)

            return FlextLdifServersOud.Entry.correct_syntax_and_return_entry(
                entry,
                attrs_dict,
                correct_rfc_syntax_in_attributes,
            )

        @staticmethod
        def validate_aci_macros_in_entry(
            attrs_dict: FlextLdifTypes.CommonDict.AttributeDict,
            validate_aci_macros: Callable[[str], FlextResult[bool]],
        ) -> str | None:
            """Validate ACI macros if present. Returns error message or None if valid."""
            aci_attrs = attrs_dict.get("aci")
            if aci_attrs and FlextRuntime.is_list_like(aci_attrs):
                for aci_value in aci_attrs:
                    if isinstance(aci_value, str):
                        validation_result = validate_aci_macros(aci_value)
                        if validation_result.is_failure:
                            return f"ACI macro validation failed: {validation_result.error}"
            return None

        @staticmethod
        def correct_syntax_and_return_entry(
            entry: FlextLdifModels.Entry,
            attrs_dict: FlextLdifTypes.CommonDict.AttributeDict,
            correct_rfc_syntax_in_attributes: Callable[
                [FlextLdifTypes.CommonDict.AttributeDict],
                FlextResult[FlextLdifTypes.CommonDict.AttributeDict],
            ],
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Correct RFC syntax issues and return entry."""
            corrected_result = correct_rfc_syntax_in_attributes(attrs_dict)
            if corrected_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(
                    corrected_result.error or "Unknown error",
                )

            corrected_data = corrected_result.unwrap()
            # Business Rule: apply_syntax_corrections expects specific types
            # Implication: Convert corrected_data and syntax_corrections to expected formats
            # Type narrowing: convert to expected types
            corrected_data_typed: dict[
                str,
                str
                | int
                | float
                | bool
                | list[str]
                | dict[str, str | list[str]]
                | None,
            ] = cast(
                "dict[str, str | int | float | bool | list[str] | dict[str, str | list[str]] | None]",
                corrected_data,
            )
            # Business Rule: apply_syntax_corrections expects list[str] or dict[str, str], not None.
            # Implication: Type narrowing ensures syntax_corrections_typed is not None before calling.
            # Type narrowing: Convert to expected types for apply_syntax_corrections.
            # Business Rule: syntax_corrections_raw may be None, list, dict, or other types.
            # Implication: Explicit type narrowing with isinstance checks ensures type safety.
            # Extract syntax_corrections with explicit type narrowing
            syntax_corrections_raw = corrected_data_typed.get("syntax_corrections")
            syntax_corrections_typed: list[str] | dict[str, str] | None = None
            if isinstance(syntax_corrections_raw, list):
                # Type narrowing: syntax_corrections_raw is list, convert to list[str]
                syntax_corrections_typed = [str(v) for v in syntax_corrections_raw]
            elif isinstance(syntax_corrections_raw, dict):
                # Type narrowing: syntax_corrections_raw is dict, convert to dict[str, str]
                # Business Rule: Use explicit iteration to help type checker understand types.
                # Implication: Type checker may infer Never for dict.items() in some contexts.
                # Additional type narrowing: ensure dict type before iteration
                syntax_corrections_dict: dict[str, str] = {}
                # Business Rule: syntax_corrections_raw is dict[str, ...] from corrected_data_typed.
                # Implication: Values may be str | int | float | bool | list[str] | dict[str, str | list[str]] | None.
                # We convert all values to str for dict[str, str] compatibility.
                if isinstance(syntax_corrections_raw, dict):
                    for k, v in syntax_corrections_raw.items():
                        syntax_corrections_dict[str(k)] = (
                            str(v) if v is not None else ""
                        )
                syntax_corrections_typed = syntax_corrections_dict
            # Business Rule: Only call apply_syntax_corrections if syntax_corrections_typed is not None.
            # Type narrowing: Check for None before calling to ensure type safety.
            if syntax_corrections_typed is not None:
                return FlextLdifServersOud.Entry.apply_syntax_corrections(
                    entry,
                    corrected_data_typed,
                    syntax_corrections_typed,
                )

            return FlextResult[FlextLdifModels.Entry].ok(entry)

        @staticmethod
        def apply_syntax_corrections(
            entry: FlextLdifModels.Entry,
            corrected_data: dict[
                str,
                str
                | int
                | float
                | bool
                | list[str]
                | dict[str, str | list[str]]
                | None,
            ],
            syntax_corrections: list[str] | dict[str, str] | None,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Apply syntax corrections to entry."""
            corrected_attrs = corrected_data.get("corrected_attributes")
            if not FlextRuntime.is_dict_like(corrected_attrs):
                return FlextResult[FlextLdifModels.Entry].ok(entry)

            attrs_for_model: dict[str, list[str]] = {}
            for k, v in corrected_attrs.items():
                # Python 3.13: Use match/case for type dispatching
                match v:
                    case list():
                        attrs_for_model[k] = [str(item) for item in v]
                    case str():
                        attrs_for_model[k] = [v]
                    case _ if FlextRuntime.is_list_like(v):
                        attrs_for_model[k] = [str(v)]

            corrected_ldif_attrs = FlextLdifModels.LdifAttributes(
                attributes=attrs_for_model,
            )
            corrected_entry = entry.model_copy(
                update={"attributes": corrected_ldif_attrs},
            )

            logger.debug(
                "OUD quirks: Applied syntax corrections before writing (structure preserved)",
                entry_dn=entry.dn.value if entry.dn else None,
                corrections_count=len(syntax_corrections)
                if FlextRuntime.is_list_like(syntax_corrections)
                else 0,
                corrections=syntax_corrections,
                corrected_attributes=list(corrected_attrs.keys())
                if FlextRuntime.is_dict_like(corrected_attrs)
                else None,
            )
            return FlextResult[FlextLdifModels.Entry].ok(corrected_entry)

        def _hook_finalize_entry_parse(
            self,
            entry: FlextLdifModels.Entry,
            original_dn: str,
            original_attrs: FlextLdifTypes.CommonDict.AttributeDictGeneric,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Hook: Process ACLs and propagate their extensions to entry metadata.

            This hook processes ACL attributes (aci) in the entry and extracts
            their metadata extensions (like targattrfilters, targetcontrol, etc.)
            and propagates them to the entry's metadata.extensions.

            Args:
                entry: Parsed entry from RFC with all hooks applied
                original_dn: Original DN before transformation
                original_attrs: Original attributes for ACL processing

            Returns:
                FlextResult with entry containing ACL metadata extensions

            """
            _ = original_dn  # Used for logging if needed

            # Use original_attrs to get ACL attributes (before any transformations)
            # original_attrs contains the raw attributes from the LDIF parsing
            if not original_attrs:
                return FlextResult.ok(entry)

            # Check if entry has ACL attributes in original_attrs
            aci_values = original_attrs.get("aci")
            if not aci_values:
                # Fallback: Check if aci is in entry.attributes instead
                # This handles cases where original_attrs may not have aci
                # (e.g., during second parsing after write)
                if entry.attributes and entry.attributes.attributes:
                    aci_values = entry.attributes.attributes.get("aci")
                if not aci_values:
                    # Also check case-insensitive variants
                    for key, value in original_attrs.items() if original_attrs else []:
                        if key.lower() == "aci":
                            aci_values = value
                            break
                    if (
                        not aci_values
                        and entry.attributes
                        and entry.attributes.attributes
                    ):
                        for key, value in entry.attributes.attributes.items():
                            if key.lower() == "aci":
                                aci_values = value
                                break
                    if not aci_values:
                        return FlextResult.ok(entry)

            # Ensure metadata exists
            if not entry.metadata:
                entry.metadata = FlextLdifModels.QuirkMetadata.create_for(
                    "oud",
                    extensions=FlextLdifModels.DynamicMetadata(),
                )

            # Get current extensions
            current_extensions: dict[str, FlextTypes.MetadataAttributeValue] = (
                dict(entry.metadata.extensions) if entry.metadata.extensions else {}
            )

            # Get ACL quirk from parent server
            parent = getattr(self, "_parent_quirk", None)
            if not parent:
                return FlextResult.ok(entry)

            # Access ACL quirk via parent's _acl_quirk attribute
            acl_quirk = getattr(parent, "_acl_quirk", None)
            if not acl_quirk:
                return FlextResult.ok(entry)

            # Process ACLs if quirk is available
            if acl_quirk:
                # Process each ACI value
                aci_list = (
                    list(aci_values)
                    if FlextRuntime.is_list_like(aci_values)
                    else [str(aci_values)]
                )

                for aci_value in aci_list:
                    if not isinstance(aci_value, str):
                        continue

                    # Ensure aci_value has "aci:" prefix for _parse_acl
                    # LDIF parsing may strip the prefix, so we need to add it back
                    normalized_aci = aci_value.strip()
                    if not normalized_aci.startswith("aci:"):
                        normalized_aci = f"aci: {normalized_aci}"

                    # Parse ACL using OUD ACL quirk's _parse_acl method
                    acl_result = acl_quirk._parse_acl(normalized_aci)
                    if acl_result.is_success:
                        acl_model = acl_result.unwrap()
                        # Extract extensions from ACL metadata
                        if acl_model.metadata and acl_model.metadata.extensions:
                            acl_extensions = (
                                acl_model.metadata.extensions.model_dump()
                                if hasattr(acl_model.metadata.extensions, "model_dump")
                                else dict(acl_model.metadata.extensions)
                            )
                            # Propagate ACL extensions to entry metadata
                            # Use standardized MetadataKeys for consistency
                            for key, value in acl_extensions.items():
                                # Map pattern names to MetadataKeys
                                # Also check for MetadataKeys directly (for round-trip preservation)
                                if key == "targattrfilters":
                                    current_extensions[
                                        FlextLdifConstants.MetadataKeys.ACL_TARGETATTR_FILTERS
                                    ] = value
                                elif (
                                    key
                                    == FlextLdifConstants.MetadataKeys.ACL_TARGETATTR_FILTERS
                                ):
                                    # Preserve if already in MetadataKeys format
                                    current_extensions[
                                        FlextLdifConstants.MetadataKeys.ACL_TARGETATTR_FILTERS
                                    ] = value
                                # Also check for lowercase key variant
                                elif key.lower() == "targattrfilters":
                                    current_extensions[
                                        FlextLdifConstants.MetadataKeys.ACL_TARGETATTR_FILTERS
                                    ] = value
                                elif key == "targetcontrol":
                                    current_extensions[
                                        FlextLdifConstants.MetadataKeys.ACL_TARGET_CONTROL
                                    ] = value
                                elif key == "extop":
                                    current_extensions[
                                        FlextLdifConstants.MetadataKeys.ACL_EXTOP
                                    ] = value
                                elif key == "ip":
                                    current_extensions[
                                        FlextLdifConstants.MetadataKeys.ACL_BIND_IP
                                    ] = value
                                elif key == "dns":
                                    current_extensions[
                                        FlextLdifConstants.MetadataKeys.ACL_BIND_DNS
                                    ] = value
                                elif key == "dayofweek":
                                    current_extensions[
                                        FlextLdifConstants.MetadataKeys.ACL_BIND_DAYOFWEEK
                                    ] = value
                                elif key == "timeofday":
                                    current_extensions[
                                        FlextLdifConstants.MetadataKeys.ACL_BIND_TIMEOFDAY
                                    ] = value
                                elif key == "authmethod":
                                    current_extensions[
                                        FlextLdifConstants.MetadataKeys.ACL_AUTHMETHOD
                                    ] = value
                                elif key == "ssf":
                                    current_extensions[
                                        FlextLdifConstants.MetadataKeys.ACL_SSF
                                    ] = value

            # Update entry metadata with ACL extensions
            # Always merge extensions if we have any ACL extensions to add
            if current_extensions:
                # Merge with existing extensions if metadata exists
                existing_extensions = (
                    dict(entry.metadata.extensions)
                    if entry.metadata and entry.metadata.extensions
                    else {}
                )
                # Merge current_extensions into existing_extensions (current takes precedence)
                merged_extensions = {**existing_extensions, **current_extensions}
                entry.metadata = entry.metadata.model_copy(
                    update={
                        "extensions": FlextLdifModels.DynamicMetadata(
                            **merged_extensions
                        ),
                    },
                )

            return FlextResult.ok(entry)

        def _hook_pre_write_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Hook: Pre-write entry validation (simplified).

            Entry is returned unchanged (RFC-valid format preserved).

            Args:
                entry: RFC Entry (already canonical)

            Returns:
                FlextResult[Entry] - entry unchanged

            """
            # Entry is RFC-canonical and already validated
            return FlextResult[FlextLdifModels.Entry].ok(entry)

        def _finalize_and_parse_entry(
            self,
            entry_dict: dict[str, FlextTypes.GeneralValueType],
            entries_list: list[FlextLdifModels.Entry],
        ) -> None:
            """Finalize entry dict and parse into entries list.

            Args:
                entry_dict: Entry dictionary with DN and attributes
                entries_list: Target list to append parsed Entry models

            """
            if FlextLdifConstants.DictKeys.DN not in entry_dict:
                return

            dn = str(entry_dict.pop(FlextLdifConstants.DictKeys.DN))
            original_entry_dict = dict(entry_dict)

            # Convert entry_dict to proper type for _parse_entry
            entry_attrs: dict[str, list[str | bytes]] = {}
            for k, v in entry_dict.items():
                if isinstance(v, list):
                    entry_attrs[str(k)] = [
                        item if isinstance(item, str | bytes) else str(item)
                        for item in v
                    ]
                elif isinstance(v, str | bytes):
                    entry_attrs[str(k)] = [v]
                else:
                    entry_attrs[str(k)] = [str(v)]

            result = self._parse_entry(dn, entry_attrs)
            if result.is_success:
                entry = result.unwrap()
                original_dn = dn
                parsed_dn = entry.dn.value if entry.dn else None
                parsed_attrs = entry.attributes.attributes if entry.attributes else {}

                # CONSOLIDATED: Use utilities for difference analysis and storage (DRY)
                converted_attrs: dict[str, list[str]] = {
                    k: list(v) if isinstance(v, list) else [str(v)]
                    for k, v in parsed_attrs.items()
                }
                dn_differences, attribute_differences, original_attrs_complete, _ = (
                    FlextLdifUtilities.Entry.analyze_differences(
                        entry_attrs=original_entry_dict,
                        converted_attrs=converted_attrs,
                        original_dn=original_dn,
                        cleaned_dn=parsed_dn or original_dn,
                    )
                )

                # Ensure metadata exists
                if not entry.metadata:
                    entry.metadata = FlextLdifModels.QuirkMetadata.create_for(
                        "oud",
                        extensions=FlextLdifModels.DynamicMetadata(),
                    )

                # CONSOLIDATED: Store via utility (DRY)
                # Business Rule: store_minimal_differences expects ScalarValue for _extra
                # Implication: Convert complex dicts to JSON strings for storage
                FlextLdifUtilities.Metadata.store_minimal_differences(
                    metadata=entry.metadata,
                    dn_differences=json.dumps(dn_differences),
                    attribute_differences=json.dumps(attribute_differences),
                    original_dn=original_dn or "",
                    parsed_dn=parsed_dn or "",
                    original_attributes_complete=json.dumps(original_attrs_complete),
                )

                logger.debug(
                    "OUD entry parsed with minimal differences",
                    entry_dn=original_dn[:50] if original_dn else None,
                )

                entries_list.append(entry)


__all__ = ["FlextLdifServersOud"]
