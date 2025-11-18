"""Oracle Unified Directory (OUD) Quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides OUD-specific quirks for schema, ACL, and entry processing.
"""

from __future__ import annotations

import base64
import operator
import re
from collections.abc import Callable, Mapping
from enum import StrEnum
from typing import ClassVar, TypedDict, cast

from flext_core import FlextLogger, FlextResult

from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities

logger = FlextLogger(__name__)

# Alias for cleaner code - MetadataKeys from Constants
MetaKeys = FlextLdifConstants.MetadataKeys


# Type definitions for validation rules structure
class EncodingRulesDict(TypedDict):
    """Encoding rules structure."""

    default_encoding: str
    allowed_encodings: list[str]


class DnCaseRulesDict(TypedDict):
    """DN case rules structure."""

    preserve_case: bool
    normalize_to: str | None


class AclFormatRulesDict(TypedDict):
    """ACL format rules structure."""

    format: str
    attribute_name: str
    requires_target: bool
    requires_subject: bool


class ValidationRulesDict(TypedDict):
    """Validation rules structure for server-specific validation."""

    requires_objectclass: bool
    requires_naming_attr: bool
    requires_binary_option: bool
    encoding_rules: EncodingRulesDict
    dn_case_rules: DnCaseRulesDict
    acl_format_rules: AclFormatRulesDict
    track_deletions: bool
    track_modifications: bool
    track_conversions: bool


class FlextLdifServersOud(FlextLdifServersRfc):
    """Oracle Unified Directory (OUD) Quirks."""

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
        SERVER_TYPE: ClassVar[str] = FlextLdifConstants.ServerTypes.OUD
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
        ALIASES: ClassVar[frozenset[str]] = frozenset(["oud", "oracle_oud"])

        # =====================================================================
        # CONVERSION CAPABILITIES
        # =====================================================================
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["oud", "rfc"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["oud", "rfc"])

        # =====================================================================
        # ACL CONFIGURATION
        # =====================================================================
        ACL_FORMAT: ClassVar[str] = "aci"  # RFC 4876 ACI attribute
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"  # OUD uses standard ACI

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

        # === ACL BIND PATTERNS MAPPING (Python 3.13) ===
        ACL_BIND_PATTERNS: ClassVar[Mapping[str, str]] = {
            ACL_BIND_RULE_TYPE_USERDN: ACL_USERDN_PATTERN,
            ACL_BIND_RULE_TYPE_GROUPDN: ACL_GROUPDN_PATTERN,
        }

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
                "orcldasselfmodifiable",
            ],
        )

        # =====================================================================
        # ATTRIBUTE TRANSFORMATIONS (Python 3.13 Mapping)
        # =====================================================================

        # === ATTRIBUTE CASE MAPPING ===
        # lowercase source → proper OUD camelCase
        ATTRIBUTE_CASE_MAP: ClassVar[Mapping[str, str]] = {
            "uniquemember": "uniqueMember",
            "displayname": "displayName",
            "distinguishedname": "distinguishedName",
            FlextLdifConstants.DictKeys.OBJECTCLASS.lower(): (
                FlextLdifConstants.DictKeys.OBJECTCLASS
            ),
            "memberof": "memberOf",
            "seealsodescription": "seeAlsoDescription",
            "orclaci": ACL_ATTRIBUTE_NAME,  # Vendor-specific ACI → RFC ACI
            "orclentrylevelaci": ACL_ATTRIBUTE_NAME,  # Vendor entry-level ACI → RFC ACI
            "acl": ACL_ATTRIBUTE_NAME,  # Generic ACL → OUD RFC ACI
        }

        # === ATTRIBUTE NAME TRANSFORMATIONS ===
        # OUD→RFC attribute name transformations (for compatibility)
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

        # Categorization priority (standard RFC order)
        CATEGORIZATION_PRIORITY: ClassVar[list[str]] = [
            "users",  # User accounts first
            "hierarchy",  # Structural containers (ou, o, dc)
            "groups",  # Groups
            "acl",  # ACL entries
        ]

        # ObjectClasses for each category (RFC-compliant)
        CATEGORY_OBJECTCLASSES: ClassVar[dict[str, frozenset[str]]] = {
            "users": frozenset([
                "person",
                "inetOrgPerson",
                "organizationalPerson",
            ]),
            "hierarchy": frozenset([
                "organizationalUnit",
                "organization",
                "domain",
                "country",
                "locality",
            ]),
            "groups": frozenset([
                "groupOfNames",
                "groupOfUniqueNames",
            ]),
        }

        # OUD hierarchy priority (RFC standard containers)
        HIERARCHY_PRIORITY_OBJECTCLASSES: ClassVar[frozenset[str]] = frozenset([
            "organizationalUnit",
            "organization",
            "domain",
        ])

        # ACL attributes for OUD
        CATEGORIZATION_ACL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset([
            "aci",  # RFC 4876 ACI
        ])

        # =====================================================================
        # DETECTION PATTERNS - Server type detection rules
        # =====================================================================

        # === DN PREFIXES (used in Entry.can_handle) ===
        DN_PREFIX_CN_CONFIG: ClassVar[str] = "cn=config"
        DN_PREFIX_CN_SCHEMA: ClassVar[str] = "cn=schema"
        DN_PREFIX_CN_DIRECTORY: ClassVar[str] = "cn=directory"
        DN_PREFIX_CN_DS: ClassVar[str] = "cn=ds"

        # === DETECTION PATTERNS ===
        # Case-insensitive pattern ((?i) flag) because detector searches in
        # lowercase content
        DETECTION_OID_PATTERN: ClassVar[str] = (
            r"(?i)(ds-sync-|ds-pwp-|ds-cfg-|root dns)"
        )
        DETECTION_PATTERN: ClassVar[str] = (
            r"(?i)(ds-sync-|ds-pwp-|ds-cfg-|root dns)"  # Alias for compatibility
        )
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

        class AclPermission(StrEnum):
            """OUD-specific ACL permissions."""

            READ = "read"
            WRITE = "write"
            ADD = "add"
            DELETE = "delete"
            SEARCH = "search"
            COMPARE = "compare"
            AUTH = "auth"
            ALL = "all"
            NONE = "none"

        class AclAction(StrEnum):
            """OUD ACL action types."""

            ALLOW = "allow"
            DENY = "deny"

        class Encoding(StrEnum):
            """OUD-supported encodings."""

            UTF_8 = "utf-8"
            UTF_16 = "utf-16"
            ASCII = "ascii"
            LATIN_1 = "latin-1"
            ISO_8859_1 = "iso-8859-1"

    # =========================================================================
    # Server identification - accessed via Constants via properties in base.py
    # =========================================================================
    # NOTE: server_type and priority are accessed via properties in base.py
    # which read from Constants.SERVER_TYPE and Constants.PRIORITY

    # === PUBLIC INTERFACE FOR SCHEMA CONFIGURATION ===

    @classmethod
    def get_schema_filterable_fields(cls) -> frozenset[str]:
        """Get schema fields that support OID filtering.

        Returns:
            frozenset of schema field names (attributetypes, objectclasses, etc.)

        """
        return cls.Constants.SCHEMA_FILTERABLE_FIELDS

    @classmethod
    def get_schema_dn(cls) -> str:
        """Get the target schema DN for this server.

        Returns:
            Schema DN in OUD format (cn=schema)

        """
        return cls.Constants.SCHEMA_DN

    @classmethod
    def get_categorization_rules(cls) -> dict[str, list[str]]:
        """Get categorization rules for entry classification.

        Returns dict compatible with FlextLdif.migrate() categorization_rules parameter:
        - hierarchy_objectclasses: List of objectClasses for hierarchy entries
        - user_objectclasses: List of objectClasses for user entries
        - group_objectclasses: List of objectClasses for group entries
        - acl_attributes: List of ACL attribute names

        Returns:
            Dict with categorization rules for OUD server quirks

        """
        # Extract objectClasses from CATEGORY_OBJECTCLASSES dict
        category_ocs = cls.Constants.CATEGORY_OBJECTCLASSES
        hierarchy_ocs = list(category_ocs.get("hierarchy", frozenset()))
        user_ocs = list(cls.Constants.CATEGORY_OBJECTCLASSES.get("users", frozenset()))
        group_ocs = list(cls.Constants.CATEGORY_OBJECTCLASSES.get("groups", frozenset()))
        # Add hierarchy priority objectClasses (always hierarchy)
        hierarchy_ocs.extend(cls.Constants.HIERARCHY_PRIORITY_OBJECTCLASSES)
        # Remove duplicates while preserving order
        hierarchy_ocs = list(dict.fromkeys(hierarchy_ocs))
        acl_attrs = list(cls.Constants.CATEGORIZATION_ACL_ATTRIBUTES)

        return {
            "hierarchy_objectclasses": hierarchy_ocs,
            "user_objectclasses": user_ocs,
            "group_objectclasses": group_ocs,
            "acl_attributes": acl_attrs,
        }

    # =========================================================================
    # SHARED HELPER METHODS - Used by both Schema and Entry nested classes
    # =========================================================================

    @staticmethod
    def _build_oud_validation_rules() -> ValidationRulesDict:
        """Build OUD-specific validation rules dictionary.

        Returns:
            ValidationRulesDict with OUD-specific validation rules

        """
        server_type = FlextLdifConstants.ServerTypes.OUD
        return {
            "requires_objectclass": (
                server_type
                in FlextLdifConstants.ServerValidationRules.OBJECTCLASS_REQUIRED_SERVERS
            ),
            "requires_naming_attr": (
                server_type
                in FlextLdifConstants.ServerValidationRules.NAMING_ATTR_REQUIRED_SERVERS
            ),
            "requires_binary_option": (
                server_type
                in FlextLdifConstants.ServerValidationRules.BINARY_OPTION_REQUIRED_SERVERS
            ),
            "encoding_rules": {
                "default_encoding": "utf-8",
                "allowed_encodings": ["utf-8", "utf-16", "ascii"],
            },
            "dn_case_rules": {
                "preserve_case": False,
                "normalize_to": "lowercase",
            },
            "acl_format_rules": {
                "format": "aci",
                "attribute_name": "aci",
                "requires_target": True,
                "requires_subject": True,
            },
            "track_deletions": True,
            "track_modifications": True,
            "track_conversions": True,
        }

    @staticmethod
    def _inject_validation_rules_static(
        entry: FlextLdifModels.Entry,
    ) -> FlextLdifModels.Entry:
        """Inject OUD-specific validation rules into Entry metadata.

        Args:
            entry: Entry to inject validation rules into

        Returns:
            Entry with validation_rules in metadata.extensions

        """
        validation_rules = FlextLdifServersOud._build_oud_validation_rules()

        if entry.metadata is None:
            entry = entry.model_copy(
                update={
                    "metadata": FlextLdifModels.QuirkMetadata.create_for(
                        FlextLdifConstants.ServerTypes.OUD,
                        extensions={},
                    ),
                },
            )

        entry.metadata.extensions["validation_rules"] = validation_rules

        dn_case_rules = cast("dict[str, object]", validation_rules["dn_case_rules"])
        dn_normalize = dn_case_rules["normalize_to"]

        logger.debug(
            "Injected OUD validation rules into Entry metadata",
            entry_dn=entry.dn.value if entry.dn else None,
            dn_normalize=dn_normalize,
            requires_objectclass=validation_rules["requires_objectclass"],
            requires_naming_attr=validation_rules["requires_naming_attr"],
        )

        return entry

    @staticmethod
    def _correct_rfc_syntax_in_attributes_static(
        attrs_dict: dict[str, object],
    ) -> FlextResult[dict[str, object]]:
        """Correct RFC syntax issues in attribute values (syntax only, not structure).

        Args:
            attrs_dict: Dictionary of attributes to correct

        Returns:
            FlextResult with corrected_attributes and syntax_corrections list

        """
        corrected_attributes: dict[str, list[str]] = {}
        syntax_corrections: list[str] = []

        for attr_name, attr_values in attrs_dict.items():
            # Convert to list[str] - handle bytes conversion
            values_list: list[str]
            if isinstance(attr_values, list):
                values_list = [
                    v.decode("utf-8", errors="replace")
                    if isinstance(v, bytes)
                    else str(v)
                    for v in attr_values
                ]
            elif isinstance(attr_values, bytes):
                values_list = [attr_values.decode("utf-8", errors="replace")]
            else:
                values_list = [str(attr_values)]

            corrected_values: list[str] = []

            for value in values_list:
                if not isinstance(value, str):
                    str_value = str(value)
                    corrected_values.append(str_value)
                    if value != str_value:
                        syntax_corrections.append(
                            f"Converted {attr_name} value to string",
                        )
                    continue

                # Ensure valid UTF-8 encoding (RFC 2849 requirement)
                try:
                    value.encode("utf-8")
                    corrected_values.append(value)
                except UnicodeEncodeError:
                    corrected_value = value.encode(
                        "utf-8",
                        errors="replace",
                    ).decode("utf-8", errors="replace")
                    corrected_values.append(corrected_value)
                    syntax_corrections.append(
                        f"Fixed UTF-8 encoding for {attr_name}",
                    )
                    logger.debug(
                        "OUD quirks: Corrected invalid UTF-8 in attribute",
                        attribute_name=attr_name,
                        original_value_preview=value[:FlextLdifServersOud.Constants.MAX_LOG_LINE_LENGTH]
                        if len(value) > FlextLdifServersOud.Constants.MAX_LOG_LINE_LENGTH
                        else value,
                        corrected_value_preview=corrected_value[:FlextLdifServersOud.Constants.MAX_LOG_LINE_LENGTH]
                        if len(corrected_value) > FlextLdifServersOud.Constants.MAX_LOG_LINE_LENGTH
                        else corrected_value,
                        value_length=len(value),
                        correction_type="utf8_encoding_fix",
                    )

            corrected_attributes[attr_name] = corrected_values

        result_dict: dict[str, object] = {
            "corrected_attributes": corrected_attributes,
            "syntax_corrections": syntax_corrections,
        }
        return FlextResult[dict[str, object]].ok(result_dict)

    @staticmethod
    def _get_oud_schema_quirk(parent_quirk: object | None) -> object:
        """Get OUD schema_quirk from parent or create new instance.

        Extracted helper to reduce complexity of _write_entry_modify_add_format_helper.

        Args:
            parent_quirk: Optional parent quirk instance

        Returns:
            OUD schema_quirk instance with write_attribute/write_objectclass methods

        """
        if parent_quirk and isinstance(parent_quirk, FlextLdifServersOud):
            return parent_quirk.schema_quirk
        return FlextLdifServersOud().schema_quirk

    @staticmethod
    def _process_attribute_type_value(
        value_to_parse: str,
        parent_quirk: object | None,
    ) -> FlextResult[str]:
        """Process and transform attributeTypes schema value.

        Simplified: Parse with OID quirks, write with OUD quirks.
        Transformation logic is handled by _transform_attribute_for_write hook.

        Args:
            value_to_parse: Attribute definition string to process
            parent_quirk: Optional parent quirk for accessing schema_quirk

        Returns:
            FlextResult with transformed attribute value

        """
        # Parse as attribute using OID quirks
        oid_quirk = FlextLdifServersOid()
        parse_result = oid_quirk.schema_quirk.parse_attribute(value_to_parse)

        if not parse_result.is_success:
            return FlextResult[str].fail(
                f"Failed to parse attribute: {parse_result.error}"
            )

        attr_model = parse_result.unwrap()

        # Write using OUD quirks - transformations applied automatically by _transform_attribute_for_write hook
        oud_schema_quirk = FlextLdifServersOud._get_oud_schema_quirk(parent_quirk)
        write_result = oud_schema_quirk.write_attribute(attr_model)  # type: ignore[attr-defined]

        if not write_result.is_success:
            return FlextResult[str].fail(
                f"Failed to write attribute: {write_result.error}"
            )

        return FlextResult[str].ok(write_result.unwrap())

    @staticmethod
    def _process_object_class_value(
        value_to_parse: str,
        parent_quirk: object | None,
    ) -> FlextResult[str]:
        """Process and transform objectClasses schema value.

        Simplified: Parse with OID quirks, write with OUD quirks.
        Transformation logic is handled by _transform_objectclass_for_write hook.

        Args:
            value_to_parse: ObjectClass definition string to process
            parent_quirk: Optional parent quirk for accessing schema_quirk

        Returns:
            FlextResult with transformed objectClass value

        """
        # Parse as objectClass using OID quirks
        oid_quirk = FlextLdifServersOid()
        parse_result = oid_quirk.schema_quirk.parse_objectclass(value_to_parse)

        if not parse_result.is_success:
            return FlextResult[str].fail(
                f"Failed to parse objectClass: {parse_result.error}"
            )

        oc_model = parse_result.unwrap()

        # Write using OUD quirks - transformations applied automatically by _transform_objectclass_for_write hook
        oud_schema_quirk = FlextLdifServersOud._get_oud_schema_quirk(parent_quirk)
        write_result = oud_schema_quirk.write_objectclass(oc_model)  # type: ignore[attr-defined]

        if not write_result.is_success:
            return FlextResult[str].fail(
                f"Failed to write objectClass: {write_result.error}"
            )

        return FlextResult[str].ok(write_result.unwrap())

    @staticmethod
    def _process_single_schema_value(
        value: str,
        schema_type: str,
        entry_dn: str,
        parent_quirk: object | None,
    ) -> FlextResult[str]:
        """Process a single schema value and return its LDIF entry.

        Args:
            value: Schema definition string
            schema_type: Type of schema (attributeTypes, objectClasses, etc.)
            entry_dn: DN for the entry
            parent_quirk: Optional parent quirk for accessing schema_quirk

        Returns:
            FlextResult with single LDIF entry string

        """
        # Remove attribute prefix if present
        value_to_parse = value.strip()
        for prefix in ("attributeTypes:", "objectClasses:"):
            if value_to_parse.startswith(prefix):
                value_to_parse = value_to_parse[len(prefix) :].strip()
                break

        # Process based on schema type - transformations applied by hooks
        schema_type_lower = schema_type.lower()
        if schema_type_lower == "attributetypes":
            result = FlextLdifServersOud._process_attribute_type_value(
                value_to_parse,
                parent_quirk,
            )
        elif schema_type_lower == "objectclasses":
            result = FlextLdifServersOud._process_object_class_value(
                value_to_parse,
                parent_quirk,
            )
        else:
            # For other schema types, use original cleaning
            cleaned = FlextLdifServersOud.Schema.clean_syntax_quotes(value)
            cleaned_value = cleaned.decode("utf-8") if isinstance(cleaned, bytes) else cleaned
            return FlextResult[str].ok(
                FlextLdifUtilities.Writer.format_schema_modify_entry(
                    entry_dn,
                    schema_type,
                    cleaned_value,
                ),
            )

        if not result.is_success:
            return result

        return FlextResult[str].ok(
            FlextLdifUtilities.Writer.format_schema_modify_entry(
                entry_dn,
                schema_type,
                result.unwrap(),
            ),
        )

    @staticmethod
    def _add_ldif_block_static(
        ldif_lines: list[str],
        schema_type: str,
        value: str | bytes,
        *,
        is_first_block: bool,
    ) -> bool:
        """Add a single LDIF block for schema value - static helper.

        Args:
            ldif_lines: List to append LDIF lines to
            schema_type: Schema type (attributeTypes, objectClasses, etc.)
            value: Schema value (string or bytes)
            is_first_block: Whether this is the first block

        Returns:
            False (next block won't be first)

        """
        # Add separator before block (not before first)
        if not is_first_block:
            ldif_lines.append("-")

        # Add directive
        ldif_lines.append(f"add: {schema_type}")

        # Value (already in RFC format)
        if isinstance(value, bytes):
            encoded_value = base64.b64encode(value).decode("ascii")
            ldif_lines.append(f"{schema_type}:: {encoded_value}")
        else:
            ldif_lines.append(f"{schema_type}: {value}")

        return False  # Next block won't be first

    @staticmethod
    def _validate_aci_macros_static(aci_value: str) -> FlextResult[bool]:
        """Validate OUD ACI macro consistency rules - static helper.

        OUD supports macro substitution in ACIs:
        - ($dn): matches substring in target, replaces in subject
        - [$dn]: hierarchical substitution in subject (drops leftmost RDN)
        - ($attr.attrName): substitutes attribute value from target entry

        Validation rules (must fail if violated):
        1. If ($dn) in subject -> ($dn) must be in target
        2. If [$dn] in subject -> ($dn) must be in target
        3. After expansion, DN must be syntactically valid

        Args:
            aci_value: Single ACI string value

        Returns:
            FlextResult[bool] - True if valid, fails with error if macro rules violated

        """
        # Check for macros in subject (userdn/groupdn/userattr)
        has_macro_in_subject = bool(
            re.search(r"\(\$dn\)|\[\$dn\]|\(\$attr\.", aci_value),
        )

        if not has_macro_in_subject:
            # No macros - validation passes
            return FlextResult[bool].ok(True)

        # If macros in subject, target MUST have ($dn)
        has_macro_in_target = "($dn)" in aci_value

        if not has_macro_in_target:
            return FlextResult[bool].fail(
                "ACI macro in subject requires ($dn) in target expression",
            )

        # Both ($dn) and [$dn] require ($dn) in target - already checked above
        logger.debug(
            "ACI macro validation passed: subject/target macro consistency OK",
            aci_preview=aci_value[:200] if len(aci_value) > 200 else aci_value,
            validation_type="macro_consistency",
        )
        return FlextResult[bool].ok(True)

    @staticmethod
    def _separate_acl_attributes_static(
        attrs_dict: dict[str, list[str]],
        acl_attr_names: frozenset[str],
    ) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
        """Separate ACL attributes from regular attributes - static helper.

        Args:
            attrs_dict: Dictionary of attributes
            acl_attr_names: Set of ACL attribute names

        Returns:
            Tuple of (acl_attrs, remaining_attrs)

        """
        acl_attrs: dict[str, list[str]] = {}
        remaining_attrs: dict[str, list[str]] = {}
        acl_lower = {name.lower() for name in acl_attr_names}

        for attr_name, values in attrs_dict.items():
            if attr_name.lower() in acl_lower:
                acl_attrs[attr_name] = values
            else:
                remaining_attrs[attr_name] = values

        return acl_attrs, remaining_attrs

    @staticmethod
    def _resolve_acl_original_names_static(
        entry_data: FlextLdifModels.Entry,
        acl_attrs: dict[str, list[str]],
    ) -> dict[str, list[str]]:
        """Resolve original ACL attribute names from metadata transformations - static helper.

        Args:
            entry_data: Entry with metadata
            acl_attrs: ACL attributes dict

        Returns:
            Original ACL attribute names dict

        """
        if not (entry_data.metadata and entry_data.metadata.extensions):
            return acl_attrs

        transformations = entry_data.metadata.extensions.get("acl_transformations")
        if not transformations or not isinstance(transformations, dict):
            return acl_attrs

        # transformations is dict[str, AttributeTransformation]
        # Key is original_name, value has original_values
        original_names: dict[str, list[str]] = {}
        for orig_name, transformation in transformations.items():
            if isinstance(transformation, dict):
                # AttributeTransformation serialized as dict
                original_names[orig_name] = transformation.get(
                    "original_values",
                    [],
                )
            elif hasattr(transformation, "original_values"):
                # AttributeTransformation object
                original_names[orig_name] = transformation.original_values

        # Validate original_names - use acl_attrs if empty
        if not original_names:
            return acl_attrs
        return original_names

    @staticmethod
    def _create_entry_metadata_with_acl_comments_static(
        entry_metadata: dict[str, object] | None,
        acl_attrs: dict[str, list[str]],
    ) -> dict[str, object]:
        """Create entry metadata with ACL attributes marked for commenting - static helper.

        Args:
            entry_metadata: Existing metadata dict or None
            acl_attrs: ACL attributes to mark for commenting

        Returns:
            New metadata dict with ACL attributes marked

        """
        # Validate entry_metadata - use empty dict if None
        if entry_metadata is None:
            new_metadata: dict[str, object] = {}
        else:
            new_metadata = dict(entry_metadata)
        removed_attrs = new_metadata.get(
            MetaKeys.REMOVED_ATTRIBUTES_WITH_VALUES,
            {},
        )

        if isinstance(removed_attrs, dict):
            removed_attrs.update(acl_attrs)
        else:
            removed_attrs = acl_attrs

        new_metadata[MetaKeys.REMOVED_ATTRIBUTES_WITH_VALUES] = removed_attrs
        return new_metadata

    @staticmethod
    def _create_entry_with_acl_comments_static(
        entry_data: FlextLdifModels.Entry,
        remaining_attrs: dict[str, list[str]],
        new_entry_metadata: dict[str, object],
    ) -> FlextLdifModels.Entry:
        """Create new entry with ACL attributes moved to metadata - static helper.

        Args:
            entry_data: Original entry
            remaining_attrs: Attributes without ACL attributes
            new_entry_metadata: Metadata with ACL attributes marked

        Returns:
            New Entry with ACL attributes moved to metadata

        """
        if entry_data.dn is None:
            return entry_data

        new_entry_result = FlextLdifModels.Entry.create(
            dn=entry_data.dn.value,
            attributes=cast("dict[str, list[str] | str]", remaining_attrs),
            metadata=entry_data.metadata,
            entry_metadata=new_entry_metadata,
        )

        if new_entry_result.is_success:
            return cast("FlextLdifModels.Entry", new_entry_result.unwrap())
        return entry_data

    @staticmethod
    def _comment_acl_attributes_static(
        entry_data: FlextLdifModels.Entry,
        acl_attr_names: frozenset[str],
    ) -> FlextLdifModels.Entry:
        """Move ACL attributes to metadata (RFC will comment them) - static helper.

        Args:
            entry_data: Entry to process
            acl_attr_names: Set of ACL attribute names to comment

        Returns:
            New Entry with ACL attributes moved to metadata

        """
        if not entry_data.attributes:
            return entry_data

        acl_attrs, remaining_attrs = FlextLdifServersOud._separate_acl_attributes_static(
            entry_data.attributes.attributes,
            acl_attr_names,
        )

        if not acl_attrs:
            return entry_data

        final_acl_attrs = FlextLdifServersOud._resolve_acl_original_names_static(
            entry_data,
            acl_attrs,
        )
        new_entry_metadata = FlextLdifServersOud._create_entry_metadata_with_acl_comments_static(
            entry_data.metadata.write_options if entry_data.metadata else None,
            final_acl_attrs,
        )

        return FlextLdifServersOud._create_entry_with_acl_comments_static(
            entry_data,
            remaining_attrs,
            new_entry_metadata,
        )

    @staticmethod
    def _write_entry_modify_add_format_helper(
        entry_data: FlextLdifModels.Entry,
        allowed_schema_oids: frozenset[str] | None = None,
        parent_quirk: object | None = None,
    ) -> FlextResult[str]:
        """Write schema entry in OUD modify-add format.

        Generates LDIF with ONE modify operation PER schema element.
        Each schema value gets its OWN complete entry, ordered by OID numerically.

        Args:
            entry_data: Schema entry to write
            allowed_schema_oids: Optional set of allowed OIDs for filtering
            parent_quirk: Optional parent quirk instance for accessing schema_quirk

        Returns:
            FlextResult with LDIF string (multiple entries, one per schema element)

        """
        if not (entry_data.dn and entry_data.dn.value):
            return FlextResult[str].fail("Entry DN is required for LDIF output")

        if not entry_data.attributes or not entry_data.attributes.attributes:
            return FlextResult[str].ok(
                f"dn: {entry_data.dn.value}\nchangetype: modify\n\n",
            )

        attrs_dict = entry_data.attributes.attributes
        allowed_oids = set(allowed_schema_oids) if allowed_schema_oids else None
        oid_pattern = re.compile(r"\(\s*(\d+(?:\.\d+)*)\s+")

        # Process schema types in order (matchingRules/matchingRuleUse excluded)
        schema_types = ["attributeTypes", "objectClasses"]
        all_entries: list[str] = []

        for schema_type in schema_types:
            attr_key = next(
                (key for key in attrs_dict if key.lower() == schema_type.lower()),
                None,
            )

            if not attr_key or not attrs_dict[attr_key]:
                continue

            filtered_values = FlextLdifUtilities.OID.filter_and_sort_by_oid(
                attrs_dict[attr_key],
                allowed_oids=allowed_oids,
                oid_pattern=oid_pattern,
            )

            for _oid, value in filtered_values:
                result = FlextLdifServersOud._process_single_schema_value(
                    value,
                    schema_type,
                    entry_data.dn.value,
                    parent_quirk,
                )
                if not result.is_success:
                    return result
                all_entries.append(result.unwrap())

        if not all_entries:
            return FlextResult[str].ok(
                f"dn: {entry_data.dn.value}\nchangetype: modify\n\n",
            )

        ldif_text = "\n".join(all_entries)
        return FlextResult[str].ok(
            ldif_text if ldif_text.endswith("\n") else f"{ldif_text}\n",
        )

    class Schema(FlextLdifServersRfc.Schema):
        """Oracle OUD schema quirk - implements FlextLdifProtocols.Quirks.SchemaProtocol.

        Extends RFC 4512 schema parsing with Oracle OUD-specific features:
        - OUD namespace (2.16.840.1.113894.*)
        - OUD-specific syntaxes
        - OUD attribute extensions
        - Compatibility with vendor-specific schemas
        - DN case registry management for schema consistency

        **Protocol Compliance**: Fully implements
        FlextLdifProtocols.Quirks.SchemaProtocol through structural typing.
        All methods match protocol signatures exactly for type safety.

        **Validation**: Verify protocol compliance with:
            from flext_ldif.protocols import FlextLdifProtocols
            quirk = FlextLdifServersOud()
            # Protocol compliance verified via structural typing
            if not isinstance(quirk, FlextLdifProtocols.Quirks.SchemaProtocol):
                raise TypeError("Quirk does not satisfy SchemaProtocol")

        Example:
            quirk = FlextLdifServersOud()
            if quirk.schema.can_handle_attribute(attr_def):
                result = quirk.schema.parse(attr_def)
                if result.is_success:
                    parsed_attr = result.unwrap()

        """

        def __init__(self, **kwargs: object) -> None:
            """Initialize OUD schema quirk.

            OUD extends RFC baseline with Oracle-specific enhancements.

            Args:
                **kwargs: Passed to parent for compatibility (ignored)

            """
            super().__init__(**kwargs)

        def _hook_post_parse_attribute(
            self,
            attr: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Hook: Validate OUD-specific attribute features after parsing.

            OUD supports extensions beyond RFC 4512:
            - Non-numeric OIDs: ending with `-oid` suffix (e.g., `1.2.3-oid`)
            - X-* extensions: X-PATTERN, X-ENUM, X-SUBST, X-APPROX,
              X-ORIGIN, X-SCHEMA-FILE
            - DN normalization for distinguishedName syntax attributes

            Validation rules (fail if violated):
            1. OIDs must be numeric or end with `-oid` suffix
            2. X-* extensions must be well-formed
            3. SYNTAX must reference valid OID

            Args:
                attr: Parsed SchemaAttribute from RFC parser

            Returns:
                FlextResult[SchemaAttribute] - validated attribute

            """
            if not attr or not attr.oid:
                return FlextResult[FlextLdifModels.SchemaAttribute].ok(attr)

            oid = str(attr.oid)

            # Validate OID format: numeric or ending in -oid (OUD extension)
            if not oid.replace(".", "").replace("-", "").isalnum():
                return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                    f"Invalid OUD OID format: {oid} (must be numeric or end with -oid)",
                )

            # Log if OUD-specific X-* extensions detected
            oud_extensions = []
            if attr.x_origin:
                oud_extensions.append("X-ORIGIN")
            if attr.x_file_ref:
                oud_extensions.append("X-FILE-REF")
            if attr.x_name:
                oud_extensions.append("X-NAME")
            if attr.x_alias:
                oud_extensions.append("X-ALIAS")
            if attr.x_oid:
                oud_extensions.append("X-OID")

            if oud_extensions:
                logger.debug(
                    "Attribute has OUD X-* extensions",
                    attribute_name=attr.name,
                    attribute_oid=attr.oid,
                    extensions=oud_extensions,
                    extension_count=len(oud_extensions),
                )

            return FlextResult[FlextLdifModels.SchemaAttribute].ok(attr)

        def _hook_post_parse_objectclass(
            self,
            oc: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Hook: Validate OUD-specific objectClass features after parsing.

            OUD has specific constraints different from RFC:
            - SingleSUP: Only ONE superior class allowed (RFC allows
              multiple via $)
            - X-* extensions: X-ENUM, X-PATTERN, X-ORIGIN, X-SCHEMA-FILE
            - No multiple structural chains (enforced separately by config)

            Validation rules (fail if violated):
            1. SUP must be single (not multiple separated by $)
            2. X-* extensions must be well-formed
            3. MUST/MAY attributes must exist in schema (done in
               validate_objectclass_dependencies)

            Args:
                oc: Parsed SchemaObjectClass from RFC parser

            Returns:
                FlextResult[SchemaObjectClass] - validated objectClass

            """
            if not oc:
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    "ObjectClass is None or empty",
                )

            # Validate SingleSUP constraint (OUD restriction)
            sup = oc.sup
            if sup:
                sup_str = str(sup)
                # Check for multiple SUPs (RFC uses $ as separator)
                if "$" in sup_str:
                    return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                        f"OUD objectClass '{oc.name}' has multiple SUPs: "
                        f"{sup_str}. "
                        "OUD only allows single SUP (use AUXILIARY classes "
                        "for additional features).",
                    )

            # ObjectClass doesn't have X-* extension fields in model
            # Log just the validation success
            logger.debug(
                "ObjectClass validated: SingleSUP constraint OK",
                objectclass_name=oc.name,
                objectclass_oid=oc.oid,
                sup_value=oc.sup,
            )

            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(oc)

        def _parse_attribute(
            self,
            attr_definition: str,
            *,
            case_insensitive: bool = False,
            allow_syntax_quotes: bool = False,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse Oracle OUD attribute definition (implements abstract method from base.py).

            Override RFC implementation to use OUD-specific parser settings.
            This method is called by base.py's parse_attribute() public method.

            Flow:
            1. Call RFC parser for baseline parsing
            2. Call _hook_post_parse_attribute() for OUD-specific validation
            3. Return result

            Args:
                attr_definition: AttributeType definition string
                case_insensitive: Ignored - OUD uses strict RFC-compliant NAME matching
                allow_syntax_quotes: Ignored - OUD uses standard SYNTAX format

            Returns:
                FlextResult with parsed SchemaAttribute model

            """
            try:
                # Step 1: Call parent RFC parser with OUD-specific settings
                # Pass parameters through for API consistency, even though OUD doesn't use them
                attr_result = super()._parse_attribute(
                    attr_definition,
                    case_insensitive=case_insensitive,  # Pass through for API consistency
                    allow_syntax_quotes=allow_syntax_quotes,  # Pass through for API consistency
                )

                if attr_result.is_failure:
                    return attr_result

                # Step 2: Apply post-parse hook for OUD-specific validation
                attr = attr_result.unwrap()
                return self._hook_post_parse_attribute(attr)

            except Exception as e:
                return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                    f"OUD attribute parsing failed: {e}",
                )

        def _parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse Oracle OUD objectClass definition (implements abstract method from base.py).

            Override RFC implementation to use OUD-specific parser settings.
            This method is called by base.py's parse_objectclass() public method.

            Flow:
            1. Call RFC parser for baseline parsing
            2. Call _hook_post_parse_objectclass() for OUD-specific validation
            3. Return result

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                FlextResult with parsed SchemaObjectClass model

            """
            try:
                # Step 1: Call parent RFC parser for objectClass parsing
                # OUD uses strict RFC-compliant parsing at the objectClass level
                oc_result = super()._parse_objectclass(oc_definition)

                if oc_result.is_failure:
                    return oc_result

                # Step 2: Apply post-parse hook for OUD-specific validation
                oc = oc_result.unwrap()
                return self._hook_post_parse_objectclass(oc)

            except Exception as e:
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    f"OUD objectClass parsing failed: {e}",
                )

        def validate_objectclass_dependencies(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
            available_attributes: set[str],
        ) -> FlextResult[bool]:
            """Validate that all MUST and MAY attributes for objectclass exist in schema.

            Checks if all required (MUST) and optional (MAY) attributes referenced by an
            objectclass definition are available in the provided set of available attributes.
            This prevents schema corruption when objectclasses with missing attributes are
            loaded into OUD.

            CRITICAL: Also validates attributes from parent objectclasses (SUP) to ensure
            inheritance chains are valid.

            Args:
                oc_data: Parsed objectclass Pydantic model with must, may fields
                available_attributes: Set of attribute names (lowercase) in current schema

            Returns:
                FlextResult[bool]:
                    - True if all attributes are available or no attributes required
                    - False if any MUST/MAY attribute is missing

            Example:
                >>> oc_data = FlextLdifModels.SchemaObjectClass(
                ...     oid="1.2.3.4",
                ...     name="orclDbServer",
                ...     must=[],
                ...     may=["orclREDACTED_LDAP_BIND_PASSWORDprivilege"],
                ... )
                >>> available = {"cn", "description"}  # orclREDACTED_LDAP_BIND_PASSWORDprivilege missing!
                >>> result = quirk.validate_objectclass_dependencies(oc_data, available)
                >>> # result.is_success and not result.unwrap() → False (missing attribute)

            """
            # Validate required fields - no fallbacks
            if not oc_data.name:
                return FlextResult[bool].fail(
                    "ObjectClass name is required for validation",
                )
            if not oc_data.oid:
                return FlextResult[bool].fail(
                    "ObjectClass OID is required for validation",
                )
            oc_name = str(oc_data.name)
            oc_oid = str(oc_data.oid)
            missing_attrs: list[str] = []

            # PHASE 1: Check MUST attributes (required - failure if missing)
            must_attrs = oc_data.must
            if must_attrs:
                must_list: list[str] = (
                    must_attrs if isinstance(must_attrs, list) else [str(must_attrs)]
                )
                missing_attrs.extend(
                    [
                        str(attr)
                        for attr in must_list
                        if not FlextLdifUtilities.Schema.is_attribute_in_list(
                            str(attr),
                            available_attributes,
                        )
                    ],
                )

            # PHASE 2: Check MAY attributes (optional - failure if missing)
            # CRITICAL FIX: MAY attributes MUST also be present in schema
            # Missing MAY attributes cause: "No attribute type matching this name or OID exists"
            may_attrs = oc_data.may
            if may_attrs:
                may_list: list[str] = (
                    may_attrs if isinstance(may_attrs, list) else [str(may_attrs)]
                )
                missing_attrs.extend(
                    [
                        str(attr)
                        for attr in may_list
                        if not FlextLdifUtilities.Schema.is_attribute_in_list(
                            str(attr),
                            available_attributes,
                        )
                    ],
                )

            # Report validation failure if any attributes missing
            if missing_attrs:
                logger.warning(
                    "ObjectClass has unresolved attributes (MUST/MAY) - will be filtered out",
                    objectclass_name=oc_name,
                    objectclass_oid=oc_oid,
                    missing_attributes=missing_attrs,
                    missing_count=len(missing_attrs),
                    must_attributes=must_attrs or None,
                    may_attributes=may_attrs or None,
                    reason="No attribute type matching this name or OID exists in the server schema - prevents OUD startup failure",
                )
                return FlextResult[bool].ok(False)

            # All MUST and MAY attributes are available
            return FlextResult[bool].ok(True)

        def _transform_attribute_for_write(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextLdifModels.SchemaAttribute:
            """Apply OUD-specific attribute transformations before writing.

            Implements hook from RFC base to apply OUD quirks:
            - Validate matching rules are RFC-compliant
            - Correct invalid SUBSTR rules
            - Track boolean attributes for special handling
            - Preserve OUD-specific extensions

            Args:
                attr_data: Parsed SchemaAttribute model

            Returns:
                Transformed SchemaAttribute with OUD-specific fixes applied

            """
            # Normalize name if present
            fixed_name = attr_data.name

            # Validate and enhance matching rules for OUD compatibility
            fixed_equality = attr_data.equality
            fixed_substr = attr_data.substr

            # UNCONDITIONAL INFO log to verify this method is ALWAYS being called
            logger.info(
                "OUD _transform_attribute_for_write CALLED",
                extra={
                    "attr_name": fixed_name,
                    "original_equality": fixed_equality,
                    "original_substr": fixed_substr,
                },
            )

            # OUD QUIRK: caseIgnoreSubstringsMatch must be SUBSTR, not EQUALITY
            # If equality is caseIgnoreSubstringsMatch, move it to substr
            if fixed_equality == "caseIgnoreSubstringsMatch":
                logger.debug(
                    "Moving caseIgnoreSubstringsMatch from EQUALITY to SUBSTR for OUD compatibility",
                    attribute_name=attr_data.name,
                    attribute_oid=attr_data.oid,
                    original_equality=fixed_equality,
                    original_substr=attr_data.substr,
                    new_substr="caseIgnoreSubstringsMatch",
                    new_equality=None,
                )
                fixed_substr = "caseIgnoreSubstringsMatch"
                fixed_equality = None  # Remove from equality - must be explicitly None, not empty string

            # OUD QUIRK: Remove redundant EQUALITY when SUBSTR is caseIgnoreSubstringsMatch
            # OUD rejects: EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch
            # OUD accepts: SUBSTR caseIgnoreSubstringsMatch (EQUALITY removed)
            # This affects 135 attributes exported by OID with redundant matching rules
            if (
                fixed_substr == "caseIgnoreSubstringsMatch"
                and fixed_equality == "caseIgnoreMatch"
            ):
                logger.info(
                    "OUD QUIRK: FOUND REDUNDANT EQUALITY+SUBSTR - Removing redundant EQUALITY",
                    attribute_name=fixed_name,
                    attribute_oid=attr_data.oid,
                    redundant_equality="caseIgnoreMatch",
                    substr_rule="caseIgnoreSubstringsMatch",
                    action="removed_redundant_equality",
                    reason="OUD rejects EQUALITY caseIgnoreMatch when SUBSTR caseIgnoreSubstringsMatch is present",
                )
                fixed_equality = None  # Remove redundant EQUALITY

            # Check for invalid SUBSTR rules and apply INVALID_SUBSTR_RULES mappings
            invalid_substr_rules = FlextLdifServersOud.Constants.INVALID_SUBSTR_RULES
            if fixed_substr and fixed_substr in invalid_substr_rules:
                replacement = invalid_substr_rules[fixed_substr]
                if replacement is not None:
                    logger.debug(
                        "Replacing invalid SUBSTR rule",
                        attribute_name=attr_data.name,
                        attribute_oid=attr_data.oid,
                        original_substr=fixed_substr,
                        replacement_substr=replacement,
                        equality_rule=fixed_equality,
                    )
                    fixed_substr = replacement

            # Check if this is a boolean attribute for special handling during write
            is_boolean = FlextLdifUtilities.Schema.is_boolean_attribute(
                fixed_name,
                set(FlextLdifServersOud.Constants.BOOLEAN_ATTRIBUTES),
            )
            if is_boolean:
                logger.debug(
                    "Identified boolean attribute",
                    attribute_name=fixed_name,
                    attribute_oid=attr_data.oid,
                    original_name=attr_data.name
                    if attr_data.name != fixed_name
                    else None,
                )

            # Create modified copy with fixed values using Pydantic v2 pattern
            return attr_data.model_copy(
                update={
                    "name": fixed_name,
                    "equality": fixed_equality,
                    "substr": fixed_substr,
                },
            )

        def _write_attribute(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[str]:
            """Write attribute with OUD-specific transformations applied.

            Overrides RFC implementation to ensure OUD quirks are applied even when
            original_format is present in metadata. This is critical for fixing
            issues like EQUALITY caseIgnoreSubstringsMatch → SUBSTR caseIgnoreSubstringsMatch.

            Args:
                attr_data: SchemaAttribute model

            Returns:
                FlextResult with OUD-compatible attribute string

            """
            # Always apply OUD transformations first, even if original_format exists
            # This ensures OUD-specific fixes (like EQUALITY→SUBSTR conversion) are applied
            transformed_attr = self._transform_attribute_for_write(attr_data)

            # Remove original_format from metadata to force writing from transformed model
            # The model is already correct (transformed during OID parse), so we don't need original_format
            # This prevents RFC base from using the incorrect original_format
            if transformed_attr.metadata and transformed_attr.metadata.extensions.get(
                "original_format",
            ):
                # Create new extensions dict without original_format
                new_extensions = {
                    k: v
                    for k, v in transformed_attr.metadata.extensions.items()
                    if k != "original_format"
                }
                # Create new metadata without original_format using model_copy
                new_metadata = transformed_attr.metadata.model_copy(
                    update={"extensions": new_extensions},
                )
                # Create new attribute model without original_format in metadata
                transformed_attr = transformed_attr.model_copy(
                    update={"metadata": new_metadata},
                )

            # Always write from transformed model to ensure OUD quirks are applied
            # This ensures EQUALITY→SUBSTR conversion and other OUD fixes are always applied
            return super()._write_attribute(transformed_attr)

        def _write_objectclass(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[str]:
            """Write objectClass with OUD-specific transformations applied.

            Overrides RFC implementation to ensure OUD quirks are applied even when
            original_format is present in metadata. This fixes:
            - SUP ( top ) → SUP top (remove parentheses)
            - SUP 'top' → SUP top (remove quotes)
            - AUXILLARY → AUXILIARY (fix typo)

            Args:
                oc_data: SchemaObjectClass model

            Returns:
                FlextResult with OUD-compatible objectClass string

            """
            # Always apply OUD transformations first
            transformed_oc = self._transform_objectclass_for_write(oc_data)

            # Remove original_format from metadata to force writing from transformed model
            # The model is already correct (transformed during OID parse), so we don't need original_format
            # This prevents RFC base from using the incorrect original_format
            if transformed_oc.metadata and transformed_oc.metadata.extensions.get(
                "original_format",
            ):
                # Create new extensions dict without original_format
                new_extensions = {
                    k: v
                    for k, v in transformed_oc.metadata.extensions.items()
                    if k != "original_format"
                }
                # Create new metadata without original_format using model_copy
                new_metadata = transformed_oc.metadata.model_copy(
                    update={"extensions": new_extensions},
                )
                # Create new objectClass model without original_format in metadata
                transformed_oc = transformed_oc.model_copy(
                    update={"metadata": new_metadata},
                )

            # Always write from transformed model to ensure OUD quirks are applied
            # This ensures SUP ( top ) → SUP top, SUP 'top' → SUP top, AUXILLARY → AUXILIARY fixes
            return super()._write_objectclass(transformed_oc)

        def extract_schemas_from_ldif(
            self,
            ldif_content: str,
            *,
            validate_dependencies: bool = True,  # OUD defaults to True (needs validation)
        ) -> FlextResult[dict[str, object]]:
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

        @staticmethod
        def clean_syntax_quotes(value: str | bytes) -> str | bytes:
            """OUD QUIRK: Remove quotes from SYNTAX OID in schema definitions.

            RFC 4512 § 4.1.2: SYNTAX OID must NOT be quoted.
            OID server exports: SYNTAX '1.3.6.1.4.1.1466.115.121.1.7' (invalid)
            OUD requires: SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 (valid)

            Args:
                value: Schema definition string (attributeTypes, objectClasses)

            Returns:
                Cleaned value with quotes removed from SYNTAX OID

            """
            if isinstance(value, bytes):
                return value  # Binary values don't need cleaning

            # Pattern: SYNTAX followed by optional space, quotes, OID, quotes
            # Captures: SYNTAX '1.3.6.1.4.1.1466.115.121.1.7' or SYNTAX "..."
            syntax_pattern = re.compile(r"SYNTAX\s+['\"]([0-9.]+)['\"]")

            # Replace quoted SYNTAX OID with unquoted version
            return syntax_pattern.sub(r"SYNTAX \1", value)

        def _add_ldif_block(
            self,
            ldif_lines: list[str],
            schema_type: str,
            value: str | bytes,
            *,
            is_first_block: bool,
        ) -> bool:
            """Add a single LDIF block for schema value.

            Returns:
                False (next block won't be first)

            """
            return FlextLdifServersOud._add_ldif_block_static(
                ldif_lines,
                schema_type,
                value,
                is_first_block=is_first_block,
            )

        def _write_entry_modify_add_format(
            self,
            entry_data: FlextLdifModels.Entry,
            allowed_schema_oids: frozenset[str] | None = None,
        ) -> FlextResult[str]:
            """Write schema entry in OUD modify-add format.

            Delegates to shared helper method to avoid code duplication.
            See FlextLdifServersOud._write_entry_modify_add_format_helper for full documentation.

            Args:
                entry_data: Schema entry to write
                allowed_schema_oids: Optional set of allowed OIDs for filtering

            Returns:
                FlextResult with LDIF string (multiple entries, one per schema element)

            """
            # Get parent_quirk from Entry instance (set during __init__ in base.py)
            # If not available, create new OUD instance to access schema_quirk
            parent_quirk: object | None = None
            if hasattr(self, "parent_quirk"):
                parent_quirk = self.parent_quirk
            elif hasattr(self, "_parent_quirk"):
                parent_quirk = self._parent_quirk
            else:
                # Fallback: create OUD instance to access schema_quirk
                parent_quirk = FlextLdifServersOud()

            return FlextLdifServersOud._write_entry_modify_add_format_helper(
                entry_data,
                allowed_schema_oids,
                parent_quirk,
            )

        def _comment_acl_attributes(
            self,
            entry_data: FlextLdifModels.Entry,
            acl_attr_names: frozenset[str],
        ) -> FlextLdifModels.Entry:
            """Move ACL attributes to metadata (RFC will comment them).

            Moves ACL attributes from entry.attributes to entry_metadata[REMOVED_ATTRIBUTES_WITH_VALUES].
            For OID entries with ACL transformations (orclaci → aci), uses original attribute name.
            The RFC layer's write_removed_attributes_as_comments feature will then write
            them as commented lines in the LDIF output.

            Args:
                entry_data: Entry to process
                acl_attr_names: Set of ACL attribute names to comment (e.g., {'aci'})

            Returns:
                New Entry with ACL attributes moved to metadata using original names from transformations

            """
            return FlextLdifServersOud._comment_acl_attributes_static(
                entry_data,
                acl_attr_names,
            )

        def _separate_acl_attributes(
            self,
            attrs_dict: dict[str, list[str]],
            acl_attr_names: frozenset[str],
        ) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
            """Separate ACL attributes from regular attributes."""
            return FlextLdifServersOud._separate_acl_attributes_static(
                attrs_dict,
                acl_attr_names,
            )

        def _resolve_acl_original_names(
            self,
            entry_data: FlextLdifModels.Entry,
            acl_attrs: dict[str, list[str]],
        ) -> dict[str, list[str]]:
            """Resolve original ACL attribute names from metadata transformations."""
            return FlextLdifServersOud._resolve_acl_original_names_static(
                entry_data,
                acl_attrs,
            )

        def _create_entry_metadata_with_acl_comments(
            self,
            entry_metadata: dict[str, object] | None,
            acl_attrs: dict[str, list[str]],
        ) -> dict[str, object]:
            """Create entry metadata with ACL attributes marked for commenting."""
            return FlextLdifServersOud._create_entry_metadata_with_acl_comments_static(
                entry_metadata,
                acl_attrs,
            )

        def _create_entry_with_acl_comments(
            self,
            entry_data: FlextLdifModels.Entry,
            remaining_attrs: dict[str, list[str]],
            new_entry_metadata: dict[str, object],
        ) -> FlextLdifModels.Entry:
            """Create new entry with ACL attributes moved to metadata."""
            return FlextLdifServersOud._create_entry_with_acl_comments_static(
                entry_data,
                remaining_attrs,
                new_entry_metadata,
            )

        def _validate_aci_macros(self, aci_value: str) -> FlextResult[bool]:
            """Validate OUD ACI macro consistency rules."""
            return FlextLdifServersOud._validate_aci_macros_static(aci_value)

        def _correct_rfc_syntax_in_attributes(
            self,
            attrs_dict: dict[str, object],
        ) -> FlextResult[dict[str, object]]:
            """Correct RFC syntax issues in attribute values (syntax only, not structure)."""
            return FlextLdifServersOud._correct_rfc_syntax_in_attributes_static(attrs_dict)

        def _hook_pre_write_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Hook: Validate and CORRECT RFC syntax issues before writing Entry.

            This hook ensures that Entry data with RFC-valid syntax is properly
            formatted for OUD LDIF output. It does NOT alter data structure
            (attributes, objectClasses, etc.) - only corrects syntax/formatting.

            Corrections applied:
            1. Validate ACI macros (syntax validation)
            2. Ensure attribute values are properly encoded (RFC 2849)
            3. Normalize string values to valid UTF-8 (RFC 2849 requirement)
            4. Ensure all values are strings (convert non-strings)

            IMPORTANT: Does NOT remove attributes, objectClasses, or alter data structure.
            All data is preserved - only syntax/formatting is corrected.

            Args:
                entry: RFC Entry (already canonical, with aci: attributes)

            Returns:
                FlextResult[Entry] - entry with corrected syntax, fail() if syntax errors

            """
            # Extract attributes dict with None check for type safety
            attrs_dict_raw = (
                entry.attributes.attributes if entry.attributes is not None else {}
            )
            # Cast to dict[str, object] for type compatibility with _correct_rfc_syntax_in_attributes
            attrs_dict: dict[str, object] = dict(attrs_dict_raw.items())

            # Step 1: Validate ACI macros if present (syntax validation)
            aci_attrs = attrs_dict.get("aci")
            if aci_attrs and isinstance(aci_attrs, list):
                for aci_value in aci_attrs:
                    if isinstance(aci_value, str):
                        validation_result = self._validate_aci_macros(aci_value)
                        if validation_result.is_failure:
                            return FlextResult[FlextLdifModels.Entry].fail(
                                f"ACI macro validation failed: {validation_result.error}",
                            )

            # Step 2: CORRECT RFC syntax issues in attribute values (syntax only, not structure)
            # Ensure all string values are valid UTF-8 and properly formatted (RFC 2849)
            corrected_result = self._correct_rfc_syntax_in_attributes(attrs_dict)
            if corrected_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(corrected_result.error or "Unknown error")

            corrected_data = corrected_result.unwrap()
            # Type narrowing for syntax_corrections
            syntax_corrections = corrected_data.get("syntax_corrections")
            if (
                syntax_corrections
                and isinstance(syntax_corrections, list)
                and len(syntax_corrections) > 0
            ):
                # Type narrowing for corrected_attributes
                corrected_attrs = corrected_data.get("corrected_attributes")
                if isinstance(corrected_attrs, dict):
                    # Type narrowing: corrected_attrs is dict[str, list[str]] from _correct_rfc_syntax_in_attributes
                    attrs_for_model: dict[str, list[str]] = {
                        k: v if isinstance(v, list) else [str(v)]
                        for k, v in corrected_attrs.items()
                        if isinstance(v, (list, str))
                    }
                    corrected_ldif_attrs = FlextLdifModels.LdifAttributes(
                        attributes=attrs_for_model,
                    )

                    # Create new Entry with corrected attributes (preserve all metadata and structure)
                    corrected_entry = entry.model_copy(
                        update={"attributes": corrected_ldif_attrs},
                    )

                    logger.debug(
                        "OUD quirks: Applied syntax corrections before writing (structure preserved)",
                        entry_dn=entry.dn.value if entry.dn else None,
                        corrections_count=len(syntax_corrections),
                        corrections=syntax_corrections,
                        corrected_attributes=list(corrected_attrs.keys())
                        if isinstance(corrected_attrs, dict)
                        else None,
                    )
                    return FlextResult[FlextLdifModels.Entry].ok(corrected_entry)

            # Entry is RFC-canonical with valid syntax - return unchanged
            # All conversions (orclaci→aci) already done in parsing phase
            return FlextResult[FlextLdifModels.Entry].ok(entry)

        def _filter_and_sort_schema_values(
            self,
            values: list[str],
            allowed_oids: set[str] | None,
            oid_pattern: re.Pattern[str],
        ) -> list[tuple[tuple[int, ...], str]]:
            """Filter schema values by whitelist and sort by OID."""
            return FlextLdifUtilities.OID.filter_and_sort_by_oid(
                values,
                allowed_oids=allowed_oids,
                oid_pattern=oid_pattern,
            )

        def _finalize_and_parse_entry(
            self,
            entry_dict: dict[str, object],
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
            # Use Entry quirk's _parse_entry via instance (returns Entry RFC canonical)
            # Create Entry instance to access _parse_entry
            entry_instance = FlextLdifServersOud.Entry()
            result = entry_instance._parse_entry(dn, entry_dict)
            if result.is_success:
                entries_list.append(result.unwrap())

        def extract_entries_from_ldif(
            self,
            ldif_content: str,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Extract and parse all directory entries from LDIF content.

            Strategy pattern: OUD-specific approach to extract entries from LDIF.

            Args:
                ldif_content: Raw LDIF content containing directory entries

            Returns:
                FlextResult with list of parsed Entry models (RFC canonical)

            """
            try:
                entries: list[FlextLdifModels.Entry] = []
                current_entry: dict[str, object] = {}
                current_attr: str | None = None
                current_values: list[str] = []

                for line in ldif_content.split("\n"):
                    # Empty line indicates end of entry
                    if not line.strip():
                        if current_entry:
                            # Finalize and process entry
                            FlextLdifUtilities.Parser.finalize_pending_attribute(
                                current_attr,
                                current_values,
                                current_entry,
                            )
                            self._finalize_and_parse_entry(current_entry, entries)
                            current_entry = {}
                            current_attr = None
                            current_values = []
                        continue

                    # Skip comments
                    if line.startswith("#"):
                        continue

                    # Continuation line (starts with space)
                    if line.startswith(" ") and current_attr and current_values:
                        current_values[-1] += line[1:]  # Remove leading space
                        continue

                    # Process new attribute line using utility
                    current_attr, current_values = (
                        FlextLdifUtilities.Parser.process_ldif_attribute_line(
                            line,
                            current_attr,
                            current_values,
                            current_entry,
                        )
                    )

                # Process final entry
                if current_entry:
                    FlextLdifUtilities.Parser.finalize_pending_attribute(
                        current_attr,
                        current_values,
                        current_entry,
                    )
                    self._finalize_and_parse_entry(current_entry, entries)

                return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

            except Exception as e:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"OUD entry extraction failed: {e}",
                )

        def _inject_validation_rules(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextLdifModels.Entry:
            """Inject OUD-specific validation rules into Entry metadata via DI."""
            return FlextLdifServersOud._inject_validation_rules_static(entry)

    class Acl(FlextLdifServersRfc.Acl):
        """Oracle OUD ACL quirk (nested).

        Extends RFC ACL parsing with Oracle OUD-specific ACL formats:
        - ds-cfg-access-control-handler: OUD access control
        - OUD-specific ACL syntax (RFC-compliant ACI format)

        Example:
            quirk = FlextLdifServersOud.Acl()
            if quirk.can_handle(acl_line):
                result = quirk.parse(acl_line)

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
        # Use OID Constants for Oracle ACI compatibility
        # Import here to avoid circular dependency at module level
        @classmethod
        def _get_oud_acl_attributes(cls) -> list[str]:
            """Get OUD ACL attributes using OID constants."""
            from flext_ldif.servers.oid import FlextLdifServersOid  # noqa: PLC0415

            return [
                FlextLdifServersOid.Constants.ORCLACI,  # OUD uses Oracle ACIs (compatibility)
                FlextLdifServersOid.Constants.ORCLENTRYLEVELACI,  # OUD entry-level ACI
            ]

        OUD_ACL_ATTRIBUTES: ClassVar[list[str]] = [
            "orclaci",  # OUD uses Oracle ACIs (compatibility) - using string literal to avoid circular import
            "orclentrylevelaci",  # OUD entry-level ACI - using string literal to avoid circular import
        ]

        def get_acl_attributes(self) -> list[str]:
            """Get RFC + OUD extensions.

            Returns:
                List of ACL attribute names (RFC foundation + OUD-specific)

            """
            return self.RFC_ACL_ATTRIBUTES + self.OUD_ACL_ATTRIBUTES

        def is_acl_attribute(self, attribute_name: str) -> bool:
            """Check if ACL attribute (case-insensitive).

            Args:
                attribute_name: Attribute name to check

            Returns:
                True if attribute is ACL attribute, False otherwise

            """
            all_attrs = self.get_acl_attributes()
            return attribute_name.lower() in [a.lower() for a in all_attrs]

        # OVERRIDDEN METHODS (from FlextLdifServersBase.Acl)
        # These methods override the base class with Oracle OUD-specific logic:
        # - can_handle(): Detects OUD ACL formats
        # - parse(): Normalizes Oracle OUD ACL to RFC-compliant internal model
        # - write(): Serializes RFC-compliant model to OUD ACI format
        # - get_attribute_name(): Returns "aci" (OUD-specific, overridden)

        # Oracle OUD server configuration defaults

        def __init__(self, **kwargs: object) -> None:
            """Initialize OUD ACL quirk.

            Args:
                **kwargs: Passed to parent for compatibility (ignored)

            """
            super().__init__(**kwargs)
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

            Detects Oracle OUD ACL by checking if the line starts with:
            - "aci:" (RFC 4876 compliant ACI)
            - "targetattr=" (inline ACI format)
            - "targetscope=" (inline ACI format)
            - "version 3.0" (ACI version marker)
            - "ds-cfg-" (OUD configuration ACL)

            Args:
                acl_line: Raw ACL line string or Acl model from LDIF

            Returns:
                True if this is Oracle OUD ACL format

            """
            if isinstance(acl_line, FlextLdifModels.Acl):
                # Check metadata for quirk type
                if acl_line.metadata and acl_line.metadata.quirk_type:
                    return str(acl_line.metadata.quirk_type) == self._get_server_type()
                # Check attribute name
                if acl_line.name:
                    acl_attr_normalized = (
                        FlextLdifUtilities.Schema.normalize_attribute_name(
                            acl_line.name,
                        )
                    )
                    const_attr_normalized = (
                        FlextLdifUtilities.Schema.normalize_attribute_name(
                            FlextLdifServersOud.Constants.ACL_ATTRIBUTE_NAME,
                        )
                    )
                    return acl_attr_normalized == const_attr_normalized
                return False

            if not acl_line:
                return False

            normalized = acl_line.strip()
            # Check for OUD ACL patterns
            aci_prefix = FlextLdifServersOud.Constants.ACL_ACI_PREFIX
            targetattr_prefix = FlextLdifServersOud.Constants.ACL_TARGETATTR_PREFIX
            targetscope_prefix = FlextLdifServersOud.Constants.ACL_TARGETSCOPE_PREFIX
            version_prefix = FlextLdifServersOud.Constants.ACL_DEFAULT_VERSION
            normalized_lower = normalized.lower()

            # RFC 4876 ACI format detection
            if (
                normalized.startswith(
                    (
                        aci_prefix,
                        targetattr_prefix,
                        targetscope_prefix,
                        version_prefix,
                    ),
                )
                or "ds-cfg-" in normalized_lower
            ):
                return True

            # ds-privilege-name format: simple privilege names (OUD-specific)
            # Examples: "config-read", "password-reset", "bypass-acl"
            # Must NOT contain "access to" (OID format), parentheses (ACI format), or equals (attribute format)
            return bool(
                normalized
                and not any(
                    pattern in normalized_lower
                    for pattern in ["access to", "(", ")", "=", ":"]
                ),
            )

        def _parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse Oracle OUD ACL string to RFC-compliant internal model.

            Supports two OUD ACL formats:
            1. RFC 4876 ACI format: aci: (targetattr=...)(version 3.0; acl "name"; ...)
            2. ds-privilege-name format: Simple privilege names like "config-read"

            Args:
            acl_line: ACL definition line (may be ACI or ds-privilege-name)

            Returns:
            FlextResult with OUD ACL Pydantic model

            """
            # Type guard: ensure acl_line is a string
            if not isinstance(acl_line, str):
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"ACL line must be a string, got {type(acl_line).__name__}"
                )
            normalized = acl_line.strip()

            # Detect format: RFC 4876 ACI or ds-privilege-name
            if normalized.startswith(FlextLdifServersOud.Constants.ACL_ACI_PREFIX):
                # RFC 4876 ACI format
                return self._parse_aci_format(acl_line)
            # Check if this is an OID format ACL (orclaci: or orclentrylevelaci:)
            if normalized.startswith(("orclaci:", "orclentrylevelaci:")):
                # This is an OID format ACL - try to parse it using OID parser
                # Import here to avoid circular dependency at module level
                from flext_ldif.servers.oid import (  # noqa: PLC0415
                    FlextLdifServersOid,
                )

                oid_quirk = FlextLdifServersOid.Acl()
                oid_parse_result = oid_quirk.parse(acl_line)
                if oid_parse_result.is_success:
                    # OID parser succeeded - return the result (with permissions preserved)
                    return oid_parse_result
            # Try RFC parser first for other non-ACI formats
            # This handles cases where other formats are written and need to be parsed
            rfc_result = super()._parse_acl(acl_line)
            if rfc_result.is_success:
                # RFC parser succeeded - check if it has a valid name
                # If name is empty and line doesn't look like RFC format, try ds-privilege-name
                acl_model = rfc_result.unwrap()
                if acl_model.name or normalized.startswith((
                    "aci:",
                    "orclaci:",
                    "orclentrylevelaci:",
                )):
                    # RFC parser returned valid result with name or recognized format
                    return rfc_result
            # If RFC parser fails or returned empty name, try ds-privilege-name format (simple privilege names)
            return self._parse_ds_privilege_name(normalized)

        def _parse_aci_format(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse RFC 4876 ACI format using functional composition.

            Normalizes OUD ACI (Access Control Instruction) format to RFC-compliant
            internal representation using monadic patterns and functional composition.

            Args:
            acl_line: ACL definition line with 'aci:' prefix

            Returns:
            FlextResult with OUD ACL Pydantic model

            """

            def validate_aci_format(acl_line: str) -> FlextResult[str]:
                """Validate and extract ACI content using monadic validation."""
                # Handle multiline ACI: check if first line starts with aci:
                first_line = acl_line.split("\n", maxsplit=1)[0].strip()
                if not first_line.startswith(
                    FlextLdifServersOud.Constants.ACL_ACI_PREFIX,
                ):
                    return FlextResult[str].fail("Not an OUD ACI format")
                # Preserve multiline format: remove "aci:" prefix but keep newlines
                if "\n" in acl_line:
                    # Multiline ACI: remove "aci:" from first line only, preserve rest
                    lines = acl_line.split("\n")
                    first_line_content = lines[0].split(":", 1)[1].strip()
                    # Reconstruct with preserved newlines
                    aci_content = first_line_content + "\n" + "\n".join(lines[1:])
                else:
                    # Single line ACI
                    aci_content = acl_line.split(":", 1)[1].strip()
                return FlextResult[str].ok(aci_content)

            def initialize_parse_context() -> dict[str, object]:
                """Initialize parsing context with default values."""
                return {
                    "acl_name": FlextLdifServersOud.Constants.ACL_DEFAULT_NAME,
                    "targetattr": FlextLdifServersOud.Constants.ACL_DEFAULT_TARGETATTR,
                    "targetscope": None,
                    "version": FlextLdifServersOud.Constants.ACL_DEFAULT_VERSION,
                    "dn_spaces": False,
                }

            def extract_components(
                context: dict[str, object],
                aci_content: str,
            ) -> dict[str, object]:
                """Extract all ACI components using functional composition."""
                # Store aci_content in context for later use
                context["aci_content"] = aci_content
                # Preserve original acl_line (may be multiline) for raw_acl
                context["original_acl_line"] = acl_line

                # Extract target attributes
                context["targetattr"] = (
                    FlextLdifUtilities.ACL.extract_component(
                        aci_content,
                        FlextLdifServersOud.Constants.ACL_TARGETATTR_PATTERN,
                        group=2,
                    )
                    or context["targetattr"]
                )

                # Extract target scope
                context["targetscope"] = FlextLdifUtilities.ACL.extract_component(
                    aci_content,
                    FlextLdifServersOud.Constants.ACL_TARGETSCOPE_PATTERN,
                    group=1,
                )

                # Extract version and ACL name
                version_match = re.search(
                    FlextLdifServersOud.Constants.ACL_VERSION_ACL_PATTERN,
                    aci_content,
                )
                if version_match:
                    context["version"] = version_match.group(1)
                    context["acl_name"] = version_match.group(2)

                return context

            try:
                # Validate ACI format first
                validation_result = validate_aci_format(acl_line)
                if not validation_result.is_success:
                    error_msg = validation_result.error or "ACI format validation failed"
                    return FlextResult[FlextLdifModels.Acl].fail(error_msg)

                # Extract components and build model
                aci_content = validation_result.unwrap()
                context = extract_components(initialize_parse_context(), aci_content)
                return self._build_acl_model(context)

            except Exception as e:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"Failed to parse OUD ACI format: {e}",
                )

        def _parse_ds_privilege_name(
            self,
            privilege_name: str,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Parse OUD ds-privilege-name format (simple privilege names).

            Oracle OUD uses simple privilege names for access control:
            - config-read, config-write, config-delete
            - password-reset, password-change
            - bypass-acl, bypass-lockdown
            - And other REDACTED_LDAP_BIND_PASSWORDistrative privileges

            Args:
            privilege_name: Simple privilege name (e.g., "config-read")

            Returns:
            FlextResult with OUD ACL Pydantic model

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
                        extensions={
                            "ds_privilege_name": privilege_name,
                            "format_type": "ds-privilege-name",
                        },
                    ),
                )

                return FlextResult[FlextLdifModels.Acl].ok(acl_model)

            except Exception as e:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"Failed to parse OUD ds-privilege-name: {e}",
                )

        def _build_acl_model(
            self,
            context: dict[str, object],
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Build ACL model from parsed context using functional composition."""
            try:
                # Extract values from context
                aci_content = context.get("aci_content", "")

                # Extract permissions using DRY utility
                permissions_list = FlextLdifUtilities.ACL.extract_permissions(
                    cast("str", aci_content),
                    FlextLdifServersOud.Constants.ACL_ALLOW_DENY_PATTERN,
                    ops_separator=FlextLdifServersOud.Constants.ACL_OPS_SEPARATOR,
                    action_filter=FlextLdifServersOud.Constants.ACL_ACTION_ALLOW,
                )

                # Extract bind rules using DRY utility with centralized patterns
                bind_rules_data = FlextLdifUtilities.ACL.extract_bind_rules(
                    cast("str", aci_content),
                    dict(FlextLdifServersOud.Constants.ACL_BIND_PATTERNS),
                )

                # Check for DN spaces in bind rules
                dn_spaces = any(
                    FlextLdifUtilities.DN.contains_pattern(rule["value"], ", ")
                    for rule in bind_rules_data
                )

                # Build permissions dict using DRY utility
                perm_map = {
                    "read": FlextLdifServersOud.Constants.PERMISSION_READ,
                    "write": FlextLdifServersOud.Constants.PERMISSION_WRITE,
                    "add": FlextLdifServersOud.Constants.PERMISSION_ADD,
                    "delete": FlextLdifServersOud.Constants.PERMISSION_DELETE,
                    "search": FlextLdifServersOud.Constants.PERMISSION_SEARCH,
                    "compare": FlextLdifServersOud.Constants.PERMISSION_COMPARE,
                    "selfwrite": FlextLdifServersOud.Constants.PERMISSION_SELF_WRITE,
                    "self_write": FlextLdifServersOud.Constants.PERMISSION_SELF_WRITE,
                    "proxy": FlextLdifServersOud.Constants.PERMISSION_PROXY,
                }
                permissions_data = FlextLdifUtilities.ACL.build_permissions_dict(
                    permissions_list,
                    perm_map,
                )

                # Handle "all" permission special case
                if FlextLdifUtilities.Schema.is_attribute_in_list(
                    FlextLdifServersOud.Constants.PERMISSION_ALL,
                    permissions_list,
                ):
                    permissions_data = dict.fromkeys(permissions_data, True)

                # Build QuirkMetadata extensions using DRY utility
                metadata_config = FlextLdifModels.AclMetadataConfig(
                    line_breaks=[],  # Will be set from context
                    dn_spaces=dn_spaces,
                    targetscope=cast("str | None", context.get("targetscope")),
                    version=cast("str", context.get("version", "3.0")),
                    default_version="3.0",
                )
                extensions = FlextLdifUtilities.ACL.build_metadata_extensions(
                    metadata_config,
                )

                # Create Acl model using functional composition
                return self._create_acl_from_context(
                    context,
                    extensions,
                    cast("str", aci_content),
                )

            except Exception as e:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"Failed to build OUD ACL model: {e}",
                )

        def _create_acl_from_context(
            self,
            context: dict[str, object],
            extensions: dict[str, object],
            aci_content: str,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Create ACL model from context using functional composition."""
            try:
                # Extract values from context

                # Extract permissions and bind rules from aci_content
                permissions_list = FlextLdifUtilities.ACL.extract_permissions(
                    aci_content,
                    FlextLdifServersOud.Constants.ACL_ALLOW_DENY_PATTERN,
                    ops_separator=FlextLdifServersOud.Constants.ACL_OPS_SEPARATOR,
                    action_filter=FlextLdifServersOud.Constants.ACL_ACTION_ALLOW,
                )

                bind_rules_data = FlextLdifUtilities.ACL.extract_bind_rules(
                    aci_content,
                    dict(FlextLdifServersOud.Constants.ACL_BIND_PATTERNS),
                )

                # Build permissions and subject using functional utilities
                perm_map = {
                    "read": FlextLdifServersOud.Constants.PERMISSION_READ,
                    "write": FlextLdifServersOud.Constants.PERMISSION_WRITE,
                    "add": FlextLdifServersOud.Constants.PERMISSION_ADD,
                    "delete": FlextLdifServersOud.Constants.PERMISSION_DELETE,
                    "search": FlextLdifServersOud.Constants.PERMISSION_SEARCH,
                    "compare": FlextLdifServersOud.Constants.PERMISSION_COMPARE,
                    "selfwrite": FlextLdifServersOud.Constants.PERMISSION_SELF_WRITE,
                    "self_write": FlextLdifServersOud.Constants.PERMISSION_SELF_WRITE,
                    "proxy": FlextLdifServersOud.Constants.PERMISSION_PROXY,
                }

                permissions_data = FlextLdifUtilities.ACL.build_permissions_dict(
                    permissions_list,
                    perm_map,
                )

                # Handle "all" permission special case
                if FlextLdifUtilities.Schema.is_attribute_in_list(
                    FlextLdifServersOud.Constants.PERMISSION_ALL,
                    permissions_list,
                ):
                    permissions_data = dict.fromkeys(permissions_data, True)

                # Build subject using functional utilities
                subject_type_map = {
                    FlextLdifServersOud.Constants.ACL_BIND_RULE_TYPE_USERDN: FlextLdifServersOud.Constants.ACL_SUBJECT_TYPE_BIND_RULES,
                    FlextLdifServersOud.Constants.ACL_BIND_RULE_TYPE_GROUPDN: "group",
                }
                special_values = {
                    # Map both with and without ldap:/// prefix
                    FlextLdifServersOud.Constants.ACL_SELF_SUBJECT: (
                        "self",
                        FlextLdifServersOud.Constants.ACL_SELF_SUBJECT,
                    ),
                    "self": (
                        "self",
                        FlextLdifServersOud.Constants.ACL_SELF_SUBJECT,
                    ),
                    FlextLdifServersOud.Constants.ACL_ANONYMOUS_SUBJECT: (
                        "anonymous",
                        "*",
                    ),
                    "anyone": (
                        "anonymous",
                        "*",
                    ),
                    FlextLdifServersOud.Constants.ACL_ANONYMOUS_SUBJECT_ALT: (
                        "anonymous",
                        "*",
                    ),
                    "*": (
                        "anonymous",
                        "*",
                    ),
                }
                subject_type, subject_value = FlextLdifUtilities.ACL.build_acl_subject(
                    bind_rules_data,
                    subject_type_map,
                    special_values,
                )

                # Create ACL model using functional composition
                acl_line = context.get("original_acl_line", "")

                # Parse targetattr: split by "||" separator if present, otherwise use as single attribute
                targetattr_str = cast("str", context["targetattr"])
                if targetattr_str and "||" in targetattr_str:
                    # Multiple attributes: "cn || sn || mail" -> ["cn", "sn", "mail"]
                    target_attributes = [
                        attr.strip()
                        for attr in targetattr_str.split("||")
                        if attr.strip()
                    ]
                    target_dn = (
                        "*"  # Multiple attributes means entry-level, not DN-specific
                    )
                elif targetattr_str and targetattr_str != "*":
                    # Single attribute: "cn" -> ["cn"]
                    target_attributes = [targetattr_str.strip()]
                    target_dn = "*"
                else:
                    # Wildcard: "*" -> []
                    target_attributes = []
                    target_dn = "*"

                acl = FlextLdifModels.Acl(
                    name=cast("str", context["acl_name"]),
                    target=FlextLdifModels.AclTarget(
                        target_dn=target_dn,
                        attributes=target_attributes,
                    ),
                    subject=FlextLdifModels.AclSubject(
                        subject_type=subject_type,
                        subject_value=subject_value,
                    ),
                    permissions=FlextLdifModels.AclPermissions(**permissions_data),
                    metadata=FlextLdifModels.QuirkMetadata.create_for(
                        self._get_server_type(),
                        extensions={
                            **extensions,
                            "original_format": cast("str", acl_line),
                        },
                    ),
                    raw_acl=cast("str", acl_line),
                )

                return FlextResult[FlextLdifModels.Acl].ok(acl)

            except Exception as e:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"Failed to create ACL model: {e}",
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
            """Build ACI target attributes part.

            Args:
                acl_data: ACL model instance

            Returns:
                Formatted target attributes string

            """
            if not acl_data.target:
                return '(targetattr="*")'

            # Use attributes list if available (from OID conversion or multi-attribute ACI)
            if acl_data.target.attributes:
                # Multiple attributes: join with " || " separator
                target_attr_str = " || ".join(acl_data.target.attributes)
                return f'(targetattr="{target_attr_str}")'

            # Fallback to target_dn if no attributes list
            if acl_data.target.target_dn and acl_data.target.target_dn != "*":
                # Single attribute or DN stored in target_dn
                target = acl_data.target.target_dn
                return f'(targetattr="{target}")'

            # Default: wildcard
            return '(targetattr="*")'

        def _build_aci_permissions(
            self,
            acl_data: FlextLdifModels.Acl,
        ) -> FlextResult[str]:
            """Build ACI permissions part.

            Args:
                acl_data: ACL model instance

            Returns:
                FlextResult with formatted permissions string

            """
            if not acl_data.permissions:
                return FlextResult[str].fail("ACL model has no permissions object")

            # Extract permission names from boolean fields directly
            perms = acl_data.permissions
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

            # Filter to only OUD-supported rights using utility
            filtered_ops = FlextLdifUtilities.ACL.filter_supported_permissions(
                ops,
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

        def _build_aci_subject(self, acl_data: FlextLdifModels.Acl) -> str:
            """Build ACI bind rules (subject) part.

            Args:
                acl_data: ACL model instance

            Returns:
                Formatted bind rules string (empty if DN was filtered out by base_dn)

            """
            if not acl_data.subject:
                # Default: allow for self
                return f'userdn="{FlextLdifServersOud.Constants.ACL_SELF_SUBJECT}";)'

            # Extract base_dn from metadata if available (set by migrate)
            base_dn: str | None = None
            if (
                acl_data.metadata
                and hasattr(acl_data.metadata, "extensions")
                and acl_data.metadata.extensions
            ):
                base_dn_value = acl_data.metadata.extensions.get("base_dn")
                if isinstance(base_dn_value, str):
                    base_dn = base_dn_value

            # Use utility to format subject with base_dn filtering
            return FlextLdifUtilities.ACL.format_aci_subject(
                acl_data.subject.subject_type,
                acl_data.subject.subject_value,
                FlextLdifServersOud.Constants,
                base_dn=base_dn,
            )

        def write(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write RFC-compliant ACL model to OUD ACI string format.

            Serializes the RFC-compliant internal model to Oracle OUD ACI format string,
            including comprehensive comment generation for vendor-specific ACL format conversions
            to ensure zero data loss (all unsupported features tracked in metadata).

            Args:
                acl_data: RFC-compliant ACL Pydantic model

            Returns:
                FlextResult with OUD ACI formatted string including conversion comments

            Example:
                Input: Acl(name="Test", target=..., subject=..., permissions=...)
                Output: 'aci: (targetattr="*")(version 3.0; acl "Test"; allow (read) userdn="ldap:///self";)'

            """
            try:
                aci_output_lines: list[str] = []

                # Generate Server Conversion Comments (server-agnostic)
                if (
                    acl_data.metadata
                    and hasattr(acl_data.metadata, "extensions")
                    and acl_data.metadata.extensions
                ):
                    extensions = acl_data.metadata.extensions

                    # Generic conversion tracking (OUD doesn't need to know source server)
                    if extensions.get(MetaKeys.CONVERTED_FROM_SERVER):
                        conversion_comments = extensions.get(
                            MetaKeys.CONVERSION_COMMENTS,
                            [],
                        )
                        if conversion_comments and isinstance(
                            conversion_comments,
                            list,
                        ):
                            aci_output_lines.extend(
                                str(comment) for comment in conversion_comments
                            )
                            aci_output_lines.append("")  # Empty line after comments

                # Check if we should use raw_acl as-is using helper
                if self._should_use_raw_acl(acl_data):
                    aci_output_lines.append(acl_data.raw_acl)
                    return FlextResult[str].ok("\n".join(aci_output_lines))

                # Build ACI from model fields using helpers
                aci_parts = []

                # Target attributes using helper
                aci_parts.append(self._build_aci_target(acl_data))

                # Version and ACL name
                acl_name = (
                    acl_data.name or FlextLdifServersOud.Constants.ACL_DEFAULT_NAME
                )
                aci_parts.append(
                    f'({FlextLdifServersOud.Constants.ACL_DEFAULT_VERSION}; acl "{acl_name}";',
                )

                # Permissions and bind rules (subject) using helpers
                perms_result = self._build_aci_permissions(acl_data)
                if perms_result.is_failure:
                    return FlextResult[str].fail(perms_result.error or "Unknown error")

                # Add permissions and subject in one extend call
                subject_str = self._build_aci_subject(acl_data)
                # If subject is empty (DN filtered out by base_dn), skip this ACL
                if not subject_str:
                    return FlextResult[str].fail(
                        "ACL subject DN was filtered out by base_dn",
                    )

                aci_parts.extend(
                    [
                        perms_result.unwrap(),
                        subject_str,
                    ],
                )

                # Build final ACI string
                aci_string = (
                    f"{FlextLdifServersOud.Constants.ACL_ACI_PREFIX} "
                    f"{' '.join(aci_parts)}"
                )
                aci_output_lines.append(aci_string)

                return FlextResult[str].ok("\n".join(aci_output_lines))

            except Exception as e:
                return FlextResult[str].fail(f"Failed to write ACL to RFC: {e}")

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

        def extract_acls_from_ldif(
            self,
            ldif_content: str,
        ) -> FlextResult[list[FlextLdifModels.Acl]]:
            """Extract and parse all ACL definitions from LDIF content.

            Strategy pattern: OUD-specific approach to extract ACIs from LDIF entries.

            Args:
            ldif_content: Raw LDIF content containing ACL definitions

            Returns:
            FlextResult with list of parsed ACL models

            """
            try:
                acls: list[FlextLdifModels.Acl] = []
                current_aci: list[str] = []
                in_multiline_aci = False

                for line in ldif_content.split("\n"):
                    stripped = line.strip()

                    # Detect ACI start using helper
                    if self._is_aci_start(stripped):
                        # Finalize any previous ACI
                        self._finalize_aci(current_aci, acls)
                        current_aci = []

                        current_aci.append(stripped)
                        # Check if this ACI continues on next lines (no closing parenthesis)
                        in_multiline_aci = not stripped.rstrip().endswith(")")

                    elif in_multiline_aci and stripped:
                        # Continuation of multiline ACI
                        current_aci.append(stripped)
                        if stripped.rstrip().endswith(")"):
                            in_multiline_aci = False

                    elif self._is_ds_cfg_acl(stripped):
                        # Handle ds-cfg format directly
                        result = self.parse(stripped)
                        if result.is_success:
                            acls.append(result.unwrap())

                # Parse any remaining ACI
                self._finalize_aci(current_aci, acls)

                return FlextResult[list[FlextLdifModels.Acl]].ok(acls)

            except Exception as e:
                return FlextResult[list[FlextLdifModels.Acl]].fail(
                    f"OUD ACL extraction failed: {e}",
                )

    class Entry(FlextLdifServersRfc.Entry):
        """Oracle OUD entry quirk (nested).

        Handles OUD-specific entry transformations:
        - OUD-specific operational attributes
        - OUD entry formatting
        - Compatibility with OID entries

        Example:
            quirk = FlextLdifServersOud.Entry()
            if quirk.can_handle_entry(entry):
                result = quirk.parse_entry(entry.dn.value, entry.attributes.attributes)

        """

        def __init__(self, **kwargs: object) -> None:
            """Initialize OUD entry quirk.

            Args:
                **kwargs: Passed to parent for compatibility (ignored)

            """
            super().__init__(**kwargs)

        # OVERRIDDEN METHODS (from FlextLdifServersBase.Entry)
        # These methods override the base class with Oracle OUD-specific logic:
        # - can_handle(): Detects OUD entries by DN/attributes (PRIVATE)
        # - _parse_entry(): Normalizes OUD entries with metadata during parsing (PRIVATE)
        # - _write_entry(): Writes OUD entries with proper formatting (PRIVATE)

        def can_handle(
            self,
            entry_dn: str,
            attributes: Mapping[str, object],
        ) -> bool:
            """Check if this quirk should handle the entry (PRIVATE).

            Only handles entries when schema/filters indicate OUD-specific processing:
            - Entries with Oracle OUD attributes (ds-cfg-* prefix)

            Args:
                entry_dn: Entry DN string
                attributes: Entry attributes dictionary

            Returns:
                True if this quirk should handle the entry

            """
            if not entry_dn or not isinstance(entry_dn, str):
                return False

            if not attributes:
                return False

            # Convert Mapping to dict for attribute access
            entry_attrs = (
                dict(attributes) if not isinstance(attributes, dict) else attributes
            )

            # Use utility methods for DN pattern matching
            if FlextLdifUtilities.DN.contains_pattern(
                entry_dn,
                FlextLdifServersOud.Constants.DN_PREFIX_CN_CONFIG,
            ) and FlextLdifUtilities.DN.contains_pattern(
                entry_dn,
                FlextLdifServersOud.Constants.DN_PREFIX_CN_SCHEMA,
            ):
                return True

            if FlextLdifUtilities.DN.contains_pattern(
                entry_dn,
                FlextLdifServersOud.Constants.DN_PREFIX_CN_CONFIG,
            ) and (
                FlextLdifUtilities.DN.contains_pattern(
                    entry_dn,
                    FlextLdifServersOud.Constants.DN_PREFIX_CN_DIRECTORY,
                )
                or FlextLdifUtilities.DN.contains_pattern(
                    entry_dn,
                    FlextLdifServersOud.Constants.DN_PREFIX_CN_DS,
                )
            ):
                return True

            # Check for OUD detection prefixes from Constants
            if any(
                attr_name.startswith(prefix)
                for attr_name in entry_attrs
                for prefix in FlextLdifServersOud.Constants.DETECTION_ATTRIBUTE_PREFIXES
            ):
                return True

            # Check for OUD boolean attributes from Constants
            if any(
                attr_name.lower() in FlextLdifServersOud.Constants.BOOLEAN_ATTRIBUTES
                for attr_name in entry_attrs
            ):
                return True

            if any(
                "pwd" in attr_name.lower() or "password" in attr_name.lower()
                for attr_name in entry_attrs
            ):
                return True

            # OUD detects entries based on OUD-specific attributes only
            # Each server should only know its own format, not other servers' formats
            return FlextLdifConstants.DictKeys.OBJECTCLASS.lower() in entry_attrs

        # Oracle OUD boolean attributes that expect TRUE/FALSE instead of 0/1
        # This IS format-specific - OUD requires TRUE/FALSE, not 0/1
        # BOOLEAN_ATTRIBUTES moved to Constants class
        # ATTRIBUTE_CASE_MAP moved to Constants class

        def _preserve_internal_attributes(
            self,
            entry: FlextLdifModels.Entry,
        ) -> dict[str, list[str]]:
            """Preserve internal metadata attributes from entry.

            Args:
                entry: Entry model with attributes

            Returns:
                Dictionary of internal attributes to preserve

            """
            processed_attrs_dict: dict[str, list[str]] = {}

            # Extract attributes dict with None check for type safety
            attrs_dict = (
                entry.attributes.attributes if entry.attributes is not None else {}
            )

            # Preserve base64 encoding metadata
            if "_base64_attrs" in attrs_dict:
                processed_attrs_dict["_base64_attrs"] = attrs_dict["_base64_attrs"]

            # Preserve special LDIF modify markers for schema entries
            if "_modify_add_attributetypes" in attrs_dict:
                processed_attrs_dict["_modify_add_attributetypes"] = attrs_dict[
                    "_modify_add_attributetypes"
                ]
            if "_modify_add_objectclasses" in attrs_dict:
                processed_attrs_dict["_modify_add_objectclasses"] = attrs_dict[
                    "_modify_add_objectclasses"
                ]

            return processed_attrs_dict

        def _process_attribute_value(
            self,
            attr_name: str,
            attr_values: str | list[str] | list[bytes] | bytes,
        ) -> list[str]:
            """Process attribute value with OUD-specific transformations.

            Args:
                attr_name: Normalized attribute name
                attr_values: Attribute value(s)

            Returns:
                Processed attribute values as list[str]

            """
            attr_lower = attr_name.lower()

            # Convert boolean attributes (0/1 → TRUE/FALSE)
            if attr_lower in FlextLdifServersOud.Constants.BOOLEAN_ATTRIBUTES:
                # Convert to list[str] - fast-fail if cannot convert
                values_list: list[str]
                if isinstance(attr_values, list):
                    # Convert bytes to str if needed
                    values_list = [
                        v.decode("utf-8", errors="replace")
                        if isinstance(v, bytes)
                        else str(v)
                        for v in attr_values
                    ]
                # Single value - convert bytes to str if needed
                elif isinstance(attr_values, bytes):
                    values_list = [attr_values.decode("utf-8", errors="replace")]
                else:
                    values_list = [str(attr_values)]

                # Type annotation matches function signature - values_list is list[str]
                # Function accepts dict[str, list[str] | list[bytes] | bytes | str]
                # Convert to compatible type
                attr_dict: dict[str, list[str] | list[bytes] | bytes | str] = {
                    attr_name: values_list
                }
                converted_dict = FlextLdifUtilities.Entry.convert_boolean_attributes(
                    attr_dict,
                    set(FlextLdifServersOud.Constants.BOOLEAN_ATTRIBUTES),
                )
                return converted_dict.get(attr_name, values_list)

            # Validate telephone numbers (using Constants to avoid hard-coding)
            if (
                attr_lower == "telephonenumber"
            ):  # Note: this is a standard RFC attribute name
                # Ensure attr_values is list[str] for validation - convert bytes to str
                if isinstance(attr_values, list):
                    telephone_values = [
                        v.decode("utf-8", errors="replace")
                        if isinstance(v, bytes)
                        else str(v)
                        for v in attr_values
                    ]
                # Single value - convert bytes to str if needed
                elif isinstance(attr_values, bytes):
                    telephone_values = [attr_values.decode("utf-8", errors="replace")]
                else:
                    telephone_values = [str(attr_values)]
                valid_numbers = FlextLdifUtilities.Entry.validate_telephone_numbers(
                    telephone_values,
                )
                if valid_numbers:
                    return valid_numbers

            # Copy other attributes as is, ensuring list[str] format
            return [
                str(val)
                for val in (
                    [attr_values] if not isinstance(attr_values, list) else attr_values
                )
            ]

        def _build_metadata_extensions(
            self,
            entry: FlextLdifModels.Entry,
            processed_attributes: dict[str, list[str]],
        ) -> dict[str, object]:
            """Build metadata extensions for OUD entry.

            Args:
                entry: Entry model with DN
                processed_attributes: Processed attributes dictionary

            Returns:
                Metadata extensions dictionary

            """
            metadata_extensions: dict[str, object] = {}

            # Preserve DN spaces
            if entry.dn is not None and FlextLdifUtilities.DN.contains_pattern(
                entry.dn.value,
                ", ",
            ):
                metadata_extensions["dn_spaces"] = True

            # Preserve attribute order
            if processed_attributes:
                metadata_extensions["attribute_order"] = list(
                    processed_attributes.keys(),
                )

            # OUD server only preserves OUD-specific patterns
            # Vendor-specific objectClasses from other servers should be handled
            # at the Entry level, not by individual server quirks

            return metadata_extensions

        def _parse_entry(
            self,
            entry_dn: str,
            entry_attrs: Mapping[str, object],
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Parse raw LDIF entry data into Entry model with OUD-specific transformations.

            Applies OUD-specific normalizations during parsing:
            - Normalize attribute names to proper camelCase
            - Convert boolean attributes from 0/1 to TRUE/FALSE
            - Validate telephone numbers
            - Preserve metadata for DN quirks and attribute ordering

            Args:
                entry_dn: Raw DN string from LDIF parser
                entry_attrs: Raw attributes mapping from LDIF parser

            Returns:
                FlextResult with parsed Entry model with OUD-specific transformations

            """
            # First call parent _parse_entry to get base Entry model
            base_result = super()._parse_entry(entry_dn, entry_attrs)
            if base_result.is_failure:
                return base_result

            entry = base_result.unwrap()

            try:
                # Preserve internal metadata attributes using helper
                processed_attrs_dict = self._preserve_internal_attributes(entry)

                # Extract attributes dict with None check for type safety
                attrs_dict = (
                    entry.attributes.attributes if entry.attributes is not None else {}
                )

                # Normalize attribute names and apply OUD-specific transformations
                final_attributes_for_new_entry: dict[str, list[str]] = {}
                for attr_name, attr_values in attrs_dict.items():
                    # Skip internal metadata attributes
                    if attr_name.startswith("_"):
                        continue

                    # Normalize attribute name to proper camelCase
                    attr_lower = attr_name.lower()
                    normalized_name = (
                        FlextLdifServersOud.Constants.ATTRIBUTE_CASE_MAP.get(
                            attr_lower,
                            attr_name,
                        )
                    )
                    if not normalized_name:
                        normalized_name = attr_name

                    # Process attribute value using helper
                    final_attributes_for_new_entry[normalized_name] = (
                        self._process_attribute_value(normalized_name, attr_values)
                    )

                # Create LdifAttributes model, combining processed and internal attributes
                combined_attributes = final_attributes_for_new_entry.copy()
                combined_attributes.update(
                    {
                        k: v
                        for k, v in processed_attrs_dict.items()
                        if k.startswith("_")
                    },
                )
                new_ldif_attributes = FlextLdifModels.LdifAttributes(
                    attributes=combined_attributes,
                )

                # Build metadata extensions using helper
                metadata_extensions = self._build_metadata_extensions(
                    entry,
                    final_attributes_for_new_entry,
                )

                new_metadata = FlextLdifModels.QuirkMetadata.create_for(
                    quirk_type=self._get_server_type(),
                    extensions=metadata_extensions,
                )

                # Validate DN is present before creating entry
                if entry.dn is None:
                    return FlextResult.fail("Entry DN cannot be None for OUD parsing")

                # Create and return the new Entry model
                return FlextResult.ok(
                    cast(
                        "FlextLdifModels.Entry",
                        FlextLdifModels.Entry.create(
                            dn=entry.dn,
                            attributes=new_ldif_attributes,
                            metadata=new_metadata,
                        ).unwrap(),
                    ),
                )

            except Exception as e:
                return FlextResult.fail(f"OUD entry parsing failed: {e}")

        def _format_aci_with_semicolons(self, aci_value: str) -> str:
            """Format ACI value with semicolons between multiple 'by' clauses for OUD.

            OUD requires semicolons (;) to separate multiple 'by' clauses in ACI.

            Example:
              Input:  "aci: access to entry by group=... (...) by group=... (...) by * (...)"
              Output: "aci: access to entry by group=... (...) ; by group=... (...) ; by * (...)"

            Args:
                aci_value: ACI value string (may be multiline)

            Returns:
                Formatted ACI with semicolons inserted after each 'by' clause (except last)

            """
            # CRITICAL: This method only does semantic transformation (add semicolons).
            # Line formatting (folding/unfolding) is the writer's responsibility, NOT the quirk's.
            # Always normalize whitespace and remove newlines - let writer handle formatting.

            # Normalize whitespace: replace all whitespace (including newlines) with single spaces)
            # This ensures the quirk only does semantic transformation, not formatting
            normalized = re.sub(r"\s+", " ", aci_value.strip())

            # OUD format requires semicolons after each "by" clause (except the last one)
            # Format: "by group=\"...\" ;" or "by *" (no semicolon if last)
            # Find all "by group=\"...\"" and "by *" clauses
            by_group_pattern = FlextLdifServersOud.Constants.ACL_BY_GROUP_PATTERN
            by_star_pattern = FlextLdifServersOud.Constants.ACL_BY_STAR_PATTERN

            # Find all by clauses with their end positions
            by_clauses = [
                (match.end(), "group")
                for match in re.finditer(by_group_pattern, normalized, re.IGNORECASE)
            ]
            by_clauses.extend(
                (match.end(), "star")
                for match in re.finditer(by_star_pattern, normalized, re.IGNORECASE)
            )

            # Sort by position (first element of tuple)
            by_clauses.sort(key=operator.itemgetter(0))

            if len(by_clauses) <= 1:
                # Only one or zero "by" clauses - no formatting needed, but still normalize whitespace
                return normalized

            # Insert semicolons after each "by" clause except the last one
            # Check if each is followed by (permissions) by next_clause
            result_parts = []
            last_pos = 0

            for i, (pos, _clause_type) in enumerate(by_clauses):
                # Add text up to this position
                result_parts.append(normalized[last_pos:pos])

                # Check if this is NOT the last clause and is followed by (permissions) by
                if i < len(by_clauses) - 1:
                    # Check what comes after this clause
                    next_text = normalized[pos : min(len(normalized), pos + 100)]
                    # Pattern: space(s) followed by (permissions) followed by space(s) and "by"
                    if re.search(r"^\s+\([^)]+\)\s+by\s+", next_text, re.IGNORECASE):
                        # Add semicolon after the closing quote or *
                        result_parts.append(" ;")

                last_pos = pos

            # Add remaining text
            result_parts.append(normalized[last_pos:])

            return "".join(result_parts)

        def _is_schema_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> bool:
            """Check if entry is a schema entry (cn=subschemasubentry).

            Schema entries contain attributeTypes, objectClasses, matchingRules, etc.

            Args:
                entry: Entry model to check

            Returns:
                True if this is a schema entry

            """
            if not entry or not entry.dn or not entry.dn.value:
                return False

            dn_lower = entry.dn.value.lower()
            # Schema entry DN can be: cn=subschemasubentry, cn=subschema, or cn=schema
            return "cn=subschema" in dn_lower or dn_lower.startswith("cn=schema")

        def _filter_and_sort_schema_values(
            self,
            values: list[str],
            allowed_oids: set[str] | None,
            oid_pattern: re.Pattern[str],
        ) -> list[tuple[tuple[int, ...], str]]:
            """Filter schema values by whitelist and sort by OID."""
            return FlextLdifUtilities.OID.filter_and_sort_by_oid(
                values,
                allowed_oids=allowed_oids,
                oid_pattern=oid_pattern,
            )

        def _add_ldif_block(
            self,
            ldif_lines: list[str],
            schema_type: str,
            value: str | bytes,
            *,
            is_first_block: bool,
        ) -> bool:
            """Add a single LDIF block for schema value.

            Returns:
                False (next block won't be first)

            """
            return FlextLdifServersOud._add_ldif_block_static(
                ldif_lines,
                schema_type,
                value,
                is_first_block=is_first_block,
            )

        def _write_entry_modify_add_format(
            self,
            entry_data: FlextLdifModels.Entry,
            allowed_schema_oids: frozenset[str] | None = None,
        ) -> FlextResult[str]:
            """Write schema entry in OUD modify-add format.

            Delegates to shared helper method to avoid code duplication.
            See FlextLdifServersOud._write_entry_modify_add_format_helper for full documentation.

            Args:
                entry_data: Schema entry to write
                allowed_schema_oids: Optional set of allowed OIDs for filtering

            Returns:
                FlextResult with LDIF string (multiple entries, one per schema element)

            """
            # Get parent_quirk from Entry instance (set during __init__ in base.py)
            # If not available, create new OUD instance to access schema_quirk
            parent_quirk: object | None = None
            if hasattr(self, "parent_quirk"):
                parent_quirk = self.parent_quirk
            elif hasattr(self, "_parent_quirk"):
                parent_quirk = self._parent_quirk
            else:
                # Fallback: create OUD instance to access schema_quirk
                parent_quirk = FlextLdifServersOud()

            return FlextLdifServersOud._write_entry_modify_add_format_helper(
                entry_data,
                allowed_schema_oids,
                parent_quirk,
            )

        def _add_original_entry_comments(
            self,
            entry_data: FlextLdifModels.Entry,
            write_options: FlextLdifModels.WriteFormatOptions | None,
        ) -> list[str]:
            """Add original entry as commented LDIF block.

            Args:
                entry_data: Entry with metadata containing original entry
                write_options: Write options with write_original_entry_as_comment flag

            Returns:
                List of LDIF comment lines (empty if feature disabled)

            """
            if not (write_options and write_options.write_original_entry_as_comment):
                return []

            # RFC Compliance: Check metadata.write_options
            if not entry_data.metadata.write_options:
                return []

            original_entry_obj = entry_data.metadata.write_options.get(
                MetaKeys.ORIGINAL_ENTRY
            )
            if not (
                original_entry_obj
                and isinstance(original_entry_obj, FlextLdifModels.Entry)
            ):
                return []

            ldif_parts: list[str] = []
            ldif_parts.extend([
                "# " + "=" * 70,
                "# ORIGINAL OID Entry (commented)",
                "# " + "=" * 70,
            ])

            original_result = self._write_entry_as_comment(original_entry_obj)
            if original_result.is_success:
                ldif_parts.append(original_result.unwrap())

            ldif_parts.extend([
                "",
                "# " + "=" * 70,
                "# CONVERTED OUD Entry (active)",
                "# " + "=" * 70,
            ])

            return ldif_parts

        def _apply_phase_aware_acl_handling(
            self,
            entry_data: FlextLdifModels.Entry,
            write_options: FlextLdifModels.WriteFormatOptions | None,
        ) -> FlextLdifModels.Entry:
            """Apply phase-aware ACL attribute commenting.

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
            return self._comment_acl_attributes(entry_data, acl_attrs)

        @staticmethod
        def _extract_acl_normalization_context(
            entry_data: FlextLdifModels.Entry,
        ) -> tuple[str | None, FlextLdifModels.DnRegistry | None]:
            """Extract base_dn and dn_registry from entry metadata.

            Extracted helper to reduce complexity of _normalize_acl_dns.

            Args:
                entry_data: Entry with potential metadata

            Returns:
                Tuple of (base_dn, dn_registry) from metadata

            """
            base_dn: str | None = None
            dn_registry: FlextLdifModels.DnRegistry | None = None

            if not entry_data.metadata.write_options:
                return base_dn, dn_registry

            # Try write_options first
            base_dn_value = entry_data.metadata.write_options.get("base_dn")
            if isinstance(base_dn_value, str):
                base_dn = base_dn_value

            # Try extensions if write_options doesn't have base_dn
            if base_dn is None and entry_data.metadata.extensions:
                extensions = entry_data.metadata.extensions
                if isinstance(extensions, dict):
                    base_dn_ext = extensions.get("base_dn")
                    if isinstance(base_dn_ext, str):
                        base_dn = base_dn_ext
                    dn_registry_ext = extensions.get("dn_registry")
                    if isinstance(dn_registry_ext, FlextLdifModels.DnRegistry):
                        dn_registry = dn_registry_ext
            else:
                # Get dn_registry from write_options
                dn_registry_value = entry_data.metadata.write_options.get("dn_registry")
                if isinstance(dn_registry_value, FlextLdifModels.DnRegistry):
                    dn_registry = dn_registry_value

            return base_dn, dn_registry

        def _create_rfc_dn_replacer(
            self,
            base_dn: str | None,
            dn_registry: FlextLdifModels.DnRegistry | None,
            dn_was_filtered: list[bool],
        ) -> Callable[[re.Match[str]], str]:
            """Create RFC format DN replacement function for re.sub.

            Extracted helper to reduce complexity of _normalize_acl_dns.

            Args:
                base_dn: Optional base DN for filtering
                dn_registry: Optional DN registry for case normalization
                dn_was_filtered: Mutable flag list to track if DN was filtered

            Returns:
                Replacement function for re.sub

            """

            def replace_dn_rfc(match: re.Match[str]) -> str:
                """Replace DN in RFC format ACL string."""
                # Validate regex groups - group(2) may be None if not captured
                prefix_group = match.group(2) or ""
                result = self._normalize_dn_in_acl_string(
                    match.group(1),
                    prefix_group,
                    match.group(3),
                    base_dn,
                    dn_registry,
                )
                if not result:
                    dn_was_filtered[0] = True
                    return match.group(0)  # Keep original if filtered
                return result

            return replace_dn_rfc

        @staticmethod
        def _create_oid_dn_replacer(
            base_dn: str | None,
            dn_registry: FlextLdifModels.DnRegistry | None,
            dn_was_filtered: list[bool],
        ) -> Callable[[re.Match[str]], str]:
            """Create OID legacy format DN replacement function for re.sub.

            Extracted helper to reduce complexity of _normalize_acl_dns.

            Args:
                base_dn: Optional base DN for filtering
                dn_registry: Optional DN registry for case normalization
                dn_was_filtered: Mutable flag list to track if DN was filtered

            Returns:
                Replacement function for re.sub

            """

            def replace_dn_oid(match: re.Match[str]) -> str:
                """Replace DN in OID legacy format ACL string."""
                dn_value = match.group(2)
                # Clean DN: remove spaces after commas (OID quirk fix)
                cleaned_dn = FlextLdifUtilitiesDN.clean_dn(dn_value)

                # Normalize case using dn_registry if available
                if dn_registry and (
                    canonical_dn := dn_registry.get_canonical_dn(cleaned_dn)
                ):
                    cleaned_dn = canonical_dn

                # Filter by base_dn if provided
                if (
                    base_dn
                    and cleaned_dn
                    and not FlextLdifUtilitiesDN.is_under_base(cleaned_dn, base_dn)
                ):
                    dn_was_filtered[0] = True
                    return match.group(0)  # Keep original if filtered

                # Return normalized ACL bind rule (preserve OID format)
                return f'by {match.group(1)}="{cleaned_dn}"'

            return replace_dn_oid

        def _normalize_single_aci_value(
            self,
            aci_value: str,
            base_dn: str | None,
            dn_registry: FlextLdifModels.DnRegistry | None,
        ) -> tuple[str, bool]:
            """Normalize a single ACI value string.

            Extracted helper to reduce complexity of _normalize_acl_dns.

            Args:
                aci_value: ACI attribute value to normalize
                base_dn: Optional base DN for filtering
                dn_registry: Optional DN registry for case normalization

            Returns:
                Tuple of (normalized_aci, was_filtered)

            """
            if not isinstance(aci_value, str):
                return str(aci_value), False

            # Track if any DN was filtered out
            dn_was_filtered: list[bool] = [False]

            # Create replacement functions
            replace_dn_rfc = self._create_rfc_dn_replacer(
                base_dn, dn_registry, dn_was_filtered
            )
            replace_dn_oid = self._create_oid_dn_replacer(
                base_dn, dn_registry, dn_was_filtered
            )

            # First normalize RFC format (userdn/groupdn with ldap:///)
            normalized_aci = re.sub(
                r'(userdn|groupdn)="(ldap:///)?([^"]+)"',
                replace_dn_rfc,
                aci_value,
            )

            # Then normalize OID legacy format (by group="..." or by dn="...")
            normalized_aci = re.sub(
                r'by\s+(group|dn)="([^"]+)"',
                replace_dn_oid,
                normalized_aci,
            )

            return normalized_aci, dn_was_filtered[0]

        def _normalize_acl_dns(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextLdifModels.Entry:
            """Normalize and filter DNs in ACL attribute values (userdn/groupdn inside ACL strings).

            Refactored to reduce complexity from 20 to <10 using 4 helper methods.
            Complexity reduced by extracting:
            - Metadata extraction logic
            - RFC DN replacement factory
            - OID DN replacement factory
            - Single ACI value normalization

            Processes ACL values (aci attribute) to:
            - Normalize DNs: remove spaces after commas, preserve case
            - Filter DNs by base_dn if provided (from entry metadata)

            Args:
                entry_data: Entry with potential ACL attributes

            Returns:
                Entry with normalized/filtered ACL values

            """
            if not entry_data.attributes or not entry_data.attributes.attributes:
                return entry_data

            # Extract base_dn and dn_registry from metadata (helper reduces complexity)
            base_dn, dn_registry = self._extract_acl_normalization_context(entry_data)

            # Process aci attribute values
            attrs = entry_data.attributes.attributes
            if "aci" not in attrs:
                return entry_data

            aci_values = attrs["aci"]
            if not aci_values:
                return entry_data

            # Normalize each ACL value string (helper reduces complexity)
            normalized_aci_values: list[str] = []
            for aci_value in aci_values:
                normalized_aci, was_filtered = self._normalize_single_aci_value(
                    aci_value, base_dn, dn_registry
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

        def _normalize_dn_in_acl_string(
            self,
            acl_type: str,  # "userdn" or "groupdn"
            prefix: str,  # "ldap:///" or ""
            dn_value: str,  # DN value inside ACL
            base_dn: str | None,  # Optional base_dn for filtering
            dn_registry: FlextLdifModels.DnRegistry
            | None = None,  # Optional DN registry for case normalization
        ) -> str:
            """Normalize and filter a single DN inside an ACL string.

            Args:
                acl_type: Type of ACL bind rule ("userdn" or "groupdn")
                prefix: LDAP URL prefix ("ldap:///" or "")
                dn_value: DN value to normalize/filter
                base_dn: Optional base_dn for filtering
                dn_registry: Optional DN registry for case normalization

            Returns:
                Normalized ACL bind rule string (empty if DN was filtered out)

            """
            # Clean DN: remove spaces after commas (OID quirk fix)
            # This fixes: "cn=Group, cn=Sub" -> "cn=Group,cn=Sub"
            cleaned_dn = FlextLdifUtilitiesDN.clean_dn(dn_value)

            # Normalize case using dn_registry if available
            if dn_registry:
                canonical_dn = dn_registry.get_canonical_dn(cleaned_dn)
                if canonical_dn:
                    cleaned_dn = canonical_dn

            # Filter by base_dn if provided (migrate responsibility)
            if (
                base_dn
                and cleaned_dn
                and not FlextLdifUtilitiesDN.is_under_base(cleaned_dn, base_dn)
            ):
                # DN filtered out - return empty string to signal filtering
                return ""

            # Return normalized ACL bind rule
            return f'{acl_type}="{prefix}{cleaned_dn}"'

        def _write_entry(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextResult[str]:
            """Write Entry to LDIF with OUD-specific formatting + phase-aware ACL handling.

            Features:
            1. Schema entries: OUD modify-add format (OUD requirement)
            2. Original entry commenting: Write source entry as commented LDIF block
            3. Phase-aware ACL handling: Comment ACL attributes in non-ACL phases
            4. Standard entries: RFC format

            Args:
                entry_data: Entry model to write

            Returns:
                FlextResult with LDIF string

            """
            # Extract write options from entry metadata
            write_options: FlextLdifModels.WriteFormatOptions | None = None
            if entry_data.metadata.write_options:
                write_options_obj = entry_data.metadata.write_options.get(
                    MetaKeys.WRITE_OPTIONS,
                )
                if isinstance(write_options_obj, FlextLdifModels.WriteFormatOptions):
                    write_options = write_options_obj

            # Build LDIF output (may include multiple blocks)
            ldif_parts: list[str] = []

            # FEATURE 1: Write original entry as comment
            ldif_parts.extend(
                self._add_original_entry_comments(entry_data, write_options),
            )

            # FEATURE 2: Phase-aware ACL attribute handling
            entry_data = self._apply_phase_aware_acl_handling(entry_data, write_options)

            # FEATURE 2.5: Normalize and filter DNs in ACL values (userdn/groupdn inside ACL strings)
            entry_data = self._normalize_acl_dns(entry_data)

            # FEATURE 3: Schema entries use modify-add format (OUD requirement)
            if self._is_schema_entry(entry_data):
                allowed_oids: frozenset[str] | None = None
                if write_options:
                    allowed_oids = getattr(write_options, "allowed_schema_oids", None)
                result = self._write_entry_modify_add_format(entry_data, allowed_oids)
            else:
                # FEATURE 4: Non-schema entries use RFC implementation
                result = super()._write_entry(entry_data)

            if result.is_failure:
                return result

            ldif_parts.append(result.unwrap())

            return FlextResult[str].ok("\n".join(ldif_parts))

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

        def _comment_acl_attributes(
            self,
            entry_data: FlextLdifModels.Entry,
            acl_attr_names: frozenset[str],
        ) -> FlextLdifModels.Entry:
            """Move ACL attributes to metadata (RFC will comment them).

            Moves ACL attributes from entry.attributes to entry_metadata[REMOVED_ATTRIBUTES_WITH_VALUES].
            For OID entries with ACL transformations (orclaci → aci), uses original attribute name.
            The RFC layer's write_removed_attributes_as_comments feature will then write
            them as commented lines in the LDIF output.

            Args:
                entry_data: Entry to process
                acl_attr_names: Set of ACL attribute names to comment (e.g., {'aci'})

            Returns:
                New Entry with ACL attributes moved to metadata using original names from transformations

            """
            return FlextLdifServersOud._comment_acl_attributes_static(
                entry_data,
                acl_attr_names,
            )

        def _separate_acl_attributes(
            self,
            attrs_dict: dict[str, list[str]],
            acl_attr_names: frozenset[str],
        ) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
            """Separate ACL attributes from regular attributes."""
            return FlextLdifServersOud._separate_acl_attributes_static(
                attrs_dict,
                acl_attr_names,
            )

        def _resolve_acl_original_names(
            self,
            entry_data: FlextLdifModels.Entry,
            acl_attrs: dict[str, list[str]],
        ) -> dict[str, list[str]]:
            """Resolve original ACL attribute names from metadata transformations."""
            return FlextLdifServersOud._resolve_acl_original_names_static(
                entry_data,
                acl_attrs,
            )

        def _create_entry_metadata_with_acl_comments(
            self,
            entry_metadata: dict[str, object] | None,
            acl_attrs: dict[str, list[str]],
        ) -> dict[str, object]:
            """Create entry metadata with ACL attributes marked for commenting."""
            return FlextLdifServersOud._create_entry_metadata_with_acl_comments_static(
                entry_metadata,
                acl_attrs,
            )

        def _create_entry_with_acl_comments(
            self,
            entry_data: FlextLdifModels.Entry,
            remaining_attrs: dict[str, list[str]],
            new_entry_metadata: dict[str, object],
        ) -> FlextLdifModels.Entry:
            """Create new entry with ACL attributes moved to metadata."""
            return FlextLdifServersOud._create_entry_with_acl_comments_static(
                entry_data,
                remaining_attrs,
                new_entry_metadata,
            )

        def write(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[str]:
            r"""Public API: Write OUD entry to LDIF format.

            Converts Entry model to LDIF format string.

            Flow:
            1. Call _hook_pre_write_entry() for OUD-specific validation/normalization
            2. Call parent RFC._write_entry() to handle LDIF output (including modify format)

            Args:
                entry: Entry model object (RFC canonical from parsing)

            Returns:
                FlextResult with LDIF formatted entry string

            """
            # Step 1: Apply pre-write hook for OUD-specific normalization
            hook_result = self._hook_pre_write_entry(entry)
            if hook_result.is_failure:
                return FlextResult[str].fail(
                    f"Pre-write hook failed: {hook_result.error}",
                )

            normalized_entry = hook_result.unwrap()

            # Step 2: Call OUD _write_entry() which handles schema entries specially
            # For schema entries, uses modify-add format
            # For other entries, delegates to RFC implementation
            return self._write_entry(normalized_entry)

        def _hook_post_parse_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Hook: Validate OUD ACI macros after parsing Entry.

            When reading OUD LDIF, ACIs may contain macros that require validation:
            - ($dn): substring matching/substitution
            - [$dn]: hierarchical substitution
            - ($attr.attrName): attribute value substitution

            This hook validates macro consistency WITHOUT expanding them
            (runtime expansion happens in OUD directory server).

            Processing:
            1. Validate ACI macro rules if aci: attributes present
            2. Preserve macros as-is (RFC Entry canonical format)
            3. Add metadata notes if macros present

            Args:
                entry: Entry parsed from OUD LDIF (in RFC canonical format)

            Returns:
                FlextResult[Entry] - validated entry, unchanged if valid

            """
            # Extract attributes dict with None check for type safety
            attrs_dict = (
                entry.attributes.attributes if entry.attributes is not None else {}
            )

            # Validate ACI macros if present
            aci_attrs = attrs_dict.get("aci")
            if aci_attrs and isinstance(aci_attrs, list):
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
                    logger.debug(
                        "Entry contains OUD ACI macros - preserved for runtime expansion",
                        entry_dn=entry.dn.value if entry.dn else None,
                        aci_count=len(aci_attrs) if isinstance(aci_attrs, list) else 1,
                        aci_preview=[
                            aci[:FlextLdifServersOud.Constants.MAX_LOG_LINE_LENGTH]
                            if len(aci) > FlextLdifServersOud.Constants.MAX_LOG_LINE_LENGTH
                            else aci
                            for aci in (
                                aci_attrs[:3]
                                if isinstance(aci_attrs, list) and len(aci_attrs) > 3
                                else aci_attrs
                            )
                        ]
                        if isinstance(aci_attrs, list)
                        else [str(aci_attrs)[:FlextLdifServersOud.Constants.MAX_LOG_LINE_LENGTH]],
                    )

            # Entry is RFC-canonical - return unchanged
            return FlextResult[FlextLdifModels.Entry].ok(entry)

        def _validate_aci_macros(self, aci_value: str) -> FlextResult[bool]:
            """Validate OUD ACI macro consistency rules."""
            return FlextLdifServersOud._validate_aci_macros_static(aci_value)

        def _correct_rfc_syntax_in_attributes(
            self,
            attrs_dict: dict[str, object],
        ) -> FlextResult[dict[str, object]]:
            """Correct RFC syntax issues in attribute values (syntax only, not structure)."""
            return FlextLdifServersOud._correct_rfc_syntax_in_attributes_static(attrs_dict)

        def _hook_pre_write_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Hook: Validate and CORRECT RFC syntax issues before writing Entry.

            This hook ensures that Entry data with RFC-valid syntax is properly
            formatted for OUD LDIF output. It does NOT alter data structure
            (attributes, objectClasses, etc.) - only corrects syntax/formatting.

            Corrections applied:
            1. Validate ACI macros (syntax validation)
            2. Ensure attribute values are properly encoded (RFC 2849)
            3. Normalize string values to valid UTF-8 (RFC 2849 requirement)
            4. Ensure all values are strings (convert non-strings)

            IMPORTANT: Does NOT remove attributes, objectClasses, or alter data structure.
            All data is preserved - only syntax/formatting is corrected.

            Args:
                entry: RFC Entry (already canonical, with aci: attributes)

            Returns:
                FlextResult[Entry] - entry with corrected syntax, fail() if syntax errors

            """
            # Extract attributes dict with None check for type safety
            attrs_dict_raw = (
                entry.attributes.attributes if entry.attributes is not None else {}
            )
            # Cast to dict[str, object] for type compatibility with _correct_rfc_syntax_in_attributes
            attrs_dict: dict[str, object] = dict(attrs_dict_raw.items())

            # Step 1: Validate ACI macros if present (syntax validation)
            aci_attrs = attrs_dict.get("aci")
            if aci_attrs and isinstance(aci_attrs, list):
                for aci_value in aci_attrs:
                    if isinstance(aci_value, str):
                        validation_result = self._validate_aci_macros(aci_value)
                        if validation_result.is_failure:
                            return FlextResult[FlextLdifModels.Entry].fail(
                                f"ACI macro validation failed: {validation_result.error}",
                            )

            # Step 2: CORRECT RFC syntax issues in attribute values (syntax only, not structure)
            # Ensure all string values are valid UTF-8 and properly formatted (RFC 2849)
            corrected_result = self._correct_rfc_syntax_in_attributes(attrs_dict)
            if corrected_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(corrected_result.error or "Unknown error")

            corrected_data = corrected_result.unwrap()
            # Type narrowing for syntax_corrections
            syntax_corrections = corrected_data.get("syntax_corrections")
            if (
                syntax_corrections
                and isinstance(syntax_corrections, list)
                and len(syntax_corrections) > 0
            ):
                # Type narrowing for corrected_attributes
                corrected_attrs = corrected_data.get("corrected_attributes")
                if isinstance(corrected_attrs, dict):
                    # Type narrowing: corrected_attrs is dict[str, list[str]] from _correct_rfc_syntax_in_attributes
                    attrs_for_model: dict[str, list[str]] = {
                        k: v if isinstance(v, list) else [str(v)]
                        for k, v in corrected_attrs.items()
                        if isinstance(v, (list, str))
                    }
                    corrected_ldif_attrs = FlextLdifModels.LdifAttributes(
                        attributes=attrs_for_model,
                    )

                    # Create new Entry with corrected attributes (preserve all metadata and structure)
                    corrected_entry = entry.model_copy(
                        update={"attributes": corrected_ldif_attrs},
                    )

                    logger.debug(
                        "OUD quirks: Applied syntax corrections before writing (structure preserved)",
                        entry_dn=entry.dn.value if entry.dn else None,
                        corrections_count=len(syntax_corrections),
                        corrections=syntax_corrections,
                        corrected_attributes=list(corrected_attrs.keys())
                        if isinstance(corrected_attrs, dict)
                        else None,
                    )
                    return FlextResult[FlextLdifModels.Entry].ok(corrected_entry)

            # Entry is RFC-canonical with valid syntax - return unchanged
            # All conversions (orclaci→aci) already done in parsing phase
            return FlextResult[FlextLdifModels.Entry].ok(entry)

        def write_entry_to_ldif(
            self,
            entry_data: dict[str, object],
        ) -> FlextResult[str]:
            r"""Write OUD entry data to standard LDIF string format.

            Converts parsed entry dictionary to LDIF format string.
            Handles Oracle-specific attributes and preserves DN formatting.

            Args:
                entry_data: Parsed OUD entry data dictionary

            Returns:
                FlextResult with LDIF formatted entry string

            Example:
                Input: {FlextLdifConstants.DictKeys.DN: "cn=test,dc=example",
                        FlextLdifConstants.DictKeys.CN: ["test"],
                        FlextLdifConstants.DictKeys.OBJECTCLASS: ["person"]}
                Output: "dn: cn=test,dc=example\\ncn: test\\nobjectClass: person\\n"

            """
            try:
                # Check for required DN field
                if FlextLdifConstants.DictKeys.DN not in entry_data:
                    return FlextResult[str].fail(
                        "Missing required FlextLdifConstants.DictKeys.DN field",
                    )

                dn_raw = entry_data[FlextLdifConstants.DictKeys.DN]
                # Ensure dn is str for string operations
                dn = str(dn_raw) if dn_raw is not None else ""

                # Auto-convert RFC schema DN to OUD schema DN
                schema_dn_prefix = "cn=subschemasubentry"
                if dn.lower().startswith(schema_dn_prefix):
                    dn = FlextLdifServersOud.Constants.SCHEMA_DN

                ldif_lines = [f"dn: {dn}"]

                # Check if this is a schema modification entry
                is_modify = False
                changetype_list = entry_data.get("changetype", [])
                if isinstance(changetype_list, list) and "modify" in changetype_list:
                    is_modify = True
                    ldif_lines.append("changetype: modify")

                # Handle LDIF modify format using utility
                if is_modify and (
                    "_modify_add_attributetypes" in entry_data
                    or "_modify_add_objectclasses" in entry_data
                ):
                    ldif_lines.extend(
                        FlextLdifUtilities.Writer.write_modify_operations(entry_data),
                    )
                else:
                    # Standard entry format - determine attribute order using utility
                    attrs_to_process = (
                        FlextLdifUtilities.Writer.determine_attribute_order(entry_data)
                    )

                    if attrs_to_process is None:
                        # Default ordering: filter out special keys
                        attrs_to_process = [
                            (key, value)
                            for key, value in entry_data.items()
                            if key
                            not in {
                                FlextLdifConstants.DictKeys.DN,
                                "_metadata",
                                FlextLdifConstants.QuirkMetadataKeys.SERVER_TYPE,
                                "changetype",
                                "_acl_attributes",
                            }
                        ]

                    # Extract base64 attributes using utility
                    base64_attrs = FlextLdifUtilities.Writer.extract_base64_attrs(
                        entry_data,
                    )

                    # Write attributes using utilities
                    for attr_name, attr_value in attrs_to_process:
                        # Check if should skip using utility
                        if FlextLdifUtilities.Writer.should_skip_attribute(attr_name):
                            continue

                        # Format attribute lines using utility
                        is_base64 = attr_name in base64_attrs
                        attr_lines = FlextLdifUtilities.Writer.format_attribute_line(
                            attr_name,
                            attr_value,
                            is_base64=is_base64,
                            attribute_case_map=dict(
                                FlextLdifServersOud.Constants.ATTRIBUTE_CASE_MAP,
                            ),
                        )
                        ldif_lines.extend(attr_lines)

                # Join with newlines and add trailing newline
                ldif_string = "\n".join(ldif_lines) + "\n"
                return FlextResult[str].ok(ldif_string)

            except Exception as e:
                return FlextResult[str].fail(f"OUD write entry failed: {e}")

        def _finalize_and_parse_entry(
            self,
            entry_dict: dict[str, object],
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
            # Use _parse_entry which returns Entry RFC canonical
            result = self._parse_entry(dn, entry_dict)
            if result.is_success:
                entries_list.append(result.unwrap())

        def extract_entries_from_ldif(
            self,
            ldif_content: str,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Extract and parse all directory entries from LDIF content.

            Strategy pattern: OUD-specific approach to extract entries from LDIF.

            Args:
                ldif_content: Raw LDIF content containing directory entries

            Returns:
                FlextResult with list of parsed Entry models (RFC canonical)

            """
            try:
                entries: list[FlextLdifModels.Entry] = []
                current_entry: dict[str, object] = {}
                current_attr: str | None = None
                current_values: list[str] = []

                for line in ldif_content.split("\n"):
                    # Empty line indicates end of entry
                    if not line.strip():
                        if current_entry:
                            # Finalize and process entry
                            FlextLdifUtilities.Parser.finalize_pending_attribute(
                                current_attr,
                                current_values,
                                current_entry,
                            )
                            self._finalize_and_parse_entry(current_entry, entries)
                            current_entry = {}
                            current_attr = None
                            current_values = []
                        continue

                    # Skip comments
                    if line.startswith("#"):
                        continue

                    # Continuation line (starts with space)
                    if line.startswith(" ") and current_attr and current_values:
                        current_values[-1] += line[1:]  # Remove leading space
                        continue

                    # Process new attribute line using utility
                    current_attr, current_values = (
                        FlextLdifUtilities.Parser.process_ldif_attribute_line(
                            line,
                            current_attr,
                            current_values,
                            current_entry,
                        )
                    )

                # Process final entry
                if current_entry:
                    FlextLdifUtilities.Parser.finalize_pending_attribute(
                        current_attr,
                        current_values,
                        current_entry,
                    )
                    self._finalize_and_parse_entry(current_entry, entries)

                return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

            except Exception as e:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"OUD entry extraction failed: {e}",
                )

        def _inject_validation_rules(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextLdifModels.Entry:
            """Inject OUD-specific validation rules into Entry metadata via DI."""
            return FlextLdifServersOud._inject_validation_rules_static(entry)


__all__ = ["FlextLdifServersOud"]
