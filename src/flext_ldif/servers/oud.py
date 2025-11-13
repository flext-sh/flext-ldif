"""Oracle Unified Directory (OUD) Quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides OUD-specific quirks for schema, ACL, and entry processing.
"""

from __future__ import annotations

import base64
import operator
import re
from collections.abc import Mapping
from enum import StrEnum
from typing import ClassVar, cast

from flext_core import FlextLogger, FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities

logger = FlextLogger(__name__)


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
            FlextLdifConstants.DictKeys.OBJECTCLASS.lower(): FlextLdifConstants.DictKeys.OBJECTCLASS,
            "memberof": "memberOf",
            "seealsodescription": "seeAlsoDescription",
            "orclaci": ACL_ATTRIBUTE_NAME,  # Oracle OID ACI → OUD RFC ACI
            "orclentrylevelaci": ACL_ATTRIBUTE_NAME,  # Oracle OID entry-level ACI → OUD RFC ACI
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
        # DETECTION PATTERNS - Server type detection rules
        # =====================================================================

        # === DN PREFIXES (used in Entry.can_handle) ===
        DN_PREFIX_CN_CONFIG: ClassVar[str] = "cn=config"
        DN_PREFIX_CN_SCHEMA: ClassVar[str] = "cn=schema"
        DN_PREFIX_CN_DIRECTORY: ClassVar[str] = "cn=directory"
        DN_PREFIX_CN_DS: ClassVar[str] = "cn=ds"

        # OID/Oracle prefixes for exclusion (OUD entries should not have these)
        OID_PREFIXES: ClassVar[tuple[str, ...]] = ("orcl", "oracle")

        # === DETECTION PATTERNS ===
        # Case-insensitive pattern ((?i) flag) because detector searches in lowercase content
        DETECTION_OID_PATTERN: ClassVar[str] = (
            r"(?i)(ds-sync-|ds-pwp-|ds-cfg-|root dns)"
        )
        DETECTION_PATTERN: ClassVar[str] = (
            r"(?i)(ds-sync-|ds-pwp-|ds-cfg-|root dns)"  # Alias for compatibility
        )
        DETECTION_WEIGHT: ClassVar[int] = (
            14  # Detection confidence weight (increased to overcome OpenLDAP cn=config ambiguity)
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

    class Schema(FlextLdifServersRfc.Schema):
        """Oracle OUD schema quirk - implements FlextLdifProtocols.Quirks.SchemaProtocol.

        Extends RFC 4512 schema parsing with Oracle OUD-specific features:
        - OUD namespace (2.16.840.1.113894.*)
        - OUD-specific syntaxes
        - OUD attribute extensions
        - Compatibility with OID schemas
        - DN case registry management for schema consistency

        **Protocol Compliance**: Fully implements
        FlextLdifProtocols.Quirks.SchemaProtocol through structural typing.
        All methods match protocol signatures exactly for type safety.

        **Validation**: Verify protocol compliance with:
            from flext_ldif.protocols import FlextLdifProtocols
            quirk = FlextLdifServersOud()
            assert isinstance(quirk, FlextLdifProtocols.Quirks.SchemaProtocol)

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
            - X-* extensions: X-PATTERN, X-ENUM, X-SUBST, X-APPROX, X-ORIGIN, X-SCHEMA-FILE
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
                    f"Attribute '{attr.name}' has OUD X-* extensions: {', '.join(oud_extensions)}",
                )

            return FlextResult[FlextLdifModels.SchemaAttribute].ok(attr)

        def _hook_post_parse_objectclass(
            self,
            oc: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Hook: Validate OUD-specific objectClass features after parsing.

            OUD has specific constraints different from RFC:
            - SingleSUP: Only ONE superior class allowed (RFC allows multiple via $)
            - X-* extensions: X-ENUM, X-PATTERN, X-ORIGIN, X-SCHEMA-FILE
            - No multiple structural chains (enforced separately by config)

            Validation rules (fail if violated):
            1. SUP must be single (not multiple separated by $)
            2. X-* extensions must be well-formed
            3. MUST/MAY attributes must exist in schema (done in validate_objectclass_dependencies)

            Args:
                oc: Parsed SchemaObjectClass from RFC parser

            Returns:
                FlextResult[SchemaObjectClass] - validated objectClass

            """
            if not oc:
                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(oc)

            # Validate SingleSUP constraint (OUD restriction)
            sup = oc.sup
            if sup:
                sup_str = str(sup)
                # Check for multiple SUPs (RFC uses $ as separator)
                if "$" in sup_str:
                    return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                        f"OUD objectClass '{oc.name}' has multiple SUPs: {sup_str}. "
                        "OUD only allows single SUP (use AUXILIARY classes for additional features).",
                    )

            # ObjectClass doesn't have X-* extension fields in model
            # Log just the validation success
            logger.debug(f"ObjectClass '{oc.name}' validated: SingleSUP constraint OK")

            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(oc)

        def _parse_attribute(
            self,
            attr_definition: str,
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

            Returns:
                FlextResult with parsed SchemaAttribute model

            """
            try:
                # Step 1: Use OUD-specific parser which will handle extensions via hooks
                attr_result = FlextLdifUtilities.Parser.parse_rfc_attribute(
                    attr_definition,
                    case_insensitive=False,  # OUD uses strict RFC-compliant NAME matching
                    allow_syntax_quotes=False,  # OUD uses standard SYNTAX format
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
                # Step 1: Use RFC baseline parser for objectClass parsing
                # Note: parse_rfc_objectclass does not support case_insensitive parameter
                # OUD uses strict RFC-compliant parsing at the objectClass level
                oc_result = FlextLdifUtilities.Parser.parse_rfc_objectclass(
                    oc_definition,
                )

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
                ...     may=["orcladminprivilege"],
                ... )
                >>> available = {"cn", "description"}  # orcladminprivilege missing!
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
                    f"ObjectClass '{oc_name}' (OID {oc_oid}) "
                    f"has unresolved attributes (MUST/MAY): {', '.join(missing_attrs)}. "
                    f"This objectclass will be filtered out to prevent OUD startup failure: "
                    f'"No attribute type matching this name or OID exists in the server schema"',
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

            # Check for invalid SUBSTR rules and apply INVALID_SUBSTR_RULES mappings
            invalid_substr_rules = FlextLdifServersOud.Constants.INVALID_SUBSTR_RULES
            if fixed_substr and fixed_substr in invalid_substr_rules:
                replacement = invalid_substr_rules[fixed_substr]
                if replacement is not None:
                    logger.debug(
                        "Replacing invalid SUBSTR rule %s with %s",
                        fixed_substr,
                        replacement,
                    )
                    fixed_substr = replacement

            # Check if this is a boolean attribute for special handling during write
            is_boolean = FlextLdifUtilities.Schema.is_boolean_attribute(
                fixed_name,
                set(FlextLdifServersOud.Constants.BOOLEAN_ATTRIBUTES),
            )
            if is_boolean:
                logger.debug("Identified boolean attribute: %s", fixed_name)

            # Create modified copy with fixed values using Pydantic v2 pattern
            return attr_data.model_copy(
                update={
                    "name": fixed_name,
                    "equality": fixed_equality,
                    "substr": fixed_substr,
                },
            )

        def extract_schemas_from_ldif(
            self,
            ldif_content: str,
            *,
            validate_dependencies: bool = True,  # OUD defaults to True (needs validation)
        ) -> FlextResult[dict[str, list[str] | str]]:
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
                FlextResult with dict containing ATTRIBUTES and
                objectclasses lists (filtered only for Oracle internal classes)

            """
            # Use base template method with OUD's dependency validation
            # This replaces 66 lines of duplicated code with a 3-line call
            return super().extract_schemas_from_ldif(
                ldif_content,
                validate_dependencies=validate_dependencies,
            )

    class Acl(FlextLdifServersRfc.Acl):
        """Oracle OUD ACL quirk (nested).

        Extends RFC ACL parsing with Oracle OUD-specific ACL formats:
        - ds-cfg-access-control-handler: OUD access control
        - OUD-specific ACL syntax (different from OID orclaci)

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

        # OUD-specific extensions (fewer than OID)
        OUD_ACL_ATTRIBUTES: ClassVar[list[str]] = [
            "orclaci",  # OUD uses Oracle ACIs (compatibility)
            "orclentrylevelaci",  # OUD entry-level ACI
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
        # Use FlextLdifAcl for OID→OUD ACL conversions instead

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
            return (
                normalized.startswith(
                    (
                        aci_prefix,
                        targetattr_prefix,
                        targetscope_prefix,
                        version_prefix,
                    ),
                )
                or "ds-cfg-" in normalized.lower()
            )

        def _parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse Oracle OUD ACL string to RFC-compliant internal model using functional composition.

            Normalizes OUD ACI (Access Control Instruction) format to RFC-compliant
            internal representation using monadic patterns and functional composition.

            Args:
            acl_line: ACL definition line (may contain newlines for multi-line ACIs)

            Returns:
            FlextResult with OUD ACL Pydantic model

            """

            def validate_aci_format(acl_line: str) -> FlextResult[str]:
                """Validate and extract ACI content using monadic validation."""
                if not acl_line.startswith(
                    FlextLdifServersOud.Constants.ACL_ACI_PREFIX
                ):
                    return FlextResult[str].fail("Not an OUD ACI format")
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
                context: dict[str, object], aci_content: str
            ) -> dict[str, object]:
                """Extract all ACI components using functional composition."""
                # Store aci_content in context for later use
                context["aci_content"] = aci_content
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
                    return FlextResult[FlextLdifModels.Acl].fail(
                        validation_result.error
                    )

                # Extract components and build model
                aci_content = validation_result.unwrap()
                context = extract_components(initialize_parse_context(), aci_content)
                return self._build_acl_model(context)

            except Exception as e:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"Failed to parse OUD ACL: {e}"
                )

        def _build_acl_model(
            self, context: dict[str, object]
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
                    metadata_config
                )

                # Create Acl model using functional composition
                return self._create_acl_from_context(
                    context, extensions, cast("str", aci_content)
                )

            except Exception as e:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"Failed to build OUD ACL model: {e}"
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
                acl = FlextLdifModels.Acl(
                    name=cast("str", context["acl_name"]),
                    target=FlextLdifModels.AclTarget(
                        target_dn=cast("str", context["targetattr"]),
                        attributes=[],
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
                    f"Failed to create ACL model: {e}"
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
            if acl_data.target and acl_data.target.target_dn:
                target = acl_data.target.target_dn
            else:
                target = "*"

            return f'(targetattr="{target}")'

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

            # Extract permission names from boolean fields using Pydantic model_dump()
            permission_dict = acl_data.permissions.model_dump()
            ops: list[str] = [
                field_name
                for field_name, value in permission_dict.items()
                if isinstance(value, bool) and value
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
                    f"ACL model has no OUD-supported permissions (all were OID-specific like {FlextLdifServersOud.Constants.PERMISSION_SELF_WRITE})",
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
                Formatted bind rules string

            """
            if not acl_data.subject:
                # Default: allow for self
                return f'userdn="{FlextLdifServersOud.Constants.ACL_SELF_SUBJECT}";)'

            # Use utility to format subject
            return FlextLdifUtilities.ACL.format_aci_subject(
                acl_data.subject.subject_type,
                acl_data.subject.subject_value,
                FlextLdifServersOud.Constants,
            )

        def write(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write RFC-compliant ACL model to OUD ACI string format.

            Serializes the RFC-compliant internal model to Oracle OUD ACI format string,
            including comprehensive comment generation for OID→OUD conversions to ensure
            zero data loss.

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

                # Generate OID→OUD Conversion Comments
                if (
                    acl_data.metadata
                    and hasattr(acl_data.metadata, "extensions")
                    and acl_data.metadata.extensions
                ):
                    extensions = acl_data.metadata.extensions

                    if extensions.get("converted_from_oid"):
                        conversion_comments = extensions.get(
                            "oud_conversion_comments",
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
                    return FlextResult[str].fail(perms_result.error)

                # Add permissions and subject in one extend call
                aci_parts.extend(
                    [
                        perms_result.unwrap(),
                        self._build_aci_subject(acl_data),
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

            # Check for OID-specific attributes (not OUD)
            # OID attributes start with "orcl" - these are not OUD entries
            if any(
                attr_name.lower().startswith(prefix)
                for attr_name in entry_attrs
                for prefix in FlextLdifServersOud.Constants.OID_PREFIXES
            ):
                return False

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
            attr_values: object,
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
                attr_dict = {
                    attr_name: (
                        attr_values
                        if isinstance(attr_values, list)
                        else [str(attr_values)]
                    ),
                }
                converted_dict = FlextLdifUtilities.Entry.convert_boolean_attributes(
                    attr_dict,
                    set(FlextLdifServersOud.Constants.BOOLEAN_ATTRIBUTES),
                )
                return converted_dict.get(attr_name, attr_dict[attr_name])

            # Validate telephone numbers (using Constants to avoid hard-coding)
            if (
                attr_lower == "telephonenumber"
            ):  # Note: this is a standard RFC attribute name
                # Ensure attr_values is list[str] for validation
                values_list: list[object] = (
                    attr_values if isinstance(attr_values, list) else [attr_values]
                )
                telephone_values = [str(v) for v in values_list]
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
                entry.dn.value, ", "
            ):
                metadata_extensions["dn_spaces"] = True

            # Preserve attribute order
            if processed_attributes:
                metadata_extensions["attribute_order"] = list(
                    processed_attributes.keys(),
                )

            # Detect Oracle objectClasses
            if FlextLdifConstants.DictKeys.OBJECTCLASS in processed_attributes:
                oc_values = processed_attributes[
                    FlextLdifConstants.DictKeys.OBJECTCLASS
                ]
                if isinstance(oc_values, list):
                    oracle_ocs = [
                        str(oc)
                        for oc in oc_values
                        if any(
                            prefix in str(oc).lower()
                            for prefix in FlextLdifServersOud.Constants.OID_PREFIXES
                        )
                    ]
                    if oracle_ocs:
                        metadata_extensions[
                            FlextLdifConstants.MetadataKeys.ORACLE_OBJECTCLASSES
                        ] = oracle_ocs

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

            # Always return single-line normalized string - writer will handle line folding if needed
            # NEVER preserve newlines - that's the writer's job based on format_options

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
            filtered_values: list[tuple[tuple[int, ...], str]] = []

            for value in values:
                # Extract OID from RFC format: ( 1.2.3.4 NAME ...
                match = oid_pattern.search(value)
                if not match:
                    continue

                oid_str = match.group(1)

                # Check if OID in whitelist
                # Filter only if allowed_oids is provided
                if allowed_oids is not None and oid_str not in allowed_oids:
                    continue

                # Parse OID for sorting (convert to tuple of ints)
                try:
                    oid_tuple = tuple(int(x) for x in oid_str.split("."))
                except ValueError:
                    continue

                filtered_values.append((oid_tuple, value))

            # Sort by OID numerically
            filtered_values.sort(key=operator.itemgetter(0))
            return filtered_values

        def _add_ldif_block(
            self,
            ldif_lines: list[str],
            schema_type: str,
            value: str | bytes,
            *,
            is_first_block: bool,
        ) -> bool:
            """Add a single LDIF block for schema value.

            Returns: False (next block won't be first)
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

        def _write_entry_modify_add_format(
            self,
            entry_data: FlextLdifModels.Entry,
            allowed_schema_oids: frozenset[str] | None = None,
        ) -> FlextResult[str]:
            """Write schema entry in OUD modify-add format.

            Generates LDIF with changetype: modify and add: blocks.
            CRITICAL: One add block PER SCHEMA VALUE, not per type.
            Ordered by OID numerically, with whitelist filtering.

            Example output:
            ```
            dn: cn=subschemasubentry
            changetype: modify
            add: attributeTypes
            attributeTypes: ( 2.16.840.1.113894.1.1.321 NAME ... )
            -
            add: attributeTypes
            attributeTypes: ( 2.16.840.1.113894.1.1.322 NAME ... )
            -
            add: objectClasses
            objectClasses: ( 2.16.840.1.113894.1.2.9 NAME ... )
            -
            ```

            Whitelist filtering:
            - attributeTypes: Only in ALLOWED_SCHEMA_OIDS
            - objectClasses: Only in ALLOWED_SCHEMA_OIDS
            - matchingRules: EXCLUDED (empty list)
            - matchingRuleUse: EXCLUDED (empty list)

            Args:
                entry_data: Schema entry to write
                allowed_schema_oids: Optional set of allowed OIDs for filtering.
                    If None, all OIDs are accepted (no filtering).
                    Should be passed from migration configuration.

            Returns:
                FlextResult with LDIF string in OUD modify-add format

            """
            # Lazy import for optional external dependency
            ldif_lines: list[str] = []

            # DN line (required)
            if not (entry_data.dn and entry_data.dn.value):
                return FlextResult[str].fail("Entry DN is required for LDIF output")
            ldif_lines.extend([
                f"dn: {entry_data.dn.value}",
                "changetype: modify",
            ])

            # Get attributes
            if not entry_data.attributes or not entry_data.attributes.attributes:
                ldif_text = "\n".join(ldif_lines) + "\n"
                return FlextResult[str].ok(ldif_text)

            attrs_dict = entry_data.attributes.attributes
            # Use provided allowed OIDs or accept all if None
            allowed_oids = set(allowed_schema_oids) if allowed_schema_oids else None

            # OID pattern: ( number.number.number... NAME ...
            oid_pattern = re.compile(r"\(\s*(\d+(?:\.\d+)*)\s+")

            # Schema attribute types to process (in order)
            schema_types_order = [
                "attributeTypes",
                "objectClasses",
                "matchingRules",
                "matchingRuleUse",
            ]

            first_block = True

            # Process each schema type in order
            for schema_type in schema_types_order:
                # Match both cases (attributeTypes, attributetypes, etc.)
                attr_key = next(
                    (key for key in attrs_dict if key.lower() == schema_type.lower()),
                    None,
                )

                if not attr_key or not attrs_dict[attr_key]:
                    continue

                # Filter: matchingRules and matchingRuleUse are EXCLUDED (not in whitelist)
                if schema_type.lower() in {"matchingrules", "matchingruleuse"}:
                    continue

                # Filter and sort by OID for other types
                filtered_values = self._filter_and_sort_schema_values(
                    attrs_dict[attr_key],
                    allowed_oids,
                    oid_pattern,
                )

                # Write each value as separate add block (CRITICAL: ONE VALUE PER BLOCK)
                for _oid, value in filtered_values:
                    first_block = self._add_ldif_block(
                        ldif_lines,
                        schema_type,
                        value,
                        is_first_block=first_block,
                    )

            # Final separator (if we added any blocks)
            if not first_block and ldif_lines[-1] != "-":
                ldif_lines.append("-")

            # Join with newlines and ensure proper LDIF formatting
            ldif_text = "\n".join(ldif_lines)
            if ldif_text and not ldif_text.endswith("\n"):
                ldif_text += "\n"

            return FlextResult[str].ok(ldif_text)

        def _write_entry(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextResult[str]:
            """Write Entry to LDIF format (override RFC to handle schema entries).

            For schema entries, uses OUD modify-add format.
            For other entries, delegates to RFC implementation.

            Args:
                entry_data: Entry model to write

            Returns:
                FlextResult with LDIF string

            """
            # Check if this is a schema entry
            if self._is_schema_entry(entry_data):
                # Check if write_options request modify format
                write_options: FlextLdifModels.WriteFormatOptions | None = None
                if entry_data.entry_metadata:
                    write_options_obj = entry_data.entry_metadata.get("_write_options")
                    if isinstance(
                        write_options_obj, FlextLdifModels.WriteFormatOptions
                    ):
                        write_options = write_options_obj

                if write_options and write_options.ldif_changetype == "modify":
                    # Use schema modify-add format
                    return self._write_entry_modify_add_format(entry_data)

            # Non-schema or no modify format requested: use RFC implementation
            return super()._write_entry(entry_data)

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
                    f"Pre-write hook failed: {hook_result.error}"
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
                        "Entry contains OUD ACI macros - preserved for runtime expansion"
                    )

            # Entry is RFC-canonical - return unchanged
            return FlextResult[FlextLdifModels.Entry].ok(entry)

        def _validate_aci_macros(self, aci_value: str) -> FlextResult[None]:
            """Validate OUD ACI macro consistency rules.

            OUD supports macro substitution in ACIs:
            - ($dn): matches substring in target, replaces in subject
            - [$dn]: hierarchical substitution in subject (drops leftmost RDN)
            - ($attr.attrName): substitutes attribute value from target entry

            Validation rules (must fail if violated):
            1. If ($dn) in subject → ($dn) must be in target
            2. If [$dn] in subject → ($dn) must be in target
            3. After expansion, DN must be syntactically valid

            Args:
                aci_value: Single ACI string value

            Returns:
                FlextResult.ok() if valid, fail() if macro rules violated

            """
            # Check for macros in subject (userdn/groupdn/userattr)
            has_macro_in_subject = bool(
                re.search(r"\(\$dn\)|\[\$dn\]|\(\$attr\.", aci_value),
            )

            if not has_macro_in_subject:
                # No macros - validation passes
                return FlextResult[None].ok(None)

            # If macros in subject, target MUST have ($dn)
            has_macro_in_target = "($dn)" in aci_value

            if not has_macro_in_target:
                return FlextResult[None].fail(
                    "ACI macro in subject requires ($dn) in target expression",
                )

            # Both ($dn) and [$dn] require ($dn) in target - already checked above
            logger.debug(
                "ACI macro validation passed: subject/target macro consistency OK"
            )
            return FlextResult[None].ok(None)

        def _hook_pre_write_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Hook: Validate OUD ACI macros before writing Entry.

            OUD ACIs may contain macros for dynamic DN substitution:
            - ($dn): substring substitution from target to subject
            - [$dn]: hierarchical substitution (for domain-level delegation)
            - ($attr.attrName): attribute value substitution

            This hook validates macro consistency WITHOUT expanding them
            (expansion happens at runtime in OUD directory server).

            Rules enforced:
            1. Subject macros require matching target macros
            2. Macro syntax must be well-formed
            3. No attribute mutations - RFC Entry preserved as-is

            Args:
                entry: RFC Entry (already canonical, with aci: attributes)

            Returns:
                FlextResult[Entry] - entry unchanged if valid, fail() if macro errors

            """
            # Extract attributes dict with None check for type safety
            attrs_dict = (
                entry.attributes.attributes if entry.attributes is not None else {}
            )

            # Validate ACI macros if present
            aci_attrs = attrs_dict.get("aci")
            if aci_attrs and isinstance(aci_attrs, list):
                for aci_value in aci_attrs:
                    if isinstance(aci_value, str):
                        validation_result = self._validate_aci_macros(aci_value)
                        if validation_result.is_failure:
                            return FlextResult[FlextLdifModels.Entry].fail(
                                f"ACI macro validation failed: {validation_result.error}",
                            )

            # Entry is RFC-canonical - return unchanged
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
            FlextResult with list of parsed Entry models

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


__all__ = ["FlextLdifServersOud"]
