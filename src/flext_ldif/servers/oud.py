"""Oracle Unified Directory (OUD) Quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides OUD-specific quirks for schema, ACL, and entry processing.
"""

from __future__ import annotations

import operator
import re
from collections.abc import Mapping
from typing import ClassVar, Final

from flext_core import FlextLogger, FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities

logger = FlextLogger(__name__)


class FlextLdifServersOud(FlextLdifServersRfc):
    """Oracle Unified Directory (OUD) Quirks."""

    # === STANDARDIZED CONSTANTS FOR AUTO-DISCOVERY ===
    class Constants(FlextLdifServersRfc.Constants):
        """Oracle Unified Directory-specific constants centralized for operations in oud.py.

        These constants follow a standardized naming pattern that can be replicated
        in other server quirks implementations for consistency.
        """

        # === STANDARDIZED CONSTANTS FOR AUTO-DISCOVERY ===
        SERVER_TYPE: ClassVar[str] = FlextLdifConstants.ServerTypes.OUD
        CANONICAL_NAME: ClassVar[str] = "oud"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["oud", "oracle_oud"])
        PRIORITY: ClassVar[int] = 10
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["oud", "rfc"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["oud", "rfc"])

        # Server-specific boolean attributes
        BOOLEAN_ATTRIBUTES: Final[frozenset[str]] = frozenset(
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
            ]
        )

        # Oracle OUD operational attributes (server-specific)
        OPERATIONAL_ATTRIBUTES: Final[frozenset[str]] = frozenset(
            [
                "ds-sync-hist",
                "ds-sync-state",
                "ds-pwp-account-disabled",
                "ds-cfg-backend-id",
                "entryUUID",  # OUD specific version
            ]
        )

        # Oracle Unified Directory ACL format constants
        ACL_FORMAT: ClassVar[str] = "aci"  # RFC 4876 ACI attribute
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"  # ACL attribute name

        # DN prefixes for pattern matching (used in Entry.can_handle)
        DN_PREFIX_CN_CONFIG: Final[str] = "cn=config"
        DN_PREFIX_CN_SCHEMA: Final[str] = "cn=schema"
        DN_PREFIX_CN_DIRECTORY: Final[str] = "cn=directory"
        DN_PREFIX_CN_DS: Final[str] = "cn=ds"

        # Detection constants (server-specific)
        DETECTION_OID_PATTERN: Final[str] = r"(ds-sync-|ds-pwp-|ds-cfg-)"
        DETECTION_ATTRIBUTE_PREFIXES: Final[frozenset[str]] = frozenset(
            [
                "ds-",
                "ds-sync",
                "ds-pwp",
                "ds-cfg",
            ]
        )
        DETECTION_OBJECTCLASS_NAMES: Final[frozenset[str]] = frozenset(
            [
                "ds-root-dse",
                "ds-unbound-id-config",
                "ds-cfg-backend",
            ]
        )
        DETECTION_DN_MARKERS: Final[frozenset[str]] = frozenset(
            [
                "cn=config",
                "cn=tasks",
                "cn=monitor",
            ]
        )
        DETECTION_ACL_PREFIX: Final[str] = "ds-cfg-"  # OUD configuration ACL prefix

        # === SCHEMA PROCESSING CONFIGURATION ===
        # Schema fields that should be processed with OID filtering
        SCHEMA_FILTERABLE_FIELDS: Final[frozenset[str]] = frozenset(
            [
                FlextLdifConstants.SchemaFields.ATTRIBUTE_TYPES,
                FlextLdifConstants.SchemaFields.ATTRIBUTE_TYPES_LOWER,
                FlextLdifConstants.SchemaFields.OBJECT_CLASSES,
                FlextLdifConstants.SchemaFields.OBJECT_CLASSES_LOWER,
                FlextLdifConstants.SchemaFields.MATCHING_RULES,
                FlextLdifConstants.SchemaFields.LDAP_SYNTAXES,
            ]
        )

        # Schema DN for OUD (different from OID's cn=subschemasubentry)
        SCHEMA_DN: Final[str] = "cn=schema"

        # OUD specific operational attributes (alias for OPERATIONAL_ATTRIBUTES for compatibility)
        OUD_SPECIFIC: Final[frozenset[str]] = frozenset(
            [
                "ds-sync-hist",
                "ds-sync-state",
                "ds-pwp-account-disabled",
                "ds-cfg-backend-id",
                "entryUUID",  # OUD specific version
            ]
        )

        # ACL-specific subject constants (migrated from nested Acl class)
        ACL_DEFAULT_NAME: Final[str] = "Anonymous ACL"  # Default ACL name for OUD
        ACL_SELF_SUBJECT: Final[str] = "ldap:///self"  # OUD self subject
        ACL_ANONYMOUS_SUBJECT: Final[str] = "ldap:///anyone"  # OUD anonymous subject
        ACL_ANONYMOUS_SUBJECT_ALT: Final[str] = (
            "ldap:///*"  # OUD anonymous subject alternative
        )
        ACL_VERSION_PREFIX: Final[str] = "(version 3.0"  # OUD ACI version prefix
        ACL_LDAP_URL_PREFIX: Final[str] = "ldap:///"  # OUD LDAP URL prefix for subjects
        ACL_ACI_PREFIX: Final[str] = "aci:"  # OUD ACI attribute prefix
        ACL_PERMISSION_SELF_WRITE: Final[str] = (
            "self_write"  # OUD self_write permission (OID-specific, promoted to write)
        )
        ACL_ALLOW_PREFIX: Final[str] = "allow ("  # OUD allow clause prefix
        ACL_TARGETATTR_PREFIX: Final[str] = "targetattr="  # OUD targetattr prefix
        ACL_TARGETSCOPE_PREFIX: Final[str] = "targetscope="  # OUD targetscope prefix
        ACL_DS_CFG_PREFIX: Final[str] = "ds-cfg-"  # OUD configuration ACL prefix

        # ACL parsing patterns (migrated from _write_acl method)
        ACL_BY_GROUP_PATTERN: Final[str] = r"by\s+group=\"[^\"]+\""
        ACL_BY_STAR_PATTERN: Final[str] = r"by\s+\*"

        # ACL parsing patterns (migrated from _parse_acl method)
        ACL_TARGETATTR_PATTERN: Final[str] = r'\(targetattr\s*(!?=)\s*"([^"]+)"\)'
        ACL_TARGETSCOPE_PATTERN: Final[str] = r'\(targetscope\s*=\s*"([^"]+)"\)'
        ACL_VERSION_ACL_PATTERN: Final[str] = r'version\s+([\d.]+);\s*acl\s+"([^"]+)"'
        ACL_ALLOW_DENY_PATTERN: Final[str] = r"(allow|deny)\s+\(([^)]+)\)"
        ACL_USERDN_PATTERN: Final[str] = r'userdn\s*=\s*"([^"]+)"'
        ACL_GROUPDN_PATTERN: Final[str] = r'groupdn\s*=\s*"([^"]+)"'
        ACL_ACTION_ALLOW: Final[str] = "allow"
        ACL_ACTION_DENY: Final[str] = "deny"

        # ACL parsing constants (migrated from _parse_acl method)
        ACL_NEWLINE_SEPARATOR: Final[str] = "\n"

        # ACL bind rule types (migrated from _parse_acl method)
        ACL_BIND_RULE_TYPE_USERDN: Final[str] = "userdn"
        ACL_BIND_RULE_TYPE_GROUPDN: Final[str] = "groupdn"
        ACL_BIND_RULE_KEY_TYPE: Final[str] = "type"
        ACL_BIND_RULE_KEY_VALUE: Final[str] = "value"

        # ACL subject types (migrated from _parse_acl method)
        ACL_SUBJECT_TYPE_BIND_RULES: Final[str] = "bind_rules"

        # ACL operation parsing constants (migrated from _parse_acl method)
        ACL_OPS_SEPARATOR: Final[str] = ","

        # ACL permission keys (migrated from _parse_acl method)
        ACL_PERM_KEY_READ: Final[str] = "read"
        ACL_PERM_KEY_WRITE: Final[str] = "write"
        ACL_PERM_KEY_ADD: Final[str] = "add"
        ACL_PERM_KEY_DELETE: Final[str] = "delete"
        ACL_PERM_KEY_SEARCH: Final[str] = "search"
        ACL_PERM_KEY_COMPARE: Final[str] = "compare"
        ACL_PERM_KEY_PROXY: Final[str] = "proxy"

        # Attribute name casing map: lowercase source → proper OUD camelCase
        # Maps common LDAP attributes with incorrect casing to OUD-expected camelCase
        # Note: ACL_ATTRIBUTE_NAME is "aci" (OUD uses RFC 4876 ACI)
        ATTRIBUTE_CASE_MAP: Final[dict[str, str]] = {
            "uniquemember": "uniqueMember",
            "displayname": "displayName",
            "distinguishedname": "distinguishedName",
            "objectclass": "objectClass",
            "memberof": "memberOf",
            "seealsodescription": "seeAlsoDescription",
            "orclaci": ACL_ATTRIBUTE_NAME,  # Oracle OID ACI → OUD RFC ACI
            "orclentrylevelaci": ACL_ATTRIBUTE_NAME,  # Oracle OID entry-level ACI → OUD RFC ACI
            "acl": ACL_ATTRIBUTE_NAME,  # Generic ACL → OUD RFC ACI
        }

        # OUD supported ACL rights (migrated from _parse_acl method)
        OUD_SUPPORTED_RIGHTS: Final[frozenset[str]] = frozenset(
            [
                "read",
                "write",
                "add",
                "delete",
                "search",
                "compare",
                "selfwrite",
                "proxy",
            ]
        )

        # OUD ACL parsing constants (migrated from Acl class)
        ACL_DEFAULT_TARGETATTR: Final[str] = "*"
        ACL_DEFAULT_VERSION: Final[str] = "version 3.0"

        # Schema attribute transformation constants (migrated from ObjectClassWriter)
        ATTRIBUTE_UNDERSCORE_TO_DASH: Final[str] = "_"
        ATTRIBUTE_DASH_REPLACEMENT: Final[str] = "-"

        # === OUD ACL SUBJECT TRANSFORMATIONS ===
        # Subject type transformations from RFC format to OUD format
        RFC_TO_OUD_SUBJECTS: Final[dict[str, tuple[str, str]]] = {
            "group_membership": ("bind_rules", 'userattr="{value}#LDAPURL"'),
            "user_attribute": ("bind_rules", 'userattr="{value}#USERDN"'),
            "group_attribute": ("bind_rules", 'userattr="{value}#GROUPDN"'),
        }

        # Subject type transformations from OUD format back to RFC format
        OUD_TO_RFC_SUBJECTS: Final[dict[str, tuple[str, str]]] = {
            "bind_rules": ("group_membership", "{value}"),
        }

        # === MATCHING RULE VALIDATIONS & REPLACEMENTS ===
        # Matching rules that are invalid for SUBSTR operations
        INVALID_SUBSTR_RULES: Final[dict[str, str | None]] = {
            "caseIgnoreMatch": "caseIgnoreSubstringsMatch",  # Common SUBSTR mistake
            "distinguishedNameMatch": None,  # No valid SUBSTR replacement
            "caseIgnoreOrderingMatch": None,  # No SUBSTR variant
            "numericStringMatch": "numericStringSubstringsMatch",  # Corrected
        }

        # Matching rules that need replacement for OUD compatibility
        MATCHING_RULE_REPLACEMENTS: Final[dict[str, str]] = {
            "caseIgnoreMatch": "caseIgnoreMatch",  # Keep as-is in OUD
            "caseIgnoreSubstringsMatch": "caseIgnoreSubstringsMatch",  # Standard
        }

        # === ATTRIBUTE TRANSFORMATION MAPPINGS ===
        # OUD→RFC attribute name transformations (for compatibility)
        ATTRIBUTE_TRANSFORMATION_OUD_TO_RFC: Final[dict[str, str]] = {
            "ds-sync-hist": "dsyncHist",  # OUD proprietary
            "ds-pwp-account-disabled": "accountDisabled",  # OUD password policy
            "entryUUID": "entryUUID",  # Standard RFC, OUD version
        }

        # RFC→OUD attribute name transformations (for reverse mapping)
        ATTRIBUTE_TRANSFORMATION_RFC_TO_OUD: Final[dict[str, str]] = {
            "dsyncHist": "ds-sync-hist",
            "accountDisabled": "ds-pwp-account-disabled",
            "entryUUID": "entryUUID",
        }

    # =========================================================================
    # Class-level attributes for server identification (from Constants)
    # =========================================================================
    server_type: ClassVar[str] = Constants.SERVER_TYPE
    priority: ClassVar[int] = Constants.PRIORITY

    def __init__(self) -> None:
        """Initialize Oracle Unified Directory quirks."""
        super().__init__()
        # Use object.__setattr__ to bypass Pydantic validation for dynamic attributes
        # Nested classes no longer require server_type and priority parameters
        object.__setattr__(self, "schema", self.Schema())
        object.__setattr__(self, "acl", self.Acl())
        object.__setattr__(self, "entry", self.Entry())

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

        def _parse_attribute(
            self,
            attr_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse Oracle OUD attribute definition (implements abstract method from base.py).

            Override RFC implementation to use OUD-specific parser settings.
            This method is called by base.py's parse_attribute() public method.

            Args:
                attr_definition: AttributeType definition string

            Returns:
                FlextResult with parsed SchemaAttribute model

            """
            try:
                # Use OUD-specific parser which will handle extensions via hooks
                return FlextLdifUtilities.Parser.parse_rfc_attribute(
                    attr_definition,
                    case_insensitive=False,  # OUD uses strict RFC-compliant NAME matching
                    _allow_syntax_quotes=False,  # OUD uses standard SYNTAX format (private param)
                )
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

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                FlextResult with parsed SchemaObjectClass model

            """
            try:
                # Use OUD-specific parser which will handle extensions via hooks
                return FlextLdifUtilities.Parser.parse_rfc_objectclass(
                    oc_definition,
                    _case_insensitive=False,  # OUD uses strict RFC-compliant NAME matching (private param)
                )
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
                    "ObjectClass name is required for validation"
                )
            if not oc_data.oid:
                return FlextResult[bool].fail(
                    "ObjectClass OID is required for validation"
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
                for attr in must_list:
                    if not FlextLdifUtilities.Schema.is_attribute_in_list(
                        str(attr), available_attributes
                    ):
                        missing_attrs.append(str(attr))

            # PHASE 2: Check MAY attributes (optional - failure if missing)
            # CRITICAL FIX: MAY attributes MUST also be present in schema
            # Missing MAY attributes cause: "No attribute type matching this name or OID exists"
            may_attrs = oc_data.may
            if may_attrs:
                may_list: list[str] = (
                    may_attrs if isinstance(may_attrs, list) else [str(may_attrs)]
                )
                for attr in may_list:
                    if not FlextLdifUtilities.Schema.is_attribute_in_list(
                        str(attr), available_attributes
                    ):
                        missing_attrs.append(str(attr))

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
                        f"Replacing invalid SUBSTR rule {fixed_substr} with {replacement}"
                    )
                    fixed_substr = replacement

            # Check if this is a boolean attribute for special handling during write
            is_boolean = FlextLdifUtilities.Schema.is_boolean_attribute(
                fixed_name,
                set(FlextLdifServersOud.Constants.BOOLEAN_ATTRIBUTES),
            )
            if is_boolean:
                logger.debug(f"Identified boolean attribute: {fixed_name}")

            # Create modified copy with fixed values using Pydantic v2 pattern
            return attr_data.model_copy(
                update={
                    "name": fixed_name,
                    "equality": fixed_equality,
                    "substr": fixed_substr,
                }
            )

        def extract_schemas_from_ldif(
            self,
            ldif_content: str,
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Extract and parse all schema definitions from LDIF content.

            Strategy pattern: OUD-specific approach to extract attributeTypes
            and objectClasses from cn=schema LDIF entries, handling OUD's
            case variations.

            Filters only Oracle internal objectClasses that OUD already provides built-in.
            All custom objectClasses pass through, including those with unresolved
            dependencies (OUD will validate at startup).

            Args:
                ldif_content: Raw LDIF content containing schema definitions

            Returns:
                FlextResult with dict containing ATTRIBUTES and
                objectclasses lists (filtered only for Oracle internal classes)

            """
            try:
                objectclasses_parsed: list[FlextLdifModels.SchemaObjectClass] = []

                # PHASE 1: Extract all attributeTypes first using FlextLdifUtilities.Schema
                attributes_parsed = (
                    FlextLdifUtilities.Schema.extract_attributes_from_lines(
                        ldif_content,
                        self.parse_attribute,
                    )
                )

                # Build set of available attribute names (lowercase) for dependency validation
                available_attributes: set[str] = set()
                for attr_data in attributes_parsed:
                    if isinstance(
                        attr_data,
                        FlextLdifModels.SchemaAttribute,
                    ) and hasattr(attr_data, "name"):
                        attr_name = str(attr_data.name).lower()
                        available_attributes.add(attr_name)

                # PHASE 2: Extract objectClasses with dependency validation using FlextLdifUtilities.Schema
                # Must happen AFTER all attributes are collected
                objectclasses_raw_data = (
                    FlextLdifUtilities.Schema.extract_objectclasses_from_lines(
                        ldif_content,
                        self.parse_objectclass,
                    )
                )

                # PHASE 3: Pass all objectClasses through to migration service
                objectclasses_parsed.extend(objectclasses_raw_data)

                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    {
                        FlextLdifConstants.DictKeys.ATTRIBUTES: attributes_parsed,
                        "objectclasses": objectclasses_parsed,
                    }
                )

            except Exception as e:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"OUD schema extraction failed: {e}",
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

        def can_handle(self, acl: str | FlextLdifModels.Acl) -> bool:
            """Check if this is an Oracle OUD ACL (public method).

            Args:
                acl: ACL line string or Acl model to check.

            Returns:
                True if this is Oracle OUD ACL format

            """
            return self.can_handle(acl)

        def can_handle_acl(self, acl_line: str | FlextLdifModels.Acl) -> bool:
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
                    return (
                        acl_line.metadata.quirk_type
                        == FlextLdifServersOud.Constants.SERVER_TYPE
                    )
                # Check attribute name
                if acl_line.name:
                    acl_attr_normalized = (
                        FlextLdifUtilities.Schema.normalize_attribute_name(
                            acl_line.name
                        )
                    )
                    const_attr_normalized = (
                        FlextLdifUtilities.Schema.normalize_attribute_name(
                            FlextLdifServersOud.Constants.ACL_ATTRIBUTE_NAME
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
                    )
                )
                or "ds-cfg-" in normalized.lower()
            )

        def _parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse Oracle OUD ACL string to RFC-compliant internal model.

            Normalizes OUD ACI (Access Control Instruction) format to RFC-compliant
            internal representation.

            Parses ACI format used by OUD, extracting:
            - targetattr: Target attributes
            - targetscope: Target scope (base, onelevel, subtree)
            - version: ACI version
            - acl_name: ACL description name
            - permissions: List of permissions (read, write, search, etc.)
            - bind_rules: Bind rules (userdn, groupdn, etc.)

            Handles complex multi-line ACIs with:
            - Line continuations (multiple allow/deny rules)
            - Varied indentation patterns
            - Spaces after commas in DNs
            - Multiple permission rules per ACI (4+ rules)

            Args:
            acl_line: ACL definition line (may contain newlines for multi-line ACIs)

            Returns:
            FlextResult with OUD ACL Pydantic model

            """
            try:
                # Initialize parsed values from Constants
                acl_name = FlextLdifServersOud.Constants.ACL_DEFAULT_NAME
                targetattr = FlextLdifServersOud.Constants.ACL_DEFAULT_TARGETATTR
                targetscope = None
                version = FlextLdifServersOud.Constants.ACL_DEFAULT_VERSION
                dn_spaces = False

                # Detect line breaks using utility
                line_breaks = FlextLdifUtilities.ACL.detect_line_breaks(
                    acl_line,
                    FlextLdifServersOud.Constants.ACL_NEWLINE_SEPARATOR,
                )

                # Parse ACI components if it's ACI format
                if not acl_line.startswith(
                    FlextLdifServersOud.Constants.ACL_ACI_PREFIX
                ):
                    return FlextResult[FlextLdifModels.Acl].fail(
                        "Not an OUD ACI format",
                    )

                aci_content = acl_line.split(":", 1)[1].strip()

                # Extract components using DRY utilities
                targetattr = (
                    FlextLdifUtilities.ACL.extract_component(
                        aci_content,
                        FlextLdifServersOud.Constants.ACL_TARGETATTR_PATTERN,
                        group=2,
                    )
                    or targetattr
                )

                targetscope = FlextLdifUtilities.ACL.extract_component(
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
                    version = version_match.group(1)
                    acl_name = version_match.group(2)

                # Extract permissions using DRY utility
                permissions_list = FlextLdifUtilities.ACL.extract_permissions(
                    aci_content,
                    FlextLdifServersOud.Constants.ACL_ALLOW_DENY_PATTERN,
                    ops_separator=FlextLdifServersOud.Constants.ACL_OPS_SEPARATOR,
                    action_filter=FlextLdifServersOud.Constants.ACL_ACTION_ALLOW,
                )

                # Extract bind rules using DRY utility
                bind_patterns = {
                    FlextLdifServersOud.Constants.ACL_BIND_RULE_TYPE_USERDN: FlextLdifServersOud.Constants.ACL_USERDN_PATTERN,
                    FlextLdifServersOud.Constants.ACL_BIND_RULE_TYPE_GROUPDN: FlextLdifServersOud.Constants.ACL_GROUPDN_PATTERN,
                }
                bind_rules_data = FlextLdifUtilities.ACL.extract_bind_rules(
                    aci_content,
                    bind_patterns,
                )

                # Check for DN spaces in bind rules
                for rule in bind_rules_data:
                    if FlextLdifUtilities.DN.contains_pattern(rule["value"], ", "):
                        dn_spaces = True
                        break

                # Build permissions dict using DRY utility
                permission_mapping = {
                    FlextLdifConstants.PermissionNames.READ.lower(): FlextLdifServersOud.Constants.ACL_PERM_KEY_READ,
                    FlextLdifConstants.PermissionNames.WRITE.lower(): FlextLdifServersOud.Constants.ACL_PERM_KEY_WRITE,
                    FlextLdifConstants.PermissionNames.ADD.lower(): FlextLdifServersOud.Constants.ACL_PERM_KEY_ADD,
                    FlextLdifConstants.PermissionNames.DELETE.lower(): FlextLdifServersOud.Constants.ACL_PERM_KEY_DELETE,
                    FlextLdifConstants.PermissionNames.SEARCH.lower(): FlextLdifServersOud.Constants.ACL_PERM_KEY_SEARCH,
                    FlextLdifConstants.PermissionNames.COMPARE.lower(): FlextLdifServersOud.Constants.ACL_PERM_KEY_COMPARE,
                    FlextLdifConstants.PermissionNames.SELFWRITE.lower(): FlextLdifServersOud.Constants.ACL_PERMISSION_SELF_WRITE,
                    FlextLdifConstants.PermissionNames.SELF_WRITE.lower(): FlextLdifServersOud.Constants.ACL_PERMISSION_SELF_WRITE,
                    FlextLdifConstants.PermissionNames.PROXY.lower(): FlextLdifServersOud.Constants.ACL_PERM_KEY_PROXY,
                }
                permissions_data = FlextLdifUtilities.ACL.build_permissions_dict(
                    permissions_list,
                    permission_mapping,
                )

                # Handle "all" permission special case
                if FlextLdifUtilities.Schema.is_attribute_in_list(
                    FlextLdifConstants.PermissionNames.ALL, permissions_list
                ):
                    for key in permissions_data:
                        permissions_data[key] = True

                # Build AclSubject using DRY utility
                subject_type_map = {
                    FlextLdifServersOud.Constants.ACL_BIND_RULE_TYPE_USERDN: FlextLdifServersOud.Constants.ACL_SUBJECT_TYPE_BIND_RULES,
                    FlextLdifServersOud.Constants.ACL_BIND_RULE_TYPE_GROUPDN: FlextLdifConstants.AclSubjectTypes.GROUP,
                }
                special_values = {
                    FlextLdifServersOud.Constants.ACL_SELF_SUBJECT: (
                        FlextLdifConstants.AclSubjectTypes.SELF,
                        FlextLdifServersOud.Constants.ACL_SELF_SUBJECT,
                    ),
                    FlextLdifServersOud.Constants.ACL_ANONYMOUS_SUBJECT: (
                        FlextLdifConstants.AclSubjectTypes.ANONYMOUS,
                        "*",
                    ),
                    FlextLdifServersOud.Constants.ACL_ANONYMOUS_SUBJECT_ALT: (
                        FlextLdifConstants.AclSubjectTypes.ANONYMOUS,
                        "*",
                    ),
                }
                subject_type, subject_value = FlextLdifUtilities.ACL.build_acl_subject(
                    bind_rules_data,
                    subject_type_map,
                    special_values,
                )

                # Build QuirkMetadata extensions using DRY utility
                FlextLdifUtilities.ACL.build_metadata_extensions(
                    line_breaks=line_breaks,
                    dn_spaces=dn_spaces,
                    targetscope=targetscope,
                    version=version,
                    default_version="3.0",
                )

                # Create Acl model
                acl = FlextLdifModels.Acl(
                    name=acl_name,
                    target=FlextLdifModels.AclTarget(
                        target_dn=targetattr,
                        attributes=[],
                    ),
                    subject=FlextLdifModels.AclSubject(
                        subject_type=subject_type,
                        subject_value=subject_value,
                    ),
                    permissions=FlextLdifModels.AclPermissions(**permissions_data),
                    metadata=FlextLdifModels.QuirkMetadata.create_for(
                        FlextLdifServersOud.Constants.SERVER_TYPE,
                        original_format=acl_line,
                    ),
                    raw_acl=acl_line,
                )

                return FlextResult[FlextLdifModels.Acl].ok(acl)

            except Exception as e:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"OUD ACL parsing failed: {e}",
                )

        def _should_use_raw_acl(self, acl_data: FlextLdifModels.Acl) -> bool:
            """Check if raw_acl should be used as-is.

            Args:
                acl_data: ACL model instance

            Returns:
                True if raw_acl should be used

            """
            if not acl_data.raw_acl:
                return False

            # Use raw_acl if already in OUD format
            if acl_data.raw_acl.startswith(
                FlextLdifServersOud.Constants.ACL_ACI_PREFIX
            ):
                return True

            # Preserve OID format for multi-attribute ACLs
            return bool(
                acl_data.target
                and acl_data.target.attributes
                and len(acl_data.target.attributes) > 1
                and (
                    "attr" in acl_data.raw_acl.lower()
                    or "attributes" in acl_data.raw_acl.lower()
                )
                and acl_data.raw_acl.startswith(("orclaci:", "access to"))
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
            self, acl_data: FlextLdifModels.Acl
        ) -> FlextResult[str]:
            """Build ACI permissions part.

            Args:
                acl_data: ACL model instance

            Returns:
                FlextResult with formatted permissions string

            """
            if not acl_data.permissions:
                return FlextResult[str].fail("ACL model has no permissions object")

            ops_property = acl_data.permissions.permissions
            ops: list[str] = ops_property() if callable(ops_property) else ops_property

            # Filter to only OUD-supported rights using utility
            filtered_ops = FlextLdifUtilities.ACL.filter_supported_permissions(
                ops,
                FlextLdifServersOud.Constants.OUD_SUPPORTED_RIGHTS,
            )

            # Check metadata bridge for self_write promotion
            if (
                acl_data.metadata
                and acl_data.metadata.self_write_to_write
                and FlextLdifServersOud.Constants.ACL_PERMISSION_SELF_WRITE in ops
                and "write" not in filtered_ops
            ):
                filtered_ops.append("write")

            if not filtered_ops:
                return FlextResult[str].fail(
                    f"ACL model has no OUD-supported permissions (all were OID-specific like {FlextLdifServersOud.Constants.ACL_PERMISSION_SELF_WRITE})"
                )

            ops_str = ",".join(filtered_ops)
            return FlextResult[str].ok(
                f"{FlextLdifServersOud.Constants.ACL_ALLOW_PREFIX}{ops_str})"
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
                aci_output_lines = []

                # Generate OID→OUD Conversion Comments
                if (
                    acl_data.metadata
                    and hasattr(acl_data.metadata, "extensions")
                    and acl_data.metadata.extensions
                ):
                    extensions = acl_data.metadata.extensions

                    if extensions.get("converted_from_oid"):
                        conversion_comments = extensions.get(
                            "oud_conversion_comments", []
                        )
                        if conversion_comments and isinstance(
                            conversion_comments, list
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
                acl_name = acl_data.name or "OUD ACL"
                aci_parts.append(
                    f'({FlextLdifServersOud.Constants.ACL_DEFAULT_VERSION}; acl "{acl_name}";'
                )

                # Permissions using helper
                perms_result = self._build_aci_permissions(acl_data)
                if perms_result.is_failure:
                    return FlextResult[str].fail(perms_result.error)
                aci_parts.append(perms_result.unwrap())

                # Bind rules (subject) using helper
                aci_parts.append(self._build_aci_subject(acl_data))

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
                FlextLdifServersOud.Constants.ACL_ACI_PREFIX.lower()
            )

        @staticmethod
        def _is_ds_cfg_acl(line: str) -> bool:
            """Check if line is a ds-cfg ACL format.

            Args:
                line: Stripped line to check

            Returns:
                True if line starts with 'ds-cfg-' (case-insensitive)

            """
            return line.lower().startswith("ds-cfg-")

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
            self, entry_dn: str, attributes: Mapping[str, object]
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
                entry_dn, FlextLdifServersOud.Constants.DN_PREFIX_CN_CONFIG
            ) and FlextLdifUtilities.DN.contains_pattern(
                entry_dn, FlextLdifServersOud.Constants.DN_PREFIX_CN_SCHEMA
            ):
                return True

            if FlextLdifUtilities.DN.contains_pattern(
                entry_dn, FlextLdifServersOud.Constants.DN_PREFIX_CN_CONFIG
            ) and (
                FlextLdifUtilities.DN.contains_pattern(
                    entry_dn, FlextLdifServersOud.Constants.DN_PREFIX_CN_DIRECTORY
                )
                or FlextLdifUtilities.DN.contains_pattern(
                    entry_dn, FlextLdifServersOud.Constants.DN_PREFIX_CN_DS
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
            oid_prefixes = ("orcl", "oracle")
            if any(
                attr_name.lower().startswith(prefix)
                for attr_name in entry_attrs
                for prefix in oid_prefixes
            ):
                return False

            return "objectclass" in entry_attrs

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

            # Preserve base64 encoding metadata
            if "_base64_attrs" in entry.attributes.attributes:
                processed_attrs_dict["_base64_attrs"] = entry.attributes.attributes[
                    "_base64_attrs"
                ]

            # Preserve special LDIF modify markers for schema entries
            if "_modify_add_attributetypes" in entry.attributes.attributes:
                processed_attrs_dict["_modify_add_attributetypes"] = (
                    entry.attributes.attributes["_modify_add_attributetypes"]
                )
            if "_modify_add_objectclasses" in entry.attributes.attributes:
                processed_attrs_dict["_modify_add_objectclasses"] = (
                    entry.attributes.attributes["_modify_add_objectclasses"]
                )

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
                    )
                }
                converted_dict = FlextLdifUtilities.Entry.convert_boolean_attributes(
                    attr_dict,
                    set(FlextLdifServersOud.Constants.BOOLEAN_ATTRIBUTES),
                )
                return converted_dict.get(attr_name, attr_dict[attr_name])

            # Validate telephone numbers
            if attr_lower == "telephonenumber":
                valid_numbers = FlextLdifUtilities.Entry.validate_telephone_numbers(
                    attr_values if isinstance(attr_values, list) else [attr_values]
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
            if FlextLdifUtilities.DN.contains_pattern(entry.dn.value, ", "):
                metadata_extensions["dn_spaces"] = True

            # Preserve attribute order
            if processed_attributes:
                metadata_extensions["attribute_order"] = list(
                    processed_attributes.keys()
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
                            prefix in str(oc).lower() for prefix in ("orcl", "oracle")
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

                # Normalize attribute names and apply OUD-specific transformations
                final_attributes_for_new_entry: dict[str, list[str]] = {}
                for attr_name, attr_values in entry.attributes.attributes.items():
                    # Skip internal metadata attributes
                    if attr_name.startswith("_"):
                        continue

                    # Normalize attribute name to proper camelCase
                    attr_lower = attr_name.lower()
                    normalized_name = (
                        FlextLdifServersOud.Constants.ATTRIBUTE_CASE_MAP.get(
                            attr_lower, attr_name
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
                    {k: v for k, v in processed_attrs_dict.items() if k.startswith("_")}
                )
                new_ldif_attributes = FlextLdifModels.LdifAttributes(
                    attributes=combined_attributes
                )

                # Build metadata extensions using helper
                metadata_extensions = self._build_metadata_extensions(
                    entry, final_attributes_for_new_entry
                )

                new_metadata = FlextLdifModels.QuirkMetadata.create_for(
                    quirk_type=FlextLdifServersOud.Constants.SERVER_TYPE,
                    extensions=metadata_extensions,
                )

                # Create and return the new Entry model
                return FlextResult.ok(
                    FlextLdifModels.Entry.create(
                        dn=entry.dn,
                        attributes=new_ldif_attributes,
                        metadata=new_metadata,
                    ).unwrap()
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
            import re

            # CRITICAL: This method only does semantic transformation (add semicolons).
            # Line formatting (folding/unfolding) is the writer's responsibility, NOT the quirk's.
            # Always normalize whitespace and remove newlines - let writer handle formatting.

            # Normalize whitespace: replace all whitespace (including newlines) with single spaces)
            # This ensures the quirk only does semantic transformation, not formatting
            normalized = re.sub(r"\s+", " ", aci_value.strip())

            # OUD format requires semicolons after each "by" clause (except the last one)
            # Format: "by group=\"...\" ;" or "by *" (no semicolon if last)
            # Find all "by group=\"...\"" and "by *" clauses
            by_group_pattern = r"by\s+group=\"[^\"]+\""
            by_star_pattern = r"by\s+\*"

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

        def write(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[str]:
            r"""Public API: Write OUD entry to LDIF format.

            Converts Entry model to LDIF format string.
            This is the public interface - delegates to write_entry_to_ldif internally.

            Args:
                entry: Entry model object

            Returns:
                FlextResult with LDIF formatted entry string

            """
            # Convert Entry model to dict format expected by write_entry_to_ldif
            entry_dict = {"dn": str(entry.dn), **entry.attributes.attributes}
            return self.write_entry_to_ldif(entry_dict)

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

                dn = entry_data[FlextLdifConstants.DictKeys.DN]

                # Auto-convert RFC schema DN to OUD schema DN
                if dn.lower().startswith("cn=subschemasubentry"):
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
                        FlextLdifUtilities.Writer.write_modify_operations(entry_data)
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
                        entry_data
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
                            is_base64,
                            FlextLdifServersOud.Constants.ATTRIBUTE_CASE_MAP,
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
            entries_list: list[dict[str, object]],
        ) -> None:
            """Finalize entry dict and parse into entries list.

            Args:
                entry_dict: Entry dictionary with DN and attributes
                entries_list: Target list to append parsed entry

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
        ) -> FlextResult[list[dict[str, object]]]:
            """Extract and parse all directory entries from LDIF content.

            Strategy pattern: OUD-specific approach to extract entries from LDIF.

            Args:
            ldif_content: Raw LDIF content containing directory entries

            Returns:
            FlextResult with list of parsed entry dictionaries

            """
            try:
                entries = []
                current_entry: dict[str, object] = {}
                current_attr: str | None = None
                current_values: list[str] = []

                for line in ldif_content.split("\n"):
                    # Empty line indicates end of entry
                    if not line.strip():
                        if current_entry:
                            # Finalize and process entry
                            FlextLdifUtilities.Parser.finalize_pending_attribute(
                                current_attr, current_values, current_entry
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
                            line, current_attr, current_values, current_entry
                        )
                    )

                # Process final entry
                if current_entry:
                    FlextLdifUtilities.Parser.finalize_pending_attribute(
                        current_attr, current_values, current_entry
                    )
                    self._finalize_and_parse_entry(current_entry, entries)

                return FlextResult[list[dict[str, object]]].ok(entries)

            except Exception as e:
                return FlextResult[list[dict[str, object]]].fail(
                    f"OUD entry extraction failed: {e}",
                )


__all__ = ["FlextLdifServersOud"]
