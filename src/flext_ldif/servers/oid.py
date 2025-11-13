"""Oracle Internet Directory (OID) Quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Implements Oracle OID-specific extensions as quirks on top of RFC-compliant
base parsers. This wraps existing OID parser logic as composable quirks.

OID-specific features:
- Oracle OID attribute types (2.16.840.1.113894.* namespace)
- Oracle orclaci and orclentrylevelaci ACLs
- Oracle-specific schema attributes
- Oracle operational attributes
"""

from __future__ import annotations

import enum as enum_module
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import ClassVar, cast

from flext_core import FlextLogger, FlextResult

from flext_ldif._utilities.detection import FlextLdifUtilitiesDetection
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.utilities import FlextLdifUtilities

logger = FlextLogger(__name__)


class FlextLdifServersOid(FlextLdifServersRfc):
    """Oracle OID server quirks - implements FlextLdifProtocols.Quirks.SchemaProtocol.

    Extends RFC 4512 schema parsing with Oracle OID-specific features:
    - Oracle OID namespace (2.16.840.1.113894.*)
    - Oracle-specific syntaxes
    - Oracle attribute extensions
    - OUD compatibility fixes (matching rules, syntax OIDs)

    **Protocol Compliance**: Fully implements
    FlextLdifProtocols.Quirks.SchemaProtocol through structural typing.
    All methods match protocol signatures exactly for type safety.

    **Validation**: Verify protocol compliance with:
        from flext_ldif.protocols import FlextLdifProtocols
        quirk = FlextLdifServersOid()
        assert isinstance(quirk, FlextLdifProtocols.Quirks.SchemaProtocol)

    Example:
        quirk = FlextLdifServersOid()
        if quirk.schema.can_handle_attribute(attr_def):
            result = quirk.schema._parse_attribute(attr_def)
            if result.is_success:
                parsed_attr = result.unwrap()

    """

    # =========================================================================
    # STANDARDIZED CONSTANTS FOR AUTO-DISCOVERY
    # =========================================================================
    class Constants(FlextLdifServersRfc.Constants):
        """Oracle Internet Directory-specific constants for server operations.

        Extends RFC baseline constants with OID-specific patterns for detection,
        ACL format, attribute mappings, and schema configuration.

        All configuration including SERVER_TYPE and PRIORITY are defined here
        following the standardized pattern used across all server implementations.
        """

        # Server identity and priority (defined at Constants level)
        SERVER_TYPE: ClassVar[str] = FlextLdifConstants.ServerTypes.OID
        PRIORITY: ClassVar[int] = 10

        # Oracle OID ACL attribute names
        ORCLACI: ClassVar[str] = "orclaci"  # Standard Oracle OID ACL
        ORCLENTRYLEVELACI: ClassVar[str] = "orclentrylevelaci"  # Entry-level ACI
        ACL_FORMAT: ClassVar[str] = "orclaci"  # OID ACL format
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "orclaci"  # ACL attribute name

        # Matching rule replacements for OUD compatibility
        MATCHING_RULE_REPLACEMENTS: ClassVar[dict[str, str]] = {
            "caseIgnoreSubStringsMatch": "caseIgnoreSubstringsMatch",  # Fix capitalization
            "accessDirectiveMatch": "caseIgnoreMatch",  # Replace OID-specific with standard
        }

        # Syntax OID replacements for OUD compatibility
        SYNTAX_OID_REPLACEMENTS: ClassVar[dict[str, str]] = {
            "1.3.6.1.4.1.1466.115.121.1.1": "1.3.6.1.4.1.1466.115.121.1.15",  # ACI List → Directory String
        }

        # OID extends RFC operational attributes with Oracle-specific ones
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

        # NOTE: PRESERVE_ON_MIGRATION inherited from RFC.Constants

        # Detection constants (server-specific)
        DETECTION_OID_PATTERN: ClassVar[str] = (
            r"(?i)(2\.16\.840\.1\.113894\.|orcl)"  # Match Oracle OIDs OR orcl* attributes (case-insensitive)
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
                "orclcontainer",  # Oracle OID container objectClass (case-insensitive match)
            ],
        )
        DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset(
            [
                "cn=orcl",
                "cn=subscriptions",
                "cn=oracle context",
            ],
        )

        # === SCHEMA PROCESSING CONFIGURATION ===
        # Schema field names (migrated from FlextLdifConstants.SchemaFields)
        SCHEMA_FIELD_ATTRIBUTE_TYPES: ClassVar[str] = "attributetypes"
        SCHEMA_FIELD_ATTRIBUTE_TYPES_LOWER: ClassVar[str] = "attributetypes"
        SCHEMA_FIELD_OBJECT_CLASSES: ClassVar[str] = "objectclasses"
        SCHEMA_FIELD_OBJECT_CLASSES_LOWER: ClassVar[str] = "objectclasses"
        SCHEMA_FIELD_MATCHING_RULES: ClassVar[str] = "matchingrules"
        SCHEMA_FIELD_LDAP_SYNTAXES: ClassVar[str] = "ldapsyntaxes"

        # Schema fields that should be processed with OID filtering
        SCHEMA_FILTERABLE_FIELDS: ClassVar[frozenset[str]] = frozenset(
            [
                SCHEMA_FIELD_ATTRIBUTE_TYPES,
                SCHEMA_FIELD_ATTRIBUTE_TYPES_LOWER,
                SCHEMA_FIELD_OBJECT_CLASSES,
                SCHEMA_FIELD_OBJECT_CLASSES_LOWER,
                SCHEMA_FIELD_MATCHING_RULES,
                SCHEMA_FIELD_LDAP_SYNTAXES,
            ],
        )

        # Schema DN for OID (RFC 4512 standard)
        SCHEMA_DN: ClassVar[str] = "cn=subschemasubentry"

        # Oracle OID boolean attributes (non-RFC: use "0"/"1" not "TRUE"/"FALSE")
        # RFC 4517 Boolean syntax requires "TRUE" or "FALSE"
        # OID quirks convert "0"→"FALSE", "1"→"TRUE" during OID→RFC
        BOOLEAN_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
            [
                # Oracle DAS (Directory Application Server) boolean attributes
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
                # Oracle password policy boolean attributes
                "pwdlockout",
                "pwdmustchange",
                "pwdallowuserchange",
            ],
        )

        # Server type variants (for compatibility checks)
        VARIANTS: ClassVar[frozenset[str]] = frozenset(["oid", "oracle_oid"])

        # Schema attribute fields that are server-specific (migrated from FlextLdifConstants.SchemaConversionMappings)
        ATTRIBUTE_FIELDS: ClassVar[frozenset[str]] = frozenset(["usage", "x_origin"])

        # ObjectClass requirements (extends RFC - allows multiple SUP)
        OBJECTCLASS_REQUIREMENTS: ClassVar[Mapping[str, bool]] = {
            "requires_sup_for_auxiliary": True,
            "allows_multiple_sup": True,  # OID allows multiple SUP
            "requires_explicit_structural": False,
        }

        # Oracle OID specific operational attributes (extended set)
        OID_SPECIFIC: ClassVar[frozenset[str]] = frozenset(
            [
                # Note: Using literal strings to avoid circular reference during class definition
                # These correspond to Constants.ACL_ATTRIBUTE_NAME and Constants.ORCLENTRYLEVELACI
                "orclaci",
                "orclentrylevelaci",
                "orclguid",  # Oracle GUID
                "orclmailaddr",  # Mail address
                "orcluseractivefrom",  # User active from date
                "orcluserinactivefrom",  # User inactive from date
            ],
        )

        # Oracle OID specific attributes (categorization - migrated from FlextLdifConstants.AttributeCategories)
        OID_SPECIFIC_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
            [
                # Note: Using literal strings to avoid circular reference during class definition
                # These correspond to Constants.ACL_ATTRIBUTE_NAME and Constants.ORCLENTRYLEVELACI
                "orcloid",  # Oracle OID identifier
                "orclguid",  # Oracle GUID
                "orclpassword",  # Oracle password attribute
                "orclaci",
                "orclentrylevelaci",
                "orcldaslov",  # Oracle DASLOV configuration
            ],
        )

        # === STANDARDIZED CONSTANTS FOR AUTO-DISCOVERY ===
        CANONICAL_NAME: ClassVar[str] = "oid"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["oid", "oracle_oid"])
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["oid"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["oid", "rfc"])

        # Server detection patterns and weights (migrated from FlextLdifConstants.ServerDetection)
        DETECTION_PATTERN: ClassVar[str] = (
            r"(?i)(2\.16\.840\.1\.113894\.|orcl)"  # Match Oracle OIDs OR orcl* attributes (case-insensitive)
        )
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
        DETECTION_WEIGHT: ClassVar[int] = (
            12  # Increased to ensure OID detection wins over other servers when OID-specific attributes/objectClasses are present
        )

        # Oracle OID metadata keys (migrated from FlextLdifConstants.QuirkMetadataKeys)
        OID_SPECIFIC_RIGHTS: ClassVar[str] = "oid_specific_rights"
        OID_TO_OUD_TRANSFORMED: ClassVar[str] = "oid_to_oud_transformed"
        ORIGINAL_OID_PERMS: ClassVar[str] = "original_oid_perms"

        # All OID metadata keys
        ALL_OID_KEYS: ClassVar[frozenset[str]] = frozenset(
            [
                OID_SPECIFIC_RIGHTS,
                OID_TO_OUD_TRANSFORMED,
                ORIGINAL_OID_PERMS,
            ],
        )

        # =====================================================================
        # CATEGORIZATION RULES - OID-specific entry categorization
        # =====================================================================
        # These define how entries are categorized during migration
        # Priority order determines which category is checked first
        # CRITICAL for entries with multiple objectClasses (e.g., cn=PERFIS)

        # Categorization priority: users → hierarchy → groups → acl
        # HIERARCHY before GROUPS ensures structural containers are preserved
        CATEGORIZATION_PRIORITY: ClassVar[list[str]] = [
            "users",  # User accounts checked first
            "hierarchy",  # Structural containers (orclContainer, ou, o)
            "groups",  # Groups (groupOfNames, orclGroup)
            "acl",  # ACL entries
        ]

        # ObjectClasses defining each category
        CATEGORY_OBJECTCLASSES: ClassVar[dict[str, frozenset[str]]] = {
            "users": frozenset([
                "person",
                "inetOrgPerson",
                "orclUser",  # OID-specific user
                "orclUserV2",
            ]),
            "hierarchy": frozenset([
                "organizationalUnit",
                "organization",
                "domain",
                "country",
                "locality",
                "orclContainer",  # OID structural container
                "orclContext",  # OID context
            ]),
            "groups": frozenset([
                "groupOfNames",
                "groupOfUniqueNames",
                "orclGroup",  # OID group
                "orclPrivilegeGroup",  # OID privilege (unless has orclContainer!)
            ]),
        }

        # ObjectClasses that ALWAYS categorize as hierarchy
        # Even if entry also has group objectClasses
        # Solves cn=PERFIS: orclContainer + orclPrivilegeGroup → hierarchy
        HIERARCHY_PRIORITY_OBJECTCLASSES: ClassVar[frozenset[str]] = frozenset([
            "orclContainer",  # Always hierarchy
            "organizationalUnit",
            "organization",
            "domain",
        ])

        # ACL attributes (reuse existing constant)
        # NOTE: Includes BOTH pre-normalization (orclaci) AND post-normalization
        # (aci) names because _normalize_attribute_name() transforms orclaci→aci
        CATEGORIZATION_ACL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset([
            "aci",  # RFC standard (normalized from orclaci/orclentrylevelaci)
            "orclaci",  # OID format (before normalization)
            "orclentrylevelaci",  # OID entry-level format (before normalization)
        ])

        # =====================================================================
        # DN PATTERNS - OID-specific DN markers
        # =====================================================================
        CN_ORCL: ClassVar[str] = "cn=orcl"
        OU_ORACLE: ClassVar[str] = "ou=oracle"
        DC_ORACLE: ClassVar[str] = "dc=oracle"

        # All Oracle DN patterns
        ORACLE_DN_PATTERNS: ClassVar[frozenset[str]] = frozenset(
            [
                CN_ORCL,
                OU_ORACLE,
                DC_ORACLE,
            ],
        )

        # Permission names inherited from RFC.Constants
        # (PERMISSION_READ, PERMISSION_WRITE, PERMISSION_ADD, PERMISSION_DELETE, PERMISSION_SEARCH, PERMISSION_COMPARE)

        # ACL subject types (migrated from FlextLdifConstants.AclSubjectTypes)
        ACL_SUBJECT_TYPE_USER: ClassVar[str] = "user"
        ACL_SUBJECT_TYPE_GROUP: ClassVar[str] = "group"
        ACL_SUBJECT_TYPE_SELF: ClassVar[str] = "self"
        ACL_SUBJECT_TYPE_ANONYMOUS: ClassVar[str] = "anonymous"

        # ACL parsing patterns (migrated from _parse_acl method)
        ACL_TYPE_PATTERN: ClassVar[str] = r"^(orclaci|orclentrylevelaci):"
        ACL_TARGET_PATTERN: ClassVar[str] = r"access to (entry|attr=\(([^)]+)\))"
        ACL_SUBJECT_PATTERN: ClassVar[str] = (
            r"by\s+(group=\"[^\"]+\"|dnattr=\([^)]+\)|guidattr=\([^)]+\"|groupattr=\([^)]+\)|\"[^\"]+\"|self|\*)"
        )
        ACL_PERMISSIONS_PATTERN: ClassVar[str] = r"\(([^)]+)\)(?:\s*$)"
        ACL_FILTER_PATTERN: ClassVar[str] = r"filter=(\([^)]*(?:\([^)]*\)[^)]*)*\))"
        ACL_CONSTRAINT_PATTERN: ClassVar[str] = r"added_object_constraint=\(([^)]+)\)"

        # ACL pattern dictionary keys (used in _get_oid_patterns)
        ACL_PATTERN_KEY_TYPE: ClassVar[str] = "acl_type"
        ACL_PATTERN_KEY_TARGET: ClassVar[str] = "target"
        ACL_PATTERN_KEY_SUBJECT: ClassVar[str] = "subject"
        ACL_PATTERN_KEY_PERMISSIONS: ClassVar[str] = "permissions"
        ACL_PATTERN_KEY_FILTER: ClassVar[str] = "filter"
        ACL_PATTERN_KEY_CONSTRAINT: ClassVar[str] = "constraint"

        # ObjectClass typo fix constant (migrated from _post_write_objectclass method)
        OBJECTCLASS_TYPO_AUXILLARY: ClassVar[str] = "AUXILLARY"
        OBJECTCLASS_TYPO_AUXILIARY: ClassVar[str] = "AUXILIARY"

        # Matching rule normalization constants (migrated from _transform_attribute_for_write method)
        MATCHING_RULE_CASE_IGNORE_SUBSTRINGS: ClassVar[str] = (
            "caseIgnoreSubstringsMatch"
        )
        MATCHING_RULE_CASE_IGNORE_SUBSTRINGS_ALT: ClassVar[str] = (
            "caseIgnoreSubStringsMatch"
        )
        MATCHING_RULE_CASE_IGNORE: ClassVar[str] = "caseIgnoreMatch"

        # Oracle OID boolean format constants (non-RFC compliant)
        # RFC 4517 compliant uses "TRUE" / "FALSE"
        # Oracle OID uses "1" / "0"
        ONE_OID: ClassVar[str] = "1"
        ZERO_OID: ClassVar[str] = "0"

        # Boolean conversion mappings (using Constants for consistency)
        OID_TO_RFC: ClassVar[dict[str, str]] = {
            ONE_OID: "TRUE",  # Use Constants.ONE_OID
            ZERO_OID: "FALSE",  # Use Constants.ZERO_OID
            "true": "TRUE",
            "false": "FALSE",
        }

        RFC_TO_OID: ClassVar[dict[str, str]] = {
            "TRUE": ONE_OID,  # Use Constants.ONE_OID
            "FALSE": ZERO_OID,  # Use Constants.ZERO_OID
            "true": ONE_OID,  # Use Constants.ONE_OID
            "false": ZERO_OID,  # Use Constants.ZERO_OID
        }

        # Universal boolean check
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

        # Matching rule replacement mappings for invalid substr rules
        INVALID_SUBSTR_RULES: ClassVar[dict[str, str | None]] = {
            "caseIgnoreMatch": "caseIgnoreSubstringsMatch",
            "caseExactMatch": "caseExactSubstringsMatch",
            "distinguishedNameMatch": None,
            "integerMatch": None,
            "numericStringMatch": "numericStringSubstringsMatch",
        }

        # NOTE: Transformation mappings removed - not used in current implementation
        # Conversions should be handled by services/conversion.py, not in server constants

        # === ACL FORMATTING CONSTANTS ===
        ACL_ACCESS_TO: ClassVar[str] = "access to"
        ACL_BY: ClassVar[str] = "by"
        ACL_FORMAT_DEFAULT: ClassVar[str] = "default"
        ACL_FORMAT_ONELINE: ClassVar[str] = "oneline"
        ACL_NAME: ClassVar[str] = "OID ACL"

        # === ACL SUBJECT PATTERNS ===
        # Subject detection patterns for OID ACL parsing
        ACL_SUBJECT_PATTERNS: ClassVar[dict[str, tuple[str | None, str, str]]] = {
            " by self ": (None, "self", "ldap:///self"),
            " by self)": (None, "self", "ldap:///self"),
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

        # === ACL SUBJECT FORMATTERS ===
        # Subject formatters for OID ACL writing
        ACL_SUBJECT_FORMATTERS: ClassVar[dict[str, tuple[str, bool]]] = {
            "self": ("self", False),
            "user_dn": ('"{0}"', True),
            "group_dn": ('group="{0}"', True),
            "group": ('group="{0}"', True),  # Alias for group_dn (from OUD parsing)
            "dn_attr": ("dnattr=({0})", False),
            "guid_attr": ("guidattr=({0})", False),
            "group_attr": ("groupattr=({0})", False),
        }

        # === ACL PERMISSION MAPPINGS ===
        # Permission name mappings for OID ACL parsing
        ACL_PERMISSION_MAPPING: ClassVar[dict[str, list[str]]] = {
            "all": ["read", "write", "add", "delete", "search", "compare", "proxy"],
            "browse": ["read", "search"],  # OID: browse maps to read+search
            "read": ["read"],
            "write": ["write"],
            "add": ["add"],
            "delete": ["delete"],
            "search": ["search"],
            "compare": ["compare"],
            "selfwrite": ["self_write"],
            "proxy": ["proxy"],
        }

        # === ACL PERMISSION NAMES ===
        # Permission name mappings for OID ACL writing
        ACL_PERMISSION_NAMES: ClassVar[dict[str, str]] = {
            "read": "read",
            "write": "write",
            "add": "add",
            "delete": "delete",
            "search": "search",
            "compare": "compare",
            "self_write": "selfwrite",
            "proxy": "proxy",
        }

        # === OID SUPPORTED PERMISSIONS ===
        # Permissions that OID supports (migrated from FlextLdifConstants.AclPermissionCompatibility)
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
            ],
        )

        # === ATTRIBUTE NAME TRANSFORMATIONS ===
        # OID→RFC attribute name transformations (for compatibility)
        # (migrated from FlextLdifConstants.AttributeTransformations)
        ATTRIBUTE_TRANSFORMATION_OID_TO_RFC: ClassVar[Mapping[str, str]] = {
            "orclguid": "entryUUID",  # Oracle GUID → RFC entryUUID
            "orclaci": "aci",  # Oracle ACL → RFC ACI
            "orclentrylevelaci": "aci",  # Oracle entry-level ACL → RFC ACI
        }

        # RFC→OID attribute name transformations (for reverse mapping)
        ATTRIBUTE_TRANSFORMATION_RFC_TO_OID: ClassVar[Mapping[str, str]] = {
            "entryUUID": "orclguid",
            "aci": "orclaci",
        }

        # === NESTED STRENUM DEFINITIONS ===
        # StrEnum definitions for type-safe permission, action, and encoding handling

        class AclPermission(enum_module.StrEnum):
            """OID-specific ACL permissions."""

            READ = "read"
            WRITE = "write"
            ADD = "add"
            DELETE = "delete"
            SEARCH = "search"
            COMPARE = "compare"
            SELF_WRITE = "self_write"
            PROXY = "proxy"
            BROWSE = "browse"
            AUTH = "auth"
            ALL = "all"
            NONE = "none"

        class AclAction(enum_module.StrEnum):
            """OID ACL action types."""

            ALLOW = "allow"
            DENY = "deny"

        class Encoding(enum_module.StrEnum):
            """OID-supported encodings."""

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
        """Get the source schema DN for this server (RFC 4512 standard).

        Returns:
            Schema DN in OID/RFC format (cn=subschemasubentry)

        """
        return cls.Constants.SCHEMA_DN

    def extract_schemas_from_ldif(
        self,
        ldif_content: str,
    ) -> FlextResult[dict[str, object]]:
        """Extract and parse all schema definitions from LDIF content.

        Delegates to the Schema nested class implementation.

        Returns:
            FlextResult containing extracted attributes and objectclasses

        """
        # Instantiate Schema nested class
        schema_class = getattr(type(self), "Schema", None)
        if not schema_class:
            return FlextResult[dict[str, object]].fail(
                "Schema nested class not available",
            )

        schema_quirk = schema_class()
        result: FlextResult[dict[str, list[str] | str]] = (
            schema_quirk.extract_schemas_from_ldif(ldif_content)
        )
        return result.map(lambda d: cast("dict[str, object]", d))

    class Schema(
        FlextLdifServersRfc.Schema,
        FlextLdifUtilitiesDetection.OidPatternMixin,
    ):
        """Oracle OID schema quirks implementation.

        Inherits OID pattern detection from OidPatternMixin, which provides
        can_handle_attribute() and can_handle_objectclass() methods that
        automatically detect OID-specific attributes using the pattern
        defined in Constants.DETECTION_OID_PATTERN.
        """

        def __init__(self, **kwargs: object) -> None:
            """Initialize OID schema quirk.

            server_type and priority are obtained from parent class Constants.
            They are not passed as parameters anymore.

            Args:
                **kwargs: Passed to parent for compatibility (ignored)

            """
            super().__init__(**kwargs)

        # Schema parsing and conversion methods
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Schema)
        # These methods override the base class with Oracle OID-specific logic:
        # - _parse_attribute(): Custom parsing logic for Oracle OID schema with special OID replacements
        # - _parse_objectclass(): Custom parsing logic for Oracle OID schema with special OID replacements
        # - _write_attribute(): Uses RFC writer with OID error handling
        # - _write_objectclass(): Uses RFC writer with OID error handling
        # - should_filter_out_attribute(): Returns False (accept all in OID mode)
        # - should_filter_out_objectclass(): Returns False (accept all in OID mode)
        # - create_metadata(): Creates OID-specific metadata

        def _parse_attribute(
            self,
            attr_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse Oracle OID attribute definition.

            Uses RFC 4512 compliant baseline parser with lenient mode for OID quirks,
            then applies OID-specific enhancements like matching rule fixes and
            syntax OID replacements.

            Args:
                attr_definition: AttributeType definition string
                                (without "attributetypes:" prefix)

            Returns:
                FlextResult with parsed OID attribute data with metadata

            """
            try:
                # Use RFC baseline parser with lenient mode for OID's non-standard syntax
                result = FlextLdifUtilities.Parser.parse_rfc_attribute(
                    attr_definition,
                    case_insensitive=True,  # OID uses case-insensitive NAME
                    allow_syntax_quotes=True,  # OID allows 'OID' format for SYNTAX
                )

                if not result.is_success:
                    return result

                # Unwrap parsed attribute from RFC baseline
                schema_attr = result.unwrap()

                # Apply OID-specific enhancements on top of RFC baseline
                # Fix matching rules that are invalid in OUD (equality, substr, ordering)
                if (
                    schema_attr.equality
                    and schema_attr.equality
                    in FlextLdifServersOid.Constants.MATCHING_RULE_REPLACEMENTS
                ):
                    schema_attr.equality = (
                        FlextLdifServersOid.Constants.MATCHING_RULE_REPLACEMENTS[
                            schema_attr.equality
                        ]
                    )

                if (
                    schema_attr.substr
                    and schema_attr.substr
                    in FlextLdifServersOid.Constants.MATCHING_RULE_REPLACEMENTS
                ):
                    schema_attr.substr = (
                        FlextLdifServersOid.Constants.MATCHING_RULE_REPLACEMENTS[
                            schema_attr.substr
                        ]
                    )

                if (
                    schema_attr.ordering
                    and schema_attr.ordering
                    in FlextLdifServersOid.Constants.MATCHING_RULE_REPLACEMENTS
                ):
                    schema_attr.ordering = (
                        FlextLdifServersOid.Constants.MATCHING_RULE_REPLACEMENTS[
                            schema_attr.ordering
                        ]
                    )

                # Fix syntax OIDs for OUD compatibility
                if (
                    schema_attr.syntax
                    and schema_attr.syntax
                    in FlextLdifServersOid.Constants.SYNTAX_OID_REPLACEMENTS
                ):
                    schema_attr.syntax = (
                        FlextLdifServersOid.Constants.SYNTAX_OID_REPLACEMENTS[
                            schema_attr.syntax
                        ]
                    )

                # Ensure metadata is preserved with OID-specific information
                if not schema_attr.metadata:
                    schema_attr.metadata = self.create_metadata(
                        attr_definition.strip(),
                    )

                # Attach timestamp metadata (previously done by decorator)
                if schema_attr.metadata:
                    schema_attr.metadata.extensions["parsed_timestamp"] = datetime.now(
                        UTC,
                    ).isoformat()

                return FlextResult[FlextLdifModels.SchemaAttribute].ok(schema_attr)

            except Exception as e:
                return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                    f"OID attribute parsing failed: {e}",
                )

        def _write_attribute(
            self,
            schema_attr: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[str]:
            """Write Oracle OID attribute definition with RFC normalization.

            Applies OID→RFC normalization transformations before writing:
            - Remove ;binary suffix from attribute names (OID-specific)
            - Replace underscores with hyphens in names (RFC compliance)
            - Matching rule fixes (caseIgnoreSubStringsMatch → caseIgnoreSubstringsMatch)
            - Syntax OID replacements for OUD compatibility

            Args:
                schema_attr: Parsed schema attribute model

            Returns:
                FlextResult with formatted LDIF attribute definition string

            """
            # Create a copy to avoid mutating the original
            attr_copy = schema_attr.model_copy(deep=True)

            # OID→RFC normalization: Remove ;binary suffix from attribute name
            if attr_copy.name and ";binary" in attr_copy.name:
                attr_copy.name = attr_copy.name.replace(";binary", "")

            # RFC compliance: Replace underscores with hyphens in attribute name
            if attr_copy.name and "_" in attr_copy.name:
                attr_copy.name = attr_copy.name.replace("_", "-")

            # Apply matching rule replacements before writing
            if (
                attr_copy.equality
                and attr_copy.equality
                in FlextLdifServersOid.Constants.MATCHING_RULE_REPLACEMENTS
            ):
                attr_copy.equality = (
                    FlextLdifServersOid.Constants.MATCHING_RULE_REPLACEMENTS[
                        attr_copy.equality
                    ]
                )

            if (
                attr_copy.substr
                and attr_copy.substr
                in FlextLdifServersOid.Constants.MATCHING_RULE_REPLACEMENTS
            ):
                attr_copy.substr = (
                    FlextLdifServersOid.Constants.MATCHING_RULE_REPLACEMENTS[
                        attr_copy.substr
                    ]
                )

            if (
                attr_copy.ordering
                and attr_copy.ordering
                in FlextLdifServersOid.Constants.MATCHING_RULE_REPLACEMENTS
            ):
                attr_copy.ordering = (
                    FlextLdifServersOid.Constants.MATCHING_RULE_REPLACEMENTS[
                        attr_copy.ordering
                    ]
                )

            # Apply syntax OID replacements before writing
            if (
                attr_copy.syntax
                and attr_copy.syntax
                in FlextLdifServersOid.Constants.SYNTAX_OID_REPLACEMENTS
            ):
                attr_copy.syntax = (
                    FlextLdifServersOid.Constants.SYNTAX_OID_REPLACEMENTS[
                        attr_copy.syntax
                    ]
                )

            # Use RFC baseline writer with corrected attribute
            return FlextLdifUtilities.Writer.write_rfc_attribute(attr_copy)

        def _parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse Oracle OID objectClass definition.

            Uses RFC 4512 compliant baseline parser with lenient mode for OID quirks,
            then applies OID-specific enhancements.

            Args:
                oc_definition: ObjectClass definition string
                            (without "objectclasses:" prefix)

            Returns:
                FlextResult with parsed OID objectClass data with metadata

            """
            try:
                # Use RFC baseline parser for objectClass parsing
                # Note: parse_rfc_objectclass does not support case_insensitive parameter
                # OID case-insensitivity is handled during attribute NAME matching, not objectClass parsing
                result = FlextLdifUtilities.Parser.parse_rfc_objectclass(
                    oc_definition,
                )

                if not result.is_success:
                    return result

                # Unwrap parsed objectClass from RFC baseline
                schema_oc = result.unwrap()

                # Apply OID-specific enhancements on top of RFC baseline
                # Fix common ObjectClass issues (RFC 4512 compliance)
                FlextLdifUtilities.ObjectClass.ensure_sup_for_auxiliary(schema_oc)
                FlextLdifUtilities.ObjectClass.align_kind_with_superior(schema_oc, None)

                # Ensure metadata is preserved with OID-specific information
                if not schema_oc.metadata:
                    schema_oc.metadata = self.create_metadata(
                        oc_definition.strip(),
                    )

                # Attach timestamp metadata (previously done by decorator)
                if schema_oc.metadata:
                    schema_oc.metadata.extensions["parsed_timestamp"] = datetime.now(
                        UTC,
                    ).isoformat()

                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(schema_oc)

            except Exception as e:
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    f"OID objectClass parsing failed: {e}",
                )

        def _write_objectclass(
            self,
            schema_oc: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[str]:
            """Write Oracle OID objectClass definition with X-ORIGIN.

            Includes X-ORIGIN field from metadata if present, which is
            important for OID schema export and OUD compatibility.

            X-ORIGIN is a server-specific extension that tracks the origin
            of objectClass definitions (e.g., "Oracle OID", "RFC 4519").

            Args:
                schema_oc: Parsed schema objectClass model

            Returns:
                FlextResult with formatted LDIF objectClass definition string

            Example:
                Input: SchemaObjectClass with metadata.x_origin = "Oracle OID"
                Output: "( 2.5.6.6 NAME 'person' STRUCTURAL X-ORIGIN 'Oracle OID' )"

            """
            # Use RFC baseline writer
            result = FlextLdifUtilities.Writer.write_rfc_objectclass(schema_oc)

            if not result.is_success:
                return result

            rfc_str = result.unwrap()

            # Add X-ORIGIN if present in metadata (stored as extra field with extra="allow")
            if schema_oc.metadata:
                x_origin = getattr(schema_oc.metadata, "x_origin", None)
                if x_origin:
                    # Insert X-ORIGIN before closing paren
                    rfc_str = rfc_str.rstrip(" )")
                    rfc_str += f" X-ORIGIN '{x_origin}' )"

            return FlextResult[str].ok(rfc_str)

        def _transform_attribute_for_write(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextLdifModels.SchemaAttribute:
            """Apply OID-specific attribute transformations before writing.

            Implements hook from RFC base to apply OID quirks:
            - Fix NAME field: remove ;binary suffix, convert _ to -
            - Fix EQUALITY/SUBSTR: correct misused matching rules
            - Validate Matching Rules: ensure rules are RFC-compliant
            - Track Boolean Attributes: mark for special handling if needed

            Args:
                attr_data: SchemaAttribute to transform

            Returns:
                Transformed SchemaAttribute with OID fixes applied

            """
            # Apply AttributeFixer transformations to NAME
            fixed_name = FlextLdifUtilities.Schema.normalize_name(attr_data.name)
            if fixed_name is None:
                # This should never happen for valid attribute names, but handle gracefully
                fixed_name = attr_data.name

            # Apply AttributeFixer transformations to EQUALITY and SUBSTR
            # OID-specific mappings: normalize case variants to RFC-compliant forms
            fixed_equality, fixed_substr = (
                FlextLdifUtilities.Schema.normalize_matching_rules(
                    attr_data.equality,
                    attr_data.substr,
                    substr_rules_in_equality={
                        FlextLdifServersOid.Constants.MATCHING_RULE_CASE_IGNORE_SUBSTRINGS: FlextLdifServersOid.Constants.MATCHING_RULE_CASE_IGNORE,
                        FlextLdifServersOid.Constants.MATCHING_RULE_CASE_IGNORE_SUBSTRINGS_ALT: FlextLdifServersOid.Constants.MATCHING_RULE_CASE_IGNORE,
                    },
                    normalized_substr_values={
                        FlextLdifServersOid.Constants.MATCHING_RULE_CASE_IGNORE_SUBSTRINGS: FlextLdifServersOid.Constants.MATCHING_RULE_CASE_IGNORE_SUBSTRINGS,
                        FlextLdifServersOid.Constants.MATCHING_RULE_CASE_IGNORE_SUBSTRINGS_ALT: FlextLdifServersOid.Constants.MATCHING_RULE_CASE_IGNORE_SUBSTRINGS,
                    },
                )
            )

            # Validate and enhance matching rules for OID compatibility
            # Check for invalid SUBSTR rules and apply INVALID_SUBSTR_RULES mappings
            invalid_substr_rules = FlextLdifServersOid.Constants.INVALID_SUBSTR_RULES
            if fixed_substr and fixed_substr in invalid_substr_rules:
                replacement = invalid_substr_rules[fixed_substr]
                if replacement is not None:
                    logger.debug(
                        "Replacing invalid SUBSTR rule %s with %s",
                        fixed_substr,
                        replacement,
                    )
                    fixed_substr = replacement
                else:
                    logger.debug(
                        "Invalid SUBSTR rule %s has no replacement, keeping as-is",
                        fixed_substr,
                    )

            # Check if this is a boolean attribute for special handling during write
            is_boolean = fixed_name and fixed_name.lower() in {
                attr.lower()
                for attr in FlextLdifServersOid.Constants.BOOLEAN_ATTRIBUTES
            }
            if is_boolean:
                logger.debug("Identified boolean attribute: %s", fixed_name)

            # Create new attribute model with fixed values
            # Extract x_origin from metadata.extensions if available
            x_origin_value = (
                attr_data.metadata.extensions.get("x_origin")
                if attr_data.metadata and attr_data.metadata.extensions
                else None
            )

            return FlextLdifModels.SchemaAttribute(
                oid=attr_data.oid,
                name=fixed_name,
                desc=attr_data.desc,
                sup=attr_data.sup,
                equality=fixed_equality,
                ordering=attr_data.ordering,
                substr=fixed_substr,
                syntax=attr_data.syntax,
                length=attr_data.length,
                usage=attr_data.usage,
                single_value=attr_data.single_value,
                no_user_modification=attr_data.no_user_modification,
                metadata=attr_data.metadata,
                x_origin=cast("str | None", x_origin_value),
                x_file_ref=attr_data.x_file_ref,
                x_name=attr_data.x_name,
                x_alias=attr_data.x_alias,
                x_oid=attr_data.x_oid,
            )

        def _post_write_objectclass(self, written_str: str) -> str:
            """Fix known typos in written objectClass strings.

            Implements post-write hook from RFC base to fix:
            - AUXILLARY (double L) → AUXILIARY (single L) typo fix

            Args:
                written_str: RFC-formatted objectClass string from RFC base

            Returns:
                Potentially fixed objectClass string

            """
            # Fix AUXILLARY (double L) → AUXILIARY (single L) typo
            fixed = written_str.replace(
                FlextLdifServersOid.Constants.OBJECTCLASS_TYPO_AUXILLARY,
                FlextLdifServersOid.Constants.OBJECTCLASS_TYPO_AUXILIARY,
            )
            if fixed != written_str:
                logger.debug(
                    f"Fixed {FlextLdifServersOid.Constants.OBJECTCLASS_TYPO_AUXILLARY} typo in objectClass definition",
                )
            return fixed

        def extract_schemas_from_ldif(
            self,
            ldif_content: str,
            *,  # keyword-only parameter
            validate_dependencies: bool = False,
        ) -> FlextResult[dict[str, object]]:
            """Extract and parse all schema definitions from LDIF content.

            OID-specific implementation: Uses base template method without dependency
            validation (OID has simpler schema requirements than OUD).

            Args:
                ldif_content: Raw LDIF content containing schema definitions
                validate_dependencies: Whether to validate attribute dependencies
                    (default False for OID as it has simpler schema)

            Returns:
                FlextResult containing extracted attributes and objectclasses
                as a dictionary with ATTRIBUTES and OBJECTCLASS lists.

            """
            return super().extract_schemas_from_ldif(
                ldif_content,
                validate_dependencies=validate_dependencies,
            )

    class Acl(FlextLdifServersRfc.Acl):
        """Oracle OID ACL quirk using universal parser with OID-specific configuration.

        Delegates to FlextLdifUtilities.ACL.parser() with OID server-specific patterns,
        permissions mapping, and subject transformations. This ensures DRY compliance
        while maintaining full OID feature support.

        OID-specific features supported:
        - orclaci: Oracle standard ACIs
        - orclentrylevelaci: Oracle entry-level ACIs
        - Complex filter expressions with balanced parentheses
        - OID-specific permissions (browse, auth, self_write, proxy)
        - Multi-subject ACLs
        - Entry-level constraints (added_object_constraint)
        """

        # ACL attribute name is obtained from Constants.ACL_ATTRIBUTE_NAME
        # No instance variable needed - use Constants directly

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

        # OID-specific extensions
        OID_ACL_ATTRIBUTES: ClassVar[list[str]] = [
            "orclaci",  # OID-specific ACI
            "orclentrylevelaci",  # OID entry-level ACI
            "orclContainerLevelACL",  # OID container ACL
        ]

        def get_acl_attributes(self) -> list[str]:
            """Get RFC + OID extensions.

            Returns:
                List of ACL attribute names (RFC foundation + OID-specific)

            """
            return self.RFC_ACL_ATTRIBUTES + self.OID_ACL_ATTRIBUTES

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
        # These methods override the base class with Oracle OID-specific logic:
        # - can_handle_acl(): Detects orclaci/orclentrylevelaci formats
        # - parse_acl(): Normalizes Oracle OID ACL to RFC-compliant internal model
        # - write_acl(): Serializes RFC-compliant model to OID ACL format
        # - get_acl_attribute_name(): Returns "orclaci" (OID-specific, overridden)

        def can_handle(self, acl_line: str | FlextLdifModels.Acl) -> bool:
            """Check if this is an Oracle OID ACL (public method).

            Args:
                acl_line: ACL line string or Acl model to check.

            Returns:
                True if this is Oracle OID ACL format

            """
            return self.can_handle_acl(acl_line)

        def can_handle_acl(self, acl_line: str | FlextLdifModels.Acl) -> bool:
            """Check if this is an Oracle OID ACL.

            Detects Oracle OID ACL by checking if the line starts with:
            - "orclaci:" (Oracle standard ACI)
            - "orclentrylevelaci:" (Oracle entry-level ACI)

            Args:
                acl_line: Raw ACL line from LDIF or Acl model

            Returns:
                True if this is orclaci or orclentrylevelaci

            """
            if isinstance(acl_line, FlextLdifModels.Acl):
                # Check metadata for OID server type
                if acl_line.metadata and acl_line.metadata.quirk_type:
                    return acl_line.metadata.quirk_type == self._get_server_type()
                return False
            if not acl_line or not isinstance(acl_line, str):
                return False
            acl_line_lower = acl_line.strip().lower()
            return acl_line_lower.startswith(
                (
                    f"{FlextLdifServersOid.Constants.ORCLACI}:",
                    f"{FlextLdifServersOid.Constants.ORCLENTRYLEVELACI}:",
                ),
            )

        def _parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse Oracle OID ACL string to RFC-compliant internal model.

            Normalizes Oracle OID-specific ACL format (orclaci/orclentrylevelaci)
            to RFC-compliant internal representation using AclParser.

            OID-specific features normalized:
            - orclaci/orclentrylevelaci ACL types
            - Complex filter expressions with nested parentheses
            - Multi-subject bindings (dnattr, guidattr, groupattr)
            - Entry-level constraints (added_object_constraint)

            Args:
                acl_line: Oracle OID ACL definition line from LDIF

            Returns:
                FlextResult with RFC-compliant Acl model

            """
            # Always try parent's _parse_acl first (RFC format)
            parent_result = super()._parse_acl(acl_line)

            # If parent validation failed (empty string, etc.), return error immediately
            if parent_result.is_failure:
                return parent_result

            if parent_result.is_success:
                acl_data = parent_result.unwrap()
                # Check if this is an OID ACL and the parent parser populated it correctly
                if self.can_handle(acl_line):
                    # If this is an OID ACL and parent didn't parse it well (empty model),
                    # skip to OID-specific parsing
                    if (
                        acl_data.permissions is not None
                        or acl_data.target is not None
                        or acl_data.subject is not None
                    ):
                        # Parent parser populated the model, use it with OID server_type
                        # Use model_copy to create new instance with updated fields
                        updated_metadata = acl_data.metadata
                        if updated_metadata:
                            updated_metadata = updated_metadata.model_copy(
                                update={
                                    "quirk_type": self._get_server_type(),
                                },
                            )
                        else:
                            updated_metadata = FlextLdifModels.QuirkMetadata.create_for(
                                self._get_server_type(),
                                extensions={"original_format": acl_line.strip()},
                            )

                        acl_data = acl_data.model_copy(
                            update={
                                "server_type": self._get_server_type(),
                                "metadata": updated_metadata,
                            },
                        )
                        return FlextResult[FlextLdifModels.Acl].ok(acl_data)
                    # Otherwise fall through to OID-specific parsing
                else:
                    # Not an OID ACL, use parent result
                    return FlextResult[FlextLdifModels.Acl].ok(acl_data)

            # RFC parser failed - use OID-specific parsing
            # Parse OID ACL format: orclaci: access to [entry|attr=(...)] [by subject (permissions)]
            try:
                # Extract target using DRY utility
                target_dn, target_attrs = FlextLdifUtilities.ACL.extract_oid_target(
                    acl_line,
                )

                # Detect subject using DRY utility with OID patterns
                subject_patterns: dict[str, tuple[str | None, str, str]] = (
                    FlextLdifServersOid.Constants.ACL_SUBJECT_PATTERNS
                )
                subject_type, subject_value = FlextLdifUtilities.ACL.detect_oid_subject(
                    acl_line,
                    subject_patterns,
                )

                # Parse permissions using DRY utility
                perms_dict = FlextLdifUtilities.ACL.parse_oid_permissions(
                    acl_line,
                    FlextLdifServersOid.Constants.ACL_PERMISSION_MAPPING,
                )

                # Create ACL model with parsed data
                acl_model = FlextLdifModels.Acl(
                    name=FlextLdifServersOid.Constants.ACL_NAME,
                    target=FlextLdifModels.AclTarget(
                        target_dn=target_dn,
                        attributes=target_attrs or [],
                    ),
                    subject=FlextLdifModels.AclSubject(
                        subject_type=subject_type,
                        subject_value=subject_value,
                    ),
                    permissions=FlextLdifModels.AclPermissions(**perms_dict),
                    server_type=cast(
                        "FlextLdifConstants.LiteralTypes.ServerType",
                        self._get_server_type(),
                    ),
                    metadata=FlextLdifModels.QuirkMetadata(
                        quirk_type=self._get_server_type(),
                        extensions={
                            "original_format": acl_line.strip(),
                            "oid_parsed": True,
                            "rfc_parsed": False,
                        },
                    ),
                    raw_acl=acl_line,
                )
                return FlextResult[FlextLdifModels.Acl].ok(acl_model)
            except Exception as e:
                logger.debug("OID ACL parse failed: %s", e)
                # Return parent's error result (don't mask it)
                return parent_result

        def _get_oid_patterns(self) -> dict[str, str]:
            """Get OID-specific regex patterns for ACL parsing.

            Returns:
                Dictionary of pattern names to regex patterns for ACL component extraction.
                Patterns support:
                - acl_type: Identifies orclaci vs orclentrylevelaci
                - target: Extracts target entry or attributes
                - subject: Matches subject bindings (group, dnattr, guidattr, etc.)
                - permissions: Extracts permission list in parentheses
                - filter: Handles nested parentheses in filter expressions
                - constraint: Extracts entry-level constraints

            """
            return {
                FlextLdifServersOid.Constants.ACL_PATTERN_KEY_TYPE: (
                    FlextLdifServersOid.Constants.ACL_TYPE_PATTERN
                ),
                FlextLdifServersOid.Constants.ACL_PATTERN_KEY_TARGET: (
                    FlextLdifServersOid.Constants.ACL_TARGET_PATTERN
                ),
                FlextLdifServersOid.Constants.ACL_PATTERN_KEY_SUBJECT: (
                    FlextLdifServersOid.Constants.ACL_SUBJECT_PATTERN
                ),
                FlextLdifServersOid.Constants.ACL_PATTERN_KEY_PERMISSIONS: (
                    FlextLdifServersOid.Constants.ACL_PERMISSIONS_PATTERN
                ),
                FlextLdifServersOid.Constants.ACL_PATTERN_KEY_FILTER: (
                    FlextLdifServersOid.Constants.ACL_FILTER_PATTERN
                ),
                FlextLdifServersOid.Constants.ACL_PATTERN_KEY_CONSTRAINT: (
                    FlextLdifServersOid.Constants.ACL_CONSTRAINT_PATTERN
                ),
            }

        def convert_rfc_acl_to_aci(
            self,
            rfc_acl_attrs: dict[str, list[str]],
            target_server: str,  # noqa: ARG002
        ) -> FlextResult[dict[str, list[str]]]:
            """Convert RFC ACL format to Oracle OID orclaci format.

            Transforms RFC ACL attributes into OID-specific orclaci format with
            proper target, subject, and permissions formatting.

            Args:
                rfc_acl_attrs: ACL attributes in RFC format
                target_server: Target server type (expected: "oid")

            Returns:
                FlextResult with OID orclaci formatted attributes

            Note:
                Placeholder implementation - returns RFC format unchanged.
                Future: Parse RFC ACL structure and format as orclaci.

            """
            # Placeholder: Return RFC format unchanged
            # Real implementation would parse RFC structure and format as orclaci
            return FlextResult.ok(rfc_acl_attrs)

        def _write_acl(
            self,
            acl_data: FlextLdifModels.Acl,
            format_option: str | None = None,
        ) -> FlextResult[str]:
            """Write ACL to OID orclaci format with formatting options.

            Serializes the RFC-compliant internal model to Oracle OID orclaci format string.

            Args:
                acl_data: Acl model to write
                format_option: Formatting option - "default" (standard) or "oneline" (no breaks)

            Returns:
                FlextResult with OID orclaci formatted string

            """
            # Get default format if not provided
            if format_option is None:
                format_option = FlextLdifServersOid.Constants.ACL_FORMAT_DEFAULT

            # If raw_acl is available and already in OID format, use it
            if acl_data.raw_acl and acl_data.raw_acl.startswith(
                FlextLdifServersOid.Constants.ORCLACI + ":",
            ):
                return FlextResult[str].ok(acl_data.raw_acl)

            # Build orclaci format using DRY utilities
            acl_parts = [
                FlextLdifServersOid.Constants.ORCLACI + ":",
                FlextLdifServersOid.Constants.ACL_ACCESS_TO,
            ]

            # Format target clause using DRY utility
            target_str = FlextLdifUtilities.ACL.format_oid_target(acl_data.target)
            acl_parts.append(target_str)

            # Format subject clause using DRY utility
            if acl_data.subject:
                acl_parts.append(FlextLdifServersOid.Constants.ACL_BY)
                subject_str = FlextLdifUtilities.ACL.format_oid_subject(
                    acl_data.subject,
                    FlextLdifServersOid.Constants.ACL_SUBJECT_FORMATTERS,
                )
                acl_parts.append(subject_str)

                # Format permissions clause using DRY utility
                perms_str = FlextLdifUtilities.ACL.format_oid_permissions(
                    acl_data.permissions,
                    FlextLdifServersOid.Constants.ACL_PERMISSION_NAMES,
                )
                acl_parts.append(perms_str)

            # Join parts based on formatting option
            if format_option == FlextLdifServersOid.Constants.ACL_FORMAT_ONELINE:
                # Single line with no breaks
                orclaci_str = " ".join(acl_parts)
            else:
                # Default: single line (standard orclaci format)
                orclaci_str = " ".join(acl_parts)

            return FlextResult[str].ok(orclaci_str)

        def can_handle_attribute(
            self,
            attribute: FlextLdifModels.SchemaAttribute,
        ) -> bool:
            """Check if this ACL quirk should be aware of a specific attribute definition."""
            _ = attribute
            return False

        def can_handle_objectclass(
            self,
            objectclass: FlextLdifModels.SchemaObjectClass,
        ) -> bool:
            """Check if this ACL quirk should be aware of a specific objectClass definition."""
            _ = objectclass
            return False

    class Entry(FlextLdifServersRfc.Entry):
        """Oracle OID Entry Quirk - Transforms OID-specific boolean values to RFC format.

        Handles OID-specific entry transformations:
        - Converts boolean attribute values from OID format ("0"/"1") to RFC format ("TRUE"/"FALSE")
        - Stores conversion metadata for audit and round-trip compatibility
        - Converts OID-specific attribute names to RFC-canonical format (orclaci → aci)
        """

        def _normalize_attribute_name(self, attr_name: str) -> str:
            """Normalize OID attribute names to RFC-canonical format.

            Converts Oracle OID-specific attribute names to RFC standard equivalents.
            This transformation happens during the PARSING phase (Phase 1) to create
            RFC-canonical entries that can be processed uniformly by downstream logic.

            Transformations:
            - orclaci → aci: OID access control list to RFC ACI
            - orclentrylevelaci → aci: OID entry-level ACL to RFC ACI

            All other attributes are delegated to the RFC base implementation for
            standard normalization (e.g., objectclass → objectClass).

            Args:
                attr_name: Raw attribute name from LDIF

            Returns:
                RFC-canonical attribute name

            """
            attr_lower = attr_name.lower()

            # OID ACL attributes → RFC ACI (Phase 1: Parsing transformation)
            if attr_lower == "orclaci":
                return "aci"  # Oracle OID ACL → RFC standard ACI
            if attr_lower == "orclentrylevelaci":
                return "aci"  # Oracle OID entry-level ACI → RFC standard ACI

            # Delegate to RFC for standard normalization (objectclass, etc.)
            return super()._normalize_attribute_name(attr_name)

        def _parse_entry(  # noqa: C901
            self,
            entry_dn: str,
            entry_attrs: Mapping[str, object],
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Parse OID entry and convert boolean attributes to RFC format.

            OID uses "0"/"1" for boolean values, but RFC4517 requires "TRUE"/"FALSE".
            OID also exports DNs with quirks (spaces, unescaped UTF-8, etc.).

            This method:
            1. Cleans DN to fix OID quirks (spaces before commas, UTF-8, etc.)
            2. Calls parent RFC parser with cleaned DN to create base Entry
            3. Converts boolean attribute values from OID format to RFC format
            4. Stores metadata about conversions and DN cleaning for tracking

            Args:
                entry_dn: Entry distinguished name (may have OID quirks)
                entry_attrs: Raw attribute mapping from LDIF parser

            Returns:
                FlextResult with Entry model with boolean values converted to RFC format
                and DN cleaned to RFC-compliant format, with original DN preserved in metadata

            """
            # Step 0: Clean DN to fix OID quirks BEFORE RFC parser validation
            # OID exports DNs with spaces (e.g., "cn=user ,ou=..." instead of "cn=user,ou=...")
            # and unescaped UTF-8 (e.g., "cn=josé" instead of "cn=jos\C3\A9")
            original_dn = entry_dn
            cleaned_dn, dn_stats = FlextLdifUtilities.DN.clean_dn_with_statistics(
                entry_dn,
            )

            # Step 1: Call RFC parser with CLEANED DN to create base Entry
            result = super()._parse_entry(cleaned_dn, entry_attrs)
            if result.is_failure:
                # Log parser rejection with diagnostic details
                # This helps track the 289 missing entries issue
                self.logger.debug(
                    "OID parser rejected entry during RFC parsing",
                    original_dn=original_dn[:100] if len(original_dn) > 100 else original_dn,
                    cleaned_dn=cleaned_dn[:100] if len(cleaned_dn) > 100 else cleaned_dn,
                    error=str(result.error)[:200],
                )
                return result

            entry = result.unwrap()

            # Check if entry has attributes
            if not entry.attributes:
                return result

            # Step 2: Convert OID boolean values to RFC format
            boolean_attributes = FlextLdifServersOid.Constants.BOOLEAN_ATTRIBUTES
            converted_attrs: set[str] = set()

            # Create new attributes dict with converted boolean values
            converted_attributes: dict[str, list[str]] = {}
            for attr_name, attr_values in entry.attributes.attributes.items():
                if attr_name.lower() in boolean_attributes:
                    # Convert boolean values
                    converted_values: list[str] = []
                    for value in attr_values:
                        value_lower = value.lower()
                        # Map OID values to RFC format
                        if value_lower in {"1", "true"}:
                            converted_values.append("TRUE")
                            converted_attrs.add(attr_name)
                        elif value_lower in {"0", "false"}:
                            converted_values.append("FALSE")
                            converted_attrs.add(attr_name)
                        else:
                            # Keep unexpected values as-is
                            converted_values.append(value)

                    converted_attributes[attr_name] = converted_values
                else:
                    converted_attributes[attr_name] = attr_values

            # Step 3: Create new Entry with converted attributes and metadata
            ldif_attrs = FlextLdifModels.LdifAttributes(
                attributes=converted_attributes,
            )

            # Create metadata with conversion information and DN cleaning
            conversion_metadata: dict[str, object] = {}
            if converted_attrs:
                conversion_metadata["boolean_attributes_converted"] = list(
                    converted_attrs,
                )
                logger.debug(
                    "Converted OID boolean attributes to RFC format: %s",
                    converted_attrs,
                )

            # Add DN cleaning metadata if DN was modified
            dn_metadata: dict[str, object] = {}
            if original_dn != cleaned_dn:
                dn_metadata["original_dn"] = original_dn
                dn_metadata["cleaned_dn"] = cleaned_dn
                dn_metadata["dn_was_cleaned"] = True
                logger.debug(
                    "Cleaned OID DN quirks: %s -> %s",
                    original_dn,
                    cleaned_dn,
                )

            metadata = FlextLdifModels.QuirkMetadata.create_for(
                FlextLdifConstants.ServerTypes.OID,
                extensions={
                    **conversion_metadata,
                    **dn_metadata,
                    "original_format": f"OID Entry with {len(converted_attrs)} boolean conversions",
                },
            )

            # Check DN is not None before creating entry
            if not entry.dn:
                return FlextResult[FlextLdifModels.Entry].fail("Entry has no DN")

            # Preserve original DN in DistinguishedName metadata if it was cleaned
            dn_to_use = entry.dn
            if original_dn != cleaned_dn:
                # Create new DN with metadata containing original DN
                dn_to_use = FlextLdifModels.DistinguishedName(
                    value=entry.dn.value,
                    metadata=dn_metadata,
                )

            # Create EntryStatistics with DN transformation tracking
            entry_stats = FlextLdifModels.EntryStatistics.create_with_dn_stats(
                dn_statistics=dn_stats,
            )
            entry_stats.was_parsed = True
            entry_stats.was_validated = True

            # Track attribute conversions
            for attr_name in converted_attrs:
                entry_stats.track_attribute_change(attr_name, "modified")

            # Track quirk application
            if dn_stats.was_transformed or converted_attrs:
                entry_stats.apply_quirk(FlextLdifConstants.ServerTypes.OID)

            # Create new Entry with converted attributes and statistics
            new_entry_result = FlextLdifModels.Entry.create(
                dn=dn_to_use,
                attributes=ldif_attrs,
                server_type=FlextLdifConstants.ServerTypes.OID,
                metadata=metadata,
                statistics=entry_stats,
            )

            if new_entry_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to create Entry with converted attributes: {new_entry_result.error}",
                )

            return new_entry_result.map(lambda e: cast("FlextLdifModels.Entry", e))
