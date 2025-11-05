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

from typing import ClassVar, Final, cast

from flext_core import FlextLogger, FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import FlextLdifTypes
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

    # === STANDARDIZED CONSTANTS FOR AUTO-DISCOVERY ===
    class Constants(FlextLdifServersRfc.Constants):
        """Oracle Internet Directory-specific constants centralized for operations in oid.py.

        These constants follow a standardized naming pattern that can be replicated
        in other server quirks implementations for consistency.
        """

        # Oracle OID ACL attribute names
        ORCLACI: Final[str] = "orclaci"  # Standard Oracle OID ACL
        ORCLENTRYLEVELACI: Final[str] = "orclentrylevelaci"  # Entry-level ACI
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
            | frozenset([
                "orclguid",
                "orclobjectguid",
                "orclentryid",
                "orclaccount",
                "pwdChangedTime",
                "pwdHistory",
                "pwdFailureTime",
            ])
        )

        # NOTE: PRESERVE_ON_MIGRATION inherited from RFC.Constants

        # Detection constants (server-specific)
        DETECTION_OID_PATTERN: ClassVar[str] = r"2\.16\.840\.1\.113894\."
        DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset([
            "orcl",
            "orclguid",
        ])
        DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset([
            "orcldirectory",
            "orcldomain",
            "orcldirectoryserverconfig",
        ])
        DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset([
            "cn=orcl",
            "cn=subscriptions",
            "cn=oracle context",
        ])

        # === SCHEMA PROCESSING CONFIGURATION ===
        # Schema field names (migrated from FlextLdifConstants.SchemaFields)
        SCHEMA_FIELD_ATTRIBUTE_TYPES: Final[str] = "attributetypes"
        SCHEMA_FIELD_ATTRIBUTE_TYPES_LOWER: Final[str] = "attributetypes"
        SCHEMA_FIELD_OBJECT_CLASSES: Final[str] = "objectclasses"
        SCHEMA_FIELD_OBJECT_CLASSES_LOWER: Final[str] = "objectclasses"
        SCHEMA_FIELD_MATCHING_RULES: Final[str] = "matchingrules"
        SCHEMA_FIELD_LDAP_SYNTAXES: Final[str] = "ldapsyntaxes"

        # Schema fields that should be processed with OID filtering
        SCHEMA_FILTERABLE_FIELDS: ClassVar[frozenset[str]] = frozenset([
            SCHEMA_FIELD_ATTRIBUTE_TYPES,
            SCHEMA_FIELD_ATTRIBUTE_TYPES_LOWER,
            SCHEMA_FIELD_OBJECT_CLASSES,
            SCHEMA_FIELD_OBJECT_CLASSES_LOWER,
            SCHEMA_FIELD_MATCHING_RULES,
            SCHEMA_FIELD_LDAP_SYNTAXES,
        ])

        # Schema DN for OID (RFC 4512 standard)
        SCHEMA_DN: ClassVar[str] = "cn=subschemasubentry"

        # Oracle OID boolean attributes (non-RFC: use "0"/"1" not "TRUE"/"FALSE")
        # RFC 4517 Boolean syntax requires "TRUE" or "FALSE"
        # OID quirks convert "0"→"FALSE", "1"→"TRUE" during OID→RFC
        BOOLEAN_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset([
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
            "orcldasadminmodifiable",
            # Oracle password policy boolean attributes
            "pwdlockout",
            "pwdmustchange",
            "pwdallowuserchange",
        ])

        # Server type variants (for compatibility checks)
        VARIANTS: ClassVar[frozenset[str]] = frozenset(["oid", "oracle_oid"])

        # Schema attribute fields that are server-specific (migrated from FlextLdifConstants.SchemaConversionMappings)
        ATTRIBUTE_FIELDS: ClassVar[frozenset[str]] = frozenset(["usage", "x_origin"])

        # ObjectClass requirements (extends RFC - allows multiple SUP)
        OBJECTCLASS_REQUIREMENTS: ClassVar[dict[str, bool]] = {
            "requires_sup_for_auxiliary": True,
            "allows_multiple_sup": True,  # OID allows multiple SUP
            "requires_explicit_structural": False,
        }

        # Oracle OID specific operational attributes (extended set)
        OID_SPECIFIC: ClassVar[frozenset[str]] = frozenset([
            # Note: Using literal strings to avoid circular reference during class definition
            # These correspond to Constants.ACL_ATTRIBUTE_NAME and Constants.ORCLENTRYLEVELACI
            "orclaci",
            "orclentrylevelaci",
            "orclguid",  # Oracle GUID
            "orclmailaddr",  # Mail address
            "orcluseractivefrom",  # User active from date
            "orcluserinactivefrom",  # User inactive from date
        ])

        # Oracle OID specific attributes (categorization - migrated from FlextLdifConstants.AttributeCategories)
        OID_SPECIFIC_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset([
            # Note: Using literal strings to avoid circular reference during class definition
            # These correspond to Constants.ACL_ATTRIBUTE_NAME and Constants.ORCLENTRYLEVELACI
            "orcloid",  # Oracle OID identifier
            "orclguid",  # Oracle GUID
            "orclpassword",  # Oracle password attribute
            "orclaci",
            "orclentrylevelaci",
            "orcldaslov",  # Oracle DASLOV configuration
        ])

        # === STANDARDIZED CONSTANTS FOR AUTO-DISCOVERY ===
        SERVER_TYPE: ClassVar[str] = FlextLdifConstants.ServerTypes.OID
        CANONICAL_NAME: ClassVar[str] = "oid"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["oid", "oracle_oid"])
        PRIORITY: ClassVar[int] = 10
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["oid"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["oid", "rfc"])

        # Server detection patterns and weights (migrated from FlextLdifConstants.ServerDetection)
        DETECTION_PATTERN: ClassVar[str] = r"2\.16\.840\.1\.113894\."
        DETECTION_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset([
            "orclOID",
            "orclGUID",
            "orclPassword",
            "orclaci",
            "orclentrylevelaci",
            "orcldaslov",
        ])
        DETECTION_WEIGHT: ClassVar[int] = 10

        # Oracle OID metadata keys (migrated from FlextLdifConstants.QuirkMetadataKeys)
        OID_SPECIFIC_RIGHTS: ClassVar[str] = "oid_specific_rights"
        OID_TO_OUD_TRANSFORMED: ClassVar[str] = "oid_to_oud_transformed"

        # Permission names inherited from RFC.Constants
        # (PERMISSION_READ, PERMISSION_WRITE, PERMISSION_ADD, PERMISSION_DELETE, PERMISSION_SEARCH, PERMISSION_COMPARE)

        # ACL subject types (migrated from FlextLdifConstants.AclSubjectTypes)
        ACL_SUBJECT_TYPE_USER: ClassVar[str] = "user"
        ACL_SUBJECT_TYPE_GROUP: ClassVar[str] = "group"
        ACL_SUBJECT_TYPE_SELF: ClassVar[str] = "self"
        ACL_SUBJECT_TYPE_ANONYMOUS: ClassVar[str] = "anonymous"

        # ACL parsing patterns (migrated from _parse_acl method)
        ACL_TYPE_PATTERN: Final[str] = r"^(orclaci|orclentrylevelaci):"
        ACL_TARGET_PATTERN: Final[str] = r"access to (entry|attr=\(([^)]+)\))"
        ACL_SUBJECT_PATTERN: Final[str] = (
            r"by\s+(group=\"[^\"]+\"|dnattr=\([^)]+\)|guidattr=\([^)]+\"|groupattr=\([^)]+\)|\"[^\"]+\"|self|\*)"
        )
        ACL_PERMISSIONS_PATTERN: Final[str] = r"\(([^)]+)\)(?:\s*$)"
        ACL_FILTER_PATTERN: Final[str] = r"filter=(\([^)]*(?:\([^)]*\)[^)]*)*\))"
        ACL_CONSTRAINT_PATTERN: Final[str] = r"added_object_constraint=\(([^)]+)\)"

        # ACL pattern dictionary keys (used in _get_oid_patterns)
        ACL_PATTERN_KEY_TYPE: Final[str] = "acl_type"
        ACL_PATTERN_KEY_TARGET: Final[str] = "target"
        ACL_PATTERN_KEY_SUBJECT: Final[str] = "subject"
        ACL_PATTERN_KEY_PERMISSIONS: Final[str] = "permissions"
        ACL_PATTERN_KEY_FILTER: Final[str] = "filter"
        ACL_PATTERN_KEY_CONSTRAINT: Final[str] = "constraint"

        # ObjectClass typo fix constant (migrated from _post_write_objectclass method)
        OBJECTCLASS_TYPO_AUXILLARY: Final[str] = "AUXILLARY"
        OBJECTCLASS_TYPO_AUXILIARY: Final[str] = "AUXILIARY"

        # Matching rule normalization constants (migrated from _transform_attribute_for_write method)
        MATCHING_RULE_CASE_IGNORE_SUBSTRINGS: Final[str] = "caseIgnoreSubstringsMatch"
        MATCHING_RULE_CASE_IGNORE_SUBSTRINGS_ALT: Final[str] = (
            "caseIgnoreSubStringsMatch"
        )
        MATCHING_RULE_CASE_IGNORE: Final[str] = "caseIgnoreMatch"

        # Oracle OID boolean format constants (non-RFC compliant)
        # RFC 4517 compliant uses "TRUE" / "FALSE"
        # Oracle OID uses "1" / "0"
        ONE_OID: Final[str] = "1"
        ZERO_OID: Final[str] = "0"

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
        OID_TRUE_VALUES: ClassVar[frozenset[str]] = frozenset([
            ONE_OID,
            "true",
            "True",
            "TRUE",
        ])
        OID_FALSE_VALUES: ClassVar[frozenset[str]] = frozenset([
            ZERO_OID,
            "false",
            "False",
            "FALSE",
        ])

        # Matching rule replacement mappings for invalid substr rules
        INVALID_SUBSTR_RULES: ClassVar[dict[str, str | None]] = {
            "caseIgnoreMatch": "caseIgnoreSubstringsMatch",
            "caseExactMatch": "caseExactSubstringsMatch",
            "distinguishedNameMatch": None,
            "integerMatch": None,
            "numericStringMatch": "numericStringSubstringsMatch",
        }

        # === OID ACL SUBJECT TRANSFORMATIONS (for OID → RFC → OUD conversion) ===
        # Subject type transformations from OID format to RFC format
        OID_TO_RFC_SUBJECTS: ClassVar[dict[str, tuple[str, str]]] = {
            "dynamic_group_dnattr": ("group_membership", 'memberOf="{value}"'),
            "dynamic_group_guidattr": ("user_attribute", 'guidattr="{value}"'),
            "dynamic_group_attr": ("group_attribute", 'groupattr="{value}"'),
        }

        # Subject type transformations from RFC format back to OID format
        RFC_TO_OID_SUBJECTS: ClassVar[dict[str, tuple[str, str]]] = {
            "group_membership": ("group_dn", 'group="{value}"'),
        }

        # === OID ATTRIBUTE TRANSFORMATIONS ===
        # Maps OID-specific attributes to RFC-compliant attributes during normalization
        ATTRIBUTE_TRANSFORMATION_OID_TO_RFC: ClassVar[dict[str, str]] = {
            "orclguid": "entryUUID",
            "orclobjectguid": "entryUUID",
            "createTimestamp": "createTimestamp",  # Preserved as-is
            "modifyTimestamp": "modifyTimestamp",  # Preserved as-is
        }

        # Maps RFC attributes back to OID-specific attributes during denormalization
        ATTRIBUTE_TRANSFORMATION_RFC_TO_OID: ClassVar[dict[str, str]] = {
            "entryUUID": "orclguid",
        }

        # === ACL FORMATTING CONSTANTS ===
        ACL_ACCESS_TO: Final[str] = "access to"
        ACL_BY: Final[str] = "by"
        ACL_FORMAT_DEFAULT: Final[str] = "default"
        ACL_FORMAT_ONELINE: Final[str] = "oneline"
        ACL_NAME: Final[str] = "OID ACL"

        # === ACL SUBJECT PATTERNS ===
        # Subject detection patterns for OID ACL parsing
        ACL_SUBJECT_PATTERNS: ClassVar[dict[str, tuple[str | None, str, str]]] = {
            " by self ": (None, "self", "ldap:///self"),
            " by self)": (None, "self", "ldap:///self"),
            ' by "': (r'by\s+"([^"]+)"', "user_dn", "ldap:///{0}"),
            " by group=": (r'by\s+group\s*=\s*"([^"]+)"', "group_dn", "ldap:///{0}"),
            " by dnattr=": (r"by\s+dnattr\s*=\s*\(([^)]+)\)", "dn_attr", "{0}#LDAPURL"),
            " by guidattr=": (r"by\s+guidattr\s*=\s*\(([^)]+)\)", "guid_attr", "{0}#USERDN"),
            " by groupattr=": (r"by\s+groupattr\s*=\s*\(([^)]+)\)", "group_attr", "{0}#GROUPDN"),
        }

        # === ACL SUBJECT FORMATTERS ===
        # Subject formatters for OID ACL writing
        ACL_SUBJECT_FORMATTERS: ClassVar[dict[str, tuple[str, bool]]] = {
            "self": ("self", False),
            "user_dn": ('"{0}"', True),
            "group_dn": ('group="{0}"', True),
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
        SUPPORTED_PERMISSIONS: ClassVar[frozenset[str]] = frozenset([
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
        ])

        # === OID PERMISSION ALTERNATIVES ===
        # Permission alternatives when converting FROM OID to other servers
        # Format: (permission, target_server) -> [alternative_permissions]
        # (migrated from FlextLdifConstants.AclPermissionCompatibility)
        PERMISSION_ALTERNATIVES: ClassVar[dict[tuple[str, str], list[str]]] = {
            ("self_write", "oud"): ["write"],
            ("self_write", "oracle_oud"): ["write"],
            ("self_write", "rfc"): ["write"],
            ("self_write", "389ds"): ["write"],
            ("self_write", "openldap"): ["write"],
            ("proxy", "oud"): [],  # No equivalent
            ("proxy", "oracle_oud"): [],
            ("proxy", "rfc"): [],
            ("proxy", "openldap"): [],
            ("browse", "oud"): ["read", "search"],
            ("browse", "oracle_oud"): ["read", "search"],
            ("browse", "rfc"): ["read", "search"],
            ("browse", "389ds"): ["read", "search"],
            ("browse", "openldap"): ["read", "search"],
            ("auth", "oud"): ["compare"],
            ("auth", "oracle_oud"): ["compare"],
            ("auth", "rfc"): ["compare"],
        }

        # === OID ATTRIBUTE ALIASES ===
        # Attribute aliases for OID (multiple names for same semantic attribute)
        # (migrated from FlextLdifConstants.SchemaConversionMappings)
        ATTRIBUTE_ALIASES: ClassVar[dict[str, list[str]]] = {
            "cn": ["commonName"],
            "mail": ["rfc822Mailbox"],
            "uid": ["userid"],
        }

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

    class Schema(
        FlextLdifServersRfc.Schema,
        FlextLdifUtilities.Detection.OidPatternMixin,  # type: ignore[name-defined]
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

        @FlextLdifUtilities.Decorators.attach_parse_metadata("oid")
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
                # Fix matching rules that are invalid in OUD
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

                return FlextResult[FlextLdifModels.SchemaAttribute].ok(schema_attr)

            except Exception as e:
                return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                    f"OID attribute parsing failed: {e}",
                )

        @FlextLdifUtilities.Decorators.attach_parse_metadata("oid")
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
                # Use RFC baseline parser with lenient mode for OID's case-insensitive NAME
                result = FlextLdifUtilities.Parser.parse_rfc_objectclass(
                    oc_definition,
                    case_insensitive=True,  # OID uses case-insensitive NAME
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

                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(schema_oc)

            except Exception as e:
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    f"OID objectClass parsing failed: {e}",
                )

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
                        "Replacing invalid SUBSTR rule %s with %s", fixed_substr, replacement,
                    )
                    fixed_substr = replacement
                else:
                    logger.debug(
                        "Invalid SUBSTR rule %s has no replacement, keeping as-is", fixed_substr,
                    )

            # Check if this is a boolean attribute for special handling during write
            is_boolean = (
                fixed_name and
                fixed_name.lower() in {
                    attr.lower()
                    for attr in FlextLdifServersOid.Constants.BOOLEAN_ATTRIBUTES
                }
            )
            if is_boolean:
                logger.debug("Identified boolean attribute: %s", fixed_name)

            # Create new attribute model with fixed values
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

        def _extract_schemas_from_ldif(
            self,
            ldif_content: str,
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Extract and parse all schema definitions from LDIF content.

            Strategy pattern: OID-specific approach to extract attributeTypes
            and objectClasses from cn=schema LDIF entries, handling OID's
            format variations.

            This is a private helper method for internal schema extraction.

            Args:
                ldif_content: Raw LDIF content containing schema definitions

            Returns:
                FlextResult containing extracted attributes and objectclasses
                as a dictionary with ATTRIBUTES and OBJECTCLASSES lists.

            """
            dk = FlextLdifConstants.DictKeys
            # Use FlextLdifUtilities.Schema for case-insensitive line parsing
            attributes = FlextLdifUtilities.Schema.extract_attributes_from_lines(
                ldif_content,
                self._parse_attribute,
            )
            objectclasses = (
                FlextLdifUtilities.Schema.extract_objectclasses_from_lines(
                    ldif_content,
                    self._parse_objectclass,
                )
            )

            return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok({
                dk.ATTRIBUTES: attributes,
                "objectclasses": objectclasses,
            })

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
                    return (
                        acl_line.metadata.quirk_type
                        == FlextLdifServersOid.Constants.SERVER_TYPE
                    )
                return False
            if not acl_line or not isinstance(acl_line, str):
                return False
            acl_line_lower = acl_line.strip().lower()
            return acl_line_lower.startswith((
                f"{FlextLdifServersOid.Constants.ORCLACI}:",
                f"{FlextLdifServersOid.Constants.ORCLENTRYLEVELACI}:",
            ))

        @FlextLdifUtilities.Decorators.attach_parse_metadata("oid")
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
            if parent_result.is_success:
                acl_data = parent_result.unwrap()
                # Check if this is an OID ACL and the parent parser populated it correctly
                if self.can_handle(acl_line):
                    # If this is an OID ACL and parent didn't parse it well (empty model),
                    # skip to OID-specific parsing
                    if acl_data.permissions is not None or acl_data.target is not None or acl_data.subject is not None:
                        # Parent parser populated the model, use it
                        acl_data.server_type = cast(
                            "FlextLdifConstants.LiteralTypes.ServerType",
                            FlextLdifServersOid.Constants.SERVER_TYPE,
                        )
                        if acl_data.metadata:
                            acl_data.metadata.quirk_type = (
                                FlextLdifServersOid.Constants.SERVER_TYPE
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
                target_dn, target_attrs = FlextLdifUtilities.ACL.extract_oid_target(acl_line)

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
                    target=FlextLdifModels.AclTarget(target_dn=target_dn, attributes=target_attrs or []),
                    subject=FlextLdifModels.AclSubject(
                        subject_type=subject_type,
                        subject_value=subject_value,
                    ),
                    permissions=FlextLdifModels.AclPermissions(**perms_dict),
                    metadata=FlextLdifModels.QuirkMetadata(
                        quirk_type=FlextLdifServersOid.Constants.SERVER_TYPE,
                        original_format=acl_line.strip(),
                        extensions={"oid_parsed": True, "rfc_parsed": False},
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

        @FlextLdifUtilities.Decorators.attach_write_metadata("oid")
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
            self, attribute: FlextLdifModels.SchemaAttribute,
        ) -> bool:
            """Check if this ACL quirk should be aware of a specific attribute definition."""
            _ = attribute
            return False

        def can_handle_objectclass(
            self, objectclass: FlextLdifModels.SchemaObjectClass,
        ) -> bool:
            """Check if this ACL quirk should be aware of a specific objectClass definition."""
            _ = objectclass
            return False
