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

import re
from typing import ClassVar, Final

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
        if quirk.schema._can_handle_attribute(attr_def):
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
        MATCHING_RULE_REPLACEMENTS: Final[dict[str, str]] = {
            "caseIgnoreSubStringsMatch": "caseIgnoreSubstringsMatch",  # Fix capitalization
            "accessDirectiveMatch": "caseIgnoreMatch",  # Replace OID-specific with standard
        }

        # Syntax OID replacements for OUD compatibility
        SYNTAX_OID_REPLACEMENTS: Final[dict[str, str]] = {
            "1.3.6.1.4.1.1466.115.121.1.1": "1.3.6.1.4.1.1466.115.121.1.15",  # ACI List → Directory String
        }

        # Oracle OID operational attributes (server-specific)
        OPERATIONAL_ATTRIBUTES: Final[frozenset[str]] = frozenset([
            "orclGUID",
            "orclOracleGUID",
            "orclPassword",
            "orclPasswordChangedTime",
            "orclIsEnabled",
        ])

        # Detection constants (server-specific)
        DETECTION_OID_PATTERN: Final[str] = r"2\.16\.840\.1\.113894\."
        DETECTION_ATTRIBUTE_PREFIXES: Final[frozenset[str]] = frozenset([
            "orcl",
            "orclguid",
        ])
        DETECTION_OBJECTCLASS_NAMES: Final[frozenset[str]] = frozenset([
            "orcldirectory",
            "orcldomain",
            "orcldirectoryserverconfig",
        ])
        DETECTION_DN_MARKERS: Final[frozenset[str]] = frozenset([
            "cn=orcl",
            "cn=subscriptions",
            "cn=oracle context",
        ])

        # Oracle OID boolean attributes (non-RFC: use "0"/"1" not "TRUE"/"FALSE")
        # RFC 4517 Boolean syntax requires "TRUE" or "FALSE"
        # OID quirks convert "0"→"FALSE", "1"→"TRUE" during OID→RFC
        BOOLEAN_ATTRIBUTES: Final[frozenset[str]] = frozenset([
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
        VARIANTS: Final[frozenset[str]] = frozenset(["oid", "oracle_oid"])

        # Oracle OID specific operational attributes (extended set)
        OID_SPECIFIC: Final[frozenset[str]] = frozenset([
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
        OID_SPECIFIC_ATTRIBUTES: Final[frozenset[str]] = frozenset([
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

        # Oracle OID metadata keys (migrated from FlextLdifConstants.QuirkMetadataKeys)
        OID_SPECIFIC_RIGHTS: Final[str] = "oid_specific_rights"
        OID_TO_OUD_TRANSFORMED: Final[str] = "oid_to_oud_transformed"

        # Oracle OID boolean format constants (non-RFC compliant)
        # RFC 4517 compliant uses "TRUE" / "FALSE"
        # Oracle OID uses "1" / "0"
        ONE_OID: Final[str] = "1"
        ZERO_OID: Final[str] = "0"

        # Boolean conversion mappings (using Constants for consistency)
        OID_TO_RFC: Final[dict[str, str]] = {
            ONE_OID: "TRUE",  # Use Constants.ONE_OID
            ZERO_OID: "FALSE",  # Use Constants.ZERO_OID
            "true": "TRUE",
            "false": "FALSE",
        }

        RFC_TO_OID: Final[dict[str, str]] = {
            "TRUE": ONE_OID,  # Use Constants.ONE_OID
            "FALSE": ZERO_OID,  # Use Constants.ZERO_OID
            "true": ONE_OID,  # Use Constants.ONE_OID
            "false": ZERO_OID,  # Use Constants.ZERO_OID
        }

        # Universal boolean check
        OID_TRUE_VALUES: Final[frozenset[str]] = frozenset([
            ONE_OID,
            "true",
            "True",
            "TRUE",
        ])
        OID_FALSE_VALUES: Final[frozenset[str]] = frozenset([
            ZERO_OID,
            "false",
            "False",
            "FALSE",
        ])

        # Matching rule replacement mappings for invalid substr rules
        INVALID_SUBSTR_RULES: Final[dict[str, str | None]] = {
            "caseIgnoreMatch": "caseIgnoreSubstringsMatch",
            "caseExactMatch": "caseExactSubstringsMatch",
            "distinguishedNameMatch": None,
            "integerMatch": None,
            "numericStringMatch": "numericStringSubstringsMatch",
        }

        # OID ACL parsing regex patterns (migrated from _get_oid_patterns method)
        ACL_PATTERNS: Final[dict[str, str]] = {
            "acl_type": r"^(orclaci|orclentrylevelaci):",
            "target": r"access to (entry|attr=\(([^)]+)\))",
            "subject": r"by\s+(group=\"[^\"]+\"|dnattr=\([^)]+\)|guidattr=\([^)]+\"|groupattr=\([^)]+\)|\"[^\"]+\"|self|\*)",
            "permissions": r"\(([^)]+)\)(?:\s*$)",
            "filter": r"filter=(\([^)]*(?:\([^)]*\)[^)]*)*\))",
            "constraint": r"added_object_constraint=\(([^)]+)\)",
        }

        # === OID ACL SUBJECT TRANSFORMATIONS (for OID → RFC → OUD conversion) ===
        # Subject type transformations from OID format to RFC format
        OID_TO_RFC_SUBJECTS: Final[dict[str, tuple[str, str]]] = {
            "dynamic_group_dnattr": ("group_membership", 'memberOf="{value}"'),
            "dynamic_group_guidattr": ("user_attribute", 'guidattr="{value}"'),
            "dynamic_group_attr": ("group_attribute", 'groupattr="{value}"'),
        }

        # Subject type transformations from RFC format back to OID format
        RFC_TO_OID_SUBJECTS: Final[dict[str, tuple[str, str]]] = {
            "group_membership": ("group_dn", 'group="{value}"'),
        }

        # === OID ATTRIBUTE TRANSFORMATIONS ===
        # Maps OID-specific attributes to RFC-compliant attributes during normalization
        ATTRIBUTE_TRANSFORMATION_OID_TO_RFC: Final[dict[str, str]] = {
            "orclguid": "entryUUID",
            "orclobjectguid": "entryUUID",
            "createTimestamp": "createTimestamp",  # Preserved as-is
            "modifyTimestamp": "modifyTimestamp",  # Preserved as-is
        }

        # Maps RFC attributes back to OID-specific attributes during denormalization
        ATTRIBUTE_TRANSFORMATION_RFC_TO_OID: Final[dict[str, str]] = {
            "entryUUID": "orclguid",
        }

    # =========================================================================
    # Class-level attributes for server identification (from Constants)
    # =========================================================================
    server_type: ClassVar[str] = Constants.SERVER_TYPE
    priority: ClassVar[int] = Constants.PRIORITY

    def __init__(self) -> None:
        """Initialize Oracle OID server quirks."""
        super().__init__()
        # Use object.__setattr__ to bypass Pydantic validation for dynamic attributes
        # Pass server_type and priority to nested class instances
        object.__setattr__(self, "schema", self.Schema())
        object.__setattr__(self, "acl", self.Acl())
        object.__setattr__(self, "entry", self.Entry())

    class Schema(FlextLdifServersRfc.Schema):
        """Oracle OID schema quirks implementation."""

        def __init__(self, **kwargs: object) -> None:
            """Initialize OID schema quirk.

            server_type and priority are obtained from parent class Constants.
            They are not passed as parameters anymore.

            Args:
                **kwargs: Passed to parent for compatibility (ignored)

            """
            super().__init__(**kwargs)

        def _can_handle_attribute(
            self, attr_definition: str | FlextLdifModels.SchemaAttribute
        ) -> bool:
            """Check if this attribute should be processed by OID quirks.

            Only handles Oracle OID-specific attributes (OID namespace 2.16.840.1.113894.*).
            Standard RFC attributes are handled by the base RFC quirks.

            Args:
                attr_definition: The attribute definition string or model to check.

            Returns:
                True if attribute is Oracle OID-specific (namespace 2.16.840.1.113894.*)

            """
            if isinstance(attr_definition, str):
                # Check if string contains OID pattern
                return bool(
                    re.search(
                        FlextLdifServersOid.Constants.DETECTION_OID_PATTERN,
                        attr_definition,
                    )
                )
            # Check if model has OID pattern in oid field
            return bool(
                attr_definition.oid
                and re.search(
                    FlextLdifServersOid.Constants.DETECTION_OID_PATTERN,
                    attr_definition.oid,
                )
            )

        # Schema parsing and conversion methods
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Schema)
        # These methods override the base class with Oracle OID-specific logic:
        # - _parse_attribute(): Custom parsing logic for Oracle OID schema with special OID replacements
        # - _parse_objectclass(): Custom parsing logic for Oracle OID schema with special OID replacements
        # - _write_attribute(): Uses RFC writer with OID error handling
        # - _write_objectclass(): Uses RFC writer with OID error handling
        # - should_filter_out_attribute(): Returns False (accept all in OID mode)
        # - should_filter_out_objectclass(): Returns False (accept all in OID mode)
        # - create_quirk_metadata(): Creates OID-specific metadata

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
                    schema_attr.metadata = self.create_quirk_metadata(
                        attr_definition.strip(),
                    )

                return FlextResult[FlextLdifModels.SchemaAttribute].ok(schema_attr)

            except Exception as e:
                return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                    f"OID attribute parsing failed: {e}",
                )

        def _can_handle_objectclass(
            self, oc_definition: str | FlextLdifModels.SchemaObjectClass
        ) -> bool:
            """Check if this objectClass should be processed by OID quirks.

            Only handles Oracle OID-specific objectClasses (OID namespace 2.16.840.1.113894.*).
            Standard RFC objectClasses are handled by the base RFC quirks.

            Args:
                oc_definition: The objectClass definition string or model to check.

            Returns:
                True if objectClass is Oracle OID-specific (namespace 2.16.840.1.113894.*)

            """
            if isinstance(oc_definition, str):
                # Check if string contains OID pattern
                return bool(
                    re.search(
                        FlextLdifServersOid.Constants.DETECTION_OID_PATTERN,
                        oc_definition,
                    )
                )
            # Check if model has OID pattern in oid field
            return bool(
                oc_definition.oid
                and re.search(
                    FlextLdifServersOid.Constants.DETECTION_OID_PATTERN,
                    oc_definition.oid,
                )
            )

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
                    schema_oc.metadata = self.create_quirk_metadata(
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
                        "caseIgnoreSubstringsMatch": "caseIgnoreMatch",
                        "caseIgnoreSubStringsMatch": "caseIgnoreMatch",
                    },
                    normalized_substr_values={
                        "caseIgnoreSubstringsMatch": "caseIgnoreSubstringsMatch",
                        "caseIgnoreSubStringsMatch": "caseIgnoreSubstringsMatch",
                    },
                )
            )

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
            fixed = written_str.replace("AUXILLARY", "AUXILIARY")
            if fixed != written_str:
                logger.debug("Fixed AUXILLARY typo in objectClass definition")
            return fixed

        def extract_schemas_from_ldif(
            self,
            ldif_content: str,
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Extract and parse all schema definitions from LDIF content.

            Strategy pattern: OID-specific approach to extract attributeTypes
            and objectClasses from cn=schema LDIF entries, handling OID's
            format variations.

            Args:
                ldif_content: Raw LDIF content containing schema definitions

            Returns:
                FlextResult containing extracted attributes and objectclasses
                as a dictionary with ATTRIBUTES and OBJECTCLASSES lists.

            """
            dk = FlextLdifConstants.DictKeys
            try:
                # Use FlextLdifUtilities.Schema for case-insensitive line parsing
                attributes = FlextLdifUtilities.Schema.extract_attributes_from_lines(
                    ldif_content,
                    self._parse_attribute,
                )
                objectclasses = FlextLdifUtilities.Schema.extract_objectclasses_from_lines(
                    ldif_content,
                    self._parse_objectclass,
                )

                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok({
                    dk.ATTRIBUTES: attributes,
                    "objectclasses": objectclasses,
                })

            except Exception as e:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"OID schema extraction failed: {e}",
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

        # OVERRIDDEN METHODS (from FlextLdifServersBase.Acl)
        # These methods override the base class with Oracle OID-specific logic:
        # - _can_handle_acl(): Detects orclaci/orclentrylevelaci formats
        # - parse_acl(): Normalizes Oracle OID ACL to RFC-compliant internal model
        # - write_acl(): Serializes RFC-compliant model to OID ACL format
        # - get_acl_attribute_name(): Returns "orclaci" (OID-specific, overridden)

        def _can_handle_acl(self, acl_line: str | FlextLdifModels.Acl) -> bool:
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
            return acl_line_lower.startswith(
                (f"{FlextLdifServersOid.Constants.ORCLACI}:", f"{FlextLdifServersOid.Constants.ORCLENTRYLEVELACI}:")
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
            if parent_result.is_success:
                return parent_result

            # RFC parser failed - use OID-specific parsing
            # Parse OID ACL format manually
            try:
                # Create minimal Acl model for OID format
                acl_model = FlextLdifModels.Acl(
                    name=FlextLdifServersOid.Constants.ACL_ATTRIBUTE_NAME,
                    target=FlextLdifModels.AclTarget(target_dn="*", attributes=[]),
                    subject=FlextLdifModels.AclSubject(
                        subject_type="*",
                        subject_value="*",
                    ),
                    permissions=FlextLdifModels.AclPermissions(),
                    raw_acl=acl_line,
                    metadata=FlextLdifModels.QuirkMetadata(
                        quirk_type=FlextLdifServersOid.Constants.SERVER_TYPE,
                        original_format=acl_line.strip(),
                        extensions={"oid_parsed": True, "rfc_parsed": False},
                    ),
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
            return FlextLdifServersOid.Constants.ACL_PATTERNS

        def get_acl_attribute_name(self) -> str:
            """Get Oracle OID ACL attribute name.

            Returns:
                OID-specific ACL attribute name from Constants.ACL_ATTRIBUTE_NAME

            """
            return FlextLdifServersOid.Constants.ACL_ATTRIBUTE_NAME

        def _write_acl(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write ACL to RFC-compliant string format (internal).

            Args:
                acl_data: Acl model to write

            Returns:
                FlextResult with RFC-compliant ACL string

            """
            # Always try parent's write method first (RFC format)
            parent_result = super()._write_acl(acl_data)
            if parent_result.is_success:
                return parent_result

            # RFC write failed - return parent error (no fallback)
            # If raw_acl is available, it should have been used by parent write method
            return parent_result

        def _can_handle_attribute(
            self, attribute: FlextLdifModels.SchemaAttribute
        ) -> bool:
            """Check if this ACL quirk should be aware of a specific attribute definition."""
            return False

        def _can_handle_objectclass(
            self, objectclass: FlextLdifModels.SchemaObjectClass
        ) -> bool:
            """Check if this ACL quirk should be aware of a specific objectClass definition."""
            return False
