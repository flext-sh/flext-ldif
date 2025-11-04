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
from flext_ldif.servers.base import FlextLdifServersBase
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
        quirk = FlextLdifServersOid(server_type="oracle_oid")
        if quirk.can_handle_attribute(attr_def):
            result = quirk.parse_attribute(attr_def)
            if result.is_success:
                parsed_attr = result.unwrap()

    """

    # Top-level configuration - mirrors Schema class for direct access
    server_type = FlextLdifConstants.ServerTypes.OID
    priority = 10

    class Constants:
        """Oracle Internet Directory-specific constants centralized for operations in oid.py.

        These constants follow a standardized naming pattern that can be replicated
        in other server quirks implementations for consistency.
        """

        # OID pattern for server detection
        OID_PATTERN: Final[re.Pattern[str]] = re.compile(
            r"2\.16\.840\.1\.113894\.",
        )

        # Matching rule replacements for OUD compatibility
        MATCHING_RULE_REPLACEMENTS: Final[dict[str, str]] = {
            "caseIgnoreSubStringsMatch": "caseIgnoreSubstringsMatch",  # Fix capitalization
            "accessDirectiveMatch": "caseIgnoreMatch",  # Replace OID-specific with standard
        }

        # Syntax OID replacements for OUD compatibility
        SYNTAX_OID_REPLACEMENTS: Final[dict[str, str]] = {
            "1.3.6.1.4.1.1466.115.121.1.1": "1.3.6.1.4.1.1466.115.121.1.15",  # ACI List → Directory String
        }

        # === STANDARDIZED CONSTANTS FOR AUTO-DISCOVERY ===
        CANONICAL_NAME: Final[str] = "oid"
        ALIASES: Final[frozenset[str]] = frozenset(["oid", "oracle_oid"])
        PRIORITY: Final[int] = 10
        CAN_NORMALIZE_FROM: Final[frozenset[str]] = frozenset(["oid"])
        CAN_DENORMALIZE_TO: Final[frozenset[str]] = frozenset(["oid", "rfc"])

    class AttributeWriter(FlextLdifServersRfc.AttributeWriter):
        """OID-specific attribute writer."""

        def _transform_attribute_for_write(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextLdifModels.SchemaAttribute:
            """Fix invalid SUBSTR matching rules for OID compatibility."""
            if attr_data.substr:
                invalid_substr_rules = {
                    "caseIgnoreMatch": "caseIgnoreSubstringsMatch",
                    "caseExactMatch": "caseExactSubstringsMatch",
                    "distinguishedNameMatch": None,
                    "integerMatch": None,
                    "numericStringMatch": "numericStringSubstringsMatch",
                }
                if attr_data.substr in invalid_substr_rules:
                    replacement = invalid_substr_rules[attr_data.substr]
                    attr_data.substr = replacement
            return attr_data

    class Schema(FlextLdifServersRfc.Schema):
        """Oracle OID schema quirks implementation."""

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.OID
        priority: ClassVar[int] = 19

        # Oracle OID namespace pattern

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.OID
        priority: ClassVar[int] = 10

        def __init__(self) -> None:
            """Initialize OID schema quirk and nested ACL quirk."""
            super().__init__()
            # Instantiate nested ACL quirk for conversion matrix access
            self.acl = FlextLdifServersOid.Acl()

        def can_handle_attribute(
            self, attribute: FlextLdifModels.SchemaAttribute
        ) -> bool:
            """Check if this attribute should be processed by OID quirks.

            Only handles Oracle OID-specific attributes (OID namespace 2.16.840.1.113894.*).
            Standard RFC attributes are handled by the base RFC quirks.

            Args:
                attribute: The attribute model to check.

            Returns:
                True if attribute is Oracle OID-specific (namespace 2.16.840.1.113894.*)

            """
            return FlextLdifServersBase.can_handle_by_oid_pattern(
                attribute, FlextLdifServersOid.Constants.OID_PATTERN
            )

        # Schema parsing and conversion methods
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Schema)
        # These methods override the base class with Oracle OID-specific logic:
        # - parse_attribute(): Custom parsing logic for Oracle OID schema with special OID replacements
        # - parse_objectclass(): Custom parsing logic for Oracle OID schema with special OID replacements
        # - convert_attribute_to_rfc(): Strips OID-specific metadata
        # - convert_objectclass_to_rfc(): Strips OID-specific metadata
        # - convert_attribute_from_rfc(): Adds OID-specific metadata and OID replacements
        # - convert_objectclass_from_rfc(): Adds OID-specific metadata and OID replacements
        # - write_attribute_to_rfc(): Uses RFC writer with OID error handling
        # - write_objectclass_to_rfc(): Uses RFC writer with OID error handling
        # - should_filter_out_attribute(): Returns False (accept all in OID mode)
        # - should_filter_out_objectclass(): Returns False (accept all in OID mode)
        # - create_quirk_metadata(): Creates OID-specific metadata

        def parse_attribute(
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
                result = FlextLdifServersRfc.AttributeParser.parse_common(
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
                    and schema_attr.equality in FlextLdifServersOid.Constants.MATCHING_RULE_REPLACEMENTS
                ):
                    schema_attr.equality = FlextLdifServersOid.Constants.MATCHING_RULE_REPLACEMENTS[
                        schema_attr.equality
                    ]

                # Fix syntax OIDs for OUD compatibility
                if (
                    schema_attr.syntax
                    and schema_attr.syntax in FlextLdifServersOid.Constants.SYNTAX_OID_REPLACEMENTS
                ):
                    schema_attr.syntax = FlextLdifServersOid.Constants.SYNTAX_OID_REPLACEMENTS[
                        schema_attr.syntax
                    ]

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

        def can_handle_objectclass(
            self, objectclass: FlextLdifModels.SchemaObjectClass
        ) -> bool:
            """Check if this objectClass should be processed by OID quirks.

            Only handles Oracle OID-specific objectClasses (OID namespace 2.16.840.1.113894.*).
            Standard RFC objectClasses are handled by the base RFC quirks.

            Args:
                objectclass: The objectclass model to check.

            Returns:
                True if objectClass is Oracle OID-specific (namespace 2.16.840.1.113894.*)

            """
            return FlextLdifServersBase.can_handle_by_oid_pattern(
                objectclass, FlextLdifServersOid.Constants.OID_PATTERN
            )

        def parse_objectclass(
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
                result = FlextLdifServersRfc.ObjectClassParser.parse_common(
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

        def convert_attribute_to_rfc(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Convert OID attribute to RFC-compliant format.

            Applies OID-to-RFC transformations:
            - NAME: Remove ;binary suffix and underscore characters
            - EQUALITY/SUBSTR: Fix misused SUBSTR rules and apply OID-specific replacements
            - SYNTAX: Remove quotes and apply OID-specific OID replacements

            Args:
                attr_data: OID attribute data

            Returns:
                FlextResult with RFC-compliant attribute data

            """
            # Use generic SchemaTransformer with OID-specific callbacks
            return FlextLdifServersRfc.SchemaTransformer.apply_attribute_transformations(
                attr_data,
                name_transform=FlextLdifServersRfc.SchemaTransformer.normalize_attribute_name,
                equality_transform=lambda eq, sub: FlextLdifServersRfc.SchemaTransformer.normalize_matching_rule(
                    eq, sub, self.Constants.MATCHING_RULE_REPLACEMENTS
                ),
                syntax_transform=lambda syn: FlextLdifServersRfc.SchemaTransformer.normalize_syntax_oid(
                    syn, self.Constants.SYNTAX_OID_REPLACEMENTS
                ),
            )

        def convert_objectclass_to_rfc(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Convert OID objectClass to RFC-compliant format.

            Args:
                oc_data: OID objectClass data

            Returns:
                FlextResult with RFC-compliant objectClass data

            """
            try:
                # Convert Oracle OID objectClass to RFC format
                # NOTE: Filtering is NOT the responsibility of quirks.
                # All attribute/objectClass filtering is handled by client-aOudMigConstants
                # in the migration service. Quirks only perform format conversions.

                # Create a working copy to apply validators
                rfc_oc = FlextLdifModels.SchemaObjectClass(
                    oid=oc_data.oid,
                    name=oc_data.name,
                    desc=oc_data.desc,
                    sup=oc_data.sup,
                    kind=oc_data.kind,
                    must=oc_data.must,
                    may=oc_data.may,
                    metadata=oc_data.metadata,
                )

                # Apply validators to fix OID-specific issues
                FlextLdifUtilities.ObjectClass.ensure_sup_for_auxiliary(rfc_oc)
                FlextLdifUtilities.ObjectClass.align_kind_with_superior(rfc_oc, None)

                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(rfc_oc)

            except Exception as e:
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    f"OID→RFC conversion failed: {e}",
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
            fixed_name = FlextLdifUtilities.Schema.normalize_name(
                attr_data.name
            )
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
                # Use shared extractor for case-insensitive line parsing
                attributes = (
                    FlextLdifServersRfc.SchemaExtractor.extract_attributes_from_lines(
                        ldif_content,
                        self.parse_attribute,
                    )
                )
                objectclasses = FlextLdifServersRfc.SchemaExtractor.extract_objectclasses_from_lines(
                    ldif_content,
                    self.parse_objectclass,
                )

                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok({
                    dk.ATTRIBUTES: attributes,
                    "objectclasses": objectclasses,
                })

            except Exception as e:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"OID schema extraction failed: {e}",
                )

        def convert_objectclass_from_rfc(
            self,
            rfc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Convert RFC-compliant objectClass to OID-specific format.

            Sets the server_type metadata field to identify the data as OID-format.

            Args:
                rfc_data: RFC-compliant objectClass data

            Returns:
                FlextResult with OID objectClass data

            """
            return FlextLdifServersRfc.SchemaConverter.set_quirk_type(
                rfc_data, self.server_type
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

        acl_attribute_name = FlextLdifConstants.AclAttributes.ORCLACI

        # OVERRIDDEN METHODS (from FlextLdifServersBase.Acl)
        # These methods override the base class with Oracle OID-specific logic:
        # - can_handle(): Detects orclaci/orclentrylevelaci formats
        # - parse(): Normalizes Oracle OID ACL to RFC-compliant internal model
        # - write(): Serializes RFC-compliant model to OID ACL format
        # - get_attribute_name(): Returns "orclaci" (OID-specific, overridden)

        # Oracle OID server configuration defaults
        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.OID
        priority: ClassVar[int] = 10

        def can_handle(self, acl_line: str) -> bool:
            """Check if this is an Oracle OID ACL.

            Detects Oracle OID ACL by checking if the line starts with:
            - "orclaci:" (Oracle standard ACI)
            - "orclentrylevelaci:" (Oracle entry-level ACI)

            Args:
                acl_line: Raw ACL line from LDIF

            Returns:
                True if this is orclaci or orclentrylevelaci

            """
            if not acl_line:
                return False
            return acl_line.strip().startswith(("orclaci:", "orclentrylevelaci:"))

        def parse(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
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
            # Use standardized AclParser with full OID-specific configuration
            return FlextLdifServersRfc.AclParser.parse_common(
                acl_line,
                server_type=self.server_type,
                acl_attribute_name=self.acl_attribute_name,
                extraction_patterns=self._get_oid_patterns(),
            )

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
                "acl_type": r"^(orclaci|orclentrylevelaci):",
                "target": r"access to (entry|attr=\(([^)]+)\))",
                "subject": r"by\s+(group=\"[^\"]+\"|dnattr=\([^)]+\)|guidattr=\([^)]+\"|groupattr=\([^)]+\)|\"[^\"]+\"|self|\*)",
                "permissions": r"\(([^)]+)\)(?:\s*$)",
                "filter": r"filter=(\([^)]*(?:\([^)]*\)[^)]*)*\))",
                "constraint": r"added_object_constraint=\(([^)]+)\)",
            }
