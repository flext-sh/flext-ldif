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
from collections.abc import Callable
from typing import ClassVar

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
        quirk = FlextLdifServersOid(server_type="oracle_oid")
        if quirk.can_handle_attribute(attr_def):
            result = quirk.parse_attribute(attr_def)
            if result.is_success:
                parsed_attr = result.unwrap()

    """

    # Top-level configuration - mirrors Schema class for direct access
    server_type = FlextLdifConstants.ServerTypes.OID
    priority = 10

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

        # Oracle OID namespace pattern

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.OID
        priority: ClassVar[int] = 10

        ORACLE_OID_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            r"2\.16\.840\.1\.113894\.",
        )

        # Fix invalid matching rules for OUD compatibility
        # OUD doesn't support: caseIgnoreSubStringsMatch (wrong case), accessDirectiveMatch (OID-specific)
        MATCHING_RULE_REPLACEMENTS: ClassVar[dict[str, str]] = {
            "caseIgnoreSubStringsMatch": "caseIgnoreSubstringsMatch",  # Fix capitalization
            "accessDirectiveMatch": "caseIgnoreMatch",  # Replace OID-specific with standard
        }

        # Replace unsupported/deprecated syntax OIDs with OUD-compatible ones
        SYNTAX_OID_REPLACEMENTS: ClassVar[dict[str, str]] = {
            "1.3.6.1.4.1.1466.115.121.1.1": "1.3.6.1.4.1.1466.115.121.1.15",  # ACI List → Directory String
        }

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
            # Validate input type first (defensive programming)
            if not isinstance(attribute, FlextLdifModels.SchemaAttribute):
                logger.error(
                    "can_handle_attribute received non-SchemaAttribute input: %s",
                    type(attribute).__name__,
                )
                return False

            attr_definition_str = None
            if attribute.metadata and attribute.metadata.original_format:
                attr_definition_str = attribute.metadata.original_format

            oid_to_check = None

            if attr_definition_str:
                # Extract OID from definition
                # Find OID in parentheses at start: ( 2.16.840.1.113894.* ...
                try:
                    match = re.search(r"\(\s*([\d.]+)", attr_definition_str)
                    if match:
                        oid_to_check = match.group(1)
                except re.error:
                    # Regex compilation/execution error (should not happen with static pattern)
                    logger.exception(
                        "Regex error in can_handle_attribute, input: %s",
                        attr_definition_str[:100],
                    )

            # Fallback to the oid from the model if parsing original_format fails or it's not present
            if not oid_to_check:
                oid_to_check = attribute.oid

            if not oid_to_check:
                return False

            # Check if it's Oracle OID namespace
            return oid_to_check.startswith("2.16.840.1.113894.")

        # --------------------------------------------------------------------- #
        # Schema parsing and conversion methods
        # --------------------------------------------------------------------- #
        # --------------------------------------------------------------------- #
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Schema)
        # --------------------------------------------------------------------- #
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
                    and schema_attr.equality in self.MATCHING_RULE_REPLACEMENTS
                ):
                    schema_attr.equality = self.MATCHING_RULE_REPLACEMENTS[
                        schema_attr.equality
                    ]

                # Fix syntax OIDs for OUD compatibility
                if (
                    schema_attr.syntax
                    and schema_attr.syntax in self.SYNTAX_OID_REPLACEMENTS
                ):
                    schema_attr.syntax = self.SYNTAX_OID_REPLACEMENTS[
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
            # Validate input type first (defensive programming)
            if not isinstance(objectclass, FlextLdifModels.SchemaObjectClass):
                logger.error(
                    "can_handle_objectclass received non-SchemaObjectClass input: %s",
                    type(objectclass).__name__,
                )
                return False

            oc_definition_str = None
            if objectclass.metadata and objectclass.metadata.original_format:
                oc_definition_str = objectclass.metadata.original_format

            oid_to_check = None

            if oc_definition_str:
                # Extract OID from definition
                # Find OID in parentheses at start: ( 2.16.840.1.113894.* ...
                match = re.search(r"\(\s*([\d.]+)", oc_definition_str)
                # No match found - this is expected for non-OID objectClasses
                if match:
                    oid_to_check = match.group(1)

            if not oid_to_check:
                oid_to_check = objectclass.oid

            if not oid_to_check:
                return False

            # Check if it's Oracle OID namespace
            return oid_to_check.startswith("2.16.840.1.113894.")

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
                # Use extracted validators for code reuse
                FlextLdifUtilities.ObjectClassValidator.ensure_sup_for_auxiliary(
                    schema_oc
                )
                FlextLdifUtilities.ObjectClassValidator.align_kind_with_superior(
                    schema_oc, None
                )

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

            Args:
                attr_data: OID attribute data

            Returns:
                FlextResult with RFC-compliant attribute data

            """
            try:
                # Oracle OID attributes can be represented in RFC format
                # by removing Oracle-specific extensions and fixing OUD-incompatible values

                # Extract values from model
                name_value = attr_data.name
                equality_value = attr_data.equality
                substr_value = attr_data.substr
                syntax_value = attr_data.syntax

                # Fix NAME - remove ;binary suffix and replace underscores
                if name_value and isinstance(name_value, str):
                    if ";binary" in name_value:
                        name_value = name_value.replace(";binary", "")
                        logger.debug("Removed ;binary from NAME: %s", name_value)
                    if "_" in name_value:
                        name_value = name_value.replace("_", "-")
                        logger.debug("Replaced _ with - in NAME: %s", name_value)

                # Fix EQUALITY - replace invalid matching rules or fix misused SUBSTR rules
                if equality_value and isinstance(equality_value, str):
                    # Check if EQUALITY is using a SUBSTR matching rule (common OID mistake)
                    # Handle both caseIgnoreSubStringsMatch (capital S) and caseIgnoreSubstringsMatch (lowercase)
                    if equality_value in {
                        "caseIgnoreSubstringsMatch",
                        "caseIgnoreSubStringsMatch",
                    }:
                        # Move to SUBSTR and use proper EQUALITY
                        equality_value = "caseIgnoreMatch"
                        substr_value = "caseIgnoreSubstringsMatch"
                        logger.debug(
                            "Fixed EQUALITY: moved substr match to SUBSTR, using caseIgnoreMatch for EQUALITY",
                        )
                    elif equality_value in self.MATCHING_RULE_REPLACEMENTS:
                        # Standard replacement
                        original = equality_value
                        equality_value = self.MATCHING_RULE_REPLACEMENTS[equality_value]
                        logger.debug(
                            "Replaced matching rule %s -> %s",
                            original,
                            equality_value,
                        )

                # Fix SYNTAX - remove quotes (OID uses 'OID' format, RFC 4512 uses OID without quotes)
                if syntax_value and isinstance(syntax_value, str):
                    # Remove quotes if present
                    if syntax_value.startswith("'") and syntax_value.endswith("'"):
                        syntax_value = syntax_value[1:-1]
                        logger.debug("Removed quotes from SYNTAX: %s", syntax_value)

                    # Replace unsupported syntax OIDs
                    if syntax_value in self.SYNTAX_OID_REPLACEMENTS:
                        original = syntax_value
                        syntax_value = self.SYNTAX_OID_REPLACEMENTS[syntax_value]
                        logger.debug(
                            "Replaced syntax OID %s -> %s",
                            original,
                            syntax_value,
                        )

                # Create new RFC attribute model with modified values
                rfc_attr = FlextLdifModels.SchemaAttribute(
                    name=name_value,
                    oid=attr_data.oid,
                    desc=attr_data.desc,
                    sup=attr_data.sup,
                    equality=equality_value,
                    ordering=attr_data.ordering,
                    substr=substr_value,
                    syntax=syntax_value,
                    length=attr_data.length,
                    usage=attr_data.usage,
                    single_value=attr_data.single_value,
                    no_user_modification=attr_data.no_user_modification,
                    metadata=attr_data.metadata,
                )

                return FlextResult[FlextLdifModels.SchemaAttribute].ok(rfc_attr)

            except Exception as e:
                return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                    f"OID→RFC conversion failed: {e}",
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
                # All attribute/objectClass filtering is handled by AlgarOudMigConstants
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
                FlextLdifUtilities.ObjectClassValidator.ensure_sup_for_auxiliary(rfc_oc)
                FlextLdifUtilities.ObjectClassValidator.align_kind_with_superior(
                    rfc_oc, None
                )

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
            fixed_name = FlextLdifUtilities.AttributeFixer.normalize_name(
                attr_data.name
            )
            if fixed_name is None:
                # This should never happen for valid attribute names, but handle gracefully
                fixed_name = attr_data.name

            # Apply AttributeFixer transformations to EQUALITY and SUBSTR
            # OID-specific mappings: normalize case variants to RFC-compliant forms
            fixed_equality, fixed_substr = (
                FlextLdifUtilities.AttributeFixer.normalize_matching_rules(
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

            Args:
                rfc_data: RFC-compliant objectClass data

            Returns:
                FlextResult with OID objectClass data

            """
            try:
                # Oracle OID uses RFC-compliant schema format
                # Set OID server type in metadata
                if rfc_data.metadata:
                    # Update existing metadata
                    oid_data = rfc_data.model_copy(
                        update={
                            "metadata": rfc_data.metadata.model_copy(
                                update={
                                    "server_type": FlextLdifConstants.LdapServers.ORACLE_OID,
                                },
                            ),
                        },
                    )
                else:
                    # Create new metadata with OID server type
                    oid_data = rfc_data.model_copy(
                        update={
                            "metadata": FlextLdifModels.QuirkMetadata(
                                quirk_type=FlextLdifConstants.LdapServers.ORACLE_OID,
                            ),
                        },
                    )

                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(oid_data)

            except Exception as e:
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    f"RFC→OID objectClass conversion failed: {e}",
                )

    class Acl(FlextLdifServersRfc.Acl):
        """Oracle OID ACL quirk using universal parser with OID-specific configuration.

        Delegates to FlextLdifUtilities.Acl.parser() with OID server-specific patterns,
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

        # --------------------------------------------------------------------- #
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Acl)
        # --------------------------------------------------------------------- #
        # These methods override the base class with Oracle OID-specific logic:
        # - can_handle_acl(): Detects orclaci/orclentrylevelaci formats
        # - parse_acl(): Parses Oracle OID ACL definitions
        # - convert_acl_to_rfc(): Converts to RFC format
        # - convert_acl_from_rfc(): Converts from RFC format
        # - write_acl_to_rfc(): Writes RFC-compliant ACL strings
        # - get_acl_attribute_name(): Returns "orclaci" (OID-specific, overridden)

        # Oracle OID server configuration defaults
        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.OID
        priority: ClassVar[int] = 10

        def can_handle_acl(self, acl: FlextLdifModels.Acl) -> bool:
            """Check if this is an Oracle OID ACL.

            Args:
                acl: The ACL model to check.

            Returns:
            True if this is orclaci or orclentrylevelaci

            """
            if not isinstance(acl, FlextLdifModels.Acl):
                return False
            if not acl.raw_acl:
                return False
            return acl.raw_acl.startswith(("orclaci:", "orclentrylevelaci:"))

        def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse Oracle OID ACL definition using universal parser with OID-specific configuration.

            Delegates to FlextLdifUtilities.Acl.parser() with OID server-specific patterns,
            permissions mapping, and subject transformations. This ensures DRY compliance
            while maintaining full OID feature support.

            Args:
                acl_line: ACL definition line

            Returns:
                FlextResult with parsed OID ACL as Pydantic model with complete metadata

            """
            return FlextLdifUtilities.Acl.parser(
                acl_line,
                    server_type="oracle_oid",
                patterns=self._get_oid_patterns(),
                permissions_map=self._get_oid_permissions(),
                subject_transforms=self._get_oid_subject_transforms(),
                extract_metadata=True,
                extract_filters=True,
                extract_constraints=True,
                extract_multi_subjects=True,
                preserve_original=True,
                normalize_output=True,
            )

        def _get_oid_patterns(self) -> dict[str, str]:
            """Get OID-specific regex patterns for ACL parsing."""
            return {
                "acl_type": r"^(orclaci|orclentrylevelaci):",
                "target": r"access to (entry|attr=\(([^)]+)\))",
                "subject": r"by\s+(group=\"[^\"]+\"|dnattr=\([^)]+\)|guidattr=\([^)]+\)|groupattr=\([^)]+\)|\"[^\"]+\"|self|\*)",
                "permissions": r"\(([^)]+)\)(?:\s*$)",
                "filter": r"filter=(\([^)]*(?:\([^)]*\)[^)]*)*\))",
                "constraint": r"added_object_constraint=\(([^)]+)\)",
            }

        def _get_oid_permissions(self) -> dict[str, list[str]]:
            """Get OID-specific permission mappings."""
            return {
                "browse": ["read", "search"],
                "auth": ["compare"],
                "selfwrite": ["self_write"],
                "self_write": ["self_write"],
                "proxy": ["proxy"],  # OID-specific, preserved in metadata
                "read": ["read"],
                "write": ["write"],
                "add": ["add"],
                "delete": ["delete"],
                "search": ["search"],
                "compare": ["compare"],
            }

        def _get_oid_subject_transforms(self) -> dict[str, Callable[[str], tuple[str, str]]]:
            """Get OID-specific subject transformation functions."""
            return {
                "dnattr": lambda attr: ("bind_rules", f'userattr="{attr}#LDAPURL"'),
                "guidattr": lambda attr: ("bind_rules", f'userattr="{attr}#USERDN"'),
                "groupattr": lambda attr: ("bind_rules", f'userattr="{attr}#GROUPDN"'),
                'group="': lambda full_str: ("group_dn", full_str.split('="')[1].rstrip('"')),
                "self": lambda _: ("self", "self"),
                "*": lambda _: ("anonymous", "*"),
            }

        def _classify_oid_subject_type(self, subject_str: str) -> str:
            """Classify OID subject string using advanced utilities."""
            return FlextLdifUtilities.SubjectTransformer.classify_subject_type(
                subject_str
            )

        def _is_constraint_convertible_to_oud(self, constraint: str) -> bool:
            """Check if OID constraint can be converted to OUD using advanced utilities."""
            return FlextLdifUtilities.MetadataProcessor._is_constraint_convertible(
                constraint, "oracle_oud"
            )


# Backward compatibility alias
FlextLdifServersOID = FlextLdifServersOid
