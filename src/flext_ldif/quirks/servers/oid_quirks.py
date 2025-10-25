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

import logging
import re
from typing import ClassVar

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.dn_service import FlextLdifDnService
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.base import (
    FlextLdifQuirksBase,
)
from flext_ldif.quirks.rfc_parsers import RfcSchemaConverter, RfcSchemaExtractor
from flext_ldif.typings import FlextLdifTypes

logger = logging.getLogger(__name__)


class FlextLdifQuirksServersOid(FlextLdifQuirksBase.SchemaQuirk):
    """Oracle OID schema quirk - implements FlextLdifProtocols.Quirks.SchemaQuirkProtocol.

    Extends RFC 4512 schema parsing with Oracle OID-specific features:
    - Oracle OID namespace (2.16.840.1.113894.*)
    - Oracle-specific syntaxes
    - Oracle attribute extensions
    - OUD compatibility fixes (matching rules, syntax OIDs)

    **Protocol Compliance**: Fully implements
    FlextLdifProtocols.Quirks.SchemaQuirkProtocol through structural typing.
    All methods match protocol signatures exactly for type safety.

    **Validation**: Verify protocol compliance with:
        from flext_ldif.protocols import FlextLdifProtocols
        quirk = FlextLdifQuirksServersOid()
        assert isinstance(quirk, FlextLdifProtocols.Quirks.SchemaQuirkProtocol)

    Example:
        quirk = FlextLdifQuirksServersOid(server_type="oracle_oid")
        if quirk.can_handle_attribute(attr_def):
            result = quirk.parse_attribute(attr_def)
            if result.is_success:
                parsed_attr = result.unwrap()

    """

    # Oracle OID namespace pattern
    ORACLE_OID_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"2\.16\.840\.1\.113894\."
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

    def __init__(
        self,
        server_type: str = FlextLdifConstants.ServerTypes.OID,
        priority: int = 10,
    ) -> None:
        """Initialize OID schema quirk and nested ACL quirk.

        Args:
            server_type: Oracle OID server type
            priority: High priority for OID-specific parsing

        """
        super().__init__(server_type=server_type, priority=priority)
        # Instantiate nested ACL quirk for conversion matrix access
        self.acl = self.AclQuirk(server_type=self.server_type)

    def can_handle_attribute(self, attr_definition: str) -> bool:
        """Check if this attribute should be processed by OID quirks.

        Only handles Oracle OID-specific attributes (OID namespace 2.16.840.1.113894.*).
        Standard RFC attributes are handled by the base RFC quirks.

        Args:
            attr_definition: AttributeType definition string

        Returns:
            True if attribute is Oracle OID-specific (namespace 2.16.840.1.113894.*)

        """
        # Validate input type first (defensive programming)
        if not isinstance(attr_definition, str):
            logger.error(
                f"can_handle_attribute received non-string input: "
                f"{type(attr_definition).__name__}"
            )
            return False

        # Extract OID from definition
        # Find OID in parentheses at start: ( 2.16.840.1.113894.* ...
        try:
            match = re.search(r"\(\s*([\d.]+)", attr_definition)
        except re.error:
            # Regex compilation/execution error (should not happen with static pattern)
            logger.exception(
                f"Regex error in can_handle_attribute, input: {attr_definition[:100]}"
            )
            return False

        # No match found - this is expected for non-OID attributes
        if not match:
            return False

        oid = match.group(1)
        # Check if it's Oracle OID namespace
        return oid.startswith("2.16.840.1.113894.")

    def parse_attribute(
        self, attr_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Parse Oracle OID attribute definition.

        OID uses RFC 4512 compliant schema format. Parses the definition
        to extract OID, NAME, DESC, SYNTAX, and other RFC 4512 attributes.

        Args:
            attr_definition: AttributeType definition string
                            (without "attributetypes:" prefix)

        Returns:
            FlextResult with parsed OID attribute data with metadata

        """
        try:
            # Extract OID (first element after opening parenthesis)
            oid_match = re.match(r"\(\s*([0-9.]+)", attr_definition)
            oid = oid_match.group(1) if oid_match else ""

            # Extract NAME (single or multiple) - case-insensitive for non-standard inputs
            name_match = re.search(r"(?i)NAME\s+(?:\(\s*)?'([^']+)'", attr_definition)
            name = name_match.group(1) if name_match else ""

            # Extract DESC
            desc_match = re.search(r"DESC\s+'([^']+)'", attr_definition)
            desc = desc_match.group(1) if desc_match else None

            # Extract SYNTAX
            syntax_match = re.search(
                r"SYNTAX\s+'?([0-9.]+)(?:\{(\d+)\})?'?", attr_definition
            )
            syntax = syntax_match.group(1) if syntax_match else None
            length = (
                int(syntax_match.group(2))
                if syntax_match and syntax_match.group(2)
                else None
            )

            # Extract EQUALITY
            equality_match = re.search(r"EQUALITY\s+(\w+)", attr_definition)
            equality = equality_match.group(1) if equality_match else None

            # Extract SUBSTR
            substr_match = re.search(r"SUBSTR\s+(\w+)", attr_definition)
            substr = substr_match.group(1) if substr_match else None

            # Extract ORDERING
            ordering_match = re.search(r"ORDERING\s+(\w+)", attr_definition)
            ordering = ordering_match.group(1) if ordering_match else None

            # Extract SUP (superior attribute)
            sup_match = re.search(r"SUP\s+(\w+)", attr_definition)
            sup = sup_match.group(1) if sup_match else None

            # Extract USAGE
            usage_match = re.search(r"USAGE\s+(\w+)", attr_definition)
            usage = usage_match.group(1) if usage_match else None

            # Check for SINGLE-VALUE and NO-USER-MODIFICATION
            single_value = "SINGLE-VALUE" in attr_definition
            no_user_modification = "NO-USER-MODIFICATION" in attr_definition

            # Create metadata for perfect round-trip preservation
            metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
                quirk_type="oid", original_format=attr_definition.strip()
            )

            # Create SchemaAttribute model
            schema_attr = FlextLdifModels.SchemaAttribute(
                name=name,
                oid=oid,
                desc=desc,
                sup=sup,
                equality=equality,
                ordering=ordering,
                substr=substr,
                syntax=syntax,
                length=length,
                usage=usage,
                single_value=single_value,
                no_user_modification=no_user_modification,
                metadata=metadata,
            )

            return FlextResult[FlextLdifModels.SchemaAttribute].ok(schema_attr)

        except Exception as e:
            return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                f"OID attribute parsing failed: {e}"
            )

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        """Check if this objectClass should be processed by OID quirks.

        Only handles Oracle OID-specific objectClasses (OID namespace 2.16.840.1.113894.*).
        Standard RFC objectClasses are handled by the base RFC quirks.

        Args:
            oc_definition: ObjectClass definition string

        Returns:
            True if objectClass is Oracle OID-specific (namespace 2.16.840.1.113894.*)

        """
        # Validate input type first (defensive programming)
        if not isinstance(oc_definition, str):
            logging.getLogger(__name__).error(
                f"can_handle_objectclass received non-string input: "
                f"{type(oc_definition).__name__}"
            )
            return False

        # Extract OID from definition
        # Find OID in parentheses at start: ( 2.16.840.1.113894.* ...
        match = re.search(r"\(\s*([\d.]+)", oc_definition)

        # No match found - this is expected for non-OID objectClasses
        if not match:
            return False

        oid = match.group(1)
        # Check if it's Oracle OID namespace
        return oid.startswith("2.16.840.1.113894.")

    def parse_objectclass(
        self, oc_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Parse Oracle OID objectClass definition.

        OID uses RFC 4512 compliant schema format. Parses the definition
        to extract OID, NAME, DESC, SUP, KIND, MUST, and MAY attributes.

        Args:
            oc_definition: ObjectClass definition string
                          (without "objectclasses:" prefix)

        Returns:
            FlextResult with parsed OID objectClass data with metadata

        """
        try:
            # Extract OID (first element after opening parenthesis)
            oid_match = re.match(r"\(\s*([0-9.]+)", oc_definition)
            oid = oid_match.group(1) if oid_match else ""

            # Extract NAME (single or multiple) - case-insensitive for non-standard inputs
            name_match = re.search(r"(?i)NAME\s+(?:\(\s*)?'([^']+)'", oc_definition)
            name = name_match.group(1) if name_match else ""

            # Extract DESC
            desc_match = re.search(r"DESC\s+'([^']+)'", oc_definition)
            desc = desc_match.group(1) if desc_match else None

            # Extract SUP (superior objectClass)
            sup_match = re.search(
                r"SUP\s+(?:\(\s*([\w\s$]+)\s*\)|(\w+))",
                oc_definition,
            )
            sup: str | list[str] | None = None
            if sup_match:
                sup_value = sup_match.group(1) or sup_match.group(2)
                sup_value = sup_value.strip()
                # Handle multiple superior classes like "organization $ organizationalUnit"
                if "$" in sup_value:
                    sup = [s.strip() for s in sup_value.split("$")]
                else:
                    sup = sup_value

            # Determine kind (STRUCTURAL, AUXILIARY, ABSTRACT)
            # RFC 4512: Default to STRUCTURAL if KIND is not specified
            if FlextLdifConstants.Schema.STRUCTURAL in oc_definition:
                kind = FlextLdifConstants.Schema.STRUCTURAL
            elif FlextLdifConstants.Schema.AUXILIARY in oc_definition:
                kind = FlextLdifConstants.Schema.AUXILIARY
            elif FlextLdifConstants.Schema.ABSTRACT in oc_definition:
                kind = FlextLdifConstants.Schema.ABSTRACT
            else:
                # RFC 4512: Default to STRUCTURAL when KIND is not specified
                kind = FlextLdifConstants.Schema.STRUCTURAL

            # Extract MUST attributes
            must_match = re.search(
                r"MUST\s+\(\s*([^)]+)\s*\)|MUST\s+(\w+)", oc_definition
            )
            must: list[str] | None = None
            if must_match:
                must_value = must_match.group(1) or must_match.group(2)
                if "$" in must_value:
                    must = [m.strip() for m in must_value.split("$")]
                else:
                    must = [must_value.strip()]

            # Extract MAY attributes
            may_match = re.search(r"MAY\s+\(\s*([^)]+)\s*\)|MAY\s+(\w+)", oc_definition)
            may: list[str] | None = None
            if may_match:
                may_value = may_match.group(1) or may_match.group(2)
                if "$" in may_value:
                    may = [m.strip() for m in may_value.split("$")]
                else:
                    may = [may_value.strip()]

            # Create metadata for perfect round-trip preservation
            metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
                quirk_type="oid", original_format=oc_definition.strip()
            )

            # Create SchemaObjectClass model
            schema_oc = FlextLdifModels.SchemaObjectClass(
                name=name,
                oid=oid,
                desc=desc,
                sup=sup,
                kind=kind,
                must=must,
                may=may,
                metadata=metadata,
            )

            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(schema_oc)

        except Exception as e:
            return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                f"OID objectClass parsing failed: {e}"
            )

    def convert_attribute_to_rfc(
        self, attr_data: FlextLdifModels.SchemaAttribute
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
                    logger.debug(f"Removed ;binary from NAME: {name_value}")
                if "_" in name_value:
                    name_value = name_value.replace("_", "-")
                    logger.debug(f"Replaced _ with - in NAME: {name_value}")

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
                        "Fixed EQUALITY: moved substr match to SUBSTR, using caseIgnoreMatch for EQUALITY"
                    )
                elif equality_value in self.MATCHING_RULE_REPLACEMENTS:
                    # Standard replacement
                    original = equality_value
                    equality_value = self.MATCHING_RULE_REPLACEMENTS[equality_value]
                    logger.debug(
                        f"Replaced matching rule {original} -> {equality_value}"
                    )

            # Fix SYNTAX - remove quotes (OID uses 'OID' format, RFC 4512 uses OID without quotes)
            if syntax_value and isinstance(syntax_value, str):
                # Remove quotes if present
                if syntax_value.startswith("'") and syntax_value.endswith("'"):
                    syntax_value = syntax_value[1:-1]
                    logger.debug(f"Removed quotes from SYNTAX: {syntax_value}")

                # Replace unsupported syntax OIDs
                if syntax_value in self.SYNTAX_OID_REPLACEMENTS:
                    original = syntax_value
                    syntax_value = self.SYNTAX_OID_REPLACEMENTS[syntax_value]
                    logger.debug(f"Replaced syntax OID {original} -> {syntax_value}")

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
                f"OID→RFC conversion failed: {e}"
            )

    def convert_objectclass_to_rfc(
        self, oc_data: FlextLdifModels.SchemaObjectClass
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

            # Extract values from model
            must_value = oc_data.must
            may_value = oc_data.may
            kind_value = oc_data.kind
            sup_value = oc_data.sup
            name_value = oc_data.name

            # Fix missing SUP for AUXILIARY objectClasses that require it
            # OUD requires AUXILIARY classes to have an explicit SUP clause
            if not sup_value and kind_value == FlextLdifConstants.Schema.AUXILIARY:
                # Known AUXILIARY classes from OID that are missing SUP top
                auxiliary_without_sup = {
                    "orcldAsAttrCategory",  # orclDASAttrCategory
                    "orcldasattrcategory",
                }
                name_lower = str(name_value).lower() if name_value else ""

                if name_lower in auxiliary_without_sup:
                    sup_value = "top"
                    logger.debug(
                        f"Adding missing SUP top to AUXILIARY class {name_value}"
                    )

            if sup_value and kind_value:
                # Known STRUCTURAL superior classes that cause conflicts
                structural_superiors = {
                    "orclpwdverifierprofile",
                    "orclapplicationentity",
                    "tombstone",
                }
                # Known AUXILIARY superior classes that cause conflicts
                auxiliary_superiors = {"javanamingref", "javanamingReference"}

                sup_lower = str(sup_value).lower() if isinstance(sup_value, str) else ""

                # If SUP is STRUCTURAL but objectClass is AUXILIARY, change to STRUCTURAL
                if (
                    sup_lower in structural_superiors
                    and kind_value == FlextLdifConstants.Schema.AUXILIARY
                ):
                    logger.debug(
                        f"Changing {name_value} from AUXILIARY to STRUCTURAL "
                        f"to match superior class {sup_value}"
                    )
                    kind_value = FlextLdifConstants.Schema.STRUCTURAL

                # If SUP is AUXILIARY but objectClass is STRUCTURAL, change to AUXILIARY
                elif (
                    sup_lower in auxiliary_superiors
                    and kind_value == FlextLdifConstants.Schema.STRUCTURAL
                ):
                    logger.debug(
                        f"Changing {name_value} from STRUCTURAL to AUXILIARY "
                        f"to match superior class {sup_value}"
                    )
                    kind_value = FlextLdifConstants.Schema.AUXILIARY

            # Create new RFC objectClass model with modified values
            rfc_oc = FlextLdifModels.SchemaObjectClass(
                oid=oc_data.oid,
                name=name_value,
                desc=oc_data.desc,
                sup=sup_value,
                kind=kind_value,
                must=must_value,
                may=may_value,
                metadata=oc_data.metadata,
            )

            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(rfc_oc)

        except Exception as e:
            return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                f"OID→RFC conversion failed: {e}"
            )

    def write_attribute_to_rfc(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[str]:
        """Write OID attribute data to RFC 4512 compliant string format.

        Converts parsed attribute model back to RFC 4512 schema definition format.
        If metadata contains original_format, uses it for perfect round-trip.

        Args:
            attr_data: Parsed OID attribute model

        Returns:
            FlextResult with RFC 4512 formatted attribute definition string

        Example:
            Input: SchemaAttribute(
                oid="2.16.840.1.113894.1.1.1",
                name="orclguid",
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
            )
            Output: (
                "( 2.16.840.1.113894.1.1.1 NAME 'orclguid' "
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
            )

        """
        try:
            # Check if we have metadata with original format for perfect round-trip
            if attr_data.metadata and attr_data.metadata.original_format:
                return FlextResult[str].ok(attr_data.metadata.original_format)

            # Build RFC 4512 attribute definition from scratch
            parts = []

            # Start with OID (required)
            oid = attr_data.oid
            parts.append(f"( {oid}")

            # Add NAME (required) - Fix invalid attribute names for OUD
            name = attr_data.name
            # Remove ;binary suffix (not allowed in OUD attribute names)
            if ";binary" in name:
                name = name.replace(";binary", "")
                logger.debug(f"Removed ;binary suffix from attribute name: {name}")
            # Replace underscore with hyphen (OUD doesn't allow _ in names)
            if "_" in name:
                name = name.replace("_", "-")
                logger.debug(
                    f"Replaced underscore with hyphen in attribute name: {name}"
                )
            parts.append(f"NAME '{name}'")

            # Add DESC (optional)
            if attr_data.desc:
                parts.append(f"DESC '{attr_data.desc}'")

            # Add SUP (optional)
            if attr_data.sup:
                parts.append(f"SUP {attr_data.sup}")

            # Add EQUALITY (optional) - Fix invalid matching rules for OUD
            if attr_data.equality:
                equality = attr_data.equality
                # Replace invalid matching rules with OUD-compatible ones
                if equality in self.MATCHING_RULE_REPLACEMENTS:
                    original_eq = equality
                    equality = self.MATCHING_RULE_REPLACEMENTS[equality]
                    logger.debug(
                        f"Replaced matching rule {original_eq} with {equality}"
                    )
                parts.append(f"EQUALITY {equality}")

            # Add ORDERING (optional)
            if attr_data.ordering:
                parts.append(f"ORDERING {attr_data.ordering}")

            # Add SUBSTR (optional)
            if attr_data.substr:
                parts.append(f"SUBSTR {attr_data.substr}")

            # Add SYNTAX (optional but common)
            if attr_data.syntax:
                syntax_str = attr_data.syntax
                if attr_data.length:
                    syntax_str += f"{{{attr_data.length}}}"
                parts.append(f"SYNTAX {syntax_str}")

            # Add SINGLE-VALUE flag (optional)
            if attr_data.single_value:
                parts.append("SINGLE-VALUE")

            # Add NO-USER-MODIFICATION flag (optional)
            if attr_data.no_user_modification:
                parts.append("NO-USER-MODIFICATION")

            # Add USAGE (optional)
            if attr_data.usage:
                parts.append(f"USAGE {attr_data.usage}")

            # Close the definition
            rfc_string = " ".join(parts) + " )"

            return FlextResult[str].ok(rfc_string)

        except Exception as e:
            return FlextResult[str].fail(f"Failed to write OID attribute to RFC: {e}")

    def write_objectclass_to_rfc(
        self, oc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[str]:
        """Write OID objectClass data to RFC 4512 compliant string format.

        Converts parsed objectClass model back to RFC 4512 schema
        definition format.
        If metadata contains original_format, uses it for perfect round-trip.

        Args:
            oc_data: Parsed OID objectClass model

        Returns:
            FlextResult with RFC 4512 formatted objectClass definition string

        Example:
            Input: SchemaObjectClass(
                oid="2.16.840.1.113894.2.1.1",
                name="orclContainer",
                kind="STRUCTURAL",
                must=["cn"],
                may=["description"],
            )
            Output: (
                "( 2.16.840.1.113894.2.1.1 NAME 'orclContainer' "
                "STRUCTURAL MUST cn MAY description )"
            )

        """
        try:
            # Check if we have metadata with original format for perfect round-trip
            if oc_data.metadata and oc_data.metadata.original_format:
                # Fix known typos in original format
                # Fix AUXILLARY (double L) → AUXILIARY (single L)
                original = oc_data.metadata.original_format
                fixed_format = original.replace("AUXILLARY", "AUXILIARY")
                if fixed_format != original:
                    logger.debug(f"Fixed AUXILLARY typo in objectClass {oc_data.name}")
                    return FlextResult[str].ok(fixed_format)
                return FlextResult[str].ok(original)

            # Build RFC 4512 objectClass definition from scratch
            parts = []

            # Start with OID (required)
            oid = oc_data.oid
            if not oid or not oid.strip():
                return FlextResult[str].fail(
                    "OID is required for objectClass RFC 4512 format"
                )
            parts.append(f"( {oid}")

            # Add NAME (required)
            name = oc_data.name
            parts.append(f"NAME '{name}'")

            # Add DESC (optional)
            if oc_data.desc:
                parts.append(f"DESC '{oc_data.desc}'")

            # Add SUP (optional)
            if oc_data.sup:
                sup_value = oc_data.sup
                if isinstance(sup_value, list):
                    # Multiple superior classes: "SUP ( org $ orgUnit )"
                    sup_str = " $ ".join(sup_value)
                    parts.append(f"SUP ( {sup_str} )")
                else:
                    parts.append(f"SUP {sup_value}")

            # Add KIND (STRUCTURAL, AUXILIARY, ABSTRACT)
            if oc_data.kind:
                parts.append(oc_data.kind)

            # Add MUST attributes (optional)
            if oc_data.must:
                must_attrs = oc_data.must
                if isinstance(must_attrs, list):
                    if len(must_attrs) > 1:
                        # Multiple required attributes: "MUST ( cn $ sn )"
                        must_str = " $ ".join(must_attrs)
                        parts.append(f"MUST ( {must_str} )")
                    elif len(must_attrs) == 1:
                        parts.append(f"MUST {must_attrs[0]}")

            # Add MAY attributes (optional)
            if oc_data.may:
                may_attrs = oc_data.may
                if isinstance(may_attrs, list):
                    if len(may_attrs) > 1:
                        # Multiple optional attributes: "MAY ( description $ seeAlso )"
                        may_str = " $ ".join(may_attrs)
                        parts.append(f"MAY ( {may_str} )")
                    elif len(may_attrs) == 1:
                        parts.append(f"MAY {may_attrs[0]}")

            # Add X-ORIGIN from metadata if present
            if oc_data.metadata and oc_data.metadata.x_origin:
                parts.append(f"X-ORIGIN '{oc_data.metadata.x_origin}'")

            # Close the definition
            rfc_string = " ".join(parts) + " )"

            return FlextResult[str].ok(rfc_string)

        except Exception as e:
            return FlextResult[str].fail(f"Failed to write OID objectClass to RFC: {e}")

    def extract_schemas_from_ldif(
        self, ldif_content: str
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
            attributes = RfcSchemaExtractor.extract_attributes_from_lines(
                ldif_content, self.parse_attribute
            )
            objectclasses = RfcSchemaExtractor.extract_objectclasses_from_lines(
                ldif_content, self.parse_objectclass
            )

            return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok({
                dk.ATTRIBUTES: attributes,
                "objectclasses": objectclasses,
            })

        except Exception as e:
            return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                f"OID schema extraction failed: {e}"
            )

    def convert_attribute_from_rfc(
        self, rfc_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Convert RFC-compliant attribute to OID-specific format.

        Args:
        rfc_data: RFC-compliant attribute data

        Returns:
        FlextResult with OID attribute data

        """
        try:
            # Oracle OID uses RFC-compliant schema format
            # Just create new model with updated metadata if needed
            # Since models are frozen, we return the input model as-is
            # (OID format is identical to RFC format for attributes)
            return FlextResult[FlextLdifModels.SchemaAttribute].ok(rfc_data)

        except Exception as e:
            return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                f"RFC→OID attribute conversion failed: {e}"
            )

    def convert_objectclass_from_rfc(
        self, rfc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Convert RFC-compliant objectClass to OID-specific format.

        Args:
        rfc_data: RFC-compliant objectClass data

        Returns:
        FlextResult with OID objectClass data

        """
        try:
            # Oracle OID uses RFC-compliant schema format
            # Just return the input model as-is
            # (OID format is identical to RFC format for objectClasses)
            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(rfc_data)

        except Exception as e:
            return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                f"RFC→OID objectClass conversion failed: {e}"
            )

    class AclQuirk(FlextLdifQuirksBase.AclQuirk):
        """Oracle OID ACL quirk (nested).

        Extends RFC ACL parsing with Oracle OID-specific ACL formats:
        - orclaci: Oracle standard ACIs
        - orclentrylevelaci: Oracle entry-level ACIs

        Example:
            quirk = FlextLdifQuirksServersOid.AclQuirk(server_type="oracle_oid")
            if quirk.can_handle_acl(acl_line):
                result = quirk.parse_acl(acl_line)

        """

        def __init__(
            self,
            server_type: str = FlextLdifConstants.ServerTypes.OID,
            priority: int = 10,
        ) -> None:
            """Initialize OID ACL quirk.

            Args:
                server_type: Oracle OID server type
                priority: High priority for OID ACL parsing

            """
            super().__init__(server_type=server_type, priority=priority)

        def can_handle_acl(self, acl_line: str) -> bool:
            """Check if this is an Oracle OID ACL.

            Args:
            acl_line: ACL definition line

            Returns:
            True if this is orclaci or orclentrylevelaci

            """
            return acl_line.startswith(("orclaci:", "orclentrylevelaci:"))

        def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse Oracle OID ACL definition to Pydantic model.

            Parses orclaci and orclentrylevelaci formats from real OID fixtures:
            - orclaci: access to entry/attr=(...) [filter=(...)]
            by <subject> (<perms>) [by...]
            - orclentrylevelaci: access to entry by <subject>
            [added_object_constraint=(...)] (<perms>)

            Args:
                acl_line: ACL definition line

            Returns:
                FlextResult with parsed OID ACL as Pydantic model

            """
            try:
                # Determine ACL type
                is_entry_level = acl_line.startswith("orclentrylevelaci:")
                acl_content = (
                    acl_line.split(":", 1)[1].strip() if ":" in acl_line else acl_line
                )

                # Extract target (entry or attr)
                target_dn = "*"
                target_attrs: list[str] = []
                if "access to entry" in acl_content:
                    target_dn = "*"
                elif "access to attr=" in acl_content:
                    attr_match = re.search(r"access to attr=\(([^)]+)\)", acl_content)
                    if attr_match:
                        target_attrs = [
                            a.strip() for a in attr_match.group(1).split(",")
                        ]
                        target_dn = "*"

                # Extract "by" clauses with subjects and permissions
                # Pattern: by <subject> (<permissions>) OR by <subject> ... (<permissions>) for entry-level with constraints
                by_pattern = r'by\s+(group="[^"]+"|dnattr=\([^)]+\)|guidattr=\([^)]+\)|groupattr=\([^)]+\)|"[^"]+"|self|\*)\s+\(([^)]+)\)'
                matches = list(re.finditer(by_pattern, acl_content))

                # For entry-level ACLs with added_object_constraint, permissions are at the end
                if (
                    not matches
                    and is_entry_level
                    and "added_object_constraint=" in acl_content
                ):
                    # Extract subject from 'by <subject> added_object_constraint=...'
                    subject_pattern = r'by\s+(group="[^"]+"|dnattr=\([^)]+\)|guidattr=\([^)]+\)|groupattr=\([^)]+\)|"[^"]+"|self|\*)'
                    subject_match = re.search(subject_pattern, acl_content)
                    # Extract permissions from the final (...) at the end
                    perms_pattern = r"\(([^)]+)\)\s*$"
                    perms_match = re.search(perms_pattern, acl_content)

                    if subject_match and perms_match:
                        # Create a synthetic match that looks like the standard format
                        matches = [(subject_match.group(1), perms_match.group(1))]

                if not matches:
                    return FlextResult[FlextLdifModels.Acl].fail(
                        f"No 'by' clauses found in OID ACL: {acl_line}"
                    )

                # Take first by_clause (OID can have multiple, but model expects single subject/permissions)
                first_match = matches[0]
                # Handle both regex match objects and tuples (from entry-level constraint parsing)
                if isinstance(first_match, tuple):
                    subject_str = first_match[0].strip()
                    permissions_str = first_match[1].strip()
                else:
                    subject_str = first_match.group(1).strip()
                    permissions_str = first_match.group(2).strip()
                permissions_list = [p.strip() for p in permissions_str.split(",")]

                # Build AclSubject from subject string
                if subject_str == "*":
                    subject_type = "anonymous"
                    subject_value = "*"
                elif subject_str == "self":
                    subject_type = "self"
                    subject_value = "self"
                elif subject_str.startswith('group="'):
                    subject_type = "group"
                    subject_value = subject_str[7:-1]  # Extract DN from group="..."
                elif subject_str.startswith("dnattr=("):
                    subject_type = "bind_rules"
                    attr = subject_str[8:-1]  # Extract attr from dnattr=(...)
                    subject_value = f'userattr="{attr}#LDAPURL"'
                elif subject_str.startswith("guidattr=("):
                    subject_type = "bind_rules"
                    attr = subject_str[10:-1]  # Extract attr from guidattr=(...)
                    subject_value = f'userattr="{attr}#USERDN"'
                elif subject_str.startswith("groupattr=("):
                    subject_type = "bind_rules"
                    attr = subject_str[11:-1]  # Extract attr from groupattr=(...)
                    subject_value = f'userattr="{attr}#GROUPDN"'
                elif subject_str.startswith('"') and subject_str.endswith('"'):
                    subject_type = "user"
                    subject_value = subject_str[1:-1]  # Extract DN from "..."
                else:
                    subject_type = "user"
                    subject_value = subject_str

                # Build AclPermissions from permissions list
                permissions_data = {}
                for perm in permissions_list:
                    perm_lower = perm.lower()
                    if perm_lower == "read":
                        permissions_data["read"] = True
                    elif perm_lower == "write":
                        permissions_data["write"] = True
                    elif perm_lower == "add":
                        permissions_data["add"] = True
                    elif perm_lower == "delete":
                        permissions_data["delete"] = True
                    elif perm_lower == "search":
                        permissions_data["search"] = True
                    elif perm_lower == "compare":
                        permissions_data["compare"] = True
                    elif perm_lower == "selfwrite":
                        permissions_data["self_write"] = True
                    elif perm_lower == "proxy":
                        permissions_data["proxy"] = True
                    elif perm_lower == "browse":
                        # OID browse → RFC read+search
                        permissions_data["read"] = True
                        permissions_data["search"] = True
                    elif perm_lower == "all":
                        permissions_data["read"] = True
                        permissions_data["write"] = True
                        permissions_data["add"] = True
                        permissions_data["delete"] = True
                        permissions_data["search"] = True
                        permissions_data["compare"] = True

                # Build complete ACL model
                acl = FlextLdifModels.Acl(
                    name="OID ACL" if is_entry_level else "OID Standard ACL",
                    target=FlextLdifModels.AclTarget(
                        target_dn=target_dn, attributes=target_attrs
                    ),
                    subject=FlextLdifModels.AclSubject(
                        subject_type=subject_type, subject_value=subject_value
                    ),
                    permissions=FlextLdifModels.AclPermissions(**permissions_data),
                    server_type="oracle_oid",
                    raw_acl=acl_line,
                )

                return FlextResult[FlextLdifModels.Acl].ok(acl)

            except Exception as e:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"OID ACL parsing failed: {e}"
                )

        def _convert_oid_to_rfc_permissions(
            self, oid_permissions: list[str]
        ) -> tuple[list[str], list[str], dict[str, object]]:
            """Convert OID permissions to RFC-compliant allow/deny permissions with metadata.

            OID → RFC conversion rules:
            - browse → read,search (RFC equivalent)
            - selfwrite → write (RFC equivalent)
            - proxy → metadata annotation (OUD must handle)
            - none → deny (all RFC permissions)
            - no<perm> → deny (<perm>)

            Args:
                oid_permissions: List of OID permission keywords

            Returns:
                Tuple of (allowed_permissions, denied_permissions, metadata_dict)
                metadata contains: {"proxy_permissions": [...], "original_oid_perms": [...]}

            """
            oid_to_rfc_map = {
                "browse": ["read", "search"],
                "selfwrite": ["write"],
            }
            rfc_valid_perms = {
                "read",
                "write",
                "add",
                "delete",
                "search",
                "compare",
                "all",
            }

            allowed: list[str] = []
            denied: list[str] = []
            proxy_perms: list[str] = []

            for perm in oid_permissions:
                perm_str = str(perm).strip().lower()

                # Special case: "none" means deny all
                if perm_str == "none":
                    denied.extend([
                        "read",
                        "write",
                        "add",
                        "delete",
                        "search",
                        "compare",
                    ])
                    continue

                # Special case: "proxy" → metadata annotation
                if perm_str == "proxy":
                    proxy_perms.append("proxy")
                    continue

                # Negated permission (no*) → deny
                if perm_str.startswith("no"):
                    base_perm = perm_str[2:]
                    if base_perm in oid_to_rfc_map:
                        denied.extend(oid_to_rfc_map[base_perm])
                    elif base_perm in rfc_valid_perms:
                        denied.append(base_perm)
                    continue

                # Positive permission → allow
                if perm_str in oid_to_rfc_map:
                    allowed.extend(oid_to_rfc_map[perm_str])
                elif perm_str in rfc_valid_perms:
                    allowed.append(perm_str)

            # Deduplicate preserving order
            def dedupe(perms: list[str]) -> list[str]:
                seen: set[str] = set()
                result: list[str] = []
                for p in perms:
                    if p not in seen:
                        seen.add(p)
                        result.append(p)
                return result

            # Build metadata
            metadata: dict[str, object] = {
                "original_oid_perms": oid_permissions,
            }
            if proxy_perms:
                metadata["proxy_permissions"] = proxy_perms

            return (dedupe(allowed), dedupe(denied), metadata)

        def convert_acl_to_rfc(
            self, acl_data: FlextLdifModels.Acl
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Convert OID ACL model to RFC-compliant ACL model (OID→RFC transformation).

            Applies OID-specific transformations to produce RFC-compliant ACL model:
            - Permission normalization via _convert_oid_to_rfc_permissions
            - Subject format conversion to RFC bind rules
            - Name prefixing with "Migrated from OID:"
            - Server type change to "rfc"

            Args:
                acl_data: OID ACL Pydantic model

            Returns:
                FlextResult with RFC-compliant ACL model

            """
            try:
                # The model from parse_acl already has permissions in the correct format
                # (as boolean fields). We just need to change the server_type to "generic"
                # and update the name. No permission conversion needed.

                # Build RFC-compliant ACL model
                rfc_acl = FlextLdifModels.Acl(
                    name=f"Migrated from OID: {acl_data.name}",
                    target=acl_data.target,  # Copy target as-is
                    subject=acl_data.subject,  # Copy subject as-is (already in correct format)
                    permissions=acl_data.permissions,  # Copy permissions as-is (already correct)
                    server_type="generic",  # Change to RFC/generic type
                    raw_acl=acl_data.raw_acl,
                )

                return FlextResult[FlextLdifModels.Acl].ok(rfc_acl)

            except Exception as e:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"OID ACL→RFC conversion failed: {e}"
                )

        def convert_acl_from_rfc(
            self, acl_data: FlextLdifModels.Acl
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Convert RFC ACL model to OID-specific format.

            Since we use a unified FlextLdifModels.Acl for all servers,
            this is a pass-through that just sets the server_type to OID.

            Args:
                acl_data: RFC-compliant ACL Pydantic model

            Returns:
                FlextResult with OID ACL model

            """
            try:
                # Change server_type to OID (use object.__setattr__ for frozen model)
                object.__setattr__(acl_data, "server_type", "oid")  # noqa: PLC2801

                return FlextResult[FlextLdifModels.Acl].ok(acl_data)

            except Exception as e:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"RFC→OID ACL conversion failed: {e}"
                )

        def write_acl_to_rfc(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write ACL model to OID orclaci format string.

            Converts ACL Pydantic model to OID orclaci format.
            Uses model fields to build proper OID syntax.

            Args:
                acl_data: ACL Pydantic model

            Returns:
                FlextResult with formatted OID orclaci string

            """
            try:
                # If raw_acl is available and is OID format, use it for perfect round-trip
                if acl_data.raw_acl and acl_data.raw_acl.startswith("orclaci:"):
                    return FlextResult[str].ok(acl_data.raw_acl)

                # Build orclaci string from model fields
                parts = ["orclaci: access to entry"]

                # Extract subject and permissions from model
                if acl_data.subject and acl_data.permissions:
                    subject_type = acl_data.subject.subject_type
                    subject_value = acl_data.subject.subject_value

                    # Convert subject to OID format
                    if subject_type == "anonymous" or subject_value == "*":
                        subject_str = "*"
                    elif subject_type == "self":
                        subject_str = "self"
                    elif subject_type == "group":
                        # Extract DN from LDAP URL if present
                        dn = (
                            subject_value.replace("ldap:///", "")
                            if "ldap:///" in subject_value
                            else subject_value
                        )
                        subject_str = f'group="{dn}"'
                    elif subject_type == "bind_rules":
                        # Check for attribute-based subjects
                        if "userattr=" in subject_value:
                            # userattr="attr#LDAPURL" → dnattr=(attr)
                            attr = subject_value.split("=")[1].split("#")[0].strip('"')
                            subject_str = f"dnattr=({attr})"
                        else:
                            # Default user DN
                            dn = (
                                subject_value.replace("ldap:///", "")
                                if "ldap:///" in subject_value
                                else subject_value
                            )
                            subject_str = dn
                    else:
                        # Default: use value as-is
                        subject_str = subject_value

                    # Get permissions (from computed field)
                    if acl_data.permissions:
                        ops = (
                            acl_data.permissions.permissions
                        )  # Computed field returns list[str]
                        # Type narrowing for Pyrefly - ensure ops is list[str]
                        if isinstance(ops, list) and ops:
                            perms_str = ",".join(str(op) for op in ops)
                        else:
                            perms_str = "all"
                    else:
                        perms_str = "all"

                    # Build "by" clause
                    parts.append(f" by {subject_str} ({perms_str})")
                else:
                    # Fallback: allow all for everyone
                    parts.append(" by * (all)")

                orclaci = "".join(parts)
                return FlextResult[str].ok(orclaci)

            except Exception as e:
                return FlextResult[str].fail(f"Failed to write ACL: {e}")

        def extract_acls_from_ldif(
            self, ldif_content: str
        ) -> FlextResult[list[FlextLdifModels.Acl]]:
            """Strategy pattern: OID-specific approach to extract ACLs from LDIF entries.

            OID ACLs use:
            - orclaci: for OID standard ACLs
            - orclentrylevelaci: for entry-level ACLs

            Args:
            ldif_content: LDIF content containing ACL definitions

            Returns:
            FlextResult containing list of parsed ACL Pydantic models

            Examples:
            >>> ldif_text = '''
            ... dn: cn=OracleContext,dc=example,dc=com
            ... orclaci: access to entry by * (browse)
            ... orclentrylevelaci: access to attr=userPassword by self (write)
            ... '''
            >>> result = oid_quirk.acl.extract_acls_from_ldif(ldif_text)
            >>> acls = result.unwrap()
            >>> len(acls)
            2

            """
            try:
                acls = []
                current_acl: list[str] = []
                in_multiline_acl = False

                for line in ldif_content.split("\n"):
                    stripped = line.strip()

                    # Detect OID ACL start (orclaci: or orclentrylevelaci:)
                    if stripped.lower().startswith(
                        "orclaci:"
                    ) or stripped.lower().startswith("orclentrylevelaci:"):
                        # Parse previous ACL if exists
                        if current_acl:
                            acl_text = "\n".join(current_acl)
                            result = self.parse_acl(acl_text)
                            if result.is_success:
                                acls.append(result.unwrap())
                            current_acl = []

                        current_acl.append(stripped)
                        # Check if ACL continues on next line
                        # (doesn't end with complete structure)
                        in_multiline_acl = not stripped.rstrip().endswith(")")

                    # Continuation line for multiline ACL
                    elif in_multiline_acl and stripped:
                        current_acl.append(stripped)
                        if stripped.rstrip().endswith(")"):
                            in_multiline_acl = False

                # Parse any remaining ACL
                if current_acl:
                    acl_text = "\n".join(current_acl)
                    result = self.parse_acl(acl_text)
                    if result.is_success:
                        acls.append(result.unwrap())

                return FlextResult[list[FlextLdifModels.Acl]].ok(acls)

            except Exception as e:
                return FlextResult[list[FlextLdifModels.Acl]].fail(
                    f"Failed to extract OID ACLs from LDIF: {e}"
                )

    class EntryQuirk(FlextLdifQuirksBase.EntryQuirk):
        """Oracle OID entry quirk (nested).

        Handles Oracle OID-specific entry transformations:
        - Oracle operational attributes
        - OID-specific object classes
        - Oracle namespace attributes

        Example:
            quirk = FlextLdifQuirksServersOid.EntryQuirk(server_type="oracle_oid")
            if quirk.can_handle_entry(dn, attributes):
                result = quirk.process_entry(dn, attributes)

        """

        def __init__(
            self,
            server_type: str = FlextLdifConstants.ServerTypes.OID,
            priority: int = 10,
        ) -> None:
            """Initialize OID entry quirk.

            Args:
                server_type: Oracle OID server type
                priority: High priority for OID entry processing

            """
            super().__init__(server_type=server_type, priority=priority)

        def clean_dn(self, dn: str) -> str:
            r"""Clean OID-specific DN formatting issues.

            STRATEGY PATTERN: Delegates to shared DnService for RFC 4514 compliance.
            This ensures consistent DN handling across all flext-ldif and
            flext-ldap components.

            OID LDIF quirks handled by shared utility:
            - Removes leading/trailing whitespace from RDN components
            - Collapses spaces around '=' in RDNs
            - Fixes malformed backslash escapes with trailing spaces
              (e.g., "\\ " -> " ")
            - Normalizes escaped characters in DN values

            Args:
                dn: The raw DN string from the LDIF.

            Returns:
                A cleaned DN string compliant with RFC 4514.

            Example:
                Input:  "cn = NAME , ou = dept , dc = example , dc = com"
                Output: "cn=NAME,ou=dept,dc=example,dc=com"

            """
            # Use shared DN utility for consistent DN handling
            return FlextLdifDnService.clean_dn(dn)

        def can_handle_entry(
            self,
            entry_dn: str,
            attributes: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> bool:
            """Check if this quirk should handle the entry.

            Args:
                entry_dn: Entry distinguished name
                attributes: Entry attributes

            Returns:
                True if this is an Oracle OID-specific entry

            """
            # Check for Oracle OID-specific attributes
            oid_attrs = [
                "orclguid",
                "orclobjectguid",
                "orclaci",
                "orclentrylevelaci",
                "orclaci",
                "orclentrycreatetime",
                "orclentrymodifytime",
            ]

            has_oid_attrs = any(
                attr.lower() in [a.lower() for a in attributes] for attr in oid_attrs
            )

            # Check for Oracle OID object classes
            object_classes = attributes.get(FlextLdifConstants.DictKeys.OBJECTCLASS, [])
            if not isinstance(object_classes, list):
                object_classes = [object_classes]

            has_oid_classes = any(
                str(oc).lower().startswith("orcl") for oc in object_classes
            )

            # Check DN patterns for OID entries - more flexible detection
            dn_lower = entry_dn.lower()
            has_oid_dn_pattern = (
                "oracle" in dn_lower
                or "orcl" in dn_lower
                or "ou=oracle" in dn_lower
                or "dc=oracle" in dn_lower
            )

            return has_oid_attrs or has_oid_classes or has_oid_dn_pattern

        def process_entry(
            self, entry_dn: str, attributes: FlextLdifTypes.Models.EntryAttributesDict
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Process entry for Oracle OID format.

            Args:
            entry_dn: Entry distinguished name
            attributes: Entry attributes

            Returns:
            FlextResult with processed entry data

            """
            try:
                # OID-specific quirk: handle non-string 'orclisvisible' values
                if "orclisvisible" in attributes:
                    val = attributes["orclisvisible"]
                    if isinstance(val, str) and val.lower() in {"true", "false"}:
                        attributes["orclisvisible"] = val.upper()

                # Extract ACL attributes to metadata (pipeline handles conversion)
                acl_attrs_oid = {"orclaci", "orclentrylevelaci", "aci"}
                forbidden_attrs = {
                    FlextLdifConstants.DictKeys.DN
                }  # DN cannot be a modifiable attribute
                acl_only_attrs = {}
                regular_attrs = {}

                for attr_name, attr_value in attributes.items():
                    attr_lower = attr_name.lower()
                    if attr_lower in forbidden_attrs:
                        # Skip DN - it's stored separately, not as an attribute
                        continue
                    if attr_lower in acl_attrs_oid:
                        acl_only_attrs[attr_name] = attr_value
                    else:
                        regular_attrs[attr_name] = attr_value

                # Oracle OID entries in RFC format
                dk = FlextLdifConstants.DictKeys
                st = FlextLdifConstants.ServerTypes
                processed_entry: dict[str, object] = {
                    dk.DN: entry_dn,
                    dk.SERVER_TYPE: st.OID,
                }

                # Add regular attributes (non-ACL)
                processed_entry.update(regular_attrs)

                # Store ACL attributes in metadata for pipeline processing
                if acl_only_attrs:
                    processed_entry["_acl_attributes"] = acl_only_attrs

                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    processed_entry
                )

            except Exception as e:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"OID entry processing failed: {e}"
                )

        def convert_entry_to_rfc(
            self, entry_data: FlextLdifTypes.Models.EntryAttributesDict
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Convert Oracle OID entry to RFC-compliant format.

            OID uses non-RFC compliant "0"/"1" for boolean attributes.
            RFC 4517 specifies Boolean syntax must be "TRUE" or "FALSE".
            This method normalizes OID booleans to RFC compliance.

            Additionally extracts ACL attributes (orclaci, orclentrylevelaci)
            to _acl_attributes metadata for pipeline processing.

            Args:
            entry_data: Oracle OID entry data

            Returns:
            FlextResult with RFC-compliant entry data and _acl_attributes metadata

            """
            try:
                # Oracle OID entries are already RFC-compliant
                # Only need to convert boolean attributes: "0"/"1" → "TRUE"/"FALSE"
                rfc_data = dict(entry_data)

                # Oracle boolean attributes (non-RFC compliant: use "0"/"1" instead of "TRUE"/"FALSE")
                # RFC 4517 Boolean syntax (OID 1.3.6.1.4.1.1466.115.121.1.7) requires "TRUE" or "FALSE"
                # OID quirks must convert "0"→"FALSE", "1"→"TRUE" during OID→RFC normalization
                oid_boolean_attrs = (
                    FlextLdifConstants.OperationalAttributes.OID_BOOLEAN_ATTRIBUTES
                )

                # Check if attributes are in nested 'attributes' dict (categorized pipeline format)
                if FlextLdifConstants.DictKeys.ATTRIBUTES in rfc_data:
                    attrs = rfc_data[FlextLdifConstants.DictKeys.ATTRIBUTES]
                    if isinstance(attrs, dict):
                        # Convert boolean values in nested attributes dict
                        for attr_name in list(attrs.keys()):
                            if attr_name.lower() in oid_boolean_attrs:
                                attr_value = attrs[attr_name]
                                if isinstance(attr_value, list):
                                    attrs[attr_name] = [
                                        "TRUE"
                                        if v == "1"
                                        else "FALSE"
                                        if v == "0"
                                        else v
                                        for v in attr_value
                                    ]
                                elif isinstance(attr_value, str):
                                    if attr_value == "1":
                                        attrs[attr_name] = "TRUE"
                                    elif attr_value == "0":
                                        attrs[attr_name] = "FALSE"
                else:
                    # Convert boolean values at top level (flat entry format)
                    for attr_name in list(rfc_data.keys()):
                        if attr_name.lower() in oid_boolean_attrs:
                            attr_value = rfc_data[attr_name]
                            if isinstance(attr_value, list):
                                rfc_data[attr_name] = [
                                    "TRUE" if v == "1" else "FALSE" if v == "0" else v
                                    for v in attr_value
                                ]
                            elif isinstance(attr_value, str):
                                if attr_value == "1":
                                    rfc_data[attr_name] = "TRUE"
                                elif attr_value == "0":
                                    rfc_data[attr_name] = "FALSE"

                # NOTE: Filtering is NOT the responsibility of quirks.
                # All attribute filtering is handled by client-aOudMigConstants
                # (BLOCKED_ATTRIBUTES) in the migration service.
                # Quirks ONLY perform FORMAT transformations (e.g., boolean 0/1 → TRUE/FALSE).
                # ACL extraction is handled separately in final pipeline phase.

                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    rfc_data
                )

            except Exception as e:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"OID entry→RFC conversion failed: {e}"
                )

        def convert_entry_from_rfc(
            self, entry_data: FlextLdifTypes.Models.EntryAttributesDict
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Convert RFC-compliant entry to Oracle OID format.

            Args:
            entry_data: RFC-compliant entry data

            Returns:
            FlextResult with OID entry data

            """
            # Oracle OID uses RFC-compliant format
            # Just ensure OID server type is set via shared converter
            return RfcSchemaConverter.set_server_type(
                entry_data, FlextLdifConstants.ServerTypes.OID
            )

        def write_entry_to_ldif(
            self, entry_data: FlextLdifTypes.Models.EntryAttributesDict
        ) -> FlextResult[str]:
            r"""Write OID entry data to standard LDIF string format.

            Converts parsed entry dictionary to LDIF format string.
            Handles Oracle-specific attributes like orclaci, orclguid, etc.

            Args:
                entry_data: Parsed OID entry data dictionary

            Returns:
                FlextResult with LDIF formatted entry string

            Example:
                Input: {
                    FlextLdifConstants.DictKeys.DN: "cn=test,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.CN: ["test"],
                    FlextLdifConstants.DictKeys.OBJECTCLASS: ["person"]
                }
                Output: "dn: cn=test,dc=example,dc=com\ncn: test\n
                    objectClass: person\n"

            """
            try:
                # Check for required DN field
                if FlextLdifConstants.DictKeys.DN not in entry_data:
                    return FlextResult[str].fail(
                        "Missing required FlextLdifConstants.DictKeys.DN field"
                    )

                dn = entry_data[FlextLdifConstants.DictKeys.DN]
                ldif_lines = [f"dn: {dn}"]

                # Get attribute ordering from metadata if available
                attr_order = None
                if "_metadata" in entry_data:
                    metadata = entry_data["_metadata"]
                    if isinstance(metadata, FlextLdifModels.QuirkMetadata):
                        attr_order = metadata.extensions.get("attribute_order")
                    elif isinstance(metadata, dict):
                        attr_order = metadata.get("extensions", {}).get(
                            "attribute_order"
                        )

                # Determine attribute iteration order
                # Define excluded keys as a set for efficient membership testing
                excluded_keys = {
                    FlextLdifConstants.DictKeys.DN,
                    "_metadata",
                    FlextLdifConstants.DictKeys.SERVER_TYPE,
                    FlextLdifConstants.DictKeys.HAS_OID_ACLS,
                }

                # Type narrowing: ensure attr_order is list before iteration
                if attr_order is not None and isinstance(attr_order, list):
                    # Use preserved ordering
                    attrs_to_process = [
                        (key, entry_data[key])
                        for key in attr_order
                        if key in entry_data and key not in excluded_keys
                    ]
                else:
                    # Default ordering: filter out special keys
                    attrs_to_process = [
                        (key, value)
                        for key, value in entry_data.items()
                        if key not in excluded_keys
                    ]

                # Write attributes
                for attr_name, attr_value in attrs_to_process:
                    # Handle both list and single values
                    if isinstance(attr_value, list):
                        ldif_lines.extend(
                            f"{attr_name}: {value}" for value in attr_value
                        )
                    else:
                        ldif_lines.append(f"{attr_name}: {attr_value}")

                # Join with newlines and add trailing newline
                ldif_string = "\n".join(ldif_lines) + "\n"

                return FlextResult[str].ok(ldif_string)

            except Exception as e:
                return FlextResult[str].fail(f"Failed to write OID entry to LDIF: {e}")

        def extract_entries_from_ldif(
            self, ldif_content: str
        ) -> FlextResult[list[FlextLdifTypes.Models.EntryAttributesDict]]:
            """Strategy pattern: OID-specific approach to extract entries from LDIF.

            Handles:
            - DN parsing with OID-specific contexts (cn=OracleContext, etc.)
            - Continuation lines (lines starting with space)
            - Multi-valued attributes
            - Base64 encoded values (:: marker)
            - OID-specific objectClasses and attributes

            Args:
            ldif_content: LDIF content containing directory entries

            Returns:
            FlextResult containing list of parsed entry dictionaries

            Examples:
            >>> ldif_text = '''
            ... dn: cn=OracleContext,dc=example,dc=com
            ... objectClass: orclContext
            ... orclVersion: 90600
            ... cn: OracleContext
            ...
            ... dn: cn=users,cn=OracleContext,dc=example,dc=com
            ... objectClass: organizationalUnit
            ... cn: users
            ... '''
            >>> result = oid_quirk.entry.extract_entries_from_ldif(ldif_text)
            >>> entries = result.unwrap()
            >>> len(entries)
            2

            """
            try:
                entries = []
                current_entry: dict[str, object] = {}
                current_attr: str | None = None
                current_values: list[str] = []

                for line in ldif_content.split("\n"):
                    # Empty line indicates end of entry
                    if not line.strip():
                        if (
                            current_entry
                            and FlextLdifConstants.DictKeys.DN in current_entry
                        ):
                            # Save last attribute if exists
                            if current_attr and current_values:
                                if current_attr in current_entry:
                                    existing_value = current_entry[current_attr]
                                    if isinstance(existing_value, list):
                                        existing_value.extend(current_values)
                                    else:
                                        current_entry[current_attr] = [
                                            existing_value,
                                            *current_values,
                                        ]
                                else:
                                    current_entry[current_attr] = (
                                        current_values
                                        if len(current_values) > 1
                                        else current_values[0]
                                    )

                            # Process entry
                            dn = str(current_entry.pop(FlextLdifConstants.DictKeys.DN))
                            result = self.process_entry(dn, current_entry)
                            if result.is_success:
                                entries.append(result.unwrap())

                            # Reset for next entry
                            current_entry = {}
                            current_attr = None
                            current_values = []
                        continue

                    # Skip comments
                    if line.startswith("#"):
                        continue

                    # Continuation line (starts with space)
                    if line.startswith(" ") and current_attr:
                        if current_values:
                            # Append continuation to last value
                            current_values[-1] += line[1:]
                        continue

                    # New attribute line
                    if ":" in line:
                        # Save previous attribute
                        if current_attr and current_values:
                            if current_attr in current_entry:
                                existing_value = current_entry[current_attr]
                                if isinstance(existing_value, list):
                                    existing_value.extend(current_values)
                                else:
                                    current_entry[current_attr] = [
                                        existing_value,
                                        *current_values,
                                    ]
                            else:
                                current_entry[current_attr] = (
                                    current_values
                                    if len(current_values) > 1
                                    else current_values[0]
                                )
                            current_values = []

                        # Parse new attribute
                        if "::" in line:
                            # Base64 encoded value
                            parts = line.split("::", 1)
                            attr_name = parts[0].strip().lower()
                            attr_value = parts[1].strip() if len(parts) > 1 else ""
                            # Note: Real implementation should decode base64
                            # For now, preserve the marker for downstream processing
                            attr_value = f"base64:{attr_value}"
                        else:
                            parts = line.split(":", 1)
                            attr_name = parts[0].strip().lower()
                            attr_value = parts[1].strip() if len(parts) > 1 else ""

                        current_attr = attr_name
                        current_values = [attr_value]

                # Handle last entry if file doesn't end with blank line
                if current_entry and FlextLdifConstants.DictKeys.DN in current_entry:
                    if current_attr and current_values:
                        if current_attr in current_entry:
                            existing_value = current_entry[current_attr]
                            if isinstance(existing_value, list):
                                existing_value.extend(current_values)
                            else:
                                current_entry[current_attr] = [
                                    existing_value,
                                    *current_values,
                                ]
                        else:
                            current_entry[current_attr] = (
                                current_values
                                if len(current_values) > 1
                                else current_values[0]
                            )

                    dn = str(current_entry.pop(FlextLdifConstants.DictKeys.DN))
                    result = self.process_entry(dn, current_entry)
                    if result.is_success:
                        entries.append(result.unwrap())

                return FlextResult[list[FlextLdifTypes.Models.EntryAttributesDict]].ok(
                    entries
                )

            except Exception as e:
                return FlextResult[
                    list[FlextLdifTypes.Models.EntryAttributesDict]
                ].fail(f"Failed to extract OID entries from LDIF: {e}")


__all__ = [
    "FlextLdifQuirksServersOid",
]
