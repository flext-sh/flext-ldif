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
from pydantic import Field

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.base import (
    FlextLdifQuirksBaseAclQuirk,
    FlextLdifQuirksBaseEntryQuirk,
    FlextLdifQuirksBaseSchemaQuirk,
)
from flext_ldif.services.dn_service import FlextLdifDnService
from flext_ldif.typings import FlextLdifTypes

logger = logging.getLogger(__name__)


class FlextLdifQuirksServersOid(FlextLdifQuirksBaseSchemaQuirk):
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
        quirk = FlextLdifQuirksServersOid(server_type="oid")
        if quirk.can_handle_attribute(attr_def):
            result = quirk.parse_attribute(attr_def)
            if result.is_success:
                parsed_attr = result.unwrap()

    """

    server_type: str = Field(
        default=FlextLdifConstants.ServerTypes.OID,
        description="Oracle OID server type",
    )
    priority: int = Field(
        default=10, description="High priority for OID-specific parsing"
    )

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

    # Attributes to skip in objectClass definitions (missing/incompatible with OUD)
    SKIP_OBJECTCLASS_ATTRIBUTES: ClassVar[set[str]] = {
        "orclaci",  # OID Access Control - incompatible with OUD
        "orclentrylevelaci",  # OID Entry-Level ACI - incompatible with OUD
        "orcldaslov",  # Missing from schema
        "orcljaznjavaclass",  # Missing from schema
    }

    def model_post_init(self, _context: object, /) -> None:
        """Initialize OID schema quirk."""

    def can_handle_attribute(self, attr_definition: str) -> bool:
        """Check if this attribute should be processed by OID quirks.

        Only handles Oracle OID-specific attributes (OID namespace 2.16.840.1.113894.*).
        Standard RFC attributes are handled by the base RFC quirks.

        Args:
            attr_definition: AttributeType definition string

        Returns:
            True if attribute is Oracle OID-specific (namespace 2.16.840.1.113894.*)

        """
        # Extract OID from definition
        try:
            # Find OID in parentheses at start: ( 2.16.840.1.113894.* ...
            match = re.search(r"\(\s*([\d.]+)", attr_definition)
            if not match:
                return False

            oid = match.group(1)
            # Check if it's Oracle OID namespace
            return oid.startswith("2.16.840.1.113894.")
        except Exception:
            return False

    def parse_attribute(self, attr_definition: str) -> FlextResult[dict[str, object]]:
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
            # Parse RFC 4512 schema definition (same approach as OUD)
            parsed_data: dict[str, object] = {}

            # Extract OID (first element after opening parenthesis)
            oid_match = re.match(r"\(\s*([0-9.]+)", attr_definition)
            if oid_match:
                parsed_data["oid"] = oid_match.group(1)

            # Extract NAME (single or multiple)
            name_match = re.search(r"NAME\s+(?:\(\s*)?'([^']+)'", attr_definition)
            if name_match:
                parsed_data["name"] = name_match.group(1)

            # Extract DESC
            desc_match = re.search(r"DESC\s+'([^']+)'", attr_definition)
            if desc_match:
                parsed_data["desc"] = desc_match.group(1)

            # Extract SYNTAX
            syntax_match = re.search(
                r"SYNTAX\s+'?([0-9.]+)(?:\{(\d+)\})?'?", attr_definition
            )
            if syntax_match:
                parsed_data["syntax"] = syntax_match.group(1)
                if syntax_match.group(2):
                    parsed_data["syntax_length"] = syntax_match.group(2)

            # Extract EQUALITY
            equality_match = re.search(r"EQUALITY\s+(\w+)", attr_definition)
            if equality_match:
                parsed_data["equality"] = equality_match.group(1)

            # Extract SUBSTR
            substr_match = re.search(r"SUBSTR\s+(\w+)", attr_definition)
            if substr_match:
                parsed_data["substr"] = substr_match.group(1)

            # Extract ORDERING
            ordering_match = re.search(r"ORDERING\s+(\w+)", attr_definition)
            if ordering_match:
                parsed_data["ordering"] = ordering_match.group(1)

            # Check for SINGLE-VALUE
            parsed_data["single_value"] = "SINGLE-VALUE" in attr_definition

            # Check for NO-USER-MODIFICATION
            parsed_data["no_user_mod"] = "NO-USER-MODIFICATION" in attr_definition

            # Extract SUP (superior attribute)
            sup_match = re.search(r"SUP\s+(\w+)", attr_definition)
            if sup_match:
                parsed_data["sup"] = sup_match.group(1)

            # Extract USAGE
            usage_match = re.search(r"USAGE\s+(\w+)", attr_definition)
            if usage_match:
                parsed_data["usage"] = usage_match.group(1)

            # Add OID server type metadata
            parsed_data[FlextLdifConstants.DictKeys.SERVER_TYPE] = "oid"

            # Add metadata for perfect round-trip preservation
            parsed_data["_metadata"] = FlextLdifModels.QuirkMetadata.create_for_quirk(
                quirk_type="oid", original_format=attr_definition.strip()
            )

            return FlextResult[dict[str, object]].ok(parsed_data)

        except Exception as e:
            return FlextResult[dict[str, object]].fail(
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
        # Extract OID from definition
        try:
            # Find OID in parentheses at start: ( 2.16.840.1.113894.* ...
            match = re.search(r"\(\s*([\d.]+)", oc_definition)
            if not match:
                return False

            oid = match.group(1)
            # Check if it's Oracle OID namespace
            return oid.startswith("2.16.840.1.113894.")
        except Exception:
            return False

    def parse_objectclass(self, oc_definition: str) -> FlextResult[dict[str, object]]:
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
            # Parse RFC 4512 objectClass definition (same approach as OUD)
            parsed_data: dict[str, object] = {}

            # Extract OID (first element after opening parenthesis)
            oid_match = re.match(r"\(\s*([0-9.]+)", oc_definition)
            if oid_match:
                parsed_data["oid"] = oid_match.group(1)

            # Extract NAME (single or multiple)
            name_match = re.search(r"NAME\s+(?:\(\s*)?'([^']+)'", oc_definition)
            if name_match:
                parsed_data["name"] = name_match.group(1)

            # Extract DESC
            desc_match = re.search(r"DESC\s+'([^']+)'", oc_definition)
            if desc_match:
                parsed_data["desc"] = desc_match.group(1)

            # Extract SUP (superior objectClass)
            sup_match = re.search(
                r"SUP\s+(?:\(\s*([\w\s$]+)\s*\)|(\w+))",
                oc_definition,
            )
            if sup_match:
                sup_value = sup_match.group(1) or sup_match.group(2)
                sup_value = sup_value.strip()
                # Handle multiple superior classes like
                # "organization $ organizationalUnit"
                if "$" in sup_value:
                    parsed_data["sup"] = [s.strip() for s in sup_value.split("$")]
                else:
                    parsed_data["sup"] = sup_value

            # Determine kind (STRUCTURAL, AUXILIARY, ABSTRACT)
            if "STRUCTURAL" in oc_definition:
                parsed_data["kind"] = "STRUCTURAL"
            elif "AUXILIARY" in oc_definition:
                parsed_data["kind"] = "AUXILIARY"
            elif "ABSTRACT" in oc_definition:
                parsed_data["kind"] = "ABSTRACT"

            # Extract MUST attributes
            must_match = re.search(
                r"MUST\s+\(\s*([^)]+)\s*\)|MUST\s+(\w+)", oc_definition
            )
            if must_match:
                must_value = must_match.group(1) or must_match.group(2)
                if "$" in must_value:
                    parsed_data["must"] = [m.strip() for m in must_value.split("$")]
                else:
                    parsed_data["must"] = [must_value.strip()]

            # Extract MAY attributes
            may_match = re.search(r"MAY\s+\(\s*([^)]+)\s*\)|MAY\s+(\w+)", oc_definition)
            if may_match:
                may_value = may_match.group(1) or may_match.group(2)
                if "$" in may_value:
                    parsed_data["may"] = [m.strip() for m in may_value.split("$")]
                else:
                    parsed_data["may"] = [may_value.strip()]

            # Add OID server type metadata
            parsed_data[FlextLdifConstants.DictKeys.SERVER_TYPE] = "oid"

            # Add metadata for perfect round-trip preservation
            parsed_data["_metadata"] = FlextLdifModels.QuirkMetadata.create_for_quirk(
                quirk_type="oid", original_format=oc_definition.strip()
            )

            return FlextResult[dict[str, object]].ok(parsed_data)

        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"OID objectClass parsing failed: {e}"
            )

    def convert_attribute_to_rfc(
        self, attr_data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        """Convert OID attribute to RFC-compliant format.

        Args:
        attr_data: OID attribute data

        Returns:
        FlextResult with RFC-compliant attribute data

        """
        try:
            # Oracle OID attributes can be represented in RFC format
            # by removing Oracle-specific extensions and fixing OUD-incompatible values

            # Copy all fields from attr_data first
            rfc_data = dict(attr_data)

            # Fix NAME - remove ;binary suffix and replace underscores
            name_value = rfc_data.get(FlextLdifConstants.DictKeys.NAME)
            if name_value and isinstance(name_value, str):
                modified = False
                if ";binary" in name_value:
                    name_value = name_value.replace(";binary", "")
                    modified = True
                    logger.debug(f"Removed ;binary from NAME: {name_value}")
                if "_" in name_value:
                    name_value = name_value.replace("_", "-")
                    modified = True
                    logger.debug(f"Replaced _ with - in NAME: {name_value}")
                if modified:
                    rfc_data[FlextLdifConstants.DictKeys.NAME] = name_value

            # Fix EQUALITY - replace invalid matching rules or fix misused SUBSTR rules
            equality_value = rfc_data.get(FlextLdifConstants.DictKeys.EQUALITY)
            if equality_value and isinstance(equality_value, str):
                # Check if EQUALITY is using a SUBSTR matching rule (common OID mistake)
                # Handle both caseIgnoreSubStringsMatch (capital S) and caseIgnoreSubstringsMatch (lowercase)
                if equality_value in {
                    "caseIgnoreSubstringsMatch",
                    "caseIgnoreSubStringsMatch",
                }:
                    # Move to SUBSTR and use proper EQUALITY
                    rfc_data[FlextLdifConstants.DictKeys.EQUALITY] = "caseIgnoreMatch"
                    rfc_data[FlextLdifConstants.DictKeys.SUBSTR] = (
                        "caseIgnoreSubstringsMatch"
                    )
                    logger.debug(
                        f"Fixed EQUALITY: moved {equality_value} to SUBSTR, using caseIgnoreMatch for EQUALITY"
                    )
                elif equality_value in self.MATCHING_RULE_REPLACEMENTS:
                    # Standard replacement
                    original = equality_value
                    rfc_data[FlextLdifConstants.DictKeys.EQUALITY] = (
                        self.MATCHING_RULE_REPLACEMENTS[equality_value]
                    )
                    logger.debug(
                        f"Replaced matching rule {original} -> {rfc_data[FlextLdifConstants.DictKeys.EQUALITY]}"
                    )

            # Fix SYNTAX - remove quotes (OID uses 'OID' format, RFC 4512 uses OID without quotes)
            syntax_value = rfc_data.get(FlextLdifConstants.DictKeys.SYNTAX)
            if syntax_value and isinstance(syntax_value, str):
                # Remove quotes if present
                if syntax_value.startswith("'") and syntax_value.endswith("'"):
                    syntax_value = syntax_value[1:-1]
                    rfc_data[FlextLdifConstants.DictKeys.SYNTAX] = syntax_value
                    logger.debug(f"Removed quotes from SYNTAX: {syntax_value}")

                # Replace unsupported syntax OIDs
                if syntax_value in self.SYNTAX_OID_REPLACEMENTS:
                    original = syntax_value
                    rfc_data[FlextLdifConstants.DictKeys.SYNTAX] = (
                        self.SYNTAX_OID_REPLACEMENTS[syntax_value]
                    )
                    logger.debug(
                        f"Replaced syntax OID {original} -> {rfc_data[FlextLdifConstants.DictKeys.SYNTAX]}"
                    )

            return FlextResult[dict[str, object]].ok(rfc_data)

        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"OID→RFC conversion failed: {e}"
            )

    def convert_objectclass_to_rfc(
        self, oc_data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        """Convert OID objectClass to RFC-compliant format.

        Args:
        oc_data: OID objectClass data

        Returns:
        FlextResult with RFC-compliant objectClass data

        """
        try:
            # Convert Oracle OID objectClass to RFC format
            # Filter out missing/incompatible attributes from MUST and MAY

            # Filter MUST attributes
            must_value = oc_data.get(FlextLdifConstants.DictKeys.MUST)
            if must_value and isinstance(must_value, list):
                filtered_must = [
                    attr
                    for attr in must_value
                    if isinstance(attr, str)
                    and attr.lower() not in self.SKIP_OBJECTCLASS_ATTRIBUTES
                ]
                must_value = filtered_must or None
                if must_value is None:
                    logger.debug("All MUST attributes filtered out")

            # Filter MAY attributes
            may_value = oc_data.get(FlextLdifConstants.DictKeys.MAY)
            if may_value and isinstance(may_value, list):
                filtered_may = [
                    attr
                    for attr in may_value
                    if isinstance(attr, str)
                    and attr.lower() not in self.SKIP_OBJECTCLASS_ATTRIBUTES
                ]
                if len(filtered_may) < len(may_value):
                    removed = set(may_value) - set(filtered_may)
                    logger.debug(f"Filtered MAY attributes: {removed}")
                may_value = filtered_may or None

            # Fix inheritance conflicts - OUD requires KIND to match superior class KIND
            # Map of known problematic superior classes and their expected KINDs
            kind_value = oc_data.get(FlextLdifConstants.DictKeys.KIND)
            sup_value = oc_data.get(FlextLdifConstants.DictKeys.SUP)

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
                if sup_lower in structural_superiors and kind_value == "AUXILIARY":
                    logger.debug(
                        f"Changing {oc_data.get('name')} from AUXILIARY to STRUCTURAL "
                        f"to match superior class {sup_value}"
                    )
                    kind_value = "STRUCTURAL"

                # If SUP is AUXILIARY but objectClass is STRUCTURAL, change to AUXILIARY
                elif sup_lower in auxiliary_superiors and kind_value == "STRUCTURAL":
                    logger.debug(
                        f"Changing {oc_data.get('name')} from STRUCTURAL to AUXILIARY "
                        f"to match superior class {sup_value}"
                    )
                    kind_value = "AUXILIARY"

            rfc_data = {
                FlextLdifConstants.DictKeys.OID: oc_data.get(
                    FlextLdifConstants.DictKeys.OID
                ),
                FlextLdifConstants.DictKeys.NAME: oc_data.get(
                    FlextLdifConstants.DictKeys.NAME
                ),
                FlextLdifConstants.DictKeys.DESC: oc_data.get(
                    FlextLdifConstants.DictKeys.DESC
                ),
                FlextLdifConstants.DictKeys.SUP: oc_data.get(
                    FlextLdifConstants.DictKeys.SUP
                ),
                FlextLdifConstants.DictKeys.KIND: oc_data.get(
                    FlextLdifConstants.DictKeys.KIND
                ),
                FlextLdifConstants.DictKeys.MUST: must_value,
                FlextLdifConstants.DictKeys.MAY: may_value,
            }

            return FlextResult[dict[str, object]].ok(rfc_data)

        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"OID→RFC conversion failed: {e}"
            )

    def write_attribute_to_rfc(self, attr_data: dict[str, object]) -> FlextResult[str]:
        """Write OID attribute data to RFC 4512 compliant string format.

        Converts parsed attribute dictionary back to RFC 4512 schema definition format.
        If metadata contains original_format, uses it for perfect round-trip.

        Args:
            attr_data: Parsed OID attribute data dictionary

        Returns:
            FlextResult with RFC 4512 formatted attribute definition string

        Example:
            Input: {
                "oid": "2.16.840.1.113894.1.1.1",
                "name": "orclguid",
                "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
            }
            Output: (
                "( 2.16.840.1.113894.1.1.1 NAME 'orclguid' "
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
            )

        """
        try:
            # Check if we have metadata with original format for perfect round-trip
            if "_metadata" in attr_data:
                metadata = attr_data["_metadata"]
                if (
                    isinstance(metadata, FlextLdifModels.QuirkMetadata)
                    and metadata.original_format
                ):
                    return FlextResult[str].ok(metadata.original_format)
                if isinstance(metadata, dict) and "original_format" in metadata:
                    return FlextResult[str].ok(str(metadata["original_format"]))

            # Build RFC 4512 attribute definition from scratch
            parts = []

            # Start with OID (required)
            if "oid" not in attr_data:
                return FlextResult[str].fail("Missing required 'oid' field")
            parts.append(f"( {attr_data['oid']}")

            # Add NAME (required) - Fix invalid attribute names for OUD
            if "name" in attr_data:
                name = str(attr_data["name"])
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
            if "desc" in attr_data:
                parts.append(f"DESC '{attr_data['desc']}'")

            # Add SUP (optional)
            if "sup" in attr_data:
                parts.append(f"SUP {attr_data['sup']}")

            # Add EQUALITY (optional) - Fix invalid matching rules for OUD
            if "equality" in attr_data:
                equality = str(attr_data["equality"])
                # Replace invalid matching rules with OUD-compatible ones
                if equality in self.MATCHING_RULE_REPLACEMENTS:
                    original = equality
                    equality = self.MATCHING_RULE_REPLACEMENTS[equality]
                    logger.debug(f"Replaced matching rule {original} with {equality}")
                parts.append(f"EQUALITY {equality}")

            # Add ORDERING (optional)
            if "ordering" in attr_data:
                parts.append(f"ORDERING {attr_data['ordering']}")

            # Add SUBSTR (optional)
            if "substr" in attr_data:
                parts.append(f"SUBSTR {attr_data['substr']}")

            # Add SYNTAX (optional but common)
            if "syntax" in attr_data:
                syntax_str = str(attr_data["syntax"])
                if "syntax_length" in attr_data:
                    syntax_str += f"{{{attr_data['syntax_length']}}}"
                parts.append(f"SYNTAX {syntax_str}")

            # Add SINGLE-VALUE flag (optional)
            if attr_data.get("single_value"):
                parts.append("SINGLE-VALUE")

            # Add NO-USER-MODIFICATION flag (optional)
            if attr_data.get("no_user_mod"):
                parts.append("NO-USER-MODIFICATION")

            # Add USAGE (optional)
            if "usage" in attr_data:
                parts.append(f"USAGE {attr_data['usage']}")

            # Add X-ORIGIN (optional)
            if "x_origin" in attr_data:
                parts.append(f"X-ORIGIN '{attr_data['x_origin']}'")

            # Close the definition
            rfc_string = " ".join(parts) + " )"

            return FlextResult[str].ok(rfc_string)

        except Exception as e:
            return FlextResult[str].fail(f"Failed to write OID attribute to RFC: {e}")

    def write_objectclass_to_rfc(self, oc_data: dict[str, object]) -> FlextResult[str]:
        """Write OID objectClass data to RFC 4512 compliant string format.

        Converts parsed objectClass dictionary back to RFC 4512 schema
        definition format.
        If metadata contains original_format, uses it for perfect round-trip.

        Args:
            oc_data: Parsed OID objectClass data dictionary

        Returns:
            FlextResult with RFC 4512 formatted objectClass definition string

        Example:
            Input: {
                "oid": "2.16.840.1.113894.2.1.1",
                "name": "orclContainer",
                "kind": "STRUCTURAL",
                "must": ["cn"],
                "may": ["description"],
            }
            Output: (
                "( 2.16.840.1.113894.2.1.1 NAME 'orclContainer' "
                "STRUCTURAL MUST cn MAY description )"
            )

        """
        try:
            # Check if we have metadata with original format for perfect round-trip
            if "_metadata" in oc_data:
                metadata = oc_data["_metadata"]
                if (
                    isinstance(metadata, FlextLdifModels.QuirkMetadata)
                    and metadata.original_format
                ):
                    return FlextResult[str].ok(metadata.original_format)
                if isinstance(metadata, dict) and "original_format" in metadata:
                    return FlextResult[str].ok(str(metadata["original_format"]))

            # Build RFC 4512 objectClass definition from scratch
            parts = []

            # Start with OID (required)
            if "oid" not in oc_data:
                return FlextResult[str].fail("Missing required 'oid' field")
            parts.append(f"( {oc_data['oid']}")

            # Add NAME (required)
            if "name" in oc_data:
                parts.append(f"NAME '{oc_data['name']}'")

            # Add DESC (optional)
            if "desc" in oc_data:
                parts.append(f"DESC '{oc_data['desc']}'")

            # Add SUP (optional)
            if "sup" in oc_data:
                sup_value = oc_data["sup"]
                if isinstance(sup_value, list):
                    # Multiple superior classes: "SUP ( org $ orgUnit )"
                    sup_str = " $ ".join(sup_value)
                    parts.append(f"SUP ( {sup_str} )")
                else:
                    parts.append(f"SUP {sup_value}")

            # Add KIND (STRUCTURAL, AUXILIARY, ABSTRACT)
            if "kind" in oc_data:
                parts.append(str(oc_data["kind"]))

            # Add MUST attributes (optional) - Filter out missing/incompatible attributes
            if oc_data.get("must"):
                must_attrs = oc_data["must"]
                if isinstance(must_attrs, list):
                    # Filter out attributes that don't exist in OUD
                    filtered_must = [
                        attr
                        for attr in must_attrs
                        if attr.lower() not in self.SKIP_OBJECTCLASS_ATTRIBUTES
                    ]
                    if len(filtered_must) > 1:
                        # Multiple required attributes: "MUST ( cn $ sn )"
                        must_str = " $ ".join(filtered_must)
                        parts.append(f"MUST ( {must_str} )")
                    elif len(filtered_must) == 1:
                        parts.append(f"MUST {filtered_must[0]}")
                    # If all filtered out, don't add MUST clause
                elif str(must_attrs).lower() not in self.SKIP_OBJECTCLASS_ATTRIBUTES:
                    parts.append(f"MUST {must_attrs}")

            # Add MAY attributes (optional) - Filter out missing/incompatible attributes
            if oc_data.get("may"):
                may_attrs = oc_data["may"]
                if isinstance(may_attrs, list):
                    # Filter out attributes that don't exist in OUD
                    filtered_may = [
                        attr
                        for attr in may_attrs
                        if attr.lower() not in self.SKIP_OBJECTCLASS_ATTRIBUTES
                    ]
                    if len(filtered_may) > 1:
                        # Multiple optional attributes: "MAY ( description $ seeAlso )"
                        may_str = " $ ".join(filtered_may)
                        parts.append(f"MAY ( {may_str} )")
                    elif len(filtered_may) == 1:
                        parts.append(f"MAY {filtered_may[0]}")
                    # If all filtered out, don't add MAY clause
                    if len(may_attrs) > len(filtered_may):
                        removed = set(may_attrs) - set(filtered_may)
                        logger.debug(f"Skipped missing attributes in MAY: {removed}")
                elif str(may_attrs).lower() not in self.SKIP_OBJECTCLASS_ATTRIBUTES:
                    parts.append(f"MAY {may_attrs}")

            # Add X-ORIGIN (optional)
            if "x_origin" in oc_data:
                parts.append(f"X-ORIGIN '{oc_data['x_origin']}'")

            # Close the definition
            rfc_string = " ".join(parts) + " )"

            return FlextResult[str].ok(rfc_string)

        except Exception as e:
            return FlextResult[str].fail(f"Failed to write OID objectClass to RFC: {e}")

    def extract_schemas_from_ldif(
        self, ldif_content: str
    ) -> FlextResult[dict[str, object]]:
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
            attributes = []
            objectclasses = []

            for raw_line in ldif_content.split("\n"):
                line = raw_line.strip()

                # OID uses case-insensitive attribute names in LDIF
                # Match: attributeTypes:, attributetypes:, or any case variation
                if line.lower().startswith("attributetypes:"):
                    attr_def = line.split(":", 1)[1].strip()
                    result = self.parse_attribute(attr_def)
                    if result.is_success:
                        attributes.append(result.unwrap())

                # Match: objectClasses:, objectclasses:, or any case variation
                elif line.lower().startswith("objectclasses:"):
                    oc_def = line.split(":", 1)[1].strip()
                    result = self.parse_objectclass(oc_def)
                    if result.is_success:
                        objectclasses.append(result.unwrap())

            return FlextResult[dict[str, object]].ok({
                dk.ATTRIBUTES: attributes,
                "objectclasses": objectclasses,
            })

        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"OID schema extraction failed: {e}"
            )

    def convert_attribute_from_rfc(
        self, rfc_data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        """Convert RFC-compliant attribute to OID-specific format.

        Args:
        rfc_data: RFC-compliant attribute data

        Returns:
        FlextResult with OID attribute data

        """
        try:
            # Oracle OID uses RFC-compliant schema format
            # Just ensure OID server type is set
            oid_data = dict(rfc_data)
            oid_data[FlextLdifConstants.DictKeys.SERVER_TYPE] = (
                FlextLdifConstants.ServerTypes.OID
            )

            return FlextResult[dict[str, object]].ok(oid_data)

        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"RFC→OID attribute conversion failed: {e}"
            )

    def convert_objectclass_from_rfc(
        self, rfc_data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        """Convert RFC-compliant objectClass to OID-specific format.

        Args:
        rfc_data: RFC-compliant objectClass data

        Returns:
        FlextResult with OID objectClass data

        """
        try:
            # Oracle OID uses RFC-compliant schema format
            # Just ensure OID server type is set
            oid_data = dict(rfc_data)
            oid_data[FlextLdifConstants.DictKeys.SERVER_TYPE] = (
                FlextLdifConstants.ServerTypes.OID
            )

            return FlextResult[dict[str, object]].ok(oid_data)

        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"RFC→OID objectClass conversion failed: {e}"
            )

    class AclQuirk(FlextLdifQuirksBaseAclQuirk):
        """Oracle OID ACL quirk (nested).

        Extends RFC ACL parsing with Oracle OID-specific ACL formats:
        - orclaci: Oracle standard ACIs
        - orclentrylevelaci: Oracle entry-level ACIs

        Example:
            quirk = FlextLdifQuirksServersOid.AclQuirk(server_type="oid")
            if quirk.can_handle_acl(acl_line):
                result = quirk.parse_acl(acl_line)

        """

        server_type: str = Field(
            default=FlextLdifConstants.ServerTypes.OID,
            description="Oracle OID server type",
        )
        priority: int = Field(
            default=10, description="High priority for OID ACL parsing"
        )

        def model_post_init(self, _context: object, /) -> None:
            """Initialize OID ACL quirk."""

        def can_handle_acl(self, acl_line: str) -> bool:
            """Check if this is an Oracle OID ACL.

            Args:
            acl_line: ACL definition line

            Returns:
            True if this is orclaci or orclentrylevelaci

            """
            return acl_line.startswith(("orclaci:", "orclentrylevelaci:"))

        def parse_acl(self, acl_line: str) -> FlextResult[dict[str, object]]:
            """Parse Oracle OID ACL definition.

            Parses orclaci and orclentrylevelaci formats from real OID fixtures:
            - orclaci: access to entry/attr=(...) [filter=(...)]
            by <subject> (<perms>) [by...]
            - orclentrylevelaci: access to entry by <subject>
            [added_object_constraint=(...)] (<perms>)

            Args:
            acl_line: ACL definition line

            Returns:
            FlextResult with parsed OID ACL data with metadata

            """
            dk = FlextLdifConstants.DictKeys
            af = FlextLdifConstants.AclFormats
            try:
                # Determine ACL type
                is_entry_level = acl_line.startswith("orclentrylevelaci:")
                acl_content = (
                    acl_line.split(":", 1)[1].strip() if ":" in acl_line else acl_line
                )

                acl_data: dict[str, object] = {
                    dk.TYPE: (dk.ENTRY_LEVEL if is_entry_level else dk.STANDARD),
                    dk.RAW: acl_line,
                    dk.FORMAT: af.OID_ACL,
                }

                # Extract target (entry or attr)
                if "access to entry" in acl_content:
                    acl_data["target"] = "entry"
                elif "access to attr=" in acl_content:
                    attr_match = re.search(r"access to attr=\(([^)]+)\)", acl_content)
                    if attr_match:
                        acl_data["target"] = "attr"
                        acl_data["target_attrs"] = attr_match.group(1)

                # Extract filter (if present)
                filter_match = re.search(
                    r"filter=(\([^)]+(?:\([^)]*\))*[^)]*\))", acl_content
                )
                if filter_match:
                    acl_data["filter"] = filter_match.group(1)

                # Extract added_object_constraint (for orclentrylevelaci)
                constraint_match = re.search(
                    r"added_object_constraint=(\([^)]+(?:\([^)]*\))*[^)]*\))",
                    acl_content,
                )
                if constraint_match:
                    acl_data["added_object_constraint"] = constraint_match.group(1)

                # Extract "by" clauses with subjects and permissions
                # Pattern: by <subject> (<permissions>)
                by_clauses = []
                by_pattern = r'by\s+(group="[^"]+"|\\*|[^\\s(]+)\s+\(([^)]+)\)'
                for match in re.finditer(by_pattern, acl_content):
                    subject = match.group(1).strip()
                    permissions = match.group(2).strip()

                    by_clauses.append({
                        "subject": subject,
                        "permissions": [p.strip() for p in permissions.split(",")],
                    })

                if by_clauses:
                    acl_data["by_clauses"] = by_clauses

                # Store OID metadata - this is OID-parsed data, not converted yet
                acl_data["_metadata"] = FlextLdifModels.QuirkMetadata.create_for_quirk(
                    quirk_type="oid", original_format=af.OID_ACL
                )

                # Return OID-parsed data (NOT converted to RFC)
                # Conversion to RFC happens in convert_acl_to_rfc when needed
                return FlextResult[dict[str, object]].ok(acl_data)

            except Exception as e:
                return FlextResult[dict[str, object]].fail(
                    f"OID ACL parsing failed: {e}"
                )

        def convert_acl_to_rfc(
            self, acl_data: dict[str, object]
        ) -> FlextResult[dict[str, object]]:
            """Convert OID ACL DATA to RFC-compliant DATA (OID→RFC transformation).

            Converts OID "by_clauses" structure to RFC "permissions" + "bind_rules" structure
            that OUD quirk expects for writing aci strings.

            Args:
            acl_data: OID ACL data with by_clauses

            Returns:
            FlextResult with RFC-compliant ACL data (permissions + bind_rules)

            """
            dk = FlextLdifConstants.DictKeys
            af = FlextLdifConstants.AclFormats
            try:
                # Convert OID by_clauses to RFC permissions + bind_rules
                by_clauses = acl_data.get("by_clauses", [])
                permissions = []
                bind_rules = []

                if isinstance(by_clauses, list):
                    for by_clause in by_clauses:
                        if not isinstance(by_clause, dict):
                            continue

                        subject = by_clause.get("subject", "*")
                        perms_list = by_clause.get("permissions", [])

                        # Build permission dict
                        permissions.append({
                            "action": "allow",
                            "operations": perms_list if isinstance(perms_list, list) else [perms_list]
                        })

                        # Convert OID subject to RFC bind rule
                        if subject == "*":
                            bind_rules.append({"type": "userdn", "value": "ldap:///*"})
                        elif subject == "self":
                            bind_rules.append({"type": "userdn", "value": "ldap:///self"})
                        elif subject.startswith('group="'):
                            dn = subject.split('"')[1]
                            bind_rules.append({"type": "groupdn", "value": f"ldap:///{dn}"})
                        elif subject.startswith('dnattr='):
                            attr = subject.replace('dnattr=(', '').replace(')', '')
                            bind_rules.append({"type": "userattr", "value": f"{attr}#LDAPURL"})
                        elif subject.startswith('guidattr='):
                            attr = subject.replace('guidattr=(', '').replace(')', '')
                            bind_rules.append({"type": "userattr", "value": f"{attr}#USERDN"})
                        elif subject.startswith('groupattr='):
                            attr = subject.replace('groupattr=(', '').replace(')', '')
                            bind_rules.append({"type": "userattr", "value": f"{attr}#GROUPDN"})
                        else:
                            bind_rules.append({"type": "userdn", "value": f"ldap:///{subject}"})

                # Build RFC data structure
                rfc_data: dict[str, object] = {
                    dk.TYPE: dk.ACL,
                    dk.FORMAT: af.RFC_GENERIC,
                    dk.SOURCE_FORMAT: af.OID_ACL,
                    "permissions": permissions,
                    "bind_rules": bind_rules,
                    # Preserve target info
                    "targetattr": acl_data.get("target_attrs", "*") if acl_data.get("target") == "attr" else "*",
                    "acl_name": "Migrated from OID",
                }

                # Preserve filter if present
                if "filter" in acl_data:
                    rfc_data["targetfilter"] = acl_data["filter"]

                return FlextResult[dict[str, object]].ok(rfc_data)

            except Exception as e:
                return FlextResult[dict[str, object]].fail(
                    f"OID ACL→RFC conversion failed: {e}"
                )

        def convert_acl_from_rfc(
            self, acl_data: dict[str, object]
        ) -> FlextResult[dict[str, object]]:
            """Convert RFC ACL to OID-specific format.

            Args:
            acl_data: RFC-compliant ACL data

            Returns:
            FlextResult with OID ACL data

            """
            dk = FlextLdifConstants.DictKeys
            af = FlextLdifConstants.AclFormats
            try:
                # Convert RFC ACL to Oracle OID format
                # This is target-specific conversion for migrations
                oid_data: dict[str, object] = {
                    dk.FORMAT: af.OID_ACL,
                    dk.TARGET_FORMAT: dk.ORCLACI,
                    dk.DATA: acl_data,
                }

                return FlextResult[dict[str, object]].ok(oid_data)

            except Exception as e:
                return FlextResult[dict[str, object]].fail(
                    f"RFC→OID ACL conversion failed: {e}"
                )

        def write_acl_to_rfc(self, acl_data: dict[str, object]) -> FlextResult[str]:
            """Write OID ACL to RFC ACI format (OID→RFC transformation).

            CRITICAL: Converts OID ACL format to RFC-compliant ACI format.
            This is the OID→RFC transformation step.

            OID format:  orclaci: access to entry by * (browse)
            RFC format:  (targetattr="*")(version 3.0; acl "name"; allow (browse) userdn="ldap:///*";)

            Args:
                acl_data: Parsed OID ACL data dictionary

            Returns:
                FlextResult with RFC ACI formatted string

            Example:
                Input: {"target": "entry", "by_clauses": [{"subject": "*", "permissions": ["browse"]}]}
                Output: '(targetattr="*")(version 3.0; acl "Migrated ACL"; allow (browse) userdn="ldap:///*";)'

            """
            try:
                aci_parts = []

                # 1. Target attributes (targetattr)
                target = acl_data.get("target", "entry")
                if target == "attr" and "target_attrs" in acl_data:
                    target_attrs = acl_data["target_attrs"]
                    aci_parts.append(f'(targetattr="{target_attrs}")')
                else:
                    # "access to entry" → all attributes
                    aci_parts.append('(targetattr="*")')

                # 2. Target filter (optional)
                if "filter" in acl_data:
                    filter_value = acl_data["filter"]
                    aci_parts.append(f'(targetfilter="{filter_value}")')

                # 3. Version and ACL name
                version = "3.0"
                acl_name = "Migrated from OID"
                aci_parts.append(f'(version {version}; acl "{acl_name}";')

                # 4. Permissions from "by" clauses
                # OID: by group="cn=Admins" (read,write)
                # RFC: allow (read,write) groupdn="ldap:///cn=Admins";
                by_clauses = acl_data.get("by_clauses", [])
                if isinstance(by_clauses, list) and by_clauses:
                    for by_clause in by_clauses:
                        if not isinstance(by_clause, dict):
                            continue

                        subject = by_clause.get("subject", "*")
                        permissions_list = by_clause.get("permissions", [])

                        # Join permissions
                        if isinstance(permissions_list, list):
                            perms_str = ",".join(str(p) for p in permissions_list)
                        else:
                            perms_str = str(permissions_list)

                        # Convert OID subject to RFC bind rule
                        # "*" → userdn="ldap:///*"
                        # group="cn=X" → groupdn="ldap:///cn=X"
                        # self → userdn="ldap:///self"
                        if subject == "*":
                            bind_rule = 'userdn="ldap:///*"'
                        elif subject == "self":
                            bind_rule = 'userdn="ldap:///self"'
                        elif subject.startswith('group="'):
                            # Extract DN from group="dn"
                            dn = subject.split('"')[1]
                            bind_rule = f'groupdn="ldap:///{dn}"'
                        elif subject.startswith('dnattr='):
                            # dnattr=(attrname) → userattr="attrname#LDAPURL"
                            attr = subject.replace('dnattr=(', '').replace(')', '')
                            bind_rule = f'userattr="{attr}#LDAPURL"'
                        elif subject.startswith('guidattr='):
                            # guidattr=(attrname) → userattr="attrname#USERDN"
                            attr = subject.replace('guidattr=(', '').replace(')', '')
                            bind_rule = f'userattr="{attr}#USERDN"'
                        elif subject.startswith('groupattr='):
                            # groupattr=(attrname) → userattr="attrname#GROUPDN"
                            attr = subject.replace('groupattr=(', '').replace(')', '')
                            bind_rule = f'userattr="{attr}#GROUPDN"'
                        else:
                            # Default: treat as DN
                            bind_rule = f'userdn="ldap:///{subject}"'

                        # Build permission rule
                        aci_parts.append(f' allow ({perms_str}) {bind_rule};')
                else:
                    # No by clauses → allow all for everyone
                    aci_parts.append(' allow (all) userdn="ldap:///*";')

                # Close the ACI
                aci_parts.append(')')

                # Combine all parts
                aci_string = "".join(aci_parts)

                return FlextResult[str].ok(aci_string)

            except Exception as e:
                return FlextResult[str].fail(f"Failed to write OID ACL to RFC: {e}")

        def extract_acls_from_ldif(
            self, ldif_content: str
        ) -> FlextResult[list[dict[str, object]]]:
            """Strategy pattern: OID-specific approach to extract ACLs from LDIF entries.

            OID ACLs use:
            - orclaci: for OID standard ACLs
            - orclentrylevelaci: for entry-level ACLs

            Args:
            ldif_content: LDIF content containing ACL definitions

            Returns:
            FlextResult containing list of parsed ACL dictionaries

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

                return FlextResult[list[dict[str, object]]].ok(acls)

            except Exception as e:
                return FlextResult[list[dict[str, object]]].fail(
                    f"Failed to extract OID ACLs from LDIF: {e}"
                )

    class EntryQuirk(FlextLdifQuirksBaseEntryQuirk):
        """Oracle OID entry quirk (nested).

        Handles Oracle OID-specific entry transformations:
        - Oracle operational attributes
        - OID-specific object classes
        - Oracle namespace attributes

        Example:
            quirk = FlextLdifQuirksServersOid.EntryQuirk(server_type="oid")
            if quirk.can_handle_entry(dn, attributes):
                result = quirk.process_entry(dn, attributes)

        """

        server_type: str = Field(
            default=FlextLdifConstants.ServerTypes.OID,
            description="Oracle OID server type",
        )
        priority: int = Field(
            default=10, description="High priority for OID entry processing"
        )

        def model_post_init(self, _context: object, /) -> None:
            """Initialize OID entry quirk."""

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
            attributes: FlextLdifTypes.Models.CustomDataDict,
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
            self, entry_dn: str, attributes: FlextLdifTypes.Models.CustomDataDict
        ) -> FlextResult[dict[str, object]]:
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

                return FlextResult[dict[str, object]].ok(processed_entry)

            except Exception as e:
                return FlextResult[dict[str, object]].fail(
                    f"OID entry processing failed: {e}"
                )

        def convert_entry_to_rfc(
            self, entry_data: dict[str, object]
        ) -> FlextResult[dict[str, object]]:
            """Convert Oracle OID entry to RFC-compliant format.

            Args:
            entry_data: Oracle OID entry data

            Returns:
            FlextResult with RFC-compliant entry data

            """
            try:
                # Oracle OID entries are already RFC-compliant
                # Remove Oracle-specific operational attributes if needed
                rfc_data = dict(entry_data)

                # Optional: Remove OID-specific operational attributes
                # that don't exist in standard LDAP
                oid_operational_attrs = [
                    "orclguid",
                    "orclobjectguid",
                    "orclentrycreatetime",
                    "orclentrymodifytime",
                    "has_oid_acls",
                    "server_type",
                ]

                for attr in oid_operational_attrs:
                    rfc_data.pop(attr, None)

                return FlextResult[dict[str, object]].ok(rfc_data)

            except Exception as e:
                return FlextResult[dict[str, object]].fail(
                    f"OID entry→RFC conversion failed: {e}"
                )

        def convert_entry_from_rfc(
            self, entry_data: dict[str, object]
        ) -> FlextResult[dict[str, object]]:
            """Convert RFC-compliant entry to Oracle OID format.

            Args:
            entry_data: RFC-compliant entry data

            Returns:
            FlextResult with OID entry data

            """
            try:
                # Oracle OID uses RFC-compliant format
                # Just ensure OID server type is set
                oid_entry = dict(entry_data)
                oid_entry[FlextLdifConstants.DictKeys.SERVER_TYPE] = (
                    FlextLdifConstants.ServerTypes.OID
                )

                return FlextResult[dict[str, object]].ok(oid_entry)

            except Exception as e:
                return FlextResult[dict[str, object]].fail(
                    f"RFC→OID entry conversion failed: {e}"
                )

        def write_entry_to_ldif(
            self, entry_data: dict[str, object]
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
        ) -> FlextResult[list[dict[str, object]]]:
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

                return FlextResult[list[dict[str, object]]].ok(entries)

            except Exception as e:
                return FlextResult[list[dict[str, object]]].fail(
                    f"Failed to extract OID entries from LDIF: {e}"
                )


__all__ = [
    "FlextLdifQuirksServersOid",
]
