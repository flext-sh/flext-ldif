"""Oracle Unified Directory (OUD) Quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides OUD-specific quirks for schema, ACL, and entry processing.
"""

from __future__ import annotations

import re
from typing import ClassVar

from flext_core import FlextLogger, FlextResult

from flext_ldif import FlextLdifModels
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.base import BaseAclQuirk, BaseEntryQuirk, BaseSchemaQuirk
from flext_ldif.quirks.rfc_parsers import RfcSchemaConverter, RfcSchemaExtractor
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities

logger = FlextLogger(__name__)


class FlextLdifQuirksServersOud(BaseSchemaQuirk):
    """Oracle OUD schema quirk - implements FlextLdifProtocols.Quirks.SchemaQuirkProtocol.

    Extends RFC 4512 schema parsing with Oracle OUD-specific features:
    - OUD namespace (2.16.840.1.113894.*)
    - OUD-specific syntaxes
    - OUD attribute extensions
    - Compatibility with OID schemas
    - DN case registry management for schema consistency

    **Protocol Compliance**: Fully implements
    FlextLdifProtocols.Quirks.SchemaQuirkProtocol through structural typing.
    All methods match protocol signatures exactly for type safety.

    **Validation**: Verify protocol compliance with:
        from flext_ldif.protocols import FlextLdifProtocols
        quirk = FlextLdifQuirksServersOud()
        assert isinstance(quirk, FlextLdifProtocols.Quirks.SchemaQuirkProtocol)

    Example:
        quirk = FlextLdifQuirksServersOud(server_type="oracle_oud")
        if quirk.can_handle_attribute(attr_def):
            result = quirk.parse_attribute(attr_def)
            if result.is_success:
                parsed_attr = result.unwrap()

    """

    # Oracle OUD namespace pattern (same as OID for compatibility)
    ORACLE_OUD_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"2\.16\.840\.1\.113894\."
    )

    # OUD configuration defaults
    server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.OUD
    priority: ClassVar[int] = 10

    def __init__(
        self,
        server_type: str = FlextLdifConstants.ServerTypes.OUD,
        priority: int = 10,
    ) -> None:
        """Initialize OUD schema quirk and nested ACL quirk.

        Args:
            server_type: Oracle OUD server type
            priority: High priority for OUD-specific parsing

        """
        super().__init__(server_type=server_type, priority=priority)
        # Instantiate nested ACL quirk for conversion matrix access
        self.acl = self.AclQuirk(server_type=server_type)

    def can_handle_attribute(self, attr_definition: str) -> bool:
        """Check if this attribute can be handled (always returns True).

        NOTE: All filtering is handled by client-aOudMigConstants (BLOCKED_ATTRIBUTES).
        This method returns True for all attributes - filtering is NOT a quirk responsibility.

        Args:
            attr_definition: AttributeType definition string (unused, required by interface)

        Returns:
            True - all attributes are passed through to migration service for filtering

        """
        # Suppress unused parameter warning - required by interface
        _ = attr_definition
        # Quirks do NOT filter - return True for all attributes
        # Migration service uses client-aOudMigConstants.Schema.BLOCKED_ATTRIBUTES
        return True

    def parse_attribute(
        self, attr_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Parse Oracle OUD attribute definition.

        OUD uses RFC 4512 compliant schema format. Parses the definition
        to extract OID, NAME, DESC, SYNTAX, and other RFC 4512 attributes.

        Args:
        attr_definition: AttributeType definition string

        Returns:
        FlextResult with parsed OUD attribute data as SchemaAttribute model

        """
        try:
            # Extract OID (first element after opening parenthesis)
            oid_match = re.match(r"\(\s*([0-9.]+)", attr_definition)
            oid = oid_match.group(1) if oid_match else "unknown"

            # Extract NAME (single or multiple)
            name_match = re.search(r"NAME\s+(?:\(\s*)?'([^']+)'", attr_definition)
            name = name_match.group(1) if name_match else oid

            # Extract DESC
            desc_match = re.search(r"DESC\s+'([^']+)'", attr_definition)
            desc = desc_match.group(1) if desc_match else None

            # Extract SYNTAX and length
            syntax_match = re.search(
                r"SYNTAX\s+([0-9.]+)(?:\{(\d+)\})?", attr_definition
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

            # Check for SINGLE-VALUE
            single_value = "SINGLE-VALUE" in attr_definition

            # Extract SUP (superior attribute)
            sup_match = re.search(r"SUP\s+(\w+)", attr_definition)
            sup = sup_match.group(1) if sup_match else None

            # Extract X-ORIGIN (OUD-specific extension)
            xorigin_match = re.search(r"X-ORIGIN\s+'([^']+)'", attr_definition)
            x_origin = xorigin_match.group(1) if xorigin_match else None

            # Build quirk metadata for OUD-specific data
            quirk_data: dict[str, object] = {}
            if x_origin:
                quirk_data["x_origin"] = x_origin

            # Use helper method for consistent metadata creation
            metadata = self.create_quirk_metadata(attr_definition.strip(), quirk_data)

            # Build SchemaAttribute model directly
            attribute = FlextLdifModels.SchemaAttribute(
                oid=oid,
                name=name,
                desc=desc,
                syntax=syntax,
                length=length,
                equality=equality,
                ordering=ordering,
                substr=substr,
                single_value=single_value,
                sup=sup,
                usage=None,  # OUD doesn't extract USAGE field
                metadata=metadata,
            )

            return FlextResult[FlextLdifModels.SchemaAttribute].ok(attribute)

        except Exception as e:
            return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                f"OUD attribute parsing failed: {e}"
            )

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        """Check if this objectClass can be handled (always returns True).

        Args:
            oc_definition: ObjectClass definition string (unused, required by interface)

        Returns:
            True - all objectClasses are passed through to migration service for filtering

        """
        # Suppress unused parameter warning - required by interface
        _ = oc_definition
        return True

    def parse_objectclass(
        self, oc_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Parse Oracle OUD objectClass definition.

        OUD uses RFC 4512 compliant schema format. Parses the definition
        to extract OID, NAME, DESC, SUP, KIND, MUST, and MAY attributes.

        Args:
        oc_definition: ObjectClass definition string

        Returns:
        FlextResult with parsed OUD objectClass data as SchemaObjectClass model

        """
        try:
            # Extract OID (first element after opening parenthesis)
            oid_match = re.match(r"\(\s*([0-9.]+)", oc_definition)
            oid = oid_match.group(1) if oid_match else "unknown"

            # Extract NAME (single or multiple)
            name_match = re.search(r"NAME\s+(?:\(\s*)?'([^']+)'", oc_definition)
            name = name_match.group(1) if name_match else oid

            # Extract DESC
            desc_match = re.search(r"DESC\s+'([^']+)'", oc_definition)
            desc = desc_match.group(1) if desc_match else None

            # Extract SUP (superior objectClass)
            # Note: SchemaObjectClass.sup is str | None, so we store first superior only
            # Multiple superiors stored in metadata
            sup_match = re.search(
                r"SUP\s+(?:\(\s*([\w\s$]+)\s*\)|(\w+))", oc_definition
            )
            sup: str | None = None
            sup_list: list[str] = []
            if sup_match:
                sup_value = sup_match.group(1) or sup_match.group(2)
                sup_value = sup_value.strip()
                # Handle multiple superior classes like "organization $ organizationalUnit"
                if "$" in sup_value:
                    sup_list = [s.strip() for s in sup_value.split("$")]
                    sup = sup_list[0]  # Use first as primary
                else:
                    sup = sup_value
                    sup_list = [sup_value]

            # Determine kind (STRUCTURAL, AUXILIARY, ABSTRACT)
            # Handle AUXILLARY typo (double L) from broken OID schemas
            if FlextLdifConstants.Schema.STRUCTURAL in oc_definition:
                kind = FlextLdifConstants.Schema.STRUCTURAL
            elif (
                FlextLdifConstants.Schema.AUXILIARY in oc_definition
                or "AUXILLARY" in oc_definition
            ):
                kind = FlextLdifConstants.Schema.AUXILIARY
                if "AUXILLARY" in oc_definition:
                    logger.debug(
                        f"Fixed AUXILLARY typo in objectClass {oc_definition[:50]}"
                    )
            elif FlextLdifConstants.Schema.ABSTRACT in oc_definition:
                kind = FlextLdifConstants.Schema.ABSTRACT
            else:
                kind = FlextLdifConstants.Schema.STRUCTURAL  # Default to STRUCTURAL

            # Extract MUST attributes
            must: list[str] = []
            must_match = re.search(
                r"MUST\s+\(\s*([^)]+)\s*\)|MUST\s+(\w+)", oc_definition
            )
            if must_match:
                must_value = must_match.group(1) or must_match.group(2)
                if "$" in must_value:
                    must = [m.strip() for m in must_value.split("$")]
                else:
                    must = [must_value.strip()]

            # Extract MAY attributes
            may: list[str] = []
            may_match = re.search(r"MAY\s+\(\s*([^)]+)\s*\)|MAY\s+(\w+)", oc_definition)
            if may_match:
                may_value = may_match.group(1) or may_match.group(2)
                if "$" in may_value:
                    may = [m.strip() for m in may_value.split("$")]
                else:
                    may = [may_value.strip()]

            # Extract X-ORIGIN (OUD-specific extension)
            xorigin_match = re.search(r"X-ORIGIN\s+'([^']+)'", oc_definition)
            x_origin = xorigin_match.group(1) if xorigin_match else None

            # Build quirk metadata for OUD-specific data
            quirk_data: dict[str, object] = {"original_format": oc_definition.strip()}
            if x_origin:
                quirk_data["x_origin"] = x_origin
            if len(sup_list) > 1:
                quirk_data["all_superiors"] = sup_list  # Store all if multiple

            metadata = FlextLdifModels.QuirkMetadata(
                quirk_type="oud",
                original_format=oc_definition.strip(),
                extensions=quirk_data,
            )

            # Build SchemaObjectClass model directly
            objectclass = FlextLdifModels.SchemaObjectClass(
                oid=oid,
                name=name,
                desc=desc,
                sup=sup,
                kind=kind,
                must=must,
                may=may,
                metadata=metadata,
            )

            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(objectclass)

        except Exception as e:
            return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                f"OUD objectClass parsing failed: {e}"
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
        oc_name = str(oc_data.name) if oc_data.name else "unknown"
        oc_oid = str(oc_data.oid) if oc_data.oid else "unknown"
        missing_attrs: list[str] = []

        # PHASE 1: Check MUST attributes (required - failure if missing)
        must_attrs = oc_data.must
        if must_attrs:
            must_list: list[str] = (
                must_attrs if isinstance(must_attrs, list) else [str(must_attrs)]
            )
            for attr in must_list:
                attr_lower = str(attr).lower()
                if attr_lower not in available_attributes:
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
                attr_lower = str(attr).lower()
                if attr_lower not in available_attributes:
                    missing_attrs.append(str(attr))

        # Report validation failure if any attributes missing
        if missing_attrs:
            logger.warning(
                f"ObjectClass '{oc_name}' (OID {oc_oid}) "
                f"has unresolved attributes (MUST/MAY): {', '.join(missing_attrs)}. "
                f"This objectclass will be filtered out to prevent OUD startup failure: "
                f'"No attribute type matching this name or OID exists in the server schema"'
            )
            return FlextResult[bool].ok(False)

        # All MUST and MAY attributes are available
        return FlextResult[bool].ok(True)

    def convert_attribute_to_rfc(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Convert OUD attribute to RFC-compliant format.

        OUD attributes are already RFC-compliant, so pass through.

        Args:
        attr_data: OUD attribute data

        Returns:
        FlextResult with RFC-compliant attribute data (same model)

        """
        # OUD attributes are RFC-compliant - return as-is
        return FlextResult[FlextLdifModels.SchemaAttribute].ok(attr_data)

    def convert_objectclass_to_rfc(
        self, oc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Convert OUD objectClass to RFC-compliant format.

        OUD objectClasses are already RFC-compliant, so pass through.

        Args:
        oc_data: OUD objectClass data

        Returns:
        FlextResult with RFC-compliant objectClass data (same model)

        """
        # OUD objectClasses are RFC-compliant - return as-is
        return FlextResult[FlextLdifModels.SchemaObjectClass].ok(oc_data)

    def write_attribute_to_rfc(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[str]:
        """Write OUD attribute data to RFC 4512 compliant string format.

        Converts parsed attribute model back to RFC 4512 schema definition format.
        If metadata contains original_format, uses it for perfect round-trip.
        Fixes invalid SUBSTR matching rules for OUD compatibility.

        Args:
            attr_data: Parsed OUD attribute data as SchemaAttribute model

        Returns:
            FlextResult with RFC 4512 formatted attribute definition string

        Example:
            Input: SchemaAttribute(oid="2.16.840.1.113894.1.1.1", name="orclGUID",
                    syntax="1.3.6.1.4.1.1466.115.121.1.15")
            Output: "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX
                     1.3.6.1.4.1.1466.115.121.1.15 )"

        """
        try:
            # Fix invalid SUBSTR matching rules BEFORE processing
            # OUD rejects non-substring matching rules in SUBSTR clause
            # Create mutable copy of substr for potential correction
            substr = attr_data.substr
            if substr:
                # Invalid: equality/ordering rules used as substring rules
                invalid_substr_rules = {
                    "caseIgnoreMatch": "caseIgnoreSubstringsMatch",
                    "caseExactMatch": "caseExactSubstringsMatch",
                    "distinguishedNameMatch": None,  # DN has no substring matching
                    "integerMatch": None,  # Integer has no substring matching
                    "numericStringMatch": "numericStringSubstringsMatch",
                }
                if substr in invalid_substr_rules:
                    replacement = invalid_substr_rules[substr]
                    if replacement:
                        logger.debug(
                            f"Replacing invalid SUBSTR rule '{substr}' with '{replacement}'"
                        )
                        substr = replacement
                    else:
                        # Remove invalid SUBSTR clause entirely
                        logger.debug(
                            f"Removing invalid SUBSTR rule '{substr}' (no substring matching available)"
                        )
                        substr = None

            # Check if we have OUD metadata with original format for perfect round-trip
            # IMPORTANT: Only use metadata if it's from OUD quirk, not from source quirk
            if (
                attr_data.metadata
                and attr_data.metadata.quirk_type == "oud"
                and attr_data.metadata.original_format
            ):
                # Only use original format if it's from OUD quirk type
                return FlextResult[str].ok(attr_data.metadata.original_format)

            # Build RFC 4512 attribute definition from scratch
            parts = []

            # Start with OID (required) and add NAME (required)
            parts.extend([
                f"( {attr_data.oid}",
                f"NAME '{attr_data.name}'",
            ])

            # Add DESC (optional) - skip if None or empty
            if attr_data.desc:
                parts.append(f"DESC '{attr_data.desc}'")

            # Add SUP (optional) - skip if None or empty
            if attr_data.sup:
                parts.append(f"SUP {attr_data.sup}")

            # Add EQUALITY (optional) - skip if None or empty
            if attr_data.equality:
                parts.append(f"EQUALITY {attr_data.equality}")

            # Add ORDERING (optional) - skip if None or empty
            if attr_data.ordering:
                parts.append(f"ORDERING {attr_data.ordering}")

            # Add SUBSTR (optional) - use corrected value
            if substr:
                parts.append(f"SUBSTR {substr}")

            # Add SYNTAX (optional but common) - skip if None or empty
            # NOTE: Syntax OID replacement (deprecated syntax → valid RFC 4517) happens in OID quirks
            # during OID→RFC conversion, NOT in OUD quirks
            if attr_data.syntax:
                syntax_str = attr_data.syntax
                if attr_data.length:
                    syntax_str += f"{{{attr_data.length}}}"
                parts.append(f"SYNTAX {syntax_str}")

            # Add SINGLE-VALUE flag (optional)
            if attr_data.single_value:
                parts.append("SINGLE-VALUE")

            # Add X-ORIGIN (optional) - retrieve from metadata
            if attr_data.metadata and attr_data.metadata.extensions:
                x_origin = attr_data.metadata.extensions.get("x_origin")
                if x_origin and isinstance(x_origin, str):
                    parts.append(f"X-ORIGIN '{x_origin}'")

            # Close the definition
            rfc_string = " ".join(parts) + " )"

            return FlextResult[str].ok(rfc_string)

        except Exception as e:
            return FlextResult[str].fail(f"Failed to write attribute to RFC: {e}")

    def write_objectclass_to_rfc(
        self,
        oc_data: FlextLdifModels.SchemaObjectClass,
        _available_attributes: set[str] | None = None,
    ) -> FlextResult[str]:
        """Write OUD objectClass data to RFC 4512 compliant string format.

        Converts parsed objectClass model back to RFC 4512 schema
        definition format. If metadata contains original_format, uses it
        for perfect round-trip.

        NOTE: This method does NOT filter MUST/MAY attributes. That responsibility
        belongs to the extraction phase via validate_objectclass_dependencies.
        Invalid objectclasses are filtered out during extraction, not modified here.

        Args:
            oc_data: Parsed OUD objectClass data as SchemaObjectClass model
            _available_attributes: Ignored (accepted for interface compatibility)

        Returns:
            FlextResult with RFC 4512 formatted objectClass definition

        """
        try:
            # Check if we have OUD metadata with original format for perfect round-trip
            # IMPORTANT: Only use metadata if it's from OUD quirk, not from source quirk
            if (
                oc_data.metadata
                and oc_data.metadata.quirk_type == "oud"
                and oc_data.metadata.original_format
            ):
                # Only use original format if it's from OUD quirk type
                return FlextResult[str].ok(oc_data.metadata.original_format)

            # Build RFC 4512 objectClass definition from scratch
            parts = []

            # Start with OID (required) and add NAME (required)
            parts.extend([
                f"( {oc_data.oid}",
                f"NAME '{oc_data.name}'",
            ])

            # Add DESC (optional) - skip if None or empty
            if oc_data.desc:
                parts.append(f"DESC '{oc_data.desc}'")

            # Add KIND (STRUCTURAL, AUXILIARY, ABSTRACT) BEFORE SUP - OUD expects this order
            parts.append(oc_data.kind)

            # Add SUP (optional) - skip if None or empty
            # Check metadata for multiple superiors (stored as all_superiors)
            if oc_data.metadata and oc_data.metadata.extensions:
                all_sup = oc_data.metadata.extensions.get("all_superiors")
                if all_sup and isinstance(all_sup, list) and len(all_sup) > 1:
                    # Multiple superior classes: "SUP ( org $ orgUnit )"
                    sup_str = " $ ".join(str(s) for s in all_sup)
                    parts.append(f"SUP ( {sup_str} )")
                elif oc_data.sup:
                    parts.append(f"SUP {oc_data.sup}")
            elif oc_data.sup:
                parts.append(f"SUP {oc_data.sup}")

            # Add MUST attributes (optional)
            # Fix illegal characters in attribute names (underscores → hyphens)
            if oc_data.must:
                fixed_must_attrs = []
                for attr in oc_data.must:
                    # Replace underscores with hyphens for OUD compatibility
                    if "_" in attr:
                        fixed_attr = attr.replace("_", "-")
                        logger.debug(
                            f"Fixed illegal character in MUST attribute: '{attr}' → '{fixed_attr}'"
                        )
                        fixed_must_attrs.append(fixed_attr)
                    else:
                        fixed_must_attrs.append(attr)

                if len(fixed_must_attrs) > 1:
                    # Multiple required attributes: "MUST ( cn $ sn )"
                    must_str = " $ ".join(fixed_must_attrs)
                    parts.append(f"MUST ( {must_str} )")
                elif len(fixed_must_attrs) == 1:
                    parts.append(f"MUST {fixed_must_attrs[0]}")

            # Add MAY attributes (optional)
            # Fix illegal characters in attribute names (underscores → hyphens)
            if oc_data.may:
                fixed_may_attrs = []
                for attr in oc_data.may:
                    # Replace underscores with hyphens for OUD compatibility
                    if "_" in attr:
                        fixed_attr = attr.replace("_", "-")
                        logger.debug(
                            f"Fixed illegal character in MAY attribute: '{attr}' → '{fixed_attr}'"
                        )
                        fixed_may_attrs.append(fixed_attr)
                    else:
                        fixed_may_attrs.append(attr)

                if len(fixed_may_attrs) > 1:
                    # Multiple optional attributes: "MAY ( description $ seeAlso )"
                    may_str = " $ ".join(fixed_may_attrs)
                    parts.append(f"MAY ( {may_str} )")
                elif len(fixed_may_attrs) == 1:
                    parts.append(f"MAY {fixed_may_attrs[0]}")

            # Add X-ORIGIN (optional) - retrieve from metadata
            if oc_data.metadata and oc_data.metadata.extensions:
                x_origin = oc_data.metadata.extensions.get("x_origin")
                if x_origin and isinstance(x_origin, str):
                    parts.append(f"X-ORIGIN '{x_origin}'")

            # Close the definition
            rfc_string = " ".join(parts) + " )"

            return FlextResult[str].ok(rfc_string)

        except Exception as e:
            return FlextResult[str].fail(f"Failed to write objectClass to RFC: {e}")

    def convert_attribute_from_rfc(
        self, rfc_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Convert RFC-compliant attribute to OUD-specific format.

        Args:
        rfc_data: RFC-compliant attribute data

        Returns:
        FlextResult with OUD attribute data

        """
        try:
            # Oracle OUD uses RFC-compliant schema format
            # Set OUD server type in metadata
            if rfc_data.metadata:
                # Update existing metadata
                oud_data = rfc_data.model_copy(
                    update={
                        "metadata": rfc_data.metadata.model_copy(
                            update={"server_type": FlextLdifConstants.ServerTypes.OUD}
                        )
                    }
                )
            else:
                # Create new metadata with OUD server type
                oud_data = rfc_data.model_copy(
                    update={
                        "metadata": FlextLdifModels.QuirkMetadata(
                            quirk_type=FlextLdifConstants.ServerTypes.OUD
                        )
                    }
                )

            return FlextResult[FlextLdifModels.SchemaAttribute].ok(oud_data)

        except Exception as e:
            return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                f"RFC→OUD attribute conversion failed: {e}"
            )

    def convert_objectclass_from_rfc(
        self, rfc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Convert RFC-compliant objectClass to OUD-specific format.

        Applies OUD-specific transformations:
        - Fixes broken OID schema definitions (missing SUP for AUXILIARY classes)
        - OUD requires AUXILIARY classes to have explicit SUP clause

        Args:
        rfc_data: RFC-compliant objectClass model

        Returns:
        FlextResult with OUD objectClass model

        """
        try:
            # Check if we need to fix missing SUP for AUXILIARY objectClasses
            # OUD requires AUXILIARY classes to have explicit SUP clause
            if (
                not rfc_data.sup
                and rfc_data.kind == FlextLdifConstants.Schema.AUXILIARY
            ):
                name_lower = rfc_data.name.lower()
                auxiliary_without_sup = {
                    "orcldAsAttrCategory".lower(),
                    "orcldasconfigpublicgroup",
                }

                if name_lower in auxiliary_without_sup:
                    # Create new model with sup="top"
                    oud_data = rfc_data.model_copy(update={"sup": "top"})
                    logger.debug(
                        f"Fixed missing SUP for AUXILIARY class {rfc_data.name}"
                    )
                    return FlextResult[FlextLdifModels.SchemaObjectClass].ok(oud_data)

            # No modifications needed - return as-is
            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(rfc_data)

        except Exception as e:
            return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                f"RFC→OUD objectClass conversion failed: {e}"
            )

    def extract_schemas_from_ldif(
        self, ldif_content: str
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

            # PHASE 1: Extract all attributeTypes first using shared extractor
            attributes_parsed = RfcSchemaExtractor.extract_attributes_from_lines(
                ldif_content, self.parse_attribute
            )

            # Build set of available attribute names (lowercase) for dependency validation
            available_attributes: set[str] = set()
            for attr_data in attributes_parsed:
                if isinstance(attr_data, FlextLdifModels.SchemaAttribute) and hasattr(
                    attr_data, "name"
                ):
                    attr_name = str(attr_data.name).lower()
                    available_attributes.add(attr_name)

            # PHASE 2: Extract objectClasses with dependency validation using shared extractor
            # Must happen AFTER all attributes are collected
            objectclasses_raw_data = (
                RfcSchemaExtractor.extract_objectclasses_from_lines(
                    ldif_content, self.parse_objectclass
                )
            )

            # PHASE 3: Pass all objectClasses through to migration service
            objectclasses_parsed.extend(objectclasses_raw_data)

            return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok({
                FlextLdifConstants.DictKeys.ATTRIBUTES: attributes_parsed,
                "objectclasses": objectclasses_parsed,
            })

        except Exception as e:
            return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                f"OUD schema extraction failed: {e}"
            )

    class AclQuirk(BaseAclQuirk):
        """Oracle OUD ACL quirk (nested).

        Extends RFC ACL parsing with Oracle OUD-specific ACL formats:
        - ds-cfg-access-control-handler: OUD access control
        - OUD-specific ACL syntax (different from OID orclaci)

        Example:
            quirk = FlextLdifQuirksServersOud.AclQuirk(server_type="oracle_oud")
            if quirk.can_handle_acl(acl_line):
                result = quirk.parse_acl(acl_line)

        """

        # Oracle OUD uses RFC 4876 compliant "aci" for ACL attribute names
        acl_attribute_name = "aci"

        # Oracle OUD server configuration defaults
        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.OUD
        priority: ClassVar[int] = 10

        def can_handle_acl(self, acl_line: str) -> bool:
            """Check if this is an Oracle OUD ACL.

            Args:
            acl_line: ACL definition line

            Returns:
            True if this is OUD ACL format

            """
            # OUD uses different ACL format than OID
            return acl_line.startswith(("ds-cfg-", "aci:"))

        def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse Oracle OUD ACL definition to Pydantic model.

            Parses ACI (Access Control Instruction) format used by OUD, extracting:
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
                # Initialize parsed values
                acl_name = "OUD ACL"
                targetattr = "*"
                targetscope = None
                version = "3.0"
                permissions_list: list[str] = []
                bind_rules_data: list[dict[str, str]] = []
                line_breaks: list[int] = []
                dn_spaces = False

                # Detect line breaks for multi-line ACIs
                if "\n" in acl_line:
                    current_pos = 0
                    for line_num, line in enumerate(acl_line.split("\n")):
                        if line_num > 0:  # Skip first line
                            line_breaks.append(current_pos)
                        current_pos += len(line) + 1  # +1 for newline

                # Parse ACI components if it's ACI format
                if acl_line.startswith("aci:"):
                    aci_content = acl_line.split(":", 1)[1].strip()

                    # Extract targetattr
                    targetattr_match = re.search(
                        r'\(targetattr\s*(!?=)\s*"([^"]+)"\)', aci_content
                    )
                    if targetattr_match:
                        targetattr = targetattr_match.group(2)

                    # Extract targetscope
                    targetscope_match = re.search(
                        r'\(targetscope\s*=\s*"([^"]+)"\)', aci_content
                    )
                    if targetscope_match:
                        targetscope = targetscope_match.group(1)

                    # Extract version and ACL name
                    version_match = re.search(
                        r'version\s+([\d.]+);\s*acl\s+"([^"]+)"', aci_content
                    )
                    if version_match:
                        version = version_match.group(1)
                        acl_name = version_match.group(2)

                    # Extract permissions (allow/deny with operations)
                    permission_matches = re.findall(
                        r"(allow|deny)\s+\(([^)]+)\)", aci_content
                    )
                    for action, ops in permission_matches:
                        if action == "allow":  # Only process allow rules
                            ops_list = [
                                op.strip() for op in ops.split(",") if op.strip()
                            ]
                            permissions_list.extend(ops_list)

                    # Extract userdn rules
                    userdn_matches = re.findall(r'userdn\s*=\s*"([^"]+)"', aci_content)
                    for userdn in userdn_matches:
                        bind_rules_data.append({"type": "userdn", "value": userdn})
                        if ", " in userdn:
                            dn_spaces = True

                    # Extract groupdn rules
                    groupdn_matches = re.findall(
                        r'groupdn\s*=\s*"([^"]+)"', aci_content
                    )
                    for groupdn in groupdn_matches:
                        bind_rules_data.append({"type": "groupdn", "value": groupdn})
                        if ", " in groupdn:
                            dn_spaces = True

                # Build AclPermissions from parsed permissions
                permissions_data: dict[str, bool] = {
                    "read": False,
                    "write": False,
                    "add": False,
                    "delete": False,
                    "search": False,
                    "compare": False,
                    "self_write": False,
                    "proxy": False,
                }

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
                    elif perm_lower in {"selfwrite", "self_write"}:
                        permissions_data["self_write"] = True
                    elif perm_lower == "proxy":
                        permissions_data["proxy"] = True
                    elif perm_lower == "all":
                        # Enable all permissions
                        for key in permissions_data:
                            permissions_data[key] = True

                # Build AclSubject from first bind rule (OUD can have multiple, take first)
                subject_type = "anonymous"
                subject_value = "*"

                if bind_rules_data:
                    first_rule = bind_rules_data[0]
                    rule_type = first_rule["type"]
                    rule_value = first_rule["value"]

                    if rule_type == "userdn":
                        if rule_value == "ldap:///self":
                            subject_type = "self"
                            subject_value = "ldap:///self"
                        elif rule_value in {"ldap:///*", "ldap:///anyone"}:
                            subject_type = "anonymous"
                            subject_value = "*"
                        else:
                            subject_type = "bind_rules"
                            subject_value = f'userdn="{rule_value}"'
                    elif rule_type == "groupdn":
                        subject_type = "group"
                        subject_value = rule_value

                # Build QuirkMetadata with extensions
                extensions: dict[str, object] = {}
                if line_breaks:
                    extensions["line_breaks"] = line_breaks
                    extensions["is_multiline"] = True
                if dn_spaces:
                    extensions["dn_spaces"] = True
                if targetscope:
                    extensions["targetscope"] = targetscope
                if version != "3.0":
                    extensions["version"] = version

                # Create Acl model (no metadata field in unified Acl model)
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
                    server_type=FlextLdifUtilities.normalize_server_type_for_literal(
                        self.server_type
                    ),
                    raw_acl=acl_line,
                )

                return FlextResult[FlextLdifModels.Acl].ok(acl)

            except Exception as e:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"OUD ACL parsing failed: {e}"
                )

        def convert_acl_to_rfc(
            self, acl_data: FlextLdifModels.Acl
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Convert OUD ACL to RFC-compliant format.

            CRITICAL FIX: Extract permissions and bind_rules to top level for OID conversion.

            Args:
            acl_data: OUD ACL data with permissions and bind_rules

            Returns:
            FlextResult with RFC-compliant ACL data

            """
            try:
                # OUD ACLs ARE RFC-compliant (OUD uses standard LDAP ACI format)
                # For OUD, just return the acl_data as-is (already RFC-compliant)
                return FlextResult[FlextLdifModels.Acl].ok(acl_data)

            except Exception as e:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"OUD ACL→RFC conversion failed: {e}"
                )

        def _convert_constraint_to_targattrfilters(self, oid_constraint: str) -> str:
            """Convert OID added_object_constraint to OUD targattrfilters format.

            OID format: added_object_constraint=(objectClass=person)
            OUD format: targattrfilters="add=objectClass:(objectClass=person)"

            Args:
                oid_constraint: OID constraint string

            Returns:
                OUD targattrfilters string

            """
            # Remove outer parentheses if present
            constraint = oid_constraint.strip()
            if constraint.startswith("(") and constraint.endswith(")"):
                constraint = constraint[1:-1]

            # OUD targattrfilters format requires operation prefix
            # add= for added entries, del= for deleted entries
            return f"add=objectClass:({constraint})"

        def convert_acl_from_rfc(
            self, acl_data: FlextLdifModels.Acl
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Convert RFC ACL to OUD format with targattrfilters and proxy handling.

            Args:
                acl_data: RFC-compliant Acl model

            Returns:
                FlextResult with OUD Acl model

            """
            try:
                # OUD ACLs are RFC-compliant, just return as-is
                return FlextResult[FlextLdifModels.Acl].ok(acl_data)

            except Exception as e:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"RFC→OUD ACL conversion failed: {e}"
                )

        def write_acl_to_rfc(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write OUD ACL model to ACI string format.

            Converts ACL Pydantic model to RFC-compliant ACI format string.
            OUD ACLs are RFC-compliant, so this builds standard ACI syntax.

            Args:
                acl_data: ACL Pydantic model

            Returns:
                FlextResult with ACI formatted string

            Example:
                Input: FlextLdifModels.Acl(name="Test", ...)
                Output: '(targetattr="*")(version 3.0; acl "Test"; allow (read) userdn="ldap:///self";)'

            """
            try:
                # If raw_acl is available, use it for perfect round-trip
                if acl_data.raw_acl and acl_data.raw_acl.startswith("aci:"):
                    return FlextResult[str].ok(acl_data.raw_acl)

                # Build ACI from model fields
                aci_parts = []

                # Target attributes
                if acl_data.target and acl_data.target.target_dn:
                    target = acl_data.target.target_dn
                else:
                    target = "*"
                aci_parts.append(f'(targetattr="{target}")')

                # Version and ACL name
                acl_name = acl_data.name or "OUD ACL"
                aci_parts.append(f'(version 3.0; acl "{acl_name}";')

                # Permissions (from model's permissions computed field)
                # OUD supports: read, write, add, delete, search, compare
                # OUD does NOT support: self_write, proxy (OID-specific)
                if acl_data.permissions:
                    ops_property = acl_data.permissions.permissions
                    # ops_property is a property, call it to get list[str]
                    ops: list[str] = (
                        ops_property() if callable(ops_property) else ops_property
                    )
                    # Filter to only OUD-supported rights
                    oud_supported_rights = {
                        "read",
                        "write",
                        "add",
                        "delete",
                        "search",
                        "compare",
                    }
                    filtered_ops = [op for op in ops if op in oud_supported_rights]

                    # Use metadata bridge: check if self_write needs to be promoted to write
                    # This allows OUD to properly convert OID→OUD without knowing OID format details
                    if (
                        acl_data.metadata
                        and acl_data.metadata.get("self_write_to_write")
                        and "self_write" in ops
                        and "write" not in filtered_ops
                    ):
                        # self_write was present in OID ACL - promote to write for OUD
                        filtered_ops.append("write")

                    if filtered_ops:
                        ops_str = ",".join(filtered_ops)
                        aci_parts.append(f"allow ({ops_str})")
                    else:
                        return FlextResult[str].fail(
                            "ACL model has no OUD-supported permissions (all were OID-specific like self_write)"
                        )
                else:
                    return FlextResult[str].fail("ACL model has no permissions object")

                # Bind rules (from model's subject field)
                if acl_data.subject:
                    subject_type = acl_data.subject.subject_type
                    subject_value = acl_data.subject.subject_value

                    # Convert to RFC format
                    if subject_type == "self":
                        aci_parts.append('userdn="ldap:///self";)')
                    elif subject_type == "anonymous":
                        aci_parts.append('userdn="ldap:///*";)')
                    elif subject_type == "group":
                        # Ensure LDAP URL format
                        if not subject_value.startswith("ldap:///"):
                            subject_value = f"ldap:///{subject_value}"
                        aci_parts.append(f'groupdn="{subject_value}";)')
                    elif subject_type == "bind_rules":
                        # Already in proper format (e.g., userattr="manager#LDAPURL")
                        aci_parts.append(f"{subject_value};)")
                    else:
                        # Default: treat as userdn
                        if not subject_value.startswith("ldap:///"):
                            subject_value = f"ldap:///{subject_value}"
                        aci_parts.append(f'userdn="{subject_value}";)')
                else:
                    # Default: allow for self
                    aci_parts.append('userdn="ldap:///self";)')

                aci_string = "aci: " + " ".join(aci_parts)
                return FlextResult[str].ok(aci_string)

            except Exception as e:
                return FlextResult[str].fail(f"Failed to write ACL to RFC: {e}")

        def extract_acls_from_ldif(
            self, ldif_content: str
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

                    # Detect ACI start (case-insensitive)
                    if stripped.lower().startswith("aci:"):
                        if current_aci:
                            # Parse accumulated multiline ACI
                            aci_text = "\n".join(current_aci)
                            result = self.parse_acl(aci_text)
                            if result.is_success:
                                acls.append(result.unwrap())
                            current_aci = []

                        current_aci.append(stripped)
                        # Check if this ACI continues on next lines
                        # (no closing parenthesis)
                        in_multiline_aci = not stripped.rstrip().endswith(")")

                    elif in_multiline_aci and stripped:
                        # Continuation of multiline ACI
                        current_aci.append(stripped)
                        if stripped.rstrip().endswith(")"):
                            in_multiline_aci = False

                    # Also handle ds-cfg format
                    elif stripped.lower().startswith("ds-cfg-"):
                        result = self.parse_acl(stripped)
                        if result.is_success:
                            acls.append(result.unwrap())

                # Parse any remaining ACI
                if current_aci:
                    aci_text = "\n".join(current_aci)
                    result = self.parse_acl(aci_text)
                    if result.is_success:
                        acls.append(result.unwrap())

                return FlextResult[list[FlextLdifModels.Acl]].ok(acls)

            except Exception as e:
                return FlextResult[list[FlextLdifModels.Acl]].fail(
                    f"OUD ACL extraction failed: {e}"
                )

    class EntryQuirk(BaseEntryQuirk):
        """Oracle OUD entry quirk (nested).

        Handles OUD-specific entry transformations:
        - OUD-specific operational attributes
        - OUD entry formatting
        - Compatibility with OID entries

        Example:
            quirk = FlextLdifQuirksServersOud.EntryQuirk(server_type="oracle_oud")
            if quirk.can_handle_entry(dn, attributes):
                result = quirk.process_entry(dn, attributes)

        """

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.OUD
        priority: ClassVar[int] = 10

        def __init__(
            self,
            server_type: str = FlextLdifConstants.ServerTypes.OUD,
            priority: int = 10,
        ) -> None:
            """Initialize OUD entry quirk.

            Args:
                server_type: Oracle OUD server type
                priority: High priority for OUD entry processing

            """
            super().__init__(server_type=server_type, priority=priority)

        def can_handle_entry(
            self, entry_dn: str, attributes: FlextLdifTypes.Models.EntryAttributesDict
        ) -> bool:
            """Check if this quirk should handle the entry.

            Args:
            entry_dn: Entry distinguished name
            attributes: Entry attributes

            Returns:
            True if this is an OUD-specific entry

            """
            # Handle all entries for OUD target
            # Can add specific OUD entry detection logic here
            _ = entry_dn
            _ = attributes
            return True

        # Oracle OUD boolean attributes that expect TRUE/FALSE instead of 0/1
        # This IS format-specific - OUD requires TRUE/FALSE, not 0/1
        BOOLEAN_ATTRIBUTES: ClassVar[set[str]] = {
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
        }

        # Attribute name casing map: lowercase source → proper OUD camelCase
        # Maps common LDAP attributes with incorrect casing to OUD-expected camelCase
        ATTRIBUTE_CASE_MAP: ClassVar[dict[str, str]] = {
            "uniquemember": "uniqueMember",
            "displayname": "displayName",
            "distinguishedname": "distinguishedName",
            "objectclass": "objectClass",
            "memberof": "memberOf",
            "seealsodescription": "seeAlsoDescription",
            "orclaci": "aci",
            "orclentrylevelaci": "aci",
            "acl": "aci",
        }

        def process_entry(
            self, entry_dn: str, attributes: FlextLdifTypes.Models.EntryAttributesDict
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Process entry for OUD format with metadata preservation.

            Handles OUD-specific FORMAT transformations:
            - Boolean attributes: Convert 0/1 to TRUE/FALSE (OUD format requirement)

            NOTE: Attribute/objectClass FILTERING is business logic, NOT format handling.
            Use FlextLdifFilters in migration service for filtering.

            Args:
            entry_dn: Entry distinguished name
            attributes: Entry attributes

            Returns:
            FlextResult with processed entry data including metadata

            """
            try:
                # OUD entries are RFC-compliant
                # Add OUD-specific FORMAT processing for boolean attributes
                processed_entry: dict[str, object] = {
                    FlextLdifConstants.DictKeys.DN: entry_dn,
                    FlextLdifConstants.DictKeys.SERVER_TYPE: "oud",
                }

                # Preserve base64 encoding metadata from entry extraction
                if "_base64_attrs" in attributes:
                    processed_entry["_base64_attrs"] = attributes["_base64_attrs"]

                # Preserve special LDIF modify markers for schema entries
                if "_modify_add_attributetypes" in attributes:
                    processed_entry["_modify_add_attributetypes"] = attributes[
                        "_modify_add_attributetypes"
                    ]
                if "_modify_add_objectclasses" in attributes:
                    processed_entry["_modify_add_objectclasses"] = attributes[
                        "_modify_add_objectclasses"
                    ]

                # NOTE: ACL transformation is handled by the pipeline using quirks system
                # (OID → RFC → OUD conversion). Quirks only perform FORMAT transformations.
                #
                # LDAP SCHEMA RULE: Only ONE STRUCTURAL objectClass per entry is allowed.
                # If multiple STRUCTURAL classes exist, OUD will reject the entry during sync.
                # This is NOT a quirk responsibility - let OUD server enforce its schema rules.

                # PHASE 0: Normalize attribute names to proper camelCase
                # Maps lowercase LDAP attribute names to OUD-expected camelCase
                normalized_attributes: dict[str, object] = {}
                for attr_name, attr_values in attributes.items():
                    # Check if this attribute needs case normalization
                    attr_lower = attr_name.lower()
                    normalized_name = self.ATTRIBUTE_CASE_MAP.get(attr_lower, attr_name)
                    normalized_attributes[normalized_name] = attr_values

                # Process attributes with boolean conversion (FORMAT transformation)
                for attr_name, attr_values in normalized_attributes.items():
                    # Skip internal metadata attributes (except LDIF modify markers, already handled above)
                    if attr_name.startswith("_"):
                        continue

                    # Check if this is a boolean attribute that needs FORMAT conversion
                    if attr_name.lower() in self.BOOLEAN_ATTRIBUTES:
                        # Convert 0/1 to TRUE/FALSE for OUD
                        if isinstance(attr_values, list):
                            converted_values = []
                            for val in attr_values:
                                str_val = str(val).strip()
                                if str_val == "0":
                                    converted_values.append("FALSE")
                                elif str_val == "1":
                                    converted_values.append("TRUE")
                                else:
                                    # Already TRUE/FALSE or other value
                                    converted_values.append(val)
                            processed_entry[attr_name] = converted_values
                        else:
                            # Single value
                            str_val = str(attr_values).strip()
                            if str_val == "0":
                                processed_entry[attr_name] = "FALSE"
                            elif str_val == "1":
                                processed_entry[attr_name] = "TRUE"
                            else:
                                processed_entry[attr_name] = attr_values
                    elif attr_name.lower() == "telephonenumber":
                        # Validate telephone numbers - must contain at least one digit
                        # Filter out invalid values like "N/A", "n/a", empty strings, etc.
                        if isinstance(attr_values, list):
                            valid_numbers = []
                            for val in attr_values:
                                str_val = str(val).strip()
                                # Check if value contains at least one numeric digit
                                if any(c.isdigit() for c in str_val):
                                    valid_numbers.append(val)
                            # Only add attribute if we have valid numbers
                            if valid_numbers:
                                processed_entry[attr_name] = valid_numbers
                        else:
                            # Single value
                            str_val = str(attr_values).strip()
                            # Only add if contains at least one digit
                            if any(c.isdigit() for c in str_val):
                                processed_entry[attr_name] = attr_values
                            # Skip invalid telephone numbers (no else - don't add attribute)
                    else:
                        # Non-boolean attribute, copy as-is
                        processed_entry[attr_name] = attr_values

                # Preserve metadata for DN quirks and attribute ordering
                metadata_extensions: dict[str, object] = {}

                # Detect DN spaces quirk (spaces after commas)
                if ", " in entry_dn:
                    metadata_extensions["dn_spaces"] = True

                # Preserve attribute ordering (using normalized names)
                if normalized_attributes:
                    attr_order: list[str] = list(normalized_attributes.keys())
                    metadata_extensions["attribute_order"] = attr_order

                # Detect Oracle-specific objectClasses (use normalized attributes)
                if FlextLdifConstants.DictKeys.OBJECTCLASS in normalized_attributes:
                    oc_values = normalized_attributes[FlextLdifConstants.DictKeys.OBJECTCLASS]
                    if isinstance(oc_values, list):
                        oracle_ocs: list[str] = [
                            str(oc)
                            for oc in oc_values
                            if any(
                                prefix in str(oc).lower()
                                for prefix in ["orcl", "oracle"]
                            )
                        ]
                        if oracle_ocs:
                            metadata_extensions["oracle_objectclasses"] = oracle_ocs

                processed_entry["_metadata"] = (
                    FlextLdifModels.QuirkMetadata.create_for_quirk(
                        quirk_type="oud", extensions=metadata_extensions
                    )
                )

                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    processed_entry
                )

            except Exception as e:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"OUD entry processing failed: {e}"
                )

        def convert_entry_to_rfc(
            self, entry_data: dict[str, object]
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Convert server-specific entry to RFC-compliant format.

            Args:
            entry_data: Server-specific entry data

            Returns:
            FlextResult with RFC-compliant entry data

            """
            try:
                # OUD entries are already RFC-compliant
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    entry_data
                )
            except Exception as e:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"OUD entry→RFC conversion failed: {e}"
                )

        def convert_entry_from_rfc(
            self, entry_data: dict[str, object]
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Convert RFC-compliant entry to OUD-specific format.

            Args:
            entry_data: RFC-compliant entry data

            Returns:
            FlextResult with OUD entry data

            """
            # Oracle OUD uses RFC-compliant format
            # Just ensure OUD server type is set via shared converter
            return RfcSchemaConverter.set_server_type(
                entry_data, FlextLdifConstants.ServerTypes.OUD
            )

        def write_entry_to_ldif(
            self, entry_data: dict[str, object]
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
                        "Missing required FlextLdifConstants.DictKeys.DN field"
                    )

                dn = entry_data[FlextLdifConstants.DictKeys.DN]
                ldif_lines = [f"dn: {dn}"]

                # Check if this is a schema modification entry (changetype: modify)
                is_modify = False
                changetype_list = entry_data.get("changetype", [])
                if isinstance(changetype_list, list) and "modify" in changetype_list:
                    is_modify = True
                    ldif_lines.append("changetype: modify")

                # Handle LDIF modify format for schema additions
                # NOTE: Schema definitions MUST be already transformed to OUD format by pipeline
                # via RFC canonical format (OID quirk → RFC → OUD quirk)
                if is_modify and (
                    "_modify_add_attributetypes" in entry_data
                    or "_modify_add_objectclasses" in entry_data
                ):
                    # Write modify-add operations for attributetypes
                    if "_modify_add_attributetypes" in entry_data:
                        attr_types = entry_data["_modify_add_attributetypes"]
                        if isinstance(attr_types, list) and attr_types:
                            ldif_lines.append("add: attributetypes")
                            ldif_lines.extend(
                                f"attributetypes: {attr_type}"
                                for attr_type in attr_types
                            )
                            ldif_lines.append("-")

                    # Write modify-add operations for objectclasses
                    if "_modify_add_objectclasses" in entry_data:
                        obj_classes = entry_data["_modify_add_objectclasses"]
                        if isinstance(obj_classes, list) and obj_classes:
                            ldif_lines.append("add: objectclasses")
                            ldif_lines.extend(
                                f"objectclasses: {obj_class}"
                                for obj_class in obj_classes
                            )
                            ldif_lines.append("-")
                else:
                    # Standard entry format (not a modify operation)
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
                    # Type narrowing: ensure attr_order is list before iteration
                    if attr_order is not None and isinstance(attr_order, list):
                        # Use preserved ordering
                        attrs_to_process = [
                            (key, entry_data[key])
                            for key in attr_order
                            if key in entry_data
                            and key
                            not in {
                                FlextLdifConstants.DictKeys.DN,
                                "_metadata",
                                FlextLdifConstants.DictKeys.SERVER_TYPE,
                            }
                        ]
                    else:
                        # Default ordering: filter out special keys
                        attrs_to_process = [
                            (key, value)
                            for key, value in entry_data.items()
                            if key
                            not in {
                                FlextLdifConstants.DictKeys.DN,
                                "_metadata",
                                FlextLdifConstants.DictKeys.SERVER_TYPE,
                                "changetype",
                            }
                        ]

                    # Extract base64 attributes metadata
                    base64_attrs = set()
                    if "_base64_attrs" in entry_data:
                        base64_data = entry_data["_base64_attrs"]
                        if isinstance(base64_data, set):
                            base64_attrs = base64_data
                        elif isinstance(base64_data, list):
                            base64_attrs = set(base64_data)

                    # Write attributes
                    # SAFETY: Filter out DN if it somehow appears in attributes
                    for attr_name, attr_value in attrs_to_process:
                        # Critical: DN is NOT an attribute - skip if present
                        if attr_name.lower() == FlextLdifConstants.DictKeys.DN:
                            continue
                        # Skip internal metadata attributes
                        if attr_name.startswith("_"):
                            continue
                        # Apply attribute name mapping (e.g., orclaci → aci, uniquemember → uniqueMember)
                        mapped_attr_name = self.ATTRIBUTE_CASE_MAP.get(attr_name.lower(), attr_name)
                        # Check if this attribute should be base64-encoded
                        is_base64 = attr_name in base64_attrs
                        attr_prefix = f"{mapped_attr_name}::" if is_base64 else f"{mapped_attr_name}:"

                        # Handle both list and single values
                        if isinstance(attr_value, list):
                            ldif_lines.extend(
                                f"{attr_prefix} {value}" for value in attr_value
                            )
                        else:
                            ldif_lines.append(f"{attr_prefix} {attr_value}")

                # Join with newlines and add trailing newline
                ldif_string = "\n".join(ldif_lines) + "\n"

                return FlextResult[str].ok(ldif_string)

            except Exception as e:
                return FlextResult[str].fail(f"Failed to write entry to LDIF: {e}")

        def extract_entries_from_ldif(
            self, ldif_content: str
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
                            # Save any pending attribute
                            if current_attr and current_values:
                                if len(current_values) == 1:
                                    current_entry[current_attr] = current_values[0]
                                else:
                                    current_entry[current_attr] = current_values
                                current_attr = None
                                current_values = []

                            # Process complete entry
                            if FlextLdifConstants.DictKeys.DN in current_entry:
                                dn = str(
                                    current_entry.pop(FlextLdifConstants.DictKeys.DN)
                                )
                                result = self.process_entry(dn, current_entry)
                                if result.is_success:
                                    entries.append(result.unwrap())

                            current_entry = {}
                        continue

                    # Skip comments
                    if line.startswith("#"):
                        continue

                    # Continuation line (starts with space)
                    if line.startswith(" ") and current_attr:
                        # Append to current attribute value
                        if current_values:
                            current_values[-1] += line[1:]  # Remove leading space
                        continue

                    # New attribute line
                    if ":" in line:
                        # Save previous attribute
                        if current_attr and current_values:
                            if len(current_values) == 1:
                                current_entry[current_attr] = current_values[0]
                            else:
                                current_entry[current_attr] = current_values

                        # Parse new attribute
                        attr_name, attr_value = line.split(":", 1)
                        attr_name = attr_name.strip()
                        attr_value = attr_value.strip()

                        # Handle base64 encoding (::) - PRESERVE for writing
                        if attr_value.startswith(":"):
                            attr_value = attr_value[1:].strip()
                            # Mark this attribute as base64-encoded in metadata
                            # We'll store this in _base64_attrs for write_entry_to_ldif
                            if "_base64_attrs" not in current_entry:
                                current_entry["_base64_attrs"] = set()
                            if isinstance(current_entry["_base64_attrs"], set):
                                current_entry["_base64_attrs"].add(attr_name)

                        # Check if this attribute already exists (multi-valued)
                        if attr_name in current_entry and attr_name != "_base64_attrs":
                            # Convert to list if needed
                            existing = current_entry[attr_name]
                            if not isinstance(existing, list):
                                current_entry[attr_name] = [existing, attr_value]
                            else:
                                existing.append(attr_value)
                            current_attr = None
                            current_values = []
                        else:
                            current_attr = attr_name
                            current_values = [attr_value]

                # Process final entry
                if current_entry:
                    if current_attr and current_values:
                        if len(current_values) == 1:
                            current_entry[current_attr] = current_values[0]
                        else:
                            current_entry[current_attr] = current_values

                    if FlextLdifConstants.DictKeys.DN in current_entry:
                        dn = str(current_entry.pop(FlextLdifConstants.DictKeys.DN))
                        result = self.process_entry(dn, current_entry)
                        if result.is_success:
                            entries.append(result.unwrap())

                return FlextResult[list[dict[str, object]]].ok(entries)

            except Exception as e:
                return FlextResult[list[dict[str, object]]].fail(
                    f"OUD entry extraction failed: {e}"
                )


__all__ = ["FlextLdifQuirksServersOud"]
