"""LDIF Metadata Utilities - Helpers for Validation Metadata Management.

Provides helper methods for preserving, extracting, and tracking validation metadata
during LDIF conversions between different LDAP servers (OID, OUD, OpenLDAP, etc.).

FASE 3: Services Integration with Metadata
- preserve_validation_metadata(): Copy metadata from source to target with transformations
- extract_rfc_violations(): Extract all RFC violations from model metadata
- track_conversion_step(): Add conversion step to transformation history

PHASE 2: Zero Data Loss Tracking
- track_transformation(): Populate AttributeTransformation in QuirkMetadata
- preserve_original_format(): Store original formatting for round-trip
- track_boolean_conversion(): Track boolean conversions (0/1 vs TRUE/FALSE)
- validate_metadata_completeness(): Check all transformations are tracked
- assert_no_data_loss(): Validation helper for testing round-trips

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Protocol, TypeVar

from flext_core import FlextLogger

if TYPE_CHECKING:
    from flext_ldif._models.domain import FlextLdifModelsDomains

logger = FlextLogger(__name__)

# Constants for content preview limits
_CONTENT_PREVIEW_LENGTH = 100
_MINIMAL_DIFF_PREVIEW_LENGTH = 50


class ModelWithValidationMetadata(Protocol):
    """Protocol for models that have validation_metadata attribute."""

    validation_metadata: dict[str, object] | None


# Generic type for models with validation_metadata field
ModelT = TypeVar("ModelT", bound=ModelWithValidationMetadata)


class FlextLdifUtilitiesMetadata:
    """Metadata utilities for LDIF validation metadata management.

    Provides helper methods for:
    - Preserving validation metadata during conversions
    - Extracting RFC violations from models
    - Tracking conversion steps in transformation history
    """

    @staticmethod
    def _copy_violations_to_target(
        source_metadata: dict[str, object],
        target_metadata: dict[str, object],
    ) -> None:
        """Copy violation fields from source to target metadata.

        Args:
            source_metadata: Source metadata with violations
            target_metadata: Target metadata to receive violations

        """
        # Preserve RFC violations from source
        for violation_key in [
            "rfc_violations",
            "dn_violations",
            "attribute_violations",
            "server_specific_violations",
        ]:
            if violation_key in source_metadata:
                target_metadata[violation_key] = source_metadata[violation_key]

        # Preserve validation context
        if "validation_context" in source_metadata:
            target_metadata["validation_context"] = source_metadata[
                "validation_context"
            ]

    @staticmethod
    def _set_model_metadata(
        model: ModelWithValidationMetadata,
        metadata: dict[str, object],
    ) -> None:
        """Set validation_metadata on model (handles both mutable and frozen models).

        Args:
            model: Model to set metadata on
            metadata: Metadata dict to set

        """
        # Safely set validation_metadata if the attribute exists
        try:
            if hasattr(model, "validation_metadata"):
                # Always use setattr for safety, regardless of frozen status
                model.validation_metadata = metadata
        except (AttributeError, TypeError):
            # Ignore if attribute cannot be set
            pass

    @staticmethod
    def preserve_validation_metadata(
        source_model: ModelT,
        target_model: ModelT,
        transformation: dict[str, object],
    ) -> ModelT:
        """Copy validation_metadata from source to target, adding transformation.

        Preserves RFC violations captured in FASE 1 validators and adds
        conversion transformation metadata for audit trail.

        Args:
            source_model: Source model with validation_metadata to preserve
            target_model: Target model to receive metadata
            transformation: Transformation details to add (step, server, changes)

        Returns:
            Target model with preserved metadata and added transformation

        Example:
            >>> transformation = {
            ...     "step": "normalize_to_rfc",
            ...     "server": "oid",
            ...     "changes": ["DN lowercased", "ACL format normalized"],
            ... }
            >>> oud_entry = FlextLdifUtilitiesMetadata.preserve_validation_metadata(
            ...     source_model=oid_entry,
            ...     target_model=rfc_entry,
            ...     transformation=transformation,
            ... )

        """
        # Extract source validation_metadata (if present)
        source_metadata = getattr(source_model, "validation_metadata", None)

        if source_metadata is None:
            # No metadata to preserve - return target unchanged
            return target_model

        # Get or initialize target metadata
        target_metadata = getattr(target_model, "validation_metadata", None)
        if target_metadata is None:
            target_metadata = {}

        # Copy violations from source to target
        FlextLdifUtilitiesMetadata._copy_violations_to_target(
            source_metadata,
            target_metadata,
        )

        # Add transformation to history
        if "transformations" not in target_metadata:
            target_metadata["transformations"] = []

        target_metadata["transformations"].append(transformation)

        # Set conversion path if not already set
        if "conversion_path" not in target_metadata:
            source_server = transformation.get("server", "unknown")
            target_metadata["conversion_path"] = f"{source_server}->..."

        # Update target model metadata
        FlextLdifUtilitiesMetadata._set_model_metadata(target_model, target_metadata)

        return target_model

    @staticmethod
    def extract_rfc_violations(model: ModelWithValidationMetadata) -> list[str]:
        """Extract all RFC violations from model validation_metadata.

        Aggregates violations from:
        - rfc_violations: Direct RFC violations
        - dn_violations: Distinguished Name RFC violations
        - attribute_violations: Attribute name RFC violations

        Args:
            model: Model with validation_metadata containing violations

        Returns:
            List of all RFC violation messages (empty if no violations)

        Example:
            >>> violations = FlextLdifUtilitiesMetadata.extract_rfc_violations(entry)
            >>> if violations:
            ...     print(f"Found {len(violations)} RFC violations")
            ...     for violation in violations:
            ...         print(f"  - {violation}")

        """
        violations: list[str] = []

        # Get validation_metadata from model
        metadata = getattr(model, "validation_metadata", None)
        if metadata is None:
            return violations

        # Extract direct RFC violations
        if "rfc_violations" in metadata:
            rfc_violations = metadata["rfc_violations"]
            if isinstance(rfc_violations, list):
                violations.extend(rfc_violations)

        # Extract DN violations
        if "dn_violations" in metadata:
            dn_violations = metadata["dn_violations"]
            if isinstance(dn_violations, list):
                violations.extend(dn_violations)

        # Extract attribute violations
        if "attribute_violations" in metadata:
            attr_violations = metadata["attribute_violations"]
            if isinstance(attr_violations, list):
                violations.extend(attr_violations)

        return violations

    @staticmethod
    def track_conversion_step(
        model: ModelT,
        step: str,
        server: str,
        changes: list[str],
    ) -> ModelT:
        """Add conversion step to model transformation history.

        Tracks each step in the conversion pipeline for audit trail and debugging.
        Creates validation_metadata if not present.

        Args:
            model: Model to track conversion step
            step: Conversion step name (e.g., "normalize_to_rfc", "denormalize_from_rfc")
            server: Server type performing the step (e.g., "oid", "oud", "rfc")
            changes: List of changes applied in this step

        Returns:
            Model with updated transformation history

        Example:
            >>> entry = FlextLdifUtilitiesMetadata.track_conversion_step(
            ...     model=entry,
            ...     step="normalize_to_rfc",
            ...     server="oid",
            ...     changes=["DN lowercased", "ACL format normalized"],
            ... )

        """
        # Get or initialize validation_metadata
        metadata = getattr(model, "validation_metadata", None)
        if metadata is None:
            metadata = {}

        # Initialize transformations list if not present
        if "transformations" not in metadata:
            metadata["transformations"] = []

        # Add conversion step
        transformation = {
            "step": step,
            "server": server,
            "changes": changes,
        }
        metadata["transformations"].append(transformation)

        # Update conversion_path
        if "conversion_path" not in metadata:
            metadata["conversion_path"] = server
        else:
            current_path = metadata["conversion_path"]
            if server not in current_path:
                metadata["conversion_path"] = f"{current_path}->{server}"

        # Set metadata on model
        FlextLdifUtilitiesMetadata._set_model_metadata(model, metadata)

        return model

    # =========================================================================
    # ZERO DATA LOSS TRACKING (Phase 2)
    # =========================================================================

    @staticmethod
    def track_transformation(
        metadata: FlextLdifModelsDomains.QuirkMetadata,
        original_name: str,
        target_name: str | None,
        original_values: list[str],
        target_values: list[str] | None,
        transformation_type: str,
        reason: str,
    ) -> None:
        """Track an attribute transformation in QuirkMetadata.

        Populates the attribute_transformations dict with a complete
        AttributeTransformation record for audit trail and round-trip support.

        CRITICAL: This function ensures ALL transformations are tracked for zero data loss.
        Every attribute change (rename, remove, modify, add) MUST be tracked here.

        Args:
            metadata: QuirkMetadata instance to update
            original_name: Original attribute name (PRESERVED EXACTLY as-is)
            target_name: Target attribute name (None if removed)
            original_values: Original attribute values (PRESERVED EXACTLY as-is)
            target_values: Converted values (None if removed)
            transformation_type: Type: renamed/removed/modified/added/soft_deleted
            reason: Human-readable explanation

        Example:
            >>> FlextLdifUtilitiesMetadata.track_transformation(
            ...     metadata=entry.metadata,
            ...     original_name="orcldasisenabled",
            ...     target_name="orcldasisenabled",
            ...     original_values=["1"],
            ...     target_values=["TRUE"],
            ...     transformation_type="modified",
            ...     reason="OID boolean '1' -> RFC 'TRUE'",
            ... )

        """
        # Import here to avoid circular imports at module level
        # This is a runtime import, not a type-only import
        # Note: PLC0415 suppressed - this import must be deferred to avoid circular dependency
        from flext_ldif._models.domain import (  # noqa: PLC0415
            FlextLdifModelsDomains,
        )

        transformation = FlextLdifModelsDomains.AttributeTransformation(
            original_name=original_name,
            target_name=target_name,
            original_values=original_values,
            target_values=target_values,
            transformation_type=transformation_type,
            reason=reason,
        )
        metadata.attribute_transformations[original_name] = transformation

        # Log transformation for traceability
        logger.debug(
            "Tracked attribute transformation",
            original_name=original_name,
            target_name=target_name,
            transformation_type=transformation_type,
        )

    @staticmethod
    def preserve_original_format(
        metadata: FlextLdifModelsDomains.QuirkMetadata,
        format_key: str,
        original_value: object,
    ) -> None:
        """Preserve original formatting details for round-trip support.

        Stores original format information in original_format_details dict.
        Used for preserving DN spacing, boolean format, ACI indentation, etc.

        Args:
            metadata: QuirkMetadata instance to update
            format_key: Key identifying the format type (e.g., 'dn_spacing')
            original_value: Original format value to preserve

        Example:
            >>> FlextLdifUtilitiesMetadata.preserve_original_format(
            ...     metadata=entry.metadata,
            ...     format_key="boolean_format",
            ...     original_value="0/1",
            ... )
            >>> FlextLdifUtilitiesMetadata.preserve_original_format(
            ...     metadata=entry.metadata,
            ...     format_key="dn_spacing",
            ...     original_value="cn=test, dc=example",
            ... )

        """
        metadata.original_format_details[format_key] = original_value

    @staticmethod
    def analyze_schema_formatting(
        definition: str,
    ) -> dict[str, object]:
        """Analyze schema definition to extract ALL formatting details.

        Captures EVERY minimal difference for perfect round-trip:
        - SYNTAX quotes (OID uses quotes, OUD/RFC don't)
        - SYNTAX spacing (spaces before/after SYNTAX keyword)
        - Attribute/ObjectClass case (attributetypes vs attributeTypes)
        - NAME format (single vs multiple names)
        - X-ORIGIN presence, value, spacing, quotes
        - OBSOLETE presence and position
        - Field order and EXACT spacing between fields
        - Trailing spaces, leading spaces
        - Spaces after OID, before NAME, etc.
        - Quotes in all string fields (NAME, DESC, X-ORIGIN)
        - Semicolons, commas, and other punctuation

        Args:
            definition: Original schema definition string

        Returns:
            Dictionary with ALL formatting details captured

        Example:
            >>> details = FlextLdifUtilitiesMetadata.analyze_schema_formatting(
            ...     "attributetypes: ( 0.9.2342.19200300.100.1.1 NAME 'uid' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )  "
            ... )
            >>> # Returns: {
            ... #     'syntax_quotes': True,
            ... #     'syntax_spacing': ' ',
            ... #     'attribute_case': 'attributetypes',
            ... #     'name_format': 'single',
            ... #     'trailing_spaces': '  ',
            ... #     'original_string_complete': '...',
            ... #     'oid_spacing_after': ' ',
            ... #     'name_quotes': "'",
            ... #     'x_origin_spacing_before': ' ',
            ... #     ...
            ... # }

        """
        details: dict[str, object] = {}

        # Store complete original string (CRITICAL: preserve EXACTLY as-is)
        details["original_string_complete"] = definition

        # Detect attribute/ObjectClass case and prefix
        if "attributetypes:" in definition.lower():
            attr_match = re.search(
                r"(attributetypes|attributeTypes):", definition, re.IGNORECASE
            )
            if attr_match:
                details["attribute_case"] = attr_match.group(1)
                # Capture spacing after colon
                colon_pos = definition.find(":")
                if colon_pos >= 0 and colon_pos + 1 < len(definition):
                    after_colon = definition[colon_pos + 1 :]
                    spacing_match = re.match(r"(\s*)", after_colon)
                    if spacing_match:
                        details["attribute_prefix_spacing"] = spacing_match.group(1)
        if "objectclasses:" in definition.lower() or "objectClasses:" in definition:
            oc_match = re.search(
                r"(objectclasses|objectClasses):", definition, re.IGNORECASE
            )
            if oc_match:
                details["objectclass_case"] = oc_match.group(1)
                # Capture spacing after colon
                colon_pos = definition.find(":")
                if colon_pos >= 0 and colon_pos + 1 < len(definition):
                    after_colon = definition[colon_pos + 1 :]
                    spacing_match = re.match(r"(\s*)", after_colon)
                    if spacing_match:
                        details["objectclass_prefix_spacing"] = spacing_match.group(1)

        # Extract OID and spacing after OID
        oid_match = re.search(r"\(\s*([0-9.]+)(\s*)", definition)
        if oid_match:
            details["oid_value"] = oid_match.group(1)
            details["oid_spacing_after"] = oid_match.group(2)

        # Extract SYNTAX details with COMPLETE formatting
        syntax_match = re.search(
            r"SYNTAX\s*([\"']?)([0-9.]+)([\"']?)(\{[0-9]+\})?",
            definition,
            re.IGNORECASE,
        )
        if syntax_match:
            details["syntax_quotes"] = bool(
                syntax_match.group(1) or syntax_match.group(3)
            )
            details["syntax_quote_char"] = (
                syntax_match.group(1) or syntax_match.group(3) or ""
            )
            details["syntax_oid"] = syntax_match.group(2)
            details["syntax_length"] = syntax_match.group(4) or None
            # Extract EXACT spacing after SYNTAX keyword
            syntax_pos = definition.find("SYNTAX")
            if syntax_pos >= 0:
                after_syntax = definition[syntax_pos + 6 :]
                spacing_match = re.match(r"(\s*)", after_syntax)
                if spacing_match:
                    details["syntax_spacing"] = spacing_match.group(1)
                # Extract EXACT spacing before SYNTAX
                before_syntax = definition[:syntax_pos]
                before_match = re.search(r"(\s+)$", before_syntax)
                if before_match:
                    details["syntax_spacing_before"] = before_match.group(1)
                else:
                    details["syntax_spacing_before"] = ""

        # Extract NAME format with COMPLETE details
        name_match = re.search(
            r"NAME\s+(\()?\s*([\"']?)([^\"'()]+)([\"']?)(\s*\))?", definition
        )
        if name_match:
            has_parens = bool(name_match.group(1))
            name_quote_start = name_match.group(2) or ""
            name_value = name_match.group(3)
            name_quote_end = name_match.group(4) or ""

            # Check if it's multiple names: NAME ( 'uid' 'userid' )
            multiple_match = re.search(
                r"NAME\s+\(\s*([\"'])([^\"']+)([\"'])\s+([\"'])([^\"']+)([\"'])",
                definition,
            )
            if multiple_match or (has_parens and " " in name_value):
                details["name_format"] = "multiple"
                # Extract ALL name values with quotes
                all_name_matches = re.findall(
                    r"([\"'])([^\"']+)([\"'])",
                    definition[name_match.start() : name_match.end() + 50],
                )
                details["name_values"] = [m[1] for m in all_name_matches]
                details["name_quotes"] = (
                    [m[0] for m in all_name_matches] if all_name_matches else []
                )
                # Extract spacing between names
                name_section = definition[name_match.start() : name_match.end() + 50]
                name_spacing = re.findall(r"[\"']\s+([\"'])", name_section)
                details["name_spacing_between"] = name_spacing
            else:
                details["name_format"] = "single"
                details["name_values"] = [name_value]
                # Use name_quote_end if name_quote_start is empty (handles both quote positions)
                quote_char = name_quote_start or name_quote_end
                details["name_quotes"] = [quote_char] if quote_char else []
            # Extract spacing before NAME
            name_pos = definition.find("NAME")
            if name_pos >= 0:
                before_name = definition[:name_pos]
                before_match = re.search(r"(\s+)$", before_name)
                if before_match:
                    details["name_spacing_before"] = before_match.group(1)
                else:
                    details["name_spacing_before"] = ""

        # Extract DESC with quotes and spacing
        desc_match = re.search(
            r"DESC\s+([\"']?)([^\"']+)([\"']?)", definition, re.IGNORECASE
        )
        if desc_match:
            details["desc_presence"] = True
            details["desc_quotes"] = desc_match.group(1) or desc_match.group(3) or ""
            details["desc_value"] = desc_match.group(2)
            # Extract spacing before DESC
            desc_pos = definition.find("DESC")
            if desc_pos >= 0:
                before_desc = definition[:desc_pos]
                before_match = re.search(r"(\s+)$", before_desc)
                if before_match:
                    details["desc_spacing_before"] = before_match.group(1)
                else:
                    details["desc_spacing_before"] = ""
        else:
            details["desc_presence"] = False

        # Extract X-ORIGIN with COMPLETE formatting
        x_origin_match = re.search(
            r"X-ORIGIN\s+([\"']?)([^\"']+)([\"']?)",
            definition,
            re.IGNORECASE,
        )
        if x_origin_match:
            details["x_origin_presence"] = True
            details["x_origin_quotes"] = (
                x_origin_match.group(1) or x_origin_match.group(3) or ""
            )
            details["x_origin_value"] = x_origin_match.group(2)
            # Extract spacing before X-ORIGIN
            x_origin_pos = definition.find("X-ORIGIN")
            if x_origin_pos >= 0:
                before_x_origin = definition[:x_origin_pos]
                before_match = re.search(r"(\s+)$", before_x_origin)
                if before_match:
                    details["x_origin_spacing_before"] = before_match.group(1)
                else:
                    details["x_origin_spacing_before"] = ""
        else:
            details["x_origin_presence"] = False
            details["x_origin_value"] = None
            details["x_origin_quotes"] = ""

        # Extract OBSOLETE with position and spacing
        obsolete_match = re.search(r"\bOBSOLETE\b", definition, re.IGNORECASE)
        if obsolete_match:
            details["obsolete_presence"] = True
            details["obsolete_position"] = obsolete_match.start()
            # Extract spacing before OBSOLETE
            before_obsolete = definition[: obsolete_match.start()]
            before_match = re.search(r"(\s+)$", before_obsolete)
            if before_match:
                details["obsolete_spacing_before"] = before_match.group(1)
            else:
                details["obsolete_spacing_before"] = ""
        else:
            details["obsolete_presence"] = False
            details["obsolete_position"] = None

        # Extract field order
        field_patterns = {
            "OID": r"\(\s*([0-9.]+)",
            "NAME": r"NAME",
            "DESC": r"DESC",
            "EQUALITY": r"EQUALITY",
            "SUBSTR": r"SUBSTR",
            "ORDERING": r"ORDERING",
            "SYNTAX": r"SYNTAX",
            "SUP": r"SUP",
            "SINGLE-VALUE": r"SINGLE-VALUE",
            "OBSOLETE": r"OBSOLETE",
            "X-ORIGIN": r"X-ORIGIN",
        }
        field_order: list[str] = []
        field_positions: dict[str, int] = {}
        for field_name, pattern in field_patterns.items():
            match = re.search(pattern, definition, re.IGNORECASE)
            if match:
                field_order.append(field_name)
                field_positions[field_name] = match.start()
        details["field_order"] = field_order
        details["field_positions"] = field_positions

        # Extract EXACT spacing between fields
        spacing_between: dict[str, str] = {}
        for i in range(len(field_order) - 1):
            field1 = field_order[i]
            field2 = field_order[i + 1]
            pos1 = field_positions.get(field1)
            pos2 = field_positions.get(field2)
            if pos1 is not None and pos2 is not None:
                # Find the end of field1
                field1_end_match = re.search(
                    field_patterns[field1],
                    definition[pos1:],
                    re.IGNORECASE,
                )
                if field1_end_match:
                    field1_end = pos1 + field1_end_match.end()
                    # Extract everything between field1 end and field2 start
                    spacing = definition[field1_end:pos2]
                    spacing_between[f"{field1}_{field2}"] = spacing
        details["spacing_between_fields"] = spacing_between

        # Extract trailing spaces after closing paren
        trailing_match = re.search(r"\)\s*$", definition)
        if trailing_match:
            trailing_spaces = definition[trailing_match.end() :]
            details["trailing_spaces"] = trailing_spaces
        else:
            details["trailing_spaces"] = ""

        # Extract leading spaces before opening paren
        leading_match = re.search(r"^\s*\(", definition)
        if leading_match:
            details["leading_spaces"] = leading_match.group(0)[:-1]  # Exclude the (
        else:
            details["leading_spaces"] = ""

        # Extract EQUALITY/SUBSTR/ORDERING presence and spacing
        for rule_name in ["EQUALITY", "SUBSTR", "ORDERING"]:
            rule_match = re.search(rf"\b{rule_name}\b", definition, re.IGNORECASE)
            if rule_match:
                details[f"{rule_name.lower()}_presence"] = True
                # Extract spacing before
                before_rule = definition[: rule_match.start()]
                before_match = re.search(r"(\s+)$", before_rule)
                if before_match:
                    details[f"{rule_name.lower()}_spacing_before"] = before_match.group(
                        1
                    )
                else:
                    details[f"{rule_name.lower()}_spacing_before"] = ""
            else:
                details[f"{rule_name.lower()}_presence"] = False

        # Extract SUP with spacing
        sup_match = re.search(r"SUP\s+([^\s]+)", definition, re.IGNORECASE)
        if sup_match:
            details["sup_presence"] = True
            details["sup_value"] = sup_match.group(1)
            # Extract spacing before SUP
            sup_pos = definition.find("SUP")
            if sup_pos >= 0:
                before_sup = definition[:sup_pos]
                before_match = re.search(r"(\s+)$", before_sup)
                if before_match:
                    details["sup_spacing_before"] = before_match.group(1)
                else:
                    details["sup_spacing_before"] = ""
        else:
            details["sup_presence"] = False

        # Extract SINGLE-VALUE with spacing
        single_value_match = re.search(r"SINGLE-VALUE", definition, re.IGNORECASE)
        if single_value_match:
            details["single_value_presence"] = True
            # Extract spacing before
            before_sv = definition[: single_value_match.start()]
            before_match = re.search(r"(\s+)$", before_sv)
            if before_match:
                details["single_value_spacing_before"] = before_match.group(1)
            else:
                details["single_value_spacing_before"] = ""
        else:
            details["single_value_presence"] = False

        # Log all captured deviations at DEBUG level for verification
        preview_len = _CONTENT_PREVIEW_LENGTH
        logger.debug(
            "Schema formatting analyzed",
            definition_preview=(
                definition[:preview_len] + "..."
                if len(definition) > preview_len
                else definition
            ),
            fields_captured=len(details),
            syntax_quotes=details.get("syntax_quotes"),
            x_origin_presence=details.get("x_origin_presence"),
            name_format=details.get("name_format"),
            obsolete_presence=details.get("obsolete_presence"),
            attribute_case=details.get("attribute_case"),
            objectclass_case=details.get("objectclass_case"),
        )

        return details

    @staticmethod
    def preserve_schema_formatting(
        metadata: FlextLdifModelsDomains.QuirkMetadata,
        definition: str,
    ) -> None:
        """Preserve complete schema formatting details for round-trip.

        Analyzes schema definition and stores ALL formatting details
        in schema_format_details for perfect round-trip conversion.

        Args:
            metadata: QuirkMetadata instance to update
            definition: Original schema definition string

        Example:
            >>> FlextLdifUtilitiesMetadata.preserve_schema_formatting(
            ...     metadata=attr.metadata,
            ...     definition="attributetypes: ( 0.9.2342.19200300.100.1.1 NAME 'uid' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )  ",
            ... )

        """
        formatting_details = FlextLdifUtilitiesMetadata.analyze_schema_formatting(
            definition
        )
        metadata.schema_format_details.update(formatting_details)

        # Log when schema formatting is preserved
        logger.debug(
            "Schema formatting preserved in metadata",
            quirk_type=metadata.quirk_type,
            fields_preserved=len(formatting_details),
            has_original_string="original_string_complete" in formatting_details,
        )

    @staticmethod
    def track_boolean_conversion(
        metadata: FlextLdifModelsDomains.QuirkMetadata,
        attr_name: str,
        original_value: str,
        converted_value: str,
        format_direction: str = "OID->RFC",
    ) -> None:
        """Track boolean conversion for round-trip support.

        Records boolean value conversion (e.g., '0'/'1' to 'TRUE'/'FALSE')
        in the boolean_conversions dict for exact round-trip restoration.

        Args:
            metadata: QuirkMetadata instance to update
            attr_name: Attribute name being converted
            original_value: Original boolean value ('0', '1', 'TRUE', 'FALSE')
            converted_value: Converted boolean value
            format_direction: Conversion direction (e.g., 'OID->RFC', 'RFC->OID')

        Example:
            >>> FlextLdifUtilitiesMetadata.track_boolean_conversion(
            ...     metadata=entry.metadata,
            ...     attr_name="orcldasisenabled",
            ...     original_value="1",
            ...     converted_value="TRUE",
            ...     format_direction="OID->RFC",
            ... )

        """
        metadata.boolean_conversions[attr_name] = {
            "original": original_value,
            "converted": converted_value,
            "format": format_direction,
        }

        # Log boolean conversion for audit trail
        logger.debug(
            "Boolean conversion tracked",
            attr_name=attr_name,
            original=original_value,
            converted=converted_value,
            direction=format_direction,
        )

    @staticmethod
    def track_schema_quirk(
        metadata: FlextLdifModelsDomains.QuirkMetadata,
        quirk_name: str,
    ) -> None:
        """Track a schema quirk that was applied during parsing.

        Records schema-level quirks for audit trail and debugging.

        Args:
            metadata: QuirkMetadata instance to update
            quirk_name: Name of the quirk applied

        Example:
            >>> FlextLdifUtilitiesMetadata.track_schema_quirk(
            ...     metadata=entry.metadata, quirk_name="matching_rule_normalization"
            ... )

        """
        if quirk_name not in metadata.schema_quirks_applied:
            metadata.schema_quirks_applied.append(quirk_name)

    @staticmethod
    def soft_delete_attribute(
        metadata: FlextLdifModelsDomains.QuirkMetadata,
        attr_name: str,
        original_values: list[str],
    ) -> None:
        """Soft-delete an attribute during conversion.

        Marks an attribute as soft-deleted (hidden for target server but
        preserved for reverse conversion). Different from removed_attributes
        which are permanently removed.

        Args:
            metadata: QuirkMetadata instance to update
            attr_name: Attribute name being soft-deleted
            original_values: Original values to preserve

        Example:
            >>> FlextLdifUtilitiesMetadata.soft_delete_attribute(
            ...     metadata=entry.metadata,
            ...     attr_name="orclguid",
            ...     original_values=["E4F5A6B7C8D9..."],
            ... )

        """
        if attr_name not in metadata.soft_delete_markers:
            metadata.soft_delete_markers.append(attr_name)
        # Also store the values in removed_attributes for restoration
        metadata.removed_attributes[attr_name] = original_values

    @staticmethod
    def preserve_attribute_case(
        metadata: FlextLdifModelsDomains.QuirkMetadata,
        normalized_name: str,
        original_case: str,
    ) -> None:
        """Preserve original attribute name case for round-trip.

        Stores the original case of attribute names for restoration
        during reverse conversion.

        Args:
            metadata: QuirkMetadata instance to update
            normalized_name: Normalized (lowercase) attribute name
            original_case: Original case of the attribute name

        Example:
            >>> FlextLdifUtilitiesMetadata.preserve_attribute_case(
            ...     metadata=entry.metadata,
            ...     normalized_name="objectclass",
            ...     original_case="objectClass",
            ... )

        """
        metadata.original_attribute_case[normalized_name] = original_case

    @staticmethod
    def validate_metadata_completeness(
        metadata: FlextLdifModelsDomains.QuirkMetadata,
        expected_transformations: list[str],
    ) -> tuple[bool, list[str]]:
        """Validate that all expected transformations are tracked.

        Checks that all expected attribute transformations are present
        in the metadata for complete audit trail.

        Args:
            metadata: QuirkMetadata instance to validate
            expected_transformations: List of attribute names that should
                have transformations tracked

        Returns:
            Tuple of (is_complete, missing_attributes)

        Example:
            >>> is_complete, missing = (
            ...     FlextLdifUtilitiesMetadata.validate_metadata_completeness(
            ...         metadata=entry.metadata,
            ...         expected_transformations=["orcldasisenabled", "pwdlockout"],
            ...     )
            ... )
            >>> if not is_complete:
            ...     print(f"Missing tracking for: {missing}")

        """
        missing = [
            attr_name
            for attr_name in expected_transformations
            if attr_name not in metadata.attribute_transformations
        ]
        return len(missing) == 0, missing

    @staticmethod
    def assert_no_data_loss(
        original_entry: FlextLdifModelsDomains.Entry,
        converted_entry: FlextLdifModelsDomains.Entry,
    ) -> tuple[bool, list[str]]:
        """Assert that no data was lost during conversion.

        Validates that all original attributes are either:
        - Present in the converted entry, OR
        - Tracked in metadata (attribute_transformations, removed_attributes, soft_delete_markers)

        Args:
            original_entry: Entry before conversion
            converted_entry: Entry after conversion

        Returns:
            Tuple of (no_data_loss, lost_attributes)

        Example:
            >>> no_loss, lost = FlextLdifUtilitiesMetadata.assert_no_data_loss(
            ...     original_entry=oid_entry, converted_entry=oud_entry
            ... )
            >>> assert no_loss, f"Data loss detected: {lost}"

        """
        lost_attributes: list[str] = []

        # Get all original attribute names
        original_attrs = set(original_entry.attributes.attributes.keys())

        # Get all tracked locations in converted entry
        converted_attrs = set(converted_entry.attributes.attributes.keys())
        tracked_transforms = set(
            converted_entry.metadata.attribute_transformations.keys()
        )
        removed_attrs = set(converted_entry.metadata.removed_attributes.keys())
        soft_deleted = set(converted_entry.metadata.soft_delete_markers)

        # Check each original attribute
        for attr_name in original_attrs:
            attr_lower = attr_name.lower()
            # Check if attribute is accounted for anywhere
            is_in_converted = any(a.lower() == attr_lower for a in converted_attrs)
            is_in_transforms = any(a.lower() == attr_lower for a in tracked_transforms)
            is_in_removed = any(a.lower() == attr_lower for a in removed_attrs)
            is_soft_deleted = any(a.lower() == attr_lower for a in soft_deleted)

            if not (
                is_in_converted or is_in_transforms or is_in_removed or is_soft_deleted
            ):
                lost_attributes.append(attr_name)

        return len(lost_attributes) == 0, lost_attributes

    @staticmethod
    def preserve_original_ldif_content(
        metadata: FlextLdifModelsDomains.QuirkMetadata,
        ldif_content: str,
        context: str = "entry_original_ldif",
    ) -> None:
        r"""Preserve complete original LDIF content before ANY parsing/conversion.

        CRITICAL: This MUST be called FIRST, before any parsing or conversion operations.
        The original LDIF content is NEVER lost and can be restored for perfect round-trip.

        Args:
            metadata: QuirkMetadata instance to update
            ldif_content: Complete original LDIF content string
            context: Context identifier (default: "entry_original_ldif")

        Example:
            >>> # In parser, BEFORE calling quirk.parse():
            >>> FlextLdifUtilitiesMetadata.preserve_original_ldif_content(
            ...     metadata=entry.metadata,
            ...     ldif_content="dn: cn=test\\ncn: test\\n",
            ...     context="entry_original_ldif",
            ... )

        """
        # Store in original_strings dict (NEVER lose this)
        metadata.original_strings[context] = ldif_content

        # Also store in extensions for easy access
        if not metadata.extensions:
            metadata.extensions = {}
        metadata.extensions[context] = ldif_content

        # Log preservation
        logger.debug(
            "Preserved original LDIF content",
            context=context,
            content_length=len(ldif_content),
        )

    @staticmethod
    def restore_from_metadata(
        entry: FlextLdifModelsDomains.Entry,
        target_server: str,
    ) -> FlextLdifModelsDomains.Entry:
        """Restore original values from metadata for reverse conversion.

        Uses metadata tracking to restore original values during
        reverse conversion (e.g., OUD->OID after OID->OUD).

        Args:
            entry: Entry with metadata to restore from
            target_server: Target server type for restoration

        Returns:
            Entry with restored original values

        Note:
            This modifies the entry in place and returns it.

        Example:
            >>> # After OID->OUD conversion, restore for OUD->OID
            >>> restored = FlextLdifUtilitiesMetadata.restore_from_metadata(
            ...     entry=oud_entry, target_server="oid"
            ... )

        """
        metadata = entry.metadata

        # Restore boolean values if target is OID
        if target_server.lower() == "oid":
            for attr_name, conversion in metadata.boolean_conversions.items():
                if attr_name in entry.attributes.attributes:
                    original_val = conversion.get("original", "")
                    if original_val:
                        entry.attributes.attributes[attr_name] = [original_val]

        # Restore soft-deleted attributes
        for attr_name in metadata.soft_delete_markers:
            if attr_name in metadata.removed_attributes:
                entry.attributes.attributes[attr_name] = metadata.removed_attributes[
                    attr_name
                ]

        # Restore attribute case if original case is tracked
        new_attrs: dict[str, list[str]] = {}
        for attr_name, values in entry.attributes.attributes.items():
            original_case = metadata.original_attribute_case.get(
                attr_name.lower(), attr_name
            )
            new_attrs[original_case] = values
        entry.attributes.attributes = new_attrs

        return entry

    @staticmethod
    def analyze_minimal_differences(
        original: str,
        converted: str | None,
        context: str = "entry",
    ) -> dict[str, object]:
        """Analyze ALL minimal differences between original and converted strings.

        Captures EVERY detail for perfect round-trip:
        - Character-by-character differences
        - Spacing differences (leading, trailing, internal)
        - Case differences
        - Punctuation differences (semicolons, commas, etc.)
        - Encoding differences
        - Missing/added characters

        Args:
            original: Original string
            converted: Converted string (None if unchanged)
            context: Context for analysis (dn, attribute, schema, etc.)

        Returns:
            Dictionary with complete difference analysis

        Example:
            >>> diff = FlextLdifUtilitiesMetadata.analyze_minimal_differences(
            ...     original="cn=test, dc=example",
            ...     converted="cn=test,dc=example",
            ...     context="dn",
            ... )
            >>> # Returns: {
            ... #     'has_differences': True,
            ... #     'differences': [{'position': 10, 'original': ' ', 'converted': ''}],
            ... #     'spacing_changes': {'removed_spaces': [10]},
            ... #     'case_changes': [],
            ... #     'punctuation_changes': [],
            ... #     'original_length': 20,
            ... #     'converted_length': 19,
            ... # }

        """
        differences: dict[str, object] = {
            "has_differences": False,
            "context": context,
            "original": original,
            "converted": converted,
            "differences": [],
            "spacing_changes": {},
            "case_changes": [],
            "punctuation_changes": [],
            "missing_chars": [],
            "added_chars": [],
            "original_length": len(original),
            "converted_length": len(converted) if converted else len(original),
        }

        if converted is None or original == converted:
            return differences

        differences["has_differences"] = True

        # Character-by-character comparison
        original_chars = list(original)
        converted_chars = list(converted)
        max_len = max(len(original_chars), len(converted_chars))

        char_differences: list[dict[str, object]] = []
        spacing_removed: list[int] = []
        spacing_added: list[int] = []
        case_changes: list[dict[str, object]] = []
        punctuation_changes: list[dict[str, object]] = []

        for i in range(max_len):
            orig_char = original_chars[i] if i < len(original_chars) else None
            conv_char = converted_chars[i] if i < len(converted_chars) else None

            if orig_char != conv_char:
                diff_entry: dict[str, object] = {
                    "position": i,
                    "original": orig_char,
                    "converted": conv_char,
                }

                # Categorize the difference
                if orig_char == " " and conv_char != " ":
                    spacing_removed.append(i)
                    diff_entry["type"] = "spacing_removed"
                elif orig_char != " " and conv_char == " ":
                    spacing_added.append(i)
                    diff_entry["type"] = "spacing_added"
                elif orig_char and conv_char and orig_char.lower() == conv_char.lower():
                    case_changes.append({
                        "position": i,
                        "original": orig_char,
                        "converted": conv_char,
                    })
                    diff_entry["type"] = "case_change"
                elif (
                    orig_char
                    and conv_char
                    and orig_char in ",;:()[]{}"
                    and conv_char in ",;:()[]{}"
                ):
                    punctuation_changes.append({
                        "position": i,
                        "original": orig_char,
                        "converted": conv_char,
                    })
                    diff_entry["type"] = "punctuation_change"
                elif orig_char is None:
                    diff_entry["type"] = "added"
                    differences["added_chars"].append({
                        "position": i,
                        "char": conv_char,
                    })
                elif conv_char is None:
                    diff_entry["type"] = "removed"
                    differences["missing_chars"].append({
                        "position": i,
                        "char": orig_char,
                    })
                else:
                    diff_entry["type"] = "character_change"

                char_differences.append(diff_entry)

        differences["differences"] = char_differences
        differences["spacing_changes"] = {
            "removed_positions": spacing_removed,
            "added_positions": spacing_added,
            "removed_count": len(spacing_removed),
            "added_count": len(spacing_added),
        }
        differences["case_changes"] = case_changes
        differences["punctuation_changes"] = punctuation_changes

        # Analyze leading/trailing spaces
        differences["leading_spaces_original"] = len(original) - len(original.lstrip())
        differences["trailing_spaces_original"] = len(original) - len(original.rstrip())
        differences["leading_spaces_converted"] = (
            len(converted) - len(converted.lstrip()) if converted else 0
        )
        differences["trailing_spaces_converted"] = (
            len(converted) - len(converted.rstrip()) if converted else 0
        )

        # CRITICAL: Capture ALL punctuation differences (semicolons, commas, colons, etc.)
        punctuation_map: dict[str, int] = {}
        for char in ",;:()[]{}":
            orig_count = original.count(char)
            conv_count = converted.count(char) if converted else 0
            if orig_count != conv_count:
                punctuation_map[char] = {
                    "original": orig_count,
                    "converted": conv_count,
                }
        if punctuation_map:
            differences["punctuation_counts"] = punctuation_map

        # CRITICAL: Capture quote differences (single vs double, presence/absence)
        quote_analysis: dict[str, object] = {}
        single_quote_orig = original.count("'")
        double_quote_orig = original.count('"')
        single_quote_conv = converted.count("'") if converted else 0
        double_quote_conv = converted.count('"') if converted else 0

        if (
            single_quote_orig != single_quote_conv
            or double_quote_orig != double_quote_conv
        ):
            quote_analysis["single_quotes"] = {
                "original": single_quote_orig,
                "converted": single_quote_conv,
            }
            quote_analysis["double_quotes"] = {
                "original": double_quote_orig,
                "converted": double_quote_conv,
            }
        if quote_analysis:
            differences["quote_analysis"] = quote_analysis

        # CRITICAL: Capture case differences in detail (which characters changed case)
        case_change_details: list[dict[str, object]] = []
        for case_change in case_changes:
            pos = case_change.get("position", -1)
            orig_char = case_change.get("original", "")
            conv_char = case_change.get("converted", "")
            if orig_char and conv_char and orig_char.lower() == conv_char.lower():
                case_change_details.append({
                    "position": pos,
                    "original": orig_char,
                    "converted": conv_char,
                    "context_before": original[max(0, pos - 5) : pos]
                    if pos >= 0
                    else "",
                    "context_after": original[pos + 1 : pos + 6]
                    if pos >= 0 and pos + 1 < len(original)
                    else "",
                })
        if case_change_details:
            differences["case_change_details"] = case_change_details

        # CRITICAL: Detect boolean conversions automatically (0/1 <-> TRUE/FALSE)
        boolean_patterns = {
            ("0", "FALSE"): "boolean_false_conversion",
            ("1", "TRUE"): "boolean_true_conversion",
            ("FALSE", "0"): "boolean_false_reverse",
            ("TRUE", "1"): "boolean_true_reverse",
        }
        
        # Check if entire string is a boolean conversion
        original_upper = original.upper().strip()
        converted_upper = converted.upper().strip() if converted else ""
        
        for (orig_pattern, conv_pattern), conversion_type in boolean_patterns.items():
            if original_upper == orig_pattern and converted_upper == conv_pattern:
                differences["boolean_conversion"] = {
                    "type": conversion_type,
                    "original": original,
                    "converted": converted,
                    "detected": True,
                }
                logger.debug(
                    "Boolean conversion detected",
                    context=context,
                    conversion_type=conversion_type,
                )
                break

        # CRITICAL: Detect soft delete patterns (attribute removed but value preserved)
        # This is detected when original has content but converted is None or empty
        if original and (not converted or not converted.strip()):
            differences["soft_delete_detected"] = {
                "original": original,
                "converted": converted or "",
                "detected": True,
                "note": "Original content preserved but converted is empty - may indicate soft delete",
            }
            logger.debug(
                "Potential soft delete detected",
                context=context,
            )

        # CRITICAL: Detect semicolon removal (common in DN normalization)
        if original.endswith(";") and converted and not converted.endswith(";"):
            differences["semicolon_removed"] = {
                "position": len(original) - 1,
                "original": ";",
                "converted": "",
                "detected": True,
            }
            logger.debug(
                "Semicolon removal detected",
                context=context,
            )

        return differences

    @staticmethod
    def track_minimal_differences_in_metadata(
        metadata: FlextLdifModelsDomains.QuirkMetadata,
        original: str,
        converted: str | None = None,
        context: str = "entry",
        attribute_name: str | None = None,
    ) -> None:
        """Track minimal differences in metadata for perfect round-trip.

        Analyzes and stores ALL minimal differences between original and converted
        strings in metadata for perfect round-trip conversion.

        CRITICAL: This function NEVER loses original data. Original string is ALWAYS
        preserved in original_strings dict, even if no conversion occurred.

        Args:
            metadata: QuirkMetadata instance to update
            original: Original string (NEVER lose this - ALWAYS preserved)
            converted: Converted string (if None, only store original)
            context: Context for analysis (entry, attribute, schema, acl, etc.)
            attribute_name: Optional attribute name for attribute-specific tracking

        Example:
            >>> FlextLdifUtilitiesMetadata.track_minimal_differences_in_metadata(
            ...     metadata=entry.metadata,
            ...     original="cn=test,dc=example;",
            ...     converted="cn=test,dc=example",
            ...     context="dn",
            ...     attribute_name="dn",
            ... )

        """
        # CRITICAL: ALWAYS preserve original string FIRST (before any analysis)
        key = attribute_name or context
        original_key = f"{key}_original"
        metadata.original_strings[original_key] = original

        # Log preservation of original for round-trip restoration
        # Show preview with ellipsis if truncated for better context
        if len(original) > _MINIMAL_DIFF_PREVIEW_LENGTH:
            preview = f"{original[:_MINIMAL_DIFF_PREVIEW_LENGTH]}..."
        else:
            preview = original

        logger.debug(
            "Tracking original value for round-trip restoration",
            attribute_name=attribute_name or context,
            metadata_key=original_key,
            original_length=len(original),
            preview=preview,
            has_conversion=converted is not None,
        )

        # Analyze differences if converted string provided
        if converted is not None:
            differences = FlextLdifUtilitiesMetadata.analyze_minimal_differences(
                original=original, converted=converted, context=context
            )

            # Store differences in metadata.minimal_differences
            metadata.minimal_differences[key] = differences

            # Also store in extensions for compatibility
            if not metadata.extensions:
                metadata.extensions = {}

            extensions_key = f"minimal_differences_{key}"
            metadata.extensions[extensions_key] = differences

            # Store converted string in extensions for easy access
            metadata.extensions[f"converted_string_{key}"] = converted

            # CRITICAL: Auto-track boolean conversions if detected
            if "boolean_conversion" in differences:
                bool_conv = differences["boolean_conversion"]
                if isinstance(bool_conv, dict) and bool_conv.get("detected"):
                    # Track in boolean_conversions field for round-trip
                    attr_name_for_bool = attribute_name or key
                    metadata.boolean_conversions[attr_name_for_bool] = {
                        "original": bool_conv.get("original", original),
                        "converted": bool_conv.get("converted", converted or ""),
                        "format": f"{context}_auto_detected",
                    }
                    logger.debug(
                        "Boolean conversion auto-tracked",
                        context=context,
                        attribute_name=attribute_name,
                    )

            # CRITICAL: Auto-track soft deletes if detected
            if "soft_delete_detected" in differences:
                soft_del = differences["soft_delete_detected"]
                if isinstance(soft_del, dict) and soft_del.get("detected"):
                    attr_name_for_soft = attribute_name or key
                    if attr_name_for_soft not in metadata.soft_delete_markers:
                        metadata.soft_delete_markers.append(attr_name_for_soft)
                    # Preserve original value in removed_attributes
                    if attr_name_for_soft not in metadata.removed_attributes:
                        metadata.removed_attributes[attr_name_for_soft] = [original]
                    logger.debug(
                        "Soft delete auto-tracked",
                        context=context,
                        attribute_name=attribute_name,
                    )

            # Log differences found
            if differences.get("has_differences", False):
                logger.debug(
                    "Minimal differences tracked",
                    context=context,
                    attribute_name=attribute_name,
                )
        else:
            # No conversion - just preserve original
            pass
