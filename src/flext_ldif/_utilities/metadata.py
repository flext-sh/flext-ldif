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
from typing import Protocol, TypeVar

from flext_core import FlextLogger, FlextModels, FlextRuntime

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels

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

    # =========================================================================
    # UNIFIED PARAMETERIZED METADATA TRACKER
    # =========================================================================

    @staticmethod
    def _track_metadata_item(
        model: ModelT,
        metadata_key: str,
        item_data: dict[str, object],
        *,
        append_to_list: bool = True,
        update_conversion_path: str | None = None,
    ) -> ModelT:
        """Generic helper to track items in model validation_metadata.

        Consolidates common pattern of get-or-init metadata, add item, set back.

        Args:
            model: Model to update
            metadata_key: Key in metadata to update (e.g., "transformations")
            item_data: Data to add
            append_to_list: If True, append to list; if False, set as dict
            update_conversion_path: If set, update conversion_path with this server

        Returns:
            Model with updated metadata

        """
        # Get or initialize validation_metadata
        metadata_obj = getattr(model, "validation_metadata", None)
        if metadata_obj is None:
            metadata_obj = FlextModels.Metadata(attributes={})
        metadata: dict[str, object] = metadata_obj.attributes

        # Initialize key if not present
        if metadata_key not in metadata:
            metadata[metadata_key] = [] if append_to_list else {}

        # Add item with proper type narrowing
        if append_to_list:
            value = metadata[metadata_key]
            if FlextRuntime.is_list_like(value):
                value.append(item_data)
            else:
                metadata[metadata_key] = [item_data]
        else:
            value = metadata[metadata_key]
            if FlextRuntime.is_dict_like(value):
                value.update(item_data)
            else:
                metadata[metadata_key] = item_data

        # Update conversion_path if requested
        if update_conversion_path:
            if "conversion_path" not in metadata:
                metadata["conversion_path"] = update_conversion_path
            else:
                current_path_obj = metadata["conversion_path"]
                if (
                    isinstance(current_path_obj, str)
                    and update_conversion_path not in current_path_obj
                ):
                    metadata["conversion_path"] = (
                        f"{current_path_obj}->{update_conversion_path}"
                    )

        # Set metadata back on model
        FlextLdifUtilitiesMetadata._set_model_metadata(model, metadata)
        return model

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
        target_metadata_obj = getattr(target_model, "validation_metadata", None)
        if target_metadata_obj is None:
            target_metadata_obj = FlextModels.Metadata(attributes={})
        target_metadata: dict[str, object] = target_metadata_obj.attributes

        # Copy violations from source to target
        FlextLdifUtilitiesMetadata._copy_violations_to_target(
            source_metadata,
            target_metadata,
        )

        # Add transformation to history
        if "transformations" not in target_metadata:
            target_metadata["transformations"] = []

        transformations_obj = target_metadata["transformations"]
        if FlextRuntime.is_list_like(transformations_obj):
            transformations_obj.append(transformation)
        else:
            target_metadata["transformations"] = [transformation]

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
        metadata = getattr(model, "validation_metadata", None)
        if metadata is None:
            return []

        # All violation keys to extract from metadata
        violation_keys = ("rfc_violations", "dn_violations", "attribute_violations")
        violations: list[str] = []

        for key in violation_keys:
            if key in metadata:
                value = metadata[key]
                if isinstance(value, list):
                    violations.extend(str(v) for v in value)

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
        return FlextLdifUtilitiesMetadata._track_metadata_item(
            model=model,
            metadata_key="transformations",
            item_data={"step": step, "server": server, "changes": changes},
            update_conversion_path=server,
        )

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
        transformation = FlextLdifModels.AttributeTransformation(
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
    def _extract_prefix_details(definition: str) -> dict[str, object]:
        """Extract attribute/ObjectClass prefix details."""
        details: dict[str, object] = {}
        if "attributetypes:" in definition.lower():
            attr_match = re.search(
                r"(attributetypes|attributeTypes):",
                definition,
                re.IGNORECASE,
            )
            if attr_match:
                details["attribute_case"] = attr_match.group(1)
                colon_pos = definition.find(":")
                if colon_pos >= 0 and colon_pos + 1 < len(definition):
                    after_colon = definition[colon_pos + 1 :]
                    spacing_match = re.match(r"(\s*)", after_colon)
                    if spacing_match:
                        details["attribute_prefix_spacing"] = spacing_match.group(1)
        if "objectclasses:" in definition.lower() or "objectClasses:" in definition:
            oc_match = re.search(
                r"(objectclasses|objectClasses):",
                definition,
                re.IGNORECASE,
            )
            if oc_match:
                details["objectclass_case"] = oc_match.group(1)
                colon_pos = definition.find(":")
                if colon_pos >= 0 and colon_pos + 1 < len(definition):
                    after_colon = definition[colon_pos + 1 :]
                    spacing_match = re.match(r"(\s*)", after_colon)
                    if spacing_match:
                        details["objectclass_prefix_spacing"] = spacing_match.group(1)
        return details

    @staticmethod
    def _extract_oid_details(definition: str) -> dict[str, object]:
        """Extract OID and spacing details."""
        details: dict[str, object] = {}
        oid_match = re.search(r"\(\s*([0-9.]+)(\s*)", definition)
        if oid_match:
            details["oid_value"] = oid_match.group(1)
            details["oid_spacing_after"] = oid_match.group(2)
        return details

    @staticmethod
    def _extract_syntax_details(definition: str) -> dict[str, object]:
        """Extract SYNTAX formatting details."""
        details: dict[str, object] = {}
        syntax_match = re.search(
            r"SYNTAX\s*([\"']?)([0-9.]+)([\"']?)(\{[0-9]+\})?",
            definition,
            re.IGNORECASE,
        )
        if syntax_match:
            details["syntax_quotes"] = bool(
                syntax_match.group(1) or syntax_match.group(3),
            )
            details["syntax_quote_char"] = (
                syntax_match.group(1) or syntax_match.group(3) or ""
            )
            details["syntax_oid"] = syntax_match.group(2)
            details["syntax_length"] = syntax_match.group(4) or None
            syntax_pos = definition.find("SYNTAX")
            if syntax_pos >= 0:
                after_syntax = definition[syntax_pos + 6 :]
                spacing_match = re.match(r"(\s*)", after_syntax)
                if spacing_match:
                    details["syntax_spacing"] = spacing_match.group(1)
                before_syntax = definition[:syntax_pos]
                before_match = re.search(r"(\s+)$", before_syntax)
                details["syntax_spacing_before"] = (
                    before_match.group(1) if before_match else ""
                )
        return details

    @staticmethod
    def _extract_name_details(definition: str) -> dict[str, object]:
        """Extract NAME format details."""
        details: dict[str, object] = {}
        name_match = re.search(
            r"NAME\s+(\()?\s*([\"']?)([^\"'()]+)([\"']?)(\s*\))?",
            definition,
        )
        if name_match:
            has_parens = bool(name_match.group(1))
            name_quote_start = name_match.group(2) or ""
            name_value = name_match.group(3)
            name_quote_end = name_match.group(4) or ""
            multiple_match = re.search(
                r"NAME\s+\(\s*([\"'])([^\"']+)([\"'])\s+([\"'])([^\"']+)([\"'])",
                definition,
            )
            if multiple_match or (has_parens and " " in name_value):
                details["name_format"] = "multiple"
                all_name_matches = re.findall(
                    r"([\"'])([^\"']+)([\"'])",
                    definition[name_match.start() : name_match.end() + 50],
                )
                details["name_values"] = [m[1] for m in all_name_matches]
                details["name_quotes"] = (
                    [m[0] for m in all_name_matches] if all_name_matches else []
                )
                name_section = definition[name_match.start() : name_match.end() + 50]
                name_spacing = re.findall(r"[\"']\s+([\"'])", name_section)
                details["name_spacing_between"] = name_spacing
            else:
                details["name_format"] = "single"
                details["name_values"] = [name_value]
                quote_char = name_quote_start or name_quote_end
                details["name_quotes"] = [quote_char] if quote_char else []
            name_pos = definition.find("NAME")
            if name_pos >= 0:
                before_name = definition[:name_pos]
                before_match = re.search(r"(\s+)$", before_name)
                details["name_spacing_before"] = (
                    before_match.group(1) if before_match else ""
                )
        return details

    @staticmethod
    def _extract_desc_details(definition: str) -> dict[str, object]:
        """Extract DESC details."""
        details: dict[str, object] = {}
        desc_match = re.search(
            r"DESC\s+([\"']?)([^\"']+)([\"']?)",
            definition,
            re.IGNORECASE,
        )
        if desc_match:
            details["desc_presence"] = True
            details["desc_quotes"] = desc_match.group(1) or desc_match.group(3) or ""
            details["desc_value"] = desc_match.group(2)
            desc_pos = definition.find("DESC")
            if desc_pos >= 0:
                before_desc = definition[:desc_pos]
                before_match = re.search(r"(\s+)$", before_desc)
                details["desc_spacing_before"] = (
                    before_match.group(1) if before_match else ""
                )
        else:
            details["desc_presence"] = False
        return details

    @staticmethod
    def _extract_x_origin_details(definition: str) -> dict[str, object]:
        """Extract X-ORIGIN details."""
        details: dict[str, object] = {}
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
            x_origin_pos = definition.find("X-ORIGIN")
            if x_origin_pos >= 0:
                before_x_origin = definition[:x_origin_pos]
                before_match = re.search(r"(\s+)$", before_x_origin)
                details["x_origin_spacing_before"] = (
                    before_match.group(1) if before_match else ""
                )
        else:
            details["x_origin_presence"] = False
            details["x_origin_value"] = None
            details["x_origin_quotes"] = ""
        return details

    @staticmethod
    def _extract_obsolete_details(definition: str) -> dict[str, object]:
        """Extract OBSOLETE details."""
        details: dict[str, object] = {}
        obsolete_match = re.search(r"\bOBSOLETE\b", definition, re.IGNORECASE)
        if obsolete_match:
            details["obsolete_presence"] = True
            details["obsolete_position"] = obsolete_match.start()
            before_obsolete = definition[: obsolete_match.start()]
            before_match = re.search(r"(\s+)$", before_obsolete)
            details["obsolete_spacing_before"] = (
                before_match.group(1) if before_match else ""
            )
        else:
            details["obsolete_presence"] = False
            details["obsolete_position"] = None
        return details

    @staticmethod
    def _extract_field_order(definition: str) -> tuple[list[str], dict[str, int]]:
        """Extract field order and positions."""
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
        return (field_order, field_positions)

    @staticmethod
    def _extract_spacing_between_fields(
        definition: str,
        field_order: list[str],
        field_positions: dict[str, int],
        field_patterns: dict[str, str],
    ) -> dict[str, str]:
        """Extract spacing between fields."""
        spacing_between: dict[str, str] = {}
        for i in range(len(field_order) - 1):
            field1 = field_order[i]
            field2 = field_order[i + 1]
            pos1 = field_positions.get(field1)
            pos2 = field_positions.get(field2)
            if pos1 is not None and pos2 is not None:
                field1_end_match = re.search(
                    field_patterns[field1],
                    definition[pos1:],
                    re.IGNORECASE,
                )
                if field1_end_match:
                    field1_end = pos1 + field1_end_match.end()
                    spacing = definition[field1_end:pos2]
                    spacing_between[f"{field1}_{field2}"] = spacing
        return spacing_between

    @staticmethod
    def _extract_leading_trailing_spaces(definition: str) -> dict[str, object]:
        """Extract leading and trailing spaces."""
        details: dict[str, object] = {}
        trailing_match = re.search(r"\)\s*$", definition)
        details["trailing_spaces"] = (
            definition[trailing_match.end() :] if trailing_match else ""
        )
        leading_match = re.search(r"^\s*\(", definition)
        details["leading_spaces"] = leading_match.group(0)[:-1] if leading_match else ""
        return details

    @staticmethod
    def _extract_matching_rule_details(definition: str) -> dict[str, object]:
        """Extract EQUALITY/SUBSTR/ORDERING details."""
        details: dict[str, object] = {}
        for rule_name in ["EQUALITY", "SUBSTR", "ORDERING"]:
            rule_match = re.search(rf"\b{rule_name}\b", definition, re.IGNORECASE)
            if rule_match:
                details[f"{rule_name.lower()}_presence"] = True
                before_rule = definition[: rule_match.start()]
                before_match = re.search(r"(\s+)$", before_rule)
                details[f"{rule_name.lower()}_spacing_before"] = (
                    before_match.group(1) if before_match else ""
                )
            else:
                details[f"{rule_name.lower()}_presence"] = False
        return details

    @staticmethod
    def _extract_sup_details(definition: str) -> dict[str, object]:
        """Extract SUP details."""
        details: dict[str, object] = {}
        sup_match = re.search(r"SUP\s+([^\s]+)", definition, re.IGNORECASE)
        if sup_match:
            details["sup_presence"] = True
            details["sup_value"] = sup_match.group(1)
            sup_pos = definition.find("SUP")
            if sup_pos >= 0:
                before_sup = definition[:sup_pos]
                before_match = re.search(r"(\s+)$", before_sup)
                details["sup_spacing_before"] = (
                    before_match.group(1) if before_match else ""
                )
        else:
            details["sup_presence"] = False
        return details

    @staticmethod
    def _extract_single_value_details(definition: str) -> dict[str, object]:
        """Extract SINGLE-VALUE details."""
        details: dict[str, object] = {}
        single_value_match = re.search(r"SINGLE-VALUE", definition, re.IGNORECASE)
        if single_value_match:
            details["single_value_presence"] = True
            before_sv = definition[: single_value_match.start()]
            before_match = re.search(r"(\s+)$", before_sv)
            details["single_value_spacing_before"] = (
                before_match.group(1) if before_match else ""
            )
        else:
            details["single_value_presence"] = False
        return details

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

        """
        details: dict[str, object] = {"original_string_complete": definition}

        # Extract all details using helper methods
        details.update(FlextLdifUtilitiesMetadata._extract_prefix_details(definition))
        details.update(FlextLdifUtilitiesMetadata._extract_oid_details(definition))
        details.update(FlextLdifUtilitiesMetadata._extract_syntax_details(definition))
        details.update(FlextLdifUtilitiesMetadata._extract_name_details(definition))
        details.update(FlextLdifUtilitiesMetadata._extract_desc_details(definition))
        details.update(FlextLdifUtilitiesMetadata._extract_x_origin_details(definition))
        details.update(FlextLdifUtilitiesMetadata._extract_obsolete_details(definition))

        # Extract field order and spacing
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
        field_order, field_positions = FlextLdifUtilitiesMetadata._extract_field_order(
            definition,
        )
        details["field_order"] = field_order
        details["field_positions"] = field_positions
        details["spacing_between_fields"] = (
            FlextLdifUtilitiesMetadata._extract_spacing_between_fields(
                definition,
                field_order,
                field_positions,
                field_patterns,
            )
        )

        # Extract remaining details
        details.update(
            FlextLdifUtilitiesMetadata._extract_leading_trailing_spaces(definition),
        )
        details.update(
            FlextLdifUtilitiesMetadata._extract_matching_rule_details(definition),
        )
        details.update(FlextLdifUtilitiesMetadata._extract_sup_details(definition))
        details.update(
            FlextLdifUtilitiesMetadata._extract_single_value_details(definition),
        )

        # Log all captured deviations at DEBUG level
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
            definition,
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
        original_entry: FlextLdifModels.Entry,
        converted_entry: FlextLdifModels.Entry,
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
            converted_entry.metadata.attribute_transformations.keys(),
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
        entry: FlextLdifModels.Entry,
        target_server: str,
    ) -> FlextLdifModels.Entry:
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
                attr_name.lower(),
                attr_name,
            )
            new_attrs[original_case] = values
        entry.attributes.attributes = new_attrs

        return entry

    @staticmethod
    def _categorize_char_difference(
        orig_char: str | None,
        conv_char: str | None,
        position: int,
        spacing_removed: list[int],
        spacing_added: list[int],
        case_changes: list[dict[str, object]],
        punctuation_changes: list[dict[str, object]],
        differences: dict[str, object],
    ) -> dict[str, object]:
        """Categorize difference between two characters."""
        diff_entry: dict[str, object] = {
            "position": position,
            "original": orig_char,
            "converted": conv_char,
        }

        if orig_char == " " and conv_char != " ":
            spacing_removed.append(position)
            diff_entry["type"] = "spacing_removed"
        elif orig_char != " " and conv_char == " ":
            spacing_added.append(position)
            diff_entry["type"] = "spacing_added"
        elif orig_char and conv_char and orig_char.lower() == conv_char.lower():
            case_changes.append(
                {
                    "position": position,
                    "original": orig_char,
                    "converted": conv_char,
                },
            )
            diff_entry["type"] = "case_change"
        elif (
            orig_char
            and conv_char
            and orig_char in ",;:()[]{}"
            and conv_char in ",;:()[]{}"
        ):
            punctuation_changes.append(
                {
                    "position": position,
                    "original": orig_char,
                    "converted": conv_char,
                },
            )
            diff_entry["type"] = "punctuation_change"
        elif orig_char is None:
            diff_entry["type"] = "added"
            added_chars_obj = differences.get("added_chars", [])
            if FlextRuntime.is_list_like(added_chars_obj):
                added_chars_obj.append({"position": position, "char": conv_char})
            else:
                differences["added_chars"] = [{"position": position, "char": conv_char}]
        elif conv_char is None:
            diff_entry["type"] = "removed"
            missing_chars_obj = differences.get("missing_chars", [])
            if FlextRuntime.is_list_like(missing_chars_obj):
                missing_chars_obj.append({"position": position, "char": orig_char})
            else:
                differences["missing_chars"] = [
                    {"position": position, "char": orig_char},
                ]
        else:
            diff_entry["type"] = "character_change"

        return diff_entry

    @staticmethod
    def _compare_char_by_char(
        original: str,
        converted: str,
        differences: dict[str, object],
    ) -> tuple[
        list[dict[str, object]],
        list[int],
        list[int],
        list[dict[str, object]],
        list[dict[str, object]],
    ]:
        """Compare strings character by character."""
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
                diff_entry = FlextLdifUtilitiesMetadata._categorize_char_difference(
                    orig_char,
                    conv_char,
                    i,
                    spacing_removed,
                    spacing_added,
                    case_changes,
                    punctuation_changes,
                    differences,
                )
                char_differences.append(diff_entry)

        return (
            char_differences,
            spacing_removed,
            spacing_added,
            case_changes,
            punctuation_changes,
        )

    @staticmethod
    def _analyze_leading_trailing_spaces(
        original: str,
        converted: str | None,
    ) -> dict[str, object]:
        """Analyze leading and trailing spaces."""
        details: dict[str, object] = {}
        details["leading_spaces_original"] = len(original) - len(original.lstrip())
        details["trailing_spaces_original"] = len(original) - len(original.rstrip())
        details["leading_spaces_converted"] = (
            len(converted) - len(converted.lstrip()) if converted else 0
        )
        details["trailing_spaces_converted"] = (
            len(converted) - len(converted.rstrip()) if converted else 0
        )
        return details

    @staticmethod
    def _analyze_punctuation_counts(
        original: str,
        converted: str | None,
    ) -> dict[str, object]:
        """Analyze punctuation count differences."""
        details: dict[str, object] = {}
        punctuation_map: dict[str, dict[str, int]] = {}
        for char in ",;:()[]{}":
            orig_count = original.count(char)
            conv_count = converted.count(char) if converted else 0
            if orig_count != conv_count:
                punctuation_map[char] = {
                    "original": orig_count,
                    "converted": conv_count,
                }
        if punctuation_map:
            details["punctuation_counts"] = punctuation_map
        return details

    @staticmethod
    def _analyze_quote_counts(
        original: str,
        converted: str | None,
    ) -> dict[str, object]:
        """Analyze quote count differences."""
        details: dict[str, object] = {}
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
            details["quote_analysis"] = quote_analysis
        return details

    @staticmethod
    def _analyze_case_change_details(
        original: str,
        case_changes: list[dict[str, object]],
    ) -> dict[str, object]:
        """Analyze case change details with context."""
        details: dict[str, object] = {}
        case_change_details: list[dict[str, object]] = []
        for case_change in case_changes:
            pos_obj = case_change.get("position", -1)
            orig_char_obj = case_change.get("original", "")
            conv_char_obj = case_change.get("converted", "")
            pos = pos_obj if isinstance(pos_obj, int) else -1
            orig_char = orig_char_obj if isinstance(orig_char_obj, str) else ""
            conv_char = conv_char_obj if isinstance(conv_char_obj, str) else ""
            if orig_char and conv_char and orig_char.lower() == conv_char.lower():
                context_before_start = max(0, pos - 5) if pos >= 0 else 0
                context_before_end = max(pos, 0)
                context_after_start = (
                    pos + 1 if pos >= 0 and pos + 1 < len(original) else len(original)
                )
                context_after_end = (
                    pos + 6 if pos >= 0 and pos + 6 < len(original) else len(original)
                )
                case_change_details.append(
                    {
                        "position": pos,
                        "original": orig_char,
                        "converted": conv_char,
                        "context_before": original[
                            context_before_start:context_before_end
                        ],
                        "context_after": original[
                            context_after_start:context_after_end
                        ],
                    },
                )
        if case_change_details:
            details["case_change_details"] = case_change_details
        return details

    @staticmethod
    def _detect_boolean_conversions(
        original: str,
        converted: str | None,
        context: str,
    ) -> dict[str, object]:
        """Detect boolean conversions automatically."""
        details: dict[str, object] = {}
        boolean_patterns = {
            ("0", "FALSE"): "boolean_false_conversion",
            ("1", "TRUE"): "boolean_true_conversion",
            ("FALSE", "0"): "boolean_false_reverse",
            ("TRUE", "1"): "boolean_true_reverse",
        }

        original_upper = original.upper().strip()
        converted_upper = converted.upper().strip() if converted else ""

        for (orig_pattern, conv_pattern), conversion_type in boolean_patterns.items():
            if original_upper == orig_pattern and converted_upper == conv_pattern:
                details["boolean_conversion"] = {
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

        if original and (not converted or not converted.strip()):
            details["soft_delete_detected"] = {
                "detected": True,
                "original": original,
                "converted": converted or "",
            }
            logger.debug(
                "Soft delete pattern detected",
                context=context,
            )

        return details

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
        mk = FlextLdifConstants.MetadataKeys
        differences: dict[str, object] = {
            mk.HAS_DIFFERENCES: False,
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

        differences[mk.HAS_DIFFERENCES] = True

        # Character-by-character comparison using helper method
        (
            char_differences,
            spacing_removed,
            spacing_added,
            case_changes,
            punctuation_changes,
        ) = FlextLdifUtilitiesMetadata._compare_char_by_char(
            original,
            converted,
            differences,
        )

        differences["differences"] = char_differences
        differences["spacing_changes"] = {
            "removed_positions": spacing_removed,
            "added_positions": spacing_added,
            "removed_count": len(spacing_removed),
            "added_count": len(spacing_added),
        }
        differences["case_changes"] = case_changes
        differences["punctuation_changes"] = punctuation_changes

        # Analyze additional details using helper methods
        differences.update(
            FlextLdifUtilitiesMetadata._analyze_leading_trailing_spaces(
                original,
                converted,
            ),
        )
        differences.update(
            FlextLdifUtilitiesMetadata._analyze_punctuation_counts(original, converted),
        )
        differences.update(
            FlextLdifUtilitiesMetadata._analyze_quote_counts(original, converted),
        )
        differences.update(
            FlextLdifUtilitiesMetadata._analyze_case_change_details(
                original,
                case_changes,
            ),
        )
        differences.update(
            FlextLdifUtilitiesMetadata._detect_boolean_conversions(
                original,
                converted,
                context,
            ),
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
    def _auto_track_conversions(
        metadata: FlextLdifModelsDomains.QuirkMetadata,
        differences: dict[str, object],
        original: str,
        converted: str | None,
        context: str,
        attribute_name: str | None,
        key: str,
    ) -> None:
        """Auto-track boolean conversions and soft deletes from differences."""
        if "boolean_conversion" in differences:
            bool_conv = differences["boolean_conversion"]
            if FlextRuntime.is_dict_like(bool_conv) and bool_conv.get("detected"):
                attr_name_for_bool = attribute_name or key
                # Type narrowing: ensure dict values are str for boolean_conversions
                bool_conv_dict: dict[str, str] = {
                    "original": str(bool_conv.get("original", original)),
                    "converted": str(bool_conv.get("converted", converted or "")),
                    "format": f"{context}_auto_detected",
                }
                metadata.boolean_conversions[attr_name_for_bool] = bool_conv_dict
                logger.debug(
                    "Boolean conversion auto-tracked",
                    context=context,
                    attribute_name=attribute_name,
                )

        if "soft_delete_detected" in differences:
            soft_del = differences["soft_delete_detected"]
            if FlextRuntime.is_dict_like(soft_del) and soft_del.get("detected"):
                attr_name_for_soft = attribute_name or key
                if attr_name_for_soft not in metadata.soft_delete_markers:
                    metadata.soft_delete_markers.append(attr_name_for_soft)
                if attr_name_for_soft not in metadata.removed_attributes:
                    metadata.removed_attributes[attr_name_for_soft] = [original]
                logger.debug(
                    "Soft delete auto-tracked",
                    context=context,
                    attribute_name=attribute_name,
                )

    @staticmethod
    def store_minimal_differences(
        metadata: FlextLdifModelsDomains.QuirkMetadata,
        dn_differences: dict[str, object],
        attribute_differences: dict[str, dict[str, object]],
        original_dn: str,
        parsed_dn: str | None,
        *,
        original_attributes_complete: dict[str, object] | None = None,
        original_dn_line: str | None = None,
        original_attr_lines: list[str] | None = None,
    ) -> None:
        """Store minimal differences in entry metadata (consolidated utility).

        Handles both DN and attribute difference tracking in one call.
        Used by OID, OUD, and other server quirks.

        Args:
            metadata: QuirkMetadata to update
            dn_differences: DN difference analysis from analyze_differences
            attribute_differences: Attribute difference analysis
            original_dn: Original DN string
            parsed_dn: Parsed/normalized DN value
            original_attributes_complete: Optional complete original attrs (for OID)
            original_dn_line: Optional original DN line from LDIF
            original_attr_lines: Optional original attribute lines from LDIF

        """
        if not metadata.extensions:
            metadata.extensions = {}

        # Store complete data in extensions using FlextLdifConstants.MetadataKeys
        # This ensures consistent key names across all server implementations
        mk = FlextLdifConstants.MetadataKeys
        metadata.extensions[mk.MINIMAL_DIFFERENCES_DN] = dn_differences
        metadata.extensions[mk.MINIMAL_DIFFERENCES_ATTRIBUTES] = attribute_differences
        if original_attributes_complete:
            metadata.extensions[mk.ORIGINAL_DN_COMPLETE] = original_dn
            metadata.extensions[mk.ORIGINAL_ATTRIBUTES_COMPLETE] = (
                original_attributes_complete
            )
        if original_dn_line is not None:
            metadata.extensions[mk.ORIGINAL_DN_LINE_COMPLETE] = original_dn_line
        if original_attr_lines is not None:
            metadata.extensions[mk.ORIGINAL_ATTR_LINES_COMPLETE] = original_attr_lines

        # Track DN differences
        if dn_differences.get(mk.HAS_DIFFERENCES):
            FlextLdifUtilitiesMetadata.track_minimal_differences_in_metadata(
                metadata=metadata,
                original=original_dn,
                converted=parsed_dn if parsed_dn and parsed_dn != original_dn else None,
                context="dn",
                attribute_name="dn",
            )

        # Track attribute differences
        for attr_name, attr_diff in attribute_differences.items():
            if attr_diff.get(mk.HAS_DIFFERENCES, False):
                original_attr_str = attr_diff.get("original", "")
                converted = attr_diff.get("converted")
                converted_attr_str = str(converted) if converted else None
                if isinstance(original_attr_str, str):
                    FlextLdifUtilitiesMetadata.track_minimal_differences_in_metadata(
                        metadata=metadata,
                        original=original_attr_str,
                        converted=converted_attr_str,
                        context="attribute",
                        attribute_name=attr_name,
                    )

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
        mk = FlextLdifConstants.MetadataKeys
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
                original=original,
                converted=converted,
                context=context,
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

            # Auto-track boolean conversions and soft deletes using helper method
            FlextLdifUtilitiesMetadata._auto_track_conversions(
                metadata,
                differences,
                original,
                converted,
                context,
                attribute_name,
                key,
            )

            # Log differences found
            if differences.get(mk.HAS_DIFFERENCES, False):
                logger.debug(
                    "Minimal differences tracked",
                    context=context,
                    attribute_name=attribute_name,
                )
        else:
            # No conversion - just preserve original
            pass

    @staticmethod
    def build_entry_metadata_extensions(
        entry_dn: str,
        original_attributes: dict[str, list[str]],
        processed_attributes: dict[str, list[str]],
        server_type: str,
        metadata_keys: type[FlextLdifConstants.MetadataKeys],
        operational_attributes: list[str] | None = None,
    ) -> dict[str, object]:
        """Build generic metadata extensions dict for bidirectional server conversion.

        Creates a standardized metadata extensions dictionary with SOURCE/TARGET
        values for converting between LDAP servers. Parametrizable for any server.

        Args:
            entry_dn: Entry Distinguished Name
            original_attributes: Original attributes from source server
            processed_attributes: Processed attributes after transformation
            server_type: Source server type (e.g., "oid", "oud", "openldap")
            metadata_keys: FlextLdifConstants.MetadataKeys for key constants
            operational_attributes: List of operational attribute names (optional)

        Returns:
            Dictionary with CORE, SOURCE, and TARGET metadata entries

        Example:
            >>> extensions = FlextLdifUtilitiesMetadata.build_entry_metadata_extensions(
            ...     entry_dn="cn=test,dc=example,dc=com",
            ...     original_attributes={"cn": ["test"], "objectClass": ["person"]},
            ...     processed_attributes={"cn": ["test"], "objectClass": ["person"]},
            ...     server_type="oud",
            ...     metadata_keys=FlextLdifConstants.MetadataKeys,
            ...     operational_attributes=["modifyTimestamp", "creatorsName"],
            ... )

        """
        # Build metadata extensions dict with CORE entry metadata
        metadata_extensions: dict[str, object] = {
            # CORE ENTRY METADATA (required for ALL servers)
            metadata_keys.ENTRY_SOURCE_SERVER: server_type,
            metadata_keys.ENTRY_ORIGINAL_FORMAT: f"{server_type.upper()} Entry (RFC-compliant)",
            # SOURCE values (original format BEFORE transformation)
            metadata_keys.ENTRY_SOURCE_DN_CASE: entry_dn,
            metadata_keys.ENTRY_SOURCE_ATTRIBUTES: list(original_attributes.keys()),
            metadata_keys.ENTRY_SOURCE_OBJECTCLASSES: original_attributes.get(
                "objectClass",
                [],
            ),
            # TARGET values (RFC format AFTER transformation)
            # For RFC-compliant servers (OUD, OpenLDAP): TARGET == SOURCE
            metadata_keys.ENTRY_TARGET_DN_CASE: entry_dn,
            metadata_keys.ENTRY_TARGET_ATTRIBUTES: list(processed_attributes.keys()),
            metadata_keys.ENTRY_TARGET_OBJECTCLASSES: processed_attributes.get(
                "objectClass",
                [],
            ),
            # Operational attributes tracking
            metadata_keys.ENTRY_SOURCE_OPERATIONAL_ATTRS: [
                attr
                for attr in original_attributes
                if (
                    operational_attributes
                    and attr.lower()
                    in {a.lower() for a in operational_attributes}
                )
            ]
            if operational_attributes
            else [],
            # Attribute conversions tracking (empty for RFC-compliant servers)
            metadata_keys.CONVERTED_ATTRIBUTES: {
                "attribute_name_conversions": {},
                "boolean_conversions": {},
            },
        }

        return metadata_extensions

    @staticmethod
    def build_rfc_compliance_metadata(
        rfc_violations: list[str],
        attribute_conflicts: list[dict[str, object]],
        boolean_conversions: dict[str, dict[str, list[str] | str]],
        converted_attributes: dict[str, list[str]],
        original_entry: FlextLdifModels.Entry,
        entry_dn: str,
    ) -> dict[str, object]:
        """Build RFC compliance metadata with violation details.

        Generic utility for tracking RFC violations during server-to-RFC conversion.
        Parametrizable for any LDAP server type.

        Args:
            rfc_violations: List of RFC violations
            attribute_conflicts: List of attribute conflicts
            boolean_conversions: Boolean conversion details
            converted_attributes: Converted attributes mapping
            original_entry: Original entry model before conversion
            entry_dn: Entry DN for logging

        Returns:
            RFC compliance metadata dictionary

        """
        if not (rfc_violations or attribute_conflicts or boolean_conversions):
            return {}

        # Extract original attributes from Entry model
        original_attributes: dict[str, list[str]] = (
            original_entry.attributes.attributes if original_entry.attributes else {}
        )

        rfc_compliance_metadata: dict[str, object] = {
            "rfc_violations": rfc_violations,
            "attribute_conflicts": attribute_conflicts,
            "has_rfc_violations": True,
            "attribute_value_changes": boolean_conversions or {},
            "attribute_value_changes_count": len(boolean_conversions),
        }

        if rfc_violations or attribute_conflicts:
            # Build violation details (type, description, severity)
            violation_details: list[dict[str, object]] = [
                {"type": "rfc_violation", "description": v, "severity": "warning"}
                for v in rfc_violations
            ]

            # Add conflict details
            for conflict in attribute_conflicts:
                attr_name = str(conflict.get("attribute", "unknown"))
                original_values = original_attributes.get(attr_name, [])
                was_removed = attr_name not in converted_attributes
                violation_details.append({
                    "type": "attribute_conflict",
                    "attribute": attr_name,
                    "reason": str(conflict.get("reason", "Unknown conflict")),
                    "conflicting_objectclass": str(
                        conflict.get("conflicting_objectclass", ""),
                    ),
                    "original_values": original_values,
                    "conflict_values": conflict.get("values", []),
                    "was_removed": was_removed,
                    "action_taken": "removed" if was_removed else "kept_with_warning",
                    "original_values_string": str(original_values),
                    "conflict_values_string": str(conflict.get("values", [])),
                })

            # Calculate removed attributes
            original_attr_set = set(original_attributes.keys())
            final_attr_set = set(converted_attributes.keys())
            removed_attrs = list(original_attr_set - final_attr_set)

            logger.debug(
                "Entry converted with RFC adjustments",
                entry_dn=entry_dn,
                violations_count=len(rfc_violations),
                violations=rfc_violations or None,
                attributes_removed=removed_attrs or None,
                boolean_conversions=len(boolean_conversions),
            )

        return rfc_compliance_metadata

    @staticmethod
    def build_original_format_details(
        original_dn: str,
        cleaned_dn: str,
        converted_attrs: set[str],
        boolean_conversions: dict[str, dict[str, list[str] | str]],
        converted_attributes: dict[str, list[str]],
        original_attributes: dict[str, list[str]],
        server_type: str,
        original_dn_line: str | None = None,
        original_attr_lines: list[str] | None = None,
    ) -> dict[str, object]:
        """Build original format details for round-trip support.

        Generic utility for preserving original format during server conversion.
        Parametrizable for any LDAP server type (OID, OUD, OpenLDAP, etc.).

        Args:
            original_dn: Original DN before cleaning
            cleaned_dn: Cleaned DN after normalization
            converted_attrs: Set of converted boolean attributes
            boolean_conversions: Boolean conversion details
            converted_attributes: Converted attributes mapping
            original_attributes: Original attributes before conversion
            server_type: Server type (e.g., "oid", "oud")
            original_dn_line: Original DN line from parser (optional)
            original_attr_lines: Original attribute lines from parser (optional)

        Returns:
            Original format details dictionary for round-trip support

        """
        # Attribute name conversion detection (generic pattern)
        attr_name_conversions: dict[str, str | None] = {}
        for orig_attr in original_attributes:
            for conv_attr in converted_attributes:
                if (
                    orig_attr.lower() != conv_attr.lower()
                    and orig_attr not in converted_attributes
                    and conv_attr not in original_attributes
                ):
                    # Potential rename detected
                    attr_name_conversions[orig_attr] = conv_attr
                    break

        return {
            "dn_spacing": original_dn,
            "dn_cleaned": cleaned_dn,
            "dn_was_modified": original_dn != cleaned_dn,
            "boolean_format": "0/1" if boolean_conversions else "RFC",
            "server_type": server_type,
            "original_dn_line": original_dn_line,
            "original_attr_lines": original_attr_lines or [],
            "original_attributes_dict": {
                k: list(v) if isinstance(v, (list, tuple)) else [str(v)] if v else []
                for k, v in original_attributes.items()
            },
            "converted_attributes_dict": converted_attributes,
            "all_conversions": {
                "boolean_attributes": list(converted_attrs),
                "boolean_conversions": boolean_conversions,
                "attribute_name_conversions": attr_name_conversions,
            },
            "removed_attributes": list(
                set(original_attributes.keys()) - set(converted_attributes.keys()),
            ),
            "removed_attributes_count": len(
                set(original_attributes.keys()) - set(converted_attributes.keys()),
            ),
        }

    @staticmethod
    def build_entry_parse_metadata(
        quirk_type: str,
        original_entry_dn: str,
        cleaned_dn: str,
        original_dn_line: str | None,
        original_attr_lines: list[str],
        dn_was_base64: bool,
        original_attribute_case: dict[str, str],
        dn_differences: dict[str, object],
        attribute_differences: dict[str, dict[str, object]],
        original_attributes_complete: dict[str, object],
    ) -> FlextLdifModels.QuirkMetadata:
        """Build QuirkMetadata with format details AND track differences (DRY utility).

        Consolidates metadata creation AND difference tracking for reuse across servers.
        Uses FlextLdifConstants.Rfc.META_* and MetadataKeys for standardized keys.

        RFC Compliance: Tracks all original data for round-trip conversions.

        Args:
            quirk_type: Server quirk type (e.g., "rfc", "oid", "oud")
            original_entry_dn: Original DN before cleaning
            cleaned_dn: Cleaned DN after normalization
            original_dn_line: Original DN line from parser
            original_attr_lines: Original attribute lines from parser
            dn_was_base64: Whether DN was base64 encoded
            original_attribute_case: Original attribute case mapping
            dn_differences: DN differences from analyze_differences
            attribute_differences: Attribute differences from analyze_differences
            original_attributes_complete: Original attributes complete dict

        Returns:
            QuirkMetadata with format details and tracked differences

        """
        from flext_ldif import FlextLdifConstants

        mk = FlextLdifConstants.MetadataKeys
        metadata = FlextLdifModels.QuirkMetadata(
            quirk_type=quirk_type,
            original_server_type=quirk_type,
            original_format_details={
                FlextLdifConstants.Rfc.META_TRANSFORMATION_SOURCE: quirk_type,
                "dn_spacing": original_entry_dn,
                FlextLdifConstants.Rfc.META_DN_WAS_BASE64: dn_was_base64,
                "original_dn_line": original_dn_line,
                "original_attr_lines": original_attr_lines,
                FlextLdifConstants.Rfc.META_DN_ORIGINAL: original_entry_dn,
            },
            original_attribute_case=original_attribute_case,
        )

        # Store minimal differences using constants for standardized keys
        if not metadata.extensions:
            metadata.extensions = {}

        # Use standardized metadata keys from FlextLdifConstants
        metadata.extensions[
            FlextLdifConstants.MetadataKeys.ENTRY_SOURCE_DN_CASE
        ] = original_entry_dn
        metadata.extensions[
            FlextLdifConstants.MetadataKeys.ENTRY_TARGET_DN_CASE
        ] = cleaned_dn
        metadata.extensions["minimal_differences_dn"] = dn_differences
        metadata.extensions["minimal_differences_attributes"] = attribute_differences
        metadata.extensions[
            FlextLdifConstants.MetadataKeys.ENTRY_SOURCE_ATTRIBUTES
        ] = original_attributes_complete
        metadata.extensions["original_dn_line_complete"] = original_dn_line
        metadata.extensions["original_attr_lines_complete"] = original_attr_lines

        # Store original strings for round-trip using new tracking methods
        metadata.original_strings[FlextLdifConstants.Rfc.META_DN_ORIGINAL] = (
            original_entry_dn
        )
        if original_dn_line:
            metadata.original_strings["entry_original_dn_line"] = original_dn_line

        # Track DN transformation if there are differences
        if dn_differences.get(mk.HAS_DIFFERENCES) and original_entry_dn != cleaned_dn:
            metadata.track_dn_transformation(
                original_dn=original_entry_dn,
                transformed_dn=cleaned_dn,
                transformation_type="normalized",
                was_base64=dn_was_base64,
            )

        # Track attribute differences
        for attr_name, attr_diff in attribute_differences.items():
            if attr_diff.get(mk.HAS_DIFFERENCES, False):
                original_attr_str = attr_diff.get("original", "")
                converted = attr_diff.get("converted")
                FlextLdifUtilitiesMetadata.track_minimal_differences_in_metadata(
                    metadata=metadata,
                    original=str(original_attr_str),
                    converted=str(converted) if converted else None,
                    context="attribute",
                    attribute_name=attr_name,
                )

        return metadata

    # =========================================================================
    # METADATA EXTRACTION HELPERS (for writing)
    # =========================================================================

    @staticmethod
    def get_original_attr_lines_from_metadata(
        entry_metadata: FlextLdifModelsDomains.QuirkMetadata | None,
    ) -> list[str] | None:
        """Get original attribute lines from entry metadata.

        Extracts original LDIF attribute lines for round-trip fidelity.
        Checks both original_format_details and extensions.

        Args:
            entry_metadata: Entry QuirkMetadata (can be None)

        Returns:
            List of original attribute lines or None if not found

        """
        if not entry_metadata:
            return None

        # Check original_format_details first
        original_attr_lines = None
        if entry_metadata.original_format_details:
            original_attr_lines = entry_metadata.original_format_details.get(
                "original_attr_lines",
                [],
            )

        # Try to get complete original lines from extensions
        if entry_metadata.extensions:
            orig_lines = entry_metadata.extensions.get(
                "original_attr_lines_complete",
            )
            if FlextRuntime.is_list_like(orig_lines):
                return [str(item) for item in orig_lines]
            if original_attr_lines and FlextRuntime.is_list_like(original_attr_lines):
                return [str(item) for item in original_attr_lines]

        return None

    @staticmethod
    def extract_original_lines_from_entry(
        entry_metadata: FlextLdifModelsDomains.QuirkMetadata | None,
    ) -> tuple[str | None, list[str] | None]:
        """Extract both original DN line and attribute lines from entry metadata.

        Consolidated utility for OID/OUD/RFC round-trip support.
        Extracts from original_format_details with proper type conversion.

        Args:
            entry_metadata: Entry QuirkMetadata (can be None)

        Returns:
            Tuple of (original_dn_line, original_attr_lines)

        """
        if not entry_metadata or not entry_metadata.original_format_details:
            return None, None

        # Extract original DN line with type-safe conversion
        original_dn_line: str | None = None
        original_dn_line_raw = entry_metadata.original_format_details.get(
            "original_dn_line",
        )
        if original_dn_line_raw is not None:
            original_dn_line = str(original_dn_line_raw)

        # Extract original attribute lines with type-safe conversion
        original_attr_lines: list[str] | None = None
        orig_attr_lines = entry_metadata.original_format_details.get(
            "original_attr_lines",
        )
        if FlextRuntime.is_list_like(orig_attr_lines):
            if not isinstance(orig_attr_lines, list):
                msg = f"Expected list, got {type(orig_attr_lines)}"
                raise TypeError(msg)
            original_attr_lines = [str(line) for line in orig_attr_lines]

        return original_dn_line, original_attr_lines

    @staticmethod
    def get_minimal_differences_from_metadata(
        entry_metadata: FlextLdifModelsDomains.QuirkMetadata | None,
    ) -> dict[str, object]:
        """Get minimal differences for attributes from metadata.

        Extracts attribute-level minimal differences for round-trip fidelity.
        Checks both minimal_differences and extensions.

        Args:
            entry_metadata: Entry QuirkMetadata (can be None)

        Returns:
            Dictionary of minimal differences (empty dict if not found)

        """
        if not entry_metadata:
            return {}

        if entry_metadata.minimal_differences:
            minimal_diffs = entry_metadata.minimal_differences
            # Ensure return type is dict[str, object]
            if FlextRuntime.is_dict_like(minimal_diffs):
                return dict(minimal_diffs)
            return {}

        if entry_metadata.extensions:
            attr_diffs = entry_metadata.extensions.get(
                "minimal_differences_attributes",
                {},
            )
            if FlextRuntime.is_dict_like(attr_diffs):
                return attr_diffs

        return {}
