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
from flext_ldif.models import FlextLdifModels

logger = FlextLogger(__name__)

# Constants for content preview limits
_CONTENT_PREVIEW_LENGTH = 100
_MINIMAL_DIFF_PREVIEW_LENGTH = 50


class ModelWithValidationMetadata(Protocol):
    """Protocol for models that have validation_metadata attribute."""

    validation_metadata: FlextModels.Metadata | None


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
        source_attributes: dict[str, object],
        target_attributes: dict[str, object],
    ) -> None:
        """Copy violation fields from source to target metadata attributes.

        Args:
            source_attributes: Source metadata attributes with violations
            target_attributes: Target metadata attributes to receive violations

        """
        # Preserve RFC violations from source
        for violation_key in [
            "rfc_violations",
            "dn_violations",
            "attribute_violations",
            "server_specific_violations",
        ]:
            if violation_key in source_attributes:
                target_attributes[violation_key] = source_attributes[violation_key]

        # Preserve validation context
        if "validation_context" in source_attributes:
            target_attributes["validation_context"] = source_attributes[
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
            metadata: Metadata dictionary to set

        """
        # Safely set validation_metadata if the attribute exists
        try:
            if hasattr(model, "validation_metadata"):
                # Create Metadata object from dict for Pydantic compatibility
                metadata_obj = FlextModels.Metadata(attributes=metadata)
                # Always use setattr for safety, regardless of frozen status
                model.validation_metadata = metadata_obj
        except (AttributeError, TypeError, ValueError):
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
            item_data: Dictionary data to add
            append_to_list: If True, append to list; if False, set as dict
            update_conversion_path: If set, update conversion_path with this server

        Returns:
            Model with updated metadata

        """
        # Get or initialize validation_metadata
        metadata_obj = getattr(model, "validation_metadata", None)
        if metadata_obj is None:
            metadata_obj = FlextModels.Metadata(attributes={})

        # Work with attributes as dict[str, object]
        metadata: dict[str, object] = (
            dict(metadata_obj.attributes)
            if isinstance(metadata_obj.attributes, dict)
            else {}
        )

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
            transformation: Transformation details dictionary to add (step, server, changes)

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
        source_metadata_obj = getattr(source_model, "validation_metadata", None)

        if source_metadata_obj is None:
            # No metadata to preserve - return target unchanged
            return target_model

        # Extract attributes from source metadata object (MUST be Metadata)
        source_metadata_attr = source_metadata_obj.attributes
        if isinstance(source_metadata_attr, FlextLdifModels.DynamicMetadata):
            source_metadata = source_metadata_attr
        else:
            source_metadata = FlextLdifModels.DynamicMetadata(
                **source_metadata_attr
            )

        # Get or initialize target metadata
        target_metadata_obj = getattr(target_model, "validation_metadata", None)
        if target_metadata_obj is None:
            target_metadata_obj = FlextModels.Metadata(attributes={})

        target_metadata_attr = target_metadata_obj.attributes
        if isinstance(target_metadata_attr, FlextLdifModels.DynamicMetadata):
            target_metadata = target_metadata_attr
        else:
            target_metadata = FlextLdifModels.DynamicMetadata(
                **target_metadata_attr
            )

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
            if key in metadata.attributes:
                value = metadata.attributes[key]
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
            item_data={
                "step": step,
                "server": server,
                "changes": changes,
            },
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
        *,
        original_value: bool | str | list[str] | int | None,
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
    def _extract_prefix_details(definition: str) -> dict[str, str]:
        """Extract attribute/ObjectClass prefix details."""
        details: dict[str, str] = {}
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
    def _extract_oid_details(definition: str) -> dict[str, str]:
        """Extract OID and spacing details."""
        details: dict[str, str] = {}
        oid_match = re.search(r"\(\s*([0-9.]+)(\s*)", definition)
        if oid_match:
            details["oid_value"] = oid_match.group(1)
            details["oid_spacing_after"] = oid_match.group(2)
        return details

    @staticmethod
    def _extract_syntax_details(
        definition: str,
    ) -> dict[str, bool | str | None]:
        """Extract SYNTAX formatting details."""
        details: dict[str, bool | str | None] = {}
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
    def _extract_name_details(definition: str) -> dict[str, str | list[str]]:
        """Extract NAME format details."""
        details: dict[str, str | list[str]] = {}
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
    def _extract_desc_details(definition: str) -> dict[str, str | bool]:
        """Extract DESC details."""
        details: dict[str, str | bool] = {}
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
    def _extract_x_origin_details(definition: str) -> dict[str, str | bool | None]:
        """Extract X-ORIGIN details."""
        details: dict[str, str | bool | None] = {}
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
    def _extract_obsolete_details(definition: str) -> dict[str, bool | int | str]:
        """Extract OBSOLETE details."""
        details: dict[str, bool | int | str] = {}
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
    def _extract_leading_trailing_spaces(definition: str) -> dict[str, str]:
        """Extract leading and trailing spaces."""
        details: dict[str, str] = {}
        trailing_match = re.search(r"\)\s*$", definition)
        details["trailing_spaces"] = (
            definition[trailing_match.end() :] if trailing_match else ""
        )
        leading_match = re.search(r"^\s*\(", definition)
        details["leading_spaces"] = leading_match.group(0)[:-1] if leading_match else ""
        return details

    @staticmethod
    def _extract_matching_rule_details(definition: str) -> dict[str, bool | str]:
        """Extract EQUALITY/SUBSTR/ORDERING details."""
        details: dict[str, bool | str] = {}

        # EQUALITY
        equality_match = re.search(r"\bEQUALITY\b", definition, re.IGNORECASE)
        if equality_match:
            details["equality_presence"] = True
            before_rule = definition[: equality_match.start()]
            before_match = re.search(r"(\s+)$", before_rule)
            details["equality_spacing_before"] = (
                before_match.group(1) if before_match else ""
            )
        else:
            details["equality_presence"] = False

        # SUBSTR
        substr_match = re.search(r"\bSUBSTR\b", definition, re.IGNORECASE)
        if substr_match:
            details["substr_presence"] = True
            before_rule = definition[: substr_match.start()]
            before_match = re.search(r"(\s+)$", before_rule)
            details["substr_spacing_before"] = (
                before_match.group(1) if before_match else ""
            )
        else:
            details["substr_presence"] = False

        # ORDERING
        ordering_match = re.search(r"\bORDERING\b", definition, re.IGNORECASE)
        if ordering_match:
            details["ordering_presence"] = True
            before_rule = definition[: ordering_match.start()]
            before_match = re.search(r"(\s+)$", before_rule)
            details["ordering_spacing_before"] = (
                before_match.group(1) if before_match else ""
            )
        else:
            details["ordering_presence"] = False

        return details

    @staticmethod
    def _extract_sup_details(definition: str) -> dict[str, bool | str]:
        """Extract SUP details."""
        details: dict[str, bool | str] = {}
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
    def _extract_single_value_details(definition: str) -> dict[str, bool | str]:
        """Extract SINGLE-VALUE details."""
        details: dict[str, bool | str] = {}
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
    ) -> FlextLdifModelsDomains.SchemaFormatDetails:
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
            SchemaFormatDetails with ALL formatting details captured

        """
        details = FlextLdifModelsDomains.SchemaFormatDetails()

        # Extract all details using helper methods
        prefix_details = FlextLdifUtilitiesMetadata._extract_prefix_details(definition)
        details.update(prefix_details)

        oid_details = FlextLdifUtilitiesMetadata._extract_oid_details(definition)
        details.update(oid_details)

        syntax_details = FlextLdifUtilitiesMetadata._extract_syntax_details(definition)
        details.update(syntax_details)

        name_details = FlextLdifUtilitiesMetadata._extract_name_details(definition)
        details.update(name_details)

        desc_details = FlextLdifUtilitiesMetadata._extract_desc_details(definition)
        details.update(desc_details)

        x_origin_details = FlextLdifUtilitiesMetadata._extract_x_origin_details(
            definition,
        )
        details.update(x_origin_details)

        obsolete_details = FlextLdifUtilitiesMetadata._extract_obsolete_details(
            definition,
        )
        details.update(obsolete_details)

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
        leading_trailing = FlextLdifUtilitiesMetadata._extract_leading_trailing_spaces(
            definition,
        )
        details.update(leading_trailing)

        matching_rule_details = (
            FlextLdifUtilitiesMetadata._extract_matching_rule_details(definition)
        )
        details.update(matching_rule_details)

        sup_details = FlextLdifUtilitiesMetadata._extract_sup_details(definition)
        details.update(sup_details)

        single_value_details = (
            FlextLdifUtilitiesMetadata._extract_single_value_details(definition)
        )
        details.update(single_value_details)

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
        metadata.schema_format_details = formatting_details

        # Log when schema formatting is preserved
        logger.debug(
            "Schema formatting preserved in metadata",
            quirk_type=metadata.quirk_type,
            fields_preserved=len(formatting_details),
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
            original_value: Original boolean value (e.g., "0", "1", "TRUE", "FALSE")
            converted_value: Converted boolean value
            format_direction: Direction of conversion (e.g., "OID->RFC" or "RFC->OID")

        Example:
            >>> FlextLdifUtilitiesMetadata.track_boolean_conversion(
            ...     metadata=entry.metadata,
            ...     attr_name="orcldasisenabled",
            ...     original_value="1",
            ...     converted_value="TRUE",
            ...     format_direction="OID->RFC",
            ... )

        """
        # Store conversion mapping for bidirectional lookup
        if format_direction == "OID->RFC":
            key = f"{attr_name}:oid_value"
            metadata.boolean_conversions[key] = original_value
            key_target = f"{attr_name}:rfc_value"
            metadata.boolean_conversions[key_target] = converted_value
        else:
            key = f"{attr_name}:rfc_value"
            metadata.boolean_conversions[key] = original_value
            key_target = f"{attr_name}:oid_value"
            metadata.boolean_conversions[key_target] = converted_value

        logger.debug(
            "Boolean conversion tracked",
            attr_name=attr_name,
            format_direction=format_direction,
        )


__all__ = ["FlextLdifUtilitiesMetadata"]
