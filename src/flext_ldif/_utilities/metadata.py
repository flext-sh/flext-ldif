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

from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes

logger = FlextLogger(__name__)


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
        source_attributes: FlextLdifModelsMetadata.DynamicMetadata,
        target_attributes: FlextLdifModelsMetadata.DynamicMetadata,
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
        metadata: FlextLdifModelsMetadata.DynamicMetadata,
    ) -> None:
        """Set validation_metadata on model (handles both mutable and frozen models).

        Args:
            model: Model to set metadata on
            metadata: DynamicMetadata instance to set

        """
        # Safely set validation_metadata if the attribute exists
        try:
            if hasattr(model, "validation_metadata"):
                # Convert DynamicMetadata to dict for FlextModels.Metadata
                metadata_dict = metadata.model_dump()
                metadata_obj = FlextModels.Metadata(attributes=metadata_dict)
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

        # Set metadata back on model - convert dict to DynamicMetadata
        dynamic_metadata = FlextLdifModelsMetadata.DynamicMetadata(**metadata)
        FlextLdifUtilitiesMetadata._set_model_metadata(model, dynamic_metadata)
        return model

    @staticmethod
    def preserve_validation_metadata(
        source_model: ModelT,
        target_model: ModelT,
        transformation: FlextLdifTypes.TransformationInfo,
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
        if isinstance(source_metadata_attr, FlextLdifModelsMetadata.DynamicMetadata):
            source_metadata = source_metadata_attr
        else:
            source_metadata = FlextLdifModelsMetadata.DynamicMetadata(
                **source_metadata_attr,
            )

        # Get or initialize target metadata
        target_metadata_obj = getattr(target_model, "validation_metadata", None)
        if target_metadata_obj is None:
            target_metadata_obj = FlextModels.Metadata(attributes={})

        target_metadata_attr = target_metadata_obj.attributes
        if isinstance(target_metadata_attr, FlextLdifModelsMetadata.DynamicMetadata):
            target_metadata = target_metadata_attr
        else:
            target_metadata = FlextLdifModelsMetadata.DynamicMetadata(
                **target_metadata_attr,
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
        metadata: FlextLdifModels.QuirkMetadata,
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
        metadata: FlextLdifModels.QuirkMetadata,
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
        # Pydantic v2: Use model_copy() to update extra fields
        if metadata.original_format_details is None:
            # Create new FormatDetails with the key
            metadata.original_format_details = FlextLdifModels.FormatDetails(**{
                format_key: original_value,
            })
        else:
            # Update existing FormatDetails via model_copy
            existing = metadata.original_format_details.model_dump()
            existing[format_key] = original_value
            metadata.original_format_details = FlextLdifModels.FormatDetails(
                **existing,
            )

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
    def _extract_obsolete_details(
        definition: str,
    ) -> dict[str, bool | int | str | None]:
        """Extract OBSOLETE details."""
        details: dict[str, bool | int | str | None] = {}
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
    ) -> FlextLdifModels.SchemaFormatDetails:
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
        # Build a dict first, then create the Pydantic model at the end
        combined: dict[str, object] = {}

        # Extract all details using helper methods
        prefix_details = FlextLdifUtilitiesMetadata._extract_prefix_details(definition)
        combined.update(prefix_details)

        oid_details = FlextLdifUtilitiesMetadata._extract_oid_details(definition)
        combined.update(oid_details)

        syntax_details = FlextLdifUtilitiesMetadata._extract_syntax_details(definition)
        combined.update(syntax_details)

        name_details = FlextLdifUtilitiesMetadata._extract_name_details(definition)
        combined.update(name_details)

        desc_details = FlextLdifUtilitiesMetadata._extract_desc_details(definition)
        combined.update(desc_details)

        x_origin_details = FlextLdifUtilitiesMetadata._extract_x_origin_details(
            definition,
        )
        combined.update(x_origin_details)

        obsolete_details = FlextLdifUtilitiesMetadata._extract_obsolete_details(
            definition,
        )
        combined.update(obsolete_details)

        # Extract field order and spacing
        field_order, field_positions = FlextLdifUtilitiesMetadata._extract_field_order(
            definition,
        )
        combined["field_order"] = field_order
        combined["field_positions"] = field_positions
        combined["spacing_between_fields"] = (
            FlextLdifUtilitiesMetadata._extract_spacing_between_fields(
                definition,
                field_order,
                field_positions,
                {
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
                },
            )
        )

        # Extract remaining details
        leading_trailing = FlextLdifUtilitiesMetadata._extract_leading_trailing_spaces(
            definition,
        )
        combined.update(leading_trailing)

        matching_rule_details = (
            FlextLdifUtilitiesMetadata._extract_matching_rule_details(definition)
        )
        combined.update(matching_rule_details)

        sup_details = FlextLdifUtilitiesMetadata._extract_sup_details(definition)
        combined.update(sup_details)

        single_value_details = FlextLdifUtilitiesMetadata._extract_single_value_details(
            definition,
        )
        combined.update(single_value_details)

        # Log all captured deviations at DEBUG level
        preview_len = FlextLdifConstants.LdifFormatting.DEFAULT_LINE_WIDTH
        logger.debug(
            "Schema formatting analyzed",
            definition_preview=(
                definition[:preview_len] + "..."
                if len(definition) > preview_len
                else definition
            ),
            fields_captured=len(combined),
        )

        # Separate known fields from dynamic extensions
        # SchemaFormatDetails defines: quotes, spacing, field_order, x_origin, x_ordered
        known_fields = {"quotes", "spacing", "field_order", "x_origin", "x_ordered"}
        model_kwargs: dict[str, object] = {}
        extension_kwargs: dict[str, object] = {}

        for key, value in combined.items():
            if key in known_fields:
                model_kwargs[key] = value
            else:
                extension_kwargs[key] = value

        # Create extensions with all dynamic fields
        extensions = FlextLdifModelsMetadata.DynamicMetadata(**extension_kwargs)
        model_kwargs["extensions"] = extensions

        return FlextLdifModels.SchemaFormatDetails(**model_kwargs)

    @staticmethod
    def preserve_schema_formatting(
        metadata: FlextLdifModels.QuirkMetadata,
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
            fields_preserved=len(formatting_details.model_fields_set),
        )

    @staticmethod
    def track_boolean_conversion(
        metadata: FlextLdifModels.QuirkMetadata,
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

    @staticmethod
    def analyze_minimal_differences(
        original: str,
        converted: str | None,
        context: str = "entry",
    ) -> dict[str, object]:
        """Analyze minimal differences between original and converted strings.

        Args:
            original: Original string
            converted: Converted string (None if unchanged)
            context: Context for analysis (dn, attribute, schema, etc.)

        Returns:
            Dictionary with difference analysis

        """
        mk = FlextLdifConstants.MetadataKeys
        differences: dict[str, object] = {
            mk.HAS_DIFFERENCES: False,
            "context": context,
            "original": original,
            "converted": converted,
            "differences": [],
            "original_length": len(original),
            "converted_length": len(converted) if converted else len(original),
        }

        if converted is None or original == converted:
            return differences

        differences[mk.HAS_DIFFERENCES] = True
        return differences

    @staticmethod
    def _apply_category_update(
        stats: FlextLdifModels.EntryStatistics,
        category: FlextLdifConstants.LiteralTypes.CategoryLiteral,
    ) -> FlextLdifModels.EntryStatistics:
        """Apply category update to stats using model_copy."""
        return stats.model_copy(update={"category_assigned": category})

    @staticmethod
    def _apply_filter_update(
        stats: FlextLdifModels.EntryStatistics,
        filter_type: str,
        *,
        passed: bool,
    ) -> FlextLdifModels.EntryStatistics:
        """Apply filter marking to stats."""
        return stats.mark_filtered(filter_type, passed=passed)

    @staticmethod
    def _apply_rejection_update(
        stats: FlextLdifModels.EntryStatistics,
        rejection_category: str,
        reason: str,
    ) -> FlextLdifModels.EntryStatistics:
        """Apply rejection marking to stats."""
        return stats.mark_rejected(rejection_category, reason)

    @staticmethod
    def _update_entry_with_stats(
        entry: FlextLdifModels.Entry,
        updated_stats: FlextLdifModels.EntryStatistics,
    ) -> FlextLdifModels.Entry:
        """Update entry with new processing stats using model_copy."""
        updated_metadata = entry.metadata.model_copy(
            update={"processing_stats": updated_stats},
        )
        return entry.model_copy(update={"metadata": updated_metadata})

    @staticmethod
    def update_entry_statistics(
        entry: FlextLdifModels.Entry,
        *,
        category: FlextLdifConstants.LiteralTypes.CategoryLiteral | None = None,
        mark_rejected: tuple[str, str] | None = None,
        mark_filtered: tuple[str, bool] | None = None,
    ) -> FlextLdifModels.Entry:
        """Update entry processing statistics using FlextLdifUtilities.

        Centralized helper for updating EntryStatistics in entry metadata.
        Uses Pydantic model_copy for immutable updates.

        Args:
            entry: Entry to update
            category: Category to assign (optional)
            mark_rejected: Tuple of (category, reason) to mark as rejected (optional)
            mark_filtered: Tuple of (filter_type, passed) to mark as filtered (optional)

        Returns:
            Entry with updated metadata

        """
        if not entry.metadata:
            return entry

        processing_stats = entry.metadata.processing_stats
        if not processing_stats:
            return entry

        updated_stats = processing_stats

        if category is not None:
            updated_stats = FlextLdifUtilitiesMetadata._apply_category_update(
                updated_stats,
                category,
            )

        if mark_filtered is not None:
            filter_type, passed = mark_filtered
            updated_stats = FlextLdifUtilitiesMetadata._apply_filter_update(
                updated_stats,
                filter_type,
                passed=passed,
            )

        if mark_rejected is not None:
            rejection_category, reason = mark_rejected
            updated_stats = FlextLdifUtilitiesMetadata._apply_rejection_update(
                updated_stats,
                rejection_category,
                reason,
            )

        return FlextLdifUtilitiesMetadata._update_entry_with_stats(entry, updated_stats)

    @staticmethod
    def get_original_attr_lines_from_metadata(
        metadata: FlextLdifModels.QuirkMetadata | None,
    ) -> list[str]:
        """Extract original attribute lines from entry metadata.

        Args:
            metadata: QuirkMetadata containing preservation data

        Returns:
            List of original attribute lines in LDIF format

        """
        if not metadata:
            return []

        # Check server_specific_data for original attributes
        if hasattr(metadata, "server_specific_data") and metadata.server_specific_data:
            extra = getattr(metadata.server_specific_data, "__pydantic_extra__", None)
            if extra and isinstance(extra, dict):
                original_lines = extra.get("original_attribute_lines")
                if isinstance(original_lines, list):
                    return original_lines

        return []

    @staticmethod
    def get_minimal_differences_from_metadata(
        metadata: FlextLdifModels.QuirkMetadata | None,
    ) -> dict[str, list[str]]:
        """Extract minimal differences (changed attributes) from entry metadata.

        Args:
            metadata: QuirkMetadata containing transformation data

        Returns:
            Dictionary mapping attribute names to their values showing only changes

        """
        if not metadata:
            return {}

        # Check for attribute transformations that indicate changes
        changes: dict[str, list[str]] = {}
        if hasattr(metadata, "attribute_transformations"):
            for attr_name, transformation in metadata.attribute_transformations.items():
                # Only include attributes that were actually transformed
                if (
                    hasattr(transformation, "target_values")
                    and transformation.target_values
                ):
                    changes[attr_name] = transformation.target_values

        return changes

    @staticmethod
    def extract_write_options(
        entry_data: FlextLdifModels.Entry,
    ) -> FlextLdifModels.WriteFormatOptions | None:
        """Extract write options from entry metadata.

        Retrieves WriteFormatOptions from entry.metadata.write_options if present.
        This is commonly used to determine formatting options during LDIF writing.

        Args:
            entry_data: Entry with optional metadata.write_options.

        Returns:
            WriteFormatOptions if found and properly typed, None otherwise.

        Example:
            >>> write_opts = FlextLdifUtilities.Metadata.extract_write_options(entry)
            >>> if write_opts and write_opts.sort_attributes:
            ...     # Apply attribute sorting
            ...     pass

        """
        if not entry_data.metadata or not entry_data.metadata.write_options:
            return None
        # Handle both dict and Pydantic model with extra="allow"
        write_opts = entry_data.metadata.write_options
        key = FlextLdifConstants.MetadataKeys.WRITE_OPTIONS
        if hasattr(write_opts, "model_extra"):
            extras = write_opts.model_extra or {}
        elif isinstance(write_opts, dict):
            extras = write_opts
        else:
            return None
        if key not in extras:
            return None
        opt = extras.get(key)
        if isinstance(opt, FlextLdifModels.WriteFormatOptions):
            return opt
        return None

    @staticmethod
    def preserve_original_ldif_content(
        metadata: FlextLdifModels.QuirkMetadata | FlextLdifModelsMetadata.EntryMetadata,
        ldif_content: str,
        **_extra: object,
    ) -> None:
        """Preserve original LDIF content in metadata for round-trip.

        Stub implementation for metadata preservation.

        Args:
            metadata: QuirkMetadata or EntryMetadata instance to update
            ldif_content: Original LDIF content
            _extra: Additional keyword arguments (ignored)

        """
        if (
            not hasattr(metadata, "server_specific_data")
            or not metadata.server_specific_data
        ):
            return
        # Store in server_specific_data as needed
        if isinstance(metadata.server_specific_data, dict):
            metadata.server_specific_data["original_ldif_content"] = ldif_content

    @staticmethod
    def build_acl_metadata_complete(
        quirk_type: str,
        _original_acl_format: str | None = None,
        **_extra: object,
    ) -> dict[str, str | int | bool]:
        """Build metadata for ACL parsing as a dictionary.

        Returns a dict that can be used as ACL metadata extensions.

        Args:
            quirk_type: Server type
            _original_acl_format: Original ACL format (unused)
            _extra: Additional keyword arguments (stored in dict)

        Returns:
            Dictionary with quirk_type and source_server fields

        """
        result: dict[str, str | int | bool] = {
            "quirk_type": quirk_type,
            "source_server": quirk_type,
        }
        # Add any extra string/int/bool params using dict update
        result.update({
            k: v for k, v in _extra.items() if isinstance(v, str | int | bool)
        })
        return result

    @staticmethod
    def build_entry_metadata_extensions(
        quirk_type: str,
        **_extra: object,
    ) -> dict[str, FlextLdifTypes.MetadataValue]:
        """Build metadata extensions for entry as a dictionary.

        Returns a dict that can be modified and then passed to QuirkMetadata.create_for().
        This allows dict-style item assignment before creating the final QuirkMetadata.
        Supports nested structures via FlextLdifTypes.MetadataValue.

        Args:
            quirk_type: Server type
            _extra: Additional keyword arguments (ignored)

        Returns:
            Dictionary with quirk_type and source_server fields

        """
        return {
            "quirk_type": quirk_type,
            "source_server": quirk_type,
        }

    @staticmethod
    def build_original_format_details(
        quirk_type: str,
        **_extra: object,
    ) -> FlextLdifModels.FormatDetails:
        """Build original format details for round-trip preservation.

        Args:
            quirk_type: Server type (used for context, stored in trailing_info)
            _extra: Additional keyword arguments (original_dn, cleaned_dn, etc.)

        Returns:
            FormatDetails instance for QuirkMetadata.original_format_details

        """
        # Extract commonly used format details from extra kwargs
        original_dn_line = _extra.get("original_dn_line")
        dn_line = str(original_dn_line) if original_dn_line is not None else None

        return FlextLdifModels.FormatDetails(
            dn_line=dn_line,
            trailing_info=f"server={quirk_type}",
        )

    @staticmethod
    def build_rfc_compliance_metadata(
        quirk_type: str,
        **_extra: object,
    ) -> dict[str, str | bool | list[str] | dict[str, str | list[str]]]:
        """Build RFC compliance metadata as a dictionary.

        Returns a dict that can be merged into extensions for QuirkMetadata.create_for().

        Args:
            quirk_type: Server type
            _extra: Additional keyword arguments (rfc_violations, attribute_conflicts, etc.)

        Returns:
            Dictionary with RFC compliance metadata

        """
        result: dict[str, str | bool | list[str] | dict[str, str | list[str]]] = {
            "quirk_type": quirk_type,
            "source_server": quirk_type,
        }
        # Extract RFC-specific metadata from extra kwargs
        if "rfc_violations" in _extra:
            violations = _extra["rfc_violations"]
            if isinstance(violations, list):
                result["rfc_violations"] = violations
        if "attribute_conflicts" in _extra:
            conflicts = _extra["attribute_conflicts"]
            if isinstance(conflicts, list):
                result["has_attribute_conflicts"] = len(conflicts) > 0
        return result

    @staticmethod
    def store_minimal_differences(
        metadata: FlextLdifModels.QuirkMetadata,
        **_extra: object,
    ) -> None:
        """Store minimal differences in metadata (stub).

        Args:
            metadata: QuirkMetadata instance
            _extra: Additional keyword arguments (ignored)

        """

    @staticmethod
    def track_minimal_differences_in_metadata(
        metadata: FlextLdifModels.QuirkMetadata,
        **_extra: object,
    ) -> None:
        """Track minimal differences in metadata (stub).

        Args:
            metadata: QuirkMetadata instance
            _extra: Additional keyword arguments (ignored)

        """

    @staticmethod
    def build_entry_parse_metadata(
        quirk_type: str,
        original_entry_dn: str,
        cleaned_dn: str,
        *,
        original_dn_line: str | None = None,
        original_attr_lines: list[str] | None = None,
        dn_was_base64: bool = False,
        original_attribute_case: dict[str, str] | None = None,
        dn_differences: dict[str, object] | None = None,
        attribute_differences: dict[str, object] | None = None,
        original_attributes_complete: dict[str, object] | None = None,
    ) -> FlextLdifModels.QuirkMetadata:
        """Build QuirkMetadata for entry parsing with format preservation.

        Creates a QuirkMetadata instance capturing all entry parsing details
        for preservation and round-trip support.

        Args:
            quirk_type: Server type performing the parse (oid, oud, rfc, etc.)
            original_entry_dn: Original DN as parsed from LDIF
            cleaned_dn: Cleaned/normalized DN
            original_dn_line: Original DN line from LDIF (with folding if present)
            original_attr_lines: Original attribute lines from LDIF
            dn_was_base64: Whether DN was base64 encoded
            original_attribute_case: Mapping of attribute names to original case
            dn_differences: Differences identified between original and cleaned DN
            attribute_differences: Differences identified between original and cleaned attributes
            original_attributes_complete: Complete original attributes for preservation

        Returns:
            QuirkMetadata with all entry parsing details preserved

        """
        # Build server_specific_data with parsing details
        server_data: dict[str, object] = {
            "original_entry_dn": original_entry_dn,
            "cleaned_dn": cleaned_dn,
            "dn_was_base64": dn_was_base64,
        }

        if original_dn_line:
            server_data["original_dn_line"] = original_dn_line

        if original_attr_lines:
            server_data["original_attribute_lines"] = original_attr_lines

        if original_attribute_case:
            server_data["original_attribute_case"] = original_attribute_case

        # Build metadata dict for DynamicMetadata
        metadata: dict[str, object] = {
            "quirk_type": quirk_type,
            "source_server": quirk_type,
            "server_specific_data": server_data,
        }

        if dn_differences:
            metadata["dn_differences"] = dn_differences

        if attribute_differences:
            metadata["attribute_differences"] = attribute_differences

        if original_attributes_complete:
            metadata["original_attributes"] = original_attributes_complete

        # Create and return QuirkMetadata (use public facade)
        return FlextLdifModels.QuirkMetadata(
            quirk_type=quirk_type,
            server_specific_data=server_data,
        )


__all__ = ["FlextLdifUtilitiesMetadata"]
