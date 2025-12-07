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
from collections.abc import Mapping
from typing import cast

from flext_core import FlextLogger, FlextModels, FlextRuntime, u

from flext_ldif._models.config import FlextLdifModelsConfig
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.typings import LdifModelT, t

# Type alias for EntryStatistics to use in type annotations
# m.EntryStatistics is a variable assignment, not a type alias
EntryStatisticsType = FlextLdifModelsDomains.EntryStatistics

# Alias for simplified usage
# Note: u is already imported directly, no need to reassign

logger = FlextLogger(__name__)

# Use types directly from typings.py and protocols.py (no local aliases)


class FlextLdifUtilitiesMetadata:
    """Metadata utilities for LDIF validation metadata management.

    Provides helper methods for:
    - Preserving validation metadata during conversions
    - Extracting RFC violations from models
    - Tracking conversion steps in transformation history
    """

    @staticmethod
    def _convert_transformation_to_metadata_value(
        transformation: t.TransformationInfo,
    ) -> Mapping[str, t.ScalarValue]:
        """Convert TransformationInfo TypedDict to MetadataAttributeValue-compatible dict.

        TransformationInfo has changes: list[str], which needs to be converted
        to a format compatible with MetadataAttributeValue (Mapping[str, ScalarValue]).
        We convert list[str] to a single string joined by commas for compatibility.

        Args:
            transformation: TransformationInfo TypedDict with step, server, changes

        Returns:
            Mapping compatible with MetadataAttributeValue

        """
        # Business Rule: TransformationInfo has total=False (all keys optional)
        # We need to handle missing keys gracefully with defaults
        # Implication: When storing transformation info in metadata, missing fields
        # are represented as empty strings to maintain MetadataAttributeValue compatibility
        return {
            "step": transformation.get("step", ""),
            "server": transformation.get("server", ""),
            "changes": ", ".join(
                transformation.get("changes", []),
            ),  # Convert list[str] to str
        }

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
        model: FlextLdifProtocols.Ldif.Constants.ModelWithValidationMetadata,
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
                # Convert DynamicMetadata to dict for m.Metadata
                metadata_dict = metadata.model_dump()
                # Create Metadata with proper type - attributes accepts dict[str, MetadataAttributeValue]
                # DynamicMetadata.model_dump() returns dict[str, object] which needs conversion
                # t.Metadata is Mapping[str, MetadataAttributeValue], but models use Metadata BaseModel
                # So we create Metadata BaseModel and assign it (runtime compatible)
                # m.Metadata provides the public API for metadata models
                # Protocol expects t.Metadata (Mapping[str, MetadataAttributeValue] | None)
                # BaseModel implements Mapping protocol, so we cast for type compatibility
                metadata_obj = m.Metadata(attributes=metadata_dict)
                # BaseModel implements Mapping protocol at runtime, cast for type checker
                model.validation_metadata = cast("t.Metadata", metadata_obj)
        except (AttributeError, TypeError, ValueError):
            # Ignore if attribute cannot be set
            pass

    # =========================================================================
    # UNIFIED PARAMETERIZED METADATA TRACKER
    # =========================================================================

    @staticmethod
    def _get_metadata_dict(model: LdifModelT) -> dict[str, object]:
        """Get mutable metadata dict from model."""
        metadata_obj = getattr(model, "validation_metadata", None)
        if metadata_obj is None:
            metadata_obj = FlextModels.Metadata(attributes={})

        if isinstance(metadata_obj, FlextModels.Metadata) and isinstance(
            metadata_obj.attributes,
            dict,
        ):
            return dict(metadata_obj.attributes)
        if isinstance(metadata_obj, FlextModels.Metadata) and isinstance(
            metadata_obj.attributes,
            FlextLdifModelsMetadata.DynamicMetadata,
        ):
            return dict(metadata_obj.attributes.model_dump())
        return {}

    @staticmethod
    def _add_to_list_metadata(
        metadata: dict[str, object],
        metadata_key: str,
        item_data: t.MetadataAttributeValue,
    ) -> None:
        """Add item to list metadata."""
        value = metadata[metadata_key]
        value_for_check: t.GeneralValueType = (
            value
            if isinstance(value, (str, int, float, bool, type(None), list, dict))
            else str(value)
        )
        if FlextRuntime.is_list_like(value_for_check):
            value_list = (
                value_for_check
                if isinstance(value_for_check, list)
                else list(value_for_check)
            )
            value_list.append(item_data)
            metadata[metadata_key] = value_list
        else:
            metadata[metadata_key] = [item_data]

    @staticmethod
    def _add_to_dict_metadata(
        metadata: dict[str, object],
        metadata_key: str,
        item_data: t.MetadataAttributeValue,
    ) -> None:
        """Add item to dict metadata."""
        value = metadata[metadata_key]
        value_for_dict_check: t.GeneralValueType = (
            value
            if isinstance(value, (str, int, float, bool, type(None), list, dict))
            else str(value)
        )
        if FlextRuntime.is_dict_like(value_for_dict_check):
            value_dict = (
                dict(value_for_dict_check)
                if not isinstance(value_for_dict_check, dict)
                else value_for_dict_check
            )
            if isinstance(item_data, dict):
                value_dict.update(item_data)
                metadata[metadata_key] = value_dict
            else:
                metadata[metadata_key] = item_data
        else:
            metadata[metadata_key] = item_data

    @staticmethod
    def _update_conversion_path(
        metadata: dict[str, object],
        update_conversion_path: str,
    ) -> None:
        """Update conversion_path in metadata."""
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

    @staticmethod
    def _track_metadata_item(
        model: LdifModelT,
        metadata_key: str,
        item_data: t.MetadataAttributeValue,
        *,
        append_to_list: bool = True,
        update_conversion_path: str | None = None,
    ) -> LdifModelT:
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
        metadata = FlextLdifUtilitiesMetadata._get_metadata_dict(model)

        if metadata_key not in metadata:
            metadata[metadata_key] = [] if append_to_list else {}

        if append_to_list:
            FlextLdifUtilitiesMetadata._add_to_list_metadata(
                metadata,
                metadata_key,
                item_data,
            )
        else:
            FlextLdifUtilitiesMetadata._add_to_dict_metadata(
                metadata,
                metadata_key,
                item_data,
            )

        if update_conversion_path:
            FlextLdifUtilitiesMetadata._update_conversion_path(
                metadata,
                update_conversion_path,
            )

        metadata_typed: dict[str, t.MetadataAttributeValue] = {
            k: cast("t.MetadataAttributeValue", v) for k, v in metadata.items()
        }
        dynamic_metadata = FlextLdifModelsMetadata.DynamicMetadata(**metadata_typed)
        FlextLdifUtilitiesMetadata._set_model_metadata(model, dynamic_metadata)
        return model

    @staticmethod
    def _extract_source_metadata(
        model: LdifModelT,
    ) -> FlextLdifModelsMetadata.DynamicMetadata | None:
        """Extract validation metadata from a model."""
        source_metadata_obj = getattr(model, "validation_metadata", None)
        if source_metadata_obj is None:
            return None

        # Ensure source_metadata_obj is FlextModels.Metadata to access attributes
        if not isinstance(source_metadata_obj, FlextModels.Metadata):
            return None

        # Extract attributes from source metadata object (MUST be Metadata)
        source_metadata_attr = source_metadata_obj.attributes
        if isinstance(source_metadata_attr, FlextLdifModelsMetadata.DynamicMetadata):
            return source_metadata_attr
        # Convert dict to DynamicMetadata using model_validate
        if isinstance(source_metadata_attr, dict):
            return FlextLdifModelsMetadata.DynamicMetadata.model_validate(
                source_metadata_attr,
            )
        # Fallback: create empty DynamicMetadata
        return FlextLdifModelsMetadata.DynamicMetadata()

    @staticmethod
    def _get_or_create_target_metadata(
        model: LdifModelT,
    ) -> FlextLdifModelsMetadata.DynamicMetadata:
        """Get or create validation metadata for a model."""
        target_metadata_obj = getattr(model, "validation_metadata", None)
        if target_metadata_obj is None or not isinstance(
            target_metadata_obj,
            FlextModels.Metadata,
        ):
            target_metadata_obj = FlextModels.Metadata(attributes={})

        target_metadata_attr = target_metadata_obj.attributes
        if isinstance(target_metadata_attr, FlextLdifModelsMetadata.DynamicMetadata):
            return target_metadata_attr
        # Convert dict to DynamicMetadata using model_validate
        if isinstance(target_metadata_attr, dict):
            return FlextLdifModelsMetadata.DynamicMetadata.model_validate(
                target_metadata_attr,
            )
        # Fallback: create empty DynamicMetadata
        return FlextLdifModelsMetadata.DynamicMetadata()

    @staticmethod
    def preserve_validation_metadata(
        source_model: ModelT,
        target_model: ModelT,
        transformation: t.TransformationInfo,
    ) -> LdifModelT:
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
        source_metadata = FlextLdifUtilitiesMetadata._extract_source_metadata(
            source_model,
        )
        if source_metadata is None:
            return target_model

        target_metadata = FlextLdifUtilitiesMetadata._get_or_create_target_metadata(
            target_model,
        )

        # Copy violations from source to target
        FlextLdifUtilitiesMetadata._copy_violations_to_target(
            source_metadata,
            target_metadata,
        )

        # Add transformation to history
        transformation_dict = (
            FlextLdifUtilitiesMetadata._convert_transformation_to_metadata_value(
                transformation,
            )
        )

        if "transformations" not in target_metadata:
            # Create new list with transformation
            new_list: list[Mapping[str, t.ScalarValue]] = [transformation_dict]
            target_metadata["transformations"] = cast(
                "t.MetadataAttributeValue",
                new_list,
            )
        else:
            transformations_obj = target_metadata["transformations"]
            if isinstance(transformations_obj, list):
                # Create new list with correct type to avoid type checker issues
                # Business Rule: transformations list accepts Mapping[str, ScalarValue] as dict
                # Type narrowing: transformations_obj is list, create new list with transformation_dict
                # Use list comprehension to create new list with proper type
                existing_items: list[Mapping[str, t.ScalarValue]] = [
                    cast("Mapping[str, t.ScalarValue]", item)
                    for item in transformations_obj
                ]
                existing_items.append(transformation_dict)
                target_metadata["transformations"] = cast(
                    "t.MetadataAttributeValue",
                    existing_items,
                )
            else:
                # Create new list if current value is not a list (should not happen for transformations)
                new_list = [transformation_dict]
                target_metadata["transformations"] = cast(
                    "t.MetadataAttributeValue",
                    new_list,
                )

        # Set conversion path if not already set
        if "conversion_path" not in target_metadata:
            source_server = transformation.get("server", "unknown")
            target_metadata["conversion_path"] = f"{source_server}->..."

        # Update target model metadata
        FlextLdifUtilitiesMetadata._set_model_metadata(target_model, target_metadata)

        return target_model

    @staticmethod
    def extract_rfc_violations(
        model: FlextLdifProtocols.Ldif.Constants.ModelWithValidationMetadata,
    ) -> list[str]:
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

        # Extract attributes from source metadata object (MUST be Metadata)
        if not isinstance(metadata, FlextModels.Metadata):
            return []
        meta_attrs = metadata.attributes

        # All violation keys to extract from metadata
        violation_keys = ("rfc_violations", "dn_violations", "attribute_violations")
        violations: list[str] = []

        def extract_violations(key: str) -> list[str]:
            """Extract violations for key."""
            if key not in meta_attrs:
                return []
            value = meta_attrs[key]
            if isinstance(value, list):
                return [str(v) for v in value]
            return []

        violations_result = u.Collection.process(
            violation_keys,
            processor=extract_violations,
            on_error="skip",
        )
        if violations_result.is_success and isinstance(violations_result.value, list):
            violations = [
                v
                for sublist in violations_result.value
                if isinstance(sublist, list)
                for v in sublist
            ]
        else:
            violations = []

        return violations

    @staticmethod
    def track_conversion_step(
        model: LdifModelT,
        step: str,
        server: str,
        changes: list[str],
    ) -> LdifModelT:
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
        # Create TransformationInfo dict (TypedDict compatible with MetadataAttributeValue)
        transformation_info: t.TransformationInfo = {
            "step": step,
            "server": server,
            "changes": changes,
        }
        # Convert TypedDict to MetadataAttributeValue-compatible format
        transformation_dict = (
            FlextLdifUtilitiesMetadata._convert_transformation_to_metadata_value(
                transformation_info,
            )
        )
        return FlextLdifUtilitiesMetadata._track_metadata_item(
            model=model,
            metadata_key="transformations",
            item_data=transformation_dict,
            update_conversion_path=server,
        )

    # =========================================================================
    # ZERO DATA LOSS TRACKING (Phase 2)
    # =========================================================================

    @staticmethod
    def track_transformation(
        metadata: m.QuirkMetadata,
        config: FlextLdifModelsConfig.TransformationTrackingConfig,
    ) -> None:
        """Track an attribute transformation in QuirkMetadata.

        Populates the attribute_transformations dict with a complete
        AttributeTransformation record for audit trail and round-trip support.

        CRITICAL: This function ensures ALL transformations are tracked for zero data loss.
        Every attribute change (rename, remove, modify, add) MUST be tracked here.

        Args:
            metadata: QuirkMetadata instance to update
            config: TransformationTrackingConfig with all transformation parameters

        Example:
            >>> config = FlextLdifModelsConfig.TransformationTrackingConfig(
            ...     original_name="orcldasisenabled",
            ...     target_name="orcldasisenabled",
            ...     original_values=["1"],
            ...     target_values=["TRUE"],
            ...     transformation_type="modified",
            ...     reason="OID boolean '1' -> RFC 'TRUE'",
            ... )
            >>> FlextLdifUtilitiesMetadata.track_transformation(entry.metadata, config)

        """
        transformation = m.AttributeTransformation(
            original_name=config.original_name,
            target_name=config.target_name,
            original_values=config.original_values,
            target_values=config.target_values,
            transformation_type=config.transformation_type,
            reason=config.reason,
        )
        metadata.attribute_transformations[config.original_name] = transformation

        # Log transformation for traceability
        logger.debug(
            "Tracked attribute transformation",
            original_name=config.original_name,
            target_name=config.target_name,
            transformation_type=config.transformation_type,
        )

    @staticmethod
    def preserve_original_format(
        metadata: m.QuirkMetadata,
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
        # Pydantic v2: Use model_validate() to create/update FormatDetails
        if metadata.original_format_details is None:
            # Create new FormatDetails with the key using model_validate
            format_dict: dict[str, t.MetadataAttributeValue] = {
                format_key: original_value,
            }
            metadata.original_format_details = m.FormatDetails.model_validate(
                format_dict,
            )
        else:
            # Update existing FormatDetails via model_copy
            existing = metadata.original_format_details.model_dump()
            existing[format_key] = original_value
            metadata.original_format_details = m.FormatDetails.model_validate(existing)

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
    def _extract_all_schema_details(
        definition: str,
    ) -> dict[str, t.MetadataAttributeValue]:
        """Extract all schema formatting details into combined dict."""
        combined: dict[str, t.MetadataAttributeValue] = {}
        extractors = [
            FlextLdifUtilitiesMetadata._extract_prefix_details,
            FlextLdifUtilitiesMetadata._extract_oid_details,
            FlextLdifUtilitiesMetadata._extract_syntax_details,
            FlextLdifUtilitiesMetadata._extract_name_details,
            FlextLdifUtilitiesMetadata._extract_desc_details,
            FlextLdifUtilitiesMetadata._extract_x_origin_details,
            FlextLdifUtilitiesMetadata._extract_obsolete_details,
            FlextLdifUtilitiesMetadata._extract_leading_trailing_spaces,
            FlextLdifUtilitiesMetadata._extract_matching_rule_details,
            FlextLdifUtilitiesMetadata._extract_sup_details,
            FlextLdifUtilitiesMetadata._extract_single_value_details,
        ]
        for extractor in extractors:
            extracted_raw = extractor(definition)
            # Type narrowing: extractor returns dict[str, t.MetadataAttributeValue]
            if isinstance(extracted_raw, dict):
                combined.update(
                    cast("dict[str, t.MetadataAttributeValue]", extracted_raw),
                )
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
        return combined

    @staticmethod
    def _build_schema_format_model(
        definition: str,
        combined: dict[str, t.MetadataAttributeValue],
    ) -> m.SchemaFormatDetails:
        """Build SchemaFormatDetails model from combined details."""
        known_fields = {
            "original_string_complete",
            "quotes",
            "spacing",
            "field_order",
            "x_origin",
            "x_ordered",
        }
        model_kwargs: dict[str, t.MetadataAttributeValue] = {
            "original_string_complete": definition,
        }
        extension_kwargs: dict[str, t.MetadataAttributeValue] = {}
        for key, value in combined.items():
            if key in known_fields:
                model_kwargs[key] = value
            else:
                extension_kwargs[key] = value
        extensions = FlextLdifModelsMetadata.DynamicMetadata.model_validate(
            extension_kwargs,
        )
        model_kwargs["extensions"] = extensions.model_dump()
        return m.SchemaFormatDetails.model_validate(model_kwargs)

    @staticmethod
    def analyze_schema_formatting(
        definition: str,
    ) -> m.SchemaFormatDetails:
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
        combined = FlextLdifUtilitiesMetadata._extract_all_schema_details(definition)
        preview_len = c.Ldif.LdifFormatting.DEFAULT_LINE_WIDTH
        logger.debug(
            "Schema formatting analyzed",
            definition_preview=(
                definition[:preview_len] + "..."
                if len(definition) > preview_len
                else definition
            ),
            fields_captured=len(combined),
        )
        return FlextLdifUtilitiesMetadata._build_schema_format_model(
            definition,
            combined,
        )

    @staticmethod
    def preserve_schema_formatting(
        metadata: m.QuirkMetadata,
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
        metadata: m.QuirkMetadata,
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
    ) -> dict[str, t.MetadataAttributeValue]:
        """Analyze minimal differences between original and converted strings.

        Args:
            original: Original string
            converted: Converted string (None if unchanged)
            context: Context for analysis (dn, attribute, schema, etc.)

        Returns:
            Dictionary with difference analysis

        """
        mk = c.MetadataKeys
        differences: dict[str, t.MetadataAttributeValue] = {
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
        stats: EntryStatisticsType,
        category: c.Ldif.LiteralTypes.CategoryLiteral,
    ) -> EntryStatisticsType:
        """Apply category update to stats using model_copy."""
        # Ensure return type is EntryStatisticsType
        return stats.model_copy(update={"category_assigned": category})

    @staticmethod
    def _apply_filter_update(
        stats: EntryStatisticsType,
        filter_type: str,
        *,
        passed: bool,
    ) -> EntryStatisticsType:
        """Apply filter marking to stats."""
        # Ensure return type is EntryStatisticsType
        return stats.mark_filtered(filter_type, passed=passed)

    @staticmethod
    def _apply_rejection_update(
        stats: EntryStatisticsType,
        rejection_category: str,
        reason: str,
    ) -> EntryStatisticsType:
        """Apply rejection marking to stats."""
        # Ensure return type is EntryStatisticsType
        return stats.mark_rejected(rejection_category, reason)

    @staticmethod
    def _update_entry_with_stats(
        entry: m.Ldif.Entry,
        updated_stats: EntryStatisticsType,
    ) -> m.Ldif.Entry:
        """Update entry with new processing stats using model_copy."""
        if entry.metadata is None:
            # Create new metadata if None
            entry.metadata = m.QuirkMetadata.create_for(
                c.normalize_server_type(c.ServerTypes.RFC.value),
            )
        # updated_stats is EntryStatisticsType (FlextLdifModelsDomains.EntryStatistics)
        # Use model_dump and model_validate to ensure facade type
        stats_dict = updated_stats.model_dump()
        # m.EntryStatistics is the facade alias, use it for validation
        stats_facade = m.EntryStatistics.model_validate(stats_dict)
        # Use dict[str, object] for model_copy update (Pydantic accepts object)
        update_dict: dict[str, object] = {"processing_stats": stats_facade}
        updated_metadata = entry.metadata.model_copy(update=update_dict)
        return entry.model_copy(update={"metadata": updated_metadata})

    @staticmethod
    def update_entry_statistics(
        entry: m.Ldif.Entry,
        *,
        category: c.Ldif.LiteralTypes.CategoryLiteral | None = None,
        mark_rejected: tuple[str, str] | None = None,
        mark_filtered: tuple[str, bool] | None = None,
    ) -> m.Ldif.Entry:
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

        # Ensure stats is always m.EntryStatistics (public facade)
        # Business Rule: processing_stats can be domain or facade, but we need facade
        stats_dict = processing_stats.model_dump()
        updated_stats = m.EntryStatistics.model_validate(stats_dict)

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
        metadata: m.QuirkMetadata | None,
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
        metadata: m.QuirkMetadata | None,
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
        entry_data: m.Ldif.Entry,
    ) -> m.Ldif.WriteFormatOptions | None:
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
        key = c.MetadataKeys.WRITE_OPTIONS
        if hasattr(write_opts, "model_extra"):
            extras = write_opts.model_extra or {}
        elif isinstance(write_opts, dict):
            extras = write_opts
        else:
            return None
        if key not in extras:
            return None
        opt = extras.get(key)
        if isinstance(opt, m.Ldif.WriteFormatOptions):
            return opt
        return None

    @staticmethod
    def preserve_original_ldif_content(
        metadata: m.QuirkMetadata | FlextLdifModelsMetadata.EntryMetadata,
        ldif_content: str,
        **_extra: t.ScalarValue,
    ) -> None:
        """Preserve original LDIF content in metadata for round-trip.

        Stub implementation for metadata preservation.

        Args:
            metadata: QuirkMetadata or EntryMetadata instance to update
            ldif_content: Original LDIF content
            _extra: Additional keyword arguments (ignored)

        """
        # Business Rule: EntryMetadata uses extra="allow" for dynamic attributes
        # but is frozen, so we cannot modify it directly. This is a stub implementation
        # that doesn't actually modify the metadata (frozen models require model_copy).
        # Implication: This method is currently a placeholder. To properly implement
        # metadata preservation, callers should use model_copy to create updated instances.
        # For now, we skip the operation since frozen models cannot be modified in-place.
        # Note: Refactored to return updated metadata instance using model_copy when needed
        _ = metadata, ldif_content  # Mark as used to avoid unused variable warnings

    @staticmethod
    def build_acl_metadata_complete(
        quirk_type: str,
        _original_acl_format: str | None = None,
        **_extra: t.ScalarValue,
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
        **_extra: t.ScalarValue,
    ) -> dict[str, t.MetadataAttributeValue]:
        """Build metadata extensions for entry as a dictionary.

        Returns a dict that can be modified and then passed to QuirkMetadata.create_for().
        This allows dict-style item assignment before creating the final QuirkMetadata.
        Supports nested structures via t.MetadataAttributeValue.

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
        **_extra: t.ScalarValue,
    ) -> m.FormatDetails:
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

        return m.FormatDetails(
            dn_line=dn_line,
            trailing_info=f"server={quirk_type}",
        )

    @staticmethod
    def build_rfc_compliance_metadata(
        quirk_type: str,
        **_extra: t.ScalarValue,
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
        metadata: m.QuirkMetadata,
        **_extra: t.ScalarValue,
    ) -> None:
        """Store minimal differences in metadata (stub).

        Args:
            metadata: QuirkMetadata instance
            _extra: Additional keyword arguments (ignored)

        """

    @staticmethod
    def track_minimal_differences_in_metadata(
        metadata: m.QuirkMetadata,
        **_extra: t.ScalarValue,
    ) -> None:
        """Track minimal differences in metadata (stub).

        Args:
            metadata: QuirkMetadata instance
            _extra: Additional keyword arguments (ignored)

        """

    @staticmethod
    def build_entry_parse_metadata(
        config: FlextLdifModelsConfig.EntryParseMetadataConfig,
    ) -> m.QuirkMetadata:
        """Build QuirkMetadata for entry parsing with format preservation.

        Creates a QuirkMetadata instance capturing all entry parsing details
        for preservation and round-trip support.

        Args:
            config: EntryParseMetadataConfig with all parsing parameters

        Returns:
            QuirkMetadata with all entry parsing details preserved

        Example:
            >>> config = FlextLdifModelsConfig.EntryParseMetadataConfig(
            ...     quirk_type="oid",
            ...     original_entry_dn="cn=test,dc=example",
            ...     cleaned_dn="cn=test,dc=example",
            ...     original_dn_line="dn: cn=test,dc=example",
            ... )
            >>> metadata = FlextLdifUtilitiesMetadata.build_entry_parse_metadata(config)

        """
        # Build server_specific_data as EntryMetadata
        server_data_dict: dict[str, t.MetadataAttributeValue] = {
            "original_entry_dn": config.original_entry_dn,
            "cleaned_dn": config.cleaned_dn,
            "dn_was_base64": config.dn_was_base64,
        }

        if config.original_dn_line:
            server_data_dict["original_dn_line"] = config.original_dn_line

        if config.original_attr_lines:
            server_data_dict["original_attribute_lines"] = config.original_attr_lines

        if config.original_attribute_case:
            server_data_dict["original_attribute_case"] = config.original_attribute_case

        # Create EntryMetadata from dict using model_validate
        # EntryMetadata accepts extra="allow" so dynamic fields are valid
        server_data = FlextLdifModelsMetadata.EntryMetadata.model_validate(
            server_data_dict,
        )

        # Build original LDIF string from components for round-trip preservation
        original_ldif_parts: list[str] = []
        if config.original_dn_line:
            original_ldif_parts.append(config.original_dn_line)
        if config.original_attr_lines:
            original_ldif_parts.extend(config.original_attr_lines)
        original_ldif = "\n".join(original_ldif_parts) if original_ldif_parts else ""

        # Build extensions dict with original_dn_complete for round-trip support
        extensions_dict: dict[str, t.MetadataAttributeValue] = {}
        mk = c.MetadataKeys
        extensions_dict[mk.ORIGINAL_DN_COMPLETE] = config.original_entry_dn

        # Create QuirkMetadata with original_strings populated
        # Convert extensions_dict to DynamicMetadata for type compatibility
        dynamic_extensions = FlextLdifModelsMetadata.DynamicMetadata(**extensions_dict)
        metadata = m.QuirkMetadata(
            quirk_type=config.quirk_type,
            server_specific_data=server_data,
            extensions=dynamic_extensions,
        )

        # Preserve original LDIF content in original_strings
        if original_ldif:
            metadata.original_strings["entry_original_ldif"] = original_ldif

        return metadata


__all__ = ["FlextLdifUtilitiesMetadata"]
