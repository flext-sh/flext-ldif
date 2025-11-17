"""LDIF Metadata Utilities - Helpers for Validation Metadata Management.

Provides helper methods for preserving, extracting, and tracking validation metadata
during LDIF conversions between different LDAP servers (OID, OUD, OpenLDAP, etc.).

FASE 3: Services Integration with Metadata
- preserve_validation_metadata(): Copy metadata from source to target with transformations
- extract_rfc_violations(): Extract all RFC violations from model metadata
- track_conversion_step(): Add conversion step to transformation history

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import logging
from typing import Protocol, TypeVar

logger = logging.getLogger(__name__)


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
