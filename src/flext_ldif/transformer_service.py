"""FLEXT LDIF Transformer Service - LDIF transformation service implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult
from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes


class FlextLdifTransformerService:
    """LDIF Transformer Service - Single Responsibility.

    Handles all LDIF transformation operations with enterprise-grade error handling.
    Uses flext-core SOURCE OF TRUTH exclusively.
    """

    def transform_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        transform_func: FlextLdifTypes.Processing.EntryTransformer[FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Transform LDIF entries using provided function.

        Args:
            entries: List of LDIF entries to transform
            transform_func: Function to apply to each entry

        Returns:
            FlextResult containing transformed entries or error

        """
        # Empty list is valid - return empty result
        if not entries:
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

        # Handle iteration exceptions
        try:
            transformed_entries: list[FlextLdifModels.Entry] = []
            for entry in entries:
                # Validate entry before transformation
                entry_validation = entry.validate_business_rules()
                if entry_validation.is_failure:
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Entry validation failed before transformation: {entry_validation.error}"
                    )

                # Apply transformation function - handle external function exceptions
                try:
                    transformed_entry = transform_func(entry)
                except Exception as e:
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Transform error: {e}"
                    )

                # Validate transformed entry
                transformed_validation = transformed_entry.validate_business_rules()
                if transformed_validation.is_failure:
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Transformed entry validation failed: {transformed_validation.error}"
                    )

                transformed_entries.append(transformed_entry)

            return FlextResult[list[FlextLdifModels.Entry]].ok(transformed_entries)
        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Transform error: {e}"
            )

    def normalize_dns(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Normalize DN formats in entries.

        Args:
            entries: List of LDIF entries to normalize

        Returns:
            FlextResult containing normalized entries or error

        """
        # Empty list is valid - return empty result
        if not entries:
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

        normalized_entries: list[FlextLdifModels.Entry] = []
        for entry in entries:
            # Validate entry before normalization - handle validation exceptions
            try:
                entry_validation = entry.validate_business_rules()
                if entry_validation.is_failure:
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Entry validation failed before normalization: {entry_validation.error}"
                    )
            except Exception as e:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"DN normalization error: {e}"
                )

            # Normalize DN - remove extra spaces and validate
            dn_parts = [
                part.strip() for part in entry.dn.value.split(",") if part.strip()
            ]
            if not dn_parts:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"DN normalization resulted in empty DN: {entry.dn.value}"
                )

            normalized_dn = ",".join(dn_parts)

            # Create new entry with normalized DN
            normalized_entry = FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value=normalized_dn),
                attributes=entry.attributes,
            )

            # Validate normalized entry
            normalized_validation = normalized_entry.validate_business_rules()
            if normalized_validation.is_failure:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Normalized entry validation failed: {normalized_validation.error}"
                )

            normalized_entries.append(normalized_entry)

        return FlextResult[list[FlextLdifModels.Entry]].ok(normalized_entries)

    def execute(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Execute transformer operation - returns empty list by default."""
        return FlextResult[list[FlextLdifModels.Entry]].ok([])

    def get_config_info(self) -> dict[str, object]:
        """Get transformer service configuration information."""
        return {
            "service": "FlextLdifTransformerService",
            "config": {
                "service_type": "FlextLdifTransformerService",
                "status": "ready",
                "operations": ["transform_entries", "normalize_dns", "execute"],
            },
        }

    def get_service_info(self) -> dict[str, object]:
        """Get transformer service information."""
        return {
            "service_name": "FlextLdifTransformerService",
            "service_type": "transformer",
            "capabilities": ["transform_entries", "normalize_dns", "execute"],
            "status": "ready",
        }


__all__ = ["FlextLdifTransformerService"]
