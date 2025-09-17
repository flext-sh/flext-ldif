"""FLEXT LDIF Transformer Service - LDIF transformation service implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable

from flext_core import FlextResult
from flext_ldif.models import FlextLdifModels


class FlextLdifTransformerService:
    """LDIF Transformer Service - Single Responsibility.

    Handles all LDIF transformation operations with enterprise-grade error handling.
    Uses flext-core SOURCE OF TRUTH exclusively.
    """

    def transform_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        transform_func: Callable[[FlextLdifModels.Entry], FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Transform LDIF entries using provided function."""
        try:
            transformed_entries: list[FlextLdifModels.Entry] = []
            for entry in entries:
                try:
                    transformed_entry = transform_func(entry)
                    transformed_entries.append(transformed_entry)
                except Exception as e:
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Transform error: {e}"
                    )
            return FlextResult[list[FlextLdifModels.Entry]].ok(transformed_entries)
        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Transform error: {e}"
            )

    def normalize_dns(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Normalize DN formats in entries."""
        try:
            normalized_entries: list[FlextLdifModels.Entry] = []
            for entry in entries:
                # Simple DN normalization - remove extra spaces
                normalized_dn = ",".join(
                    part.strip() for part in entry.dn.value.split(",")
                )
                normalized_entry = FlextLdifModels.Entry(
                    dn=FlextLdifModels.DistinguishedName(value=normalized_dn),
                    attributes=entry.attributes,
                )
                normalized_entries.append(normalized_entry)
            return FlextResult[list[FlextLdifModels.Entry]].ok(normalized_entries)
        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"DN normalization error: {e}"
            )

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
