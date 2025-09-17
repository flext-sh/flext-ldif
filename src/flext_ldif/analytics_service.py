"""FLEXT LDIF Analytics Service - Standalone analytics operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels


class FlextLdifAnalyticsService:
    """LDIF Analytics Service - Simplified with direct flext-core usage.

    Handles all LDIF analytics operations with minimal complexity.
    Uses flext-core patterns directly without unnecessary abstractions.
    """

    def analyze_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, int]]:
        """Analyze LDIF entries and return statistics."""
        stats = {
            "total_entries": len(entries),
            "person_entries": sum(1 for e in entries if e.is_person_entry()),
            "group_entries": sum(1 for e in entries if e.is_group_entry()),
            "organizational_unit_entries": sum(
                1
                for e in entries
                if "organizationalunit"
                in (
                    oc.lower()
                    for oc in (
                        e.get_attribute(FlextLdifConstants.OBJECTCLASS_ATTRIBUTE) or []
                    )
                )
            ),
        }
        return FlextResult[dict[str, int]].ok(stats)

    def get_objectclass_distribution(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, int]]:
        """Get object class distribution."""
        distribution: dict[str, int] = {}
        for entry in entries:
            object_classes = (
                entry.get_attribute(FlextLdifConstants.OBJECTCLASS_ATTRIBUTE) or []
            )
            for oc in object_classes:
                oc_lower = oc.lower()
                distribution[oc_lower] = distribution.get(oc_lower, 0) + 1
        return FlextResult[dict[str, int]].ok(distribution)

    def get_dn_depth_analysis(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, int]]:
        """Analyze DN depth distribution."""
        depth_distribution: dict[str, int] = {}
        for entry in entries:
            dn_parts = entry.dn.value.split(",")
            depth = len(dn_parts)
            depth_key = f"depth_{depth}"
            depth_distribution[depth_key] = depth_distribution.get(depth_key, 0) + 1
        return FlextResult[dict[str, int]].ok(depth_distribution)

    def analyze_patterns(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, int]]:
        """Analyze patterns in LDIF entries."""
        return self.analyze_entries(entries)

    def get_config_info(self) -> dict[str, object]:
        """Get analytics service configuration information."""
        return {
            "service": "FlextLdifAnalyticsService",
            "config": {
                "analytics_enabled": True,
                "supported_metrics": [
                    "entry_count",
                    "attribute_count",
                    "dn_depth_analysis",
                ],
            },
        }


__all__ = ["FlextLdifAnalyticsService"]
