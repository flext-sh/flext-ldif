"""FLEXT LDIF Analytics Service - LDIF analytics and reporting.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult

from flext_ldif.models import FlextLDIFModels


class FlextLDIFAnalyticsService:
    """LDIF Analytics Service - Single Responsibility.

    Handles all LDIF analytics operations with enterprise-grade error handling.
    Uses flext-core SOURCE OF TRUTH exclusively.
    """

    def analyze_entries(
        self, entries: list[FlextLDIFModels.Entry]
    ) -> FlextResult[dict[str, int]]:
        """Analyze LDIF entries and return statistics."""
        try:
            stats = {
                "total_entries": len(entries),
                "person_entries": sum(1 for e in entries if e.is_person()),
                "group_entries": sum(1 for e in entries if e.is_group()),
                "organizational_unit_entries": sum(
                    1
                    for e in entries
                    if "organizationalunit"
                    in (oc.lower() for oc in (e.get_attribute("objectClass") or []))
                ),
            }
            return FlextResult[dict[str, int]].ok(stats)
        except Exception as e:
            return FlextResult[dict[str, int]].fail(f"Analysis error: {e}")

    def get_objectclass_distribution(
        self, entries: list[FlextLDIFModels.Entry]
    ) -> FlextResult[dict[str, int]]:
        """Get object class distribution."""
        try:
            distribution: dict[str, int] = {}
            for entry in entries:
                object_classes = entry.get_attribute("objectClass") or []
                for oc in object_classes:
                    oc_lower = oc.lower()
                    distribution[oc_lower] = distribution.get(oc_lower, 0) + 1
            return FlextResult[dict[str, int]].ok(distribution)
        except Exception as e:
            return FlextResult[dict[str, int]].fail(f"ObjectClass analysis error: {e}")

    def get_dn_depth_analysis(
        self, entries: list[FlextLDIFModels.Entry]
    ) -> FlextResult[dict[str, int]]:
        """Analyze DN depth distribution."""
        try:
            depth_distribution: dict[str, int] = {}
            for entry in entries:
                dn_parts = entry.dn.value.split(",")
                depth = len(dn_parts)
                depth_key = f"depth_{depth}"
                depth_distribution[depth_key] = depth_distribution.get(depth_key, 0) + 1
            return FlextResult[dict[str, int]].ok(depth_distribution)
        except Exception as e:
            return FlextResult[dict[str, int]].fail(f"DN depth analysis error: {e}")

    def analyze_patterns(
        self, entries: list[FlextLDIFModels.Entry]
    ) -> FlextResult[dict[str, int]]:
        """Analyze patterns in LDIF entries - alias for analyze_entries."""
        return self.analyze_entries(entries)

    def get_config_info(self) -> dict[str, object]:
        """Get analytics service configuration information."""
        return {
            "service": "FlextLDIFAnalyticsService",
            "config": {
                "analytics_enabled": True,
                "supported_metrics": [
                    "entry_count",
                    "attribute_count",
                    "dn_depth_analysis",
                ],
            },
        }


__all__ = ["FlextLDIFAnalyticsService"]
