"""FLEXT-LDIF Analytics Service.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import override

from flext_core import FlextDomainService, FlextResult, get_logger
from pydantic import Field

from flext_ldif.constants import FlextLdifAnalyticsConstants
from flext_ldif.models import (
    FlextLdifConfig,
    FlextLdifEntry,
)

logger = get_logger(__name__)


class FlextLdifAnalyticsService(FlextDomainService[dict[str, int]]):
    """Concrete LDIF analytics service using flext-core patterns."""

    config: FlextLdifConfig = Field(default_factory=FlextLdifConfig)

    @override
    def execute(self) -> FlextResult[dict[str, int]]:
        """Execute analytics operation - required by FlextDomainService."""
        # This would be called with specific entries in real usage
        return FlextResult[dict[str, int]].ok({
            FlextLdifAnalyticsConstants.TOTAL_ENTRIES_KEY: 0
        })

    def analyze_entry_patterns(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[dict[str, int]]:
        """Analyze patterns in LDIF entries."""
        patterns = {
            FlextLdifAnalyticsConstants.TOTAL_ENTRIES_KEY: len(entries),
            FlextLdifAnalyticsConstants.ENTRIES_WITH_CN_KEY: 0,
            FlextLdifAnalyticsConstants.ENTRIES_WITH_MAIL_KEY: 0,
            FlextLdifAnalyticsConstants.ENTRIES_WITH_TELEPHONE_KEY: 0,
        }

        for entry in entries:
            if entry.has_attribute(FlextLdifAnalyticsConstants.CN_ATTRIBUTE):
                patterns[FlextLdifAnalyticsConstants.ENTRIES_WITH_CN_KEY] += 1
            if entry.has_attribute(FlextLdifAnalyticsConstants.MAIL_ATTRIBUTE):
                patterns[FlextLdifAnalyticsConstants.ENTRIES_WITH_MAIL_KEY] += 1
            if entry.has_attribute(FlextLdifAnalyticsConstants.TELEPHONE_ATTRIBUTE):
                patterns[FlextLdifAnalyticsConstants.ENTRIES_WITH_TELEPHONE_KEY] += 1

        return FlextResult[dict[str, int]].ok(patterns)

    def get_objectclass_distribution(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[dict[str, int]]:
        """Get distribution of objectClass types."""
        distribution: dict[str, int] = {}

        for entry in entries:
            object_classes = entry.get_object_classes()
            for obj_class in object_classes:
                distribution[obj_class] = distribution.get(obj_class, 0) + 1

        return FlextResult[dict[str, int]].ok(distribution)

    def get_dn_depth_analysis(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[dict[str, int]]:
        """Analyze DN depth distribution."""
        depth_analysis: dict[str, int] = {}

        for entry in entries:
            depth = entry.dn.get_depth()
            depth_key = FlextLdifAnalyticsConstants.DEPTH_KEY_FORMAT.format(depth=depth)
            depth_analysis[depth_key] = depth_analysis.get(depth_key, 0) + 1

        return FlextResult[dict[str, int]].ok(depth_analysis)


__all__ = ["FlextLdifAnalyticsService"]
