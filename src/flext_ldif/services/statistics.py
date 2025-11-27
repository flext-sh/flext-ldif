"""Statistics Service - Pipeline Statistics Generation and Analysis.

Provides comprehensive statistics and metrics for LDIF processing pipelines,
including categorization counts, rejection analysis, and output file tracking.

Scope: Statistics generation for categorized entries, rejection analysis,
and output file tracking for LDIF processing pipelines.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import override

from flext_core import FlextDecorators, FlextResult

from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels


class FlextLdifStatistics(
    FlextLdifServiceBase[FlextLdifModels.StatisticsServiceStatus]
):
    """Statistics service for LDIF processing pipeline.

    Provides methods for generating comprehensive statistics about
    categorized and migrated LDIF entries.

    Single Responsibility: Statistics generation and analysis only.
    Uses FlextUtilities for data processing and FlextResult for error handling.
    """

    def __init__(self) -> None:
        """Initialize statistics service."""
        super().__init__()

    @override
    @FlextDecorators.log_operation("statistics_service_check")
    @FlextDecorators.track_performance()
    def execute(
        self,
    ) -> FlextResult[FlextLdifModels.StatisticsServiceStatus]:
        """Execute statistics service self-check.

        Returns:
            FlextResult containing service status (health check)

        """
        return FlextResult[FlextLdifModels.StatisticsServiceStatus].ok(
            FlextLdifModels.StatisticsServiceStatus(
                service="StatisticsService",
                status="operational",
                capabilities=[
                    "generate_statistics",
                    "count_entries",
                    "analyze_rejections",
                ],
                version="1.0.0",
            ),
        )

    def generate_statistics(
        self,
        categorized: FlextLdifModels.FlexibleCategories,
        written_counts: dict[str, int],
        output_dir: Path,
        output_files: dict[str, str],
    ) -> FlextResult[FlextLdifModels.StatisticsResult]:
        """Generate complete statistics for categorized migration.

        Args:
            categorized: FlexibleCategories model with categorized entries
            written_counts: Dictionary mapping category to count written
            output_dir: Output directory path
            output_files: Dictionary mapping category to output filename

        Returns:
            FlextResult containing StatisticsResult model with counts, rejection info, and metadata

        """
        total_entries = sum(len(entries) for entries in categorized.values())
        categorized_counts = {
            category: len(entries) for category, entries in categorized.items()
        }

        rejected_entries = categorized.get(FlextLdifConstants.Categories.REJECTED, [])
        rejection_count = len(rejected_entries)
        rejection_reasons = self._extract_rejection_reasons(rejected_entries)

        rejection_rate = rejection_count / total_entries if total_entries > 0 else 0.0

        output_files_info = {
            category: str(output_dir / output_files.get(category, f"{category}.ldif"))
            for category in written_counts
        }

        return FlextResult[FlextLdifModels.StatisticsResult].ok(
            FlextLdifModels.StatisticsResult(
                total_entries=total_entries,
                categorized=categorized_counts,
                rejection_rate=rejection_rate,
                rejection_count=rejection_count,
                rejection_reasons=rejection_reasons,
                written_counts=written_counts,
                output_files=output_files_info,
            ),
        )

    def calculate_for_entries(
        self,
        entries: Sequence[FlextLdifModels.Entry],
    ) -> FlextResult[FlextLdifModels.EntriesStatistics]:
        """Calculate general-purpose statistics for a list of Entry models.

        Args:
            entries: Sequence of Entry models to analyze

        Returns:
            FlextResult containing EntriesStatistics model with distributions

        """
        object_class_distribution: Counter[str] = Counter()
        server_type_distribution: Counter[str] = Counter()

        for entry in entries:
            object_class_distribution.update(entry.get_objectclass_names())

            if entry.metadata and isinstance(
                st_value := entry.metadata.extensions.get("server_type"), str
            ):
                server_type_distribution[st_value] += 1

        return FlextResult[FlextLdifModels.EntriesStatistics].ok(
            FlextLdifModels.EntriesStatistics(
                total_entries=len(entries),
                object_class_distribution=dict(object_class_distribution),
                server_type_distribution=dict(server_type_distribution),
            ),
        )

    def _extract_rejection_reasons(
        self,
        rejected_entries: list[FlextLdifModels.Entry],
    ) -> list[str]:
        """Extract unique rejection reasons from rejected entries.

        Args:
            rejected_entries: List of rejected Entry models

        Returns:
            List of unique rejection reason strings

        """
        reasons: set[str] = set()
        for entry in rejected_entries:
            if entry.metadata and entry.metadata.processing_stats:
                rejection_reason = entry.metadata.processing_stats.rejection_reason
                if rejection_reason is not None:
                    reasons.add(rejection_reason)
        return sorted(reasons)


__all__ = ["FlextLdifStatistics"]
