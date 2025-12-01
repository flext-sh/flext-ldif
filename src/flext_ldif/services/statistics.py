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

from flext_ldif._models.results import _CategoryPaths, _DynamicCounts
from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels


class FlextLdifStatistics(
    FlextLdifServiceBase[FlextLdifModels.StatisticsServiceStatus],
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

        # Build categorized counts as _DynamicCounts model
        # Create model with values using model_construct to avoid frozen model issues
        categorized_counts_dict = {
            category: len(entries) for category, entries in categorized.items()
        }
        categorized_counts_model = _DynamicCounts.model_construct(**categorized_counts_dict)

        rejected_entries_raw = categorized.get(FlextLdifConstants.Categories.REJECTED, [])
        # Type narrowing: categorized is Categories[Entry], so get() returns list[Entry]
        rejected_entries: list[FlextLdifModels.Entry] = [
            entry for entry in rejected_entries_raw
            if isinstance(entry, FlextLdifModels.Entry)
        ]
        rejection_count = len(rejected_entries)
        rejection_reasons = self._extract_rejection_reasons(rejected_entries)

        rejection_rate = rejection_count / total_entries if total_entries > 0 else 0.0

        # Build written counts as _DynamicCounts model
        # Create model with values using model_construct to avoid frozen model issues
        written_counts_model = _DynamicCounts.model_construct(**written_counts)

        # Build output files paths as _CategoryPaths model
        output_files_model = _CategoryPaths()
        for category in written_counts:
            path_str = str(output_dir / output_files.get(category, f"{category}.ldif"))
            setattr(output_files_model, category, path_str)

        return FlextResult[FlextLdifModels.StatisticsResult].ok(
            FlextLdifModels.StatisticsResult(
                total_entries=total_entries,
                categorized=categorized_counts_model,
                rejection_rate=rejection_rate,
                rejection_count=rejection_count,
                rejection_reasons=rejection_reasons,
                written_counts=written_counts_model,
                output_files=output_files_model,
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
                st_value := entry.metadata.extensions.get("server_type"),
                str,
            ):
                server_type_distribution[st_value] += 1

        # Build object_class_distribution as _DynamicCounts model
        obj_class_model = _DynamicCounts()
        for class_name, count in object_class_distribution.items():
            obj_class_model.set_count(class_name, count)

        # Build server_type_distribution as _DynamicCounts model
        server_type_model = _DynamicCounts()
        for server_type, count in server_type_distribution.items():
            server_type_model.set_count(server_type, count)

        return FlextResult[FlextLdifModels.EntriesStatistics].ok(
            FlextLdifModels.EntriesStatistics(
                total_entries=len(entries),
                object_class_distribution=obj_class_model,
                server_type_distribution=server_type_model,
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
