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

from flext_ldif._models.results import (
    _CategoryPaths,
    _DynamicCounts,
    _FlexibleCategories,
)
from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels


class FlextLdifStatistics(
    FlextLdifServiceBase[FlextLdifModels.StatisticsServiceStatus],
):
    """Statistics service for LDIF processing pipeline.

    Business Rule: Statistics service generates comprehensive metrics for LDIF
    processing pipelines. Service provides categorization counts, rejection
    analysis, and output file tracking. All statistics are computed from
    categorized entries and written file counts.

    Implication: Statistics enable monitoring and analysis of migration pipelines.
    Service provides detailed metrics for each category (schema, hierarchy,
    users, groups, ACL, rejected) with file tracking and rejection reasons.

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

        Business Rule: Service health check validates statistics generation
        capabilities. Returns service status with available operations and
        version information for monitoring and diagnostics.

        Implication: Health check enables service discovery and monitoring.
        Status includes available capabilities (generate_statistics, count_entries,
        analyze_rejections) for dynamic feature detection.

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
        categorized: FlextLdifModels.FlexibleCategories | _FlexibleCategories,
        written_counts: dict[str, int],
        output_dir: Path,
        output_files: dict[str, str],
    ) -> FlextResult[FlextLdifModels.StatisticsResult]:
        """Generate complete statistics for categorized migration.

        Business Rule: Statistics generation computes comprehensive metrics from
        categorized entries and written file counts. Service aggregates counts
        by category, analyzes rejections, and tracks output files. Statistics
        include total entries, categorized counts, rejection analysis, and
        file metadata.

        Implication: Statistics enable monitoring and analysis of migration
        pipelines. Detailed metrics support troubleshooting and performance
        optimization. File tracking enables audit trails for migration operations.

        Args:
            categorized: FlexibleCategories model with categorized entries
            written_counts: Dictionary mapping category to count written
            output_dir: Output directory path
            output_files: Dictionary mapping category to output filename

        Returns:
            FlextResult containing StatisticsResult model with counts,
                rejection info, and metadata

        """
        total_entries = sum(len(entries) for entries in categorized.values())

        # Build categorized counts as _DynamicCounts model
        # Create model with values using model_validate for frozen models
        categorized_counts_dict = {
            category: len(entries) for category, entries in categorized.items()
        }
        categorized_counts_model = _DynamicCounts.model_validate(
            categorized_counts_dict
        )

        rejected_entries_raw = categorized.get(
            FlextLdifConstants.Categories.REJECTED, []
        )
        # Type narrowing: categorized is Categories[Entry], so get() returns list[Entry]
        rejected_entries: list[FlextLdifModels.Entry] = [
            entry
            for entry in rejected_entries_raw
            if isinstance(entry, FlextLdifModels.Entry)
        ]
        rejection_count = len(rejected_entries)
        rejection_reasons = self._extract_rejection_reasons(rejected_entries)

        rejection_rate = rejection_count / total_entries if total_entries > 0 else 0.0

        # Build written counts as _DynamicCounts model
        # Create model with values using model_validate for frozen models
        written_counts_model = _DynamicCounts.model_validate(written_counts)

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

            # Check for server_type in metadata extensions
            if entry.metadata:
                extensions = entry.metadata.extensions
                if extensions and isinstance(
                    st_value := extensions.get("server_type"),
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

        # Debug: Check what we have before creating EntriesStatistics
        # server_type_distribution dict should have the counts
        if not server_type_distribution:
            # If empty, create empty model
            server_type_model = _DynamicCounts()

        # Create EntriesStatistics - ensure we pass the populated models
        entries_stats = FlextLdifModels.EntriesStatistics(
            total_entries=len(entries),
            object_class_distribution=obj_class_model,
            server_type_distribution=server_type_model,
        )

        return FlextResult[FlextLdifModels.EntriesStatistics].ok(entries_stats)

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
