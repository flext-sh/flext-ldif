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

from flext_core import d, r

from flext_ldif._models.results import FlextLdifModelsResults
from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.models import m
from flext_ldif.utilities import u


class FlextLdifStatistics(
    FlextLdifServiceBase[FlextLdifModelsResults.StatisticsServiceStatus],
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
    Uses ucessing and FlextResult for error handling.
    """

    def __init__(self) -> None:
        """Initialize statistics service."""
        super().__init__()

    @override
    @d.log_operation("statistics_service_check")
    @d.track_performance()
    def execute(
        self,
    ) -> r[m.Ldif.LdifResults.StatisticsServiceStatus]:
        """Execute statistics service self-check.

        Business Rule: Service health check validates statistics generation
        capabilities. Returns service status with available operations and
        version information for monitoring and diagnostics.

        Implication: Health check enables service discovery and monitoring.
        Status includes available capabilities (generate_statistics, count_entries,
        analyze_rejections) for dynamic feature detection.

        Returns:
            r containing service status (health check)

        """
        return r[m.Ldif.LdifResults.StatisticsServiceStatus].ok(
            m.Ldif.LdifResults.StatisticsServiceStatus(
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
        categorized: m.Ldif.LdifResults.FlexibleCategories,
        written_counts: dict[str, int],
        output_dir: Path,
        output_files: dict[str, str],
    ) -> r[m.Ldif.LdifResults.StatisticsResult]:
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
            r containing StatisticsResult model with counts,
                rejection info, and metadata

        """
        # Convert values to list with explicit type casting for counting
        categorized_values_list: list[object] = [
            entries for _category_key, entries in categorized.items()
        ]
        # Sum counts using utilities
        total_entries = sum(
            u.Ldif.count(entries) if isinstance(entries, list) else 0
            for entries in categorized_values_list
        )

        # Build categorized counts using utilities and model validation
        categorized_counts_dict = {
            category: u.Ldif.count(entries) for category, entries in categorized.items()
        }
        categorized_counts_model = m.Ldif.LdifResults.DynamicCounts.model_validate(
            categorized_counts_dict,
        )

        # Access rejected entries directly from categorized dict
        rejected_entries = [
            entry
            for entry in categorized.get("rejected", [])
            if isinstance(entry, m.Ldif.Entry)
        ]
        rejection_count = u.Ldif.count(rejected_entries)
        rejection_reasons = self._extract_rejection_reasons(rejected_entries)

        # Calculate rejection rate as percentage
        total_entries_int = total_entries if isinstance(total_entries, int) else 0
        rejection_rate = (
            rejection_count / total_entries_int if total_entries_int > 0 else 0.0
        )

        # Build written counts and output files models
        written_counts_model = m.Ldif.LdifResults.DynamicCounts.model_validate(
            written_counts,
        )

        output_files_model = m.Ldif.Results.CategoryPaths()
        for category in written_counts:
            filename = u.Ldif.take(output_files, category, default=f"{category}.ldif")
            filename_str = filename if isinstance(filename, str) else f"{category}.ldif"
            setattr(output_files_model, category, str(output_dir / filename_str))

        return r[m.Ldif.LdifResults.StatisticsResult].ok(
            m.Ldif.LdifResults.StatisticsResult(
                total_entries=total_entries_int,
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
        entries: Sequence[m.Ldif.Entry],
    ) -> r[m.Ldif.LdifResults.EntriesStatistics]:
        """Calculate general-purpose statistics for a list of Entry models.

        Args:
            entries: Sequence of Entry models to analyze

        Returns:
            r containing EntriesStatistics model with distributions

        """
        object_class_distribution: Counter[str] = Counter()
        server_type_distribution: Counter[str] = Counter()

        for entry in entries:
            object_class_distribution.update(entry.get_objectclass_names())

            # Check for server_type in metadata extensions
            if entry.metadata and entry.metadata.extensions:
                st_value = u.Ldif.take(
                    entry.metadata.extensions,
                    "server_type",
                    as_type=str,
                )
                if st_value is not None:
                    server_type_distribution[st_value] += 1

        # Process entries directly - batch processing handled inline

        # Build distribution models
        obj_class_model = m.Ldif.LdifResults.DynamicCounts()
        for class_name, count in object_class_distribution.items():
            obj_class_model.set_count(class_name, count)

        server_type_model = m.Ldif.LdifResults.DynamicCounts()
        for server_type, count in server_type_distribution.items():
            server_type_model.set_count(server_type, count)

        # Create EntriesStatistics - ensure we pass the populated models
        entries_stats = m.Ldif.LdifResults.EntriesStatistics(
            total_entries=len(entries),
            object_class_distribution=obj_class_model,
            server_type_distribution=server_type_model,
        )

        return r[m.Ldif.LdifResults.EntriesStatistics].ok(entries_stats)

    def _extract_rejection_reasons(
        self,
        rejected_entries: list[m.Ldif.Entry],
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
                reason = entry.metadata.processing_stats.rejection_reason
                if reason:
                    reasons.add(reason)

        return sorted(reasons)


__all__ = ["FlextLdifStatistics"]
