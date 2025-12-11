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

# Removed: # Import removed - use m.* facade (use m.* instead)
from flext_ldif._models.results import (
    FlextLdifModelsResults,
    _CategoryPaths,
    _FlexibleCategories,
)

# Note: _DynamicCounts is accessed via facade (m.Ldif.LdifResults.DynamicCounts)
# to maintain architecture layering
from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.models import m
from flext_ldif.utilities import u


class FlextLdifStatistics(
    FlextLdifServiceBase[m.Ldif.StatisticsServiceStatus],
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
    ) -> r[m.Ldif.StatisticsServiceStatus]:
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
        return r[m.Ldif.StatisticsServiceStatus].ok(
            m.Ldif.StatisticsServiceStatus(
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
        categorized: _FlexibleCategories,
        written_counts: dict[str, int],
        output_dir: Path,
        output_files: dict[str, str],
    ) -> r[FlextLdifModelsResults.StatisticsResult]:
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

        # Use u.count directly via u.map for unified counting (DSL pattern)
        def count_entries(entries: object) -> int:
            """Count entries in list."""
            # Type narrowing: entries is list[object] after isinstance check
            entries_list: list[object] = entries if isinstance(entries, list) else []
            return u.Collection.count(entries_list)

        # Convert values to list with explicit type casting
        # Build list manually to avoid ValuesView type issues with pyrefly
        # Use .items() to get (key, value) pairs and extract values
        categorized_values_list: list[object] = [
            entries for _category_key, entries in categorized.items()
        ]
        # Sum counts using built-in sum() - u.Collection.map returns list[int]
        mapped_counts = u.Collection.map(categorized_values_list, mapper=count_entries)
        total_entries = sum(mapped_counts) if isinstance(mapped_counts, list) else 0

        # Build categorized counts as _DynamicCounts model using DSL pattern
        # Use dict comprehension with u.count for clarity
        # Type narrowing: entries is list[object] from categorized dict
        categorized_counts_dict = {
            category: u.Collection.count(entries)
            for category, entries in categorized.items()
        }
        categorized_counts_model = m.Ldif.LdifResults.DynamicCounts.model_validate(
            categorized_counts_dict,
        )

        # Access rejected entries directly from categorized dict
        # u.Ldif.take() doesn't work correctly with _FlexibleCategories Pydantic models
        rejected_key = "rejected"
        # Type narrowing: categorized.get returns list[m.Ldif.Entry]
        rejected_entries_raw: list[m.Ldif.Entry] = (
            categorized.get(rejected_key, []) if hasattr(categorized, "get") else []
        )
        # Type narrowing: categorized is Categories[Entry], so get() returns list[Entry]
        # Use named function instead of lambda (DSL pattern)

        def is_entry(entry: object) -> bool:
            """Check if entry is Entry model."""
            return isinstance(entry, m.Ldif.Entry)

        # Use list comprehension to avoid u.filter overload issues with object type
        # Type narrowing: isinstance ensures list[m.Ldif.Entry]
        rejected_entries = [
            entry for entry in rejected_entries_raw if isinstance(entry, m.Ldif.Entry)
        ]
        rejection_count = u.Collection.count(rejected_entries)
        rejection_reasons = self._extract_rejection_reasons(rejected_entries)

        # Type narrowing: ensure total_entries is int for division
        total_entries_int = total_entries if isinstance(total_entries, int) else 0
        rejection_rate = (
            rejection_count / total_entries_int if total_entries_int > 0 else 0.0
        )

        # Build written counts as DynamicCounts model
        # Create model with values using model_validate for frozen models
        written_counts_model = m.Ldif.LdifResults.DynamicCounts.model_validate(
            written_counts
        )

        # Build output files paths as _CategoryPaths model
        output_files_model = _CategoryPaths()
        for category in written_counts:
            # Type narrowing: u.Ldif.take returns str when default is str
            path_str = str(
                output_dir
                / u.Ldif.take(output_files, category, default=f"{category}.ldif"),
            )
            setattr(output_files_model, category, path_str)

        return r[FlextLdifModelsResults.StatisticsResult].ok(
            FlextLdifModelsResults.StatisticsResult(
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
    ) -> r[FlextLdifModelsResults.EntriesStatistics]:
        """Calculate general-purpose statistics for a list of Entry models.

        Args:
            entries: Sequence of Entry models to analyze

        Returns:
            r containing EntriesStatistics model with distributions

        """
        object_class_distribution: Counter[str] = Counter()
        server_type_distribution: Counter[str] = Counter()

        def process_entry(entry: m.Ldif.Entry) -> None:
            """Process entry to update distributions."""
            object_class_distribution.update(entry.get_objectclass_names())

            # Check for server_type in metadata extensions
            if entry.metadata and entry.metadata.extensions:
                extensions = entry.metadata.extensions
                st_value = u.Ldif.take(extensions, "server_type", as_type=str)
                if st_value is not None:
                    server_type_distribution[st_value] += 1

        _ = u.Collection.batch(
            list(entries),
            process_entry,
            on_error="skip",
        )

        # Build object_class_distribution as DynamicCounts model
        obj_class_model = m.Ldif.LdifResults.DynamicCounts()
        for class_name, count in object_class_distribution.items():
            obj_class_model.set_count(class_name, count)

        # Build server_type_distribution as DynamicCounts model
        server_type_model = m.Ldif.LdifResults.DynamicCounts()
        for server_type, count in server_type_distribution.items():
            server_type_model.set_count(server_type, count)

        # Debug: Check what we have before creating EntriesStatistics
        # server_type_distribution dict should have the counts
        if not server_type_distribution:
            # If empty, create empty model
            server_type_model = m.Ldif.LdifResults.DynamicCounts()

        # Create EntriesStatistics - ensure we pass the populated models
        entries_stats = FlextLdifModelsResults.EntriesStatistics(
            total_entries=len(entries),
            object_class_distribution=obj_class_model,
            server_type_distribution=server_type_model,
        )

        return r[FlextLdifModelsResults.EntriesStatistics].ok(entries_stats)

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

        def extract_reason(entry: m.Ldif.Entry) -> str | r[str]:
            """Extract rejection reason from entry."""
            if entry.metadata and entry.metadata.processing_stats:
                reason = entry.metadata.processing_stats.rejection_reason
                if reason:
                    return r[str].ok(reason)
            return r[str].fail("No rejection reason")

        batch_result = u.Collection.batch(
            rejected_entries,
            extract_reason,
            on_error="skip",
        )
        # u.Collection.batch returns FlextResult[BatchResultDict]
        if batch_result.is_success and batch_result.value:
            batch_dict = batch_result.value
            results_raw = batch_dict.get("results", [])
            # Type narrowing: results_raw is list[t.GeneralValueType] from batch dict
            # extract_reason returns str | r[str], so results are str after unwrapping
            if not isinstance(results_raw, list):
                return sorted(reasons)
            results: list[str | None] = [
                str(r) if r is not None else None for r in results_raw
            ]
            for reason in results:
                if reason is not None:
                    reasons.add(reason)
        return sorted(reasons)


__all__ = ["FlextLdifStatistics"]
