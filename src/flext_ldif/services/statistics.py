"""Statistics Service - Pipeline Statistics Generation and Analysis."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import override

from flext_core import d, r

from flext_ldif._models.results import FlextLdifModelsResults
from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.models import m
from flext_ldif.utilities import FlextLdifUtilities as u


class FlextLdifStatistics(
    FlextLdifServiceBase[FlextLdifModelsResults.StatisticsServiceStatus],
):
    """Statistics service for LDIF processing pipeline."""

    def __init__(self) -> None:
        """Initialize statistics service."""
        super().__init__()

    @override
    @d.log_operation("statistics_service_check")
    @d.track_performance()
    def execute(
        self,
    ) -> r[m.Ldif.LdifResults.StatisticsServiceStatus]:
        """Execute statistics service self-check."""
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
        """Generate complete statistics for categorized migration."""
        categorized_values_list: list[object] = [
            entries for _category_key, entries in categorized.items()
        ]

        total_entries = sum(
            u.count(entries) if isinstance(entries, list) else 0
            for entries in categorized_values_list
        )

        categorized_counts_dict = {
            category: u.count(entries) for category, entries in categorized.items()
        }
        categorized_counts_model = m.Ldif.LdifResults.DynamicCounts.model_validate(
            categorized_counts_dict,
        )

        rejected_entries = [
            entry
            for entry in categorized.get("rejected", [])
            if isinstance(entry, m.Ldif.Entry)
        ]
        rejection_count = u.count(rejected_entries)
        rejection_reasons = self._extract_rejection_reasons(rejected_entries)

        total_entries_int = total_entries if isinstance(total_entries, int) else 0
        rejection_rate = (
            rejection_count / total_entries_int if total_entries_int > 0 else 0.0
        )

        written_counts_model = m.Ldif.LdifResults.DynamicCounts.model_validate(
            written_counts,
        )

        output_files_model = m.Ldif.Results.CategoryPaths()
        for category in written_counts:
            filename = u.take(output_files, category, default=f"{category}.ldif")
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
        """Calculate general-purpose statistics for a list of Entry models."""
        object_class_distribution: Counter[str] = Counter()
        server_type_distribution: Counter[str] = Counter()

        for entry in entries:
            object_class_distribution.update(entry.get_objectclass_names())

            if entry.metadata is not None and entry.metadata.extensions is not None:
                st_value = u.take(
                    entry.metadata.extensions,
                    "server_type",
                    as_type=str,
                )
                if st_value is not None and isinstance(st_value, str):
                    server_type_distribution[st_value] += 1

        obj_class_model = m.Ldif.LdifResults.DynamicCounts()
        for class_name, count in object_class_distribution.items():
            obj_class_model.set_count(class_name, count)

        server_type_model = m.Ldif.LdifResults.DynamicCounts()
        for server_type, count in server_type_distribution.items():
            server_type_model.set_count(server_type, count)

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
        """Extract unique rejection reasons from rejected entries."""
        reasons: set[str] = set()

        for entry in rejected_entries:
            if entry.metadata and entry.metadata.processing_stats:
                reason = entry.metadata.processing_stats.rejection_reason
                if reason:
                    reasons.add(reason)

        return sorted(reasons)


__all__ = ["FlextLdifStatistics"]
