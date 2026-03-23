"""Statistics Service - Pipeline Statistics Generation and Analysis."""

from __future__ import annotations

from collections import Counter
from collections.abc import MutableMapping, MutableSequence
from pathlib import Path
from typing import override

from flext_ldif import FlextLdifServiceBase, d, m, r, u


class FlextLdifStatistics(FlextLdifServiceBase[m.Ldif.StatisticsServiceStatus]):
    """Statistics service for LDIF processing pipeline."""

    def __init__(self) -> None:
        """Initialize statistics service."""
        super().__init__()

    def calculate_for_entries(
        self,
        entries: MutableSequence[m.Ldif.Entry],
    ) -> r[m.Ldif.EntriesStatistics]:
        """Calculate general-purpose statistics for a list of Entry models."""
        object_class_distribution: Counter[str] = Counter()
        server_type_distribution: Counter[str] = Counter()
        for entry in entries:
            object_class_distribution.update(entry.get_objectclass_names())
            metadata = entry.metadata
            if metadata is not None:
                server_type_value = metadata.extensions.get("server_type")
                if isinstance(server_type_value, str):
                    server_type_distribution[server_type_value] += 1
        obj_class_model = m.Ldif.DynamicCounts()
        for class_name, count in object_class_distribution.items():
            obj_class_model.set_count(class_name, count)
        server_type_model = m.Ldif.DynamicCounts()
        for server_type, count in server_type_distribution.items():
            server_type_model.set_count(server_type, count)
        entries_stats = m.Ldif.EntriesStatistics(
            total_entries=len(entries),
            object_class_distribution=obj_class_model,
            server_type_distribution=server_type_model,
        )
        return r[m.Ldif.EntriesStatistics].ok(entries_stats)

    @override
    @d.log_operation("statistics_service_check")
    @d.track_operation()
    def execute(self) -> r[m.Ldif.StatisticsServiceStatus]:
        """Execute statistics service self-check."""
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
        categorized: m.Ldif.FlexibleCategories,
        written_counts: MutableMapping[str, int],
        output_dir: Path,
        output_files: MutableMapping[str, str],
    ) -> r[m.Ldif.StatisticsResult]:
        """Generate complete statistics for categorized migration."""
        total_entries = sum(
            len(entries) if isinstance(entries, list) else 0
            for entries in categorized.values()
        )
        categorized_counts_dict = {
            category: u.count(entries) for category, entries in categorized.items()
        }
        categorized_counts_model = m.Ldif.DynamicCounts.model_validate(
            categorized_counts_dict,
        )
        rejected_entries: MutableSequence[m.Ldif.Entry] = [
            m.Ldif.Entry.model_validate(entry)
            for entry in categorized.get("rejected", [])
        ]
        rejection_count = u.count(rejected_entries)
        _ = self._extract_rejection_reasons(rejected_entries)
        total_entries_int = total_entries
        rejection_rate = (
            rejection_count / total_entries_int if total_entries_int > 0 else 0.0
        )
        written_counts_model = m.Ldif.DynamicCounts.model_validate(written_counts)
        output_files_model = m.Ldif.CategoryPaths()
        for category in written_counts:
            filename = u.take(output_files, category, default=f"{category}.ldif")
            output_filename = (
                filename if isinstance(filename, str) else f"{category}.ldif"
            )
            setattr(
                output_files_model,
                category,
                str(output_dir.joinpath(output_filename)),
            )
        return r[m.Ldif.StatisticsResult].ok(
            m.Ldif.StatisticsResult(
                total_entries=total_entries_int,
                categorized=categorized_counts_model,
                rejection_rate=rejection_rate,
                rejection_count=rejection_count,
                written_counts=written_counts_model,
                output_files=output_files_model,
            ),
        )

    def _extract_rejection_reasons(
        self,
        rejected_entries: MutableSequence[m.Ldif.Entry],
    ) -> MutableSequence[str]:
        """Extract unique rejection reasons from rejected entries."""
        reasons: set[str] = set()
        for entry in rejected_entries:
            if entry.metadata and entry.metadata.processing_stats:
                reason = entry.metadata.processing_stats.rejection_reason
                if reason:
                    reasons.add(reason)
        return sorted(reasons)


__all__ = ["FlextLdifStatistics"]
