"""Statistics Service - Pipeline Statistics Generation and Analysis.

Provides comprehensive statistics and metrics for LDIF processing pipelines,
including categorization counts, rejection analysis, and output file tracking.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path
from typing import override

from flext_core import FlextDecorators, FlextResult, FlextService

from flext_ldif.constants import FlextLdifConstants


class FlextLdifStatisticsService(FlextService[dict[str, object]]):
    """Statistics service for LDIF processing pipeline.

    Provides methods for generating comprehensive statistics about
    categorized and migrated LDIF entries.

    This service replaces the utilities.py Statistics class with
    a proper service-oriented implementation.

    """

    def __init__(self) -> None:
        """Initialize statistics service."""
        super().__init__()

    @override
    @FlextDecorators.log_operation("statistics_service_check")
    @FlextDecorators.track_performance()
    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute statistics service self-check.

        Returns:
            FlextResult containing service status

        """
        return FlextResult[dict[str, object]].ok({
            "service": "StatisticsService",
            "status": "operational",
            "capabilities": [
                "generate_statistics",
                "count_entries",
                "analyze_rejections",
            ],
        })

    def generate_statistics(
        self,
        categorized: dict[str, list[dict[str, object]]],
        written_counts: dict[str, int],
        output_dir: Path,
        output_files: dict[str, object],
    ) -> FlextResult[dict[str, object]]:
        """Generate complete statistics for categorized migration.

        Args:
            categorized: Dictionary mapping category to entry list
            written_counts: Dictionary mapping category to count written
            output_dir: Output directory path
            output_files: Dictionary mapping category to output filename

        Returns:
            FlextResult containing statistics dictionary with counts, rejection info, and metadata

        """
        try:
            # Calculate total entries
            total_entries = sum(len(entries) for entries in categorized.values())

            # Build categorized counts
            categorized_counts: dict[str, object] = {}
            for category, entries in categorized.items():
                categorized_counts[category] = len(entries)

            # Count rejections and gather reasons
            rejected_entries = categorized.get("rejected", [])
            rejection_count = len(rejected_entries)
            rejection_reasons: list[str] = []

            for entry in rejected_entries:
                attrs = entry.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
                if isinstance(attrs, dict) and "rejectionReason" in attrs:
                    reason_value = attrs["rejectionReason"]
                    if (
                        isinstance(reason_value, str)
                        and reason_value not in rejection_reasons
                    ):
                        rejection_reasons.append(reason_value)

            # Calculate rejection rate
            rejection_rate = (
                rejection_count / total_entries if total_entries > 0 else 0.0
            )

            # Build output files info (LDIF files, not directories)
            output_files_info: dict[str, object] = {}
            for category in written_counts:
                filename_obj = output_files.get(category, f"{category}.ldif")
                category_filename = (
                    filename_obj
                    if isinstance(filename_obj, str)
                    else f"{category}.ldif"
                )
                output_path = output_dir / category_filename
                output_files_info[category] = str(output_path)

            return FlextResult[dict[str, object]].ok({
                "total_entries": total_entries,
                "categorized": categorized_counts,
                "rejection_rate": rejection_rate,
                "rejection_count": rejection_count,
                "rejection_reasons": rejection_reasons,
                "written_counts": written_counts,
                "output_files": output_files_info,
            })
        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[dict[str, object]].fail(
                f"Failed to generate statistics: {e}",
            )


__all__ = ["FlextLdifStatisticsService"]
