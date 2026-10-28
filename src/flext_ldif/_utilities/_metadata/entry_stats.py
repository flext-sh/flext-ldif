"""LDIF entry statistics metadata utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import FlextLdifModels, c, t
from flext_ldif._models import FlextLdifModelsDomainEntryStatistics


class FlextLdifUtilitiesMetadataEntryStats:
    """Apply category, filter, and rejection updates to entry statistics."""

    @staticmethod
    def update_entry_statistics(
        entry: FlextLdifModels.Ldif.Entry,
        *,
        category: str | None = None,
        mark_rejected: t.StrPair | None = None,
        mark_filtered: tuple[str, bool] | None = None,
    ) -> FlextLdifModels.Ldif.Entry:
        """Apply immutable statistics updates without revalidating owned models.

        Returns:
            The resulting ``FlextLdifModels.Ldif.Entry``.

        """
        processing_stats = (
            entry.metadata.processing_stats if entry.metadata is not None else None
        )
        updated_stats = (
            processing_stats
            if processing_stats is not None
            else FlextLdifModelsDomainEntryStatistics.EntryStatistics(
                attributes_added=[],
                attributes_removed=[],
                attributes_modified=[],
                attributes_filtered=[],
                objectclasses_original=[],
                objectclasses_final=[],
                servers_applied=[],
                filters_applied=[],
                filter_results={},
                errors=[],
                warnings=[],
            )
        )
        if category is not None:
            updated_stats = updated_stats.model_copy(
                update={"category_assigned": category},
            )
        if mark_filtered is not None:
            filter_type, passed = mark_filtered
            updated_stats = updated_stats.mark_filtered(filter_type, passed=passed)
        if mark_rejected is not None:
            rejection_category, reason = mark_rejected
            updated_stats = updated_stats.mark_rejected(rejection_category, reason)
        entry_metadata = entry.metadata
        if entry_metadata is None:
            entry_metadata = FlextLdifModels.Ldif.ServerMetadata(
                server_type=c.Ldif.ServerTypes.RFC,
            )
        return entry.model_copy(
            update={
                "metadata": entry_metadata.model_copy(
                    update={"processing_stats": updated_stats},
                ),
            },
        )


__all__: list[str] = ["FlextLdifUtilitiesMetadataEntryStats"]
