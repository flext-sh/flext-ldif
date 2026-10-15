"""LDIF entry statistics metadata utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableMapping

from flext_ldif import FlextLdifModels, c, t
from flext_ldif._models import FlextLdifModelsDomainEntryStatistics
from flext_ldif._utilities import FlextLdifMetadataBuilders, FlextLdifUtilitiesServer


class FlextLdifMetadataEntryStats:
    """Apply category, filter, and rejection updates to entry statistics."""

    @staticmethod
    def _apply_category_update(
        stats: FlextLdifModelsDomainEntryStatistics,
        category: str,
    ) -> FlextLdifModelsDomainEntryStatistics:
        """Apply category update to stats using model_copy.

        Returns:
            The resulting ``FlextLdifModelsDomainEntryStatistics``.

        """
        copied: FlextLdifModelsDomainEntryStatistics = stats.model_copy(
            update={"category_assigned": category},
        )
        return copied

    @staticmethod
    def _apply_filter_update(
        stats: FlextLdifModelsDomainEntryStatistics,
        filter_type: str,
        *,
        passed: bool,
    ) -> FlextLdifModelsDomainEntryStatistics:
        """Apply filter marking to stats.

        Returns:
            The resulting ``FlextLdifModelsDomainEntryStatistics``.

        """
        return stats.mark_filtered(filter_type, passed=passed)

    @staticmethod
    def _apply_rejection_update(
        stats: FlextLdifModelsDomainEntryStatistics,
        rejection_category: str,
        reason: str,
    ) -> FlextLdifModelsDomainEntryStatistics:
        """Apply rejection marking to stats.

        Returns:
            The resulting ``FlextLdifModelsDomainEntryStatistics``.

        """
        return stats.mark_rejected(rejection_category, reason)

    @staticmethod
    def _update_entry_with_stats(
        entry: FlextLdifModels.Ldif.Entry,
        updated_stats: FlextLdifModelsDomainEntryStatistics,
    ) -> FlextLdifModels.Ldif.Entry:
        """Update entry with new processing stats using model_copy.

        Returns:
            The resulting ``FlextLdifModels.Ldif.Entry``.

        """
        entry_metadata = entry.metadata
        if entry_metadata is None:
            entry_metadata = FlextLdifMetadataBuilders.server_metadata_for(
                FlextLdifUtilitiesServer.normalize_server_type(
                    c.Ldif.ServerTypes.RFC.value
                ),
            )
        update_dict: MutableMapping[str, FlextLdifModelsDomainEntryStatistics] = {
            "processing_stats": updated_stats,
        }
        updated_metadata = entry_metadata.model_copy(update=update_dict)
        updated_entry: FlextLdifModels.Ldif.Entry = entry.model_copy(
            update={"metadata": updated_metadata},
        )
        return updated_entry

    @staticmethod
    def update_entry_statistics(
        entry: FlextLdifModels.Ldif.Entry,
        *,
        category: str | None = None,
        mark_rejected: t.StrPair | None = None,
        mark_filtered: tuple[str, bool] | None = None,
    ) -> FlextLdifModels.Ldif.Entry:
        """Update entry processing statistics using FlextLdifUtilities.

        Returns:
            The resulting ``FlextLdifModels.Ldif.Entry``.

        """
        processing_stats = (
            entry.metadata.processing_stats if entry.metadata is not None else None
        )
        updated_stats = (
            FlextLdifModelsDomainEntryStatistics.model_validate(
                processing_stats.model_dump(),
            )
            if processing_stats is not None
            else FlextLdifModelsDomainEntryStatistics(
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
            updated_stats = FlextLdifMetadataEntryStats._apply_category_update(
                updated_stats,
                category,
            )
        if mark_filtered is not None:
            filter_type, passed = mark_filtered
            updated_stats = FlextLdifMetadataEntryStats._apply_filter_update(
                updated_stats,
                filter_type,
                passed=passed,
            )
        if mark_rejected is not None:
            rejection_category, reason = mark_rejected
            updated_stats = FlextLdifMetadataEntryStats._apply_rejection_update(
                updated_stats,
                rejection_category,
                reason,
            )
        return FlextLdifMetadataEntryStats._update_entry_with_stats(
            entry,
            updated_stats,
        )


__all__: list[str] = ["FlextLdifMetadataEntryStats"]
