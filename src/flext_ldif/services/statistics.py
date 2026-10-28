"""Statistics Service - Pipeline Statistics Generation and Analysis.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence

from flext_ldif import m, p, r, s, u


class FlextLdifStatistics(s[p.Ldif.Response]):
    """Statistics service for LDIF processing pipeline."""

    @staticmethod
    def calculate_for_entries(
        entries: Sequence[p.Ldif.Entry] | p.Ldif.ParseResponse,
    ) -> p.Result[p.Ldif.EntriesStatistics]:
        """Calculate general-purpose statistics for a list of Entry models.

        Returns:
            The resulting ``p.Result[p.Ldif.EntriesStatistics]``.

        """
        normalized_entries = u.Ldif.as_entries(entries)
        object_class_distribution: Counter[str] = Counter()
        server_type_distribution: Counter[str] = Counter()
        for entry in normalized_entries:
            object_class_distribution.update(u.Ldif.resolve_objectclass_names(entry))
            metadata = entry.metadata
            if metadata is not None:
                server_type_value = metadata.extensions.get("server_type")
                if isinstance(server_type_value, str):
                    server_type_distribution[server_type_value] += 1
        entries_stats: p.Ldif.EntriesStatistics = m.Ldif.EntriesStatistics(
            total_entries=len(normalized_entries),
            object_class_distribution=m.Ldif.DynamicCounts(
                root=object_class_distribution
            ),
            server_type_distribution=m.Ldif.DynamicCounts(
                root=server_type_distribution
            ),
        )
        return r[p.Ldif.EntriesStatistics].ok(entries_stats)


__all__: list[str] = ["FlextLdifStatistics"]
