"""Statistics Service - Pipeline Statistics Generation and Analysis."""

from __future__ import annotations

from collections import Counter

from flext_ldif import m, p, r, s, t, u


class FlextLdifStatistics(s):
    """Statistics service for LDIF processing pipeline."""

    def calculate_for_entries(
        self, entries: t.MutableSequenceOf[m.Ldif.Entry] | m.Ldif.ParseResponse
    ) -> p.Result[m.Ldif.EntriesStatistics]:
        """Calculate general-purpose statistics for a list of Entry models."""
        normalized_entries = u.Ldif.as_entries(entries)
        object_class_distribution: Counter[str] = Counter()
        server_type_distribution: Counter[str] = Counter()
        for entry in normalized_entries:
            object_class_distribution.update(u.Ldif.get_objectclass_names(entry))
            metadata = entry.metadata
            if metadata is not None:
                server_type_value = metadata.extensions.get("server_type")
                if isinstance(server_type_value, str):
                    server_type_distribution[server_type_value] += 1
        obj_class_model = m.Ldif.DynamicCounts()
        for class_name, count in object_class_distribution.items():
            obj_class_model.update_count(class_name, count)
        server_type_model = m.Ldif.DynamicCounts()
        for server_type, count in server_type_distribution.items():
            server_type_model.update_count(server_type, count)
        entries_stats = m.Ldif.EntriesStatistics(
            total_entries=len(normalized_entries),
            object_class_distribution=obj_class_model,
            server_type_distribution=server_type_model,
        )
        return r[m.Ldif.EntriesStatistics].ok(entries_stats)


__all__: list[str] = ["FlextLdifStatistics"]
