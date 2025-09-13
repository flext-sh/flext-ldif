"""FLEXT LDIF Repository Service - LDIF repository service implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult

from flext_ldif.models import FlextLDIFModels


class FlextLDIFRepositoryService:
    """LDIF Repository Service - Single Responsibility.

    Handles all LDIF repository operations with enterprise-grade error handling.
    Uses flext-core SOURCE OF TRUTH exclusively.
    """

    def find_entry_by_dn(
        self, entries: list[FlextLDIFModels.Entry], dn: str
    ) -> FlextResult[FlextLDIFModels.Entry | None]:
        """Find entry by DN."""
        try:
            for entry in entries:
                if entry.dn.value.lower() == dn.lower():
                    return FlextResult[FlextLDIFModels.Entry | None].ok(entry)
            return FlextResult[FlextLDIFModels.Entry | None].ok(None)
        except Exception as e:
            return FlextResult[FlextLDIFModels.Entry | None].fail(f"Find error: {e}")

    def filter_entries_by_attribute(
        self,
        entries: list[FlextLDIFModels.Entry],
        attribute_name: str,
        attribute_value: str | None,
    ) -> FlextResult[list[FlextLDIFModels.Entry]]:
        """Filter entries by attribute value."""
        try:
            if not attribute_name or not attribute_name.strip():
                return FlextResult[list[FlextLDIFModels.Entry]].fail(
                    "Attribute name cannot be empty"
                )

            filtered_entries: list[FlextLDIFModels.Entry] = []
            for entry in entries:
                values = entry.get_attribute(attribute_name) or []
                if attribute_value is None:
                    # Filter by presence of attribute (any value)
                    if values:
                        filtered_entries.append(entry)
                # Filter by specific attribute value
                elif attribute_value in values:
                    filtered_entries.append(entry)
            return FlextResult[list[FlextLDIFModels.Entry]].ok(filtered_entries)
        except Exception as e:
            return FlextResult[list[FlextLDIFModels.Entry]].fail(f"Filter error: {e}")

    def filter_entries_by_objectclass(
        self, entries: list[FlextLDIFModels.Entry], object_class: str
    ) -> FlextResult[list[FlextLDIFModels.Entry]]:
        """Filter entries by object class."""
        try:
            if not object_class or not object_class.strip():
                return FlextResult[list[FlextLDIFModels.Entry]].fail(
                    "Object class cannot be empty"
                )

            filtered_entries: list[FlextLDIFModels.Entry] = []
            for entry in entries:
                object_classes = entry.get_attribute("objectClass") or []
                if object_class.lower() in (oc.lower() for oc in object_classes):
                    filtered_entries.append(entry)
            return FlextResult[list[FlextLDIFModels.Entry]].ok(filtered_entries)
        except Exception as e:
            return FlextResult[list[FlextLDIFModels.Entry]].fail(
                f"ObjectClass filter error: {e}"
            )

    def filter_entries_by_object_class(
        self, entries: list[FlextLDIFModels.Entry], object_class: str
    ) -> FlextResult[list[FlextLDIFModels.Entry]]:
        """Filter entries by object class - alias for filter_entries_by_objectclass."""
        return self.filter_entries_by_objectclass(entries, object_class)

    def get_statistics(
        self, entries: list[FlextLDIFModels.Entry]
    ) -> FlextResult[dict[str, int]]:
        """Get comprehensive entry statistics."""
        try:
            unique_dns = len({e.dn.value for e in entries})
            total_attributes = sum(len(e.attributes.data) for e in entries)

            stats = {
                "total_entries": len(entries),
                "unique_dns": unique_dns,
                "total_attributes": total_attributes,
                "person_entries": sum(1 for e in entries if e.is_person()),
                "group_entries": sum(1 for e in entries if e.is_group()),
                "organizational_unit_entries": sum(
                    1
                    for e in entries
                    if "organizationalunit"
                    in (oc.lower() for oc in (e.get_attribute("objectClass") or []))
                ),
            }
            return FlextResult[dict[str, int]].ok(stats)
        except Exception as e:
            return FlextResult[dict[str, int]].fail(f"Statistics error: {e}")

    def get_config_info(self) -> dict[str, object]:
        """Get repository service configuration information."""
        return {
            "service": "FlextLDIFRepositoryService",
            "config": {
                "repository_enabled": True,
                "supported_operations": [
                    "store_entries",
                    "retrieve_entries",
                    "get_statistics",
                ],
                "storage_backend": "memory",
            },
        }


__all__ = ["FlextLDIFRepositoryService"]
