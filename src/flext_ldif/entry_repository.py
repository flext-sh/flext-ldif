"""FLEXT-LDIF Repository Service."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import FlextDomainService, FlextResult, get_logger
from pydantic import Field

if TYPE_CHECKING:
    from .config import FlextLdifConfig
    from .models import FlextLdifEntry

logger = get_logger(__name__)


class FlextLdifRepositoryService(FlextDomainService[dict[str, int]]):
    """Concrete LDIF repository service using flext-core patterns."""

    config: FlextLdifConfig | None = Field(default=None)

    def execute(self) -> FlextResult[dict[str, int]]:
        """Execute repository operation - required by FlextDomainService."""
        # This would be called with specific queries in real usage
        return FlextResult.ok({})

    def find_by_dn(
        self,
        entries: list[FlextLdifEntry],
        dn: str,
    ) -> FlextResult[FlextLdifEntry | None]:
        """Find entry by distinguished name."""
        if not dn or not dn.strip():
            return FlextResult.fail("DN cannot be empty")

        dn_lower = dn.lower()
        for entry in entries:
            if entry.dn.value.lower() == dn_lower:
                return FlextResult.ok(entry)

        return FlextResult.ok(None)

    def filter_by_objectclass(
        self,
        entries: list[FlextLdifEntry],
        objectclass: str,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter entries by objectClass attribute."""
        if not objectclass or not objectclass.strip():
            return FlextResult.fail("ObjectClass cannot be empty")

        filtered = [entry for entry in entries if entry.has_object_class(objectclass)]
        return FlextResult.ok(filtered)

    def filter_by_attribute(
        self,
        entries: list[FlextLdifEntry],
        attribute: str,
        value: str,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter entries by attribute value."""
        if not attribute or not attribute.strip():
            return FlextResult.fail("Attribute name cannot be empty")

        filtered = []
        for entry in entries:
            attr_values = entry.get_attribute(attribute)
            if attr_values and value in attr_values:
                filtered.append(entry)

        return FlextResult.ok(filtered)

    def get_statistics(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[dict[str, int]]:
        """Get statistical information about entries."""
        stats = {
            "total_entries": len(entries),
            "person_entries": 0,
            "group_entries": 0,
            "other_entries": 0,
        }

        for entry in entries:
            if entry.is_person_entry():
                stats["person_entries"] += 1
            elif entry.is_group_entry():
                stats["group_entries"] += 1
            else:
                stats["other_entries"] += 1

        return FlextResult.ok(stats)


__all__ = ["FlextLdifRepositoryService"]

# Rebuild model to resolve forward references after config is defined

# Note: model_rebuild() is called in api.py to avoid circular imports
