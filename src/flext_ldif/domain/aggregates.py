"""LDIF Domain Aggregates - Business Boundaries.

🏗️ CLEAN ARCHITECTURE: Domain Aggregates
Built on flext-core foundation patterns.

Aggregates define consistency boundaries in the LDIF domain.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import DomainAggregateRoot
from pydantic import Field

from flext_ldif.domain.events import LDIFDocumentParsed, LDIFProcessingCompleted

if TYPE_CHECKING:
    from flext_ldif.domain.entities import LDIFEntry
    from flext_ldif.domain.values import LDIFContent


class LDIFDocument(DomainAggregateRoot):
    """LDIF Document Aggregate Root.

    Manages the consistency boundary for LDIF document processing.
    Coordinates between entries, validation, and transformation.
    """

    content: str
    entries: list[LDIFEntry] = Field(default_factory=list)
    is_parsed: bool = False
    is_validated: bool = False

    def parse_content(self, content: LDIFContent) -> None:
        """Parse LDIF content into entries.

        Args:
            content: LDIF content to parse

        """
        self.content = str(content)
        self.is_parsed = True

        # Raise domain event
        event = LDIFDocumentParsed(
            aggregate_id=str(self.id),
            entry_count=len(self.entries),
            content_length=len(self.content),
        )
        self.add_event(event)

    def add_entry(self, entry: LDIFEntry) -> None:
        """Add entry to document.

        Args:
            entry: LDIF entry to add

        """
        self.entries.append(entry)

    def validate_document(self) -> bool:
        """Validate entire document.

        Returns:
            True if document is valid

        """
        # Basic validation
        if not self.is_parsed or not self.entries:
            return False

        # Validate all entries have unique DNs
        dns = [entry.dn for entry in self.entries if entry.dn]
        if len(dns) != len(set(dns)):
            return False

        self.is_validated = True
        return True

    def complete_processing(self) -> None:
        """Mark processing as completed."""
        if self.is_parsed and self.is_validated:
            event = LDIFProcessingCompleted(
                aggregate_id=str(self.id),
                entry_count=len(self.entries),
                success=True,
            )
            self.add_event(event)

    def get_entry_count(self) -> int:
        """Get number of entries in document.

        Returns:
            Number of entries

        """
        return len(self.entries)

    def get_entries_by_objectclass(self, object_class: str) -> list[LDIFEntry]:
        """Get entries filtered by object class.

        Args:
            object_class: Object class to filter by

        Returns:
            List of matching entries

        """
        matching_entries = []
        for entry in self.entries:
            object_classes = entry.attributes.get_values("objectClass")
            if object_class in object_classes:
                matching_entries.append(entry)
        return matching_entries
