"""FlextLdif Domain Aggregates - Business Boundaries.

🏗️ CLEAN ARCHITECTURE: Domain Aggregates
Built on flext-core foundation patterns.

Aggregates define consistency boundaries in the FlextLdif domain.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext-core root namespace imports
from flext_core import FlextAggregateRoot
from pydantic import Field

from flext_ldif.domain.events import (
    FlextLdifDocumentParsed,
    FlextLdifProcessingCompleted,
)

if TYPE_CHECKING:
    from flext_ldif.domain.entities import FlextLdifEntry
    from flext_ldif.domain.values import LDIFContent


class FlextLdifDocument(FlextAggregateRoot):
    """FlextLdif Document Aggregate Root.

    Manages the consistency boundary for FlextLdif document processing.
    """

    content: LDIFContent = Field(..., description="LDIF content")
    entries: list[FlextLdifEntry] = Field(
        default_factory=list, description="Parsed entries",
    )
    version: int = Field(default=1, description="LDIF version")
    encoding: str = Field(default="utf-8", description="Character encoding")
    is_parsed: bool = Field(default=False, description="Parse status")
    is_validated: bool = Field(default=False, description="Validation status")

    def parse_content(self, entries: list[FlextLdifEntry]) -> None:
        """Parse LDIF content and update entries.

        Args:
            entries: List of parsed FlextLdif entries

        """
        object.__setattr__(self, "entries", entries)
        object.__setattr__(self, "is_parsed", True)

        # Raise domain event
        event = FlextLdifDocumentParsed.model_validate(
            {
                "aggregate_id": str(self.id),
                "entry_count": len(entries),
                "content_length": len(str(self.content)),
            },
        )
        self.add_domain_event(event)

    def complete_processing(
        self, success: bool, errors: list[str] | None = None,
    ) -> None:
        """Complete document processing.

        Args:
            success: Processing success status
            errors: List of errors if any

        """
        # Raise domain event
        event = FlextLdifProcessingCompleted.model_validate(
            {
                "aggregate_id": str(self.id),
                "entry_count": len(self.entries),
                "success": success,
                "errors": errors or [],
            },
        )
        self.add_domain_event(event)

    def get_entries_by_object_class(self, object_class: str) -> list[FlextLdifEntry]:
        """Get entries filtered by object class.

        Args:
            object_class: Object class to filter by

        Returns:
            List of matching entries

        """
        return [entry for entry in self.entries if entry.has_object_class(object_class)]

    def get_entry_count(self) -> int:
        """Get number of entries in document."""
        return len(self.entries)

    def is_empty(self) -> bool:
        """Check if document has no entries."""
        return len(self.entries) == 0

    def validate_domain_rules(self) -> None:
        """Validate domain business rules for LDIF document.

        Validates:
        - LDIF content is valid
        - Document version is valid (>= 1)
        - Encoding is supported
        - All parsed entries are valid
        - Parse/validation status consistency

        Raises:
            ValueError: If domain rules are violated

        """
        # Validate document version
        if self.version < 1:
            raise ValueError("LDIF document version must be >= 1")

        # Validate encoding
        import codecs
        try:
            codecs.lookup(self.encoding)
        except LookupError as e:
            raise ValueError(f"Unsupported encoding: {self.encoding}") from e

        # Validate content exists
        if not self.content:
            raise ValueError("LDIF document must have content")

        # If document is marked as parsed, validate entries
        if self.is_parsed:
            if not self.entries:
                raise ValueError("Parsed document must have entries")

            # Validate all entries
            for i, entry in enumerate(self.entries):
                try:
                    entry.validate_domain_rules()
                except Exception as e:
                    raise ValueError(f"Entry {i} validation failed: {e}") from e

        # Business rule: If marked as validated, must also be parsed
        if self.is_validated and not self.is_parsed:
            raise ValueError("Document cannot be validated without being parsed first")

        # Business rule: Ensure content length is reasonable
        content_str = str(self.content)
        if len(content_str) > 100_000_000:  # 100MB limit
            raise ValueError("LDIF document content exceeds maximum size limit")

        # Business rule: Non-empty content should result in entries when parsed
        if self.is_parsed and content_str.strip() and not self.entries:
            raise ValueError("Non-empty LDIF content should produce at least one entry when parsed")


__all__ = [
    "FlextLdifDocument",
]
