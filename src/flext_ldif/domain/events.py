"""LDIF Domain Events - Business Events.

🏗️ CLEAN ARCHITECTURE: Domain Events
Built on flext-core foundation patterns.

Events represent important business occurrences in the LDIF domain.
"""

from __future__ import annotations

from typing import Any

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext-core root namespace imports
from flext_core import FlextValueObject
from pydantic import Field

DomainEvent = FlextValueObject


class FlextLdifDocumentParsed(DomainEvent):
    """Event raised when FlextLdif document is parsed."""

    aggregate_id: str
    entry_count: int
    content_length: int
    parsing_time_ms: float | None = None

    def validate_domain_rules(self) -> None:
        """Validate document parsed event domain rules."""
        if not self.aggregate_id or not isinstance(self.aggregate_id, str):
            msg = "aggregate_id must be a non-empty string"
            raise ValueError(msg)
        if self.entry_count < 0:
            msg = "entry_count must be non-negative"
            raise ValueError(msg)
        if self.content_length < 0:
            msg = "content_length must be non-negative"
            raise ValueError(msg)


class FlextLdifEntryValidated(DomainEvent):
    """Event raised when FlextLdif entry is validated."""

    aggregate_id: str
    entry_dn: str
    is_valid: bool
    validation_errors: list[str] = Field(default_factory=list)

    def validate_domain_rules(self) -> None:
        """Validate entry validated event domain rules."""
        if not self.aggregate_id or not isinstance(self.aggregate_id, str):
            msg = "aggregate_id must be a non-empty string"
            raise ValueError(msg)
        if not self.entry_dn or not isinstance(self.entry_dn, str):
            msg = "entry_dn must be a non-empty string"
            raise ValueError(msg)
        # is_valid is already typed as bool, no need to validate


class FlextLdifProcessingCompleted(DomainEvent):
    """Event raised when FlextLdif processing is completed."""

    aggregate_id: str
    entry_count: int
    success: bool
    processing_time_ms: float | None = None
    errors: list[str] = Field(default_factory=list)

    def validate_domain_rules(self) -> None:
        """Validate processing completed event domain rules."""
        if not self.aggregate_id or not isinstance(self.aggregate_id, str):
            msg = "aggregate_id must be a non-empty string"
            raise ValueError(msg)
        if self.entry_count < 0:
            msg = "entry_count must be non-negative"
            raise ValueError(msg)
        # success is already typed as bool, no need to validate


class FlextLdifWriteCompleted(DomainEvent):
    """Event raised when LDIF write operation is completed."""

    aggregate_id: str
    output_path: str
    entry_count: int
    bytes_written: int

    def validate_domain_rules(self) -> None:
        """Validate write completed event domain rules."""
        if not self.aggregate_id or not isinstance(self.aggregate_id, str):
            msg = "aggregate_id must be a non-empty string"
            raise ValueError(msg)
        if not self.output_path or not isinstance(self.output_path, str):
            msg = "output_path must be a non-empty string"
            raise ValueError(msg)
        if self.entry_count < 0:
            msg = "entry_count must be non-negative"
            raise ValueError(msg)
        if self.bytes_written < 0:
            msg = "bytes_written must be non-negative"
            raise ValueError(msg)


class FlextLdifTransformationApplied(DomainEvent):
    """Event raised when transformation is applied to LDIF."""

    aggregate_id: str
    transformation_type: str
    entries_affected: int
    transformation_rules: dict[str, Any] = Field(default_factory=dict)

    def validate_domain_rules(self) -> None:
        """Validate transformation applied event domain rules."""
        if not self.aggregate_id or not isinstance(self.aggregate_id, str):
            msg = "aggregate_id must be a non-empty string"
            raise ValueError(msg)
        if not self.transformation_type or not isinstance(
            self.transformation_type,
            str,
        ):
            msg = "transformation_type must be a non-empty string"
            raise ValueError(msg)
        if self.entries_affected < 0:
            msg = "entries_affected must be non-negative"
            raise ValueError(msg)


class FlextLdifValidationFailed(DomainEvent):
    """Event raised when LDIF validation fails."""

    aggregate_id: str
    entry_dn: str | None = None
    error_message: str
    error_code: str | None = None

    def validate_domain_rules(self) -> None:
        """Validate validation failed event domain rules."""
        if not self.aggregate_id or not isinstance(self.aggregate_id, str):
            msg = "aggregate_id must be a non-empty string"
            raise ValueError(msg)
        if not self.error_message or not isinstance(self.error_message, str):
            msg = "error_message must be a non-empty string"
            raise ValueError(msg)


class FlextLdifFilterApplied(DomainEvent):
    """Event raised when filter is applied to LDIF entries."""

    aggregate_id: str
    filter_criteria: str
    entries_matched: int
    total_entries: int

    def validate_domain_rules(self) -> None:
        """Validate filter applied event domain rules."""
        if not self.aggregate_id or not isinstance(self.aggregate_id, str):
            msg = "aggregate_id must be a non-empty string"
            raise ValueError(msg)
        if not self.filter_criteria or not isinstance(self.filter_criteria, str):
            msg = "filter_criteria must be a non-empty string"
            raise ValueError(msg)
        if self.entries_matched < 0:
            msg = "entries_matched must be non-negative"
            raise ValueError(msg)
        if self.total_entries < 0:
            msg = "total_entries must be non-negative"
            raise ValueError(msg)
        if self.entries_matched > self.total_entries:
            msg = "entries_matched cannot exceed total_entries"
            raise ValueError(msg)


__all__ = [
    "FlextLdifDocumentParsed",
    "FlextLdifEntryValidated",
    "FlextLdifFilterApplied",
    "FlextLdifProcessingCompleted",
    "FlextLdifTransformationApplied",
    "FlextLdifValidationFailed",
    "FlextLdifWriteCompleted",
]
