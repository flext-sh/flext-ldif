"""LDIF Domain Events - Business Events.

🏗️ CLEAN ARCHITECTURE: Domain Events
Built on flext-core foundation patterns.

Events represent important business occurrences in the LDIF domain.
"""

from __future__ import annotations

from typing import Any

from flext_core import DomainEvent
from pydantic import Field


class LDIFDocumentParsed(DomainEvent):
    """Event raised when LDIF document is parsed."""

    aggregate_id: str
    entry_count: int
    content_length: int
    parsing_time_ms: float | None = None


class LDIFEntryValidated(DomainEvent):
    """Event raised when LDIF entry is validated."""

    aggregate_id: str
    entry_dn: str
    is_valid: bool
    validation_errors: list[str] = Field(default_factory=list)


class LDIFProcessingCompleted(DomainEvent):
    """Event raised when LDIF processing is completed."""

    aggregate_id: str
    entry_count: int
    success: bool
    processing_time_ms: float | None = None
    errors: list[str] = Field(default_factory=list)


class LDIFWriteCompleted(DomainEvent):
    """Event raised when LDIF write operation is completed."""

    aggregate_id: str
    output_path: str
    entry_count: int
    bytes_written: int


class LDIFTransformationApplied(DomainEvent):
    """Event raised when transformation is applied to LDIF."""

    aggregate_id: str
    transformation_type: str
    entries_affected: int
    transformation_rules: dict[str, Any] = Field(default_factory=dict)


class LDIFValidationFailed(DomainEvent):
    """Event raised when LDIF validation fails."""

    aggregate_id: str
    entry_dn: str | None = None
    error_message: str
    error_code: str | None = None


class LDIFFilterApplied(DomainEvent):
    """Event raised when filter is applied to LDIF entries."""

    aggregate_id: str
    filter_criteria: str
    entries_matched: int
    total_entries: int
