"""Domain Event Definitions for LDIF Operations - Single unified class.

This module defines domain events that represent meaningful business occurrences
in the LDIF processing domain. Events are published after successful operations.
Follows FLEXT pattern: single unified class per module with nested models.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field


class FlextLdifEvents(BaseModel):
    """Unified LDIF domain events namespace - single class per module pattern.

    Contains all domain event models for LDIF processing operations.
    Events are published after successful operations to enable event-driven
    architecture and observability.
    """

    class Parsed(BaseModel):
        """Event published after successful LDIF parsing.

        Attributes:
        source: File path or content that was parsed
        entry_count: Number of entries parsed
        server_type: Server type used for parsing quirks
        timestamp: Event occurrence time (UTC)
        correlation_id: Optional correlation ID for tracking

        """

        source: str | Path = Field(..., description="Parsed LDIF source")
        entry_count: int = Field(..., description="Number of entries parsed", ge=0)
        server_type: str = Field(..., description="Server type for quirks")
        timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
        correlation_id: str | None = Field(default=None)

    class Written(BaseModel):
        """Event published after successful LDIF writing.

        Attributes:
        output_path: File path where LDIF was written (None if string output)
        entry_count: Number of entries written
        timestamp: Event occurrence time (UTC)
        correlation_id: Optional correlation ID for tracking

        """

        output_path: Path | None = Field(default=None, description="Output file path")
        entry_count: int = Field(..., description="Number of entries written", ge=0)
        timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
        correlation_id: str | None = Field(default=None)

    class Migrated(BaseModel):
        """Event published after successful LDIF migration.

        Attributes:
        from_server: Source server type
        to_server: Target server type
        entry_count: Number of entries migrated
        schema_files: Number of schema files processed
        timestamp: Event occurrence time (UTC)
        correlation_id: Optional correlation ID for tracking

        """

        from_server: str = Field(..., description="Source server type")
        to_server: str = Field(..., description="Target server type")
        entry_count: int = Field(..., description="Entries migrated", ge=0)
        schema_files: int = Field(..., description="Schema files processed", ge=0)
        timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
        correlation_id: str | None = Field(default=None)

    class Validated(BaseModel):
        """Event published after LDIF validation.

        Attributes:
        entry_count: Number of entries validated
        is_valid: Whether validation passed
        error_count: Number of validation errors
        warning_count: Number of validation warnings
        timestamp: Event occurrence time (UTC)
        correlation_id: Optional correlation ID for tracking

        """

        entry_count: int = Field(..., description="Entries validated", ge=0)
        is_valid: bool = Field(..., description="Validation result")
        error_count: int = Field(default=0, description="Validation errors", ge=0)
        warning_count: int = Field(default=0, description="Validation warnings", ge=0)
        timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
        correlation_id: str | None = Field(default=None)


# Backward compatibility aliases (map old names to unified class)
LdifParsedEvent = FlextLdifEvents.Parsed
LdifWrittenEvent = FlextLdifEvents.Written
LdifMigratedEvent = FlextLdifEvents.Migrated
LdifValidatedEvent = FlextLdifEvents.Validated

__all__ = [
    "FlextLdifEvents",
    "LdifMigratedEvent",
    # Backward compatibility aliases
    "LdifParsedEvent",
    "LdifValidatedEvent",
    "LdifWrittenEvent",
]
