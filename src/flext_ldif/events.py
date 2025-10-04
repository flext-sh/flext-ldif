"""FLEXT LDIF Events - Domain Events for FlextBus Integration.

Domain events emitted during LDIF processing operations.
Extends flext-core FlextModels with LDIF-specific event patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Literal

from flext_core import FlextModels, FlextTypes
from pydantic import ConfigDict, Field


class FlextLdifEvents:
    """LDIF-specific domain events extending FlextModels.

    Contains all domain events for LDIF processing operations,
    following CQRS patterns for event-driven architecture.
    """

    class EntryParsedEvent(FlextModels.DomainEvent):
        """Event emitted when LDIF entries are successfully parsed.

        Emitted after successful parse operations for monitoring and extensibility.
        """

        entry_count: int = Field(..., description="Number of entries parsed")
        source_type: Literal["file", "string", "bytes", "list"] = Field(
            ..., description="Type of source that was parsed"
        )
        format_detected: Literal["rfc", "oid", "auto"] = Field(
            ..., description="Format used for parsing"
        )
        timestamp: str = Field(..., description="ISO format timestamp")

        model_config = ConfigDict(frozen=True)

        def __init__(self, **data: object) -> None:
            """Initialize with default event_type and aggregate_id."""
            data.setdefault("event_type", "entry.parsed")
            data.setdefault("aggregate_id", "ldif-parser")
            super().__init__(**data)

    class EntriesValidatedEvent(FlextModels.DomainEvent):
        """Event emitted when LDIF entries are validated against schema.

        Emitted after validation operations complete successfully.
        """

        entry_count: int = Field(..., description="Number of entries validated")
        is_valid: bool = Field(..., description="Overall validation result")
        error_count: int = Field(default=0, description="Number of validation errors")
        strict_mode: bool = Field(..., description="Whether strict validation was used")
        timestamp: str = Field(..., description="ISO format timestamp")

        model_config = ConfigDict(frozen=True)

        def __init__(self, **data: object) -> None:
            """Initialize with default event_type and aggregate_id."""
            data.setdefault("event_type", "entries.validated")
            data.setdefault("aggregate_id", "ldif-validator")
            super().__init__(**data)

    class AnalyticsGeneratedEvent(FlextModels.DomainEvent):
        """Event emitted when analytics are generated from LDIF entries.

        Emitted after analytics operations complete.
        """

        entry_count: int = Field(..., description="Number of entries analyzed")
        unique_object_classes: int = Field(
            ..., description="Number of unique objectClass values found"
        )
        patterns_detected: int = Field(
            default=0, description="Number of patterns detected"
        )
        statistics: dict[str, int | float] = Field(
            default_factory=dict, description="Additional statistics"
        )
        timestamp: str = Field(..., description="ISO format timestamp")

        model_config = ConfigDict(frozen=True)

        def __init__(self, **data: object) -> None:
            """Initialize with default event_type and aggregate_id."""
            data.setdefault("event_type", "analytics.generated")
            data.setdefault("aggregate_id", "ldif-analytics")
            super().__init__(**data)

    class EntriesWrittenEvent(FlextModels.DomainEvent):
        """Event emitted when LDIF entries are written to output.

        Emitted after successful write operations.
        """

        entry_count: int = Field(..., description="Number of entries written")
        output_path: str = Field(..., description="Output file path")
        format_used: Literal["rfc", "oid"] = Field(
            ..., description="Format used for writing"
        )
        output_size_bytes: int = Field(
            default=0, description="Size of written output in bytes"
        )
        timestamp: str = Field(..., description="ISO format timestamp")

        model_config = ConfigDict(frozen=True)

        def __init__(self, **data: object) -> None:
            """Initialize with default event_type and aggregate_id."""
            data.setdefault("event_type", "entries.written")
            data.setdefault("aggregate_id", "ldif-writer")
            super().__init__(**data)

    class MigrationCompletedEvent(FlextModels.DomainEvent):
        """Event emitted when LDIF migration completes.

        Emitted after successful migration between formats.
        """

        source_entries: int = Field(..., description="Number of source entries")
        target_entries: int = Field(..., description="Number of target entries")
        migration_type: str = Field(..., description="Type of migration performed")
        entry_count: int = Field(..., description="Number of entries migrated")
        source_format: Literal["rfc", "oid", "oud"] = Field(
            ..., description="Source format"
        )
        target_format: Literal["rfc", "oid", "oud"] = Field(
            ..., description="Target format"
        )
        quirks_applied: FlextTypes.StringList = Field(
            default_factory=list, description="List of quirks applied during migration"
        )
        timestamp: str = Field(..., description="ISO format timestamp")

        model_config = ConfigDict(frozen=True)

        def __init__(self, **data: object) -> None:
            """Initialize with default event_type and aggregate_id."""
            data.setdefault("event_type", "migration.completed")
            data.setdefault("aggregate_id", "ldif-migrator")
            super().__init__(**data)

    class QuirkRegisteredEvent(FlextModels.DomainEvent):
        """Event emitted when a custom quirk is registered.

        Emitted after successful quirk registration.
        """

        server_type: str = Field(..., description="Server type for the quirk")
        quirk_name: str = Field(..., description="Name of registered quirk")
        quirk_config: FlextTypes.Dict = Field(
            default_factory=dict, description="Quirk configuration"
        )
        override: bool = Field(..., description="Whether existing quirk was overridden")
        timestamp: str = Field(..., description="ISO format timestamp")

        model_config = ConfigDict(frozen=True)

        def __init__(self, **data: object) -> None:
            """Initialize with default event_type and aggregate_id."""
            data.setdefault("event_type", "quirk.registered")
            data.setdefault("aggregate_id", "ldif-registry")
            super().__init__(**data)
