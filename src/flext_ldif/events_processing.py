"""Processing domain events."""

from flext_core import FlextCore
from pydantic import Field


class EntryParsedEvent(FlextCore.Models.DomainEvent):
    """Event emitted when an entry is successfully parsed."""

    event_type: str = Field(..., description="Event type")
    aggregate_id: str = Field(..., description="Aggregate ID")
    entry_count: int = Field(..., description="Number of entries parsed")
    source_type: str = Field(..., description="Type of source")
    format_detected: str = Field(..., description="Detected format")
    timestamp: str = Field(..., description="Event timestamp")


class EntriesValidatedEvent(FlextCore.Models.DomainEvent):
    """Event emitted when entries are validated."""

    event_type: str = Field(..., description="Event type")
    aggregate_id: str = Field(..., description="Aggregate ID")
    entry_count: int = Field(..., description="Number of entries validated")
    is_valid: bool = Field(..., description="Whether validation passed")
    error_count: int = Field(..., description="Number of validation errors")
    strict_mode: bool = Field(..., description="Whether strict mode was used")
    timestamp: str = Field(..., description="Event timestamp")


class AnalyticsGeneratedEvent(FlextCore.Models.DomainEvent):
    """Event emitted when analytics are generated."""

    event_type: str = Field(..., description="Event type")
    aggregate_id: str = Field(..., description="Aggregate ID")
    entry_count: int = Field(..., description="Number of entries analyzed")
    statistics: dict[str, int | float] = Field(..., description="Analytics statistics")
    timestamp: str = Field(..., description="Event timestamp")


class EntriesWrittenEvent(FlextCore.Models.DomainEvent):
    """Event emitted when entries are written."""

    event_type: str = Field(..., description="Event type")
    aggregate_id: str = Field(..., description="Aggregate ID")
    entry_count: int = Field(..., description="Number of entries written")
    output_path: str = Field(..., description="Output path")
    format_used: str = Field(..., description="Format used for writing")
    format_options: dict[str, int] = Field(
        default_factory=dict, description="Format options"
    )
    timestamp: str = Field(..., description="Event timestamp")


class MigrationCompletedEvent(FlextCore.Models.DomainEvent):
    """Event emitted when migration is completed."""

    event_type: str = Field(..., description="Event type")
    aggregate_id: str = Field(..., description="Aggregate ID")
    source_entries: int = Field(..., description="Number of source entries")
    target_entries: int = Field(..., description="Number of target entries")
    migration_type: str = Field(..., description="Type of migration performed")
    timestamp: str = Field(..., description="Event timestamp")


class QuirkRegisteredEvent(FlextCore.Models.DomainEvent):
    """Event emitted when a quirk is registered."""

    event_type: str = Field(..., description="Event type")
    aggregate_id: str = Field(..., description="Aggregate ID")
    server_type: str = Field(..., description="Server type")
    quirk_name: str = Field(..., description="Name of the registered quirk")
    timestamp: str = Field(..., description="Event timestamp")
