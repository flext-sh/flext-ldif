"""Schema DTO models."""

from __future__ import annotations

from flext_core import FlextCore
from pydantic import Field


class SchemaDiscoveryResult(FlextCore.Models.Value):
    """Result of schema discovery operations."""

    model_config = {"frozen": True}

    attributes: dict[str, FlextCore.Types.Dict] = Field(
        default_factory=dict, description="Discovered attributes with their metadata"
    )
    objectclasses: dict[str, FlextCore.Types.Dict] = Field(
        default_factory=dict,
        description="Discovered object classes with their metadata",
    )
    total_attributes: int = Field(
        default=0, description="Total number of attributes discovered"
    )
    total_objectclasses: int = Field(
        default=0, description="Total number of object classes discovered"
    )

    def has_schema_data(self) -> bool:
        """Check if schema contains any data."""
        return bool(self.attributes or self.objectclasses)
