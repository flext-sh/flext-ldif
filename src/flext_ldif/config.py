"""LDIF configuration using flext-core patterns.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext-core root namespace imports
from flext_core import FlextBaseSettings, get_logger
from pydantic import Field
from pydantic_settings import SettingsConfigDict

BaseSettings = FlextBaseSettings
logger = get_logger(__name__)


class FlextLdifConfig(BaseSettings):
    """LDIF processing configuration."""

    def __init__(self, **data: object) -> None:
        """Initialize configuration with logging."""
        logger.debug("Initializing FlextLdifConfig")
        logger.trace("Configuration data provided: %s", list(data.keys()) if data else "none")

        super().__init__(**data)  # type: ignore[arg-type]

        logger.debug("Configuration initialized with values:")
        logger.debug("  input_encoding: %s", self.input_encoding)
        logger.debug("  output_encoding: %s", self.output_encoding)
        logger.debug("  strict_validation: %s", self.strict_validation)
        logger.debug("  allow_empty_attributes: %s", self.allow_empty_attributes)
        logger.debug("  max_entries: %d", self.max_entries)
        logger.debug("  max_entry_size: %d", self.max_entry_size)
        logger.debug("  output_directory: %s", self.output_directory)
        logger.debug("  create_output_dir: %s", self.create_output_dir)

        logger.trace("Full configuration: %s", self.model_dump())
        logger.info("LDIF configuration initialized successfully",
                   encoding=f"{self.input_encoding}→{self.output_encoding}",
                   validation_mode="strict" if self.strict_validation else "standard",
                   max_entries=self.max_entries,
                   max_entry_size_mb=round(self.max_entry_size / 1024 / 1024, 2))

    model_config = SettingsConfigDict(
        env_prefix="FLEXT_LDIF_",
        env_file=".env",
        case_sensitive=False,
        extra="ignore",
    )

    # File processing
    input_encoding: str = Field(default="utf-8", description="Input file encoding")
    output_encoding: str = Field(default="utf-8", description="Output file encoding")

    # Validation settings
    strict_validation: bool = Field(
        default=True,
        description="Enable strict validation",
    )
    allow_empty_attributes: bool = Field(
        default=False,
        description="Allow empty attribute values",
    )

    # Processing limits
    max_entries: int = Field(default=10000, description="Maximum entries to process")
    max_entry_size: int = Field(
        default=1048576,
        description="Maximum entry size in bytes",  # 1MB
    )

    # Output settings
    output_directory: Path = Field(default=Path(), description="Output directory")
    create_output_dir: bool = Field(
        default=True,
        description="Create output directory if missing",
    )


__all__ = [
    "FlextLdifConfig",
]
