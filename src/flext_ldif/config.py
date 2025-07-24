"""LDIF configuration using flext-core patterns.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext-core root namespace imports
from flext_core import FlextCoreSettings
from pydantic import Field
from pydantic_settings import SettingsConfigDict

BaseSettings = FlextCoreSettings


class FlextLdifConfig(BaseSettings):
    """LDIF processing configuration."""

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
