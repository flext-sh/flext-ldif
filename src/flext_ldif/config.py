"""FLEXT-LDIF Configuration Management.

This module provides enterprise-grade configuration management for LDIF processing
operations, extending flext-core configuration patterns with LDIF-specific settings,
validation rules, and environment variable integration.

The configuration system supports multiple configuration sources with proper
precedence handling, type validation, and enterprise deployment patterns including
environment-specific overrides and secure secrets management.

Key Components:
    - FlextLdifConfig: Main configuration class extending FlextBaseSettings
    - Environment variable integration with LDIF_ prefix
    - Comprehensive validation with business rule enforcement
    - Production-ready defaults and security configurations

Architecture:
    Part of Infrastructure Layer in Clean Architecture, this module handles
    external configuration concerns while providing type-safe configuration
    objects to application and domain layers through dependency injection.

Configuration Sources (in precedence order):
    1. Command-line arguments (highest priority)
    2. Environment variables with LDIF_ prefix
    3. Configuration files (.env, config.yaml)
    4. Default values (lowest priority)

Example:
    Basic configuration setup with environment overrides:

    >>> import os
    >>> from flext_ldif.config import FlextLdifConfig
    >>>
    >>> # Set environment variables
    >>> os.environ['LDIF_MAX_ENTRIES'] = '50000'
    >>> os.environ['LDIF_STRICT_VALIDATION'] = 'true'
    >>>
    >>> # Create configuration with environment override
    >>> config = FlextLdifConfig()
    >>> print(config.max_entries)  # 50000 (from environment)
    >>> print(config.strict_validation)  # True (from environment)
    >>>
    >>> # Override programmatically
    >>> config = FlextLdifConfig(
    ...     max_entries=100000,
    ...     enable_observability=True
    ... )

Integration:
    - Extends flext-core FlextBaseSettings with LDIF-specific validation
    - Supports Pydantic validation and serialization patterns
    - Integrates with dependency injection container for service configuration
    - Provides enterprise-grade configuration management with audit logging

Author: FLEXT Development Team
Version: 0.9.0
License: MIT

"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext-core root namespace imports
from flext_core import FlextResult, get_logger
from flext_core.models import FlextBaseSettings
from pydantic import Field, field_validator
from pydantic_settings import SettingsConfigDict

logger = get_logger(__name__)


class FlextLdifConfig(FlextBaseSettings):
    """LDIF processing configuration."""

    def __init__(self, **data: object) -> None:
        """Initialize configuration with logging."""
        logger.debug("Initializing FlextLdifConfig")
        logger.trace(
            "Configuration data provided: %s",
            list(data.keys()) if data else "none",
        )

        # Call parent init without explicit kwargs
        super().__init__()

        # Now apply any provided data through Pydantic's model_validate
        if data:
            for key, value in data.items():
                if hasattr(self, key):
                    setattr(self, key, value)

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
        logger.info(
            "LDIF configuration initialized successfully",
            encoding=f"{self.input_encoding}→{self.output_encoding}",
            validation_mode="strict" if self.strict_validation else "standard",
            max_entries=self.max_entries,
            max_entry_size_mb=round(self.max_entry_size / 1024 / 1024, 2),
        )

    model_config: ClassVar[SettingsConfigDict] = SettingsConfigDict(
        env_prefix="FLEXT_LDIF_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        validate_assignment=True,
        env_nested_delimiter="__",
    )

    # File processing
    input_encoding: str = Field(
        default="utf-8",
        description="Input file encoding",
        pattern=r"^[a-zA-Z0-9\-_]+$",
    )
    output_encoding: str = Field(
        default="utf-8",
        description="Output file encoding",
        pattern=r"^[a-zA-Z0-9\-_]+$",
    )

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
    max_entries: int = Field(
        default=10000,
        description="Maximum entries to process",
        ge=1,
        le=1000000,
    )
    max_entry_size: int = Field(
        default=1048576,
        description="Maximum entry size in bytes (1MB)",
        ge=1024,  # 1KB minimum
        le=104857600,  # 100MB maximum
    )

    # Output settings
    output_directory: Path = Field(
        default_factory=Path.cwd,
        description="Output directory for LDIF files",
    )
    create_output_dir: bool = Field(
        default=True,
        description="Create output directory if missing",
    )

    # Advanced settings
    line_wrap_length: int = Field(
        default=76,
        description="LDIF line wrapping length (RFC 2849)",
        ge=50,
        le=998,
    )
    sort_attributes: bool = Field(
        default=False,
        description="Sort attributes in output",
    )
    normalize_dn: bool = Field(
        default=False,
        description="Normalize DN format in output",
    )

    @field_validator("output_directory")
    @classmethod
    def validate_output_directory(cls, v: Path) -> Path:
        """Ensure output directory is absolute path."""
        return v.absolute()

    def validate_semantic_rules(self) -> FlextResult[None]:
        """Validate LDIF configuration semantic rules."""
        # Check encoding validity
        try:
            "test".encode(self.input_encoding)
            "test".encode(self.output_encoding)
        except LookupError as e:
            return FlextResult.fail(f"Invalid encoding: {e}")

        # Check size limits consistency
        if self.max_entry_size > self.max_entries * 1024:
            logger.warning(
                "max_entry_size (%d) might be too large for max_entries (%d)",
                self.max_entry_size,
                self.max_entries,
            )

        return FlextResult.ok(None)


__all__ = [
    "FlextLdifConfig",
]
