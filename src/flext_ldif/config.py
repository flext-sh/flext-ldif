"""FLEXT-LDIF Configuration Management - LDIF-specific configuration.

Extends flext-core FlextConfig with LDIF-specific settings and validation.
Uses flext-core SOURCE OF TRUTH exclusively.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar, Self

from flext_core import FlextResult
from pydantic import BaseModel, Field, field_validator, model_validator

# Configuration validation constants
MIN_WORKERS_FOR_PARALLEL = 2
MIN_ANALYTICS_CACHE_SIZE = 100
MIN_PRODUCTION_ENTRIES = 1000
MIN_BUFFER_SIZE = 4096
MAX_WORKERS_LIMIT = 16
MAX_ANALYTICS_CACHE_SIZE = 50000


class FlextLDIFConfig(BaseModel):
    """LDIF-specific configuration using Pydantic BaseModel.

    Provides LDIF-specific settings with proper validation.
    Uses singleton pattern for global configuration access.
    """

    # SINGLETON PATTERN - Global LDIF configuration instance
    _global_instance: ClassVar[FlextLDIFConfig | None] = None
    _sealed: bool = False

    # =============================================================================
    # LDIF-SPECIFIC CONFIGURATION FIELDS
    # =============================================================================

    # LDIF Processing Configuration
    ldif_max_entries: int = Field(
        default=1000000,
        description="Maximum number of LDIF entries to process in a single operation",
        ge=1,
        le=10000000,
    )

    ldif_max_line_length: int = Field(
        default=8192,
        description="Maximum line length for LDIF parsing",
        ge=1,
        le=65536,
    )

    ldif_buffer_size: int = Field(
        default=65536,
        description="Buffer size for LDIF file operations",
        ge=1024,
        le=1048576,
    )

    ldif_encoding: str = Field(
        default="utf-8",
        description="Default encoding for LDIF files",
    )

    # LDIF Validation Configuration
    ldif_strict_validation: bool = Field(
        default=True,
        description="Enable strict LDIF validation (RFC 2849 compliance)",
    )

    ldif_allow_empty_values: bool = Field(
        default=False,
        description="Allow empty attribute values in LDIF entries",
    )

    ldif_validate_dn_format: bool = Field(
        default=True,
        description="Validate DN format according to LDAP standards",
    )

    ldif_validate_object_class: bool = Field(
        default=True,
        description="Validate objectClass attributes",
    )

    # LDIF Processing Behavior
    ldif_normalize_dns: bool = Field(
        default=True,
        description="Normalize DN components during processing",
    )

    ldif_preserve_case: bool = Field(
        default=False,
        description="Preserve case sensitivity in attribute names",
    )

    ldif_skip_comments: bool = Field(
        default=True,
        description="Skip comment lines in LDIF files",
    )

    # LDIF Analytics Configuration
    ldif_enable_analytics: bool = Field(
        default=True,
        description="Enable LDIF entry analytics and statistics",
    )

    ldif_analytics_cache_size: int = Field(
        default=10000,
        description="Cache size for analytics operations",
        ge=100,
        le=100000,
    )

    # LDIF Performance Configuration
    ldif_parallel_processing: bool = Field(
        default=False,
        description="Enable parallel processing for large LDIF files",
    )

    ldif_max_workers: int = Field(
        default=4,
        description="Maximum number of worker threads for parallel processing",
        ge=1,
        le=32,
    )

    ldif_chunk_size: int = Field(
        default=1000,
        description="Chunk size for processing large LDIF files",
        ge=100,
        le=10000,
    )

    # =============================================================================
    # VALIDATION METHODS
    # =============================================================================

    @field_validator("ldif_encoding")
    @classmethod
    def validate_encoding(cls, v: str) -> str:
        """Validate encoding is supported."""
        try:
            test_bytes = "test".encode(v)
            test_bytes.decode(v)
        except (UnicodeError, LookupError) as e:
            msg = f"Unsupported encoding: {v}"
            raise ValueError(msg) from e
        return v

    @model_validator(mode="after")
    def validate_ldif_configuration(self) -> Self:
        """Validate LDIF-specific configuration consistency."""
        # Validate worker configuration
        if self.ldif_parallel_processing and self.ldif_max_workers < MIN_WORKERS_FOR_PARALLEL:
            msg = "Parallel processing requires at least 2 workers"
            raise ValueError(msg)

        # Validate chunk size vs max entries
        if self.ldif_chunk_size > self.ldif_max_entries:
            msg = "Chunk size cannot exceed maximum entries"
            raise ValueError(msg)

        # Validate analytics cache size
        if self.ldif_enable_analytics and self.ldif_analytics_cache_size < MIN_ANALYTICS_CACHE_SIZE:
            msg = "Analytics cache size must be at least 100"
            raise ValueError(msg)

        return self

    # =============================================================================
    # SINGLETON PATTERN IMPLEMENTATION
    # =============================================================================

    @classmethod
    def get_global_instance(cls) -> FlextLDIFConfig:
        """Get global LDIF configuration instance (singleton pattern).

        Returns:
            Global FlextLDIFConfig instance

        Raises:
            RuntimeError: If configuration has not been initialized

        """
        if cls._global_instance is None:
            msg = "FlextLDIFConfig not initialized. Call initialize_global_config() first."
            raise RuntimeError(msg)
        return cls._global_instance

    @classmethod
    def initialize_global_config(
        cls, **config_params: object
    ) -> FlextResult[FlextLDIFConfig]:
        """Initialize global LDIF configuration instance.

        Args:
            **config_params: Configuration parameters to override defaults

        Returns:
            FlextResult containing initialized configuration

        """
        try:
            if cls._global_instance is not None:
                return FlextResult[FlextLDIFConfig].ok(cls._global_instance)

            # Initialize with provided parameters
            config = cls(**config_params)  # type: ignore[arg-type]
            cls._global_instance = config

            return FlextResult[FlextLDIFConfig].ok(config)
        except ValueError as e:
            return FlextResult[FlextLDIFConfig].fail(str(e))
        except Exception as e:
            return FlextResult[FlextLDIFConfig].fail(
                f"Failed to initialize LDIF configuration: {e}",
                error_code="LDIF_CONFIG_INIT_ERROR",
            )

    @classmethod
    def reset_global_config(cls) -> None:
        """Reset global configuration instance (for testing)."""
        cls._global_instance = None

    # =============================================================================
    # LDIF-SPECIFIC CONFIGURATION METHODS
    # =============================================================================

    def get_ldif_processing_config(self) -> dict[str, object]:
        """Get LDIF processing configuration as dictionary.

        Returns:
            Dictionary containing LDIF processing settings

        """
        return {
            "max_entries": self.ldif_max_entries,
            "max_line_length": self.ldif_max_line_length,
            "buffer_size": self.ldif_buffer_size,
            "encoding": self.ldif_encoding,
            "parallel_processing": self.ldif_parallel_processing,
            "max_workers": self.ldif_max_workers,
            "chunk_size": self.ldif_chunk_size,
        }

    def get_ldif_validation_config(self) -> dict[str, object]:
        """Get LDIF validation configuration as dictionary.

        Returns:
            Dictionary containing LDIF validation settings

        """
        return {
            "strict_validation": self.ldif_strict_validation,
            "allow_empty_values": self.ldif_allow_empty_values,
            "validate_dn_format": self.ldif_validate_dn_format,
            "validate_object_class": self.ldif_validate_object_class,
            "normalize_dns": self.ldif_normalize_dns,
            "preserve_case": self.ldif_preserve_case,
            "skip_comments": self.ldif_skip_comments,
        }

    def seal(self) -> None:
        """Seal configuration to prevent further modifications."""
        self._sealed = True

    def apply_ldif_overrides(self, overrides: dict[str, object]) -> FlextResult[None]:
        """Apply LDIF-specific configuration overrides."""
        if self._sealed:
            return FlextResult[None].fail("Cannot modify sealed configuration")

        try:
            for key, value in overrides.items():
                if hasattr(self, key):
                    setattr(self, key, value)

            # Re-validate configuration after overrides
            self.validate_ldif_configuration()
            return FlextResult[None].ok(None)
        except ValueError as e:
            return FlextResult[None].fail(str(e))
        except Exception as e:
            return FlextResult[None].fail(f"Failed to apply overrides: {e}")

    def get_ldif_analytics_config(self) -> dict[str, object]:
        """Get LDIF analytics configuration as dictionary.

        Returns:
            Dictionary containing LDIF analytics settings

        """
        return {
            "enable_analytics": self.ldif_enable_analytics,
            "cache_size": self.ldif_analytics_cache_size,
        }

    def validate_ldif_business_rules(self) -> FlextResult[None]:
        """Validate LDIF-specific business rules.

        Returns:
            FlextResult indicating validation success or failure

        """
        try:
            errors = []

            # Validate processing limits
            if self.ldif_max_entries < MIN_PRODUCTION_ENTRIES:
                errors.append("Maximum entries too low for production use")

            if self.ldif_buffer_size < MIN_BUFFER_SIZE:
                errors.append("Buffer size too small for efficient processing")

            # Validate worker configuration
            if self.ldif_parallel_processing and self.ldif_max_workers > MAX_WORKERS_LIMIT:
                errors.append("Too many workers may cause resource contention")

            # Validate analytics configuration
            if self.ldif_enable_analytics and self.ldif_analytics_cache_size > MAX_ANALYTICS_CACHE_SIZE:
                errors.append("Analytics cache size too large for memory efficiency")

            if errors:
                return FlextResult[None].fail(
                    f"LDIF business rule validation failed: {'; '.join(errors)}",
                    error_code="LDIF_BUSINESS_RULE_ERROR",
                )

            return FlextResult[None].ok(None)
        except Exception as e:
            return FlextResult[None].fail(
                f"LDIF business rule validation error: {e}",
                error_code="LDIF_BUSINESS_RULE_ERROR",
            )


# =============================================================================
# CONVENIENCE FUNCTIONS FOR GLOBAL CONFIG ACCESS
# =============================================================================

def get_ldif_config() -> FlextLDIFConfig:
    """Get global LDIF configuration instance.

    Returns:
        Global FlextLDIFConfig instance

    Raises:
        RuntimeError: If configuration has not been initialized

    """
    return FlextLDIFConfig.get_global_instance()


def initialize_ldif_config(**config_params: object) -> FlextResult[FlextLDIFConfig]:
    """Initialize global LDIF configuration.

    Args:
        **config_params: Configuration parameters to override defaults

    Returns:
        FlextResult containing initialized configuration

    """
    return FlextLDIFConfig.initialize_global_config(**config_params)


def reset_ldif_config() -> None:
    """Reset global LDIF configuration (for testing)."""
    FlextLDIFConfig.reset_global_config()


__all__ = [
    "FlextLDIFConfig",
    "get_ldif_config",
    "initialize_ldif_config",
    "reset_ldif_config",
]
