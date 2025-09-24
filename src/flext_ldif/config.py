"""FLEXT LDIF Configuration - LDIF-specific configuration management.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Self

from flext_core.config import FlextConfig
from pydantic import Field, field_validator, model_validator

from flext_core import FlextConstants, FlextContainer, FlextResult
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.mixins import FlextLdifMixins


class FlextLdifConfig(FlextConfig):
    """LDIF-specific configuration extending flext-core FlextConfig.

    Single unified class containing all LDIF configuration definitions
    following SOLID principles and FLEXT ecosystem patterns.

    Provides LDIF-specific settings with proper validation.
    Uses flext-core SOURCE OF TRUTH for configuration management.
    """

    # =============================================================================
    # PRIVATE ATTRIBUTES
    # =============================================================================

    _sealed: bool = False

    # =============================================================================
    # LDIF-SPECIFIC CONFIGURATION FIELDS
    # =============================================================================

    # LDIF Processing Configuration - using FlextConstants as SOURCE OF TRUTH
    ldif_max_entries: int = Field(
        default=FlextConstants.Limits.MAX_LIST_SIZE * 100,  # 1,000,000
        description="Maximum number of LDIF entries to process in a single operation",
        ge=1,
        le=10000000,
    )

    ldif_max_line_length: int = Field(
        default=FlextConstants.Utilities.BYTES_PER_KB * 8,  # 8192 bytes
        description="Maximum line length for LDIF parsing",
        ge=1,
        le=65536,
    )

    ldif_buffer_size: int = Field(
        default=FlextConstants.Utilities.BYTES_PER_KB * 64,  # 65536 bytes
        description="Buffer size for LDIF file operations",
        ge=1024,
        le=1048576,
    )

    ldif_encoding: str = Field(
        default="utf-8",
        description="Default encoding for LDIF files",
    )

    base_url: str = Field(
        default="ldap://localhost:389",
        description="Base URL for LDAP server connection",
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
        description="Chunk size for LDIF file processing",
        ge=1,
        le=10000,
    )

    ldif_max_file_size_mb: int = Field(
        default=100,
        description="Maximum file size in MB for LDIF file processing",
        ge=1,
        le=1024,
    )

    # =============================================================================
    # VALIDATION METHODS
    # =============================================================================

    @field_validator("ldif_encoding")
    @classmethod
    def validate_ldif_encoding(cls, v: str) -> str:
        """Validate encoding is supported.

        Returns:
            str: The validated encoding string

        Raises:
            ValueError: If the encoding is not supported

        """
        return FlextLdifMixins.ValidationMixin.validate_encoding(v)

    @model_validator(mode="after")
    def validate_ldif_configuration(self) -> Self:
        """Validate LDIF-specific configuration consistency.

        Extends FlextConfig.validate_configuration_consistency() with LDIF-specific validation.

        Returns:
            Self: The validated configuration instance

        Raises:
            ValueError: If configuration validation fails

        """
        # Add LDIF-specific validation
        # Validate worker configuration using business rules mixin
        worker_result = FlextLdifMixins.BusinessRulesMixin.validate_parallel_configuration_consistency(
            parallel_enabled=self.ldif_parallel_processing,
            worker_count=self.ldif_max_workers,
            min_workers=FlextLdifConstants.Processing.MIN_WORKERS_FOR_PARALLEL,
        )
        if worker_result.is_failure:
            raise ValueError(worker_result.error)

        # Validate chunk size vs max entries
        if self.ldif_chunk_size > self.ldif_max_entries:
            msg = "Chunk size cannot exceed maximum entries"
            raise ValueError(msg)

        # Validate analytics cache size
        if (
            self.ldif_enable_analytics
            and self.ldif_analytics_cache_size
            < FlextLdifConstants.Processing.MIN_ANALYTICS_CACHE_SIZE
        ):
            msg = "Analytics cache size must be at least 100"
            raise ValueError(msg)

        return self

    # =============================================================================
    # LDIF-SPECIFIC CONFIGURATION METHODS
    # =============================================================================

    def get_ldif_processing_config(self: Self) -> dict[str, object]:
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
            "max_file_size_mb": self.ldif_max_file_size_mb,
        }

    def get_ldif_validation_config(self: Self) -> dict[str, object]:
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

    def get_ldif_analytics_config(self: Self) -> dict[str, object]:
        """Get LDIF analytics configuration as dictionary.

        Returns:
            Dictionary containing LDIF analytics settings

        """
        return {
            "enable_analytics": self.ldif_enable_analytics,
            "cache_size": self.ldif_analytics_cache_size,
        }

    def validate_ldif_business_rules(self: Self) -> FlextResult[None]:
        """Validate LDIF-specific business rules.

        Returns:
            FlextResult indicating validation success or failure

        """
        try:
            errors: list[str] = []

            # Validate processing limits using business rules mixin
            entries_result = (
                FlextLdifMixins.BusinessRulesMixin.validate_minimum_entries(
                    self.ldif_max_entries,
                    FlextLdifConstants.Processing.MIN_PRODUCTION_ENTRIES,
                    "entries",
                )
            )
            if entries_result.is_failure:
                errors.append(
                    entries_result.error or "Maximum entries too low for production use"
                )

            if (
                self.ldif_buffer_size < FlextLdifConstants.Format.MIN_BUFFER_SIZE
            ):  # pragma: no cover
                errors.append("Buffer size too small for efficient processing")

            # Validate worker configuration using business rules mixin
            workers_result = (
                FlextLdifMixins.BusinessRulesMixin.validate_resource_limits(
                    self.ldif_max_workers,
                    FlextLdifConstants.Processing.MAX_WORKERS_LIMIT,
                    "Workers",
                )
            )
            if workers_result.is_failure:
                errors.append(
                    workers_result.error
                    or "Too many workers may cause resource contention"
                )

            # Validate analytics configuration using business rules mixin
            analytics_result = (
                FlextLdifMixins.BusinessRulesMixin.validate_resource_limits(
                    self.ldif_analytics_cache_size,
                    FlextLdifConstants.Processing.MAX_ANALYTICS_CACHE_SIZE,
                    "Analytics cache size",
                )
            )
            if analytics_result.is_failure:
                errors.append(
                    analytics_result.error
                    or "Analytics cache size too large for memory efficiency"
                )

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

    def apply_ldif_overrides(self, overrides: dict[str, object]) -> FlextResult[None]:
        """Apply LDIF-specific configuration overrides.

        Returns:
            FlextResult[None]: Success or failure result

        """
        # Check if configuration is sealed
        if self.is_sealed():
            return FlextResult[None].fail(
                "Cannot apply overrides to sealed configuration"
            )

        try:
            for key, value in overrides.items():
                if hasattr(self, key):
                    setattr(self, key, value)

            # Re-validate configuration after overrides
            # Create a new instance to trigger validation
            try:
                self.__class__(**self.model_dump())
            except ValueError as e:
                return FlextResult[None].fail(str(e))

            return FlextResult[None].ok(None)
        except ValueError as e:  # pragma: no cover
            return FlextResult[None].fail(str(e))
        except Exception as e:  # pragma: no cover
            return FlextResult[None].fail(f"Failed to apply overrides: {e}")

    @classmethod
    def get_global_ldif_config(cls: object) -> FlextLdifConfig:
        """Get global LDIF configuration instance.

        Returns:
            Global FlextLdifConfig instance

        Raises:
            RuntimeError: If configuration has not been initialized

        """
        # Use the parent's singleton pattern correctly
        # Use FlextContainer for global configuration management
        container = FlextContainer.get_global()
        global_instance_result = container.get("ldif_config")
        if global_instance_result.is_success:
            global_instance = global_instance_result.value
        else:
            global_instance = None

        # If it's already a FlextLdifConfig, return it
        if isinstance(global_instance, FlextLdifConfig):
            return global_instance

        # If it's a base FlextConfig, we need to initialize LDIF config
        # This should not happen in normal operation, but handle gracefully
        msg = "Global instance is not a FlextLdifConfig instance. Call initialize_global_ldif_config() first."
        raise RuntimeError(msg)

    @classmethod
    def initialize_global_ldif_config(
        cls,
        **kwargs: object,
    ) -> FlextResult[FlextLdifConfig]:
        """Initialize global LDIF configuration.

        Args:
            **kwargs: Configuration parameters to override defaults

        Returns:
            FlextResult containing initialized configuration

        """
        try:
            # Check if already initialized
            try:
                existing = cls.get_global_ldif_config()
                return FlextResult[FlextLdifConfig].ok(existing)
            except RuntimeError:
                # Not initialized yet, proceed with initialization
                pass

            # Create new LDIF config instance with parameters - this triggers Pydantic validation
            # Pydantic BaseSettings handles kwargs properly
            # Type cast to bypass mypy's argument checking since BaseSettings handles dynamic kwargs
            config = cls(**kwargs)  # type: ignore[arg-type]

            # Set as global instance using parent's method
            # Use FlextContainer for global configuration management
            container = FlextContainer.get_global()
            container.register("ldif_config", config)

            return FlextResult[FlextLdifConfig].ok(config)
        except ValueError as e:  # pragma: no cover
            return FlextResult[FlextLdifConfig].fail(str(e))
        except Exception as e:  # pragma: no cover
            return FlextResult[FlextLdifConfig].fail(
                f"Failed to initialize LDIF configuration: {e}",
                error_code="LDIF_CONFIG_INIT_ERROR",
            )

    def seal(self) -> None:
        """Seal configuration to prevent further modifications."""
        # Mark configuration as sealed
        self._sealed = True

    def is_sealed(self) -> bool:
        """Check if configuration is sealed."""
        return getattr(self, "_sealed", False)

    @classmethod
    def reset_global_ldif_config(cls: object) -> None:
        """Reset global LDIF configuration (for testing)."""
        # Use FlextContainer for global configuration management
        container = FlextContainer.get_global()
        container.unregister("ldif_config")


__all__ = ["FlextLdifConfig"]
