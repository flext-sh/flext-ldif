"""Configuration management for LDIF operations.

This module defines configuration settings using Pydantic models with validation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextConfig, FlextConstants
from pydantic import Field, model_validator

from flext_ldif.constants import FlextLdifConstants


class FlextLdifConfig(FlextConfig):
    """Pydantic 2 Settings class for flext-ldif using FlextConfig as configuration source.

    Leverages FlextConfig's newer features:
    - Centralized configuration management through FlextConfig
    - Enhanced singleton pattern with proper lifecycle management
    - Integrated environment variable handling
    - validation and type safety
    - Automatic dependency injection integration
    - Built-in configuration validation and consistency checks

    All flext-ldif specific configuration flows through FlextConfig,
    eliminating duplication and ensuring consistency across the FLEXT ecosystem.
    """

    # Inherit model_config from FlextConfig (includes debug, trace, all parent fields)
    # NO model_config override - Pydantic v2 pattern for proper field inheritance

    # LDIF Format Configuration using FlextLdifConstants for defaults
    ldif_encoding: FlextLdifConstants.LiteralTypes.EncodingType = Field(
        default="utf-8",
        description="Character encoding for LDIF files",
    )

    ldif_max_line_length: int = Field(
        default=FlextLdifConstants.Format.MAX_LINE_LENGTH,
        ge=FlextLdifConstants.Format.MIN_LINE_LENGTH,
        le=FlextLdifConstants.Format.MAX_LINE_LENGTH_EXTENDED,
        description="Maximum LDIF line length (RFC 2849 compliance)",
    )

    ldif_skip_comments: bool = Field(
        default=FlextLdifConstants.ConfigDefaults.LDIF_SKIP_COMMENTS,
        description="Skip comment lines during parsing",
    )

    ldif_validate_dn_format: bool = Field(
        default=FlextLdifConstants.ConfigDefaults.LDIF_VALIDATE_DN_FORMAT,
        description="Validate DN format during parsing",
    )

    ldif_strict_validation: bool = Field(
        default=FlextLdifConstants.ConfigDefaults.LDIF_STRICT_VALIDATION,
        description="Enable strict LDIF validation",
    )

    # Processing Configuration using FlextLdifConstants for defaults
    ldif_max_entries: int = Field(
        default=FlextLdifConstants.ConfigDefaults.LDIF_MAX_ENTRIES,
        ge=FlextConstants.Performance.BatchProcessing.DEFAULT_SIZE,
        le=FlextLdifConstants.MAX_ENTRIES_ABSOLUTE,
        description="Maximum number of entries to process",
    )

    ldif_chunk_size: int = Field(
        default=FlextLdifConstants.DEFAULT_BATCH_SIZE,
        ge=FlextLdifConstants.LdifProcessing.MIN_CHUNK_SIZE,
        le=FlextLdifConstants.LdifProcessing.MAX_CHUNK_SIZE,
        description="Chunk size for LDIF processing",
    )

    # max_workers inherited from FlextConfig (use self.max_workers)
    # Override to respect debug mode constraints

    # Memory and Performance Configuration - Fix default value
    memory_limit_mb: int = Field(
        default=FlextLdifConstants.MIN_MEMORY_MB,
        ge=FlextLdifConstants.MIN_MEMORY_MB,
        le=FlextLdifConstants.MAX_MEMORY_MB,
        description="Memory limit in MB",
    )

    enable_performance_optimizations: bool = Field(
        default=FlextLdifConstants.ConfigDefaults.ENABLE_PERFORMANCE_OPTIMIZATIONS,
        description="Enable performance optimizations",
    )

    enable_parallel_processing: bool = Field(
        default=FlextLdifConstants.ConfigDefaults.ENABLE_PARALLEL_PROCESSING,
        description="Enable parallel processing",
    )

    parallel_threshold: int = Field(
        default=FlextLdifConstants.SMALL_ENTRY_COUNT_THRESHOLD,
        ge=FlextLdifConstants.LdifProcessing.MIN_WORKERS,
        description="Threshold for enabling parallel processing",
    )

    # Analytics Configuration
    ldif_enable_analytics: bool = Field(
        default=FlextLdifConstants.ConfigDefaults.LDIF_ENABLE_ANALYTICS,
        description="Enable LDIF analytics collection",
    )

    ldif_analytics_cache_size: int = Field(
        default=FlextLdifConstants.DEFAULT_BATCH_SIZE,
        ge=FlextLdifConstants.MIN_ANALYTICS_CACHE_SIZE,
        le=FlextLdifConstants.MAX_ANALYTICS_CACHE_SIZE,
        description="Cache size for LDIF analytics",
    )

    analytics_detail_level: FlextLdifConstants.LiteralTypes.AnalyticsDetailLevel = (
        Field(
            default="medium",
            description="Analytics detail level (low, medium, high)",
        )
    )

    # Additional LDIF processing configuration
    ldif_line_separator: str = Field(
        default=FlextLdifConstants.ConfigDefaults.LDIF_LINE_SEPARATOR,
        description="Line separator for LDIF output",
    )

    ldif_version_string: str = Field(
        default=FlextLdifConstants.ConfigDefaults.LDIF_VERSION_STRING,
        description="LDIF version string",
    )

    ldif_batch_size: int = Field(
        default=FlextLdifConstants.DEFAULT_BATCH_SIZE,
        ge=FlextLdifConstants.MIN_BATCH_SIZE,
        le=FlextLdifConstants.MAX_BATCH_SIZE,
        description="Batch size for LDIF processing",
    )

    ldif_fail_on_warnings: bool = Field(
        default=FlextLdifConstants.ConfigDefaults.LDIF_FAIL_ON_WARNINGS,
        description="Fail processing on warnings",
    )

    ldif_analytics_sample_rate: float = Field(
        default=FlextLdifConstants.ConfigDefaults.LDIF_ANALYTICS_SAMPLE_RATE,
        ge=FlextLdifConstants.MIN_SAMPLE_RATE,
        le=FlextLdifConstants.MAX_SAMPLE_RATE,
        description="Analytics sampling rate (0.0 to 1.0)",
    )

    ldif_analytics_max_entries: int = Field(
        default=FlextLdifConstants.ConfigDefaults.LDIF_ANALYTICS_MAX_ENTRIES,
        ge=FlextLdifConstants.LdifProcessing.MIN_WORKERS,
        le=FlextLdifConstants.MAX_ANALYTICS_ENTRIES_ABSOLUTE,
        description="Maximum entries for analytics processing",
    )

    ldif_default_server_type: str = Field(
        default=FlextLdifConstants.ServerTypes.RFC,
        description="Default server type for LDIF processing",
    )

    ldif_server_specific_quirks: bool = Field(
        default=FlextLdifConstants.ConfigDefaults.LDIF_SERVER_SPECIFIC_QUIRKS,
        description="Enable server-specific quirk handling",
    )

    # Quirks Detection and Mode Configuration
    quirks_detection_mode: FlextLdifConstants.LiteralTypes.DetectionMode = Field(
        default="auto",
        description="Quirks detection mode: auto (detect server type), manual (use quirks_server_type), disabled (RFC only)",
    )

    quirks_server_type: str | None = Field(
        default=None,
        description="Override server type for quirks when detection_mode is 'manual'",
    )

    enable_relaxed_parsing: bool = Field(
        default=False,
        description="Enable relaxed mode for broken/non-compliant LDIF files",
    )

    # Validation Configuration using FlextLdifConstants for defaults
    validation_level: FlextLdifConstants.LiteralTypes.ValidationLevel = Field(
        default="strict",
        description="Validation strictness level",
    )

    strict_rfc_compliance: bool = Field(
        default=FlextLdifConstants.ConfigDefaults.STRICT_RFC_COMPLIANCE,
        description="Enable strict RFC 2849 compliance",
    )

    # Server Configuration using FlextLdifConstants for defaults
    server_type: FlextLdifConstants.LiteralTypes.ServerType = Field(
        default="generic",
        description="Target LDAP server type",
    )

    # Error Handling Configuration
    error_recovery_mode: FlextLdifConstants.LiteralTypes.ErrorRecoveryMode = Field(
        default="continue",
        description="Error recovery mode (continue, stop, skip)",
    )

    # Development and Debug Configuration
    # debug, trace inherited from FlextConfig (use self.debug, self.trace)
    # log_verbosity inherited from FlextConfig (use self.log_verbosity for detailed logging)

    @model_validator(mode="after")
    def validate_ldif_configuration_consistency(self) -> FlextLdifConfig:
        """Validate LDIF configuration consistency."""
        # Validate performance configuration consistency
        if self.enable_performance_optimizations:
            if (
                self.max_workers
                < FlextLdifConstants.ValidationRules.MIN_WORKERS_PERFORMANCE_RULE
            ):
                msg = (
                    f"Performance mode requires at least "
                    f"{FlextLdifConstants.ValidationRules.MIN_WORKERS_PERFORMANCE_RULE} workers"
                )
                raise ValueError(msg)

            if (
                self.ldif_chunk_size
                < FlextLdifConstants.ValidationRules.MIN_CHUNK_SIZE_PERFORMANCE_RULE
            ):
                msg = (
                    f"Performance mode requires chunk size >= "
                    f"{FlextLdifConstants.ValidationRules.MIN_CHUNK_SIZE_PERFORMANCE_RULE}"
                )
                raise ValueError(msg)

        # Validate debug mode consistency (use inherited debug fields from FlextConfig)
        # NO environment-mode-specific behavior - log_level should NOT affect other parameters
        if (self.debug or self.trace) and self.enable_performance_optimizations:
            # Debug mode conflicts with performance optimizations
            # Disable performance mode only
            self.enable_performance_optimizations = False
        # max_workers is NOT affected by log_level or environment mode
        # Only respect explicit debug/trace flags, NOT log_level

        # Validate analytics configuration
        if (
            self.ldif_enable_analytics
            and self.ldif_analytics_cache_size
            <= FlextLdifConstants.ValidationRules.MIN_ANALYTICS_CACHE_RULE - 1
        ):
            msg = "Analytics cache size must be positive when analytics is enabled"
            raise ValueError(msg)

        # Validate parallel processing threshold
        if (
            self.enable_parallel_processing
            and self.parallel_threshold
            < FlextLdifConstants.ValidationRules.MIN_PARALLEL_THRESHOLD_RULE
        ):
            msg = (
                "Parallel threshold must be positive when parallel processing "
                "is enabled"
            )
            raise ValueError(msg)

        # Validate quirks configuration
        if self.quirks_detection_mode == "manual" and not self.quirks_server_type:
            msg = (
                "quirks_server_type must be specified when "
                "quirks_detection_mode is 'manual'"
            )
            raise ValueError(msg)

        return self

    # =========================================================================
    # UTILITY METHODS - Enhanced with FlextConfig integration
    # =========================================================================

    def get_effective_encoding(self) -> str:
        """Get effective encoding, considering environment and server type.

        Returns:
        Effective character encoding to use

        """
        # Server-specific encoding preferences
        if self.server_type == FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY:
            return "utf-16" if self.ldif_encoding == "utf-8" else self.ldif_encoding
        return self.ldif_encoding

    def get_effective_workers(self, entry_count: int) -> int:
        """Calculate effective number of workers based on entry count and configuration.

        Args:
        entry_count: Number of entries to process

        Returns:
        Effective number of workers to use

        """
        if not self.enable_parallel_processing:
            return 1

        if entry_count < self.parallel_threshold:
            return 1
        if entry_count < FlextLdifConstants.MEDIUM_ENTRY_COUNT_THRESHOLD:
            return min(
                FlextLdifConstants.LdifProcessing.MIN_WORKERS_FOR_PARALLEL,
                self.max_workers,
            )
        return self.max_workers

    def is_performance_optimized(self) -> bool:
        """Check if configuration is optimized for performance."""
        return (
            self.enable_performance_optimizations
            and self.max_workers
            >= FlextLdifConstants.LdifProcessing.PERFORMANCE_MIN_WORKERS
            and self.ldif_chunk_size
            >= FlextLdifConstants.LdifProcessing.PERFORMANCE_MIN_CHUNK_SIZE
            and self.memory_limit_mb
            >= FlextLdifConstants.PERFORMANCE_MEMORY_MB_THRESHOLD
        )

    def is_development_optimized(self) -> bool:
        """Check if configuration is optimized for development.

        Uses inherited fields from FlextConfig:
        - self.debug (replaces debug_mode)
        - self.log_verbosity (replaces verbose_logging - checks for "detailed" or "full")
        - self.max_workers
        """
        return (
            self.debug
            and self.log_verbosity in {"detailed", "full"}
            and self.max_workers <= FlextLdifConstants.DEBUG_MAX_WORKERS
        )


__all__ = ["FlextLdifConfig"]
