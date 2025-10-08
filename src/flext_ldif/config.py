"""FLEXT LDIF Configuration - Advanced Pydantic 2 Settings with Centralized Validation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

from flext_core import FlextConfig, FlextConstants
from pydantic import Field, field_validator, model_validator
from pydantic_settings import SettingsConfigDict

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.typings import FlextLdifTypes


class FlextLdifConfig(FlextConfig):
    """Advanced Pydantic 2 Settings class for flext-ldif using FlextConfig as configuration source.

    Leverages FlextConfig's newer features:
    - Centralized configuration management through FlextConfig
    - Enhanced singleton pattern with proper lifecycle management
    - Integrated environment variable handling
    - Advanced validation and type safety
    - Automatic dependency injection integration
    - Built-in configuration validation and consistency checks

    All flext-ldif specific configuration flows through FlextConfig,
    eliminating duplication and ensuring consistency across the FLEXT ecosystem.
    """

    model_config = SettingsConfigDict(
        env_prefix="FLEXT_LDIF_",
        case_sensitive=False,
        extra="ignore",
        # Enhanced Pydantic 2.11+ features through FlextConfig
        validate_assignment=True,
        str_strip_whitespace=True,
        json_schema_extra={
            "title": "FLEXT LDIF Configuration",
            "description": "Enterprise LDIF processing using FlextConfig as source",
        },
    )

    # LDIF Format Configuration using FlextLdifConstants for defaults
    ldif_encoding: str = Field(
        default=FlextLdifConstants.Encoding.DEFAULT_ENCODING,
        description="Character encoding for LDIF files",
    )

    ldif_max_line_length: int = Field(
        default=FlextLdifConstants.Format.MAX_LINE_LENGTH,
        ge=40,
        le=200,
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
        le=10000000,
        description="Maximum number of entries to process",
    )

    ldif_chunk_size: int = Field(
        default=FlextConstants.Performance.BatchProcessing.DEFAULT_SIZE,
        ge=100,
        le=10000,
        description="Chunk size for LDIF processing",
    )

    max_workers: int = Field(
        default=FlextLdifConstants.PERFORMANCE_MIN_WORKERS,
        ge=1,
        le=FlextLdifConstants.MAX_WORKERS_LIMIT,
        description="Maximum number of worker threads",
    )

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
        ge=1,
        description="Threshold for enabling parallel processing",
    )

    # Analytics Configuration
    ldif_enable_analytics: bool = Field(
        default=FlextLdifConstants.ConfigDefaults.LDIF_ENABLE_ANALYTICS,
        description="Enable LDIF analytics collection",
    )

    ldif_analytics_cache_size: int = Field(
        default=FlextConstants.Performance.BatchProcessing.DEFAULT_SIZE,
        ge=FlextLdifConstants.MIN_ANALYTICS_CACHE_SIZE,
        le=FlextLdifConstants.MAX_ANALYTICS_CACHE_SIZE,
        description="Cache size for LDIF analytics",
    )

    analytics_detail_level: str = Field(
        default=FlextLdifConstants.DictKeys.MEDIUM,
        description="Analytics detail level (low, medium, high)",
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
        ge=1,
        le=FlextLdifConstants.MAX_BATCH_SIZE,
        description="Batch size for LDIF processing",
    )

    ldif_fail_on_warnings: bool = Field(
        default=FlextLdifConstants.ConfigDefaults.LDIF_FAIL_ON_WARNINGS,
        description="Fail processing on warnings",
    )

    ldif_analytics_sample_rate: float = Field(
        default=FlextLdifConstants.ConfigDefaults.LDIF_ANALYTICS_SAMPLE_RATE,
        ge=0.0,
        le=1.0,
        description="Analytics sampling rate (0.0 to 1.0)",
    )

    ldif_analytics_max_entries: int = Field(
        default=FlextLdifConstants.ConfigDefaults.LDIF_ANALYTICS_MAX_ENTRIES,
        ge=1,
        le=100000,
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

    # Validation Configuration using FlextLdifConstants for defaults
    validation_level: FlextLdifTypes.ValidationLevel = Field(
        default=cast(
            "FlextLdifTypes.ValidationLevel",
            FlextLdifConstants.LiteralTypes.VALIDATION_LEVELS[0],
        ),  # "strict"
        description="Validation strictness level",
    )

    strict_rfc_compliance: bool = Field(
        default=FlextLdifConstants.ConfigDefaults.STRICT_RFC_COMPLIANCE,
        description="Enable strict RFC 2849 compliance",
    )

    # Server Configuration using FlextLdifConstants for defaults
    server_type: FlextLdifTypes.ServerType = Field(
        default=cast(
            "FlextLdifTypes.ServerType", FlextLdifConstants.ServerTypes.GENERIC
        ),
        description="Target LDAP server type",
    )

    # Error Handling Configuration
    error_recovery_mode: str = Field(
        default=FlextLdifConstants.ConfigDefaults.ERROR_RECOVERY_MODE_CONTINUE,
        description="Error recovery mode (continue, stop, skip)",
    )

    # Development and Debug Configuration
    debug_mode: bool = Field(
        default=FlextLdifConstants.ConfigDefaults.DEBUG_MODE,
        description="Enable debug mode",
    )

    verbose_logging: bool = Field(
        default=FlextLdifConstants.ConfigDefaults.VERBOSE_LOGGING,
        description="Enable verbose logging",
    )

    # Pydantic 2.11 field validators
    @field_validator("ldif_encoding")
    @classmethod
    def validate_ldif_encoding(cls, v: str) -> str:
        """Validate LDIF encoding is supported."""
        if v not in FlextLdifConstants.Encoding.SUPPORTED_ENCODINGS:
            supported = ", ".join(FlextLdifConstants.Encoding.SUPPORTED_ENCODINGS)
            msg = f"Invalid encoding: {v}. Supported encodings: {supported}"
            raise ValueError(msg)
        return v.lower()

    @field_validator("max_workers")
    @classmethod
    def validate_max_workers(cls, v: int) -> int:
        """Validate max workers configuration."""
        if v < 1:
            msg = "max_workers must be at least 1"
            raise ValueError(msg)
        if v > FlextLdifConstants.MAX_WORKERS_LIMIT:
            msg = f"max_workers cannot exceed {FlextLdifConstants.MAX_WORKERS_LIMIT}"
            raise ValueError(msg)
        return v

    @field_validator("validation_level")
    @classmethod
    def validate_validation_level(cls, v: str) -> str:
        """Validate validation level."""
        valid_levels = {
            FlextLdifConstants.RfcCompliance.STRICT,
            FlextLdifConstants.RfcCompliance.MODERATE,
            FlextLdifConstants.RfcCompliance.LENIENT,
        }
        if v not in valid_levels:
            msg = f"validation_level must be one of: {', '.join(valid_levels)}"
            raise ValueError(msg)
        return v

    @field_validator("server_type")
    @classmethod
    def validate_server_type(cls, v: str) -> str:
        """Validate server type."""
        valid_types = {
            FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY,
            FlextLdifConstants.LdapServers.OPENLDAP,
            FlextLdifConstants.LdapServers.APACHE_DIRECTORY,
            FlextLdifConstants.LdapServers.NOVELL_EDIRECTORY,
            FlextLdifConstants.LdapServers.IBM_TIVOLI,
            FlextLdifConstants.LdapServers.GENERIC,
        }
        if v not in valid_types:
            msg = f"Invalid server_type: {v}. Must be one of: {', '.join(valid_types)}"
            raise ValueError(msg)
        return v

    @field_validator("analytics_detail_level")
    @classmethod
    def validate_analytics_detail_level(cls, v: str) -> str:
        """Validate analytics detail level."""
        valid_levels = {
            FlextLdifConstants.ConfigDefaults.ANALYTICS_DETAIL_LEVEL_LOW,
            FlextLdifConstants.DictKeys.MEDIUM,
            FlextLdifConstants.DictKeys.HIGH,
        }
        if v not in valid_levels:
            msg = f"analytics_detail_level must be one of: {', '.join(valid_levels)}"
            raise ValueError(msg)
        return v

    @field_validator("error_recovery_mode")
    @classmethod
    def validate_error_recovery_mode(cls, v: str) -> str:
        """Validate error recovery mode."""
        valid_modes = {
            FlextLdifConstants.ConfigDefaults.ERROR_RECOVERY_MODE_CONTINUE,
            FlextLdifConstants.DictKeys.STOP,
            FlextLdifConstants.DictKeys.SKIP,
        }
        if v not in valid_modes:
            msg = f"error_recovery_mode must be one of: {', '.join(valid_modes)}"
            raise ValueError(msg)
        return v

    @model_validator(mode="after")
    def validate_ldif_configuration_consistency(self) -> FlextLdifConfig:
        """Validate LDIF configuration consistency."""
        # Validate performance configuration consistency
        if self.enable_performance_optimizations:
            if self.max_workers < FlextLdifConstants.PERFORMANCE_MIN_WORKERS:
                msg = (
                    f"Performance mode requires at least "
                    f"{FlextLdifConstants.PERFORMANCE_MIN_WORKERS} workers"
                )
                raise ValueError(msg)

            if self.ldif_chunk_size < FlextLdifConstants.PERFORMANCE_MIN_CHUNK_SIZE:
                msg = (
                    f"Performance mode requires chunk size >= "
                    f"{FlextLdifConstants.PERFORMANCE_MIN_CHUNK_SIZE}"
                )
                raise ValueError(msg)

        # Validate debug mode consistency
        if self.debug_mode and self.max_workers > FlextLdifConstants.DEBUG_MAX_WORKERS:
            msg = (
                f"Debug mode should use <= "
                f"{FlextLdifConstants.DEBUG_MAX_WORKERS} workers "
                f"for better debugging"
            )
            raise ValueError(msg)

        # Validate analytics configuration
        if self.ldif_enable_analytics and self.ldif_analytics_cache_size <= 0:
            msg = "Analytics cache size must be positive when analytics is enabled"
            raise ValueError(msg)

        # Validate parallel processing threshold
        if self.enable_parallel_processing and self.parallel_threshold <= 0:
            msg = (
                "Parallel threshold must be positive when parallel processing "
                "is enabled"
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
            return (
                FlextLdifConstants.Encoding.UTF16
                if self.ldif_encoding == FlextLdifConstants.Encoding.UTF8
                else self.ldif_encoding
            )
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
            return min(FlextLdifConstants.MIN_WORKERS_FOR_PARALLEL, self.max_workers)
        return self.max_workers

    def is_performance_optimized(self) -> bool:
        """Check if configuration is optimized for performance."""
        return (
            self.enable_performance_optimizations
            and self.max_workers >= FlextLdifConstants.PERFORMANCE_MIN_WORKERS
            and self.ldif_chunk_size >= FlextLdifConstants.PERFORMANCE_MIN_CHUNK_SIZE
            and self.memory_limit_mb
            >= FlextLdifConstants.PERFORMANCE_MEMORY_MB_THRESHOLD
        )

    def is_development_optimized(self) -> bool:
        """Check if configuration is optimized for development."""
        return (
            self.debug_mode
            and self.verbose_logging
            and self.max_workers <= FlextLdifConstants.DEBUG_MAX_WORKERS
        )


__all__ = ["FlextLdifConfig"]
