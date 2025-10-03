"""FLEXT LDIF Configuration - Advanced Pydantic 2 Settings with Centralized Validation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import SettingsConfigDict

from flext_core import FlextConfig, FlextConstants, FlextTypes
from flext_ldif.constants import FlextLdifConstants


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
        default=False,
        description="Skip comment lines during parsing",
    )

    ldif_validate_dn_format: bool = Field(
        default=True,
        description="Validate DN format during parsing",
    )

    ldif_strict_validation: bool = Field(
        default=True,
        description="Enable strict LDIF validation",
    )

    # Processing Configuration using FlextLdifConstants for defaults
    ldif_max_entries: int = Field(
        default=1000000,
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
        default=FlextLdifConstants.Processing.PERFORMANCE_MIN_WORKERS,
        ge=1,
        le=FlextLdifConstants.Processing.MAX_WORKERS_LIMIT,
        description="Maximum number of worker threads",
    )

    # Memory and Performance Configuration - Fix default value
    memory_limit_mb: int = Field(
        default=FlextLdifConstants.Processing.MIN_MEMORY_MB,
        ge=FlextLdifConstants.Processing.MIN_MEMORY_MB,
        le=8192,
        description="Memory limit in MB",
    )

    enable_performance_optimizations: bool = Field(
        default=True,
        description="Enable performance optimizations",
    )

    enable_parallel_processing: bool = Field(
        default=True,
        description="Enable parallel processing",
    )

    parallel_threshold: int = Field(
        default=FlextLdifConstants.Processing.SMALL_ENTRY_COUNT_THRESHOLD,
        ge=1,
        description="Threshold for enabling parallel processing",
    )

    # Analytics Configuration
    ldif_enable_analytics: bool = Field(
        default=True,
        description="Enable LDIF analytics collection",
    )

    ldif_analytics_cache_size: int = Field(
        default=FlextConstants.Performance.BatchProcessing.DEFAULT_SIZE,
        ge=FlextLdifConstants.Processing.MIN_ANALYTICS_CACHE_SIZE,
        le=FlextLdifConstants.Processing.MAX_ANALYTICS_CACHE_SIZE,
        description="Cache size for LDIF analytics",
    )

    analytics_detail_level: str = Field(
        default="medium",
        description="Analytics detail level (low, medium, high)",
    )

    # Validation Configuration using FlextLdifConstants for defaults
    validation_level: Literal["strict", "moderate", "lenient"] = Field(
        default="strict",
        description="Validation strictness level",
    )

    strict_rfc_compliance: bool = Field(
        default=True,
        description="Enable strict RFC 2849 compliance",
    )

    # Server Configuration using FlextLdifConstants for defaults
    server_type: Literal[
        "active_directory",
        "openldap",
        "apache_directory",
        "novell_edirectory",
        "ibm_tivoli",
        "generic",
    ] = Field(
        default="generic",
        description="Target LDAP server type",
    )

    # Error Handling Configuration
    error_recovery_mode: str = Field(
        default="continue",
        description="Error recovery mode (continue, stop, skip)",
    )

    # Development and Debug Configuration
    debug_mode: bool = Field(
        default=False,
        description="Enable debug mode",
    )

    verbose_logging: bool = Field(
        default=False,
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
        if v > FlextLdifConstants.Processing.MAX_WORKERS_LIMIT:
            msg = (
                f"max_workers cannot exceed "
                f"{FlextLdifConstants.Processing.MAX_WORKERS_LIMIT}"
            )
            raise ValueError(msg)
        return v

    @field_validator("validation_level")
    @classmethod
    def validate_validation_level(cls, v: str) -> str:
        """Validate validation level."""
        valid_levels = {"strict", "moderate", "lenient"}
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
        valid_levels = {"low", "medium", "high"}
        if v not in valid_levels:
            msg = f"analytics_detail_level must be one of: {', '.join(valid_levels)}"
            raise ValueError(msg)
        return v

    @field_validator("error_recovery_mode")
    @classmethod
    def validate_error_recovery_mode(cls, v: str) -> str:
        """Validate error recovery mode."""
        valid_modes = {"continue", "stop", "skip"}
        if v not in valid_modes:
            msg = f"error_recovery_mode must be one of: {', '.join(valid_modes)}"
            raise ValueError(msg)
        return v

    @model_validator(mode="after")
    def validate_ldif_configuration_consistency(self) -> FlextLdifConfig:
        """Validate LDIF configuration consistency."""
        # Validate performance configuration consistency
        if self.enable_performance_optimizations:
            if self.max_workers < FlextLdifConstants.Processing.PERFORMANCE_MIN_WORKERS:
                msg = (
                    f"Performance mode requires at least "
                    f"{FlextLdifConstants.Processing.PERFORMANCE_MIN_WORKERS} workers"
                )
                raise ValueError(msg)

            if (
                self.ldif_chunk_size
                < FlextLdifConstants.Processing.PERFORMANCE_MIN_CHUNK_SIZE
            ):
                msg = (
                    f"Performance mode requires chunk size >= "
                    f"{FlextLdifConstants.Processing.PERFORMANCE_MIN_CHUNK_SIZE}"
                )
                raise ValueError(msg)

        # Validate debug mode consistency
        if (
            self.debug_mode
            and self.max_workers > FlextLdifConstants.Processing.DEBUG_MAX_WORKERS
        ):
            msg = (
                f"Debug mode should use <= "
                f"{FlextLdifConstants.Processing.DEBUG_MAX_WORKERS} workers "
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
    # ENVIRONMENT-SPECIFIC CONFIGURATION METHODS
    # =========================================================================

    @classmethod
    def create_for_environment(
        cls, environment: str, **overrides: object
    ) -> FlextLdifConfig:
        """Create configuration optimized for specific environment.

        Args:
            environment: Environment name ("development", "production", "testing")
            **overrides: Additional configuration overrides

        Returns:
            FlextLdifConfig instance configured for the environment

        """
        base_config: FlextTypes.Dict = {"environment": environment}

        # Environment-specific defaults
        if environment == "development":
            base_config.update({
                "debug_mode": True,
                "verbose_logging": True,
                "ldif_strict_validation": False,
                "enable_performance_optimizations": False,
                "max_workers": FlextLdifConstants.Processing.DEBUG_MAX_WORKERS,
            })
        elif environment == "production":
            base_config.update({
                "debug_mode": False,
                "verbose_logging": False,
                "ldif_strict_validation": True,
                "enable_performance_optimizations": True,
                "max_workers": FlextLdifConstants.Processing.MAX_WORKERS_LIMIT,
            })
        elif environment == "testing":
            base_config.update({
                "debug_mode": False,
                "verbose_logging": False,
                "ldif_strict_validation": True,
                "enable_performance_optimizations": False,
                "max_workers": 2,
            })

        # Apply overrides
        base_config.update(overrides)
        return cls(**base_config)

    @classmethod
    def create_for_performance(cls) -> FlextLdifConfig:
        """Create configuration optimized for high-performance processing.

        Returns:
            FlextLdifConfig instance with performance optimizations enabled

        """
        return cls(
            debug_mode=False,
            verbose_logging=False,
            max_workers=FlextLdifConstants.Processing.PERFORMANCE_MIN_WORKERS,
            ldif_chunk_size=FlextLdifConstants.Processing.PERFORMANCE_MIN_CHUNK_SIZE,
            enable_performance_optimizations=True,
            enable_parallel_processing=True,
            memory_limit_mb=FlextLdifConstants.Processing.PERFORMANCE_MEMORY_MB_THRESHOLD,
            ldif_strict_validation=True,
            ldif_enable_analytics=False,  # Skip analytics for performance
        )

    @classmethod
    def create_for_development(cls) -> FlextLdifConfig:
        """Create configuration optimized for development environment.

        Returns:
            FlextLdifConfig instance with development-friendly settings

        """
        return cls(
            debug_mode=True,
            verbose_logging=True,
            enable_performance_optimizations=False,
            max_workers=FlextLdifConstants.Processing.DEBUG_MAX_WORKERS,
            ldif_chunk_size=FlextConstants.Performance.BatchProcessing.DEFAULT_SIZE // 10,
            memory_limit_mb=FlextLdifConstants.Processing.MIN_MEMORY_MB,
            ldif_strict_validation=False,
            ldif_enable_analytics=True,
        )

    @classmethod
    def create_for_server_type(cls, server_type: str) -> FlextLdifConfig:
        """Create configuration optimized for specific LDAP server type.

        Args:
            server_type: LDAP server type (openldap, active_directory, etc.)

        Returns:
            FlextLdifConfig instance configured for the server type

        """
        base_config: FlextTypes.Dict = {"server_type": server_type}

        # Server-specific optimizations
        if server_type == "openldap":
            base_config.update({
                "ldif_strict_validation": True,
                "ldif_validate_dn_format": True,
                "strict_rfc_compliance": True,
            })
        elif server_type == "active_directory":
            base_config.update({
                "ldif_strict_validation": False,
                "ldif_validate_dn_format": False,
                "strict_rfc_compliance": False,
            })
        elif server_type == "apache_directory":
            base_config.update({
                "ldif_strict_validation": True,
                "ldif_validate_dn_format": True,
                "strict_rfc_compliance": True,
            })

        return cls(**base_config)

    # =========================================================================
    # UTILITY METHODS - Enhanced with FlextConfig integration
    # =========================================================================

    def get_effective_encoding(self) -> str:
        """Get effective encoding, considering environment and server type.

        Returns:
            Effective character encoding to use

        """
        # Server-specific encoding preferences
        if self.server_type == "active_directory":
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
        if entry_count < FlextLdifConstants.Processing.MEDIUM_ENTRY_COUNT_THRESHOLD:
            return min(
                FlextLdifConstants.Processing.MIN_WORKERS_FOR_PARALLEL,
                self.max_workers
            )
        return self.max_workers

    def is_performance_optimized(self) -> bool:
        """Check if configuration is optimized for performance."""
        return (
            self.enable_performance_optimizations
            and self.max_workers
            >= FlextLdifConstants.Processing.PERFORMANCE_MIN_WORKERS
            and self.ldif_chunk_size
            >= FlextLdifConstants.Processing.PERFORMANCE_MIN_CHUNK_SIZE
            and self.memory_limit_mb
            >= FlextLdifConstants.Processing.PERFORMANCE_MEMORY_MB_THRESHOLD
        )

    def is_development_optimized(self) -> bool:
        """Check if configuration is optimized for development."""
        return (
            self.debug_mode
            and self.verbose_logging
            and self.max_workers <= FlextLdifConstants.Processing.DEBUG_MAX_WORKERS
        )


__all__ = ["FlextLdifConfig"]
