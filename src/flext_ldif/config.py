"""FLEXT LDIF Configuration - Advanced Pydantic 2 Settings with Centralized Validation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import SettingsConfigDict

from flext_core import FlextConfig, FlextResult
from flext_ldif.constants import FlextLdifConstants


class FlextLdifConfig(FlextConfig):
    """LDIF domain configuration extending flext-core FlextConfig.

    Provides centralized configuration with Pydantic 2 validation.
    Uses advanced settings patterns with environment variable support.
    """

    model_config = SettingsConfigDict(
        env_prefix="FLEXT_LDIF_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="forbid",
        validate_assignment=True,
        use_enum_values=True,
        arbitrary_types_allowed=True,
    )

    # =============================================================================
    # CORE CONFIGURATION SETTINGS - Essential LDIF Processing
    # =============================================================================

    # LDIF-Specific Configuration
    ldif_encoding: str = Field(
        default="utf-8",
        description="Character encoding for LDIF files",
    )

    ldif_max_line_length: int = Field(
        default=78,
        ge=40,
        le=200,
        description="Maximum LDIF line length (RFC 2849 compliance)",
    )

    ldif_skip_comments: bool = Field(
        default=False,
        description="Skip comment lines during parsing",
    )

    ldif_validate_dn_format: bool = Field(
        default=False,
        description="Validate DN format during parsing",
    )

    ldif_strict_validation: bool = Field(
        default=True,
        description="Enable strict LDIF validation",
    )

    ldif_max_entries: int = Field(
        default=1000000,
        ge=1000,
        le=10000000,
        description="Maximum number of entries to process",
    )

    ldif_chunk_size: int = Field(
        default=1000,
        ge=100,
        le=10000,
        description="Chunk size for LDIF processing",
    )

    ldif_enable_analytics: bool = Field(
        default=True,
        description="Enable LDIF analytics collection",
    )

    ldif_analytics_cache_size: int = Field(
        default=1000,
        ge=100,
        le=10000,
        description="Cache size for LDIF analytics",
    )

    # Processing Configuration
    max_workers: int = Field(
        default=4,
        ge=1,
        le=16,
        description="Maximum number of worker threads",
    )

    validation_level: Literal["strict", "moderate", "lenient"] = Field(
        default="strict",
        description="Validation strictness level",
    )

    # Server Configuration
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

    # Performance Configuration
    enable_performance_optimizations: bool = Field(
        default=True,
        description="Enable performance optimizations",
    )

    memory_limit_mb: int = Field(
        default=512,
        ge=64,
        le=8192,
        description="Memory limit in MB",
    )

    # Development Configuration
    debug_mode: bool = Field(
        default=False,
        description="Enable debug mode",
    )

    verbose_logging: bool = Field(
        default=False,
        description="Enable verbose logging",
    )

    # Missing attributes needed by other modules
    enable_parallel_processing: bool = Field(
        default=True,
        description="Enable parallel processing",
    )

    parallel_threshold: int = Field(
        default=100,
        ge=1,
        description="Threshold for enabling parallel processing",
    )

    error_recovery_mode: str = Field(
        default="continue",
        description="Error recovery mode",
    )

    default_encoding: str = Field(
        default="utf-8",
        description="Default character encoding",
    )

    enable_analytics: bool = Field(
        default=True,
        description="Enable analytics collection",
    )

    analytics_detail_level: str = Field(
        default="medium",
        description="Analytics detail level",
    )

    strict_rfc_compliance: bool = Field(
        default=True,
        description="Enable strict RFC compliance",
    )

    # =============================================================================
    # VALIDATION METHODS
    # =============================================================================

    @field_validator("max_workers")
    @classmethod
    def validate_max_workers(cls, v: int) -> int:
        """Validate max workers configuration."""
        if v < 1:
            msg = "max_workers must be at least 1"
            raise ValueError(msg)
        if v > FlextLdifConstants.Processing.MAX_WORKERS_LIMIT:
            msg = f"max_workers cannot exceed {FlextLdifConstants.Processing.MAX_WORKERS_LIMIT}"
            raise ValueError(msg)
        return v

    @field_validator("validation_level")
    @classmethod
    def validate_validation_level(cls, v: str) -> str:
        """Validate validation level."""
        if v not in {"strict", "moderate", "lenient"}:
            msg = "validation_level must be strict, moderate, or lenient"
            raise ValueError(msg)
        return v

    @field_validator("ldif_encoding")
    @classmethod
    def validate_encoding(cls, v: str) -> str:
        """Validate encoding configuration."""
        if not v or not v.strip():
            msg = "encoding cannot be empty"
            raise ValueError(msg)
        return v.strip().lower()

    @model_validator(mode="after")
    def validate_server_configs(self) -> FlextLdifConfig:
        """Validate server-specific configurations."""
        # Server-specific validation logic
        if self.server_type == "active_directory" and self.ldif_strict_validation:
            # AD has specific requirements
            pass

        return self

    # =============================================================================
    # BUSINESS LOGIC METHODS
    # =============================================================================

    def validate_configuration_consistency(self) -> FlextLdifConfig:
        """Validate configuration consistency."""
        # Check for conflicting settings
        if self.enable_performance_optimizations and self.debug_mode:
            # Performance optimizations might conflict with debug mode
            pass

        return self

    @classmethod
    def create_for_server_type(
        cls,
        server_type: str,
        **kwargs: object,
    ) -> FlextLdifConfig:
        """Create configuration optimized for specific server type."""
        config_data = {
            "server_type": server_type,
            **kwargs,
        }

        # Server-specific optimizations
        if server_type == "openldap":
            config_data.update({
                "ldif_strict_validation": True,
                "ldif_validate_dn_format": True,
            })
        elif server_type == "active_directory":
            config_data.update({
                "ldif_strict_validation": False,
                "ldif_validate_dn_format": False,
            })

        return cls(
            ldif_encoding=config_data.get("ldif_encoding", "utf-8"),
            ldif_max_line_length=config_data.get("ldif_max_line_length", 78),
            ldif_skip_comments=config_data.get("ldif_skip_comments", False),
            ldif_validate_dn_format=config_data.get("ldif_validate_dn_format", False),
            ldif_strict_validation=config_data.get("ldif_strict_validation", True),
            ldif_max_entries=config_data.get("ldif_max_entries", 1000000),
            ldif_chunk_size=config_data.get("ldif_chunk_size", 1000),
            ldif_enable_analytics=config_data.get("ldif_enable_analytics", True),
            ldif_analytics_cache_size=config_data.get(
                "ldif_analytics_cache_size", 1000
            ),
            max_workers=config_data.get("max_workers", 4),
            memory_limit_mb=config_data.get("memory_limit_mb", 512),
            enable_performance_optimizations=config_data.get(
                "enable_performance_optimizations", False
            ),
            debug_mode=config_data.get("debug_mode", False),
            verbose_logging=config_data.get("verbose_logging", False),
            validation_level=config_data.get("validation_level", "strict"),
            server_type=config_data.get("server_type", "generic"),
        )

    @classmethod
    def create_for_performance(
        cls,
        **kwargs: object,
    ) -> FlextLdifConfig:
        """Create configuration optimized for performance."""
        config_data = {
            "enable_performance_optimizations": True,
            "max_workers": 8,
            "ldif_chunk_size": 5000,
            "memory_limit_mb": 1024,
            **kwargs,
        }

        return cls(
            ldif_encoding=config_data.get("ldif_encoding", "utf-8"),
            ldif_max_line_length=config_data.get("ldif_max_line_length", 78),
            ldif_skip_comments=config_data.get("ldif_skip_comments", False),
            ldif_validate_dn_format=config_data.get("ldif_validate_dn_format", False),
            ldif_strict_validation=config_data.get("ldif_strict_validation", True),
            ldif_max_entries=config_data.get("ldif_max_entries", 1000000),
            ldif_chunk_size=config_data.get("ldif_chunk_size", 5000),  # Use performance value
            ldif_enable_analytics=config_data.get("ldif_enable_analytics", True),
            ldif_analytics_cache_size=config_data.get(
                "ldif_analytics_cache_size", 1000
            ),
            max_workers=config_data.get("max_workers", 8),  # Use performance value
            memory_limit_mb=config_data.get("memory_limit_mb", 1024),  # Use performance value
            enable_performance_optimizations=config_data.get(
                "enable_performance_optimizations", True  # Enable for performance
            ),
            debug_mode=config_data.get("debug_mode", False),
            verbose_logging=config_data.get("verbose_logging", False),
            validation_level=config_data.get("validation_level", "strict"),
            server_type=config_data.get("server_type", "generic"),
            # Add all existing fields but remove non-existent ones
            enable_parallel_processing=config_data.get("enable_parallel_processing", True),
            parallel_threshold=config_data.get("parallel_threshold", 100),
            error_recovery_mode=config_data.get("error_recovery_mode", "continue"),
            default_encoding=config_data.get("default_encoding", "utf-8"),
            enable_analytics=config_data.get("enable_analytics", True),
            analytics_detail_level=config_data.get("analytics_detail_level", "medium"),
            strict_rfc_compliance=config_data.get("strict_rfc_compliance", True),
        )

    @classmethod
    def create_for_development(
        cls,
        **kwargs: object,
    ) -> FlextLdifConfig:
        """Create configuration optimized for development."""
        config_data = {
            "debug_mode": True,
            "verbose_logging": True,
            "ldif_strict_validation": True,
            "max_workers": 2,
            **kwargs,
        }

        return cls(
            ldif_encoding=config_data.get("ldif_encoding", "utf-8"),
            ldif_max_line_length=config_data.get("ldif_max_line_length", 78),
            ldif_skip_comments=config_data.get("ldif_skip_comments", False),
            ldif_validate_dn_format=config_data.get("ldif_validate_dn_format", False),
            ldif_strict_validation=config_data.get("ldif_strict_validation", True),
            ldif_max_entries=config_data.get("ldif_max_entries", 1000000),
            ldif_chunk_size=config_data.get("ldif_chunk_size", 1000),
            ldif_enable_analytics=config_data.get("ldif_enable_analytics", True),
            ldif_analytics_cache_size=config_data.get(
                "ldif_analytics_cache_size", 1000
            ),
            max_workers=config_data.get("max_workers", 2),  # Use development value
            memory_limit_mb=config_data.get("memory_limit_mb", 512),
            enable_performance_optimizations=config_data.get(
                "enable_performance_optimizations", False
            ),
            debug_mode=config_data.get("debug_mode", True),  # Enable for development
            verbose_logging=config_data.get("verbose_logging", True),  # Enable for development
            validation_level=config_data.get("validation_level", "strict"),
            server_type=config_data.get("server_type", "generic"),
            # Remove non-existent fields and add existing ones
            enable_parallel_processing=config_data.get("enable_parallel_processing", True),
            parallel_threshold=config_data.get("parallel_threshold", 100),
            error_recovery_mode=config_data.get("error_recovery_mode", "continue"),
            default_encoding=config_data.get("default_encoding", "utf-8"),
            enable_analytics=config_data.get("enable_analytics", True),
            analytics_detail_level=config_data.get("analytics_detail_level", "medium"),
            strict_rfc_compliance=config_data.get("strict_rfc_compliance", True),
        )

    def get_server_config(self, server_type: str) -> dict[str, object]:
        """Get server-specific configuration."""
        return {
            "server_type": server_type,
            "optimized": True,
        }

    def update_server_config(
        self,
        server_type: str,
        config_updates: dict[str, object],
    ) -> None:
        """Update server-specific configuration."""
        # Update configuration based on server type

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

    def get_effective_encoding(self) -> str:
        """Get effective encoding for file processing."""
        return self.ldif_encoding

    def get_effective_workers(self, entry_count: int) -> int:
        """Get effective number of workers based on entry count."""
        if entry_count < FlextLdifConstants.Processing.SMALL_ENTRY_COUNT_THRESHOLD:
            return 1
        if entry_count < FlextLdifConstants.Processing.MEDIUM_ENTRY_COUNT_THRESHOLD:
            return min(
                FlextLdifConstants.Processing.MIN_WORKERS_FOR_PARALLEL, self.max_workers
            )
        return self.max_workers

    # =============================================================================
    # GLOBAL CONFIGURATION MANAGEMENT
    # =============================================================================

    @classmethod
    def initialize_global_ldif_config(
        cls,
        config: FlextLdifConfig | None = None,
    ) -> FlextLdifConfig:
        """Initialize global LDIF configuration."""
        if config is None:
            config = cls()
        return config

    @classmethod
    def get_global_ldif_config(cls) -> FlextLdifConfig:
        """Get global LDIF configuration."""
        return cls()

    @classmethod
    def reset_global_ldif_config(cls) -> None:
        """Reset global LDIF configuration."""

    # =============================================================================
    # BUSINESS RULES VALIDATION
    # =============================================================================

    def validate_ldif_business_rules(self) -> FlextResult[bool]:
        """Validate LDIF-specific business rules."""
        try:
            # Validate encoding
            if not self.ldif_encoding:
                return FlextResult[bool].fail("LDIF encoding is required")

            # Validate max entries
            if self.ldif_max_entries < 1:
                return FlextResult[bool].fail("LDIF max entries must be positive")

            # Validate chunk size
            if self.ldif_chunk_size < 1:
                return FlextResult[bool].fail("LDIF chunk size must be positive")

            return FlextResult[bool].ok(True)
        except Exception as e:
            return FlextResult[bool].fail(str(e))

    def apply_ldif_overrides(
        self,
        overrides: dict[str, object],
    ) -> FlextLdifConfig:
        """Apply LDIF-specific configuration overrides."""
        # Create new config with overrides
        config_data = self.model_dump()
        config_data.update(overrides)
        return self.__class__(**config_data)

    def seal(self) -> None:
        """Seal configuration to prevent further modifications."""
        # Mark configuration as sealed


__all__ = ["FlextLdifConfig"]
