"""Configuration management for LDIF operations.

This module defines configuration settings using Pydantic models with validation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import Annotated, Literal, cast

from flext_core import FlextConfig, FlextConstants
from pydantic import Field, model_validator
from pydantic.functional_validators import BeforeValidator

from flext_ldif.constants import FlextLdifConstants

# =============================================================================
# MODULE-LEVEL VALIDATORS (Pydantic 2.11+ BeforeValidator pattern)
# =============================================================================


def _coerce_bool_from_env(v: object) -> bool:
    """Coerce environment variable strings to bool (strict mode compatible).

    Args:
    v: Value to coerce to bool

    Returns:
    Boolean value

    """
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.lower() in {"true", "1", "yes", "on"}
    if isinstance(v, int):
        return v != 0
    return bool(v)


def _coerce_int_from_env(v: object) -> int:
    """Coerce environment variable strings to int (strict mode compatible).

    Args:
    v: Value to coerce to int

    Returns:
    Integer value

    """
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        return int(v.strip())
    # Cast to int-compatible type for Pyrefly
    return int(cast("int | float", v))


def _coerce_float_from_env(v: object) -> float:
    """Coerce environment variable strings to float (strict mode compatible).

    Args:
    v: Value to coerce to float

    Returns:
    Float value

    """
    if isinstance(v, float):
        return v
    if isinstance(v, (int, str)):
        return float(v)
    # Cast to float-compatible type for Pyrefly
    return float(cast("int | float | str", v))


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
    ldif_encoding: Literal[
        "utf-8", "latin-1", "ascii", "utf-16", "utf-32", "cp1252", "iso-8859-1"
    ] = Field(
        default="utf-8",
        description="Character encoding for LDIF files",
    )

    ldif_max_line_length: int = Field(
        default=FlextLdifConstants.Format.MAX_LINE_LENGTH,
        ge=FlextLdifConstants.Format.MIN_LINE_LENGTH,
        le=FlextLdifConstants.Format.MAX_LINE_LENGTH_EXTENDED,
        description="Maximum LDIF line length (RFC 2849 compliance)",
    )

    ldif_skip_comments: Annotated[bool, BeforeValidator(_coerce_bool_from_env)] = Field(
        default=FlextLdifConstants.ConfigDefaults.LDIF_SKIP_COMMENTS,
        description="Skip comment lines during parsing",
    )

    ldif_validate_dn_format: Annotated[bool, BeforeValidator(_coerce_bool_from_env)] = (
        Field(
            default=FlextLdifConstants.ConfigDefaults.LDIF_VALIDATE_DN_FORMAT,
            description="Validate DN format during parsing",
        )
    )

    ldif_strict_validation: Annotated[bool, BeforeValidator(_coerce_bool_from_env)] = (
        Field(
            default=FlextLdifConstants.ConfigDefaults.LDIF_STRICT_VALIDATION,
            description="Enable strict LDIF validation",
        )
    )

    # Processing Configuration using FlextLdifConstants for defaults
    ldif_max_entries: Annotated[int, BeforeValidator(_coerce_int_from_env)] = Field(
        default=FlextLdifConstants.ConfigDefaults.LDIF_MAX_ENTRIES,
        ge=FlextConstants.Performance.BatchProcessing.DEFAULT_SIZE,
        le=FlextLdifConstants.MAX_ENTRIES_ABSOLUTE,
        description="Maximum number of entries to process",
    )

    ldif_chunk_size: Annotated[int, BeforeValidator(_coerce_int_from_env)] = Field(
        default=FlextLdifConstants.DEFAULT_BATCH_SIZE,
        ge=FlextLdifConstants.LdifProcessing.MIN_CHUNK_SIZE,
        le=FlextLdifConstants.LdifProcessing.MAX_CHUNK_SIZE,
        description="Chunk size for LDIF processing",
    )

    # max_workers inherited from FlextConfig (use self.max_workers)

    # Memory and Performance Configuration - Fix default value
    memory_limit_mb: Annotated[int, BeforeValidator(_coerce_int_from_env)] = Field(
        default=FlextLdifConstants.MIN_MEMORY_MB,
        ge=FlextLdifConstants.MIN_MEMORY_MB,
        le=FlextLdifConstants.MAX_MEMORY_MB,
        description="Memory limit in MB",
    )

    enable_performance_optimizations: Annotated[
        bool, BeforeValidator(_coerce_bool_from_env)
    ] = Field(
        default=FlextLdifConstants.ConfigDefaults.ENABLE_PERFORMANCE_OPTIMIZATIONS,
        description="Enable performance optimizations",
    )

    enable_parallel_processing: Annotated[
        bool, BeforeValidator(_coerce_bool_from_env)
    ] = Field(
        default=FlextLdifConstants.ConfigDefaults.ENABLE_PARALLEL_PROCESSING,
        description="Enable parallel processing",
    )

    parallel_threshold: Annotated[int, BeforeValidator(_coerce_int_from_env)] = Field(
        default=FlextLdifConstants.SMALL_ENTRY_COUNT_THRESHOLD,
        ge=FlextLdifConstants.LdifProcessing.MIN_WORKERS,
        description="Threshold for enabling parallel processing",
    )

    # Analytics Configuration
    ldif_enable_analytics: Annotated[bool, BeforeValidator(_coerce_bool_from_env)] = (
        Field(
            default=FlextLdifConstants.ConfigDefaults.LDIF_ENABLE_ANALYTICS,
            description="Enable LDIF analytics collection",
        )
    )

    ldif_analytics_cache_size: Annotated[int, BeforeValidator(_coerce_int_from_env)] = (
        Field(
            default=FlextLdifConstants.DEFAULT_BATCH_SIZE,
            ge=FlextLdifConstants.MIN_ANALYTICS_CACHE_SIZE,
            le=FlextLdifConstants.MAX_ANALYTICS_CACHE_SIZE,
            description="Cache size for LDIF analytics",
        )
    )

    analytics_detail_level: Literal["low", "medium", "high"] = Field(
        default="medium",
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

    ldif_batch_size: Annotated[int, BeforeValidator(_coerce_int_from_env)] = Field(
        default=FlextLdifConstants.DEFAULT_BATCH_SIZE,
        ge=FlextLdifConstants.MIN_BATCH_SIZE,
        le=FlextLdifConstants.MAX_BATCH_SIZE,
        description="Batch size for LDIF processing",
    )

    ldif_fail_on_warnings: Annotated[bool, BeforeValidator(_coerce_bool_from_env)] = (
        Field(
            default=FlextLdifConstants.ConfigDefaults.LDIF_FAIL_ON_WARNINGS,
            description="Fail processing on warnings",
        )
    )

    ldif_analytics_sample_rate: Annotated[
        float, BeforeValidator(_coerce_float_from_env)
    ] = Field(
        default=FlextLdifConstants.ConfigDefaults.LDIF_ANALYTICS_SAMPLE_RATE,
        ge=FlextLdifConstants.MIN_SAMPLE_RATE,
        le=FlextLdifConstants.MAX_SAMPLE_RATE,
        description="Analytics sampling rate (0.0 to 1.0)",
    )

    ldif_analytics_max_entries: Annotated[
        int, BeforeValidator(_coerce_int_from_env)
    ] = Field(
        default=FlextLdifConstants.ConfigDefaults.LDIF_ANALYTICS_MAX_ENTRIES,
        ge=FlextLdifConstants.LdifProcessing.MIN_WORKERS,
        le=FlextLdifConstants.MAX_ANALYTICS_ENTRIES_ABSOLUTE,
        description="Maximum entries for analytics processing",
    )

    ldif_default_server_type: str = Field(
        default=FlextLdifConstants.ServerTypes.RFC,
        description="Default server type for LDIF processing",
    )

    ldif_server_specific_quirks: Annotated[
        bool, BeforeValidator(_coerce_bool_from_env)
    ] = Field(
        default=FlextLdifConstants.ConfigDefaults.LDIF_SERVER_SPECIFIC_QUIRKS,
        description="Enable server-specific quirk handling",
    )

    # Validation Configuration using FlextLdifConstants for defaults
    validation_level: Literal["strict", "moderate", "lenient"] = Field(
        default="strict",
        description="Validation strictness level",
    )

    strict_rfc_compliance: Annotated[bool, BeforeValidator(_coerce_bool_from_env)] = (
        Field(
            default=FlextLdifConstants.ConfigDefaults.STRICT_RFC_COMPLIANCE,
            description="Enable strict RFC 2849 compliance",
        )
    )

    # Server Configuration using FlextLdifConstants for defaults
    server_type: Literal[
        "active_directory",
        "openldap",
        "openldap1",
        "openldap2",
        "apache_directory",
        "novell_edirectory",
        "ibm_tivoli",
        "generic",
        "oid",
        "oud",
        "rfc",
    ] = Field(
        default="generic",
        description="Target LDAP server type",
    )

    # Error Handling Configuration
    error_recovery_mode: Literal["continue", "stop", "skip"] = Field(
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

        # Validate debug mode consistency (use inherited self.debug from FlextConfig)
        if (
            self.debug
            and self.max_workers
            > FlextLdifConstants.ValidationRules.MAX_WORKERS_DEBUG_RULE
        ):
            msg = (
                f"Debug mode should use <= "
                f"{FlextLdifConstants.ValidationRules.MAX_WORKERS_DEBUG_RULE} workers "
                f"for better debugging"
            )
            raise ValueError(msg)

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
