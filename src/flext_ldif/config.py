"""Configuration management for LDIF operations.

This module defines configuration settings using Pydantic models with validation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import codecs
from typing import Protocol

from flext_core import FlextConfig, FlextConstants
from pydantic import Field, field_validator, model_validator
from pydantic_settings import SettingsConfigDict

from flext_ldif.constants import FlextLdifConstants


class ValidationInfoProtocol(Protocol):
    """Protocol for Pydantic ValidationInfo to avoid explicit Any issues."""

    @property
    def field_name(self) -> str | None: ...

    @property
    def data(self) -> dict[str, object] | None: ...

    @property
    def mode(self) -> str: ...


@FlextConfig.auto_register("ldif")
class FlextLdifConfig(FlextConfig.AutoConfig):
    """Pydantic v2 configuration for LDIF operations (nested config pattern).

    **ARCHITECTURAL PATTERN**: Zero-Boilerplate Auto-Registration

    This class uses FlextConfig.AutoConfig for automatic:
    - Singleton pattern (thread-safe)
    - Namespace registration (accessible via config.ldif)
    - Test reset capability (_reset_instance)

    **Features**:
    - Pydantic v2 BaseModel for nested configuration
    - Generic LDIF field names (ldif_*) - RFC 2849/4512 compliant
    - Automatic singleton via FlextConfig.AutoConfig
    - Complete type safety and validation
    - Supports both direct instantiation and nested usage

    **Usage**:
        # Get singleton instance
        config = FlextLdifConfig.get_instance()

        # Or via FlextConfig namespace
        from flext_core import FlextConfig
        config = FlextConfig.get_global_instance()
        ldif_config = config.ldif
    """

    # Model configuration (disable str_strip_whitespace for LDIF fields that need whitespace)
    # env_prefix enables automatic loading from FLEXT_LDIF_* environment variables
    model_config = SettingsConfigDict(
        env_prefix="FLEXT_LDIF_",
        env_file=".env",
        env_file_encoding="utf-8",
        str_strip_whitespace=False,
        validate_assignment=True,
        validate_default=True,
        frozen=False,
        arbitrary_types_allowed=True,
        extra="ignore",
    )

    # LDIF Format Configuration using FlextLdifConstants for defaults
    # Note: Fields like max_workers, debug, trace, log_verbosity come from root FlextConfig
    # when used in nested pattern (config.ldif references root config.max_workers)
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

    ldif_server_specifics: bool = Field(
        default=FlextLdifConstants.ConfigDefaults.LDIF_SERVER_SPECIFICS,
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

    # =========================================================================
    # FIELD VALIDATORS - Pydantic v2 Advanced Usage
    # =========================================================================

    @field_validator("ldif_encoding", mode="after")
    @classmethod
    def validate_ldif_encoding(cls, v: str, info: ValidationInfoProtocol) -> str:
        """Validate ldif_encoding is a valid Python codec.

        RFC 2849 § 2: LDIF files SHOULD use UTF-8 encoding.
        This validator ensures the specified encoding is supported by Python.

        Args:
            v: Encoding string to validate
            info: Pydantic ValidationInfo context

        Returns:
            Validated encoding string

        Raises:
            ValueError: If encoding is not supported by Python

        """
        try:
            codecs.lookup(v)
        except LookupError as e:
            # Suggest RFC-recommended encoding
            suggestion = "utf-8 (RFC 2849 recommended)"
            msg = (
                f"Invalid encoding '{v}' in field '{info.field_name}': {e}\n"
                f"Suggestion: Use '{suggestion}' for maximum compatibility."
            )
            raise ValueError(msg) from e
        return v

    @field_validator("server_type", mode="before")
    @classmethod
    def validate_server_type(cls, v: str, info: ValidationInfoProtocol) -> str:
        """Validate server_type is a recognized LDAP server.

        Ensures server_type is one of the supported server types defined in
        FlextLdifConstants.ServerTypes. Accepts both canonical forms and common aliases.

        Args:
            v: Server type string to validate (canonical or alias)
            info: Pydantic ValidationInfo context

        Returns:
            Normalized/validated server type string (canonical form)

        Raises:
            ValueError: If server_type is not recognized

        """
        # Normalize aliases to canonical form (ad → active_directory, etc)
        normalized = FlextLdifConstants.ServerTypes.normalize(v)

        valid_servers = [
            FlextLdifConstants.ServerTypes.RFC,
            FlextLdifConstants.ServerTypes.OID,
            FlextLdifConstants.ServerTypes.OUD,
            FlextLdifConstants.ServerTypes.OPENLDAP,
            FlextLdifConstants.ServerTypes.OPENLDAP1,
            FlextLdifConstants.ServerTypes.OPENLDAP2,
            FlextLdifConstants.ServerTypes.AD,
            FlextLdifConstants.ServerTypes.DS_389,  # Fixed: DS_389 not DS389
            FlextLdifConstants.ServerTypes.APACHE,
            FlextLdifConstants.ServerTypes.NOVELL,
            FlextLdifConstants.ServerTypes.IBM_TIVOLI,  # Fixed: IBM_TIVOLI not TIVOLI
            FlextLdifConstants.ServerTypes.RELAXED,
            FlextLdifConstants.ServerTypes.GENERIC,  # Use constant instead of hardcoded
        ]
        if normalized not in valid_servers:
            # Suggest most common/useful server types
            common_servers = [
                FlextLdifConstants.ServerTypes.RFC,
                FlextLdifConstants.ServerTypes.OUD,
                FlextLdifConstants.ServerTypes.OID,
                FlextLdifConstants.ServerTypes.OPENLDAP,
            ]
            msg = (
                f"Invalid server_type '{v}' in field '{info.field_name}'.\n"
                f"Valid options: {', '.join(valid_servers)}\n"
                f"Common choices: {', '.join(common_servers)}"
            )
            raise ValueError(msg)
        return normalized  # Return normalized form

    @field_validator("ldif_line_separator", mode="after")
    @classmethod
    def validate_ldif_line_separator(cls, v: str, info: ValidationInfoProtocol) -> str:
        """Validate ldif_line_separator is RFC 2849 compliant.

        RFC 2849 § 2: Line separator can be LF, CRLF, or CR.

        Args:
            v: Line separator string to validate
            info: Pydantic ValidationInfo context

        Returns:
            Validated line separator string

        Raises:
            ValueError: If line separator is not RFC compliant

        """
        # RFC 2849 valid line separators
        valid_separators = ["\n", "\r\n", "\r"]
        if v not in valid_separators:
            # Suggest most common separator
            msg = (
                f"Invalid ldif_line_separator '{v!r}' in field '{info.field_name}'.\n"
                f"Must be one of: {', '.join(repr(s) for s in valid_separators)} (RFC 2849 § 2)\n"
                f"Suggestion: Use '\\n' (LF) for Unix/Linux or '\\r\\n' (CRLF) for Windows."
            )
            raise ValueError(msg)
        return v

    @field_validator("ldif_version_string", mode="after")
    @classmethod
    def validate_ldif_version_string(cls, v: str, info: ValidationInfoProtocol) -> str:
        """Validate ldif_version_string is RFC 2849 compliant.

        RFC 2849 § 2: version-spec = "version:" FILL version-number
        Currently only version 1 is defined.

        Args:
            v: Version string to validate
            info: Pydantic ValidationInfo context

        Returns:
            Validated version string

        Raises:
            ValueError: If version string is not RFC 2849 compliant

        """
        # RFC 2849 version format: "version: 1"
        if not v.startswith("version:"):
            msg = (
                f"Invalid ldif_version_string '{v}' in field '{info.field_name}'. "
                f"Must start with 'version:' (RFC 2849 § 2)\n"
                f"Suggestion: Use 'version: 1' (RFC 2849 standard)"
            )
            raise ValueError(msg)

        # Extract version number
        try:
            version_part = v.split(":", 1)[1].strip()
            version_num = int(version_part)
            if version_num != 1:
                msg = (
                    f"Unsupported LDIF version {version_num} in field '{info.field_name}'. "
                    f"Only version 1 is supported (RFC 2849)\n"
                    f"Suggestion: Use 'version: 1'"
                )
                raise ValueError(msg)
        except (IndexError, ValueError) as e:
            msg = (
                f"Invalid ldif_version_string format '{v}' in field '{info.field_name}'. "
                f"Expected 'version: 1' (RFC 2849 § 2)\n"
                f"Suggestion: Use exactly 'version: 1'"
            )
            raise ValueError(msg) from e

        return v

    @field_validator("quirks_server_type", mode="before")
    @classmethod
    def validate_quirks_server_type(
        cls,
        v: str | None,
        info: ValidationInfoProtocol,
    ) -> str | None:
        """Validate quirks_server_type when specified is a recognized server.

        Ensures quirks_server_type (when not None) is one of the supported
        server types defined in FlextLdifConstants.ServerTypes.
        Accepts both canonical forms and common aliases.

        Args:
            v: Server type string to validate (canonical or alias, or None)
            info: Pydantic ValidationInfo context

        Returns:
            Normalized/validated server type string (canonical form) or None

        Raises:
            ValueError: If server_type is specified but not recognized

        """
        if v is None:
            return v

        # Normalize aliases to canonical form (ad → active_directory, etc)
        normalized = FlextLdifConstants.ServerTypes.normalize(v)

        # Use same validation logic as server_type field
        valid_servers = [
            FlextLdifConstants.ServerTypes.RFC,
            FlextLdifConstants.ServerTypes.OID,
            FlextLdifConstants.ServerTypes.OUD,
            FlextLdifConstants.ServerTypes.OPENLDAP,
            FlextLdifConstants.ServerTypes.OPENLDAP1,
            FlextLdifConstants.ServerTypes.OPENLDAP2,
            FlextLdifConstants.ServerTypes.AD,
            FlextLdifConstants.ServerTypes.DS_389,
            FlextLdifConstants.ServerTypes.APACHE,
            FlextLdifConstants.ServerTypes.NOVELL,
            FlextLdifConstants.ServerTypes.IBM_TIVOLI,
            FlextLdifConstants.ServerTypes.RELAXED,
            FlextLdifConstants.ServerTypes.GENERIC,
        ]
        if normalized not in valid_servers:
            common_servers = [
                FlextLdifConstants.ServerTypes.RFC,
                FlextLdifConstants.ServerTypes.OUD,
                FlextLdifConstants.ServerTypes.OID,
                FlextLdifConstants.ServerTypes.OPENLDAP,
            ]
            msg = (
                f"Invalid quirks_server_type '{v}' in field '{info.field_name}'.\n"
                f"Valid options: {', '.join(valid_servers)}\n"
                f"Common choices: {', '.join(common_servers)}"
            )
            raise ValueError(msg)
        return normalized  # Return normalized form

    @field_validator("ldif_default_server_type", mode="after")
    @classmethod
    def validate_ldif_default_server_type(
        cls,
        v: str,
        info: ValidationInfoProtocol,
    ) -> str:
        """Validate ldif_default_server_type is a recognized server.

        Ensures ldif_default_server_type is one of the supported server types.

        Args:
            v: Server type string to validate
            info: Pydantic ValidationInfo context

        Returns:
            Validated server type string

        Raises:
            ValueError: If server_type is not recognized

        """
        # Use same validation logic as server_type field
        valid_servers = [
            FlextLdifConstants.ServerTypes.RFC,
            FlextLdifConstants.ServerTypes.OID,
            FlextLdifConstants.ServerTypes.OUD,
            FlextLdifConstants.ServerTypes.OPENLDAP,
            FlextLdifConstants.ServerTypes.OPENLDAP1,
            FlextLdifConstants.ServerTypes.OPENLDAP2,
            FlextLdifConstants.ServerTypes.AD,
            FlextLdifConstants.ServerTypes.DS_389,
            FlextLdifConstants.ServerTypes.APACHE,
            FlextLdifConstants.ServerTypes.NOVELL,
            FlextLdifConstants.ServerTypes.IBM_TIVOLI,
            FlextLdifConstants.ServerTypes.RELAXED,
            FlextLdifConstants.ServerTypes.GENERIC,
        ]
        if v not in valid_servers:
            msg = (
                f"Invalid ldif_default_server_type '{v}' in field '{info.field_name}'.\n"
                f"Valid options: {', '.join(valid_servers)}\n"
                f"Suggestion: Use '{FlextLdifConstants.ServerTypes.RFC}' for RFC compliance"
            )
            raise ValueError(msg)
        return v

    # =========================================================================
    # MODEL VALIDATOR - Cross-Field Validation
    # =========================================================================

    @model_validator(mode="after")
    def validate_ldif_configuration_consistency(self) -> FlextLdifConfig:
        """Validate LDIF configuration consistency.

        Note: Validations that require root config fields (max_workers, debug, trace)
        should be performed at the root config level (e.g., AlgarOudMigConfig).
        """
        # Validate analytics configuration
        if (
            self.ldif_enable_analytics
            and self.ldif_analytics_cache_size
            <= FlextLdifConstants.ValidationRules.MIN_ANALYTICS_CACHE_RULE - 1
        ):
            msg = "Analytics cache size must be positive when analytics is enabled"
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
        if self.server_type == FlextLdifConstants.ServerTypes.AD:
            return "utf-16" if self.ldif_encoding == "utf-8" else self.ldif_encoding
        return self.ldif_encoding


__all__ = ["FlextLdifConfig"]
