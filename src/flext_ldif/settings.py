"""Configuration management for LDIF operations using Pydantic models with validation.

This module manages all configuration aspects for flext-ldif package including
parsing, writing, server detection, and validation settings. Provides
comprehensive LDIF processing configuration with server-specific quirks
handling, format options for parsing and writing, and advanced validation rules.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import codecs
from typing import Self

from pydantic import Field, ValidationInfo, field_validator, model_validator
from pydantic_settings import SettingsConfigDict

from flext import FlextSettings
from flext_ldif._shared import normalize_server_type
from flext_ldif.constants import c


@FlextSettings.auto_register("ldif")
class FlextLdifSettings(FlextSettings):
    """Pydantic v2 configuration for LDIF operations (nested config pattern).

    **ARCHITECTURAL PATTERN**: BaseSettings Configuration

    This class provides:
    - Environment variable support via FLEXT_LDIF_* prefix
    - Namespace registration (accessible via FlextSettings.get_namespace)
    - Pydantic v2 validation and type safety
    - Complete LDIF processing configuration

    **Features**:
    - Pydantic v2 BaseSettings for configuration with env support
    - Generic LDIF field names (ldif_*) - RFC 2849/4512 compliant
    - Complete type safety and validation
    - Supports both direct instantiation and nested usage

    **Usage**:
    # Get direct instance
    config = FlextLdifSettings()

    # Or via FlextSettings namespace
    from flext import FlextSettings
    ldif_config = (
        FlextSettings.get_global_instance()
        .get_namespace("ldif", FlextLdifSettings)
    )
    """

    # Model configuration (disable str_strip_whitespace for LDIF fields
    # that need whitespace)
    # env_prefix enables automatic loading from FLEXT_LDIF_* environment variables
    # Use FlextSettings.resolve_env_file() to ensure all FLEXT configs use same .env
    model_config = SettingsConfigDict(
        env_prefix="FLEXT_LDIF_",
        env_file=FlextSettings.resolve_env_file(),
        env_file_encoding="utf-8",
        str_strip_whitespace=False,
        validate_assignment=True,
        validate_default=True,
        frozen=False,
        arbitrary_types_allowed=True,
        extra="ignore",
    )

    # LDIF Format Configuration using FlextLdifConstants for defaults
    # Note: Fields like max_workers, debug, trace, log_verbosity come from

    ldif_encoding: c.Ldif.LiteralTypes.EncodingLiteral = Field(
        default="utf-8",  # Use literal value instead of constant for
        # type compatibility
        description="Character encoding for LDIF files",
    )

    ldif_max_line_length: int = Field(
        default=c.Ldif.LdifFormatting.MAX_LINE_WIDTH,
        ge=c.Ldif.LdifFormatting.DEFAULT_LINE_WIDTH,
        le=c.Ldif.LdifFormatting.MAX_LINE_WIDTH,
        description="Maximum LDIF line length (RFC 2849 compliance)",
    )

    ldif_skip_comments: bool = Field(
        default=True,
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
        default=10000,
        ge=c.Performance.BatchProcessing.DEFAULT_SIZE,
        le=c.Ldif.LdifProcessing.MAX_ENTRIES_ABSOLUTE,
        description="Maximum number of entries to process",
    )

    ldif_chunk_size: int = Field(
        default=c.DEFAULT_BATCH_SIZE,
        ge=c.Ldif.LdifProcessing.MIN_BATCH_SIZE,
        le=c.Ldif.LdifProcessing.MAX_BATCH_SIZE,
        description="Chunk size for LDIF processing",
    )

    # max_workers inherited from FlextSettings (use self.max_workers)
    # Override to respect debug mode constraints

    # Memory and Performance Configuration - Fix default value
    memory_limit_mb: int = Field(
        default=c.Ldif.LdifProcessing.MIN_MEMORY_MB,
        ge=c.Ldif.LdifProcessing.MIN_MEMORY_MB,
        le=c.Ldif.LdifProcessing.MAX_MEMORY_MB,
        description="Memory limit in MB",
    )

    # Analytics Configuration
    ldif_enable_analytics: bool = Field(
        default=False,
        description="Enable LDIF analytics collection",
    )

    ldif_analytics_cache_size: int = Field(
        default=c.DEFAULT_BATCH_SIZE,
        ge=c.Ldif.LdifProcessing.MIN_ANALYTICS_CACHE_SIZE,
        le=c.Ldif.LdifProcessing.MAX_ANALYTICS_CACHE_SIZE,
        description="Cache size for LDIF analytics",
    )

    analytics_detail_level: c.Ldif.LiteralTypes.AnalyticsDetailLevelLiteral = Field(
        default="medium",
        description="Analytics detail level (low, medium, high)",
    )

    # Additional LDIF processing configuration
    ldif_line_separator: str = Field(
        default="\n",
        description="Line separator for LDIF output",
    )

    ldif_version_string: str = Field(
        default="version: 1",
        description="LDIF version string (RFC 2849 format: 'version: 1')",
    )

    ldif_batch_size: int = Field(
        default=c.DEFAULT_BATCH_SIZE,
        ge=c.Ldif.LdifProcessing.MIN_BATCH_SIZE,
        le=c.Ldif.LdifProcessing.MAX_BATCH_SIZE,
        description="Batch size for LDIF processing",
    )

    ldif_fail_on_warnings: bool = Field(
        default=False,
        description="Fail processing on warnings",
    )

    ldif_analytics_sample_rate: float = Field(
        default=0.1,
        ge=c.Ldif.LdifProcessing.MIN_SAMPLE_RATE,
        le=c.Ldif.LdifProcessing.MAX_SAMPLE_RATE,
        description="Analytics sampling rate (0.0 to 1.0)",
    )

    ldif_analytics_max_entries: int = Field(
        default=1000,
        ge=1,
        le=c.Ldif.LdifProcessing.MAX_ANALYTICS_ENTRIES_ABSOLUTE,
        description="Maximum entries for analytics processing",
    )

    ldif_default_server_type: c.Ldif.LiteralTypes.ServerTypeLiteral = Field(
        default="rfc",  # Use literal value instead of enum for type compatibility
        description="Default server type for LDIF processing",
    )

    ldif_server_specifics: bool = Field(
        default=True,
        description="Enable server-specific quirk handling",
    )

    # Quirks Detection and Mode Configuration
    quirks_detection_mode: c.Ldif.LiteralTypes.DetectionModeLiteral = Field(
        default="auto",
        description=(
            "Quirks detection mode: auto (detect server type), "
            "manual (use quirks_server_type), disabled (RFC only)"
        ),
    )

    quirks_server_type: c.Ldif.LiteralTypes.ServerTypeLiteral | None = Field(
        default=None,
        description=("Override server type for quirks when detection_mode is 'manual'"),
    )

    enable_relaxed_parsing: bool = Field(
        default=False,
        description="Enable relaxed mode for broken/non-compliant LDIF files",
    )

    # Validation Configuration using FlextLdifConstants for defaults
    validation_level: c.Ldif.LiteralTypes.ValidationLevelLiteral = Field(
        default="strict",
        description="Validation strictness level",
    )

    strict_rfc_compliance: bool = Field(
        default=True,
        description="Enable strict RFC 2849 compliance",
    )

    # Server Configuration using FlextLdifConstants for defaults
    server_type: c.Ldif.LiteralTypes.ServerTypeLiteral = Field(
        default="generic",
        description="Target LDAP server type",
    )

    # Error Handling Configuration
    error_recovery_mode: c.Ldif.LiteralTypes.ErrorRecoveryModeLiteral = Field(
        default="continue",
        description="Error recovery mode (continue, stop, skip)",
    )

    # Development and Debug Configuration
    # debug, trace inherited from FlextSettings (use self.debug, self.trace)
    # log_verbosity inherited from FlextSettings
    # (use self.log_verbosity for detailed logging)

    # =========================================================================
    # WRITE FORMAT CONFIGURATION
    # All fields from WriteFormatOptions consolidated here
    # =========================================================================

    ldif_write_respect_attribute_order: bool = Field(
        default=True,
        description=(
            "If True, writes attributes in the order specified in Entry.metadata."
        ),
    )

    ldif_write_sort_attributes: bool = Field(
        default=False,
        description=(
            "If True, sorts attributes alphabetically. "
            "Overridden by respect_attribute_order."
        ),
    )

    ldif_write_hidden_attributes_as_comments: bool = Field(
        default=False,
        description=(
            "If True, attributes marked as 'hidden' in metadata will be "
            "written as comments."
        ),
    )

    ldif_write_metadata_as_comments: bool = Field(
        default=False,
        description=(
            "If True, the entry's main metadata will be written as a commented block."
        ),
    )

    ldif_write_include_version_header: bool = Field(
        default=True,
        description="If True, includes the LDIF version header in output.",
    )

    ldif_write_include_timestamps: bool = Field(
        default=False,
        description=(
            "If True, includes timestamp comments for when entries were written."
        ),
    )

    ldif_write_base64_encode_binary: bool = Field(
        default=False,
        description=("If True, automatically base64 encodes binary attribute values."),
    )

    ldif_write_fold_long_lines: bool = Field(
        default=True,
        description=(
            "If True, folds lines longer than ldif_max_line_length "
            "according to RFC 2849."
        ),
    )

    ldif_write_restore_original_format: bool = Field(
        default=False,
        description=(
            "If True, restores original LDIF format from metadata for "
            "perfect round-trip. Uses "
            "entry.metadata.original_strings['entry_original_ldif'] to "
            "preserve all minimal differences (spacing, case, punctuation, "
            "quotes, etc.). CRITICAL for zero data loss."
        ),
    )

    ldif_write_empty_values: bool = Field(
        default=True,
        description=(
            "If True, writes attributes with empty values. If False, omits them."
        ),
    )

    ldif_write_normalize_attribute_names: bool = Field(
        default=False,
        description="If True, normalizes attribute names to lowercase.",
    )

    ldif_write_include_dn_comments: bool = Field(
        default=False,
        description=("If True, includes DN explanation comments for complex entries."),
    )

    ldif_write_removed_attributes_as_comments: bool = Field(
        default=False,
        description=("If True, writes removed attributes as comments in LDIF output."),
    )

    ldif_write_migration_header: bool = Field(
        default=False,
        description=(
            "If True, writes migration metadata header at the start of LDIF file."
        ),
    )

    ldif_write_migration_header_template: str | None = Field(
        default=None,
        description=(
            "Jinja2 template string for migration header. "
            "If None, uses default template."
        ),
    )

    ldif_write_rejection_reasons: bool = Field(
        default=False,
        description=(
            "If True, writes rejection reasons as comments for rejected entries."
        ),
    )

    ldif_write_transformation_comments: bool = Field(
        default=False,
        description=(
            "If True, writes transformation details as comments "
            "(e.g., objectClass changes). "
            "Tags: [REMOVED], [RENAMED], [TRANSFORMED]."
        ),
    )

    ldif_write_include_removal_statistics: bool = Field(
        default=False,
        description=(
            "If True, includes statistics about removed attributes in headers."
        ),
    )

    ldif_write_changetype: c.Ldif.LiteralTypes.ChangeTypeLiteral | None = Field(
        default=None,
        description=(
            "If set to 'modify', writes entries in LDIF modify format "
            "(changetype: modify). Otherwise uses add format."
        ),
    )

    ldif_write_modify_operation: c.Ldif.LiteralTypes.ModifyOperationLiteral = Field(
        default="add",
        description=(
            "LDIF modify operation: 'add' or 'replace'. "
            "Used when ldif_changetype='modify'. "
            "Default 'add' for schema/ACL phases."
        ),
    )

    ldif_write_original_entry_as_comment: bool = Field(
        default=False,
        description=(
            "If True, writes original source entry as commented LDIF block "
            "before converted entry."
        ),
    )

    ldif_write_entry_category: c.Ldif.LiteralTypes.CategoryLiteral | None = Field(
        default=None,
        description=(
            "Migration category (e.g., 'hierarchy', 'users', 'groups', "
            "'acl'). Used for phase-specific formatting."
        ),
    )

    ldif_write_acl_attribute_names: frozenset[str] = Field(
        default_factory=frozenset,
        description=(
            "Set of ACL attribute names (e.g., {'orclaci', "
            "'orclentrylevelaci'}). Used to identify ACL attributes."
        ),
    )

    ldif_write_comment_acl_in_non_acl_phases: bool = Field(
        default=True,
        description=(
            "If True, ACL attributes are written as comments when "
            "entry_category != 'acl'."
        ),
    )

    ldif_write_use_rfc_attribute_order: bool = Field(
        default=False,
        description=(
            "If True, writes attributes in RFC 2849 order: objectClass "
            "first after DN, then remaining attributes alphabetically. "
            "DN is always first (handled automatically by writer)."
        ),
    )

    ldif_write_rfc_order_priority_attributes: list[str] = Field(
        default_factory=lambda: ["objectClass"],
        description=(
            "Attributes to write first after DN, in order. "
            "Default: ['objectClass']. "
            "Remaining attributes sorted alphabetically."
        ),
    )

    # =========================================================================
    # PARSE FORMAT CONFIGURATION
    # All fields from ParseFormatOptions consolidated here
    # =========================================================================

    ldif_parse_auto_parse_schema: bool = Field(
        default=True,
        description=("If True, automatically parses schema definitions from entries."),
    )

    ldif_parse_auto_extract_acls: bool = Field(
        default=True,
        description="If True, automatically extracts ACLs from entry attributes.",
    )

    ldif_parse_preserve_attribute_order: bool = Field(
        default=False,
        description=(
            "If True, preserves the original attribute order from the LDIF "
            "file in Entry.metadata."
        ),
    )

    ldif_parse_validate_entries: bool = Field(
        default=True,
        description="If True, validates entries against LDAP schema rules.",
    )

    ldif_parse_normalize_dns: bool = Field(
        default=True,
        description="If True, normalizes DN formatting to RFC 2253 standard.",
    )

    ldif_parse_max_parse_errors: int = Field(
        default=100,
        ge=0,
        le=10000,
        description=(
            "Maximum number of parsing errors to collect before stopping. "
            "0 means no limit."
        ),
    )

    ldif_parse_include_operational_attrs: bool = Field(
        default=False,
        description="If True, includes operational attributes in parsed entries.",
    )

    ldif_parse_strict_schema_validation: bool = Field(
        default=False,
        description=(
            "If True, applies strict schema validation and fails on violations."
        ),
    )

    # =========================================================================
    # FIELD VALIDATORS - Pydantic v2 Advanced Usage
    # =========================================================================

    @field_validator("ldif_encoding", mode="after")
    @classmethod
    def validate_ldif_encoding(
        cls,
        v: str,
        info: ValidationInfo,
    ) -> str:
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
            _ = codecs.lookup(v)
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
    def validate_server_type(
        cls,
        v: str,
        info: ValidationInfo,
    ) -> str:
        """Validate server_type is a recognized LDAP server.

        Ensures server_type is one of the supported server types defined in
        c.Ldif.ServerTypes. Accepts both canonical forms and
        common aliases.

        Args:
            v: Server type string to validate (canonical or alias)
            info: Pydantic ValidationInfo context

        Returns:
            Normalized/validated server type string (canonical form)

        Raises:
            ValueError: If server_type is not recognized

        """
        normalized = normalize_server_type(v)

        valid_servers = [
            c.Ldif.ServerTypes.RFC,
            c.Ldif.ServerTypes.OID,
            c.Ldif.ServerTypes.OUD,
            c.Ldif.ServerTypes.OPENLDAP,
            c.Ldif.ServerTypes.OPENLDAP1,
            c.Ldif.ServerTypes.OPENLDAP2,
            c.Ldif.ServerTypes.AD,
            c.Ldif.ServerTypes.DS389,
            c.Ldif.ServerTypes.APACHE,
            c.Ldif.ServerTypes.NOVELL,
            c.Ldif.ServerTypes.IBM_TIVOLI,
            # Fixed: IBM_TIVOLI not TIVOLI
            c.Ldif.ServerTypes.RELAXED,
            c.Ldif.ServerTypes.GENERIC,
            # Use constant instead of hardcoded
        ]
        if normalized not in valid_servers:
            # Suggest most common/useful server types
            common_servers = [
                c.Ldif.ServerTypes.RFC,
                c.Ldif.ServerTypes.OUD,
                c.Ldif.ServerTypes.OID,
                c.Ldif.ServerTypes.OPENLDAP,
            ]
            msg = (
                f"Invalid server_type '{v}' in field '{info.field_name or 'unknown'}'.\n"
                f"Valid options: {', '.join(valid_servers)}\n"
                f"Common choices: {', '.join(common_servers)}"
            )
            raise ValueError(msg)
        return normalized  # Return normalized form

    @field_validator("ldif_line_separator", mode="after")
    @classmethod
    def validate_ldif_line_separator(
        cls,
        v: str,
        info: ValidationInfo,
    ) -> str:
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
                f"Invalid ldif_line_separator '{v!r}' in field "
                f"'{info.field_name}'.\n"
                f"Must be one of: {', '.join(repr(s) for s in valid_separators)} "
                f"(RFC 2849 § 2)\n"
                f"Suggestion: Use '\\n' (LF) for Unix/Linux or "
                f"'\\r\\n' (CRLF) for Windows."
            )
            raise ValueError(msg)
        return v

    @field_validator("ldif_version_string", mode="after")
    @classmethod
    def validate_ldif_version_string(
        cls,
        v: str,
        info: ValidationInfo,
    ) -> str:
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
                f"Invalid ldif_version_string '{v}' in field "
                f"'{info.field_name}'. "
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
                    f"Unsupported LDIF version {version_num} in field "
                    f"'{info.field_name}'. "
                    f"Only version 1 is supported (RFC 2849)\n"
                    f"Suggestion: Use 'version: 1'"
                )
                raise ValueError(msg)
        except (IndexError, ValueError) as e:
            msg = (
                f"Invalid ldif_version_string format '{v}' in field "
                f"'{info.field_name}'. "
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
        info: ValidationInfo,
    ) -> str | None:
        """Validate quirks_server_type when specified is a recognized server.

        Ensures quirks_server_type (when not None) is one of the supported
        server types defined in c.Ldif.ServerTypes.
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

        normalized = normalize_server_type(v)

        # Use same validation logic as server_type field
        valid_servers = [
            c.Ldif.ServerTypes.RFC,
            c.Ldif.ServerTypes.OID,
            c.Ldif.ServerTypes.OUD,
            c.Ldif.ServerTypes.OPENLDAP,
            c.Ldif.ServerTypes.OPENLDAP1,
            c.Ldif.ServerTypes.OPENLDAP2,
            c.Ldif.ServerTypes.AD,
            c.Ldif.ServerTypes.DS389,
            c.Ldif.ServerTypes.APACHE,
            c.Ldif.ServerTypes.NOVELL,
            c.Ldif.ServerTypes.IBM_TIVOLI,
            c.Ldif.ServerTypes.RELAXED,
            c.Ldif.ServerTypes.GENERIC,
        ]
        if normalized not in valid_servers:
            common_servers = [
                c.Ldif.ServerTypes.RFC,
                c.Ldif.ServerTypes.OUD,
                c.Ldif.ServerTypes.OID,
                c.Ldif.ServerTypes.OPENLDAP,
            ]
            msg = (
                f"Invalid quirks_server_type '{v}' in field '{info.field_name or 'unknown'}'.\n"
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
        info: ValidationInfo,
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
            c.Ldif.ServerTypes.RFC,
            c.Ldif.ServerTypes.OID,
            c.Ldif.ServerTypes.OUD,
            c.Ldif.ServerTypes.OPENLDAP,
            c.Ldif.ServerTypes.OPENLDAP1,
            c.Ldif.ServerTypes.OPENLDAP2,
            c.Ldif.ServerTypes.AD,
            c.Ldif.ServerTypes.DS389,
            c.Ldif.ServerTypes.APACHE,
            c.Ldif.ServerTypes.NOVELL,
            c.Ldif.ServerTypes.IBM_TIVOLI,
            c.Ldif.ServerTypes.RELAXED,
            c.Ldif.ServerTypes.GENERIC,
        ]
        if v not in valid_servers:
            msg = (
                f"Invalid ldif_default_server_type '{v}' in field "
                f"'{info.field_name}'.\n"
                f"Valid options: {', '.join(valid_servers)}\n"
                f"Suggestion: Use '{c.Ldif.ServerTypes.RFC}' "
                f"for RFC compliance"
            )
            raise ValueError(msg)
        return v

    # =========================================================================
    # MODEL VALIDATOR - Cross-Field Validation
    # =========================================================================

    @model_validator(mode="after")
    def validate_ldif_configuration_consistency(self) -> Self:
        """Validate LDIF configuration consistency.

            Note: Validations that require root config fields
            (max_workers, debug, trace)
        should be performed at the root config level (e.g., client-aOudMigSettings).
        """
        # Validate analytics configuration
        if (
            self.ldif_enable_analytics
            and self.ldif_analytics_cache_size
            <= c.Ldif.ValidationRules.MIN_ANALYTICS_CACHE_RULE - 1
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
    # UTILITY METHODS - Enhanced with FlextSettings integration
    # =========================================================================

    def get_effective_encoding(self) -> str:
        """Get effective encoding, considering environment and server type.

        Returns:
        Effective character encoding to use

        """
        # Server-specific encoding preferences
        if self.server_type == c.Ldif.ServerTypes.AD.value:
            return "utf-16" if self.ldif_encoding == "utf-8" else self.ldif_encoding
        return self.ldif_encoding

    # =========================================================================
    # PUBLIC API - Direct access to models (no wrappers)
    # =========================================================================
    # WriteFormatOptions is deprecated - use FlextLdifSettings fields (ldif_write_*)
    # Direct access via FlextLdifModelsSettings.WriteFormatOptions when needed


__all__ = ["FlextLdifSettings"]
