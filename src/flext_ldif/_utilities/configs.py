"""Power Method Configuration Models - Pydantic v2 config models for power methods.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Defines Pydantic v2 configuration models for the FlextLdifUtilities power methods:
    - ProcessConfig: Configuration for process() method
    - TransformConfig: Configuration for transform() method
    - FilterConfig: Configuration for filter() method
    - ValidationConfig: Configuration for validate() method
    - WriteConfig: Configuration for write() method

Python 3.13+ features:
    - PEP 695 type parameter syntax
    - Pydantic v2 model configuration
    - Literal types for enumerations

Usage:
    from flext_ldif._utilities.configs import ProcessConfig

    config = ProcessConfig(
        source_server="oid",
        target_server="oud",
        normalize_dns=True,
    )
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Literal, cast

from pydantic import BaseModel, Field

# =========================================================================
# TYPE ALIASES - Server types and common options
# =========================================================================

type ServerType = Literal[
    "oid",
    "oud",
    "openldap",
    "openldap1",
    "ad",
    "apache",
    "ds389",
    "novell",
    "tivoli",
    "rfc",
    "relaxed",
    "auto",
]
"""Server type literal for LDIF processing."""

type CaseFoldOption = Literal["lower", "upper", "preserve"]
"""Case folding options for DN and attribute normalization."""

type SpaceHandlingOption = Literal["trim", "preserve", "normalize"]
"""Space handling options for DN normalization."""

type EscapeHandlingOption = Literal["minimal", "full"]
"""Escape handling options for DN normalization."""

type ValidationRuleSet = Literal["rfc", "strict", "lenient"]
"""Built-in validation rule sets."""

type OutputFormat = Literal["ldif", "json", "yaml", "csv"]
"""Output format options for write operations."""

type SortOption = Literal["dn", "objectclass", "none"]
"""Sorting options for output."""


# =========================================================================
# DN NORMALIZATION CONFIG
# =========================================================================


class DnNormalizationConfig(BaseModel):
    """Configuration for DN normalization operations.

    Controls how Distinguished Names are normalized during processing.

    Attributes:
        case_fold: Case folding option (lower, upper, preserve)
        space_handling: How to handle spaces (trim, preserve, normalize)
        escape_handling: How to handle escape sequences (minimal, full)
        validate_before: Validate DN before normalization

    """

    case_fold: CaseFoldOption = Field(
        default="lower",
        description="Case folding option for DN components",
    )
    space_handling: SpaceHandlingOption = Field(
        default="trim",
        description="How to handle spaces in DN values",
    )
    escape_handling: EscapeHandlingOption = Field(
        default="minimal",
        description="How to handle escape sequences",
    )
    validate_before: bool = Field(
        default=True,
        description="Validate DN before normalization",
    )

    model_config = {"frozen": True}


# =========================================================================
# ATTRIBUTE NORMALIZATION CONFIG
# =========================================================================


class AttrNormalizationConfig(BaseModel):
    """Configuration for attribute normalization operations.

    Controls how attribute names and values are normalized.

    Attributes:
        case_fold_names: Case fold attribute names
        trim_values: Trim whitespace from attribute values
        normalize_binary: Normalize binary attribute encoding
        remove_empty: Remove empty attribute values

    """

    case_fold_names: bool = Field(
        default=True,
        description="Lowercase attribute names",
    )
    trim_values: bool = Field(
        default=True,
        description="Trim whitespace from values",
    )
    normalize_binary: bool = Field(
        default=True,
        description="Normalize binary value encoding",
    )
    remove_empty: bool = Field(
        default=False,
        description="Remove empty attribute values",
    )

    model_config = {"frozen": True}


# =========================================================================
# ACL CONVERSION CONFIG
# =========================================================================


class AclConversionConfig(BaseModel):
    """Configuration for ACL conversion operations.

    Controls how Access Control Lists are converted between servers.

    Attributes:
        permission_map: Custom permission mappings
        preserve_comments: Keep comments in ACL definitions
        strict_mapping: Fail on unmapped permissions

    """

    permission_map: Mapping[str, str] | None = Field(
        default=None,
        description="Custom permission name mappings",
    )
    preserve_comments: bool = Field(
        default=True,
        description="Preserve comments in ACL definitions",
    )
    strict_mapping: bool = Field(
        default=False,
        description="Fail if permission cannot be mapped",
    )

    model_config = {"frozen": True}


# =========================================================================
# VALIDATION CONFIG
# =========================================================================


class ValidationConfig(BaseModel):
    """Configuration for validation operations.

    Controls how entries and schemas are validated.

    Attributes:
        strict_rfc: Enforce strict RFC 2849/4512 compliance
        collect_all: Collect all errors vs fail on first
        max_errors: Maximum errors to collect (0 = unlimited)
        warn_on_unknown: Warn on unknown attributes

    """

    strict_rfc: bool = Field(
        default=True,
        description="Enforce strict RFC compliance",
    )
    collect_all: bool = Field(
        default=True,
        description="Collect all errors instead of failing on first",
    )
    max_errors: int = Field(
        default=0,
        ge=0,
        description="Maximum errors to collect (0 = unlimited)",
    )
    warn_on_unknown: bool = Field(
        default=True,
        description="Warn on unknown attributes or objectClasses",
    )

    model_config = {"frozen": True}


# =========================================================================
# METADATA CONFIG
# =========================================================================


class MetadataConfig(BaseModel):
    """Configuration for metadata handling.

    Controls how metadata is preserved and tracked during processing.

    Attributes:
        preserve_original: Keep original entry metadata
        track_transformations: Track transformation history
        include_timestamps: Add timestamp metadata
        include_source_info: Include source server info

    """

    preserve_original: bool = Field(
        default=True,
        description="Preserve original entry metadata",
    )
    track_transformations: bool = Field(
        default=True,
        description="Track transformation history in metadata",
    )
    include_timestamps: bool = Field(
        default=False,
        description="Add timestamp to metadata",
    )
    include_source_info: bool = Field(
        default=False,
        description="Include source server info in metadata",
    )

    model_config = {"frozen": True}


# =========================================================================
# PROCESS CONFIG - Main configuration for process()
# =========================================================================


class ProcessConfig(BaseModel):
    """Configuration for FlextLdifUtilities.process() method.

    This is the main configuration object for the universal entry processor.
    It combines all sub-configurations for a complete processing pipeline.

    Attributes:
        source_server: Source server type (or "auto" for detection)
        target_server: Target server type (or None for no conversion)
        dn_config: DN normalization configuration
        attr_config: Attribute normalization configuration
        acl_config: ACL conversion configuration
        validation_config: Validation configuration
        metadata_config: Metadata handling configuration
        normalize_dns: Enable DN normalization
        normalize_attrs: Enable attribute normalization
        convert_acls: Enable ACL conversion
        preserve_metadata: Enable metadata preservation

    Examples:
        >>> config = ProcessConfig(
        ...     source_server="oid",
        ...     target_server="oud",
        ...     normalize_dns=True,
        ... )

    """

    source_server: ServerType = Field(
        default="auto",
        description="Source server type or 'auto' for detection",
    )
    target_server: ServerType | None = Field(
        default=None,
        description="Target server type or None for no conversion",
    )

    # Sub-configurations
    dn_config: DnNormalizationConfig = Field(
        default_factory=DnNormalizationConfig,
        description="DN normalization configuration",
    )
    attr_config: AttrNormalizationConfig = Field(
        default_factory=AttrNormalizationConfig,
        description="Attribute normalization configuration",
    )
    acl_config: AclConversionConfig = Field(
        default_factory=AclConversionConfig,
        description="ACL conversion configuration",
    )
    validation_config: ValidationConfig = Field(
        default_factory=ValidationConfig,
        description="Validation configuration",
    )
    metadata_config: MetadataConfig = Field(
        default_factory=MetadataConfig,
        description="Metadata handling configuration",
    )

    # Quick toggles (override sub-config defaults)
    normalize_dns: bool = Field(
        default=True,
        description="Enable DN normalization",
    )
    normalize_attrs: bool = Field(
        default=True,
        description="Enable attribute normalization",
    )
    convert_acls: bool = Field(
        default=True,
        description="Enable ACL conversion (if target_server set)",
    )
    preserve_metadata: bool = Field(
        default=True,
        description="Enable metadata preservation",
    )

    model_config = {"frozen": True}

    @classmethod
    def builder(cls) -> ProcessConfigBuilder:
        """Create a builder for ProcessConfig.

        Business Rule:
        - Returns builder instance from builders module for fluent configuration
        - Uses lazy import to avoid circular dependency (builders imports configs)
        - Builder pattern enables method chaining for complex configurations

        Returns:
            ProcessConfigBuilder for fluent configuration

        """
        from flext_ldif._utilities.builders import ProcessConfigBuilder as BuilderImpl

        # Cast to satisfy type checker - actual type is BuilderImpl from builders module
        return cast("ProcessConfigBuilder", BuilderImpl())


# =========================================================================
# TRANSFORM CONFIG
# =========================================================================


class TransformConfig(BaseModel):
    """Configuration for FlextLdifUtilities.transform() method.

    Controls transformation pipeline behavior.

    Attributes:
        fail_fast: Stop on first transformation error
        preserve_order: Preserve entry order
        track_changes: Track changes in metadata

    """

    fail_fast: bool = Field(
        default=True,
        description="Stop on first transformation error",
    )
    preserve_order: bool = Field(
        default=True,
        description="Preserve entry order during transformation",
    )
    track_changes: bool = Field(
        default=True,
        description="Track transformation changes in metadata",
    )

    model_config = {"frozen": True}

    @classmethod
    def builder(cls) -> TransformConfigBuilder:
        """Create a builder for TransformConfig.

        Business Rule:
        - Returns builder instance from builders module for fluent configuration
        - Uses lazy import to avoid circular dependency (builders imports configs)
        - Builder pattern enables method chaining for complex configurations

        Returns:
            TransformConfigBuilder for fluent configuration

        """
        from flext_ldif._utilities.builders import TransformConfigBuilder as BuilderImpl

        # Cast to satisfy type checker - actual type is BuilderImpl from builders module
        return cast("TransformConfigBuilder", BuilderImpl())


# =========================================================================
# FILTER CONFIG
# =========================================================================


class FilterConfig(BaseModel):
    """Configuration for FlextLdifUtilities.filter() method.

    Controls filtering behavior.

    Attributes:
        mode: Filter combination mode ("all" = AND, "any" = OR)
        case_sensitive: Case-sensitive matching for patterns
        include_metadata_matches: Include metadata in filter matching

    """

    mode: Literal["all", "any"] = Field(
        default="all",
        description="Filter combination mode (all=AND, any=OR)",
    )
    case_sensitive: bool = Field(
        default=False,
        description="Case-sensitive pattern matching",
    )
    include_metadata_matches: bool = Field(
        default=False,
        description="Include metadata fields in matching",
    )

    model_config = {"frozen": True}

    @classmethod
    def builder(cls) -> FilterConfigBuilder:
        """Create a builder for FilterConfig.

        Business Rule:
        - Returns builder instance from builders module for fluent configuration
        - Uses lazy import to avoid circular dependency (builders imports configs)
        - Builder pattern enables method chaining for complex configurations

        Returns:
            FilterConfigBuilder for fluent configuration

        """
        from flext_ldif._utilities.builders import FilterConfigBuilder as BuilderImpl

        # Cast to satisfy type checker - actual type is BuilderImpl from builders module
        return cast("FilterConfigBuilder", BuilderImpl())


# =========================================================================
# WRITE CONFIG
# =========================================================================


class WriteConfig(BaseModel):
    """Configuration for FlextLdifUtilities.write() method.

    Controls output formatting and behavior.

    Attributes:
        format: Output format (ldif, json, yaml, csv)
        line_width: Maximum line width for LDIF folding
        fold_lines: Enable line folding
        base64_attrs: Attributes to always base64 encode (or "auto")
        sort_by: Sort entries by (dn, objectclass, none)
        attr_order: Preferred attribute order
        include_metadata: Include metadata in output
        server: Target server for server-specific formatting

    """

    format: OutputFormat = Field(
        default="ldif",
        description="Output format",
    )
    line_width: int = Field(
        default=76,
        ge=20,
        le=200,
        description="Maximum line width for folding",
    )
    fold_lines: bool = Field(
        default=True,
        description="Enable line folding",
    )
    base64_attrs: Sequence[str] | Literal["auto"] = Field(
        default="auto",
        description="Attributes to base64 encode",
    )
    sort_by: SortOption = Field(
        default="dn",
        description="Sort entries by field",
    )
    attr_order: Sequence[str] | None = Field(
        default=None,
        description="Preferred attribute order",
    )
    include_metadata: bool = Field(
        default=False,
        description="Include metadata in output",
    )
    server: ServerType | None = Field(
        default=None,
        description="Target server for formatting",
    )

    model_config = {"frozen": True}

    @classmethod
    def builder(cls) -> WriteConfigBuilder:
        """Create a builder for WriteConfig.

        Business Rule:
        - Returns builder instance from builders module for fluent configuration
        - Uses lazy import to avoid circular dependency (builders imports configs)
        - Builder pattern enables method chaining for complex configurations

        Returns:
            WriteConfigBuilder for fluent configuration

        """
        from flext_ldif._utilities.builders import WriteConfigBuilder as BuilderImpl

        # Cast to satisfy type checker - actual type is BuilderImpl from builders module
        return cast("WriteConfigBuilder", BuilderImpl())


# =========================================================================
# LOAD CONFIG
# =========================================================================


class LoadConfig(BaseModel):
    """Configuration for FlextLdifUtilities.load() method.

    Controls LDIF loading behavior.

    Attributes:
        server: Expected server type (or "auto" for detection)
        validate_on_load: Validate entries during loading
        preserve_whitespace: Preserve whitespace in values
        encoding: File encoding

    """

    server: ServerType = Field(
        default="auto",
        description="Expected server type",
    )
    validate_on_load: bool = Field(
        default=False,
        description="Validate entries during loading",
    )
    preserve_whitespace: bool = Field(
        default=False,
        description="Preserve leading/trailing whitespace",
    )
    encoding: str = Field(
        default="utf-8",
        description="File encoding",
    )

    model_config = {"frozen": True}


# =========================================================================
# SCHEMA PARSE CONFIG
# =========================================================================


class SchemaParseConfig(BaseModel):
    """Configuration for FlextLdifUtilities.parse_schema() method.

    Controls schema parsing behavior.

    Attributes:
        server: Expected server type (or "auto" for detection)
        include_elements: Elements to include (attributes, objectclasses, etc.)
        normalize: Normalize parsed elements
        resolve_inheritance: Resolve schema inheritance
        validate_schema: Validate parsed schema

    """

    server: ServerType = Field(
        default="auto",
        description="Expected server type",
    )
    include_elements: (
        Sequence[Literal["attributes", "objectclasses", "syntaxes", "matching_rules"]]
        | None
    ) = Field(
        default=None,
        description="Elements to include (None = all)",
    )
    normalize: bool = Field(
        default=True,
        description="Normalize parsed elements",
    )
    resolve_inheritance: bool = Field(
        default=True,
        description="Resolve schema inheritance",
    )
    validate_schema: bool = Field(
        default=True,
        description="Validate parsed schema",
    )

    model_config = {"frozen": True}


# =========================================================================
# BUILDER FORWARD DECLARATIONS
# =========================================================================


# Forward declarations for builder types (defined in builders.py)
# These are stub classes for type annotations only - actual implementations are in builders.py
# Using string annotations in method signatures to avoid circular import issues
class ProcessConfigBuilder:
    """Builder for ProcessConfig - actual implementation in builders.py."""


class TransformConfigBuilder:
    """Builder for TransformConfig - actual implementation in builders.py."""


class FilterConfigBuilder:
    """Builder for FilterConfig - actual implementation in builders.py."""


class WriteConfigBuilder:
    """Builder for WriteConfig - actual implementation in builders.py."""


__all__ = [
    "AclConversionConfig",
    "AttrNormalizationConfig",
    "CaseFoldOption",
    # Sub-configs
    "DnNormalizationConfig",
    "EscapeHandlingOption",
    "FilterConfig",
    "LoadConfig",
    "MetadataConfig",
    "OutputFormat",
    # Main configs
    "ProcessConfig",
    "SchemaParseConfig",
    # Type aliases
    "ServerType",
    "SortOption",
    "SpaceHandlingOption",
    "TransformConfig",
    "ValidationConfig",
    "ValidationRuleSet",
    "WriteConfig",
]
