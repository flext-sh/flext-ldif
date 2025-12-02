"""Power Method Builders - Fluent builders for configuration objects.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides fluent builder classes for constructing configuration objects:
    - ProcessConfigBuilder: Build ProcessConfig with method chaining
    - TransformConfigBuilder: Build TransformConfig with method chaining
    - FilterConfigBuilder: Build FilterConfig with method chaining
    - WriteConfigBuilder: Build WriteConfig with method chaining

Python 3.13+ features:
    - Self type for method chaining
    - PEP 695 type parameter syntax
    - Keyword-only arguments

Usage:
    from flext_ldif._utilities.builders import ProcessConfigBuilder

    config = (
        ProcessConfigBuilder()
        .source("oid")
        .target("oud")
        .normalize_dn(case="lower", spaces="trim")
        .preserve_metadata(original=True, tracking=True)
        .build()
    )
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Literal, Self

from flext_ldif._utilities.configs import (
    AclConversionConfig,
    AttrNormalizationConfig,
    CaseFoldOption,
    DnNormalizationConfig,
    EscapeHandlingOption,
    FilterConfig,
    MetadataConfig,
    OutputFormat,
    ProcessConfig,
    ServerType,
    SortOption,
    SpaceHandlingOption,
    TransformConfig,
    ValidationConfig,
    WriteConfig,
)

# =========================================================================
# PROCESS CONFIG BUILDER
# =========================================================================


class ProcessConfigBuilder:
    """Fluent builder for ProcessConfig.

    Provides a fluent interface for constructing ProcessConfig objects
    with method chaining. Each method returns Self for chaining,
    and build() returns the final ProcessConfig.

    Examples:
        >>> config = (
        ...     ProcessConfigBuilder()
        ...     .source("oid")
        ...     .target("oud")
        ...     .normalize_dn(case="lower", spaces="trim")
        ...     .preserve_metadata(original=True, tracking=True)
        ...     .validation(strict_rfc=True)
        ...     .build()
        ... )

    """

    __slots__ = (
        "_acl_config",
        "_attr_config",
        "_convert_acls",
        "_dn_config",
        "_metadata_config",
        "_normalize_attrs",
        "_normalize_dns",
        "_preserve_metadata",
        "_source_server",
        "_target_server",
        "_validation_config",
    )

    def __init__(self) -> None:
        """Initialize builder with default values."""
        self._source_server: ServerType = "auto"
        self._target_server: ServerType | None = None
        self._dn_config: DnNormalizationConfig | None = None
        self._attr_config: AttrNormalizationConfig | None = None
        self._acl_config: AclConversionConfig | None = None
        self._validation_config: ValidationConfig | None = None
        self._metadata_config: MetadataConfig | None = None
        self._normalize_dns: bool = True
        self._normalize_attrs: bool = True
        self._convert_acls: bool = True
        self._preserve_metadata: bool = True

    def source(self, server: ServerType) -> Self:
        """Set the source server type.

        Args:
            server: Source server type (e.g., "oid", "oud", "openldap")

        Returns:
            Self for method chaining

        """
        self._source_server = server
        return self

    def target(self, server: ServerType) -> Self:
        """Set the target server type.

        Args:
            server: Target server type for conversion

        Returns:
            Self for method chaining

        """
        self._target_server = server
        return self

    def normalize_dn(
        self,
        *,
        case: CaseFoldOption = "lower",
        spaces: SpaceHandlingOption = "trim",
        escapes: EscapeHandlingOption = "minimal",
        validate: bool = True,
    ) -> Self:
        """Configure DN normalization.

        Args:
            case: Case folding option (lower, upper, preserve)
            spaces: Space handling (trim, preserve, normalize)
            escapes: Escape handling (minimal, full)
            validate: Validate DN before normalization

        Returns:
            Self for method chaining

        """
        self._dn_config = DnNormalizationConfig(
            case_fold=case,
            space_handling=spaces,
            escape_handling=escapes,
            validate_before=validate,
        )
        return self

    def normalize_attrs(
        self,
        *,
        case_fold_names: bool = True,
        trim_values: bool = True,
        normalize_binary: bool = True,
        remove_empty: bool = False,
    ) -> Self:
        """Configure attribute normalization.

        Args:
            case_fold_names: Lowercase attribute names
            trim_values: Trim whitespace from values
            normalize_binary: Normalize binary encoding
            remove_empty: Remove empty values

        Returns:
            Self for method chaining

        """
        self._attr_config = AttrNormalizationConfig(
            case_fold_names=case_fold_names,
            trim_values=trim_values,
            normalize_binary=normalize_binary,
            remove_empty=remove_empty,
        )
        return self

    def acl_mapping(
        self,
        *,
        permission_map: Mapping[str, str] | None = None,
        preserve_comments: bool = True,
        strict: bool = False,
    ) -> Self:
        """Configure ACL conversion.

        Args:
            permission_map: Custom permission mappings
            preserve_comments: Keep comments in ACLs
            strict: Fail on unmapped permissions

        Returns:
            Self for method chaining

        """
        self._acl_config = AclConversionConfig(
            permission_map=permission_map,
            preserve_comments=preserve_comments,
            strict_mapping=strict,
        )
        return self

    def validation(
        self,
        *,
        strict_rfc: bool = True,
        collect_all: bool = True,
        max_errors: int = 0,
        warn_on_unknown: bool = True,
    ) -> Self:
        """Configure validation behavior.

        Args:
            strict_rfc: Enforce strict RFC compliance
            collect_all: Collect all errors
            max_errors: Maximum errors (0 = unlimited)
            warn_on_unknown: Warn on unknown attributes

        Returns:
            Self for method chaining

        """
        self._validation_config = ValidationConfig(
            strict_rfc=strict_rfc,
            collect_all=collect_all,
            max_errors=max_errors,
            warn_on_unknown=warn_on_unknown,
        )
        return self

    def preserve_metadata(
        self,
        *,
        original: bool = True,
        tracking: bool = True,
        timestamps: bool = False,
        source_info: bool = False,
    ) -> Self:
        """Configure metadata handling.

        Args:
            original: Preserve original metadata
            tracking: Track transformations
            timestamps: Add timestamps
            source_info: Include source server info

        Returns:
            Self for method chaining

        """
        self._metadata_config = MetadataConfig(
            preserve_original=original,
            track_transformations=tracking,
            include_timestamps=timestamps,
            include_source_info=source_info,
        )
        return self

    def enable_dn_normalization(self, enabled: bool = True) -> Self:
        """Enable or disable DN normalization.

        Args:
            enabled: Whether to normalize DNs

        Returns:
            Self for method chaining

        """
        self._normalize_dns = enabled
        return self

    def enable_attr_normalization(self, enabled: bool = True) -> Self:
        """Enable or disable attribute normalization.

        Args:
            enabled: Whether to normalize attributes

        Returns:
            Self for method chaining

        """
        self._normalize_attrs = enabled
        return self

    def enable_acl_conversion(self, enabled: bool = True) -> Self:
        """Enable or disable ACL conversion.

        Args:
            enabled: Whether to convert ACLs

        Returns:
            Self for method chaining

        """
        self._convert_acls = enabled
        return self

    def build(self) -> ProcessConfig:
        """Build the ProcessConfig.

        Returns:
            Configured ProcessConfig instance

        """
        return ProcessConfig(
            source_server=self._source_server,
            target_server=self._target_server,
            dn_config=self._dn_config or DnNormalizationConfig(),
            attr_config=self._attr_config or AttrNormalizationConfig(),
            acl_config=self._acl_config or AclConversionConfig(),
            validation_config=self._validation_config or ValidationConfig(),
            metadata_config=self._metadata_config or MetadataConfig(),
            normalize_dns=self._normalize_dns,
            normalize_attrs=self._normalize_attrs,
            convert_acls=self._convert_acls,
            preserve_metadata=self._preserve_metadata,
        )


# =========================================================================
# TRANSFORM CONFIG BUILDER
# =========================================================================


class TransformConfigBuilder:
    """Fluent builder for TransformConfig.

    Examples:
        >>> config = (
        ...     TransformConfigBuilder()
        ...     .fail_fast(True)
        ...     .preserve_order(True)
        ...     .track_changes(True)
        ...     .build()
        ... )

    """

    __slots__ = ("_fail_fast", "_preserve_order", "_track_changes")

    def __init__(self) -> None:
        """Initialize builder with default values."""
        self._fail_fast: bool = True
        self._preserve_order: bool = True
        self._track_changes: bool = True

    def fail_fast(self, enabled: bool = True) -> Self:
        """Set fail-fast behavior.

        Args:
            enabled: Stop on first error

        Returns:
            Self for method chaining

        """
        self._fail_fast = enabled
        return self

    def preserve_order(self, enabled: bool = True) -> Self:
        """Set order preservation.

        Args:
            enabled: Preserve entry order

        Returns:
            Self for method chaining

        """
        self._preserve_order = enabled
        return self

    def track_changes(self, enabled: bool = True) -> Self:
        """Set change tracking.

        Args:
            enabled: Track changes in metadata

        Returns:
            Self for method chaining

        """
        self._track_changes = enabled
        return self

    def build(self) -> TransformConfig:
        """Build the TransformConfig.

        Returns:
            Configured TransformConfig instance

        """
        return TransformConfig(
            fail_fast=self._fail_fast,
            preserve_order=self._preserve_order,
            track_changes=self._track_changes,
        )


# =========================================================================
# FILTER CONFIG BUILDER
# =========================================================================


class FilterConfigBuilder:
    """Fluent builder for FilterConfig.

    Examples:
        >>> config = FilterConfigBuilder().mode("all").case_sensitive(False).build()

    """

    __slots__ = ("_case_sensitive", "_include_metadata_matches", "_mode")

    def __init__(self) -> None:
        """Initialize builder with default values."""
        self._mode: Literal["all", "any"] = "all"
        self._case_sensitive: bool = False
        self._include_metadata_matches: bool = False

    def mode(self, mode: Literal["all", "any"]) -> Self:
        """Set filter combination mode.

        Args:
            mode: "all" for AND, "any" for OR

        Returns:
            Self for method chaining

        """
        self._mode = mode
        return self

    def case_sensitive(self, enabled: bool = True) -> Self:
        """Set case sensitivity.

        Args:
            enabled: Case-sensitive matching

        Returns:
            Self for method chaining

        """
        self._case_sensitive = enabled
        return self

    def include_metadata_matches(self, enabled: bool = True) -> Self:
        """Include metadata in matching.

        Args:
            enabled: Match against metadata fields

        Returns:
            Self for method chaining

        """
        self._include_metadata_matches = enabled
        return self

    def build(self) -> FilterConfig:
        """Build the FilterConfig.

        Returns:
            Configured FilterConfig instance

        """
        return FilterConfig(
            mode=self._mode,
            case_sensitive=self._case_sensitive,
            include_metadata_matches=self._include_metadata_matches,
        )


# =========================================================================
# WRITE CONFIG BUILDER
# =========================================================================


class WriteConfigBuilder:
    """Fluent builder for WriteConfig.

    Examples:
        >>> config = (
        ...     WriteConfigBuilder()
        ...     .format("ldif")
        ...     .line_width(76)
        ...     .sort_by("dn")
        ...     .attr_order(["dn", "objectClass", "cn"])
        ...     .build()
        ... )

    """

    __slots__ = (
        "_attr_order",
        "_base64_attrs",
        "_fold_lines",
        "_format",
        "_include_metadata",
        "_line_width",
        "_server",
        "_sort_by",
    )

    def __init__(self) -> None:
        """Initialize builder with default values."""
        self._format: OutputFormat = "ldif"
        self._line_width: int = 76
        self._fold_lines: bool = True
        self._base64_attrs: Sequence[str] | Literal["auto"] = "auto"
        self._sort_by: SortOption = "dn"
        self._attr_order: Sequence[str] | None = None
        self._include_metadata: bool = False
        self._server: ServerType | None = None

    def format(self, fmt: OutputFormat) -> Self:
        """Set output format.

        Args:
            fmt: Output format (ldif, json, yaml, csv)

        Returns:
            Self for method chaining

        """
        self._format = fmt
        return self

    def line_width(self, width: int) -> Self:
        """Set line width for folding.

        Args:
            width: Maximum line width

        Returns:
            Self for method chaining

        """
        self._line_width = width
        return self

    def fold_lines(self, enabled: bool = True) -> Self:
        """Enable or disable line folding.

        Args:
            enabled: Whether to fold long lines

        Returns:
            Self for method chaining

        """
        self._fold_lines = enabled
        return self

    def base64_attrs(self, attrs: Sequence[str] | Literal["auto"]) -> Self:
        """Set attributes to base64 encode.

        Args:
            attrs: Attribute names or "auto"

        Returns:
            Self for method chaining

        """
        self._base64_attrs = attrs
        return self

    def sort_by(self, field: SortOption) -> Self:
        """Set sorting field.

        Args:
            field: Sort by (dn, objectclass, none)

        Returns:
            Self for method chaining

        """
        self._sort_by = field
        return self

    def attr_order(self, order: Sequence[str]) -> Self:
        """Set preferred attribute order.

        Args:
            order: Attribute names in preferred order

        Returns:
            Self for method chaining

        """
        self._attr_order = order
        return self

    def include_metadata(self, enabled: bool = True) -> Self:
        """Include metadata in output.

        Args:
            enabled: Whether to include metadata

        Returns:
            Self for method chaining

        """
        self._include_metadata = enabled
        return self

    def server(self, server: ServerType) -> Self:
        """Set target server for formatting.

        Args:
            server: Target server type

        Returns:
            Self for method chaining

        """
        self._server = server
        return self

    def build(self) -> WriteConfig:
        """Build the WriteConfig.

        Returns:
            Configured WriteConfig instance

        """
        return WriteConfig(
            format=self._format,
            line_width=self._line_width,
            fold_lines=self._fold_lines,
            base64_attrs=self._base64_attrs,
            sort_by=self._sort_by,
            attr_order=self._attr_order,
            include_metadata=self._include_metadata,
            server=self._server,
        )


__all__ = [
    "FilterConfigBuilder",
    "ProcessConfigBuilder",
    "TransformConfigBuilder",
    "WriteConfigBuilder",
]
