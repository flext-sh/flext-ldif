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

from collections.abc import Sequence
from typing import Literal, Self

from flext_ldif.models import m

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
        self._source_server: m.Ldif.Config.ServerType = m.Ldif.Config.ServerType.AUTO
        self._target_server: m.Ldif.Config.ServerType | None = None
        self._dn_config: m.Ldif.Config.DnNormalizationConfig | None = None
        self._attr_config: m.Ldif.Config.AttrNormalizationConfig | None = None
        self._acl_config: m.Ldif.Config.AclConversionConfig | None = None
        self._validation_config: m.Ldif.Config.ValidationConfig | None = None
        self._metadata_config: m.Ldif.Config.MetadataConfig | None = None

    def source(self, server: m.Ldif.Config.ServerType) -> Self:
        """Set the source server type.

        Args:
            server: Source server type (e.g., "oid", "oud", "openldap")

        Returns:
            Self for method chaining

        """
        self._source_server = server
        return self

    def target(self, server: m.Ldif.Config.ServerType) -> Self:
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
        case: m.Ldif.Config.CaseFoldOption | None = None,
        spaces: m.Ldif.Config.SpaceHandlingOption | None = None,
        escapes: m.Ldif.Config.EscapeHandlingOption | None = None,
    ) -> Self:
        """Configure DN normalization.

        Args:
            case: Case folding option (lower, upper, preserve)
            spaces: Space handling (trim, preserve, normalize)
            escapes: Escape handling (preserve, unescape, normalize)

        Returns:
            Self for method chaining

        """
        # Pydantic 2: Create config and update attributes directly
        # FlextModels.Config doesn't have model_copy, so we update attributes
        self._dn_config = m.Ldif.Config.DnNormalizationConfig()
        if case is not None:
            self._dn_config.case_fold = str(case)  # Convert StrEnum to str for Literal compatibility
        if spaces is not None:
            self._dn_config.space_handling = str(spaces)  # Convert StrEnum to str for Literal compatibility
        if escapes is not None:
            self._dn_config.escape_handling = str(escapes)  # Convert StrEnum to str for Literal compatibility
        return self

    def normalize_attrs(
        self,
        *,
        sort_attributes: m.Ldif.Config.SortOption | None = None,
        sort_values: bool = True,
        normalize_whitespace: bool = True,
    ) -> Self:
        """Configure attribute normalization.

        Args:
            sort_attributes: How to sort attributes (alphabetical, hierarchical, none)
            sort_values: Sort attribute values
            normalize_whitespace: Normalize whitespace in values

        Returns:
            Self for method chaining

        """
        # Pydantic 2: Create config and update attributes directly
        self._attr_config = m.Ldif.Config.AttrNormalizationConfig()
        if sort_attributes is not None:
            self._attr_config.sort_attributes = sort_attributes
        self._attr_config.sort_values = sort_values
        self._attr_config.normalize_whitespace = normalize_whitespace
        return self

    def acl_conversion(
        self,
        *,
        convert_aci: bool = True,
        preserve_original_aci: bool = False,
        map_server_specific: bool = True,
    ) -> Self:
        """Configure ACL conversion.

        Args:
            convert_aci: Enable ACL conversion
            preserve_original_aci: Preserve original ACL in metadata
            map_server_specific: Map server-specific ACLs

        Returns:
            Self for method chaining

        """
        # Pydantic 2: Create config and update attributes directly
        self._acl_config = m.Ldif.Config.AclConversionConfig()
        self._acl_config.convert_aci = convert_aci
        self._acl_config.preserve_original_aci = preserve_original_aci
        self._acl_config.map_server_specific = map_server_specific
        return self

    def validation(
        self,
        *,
        strict_rfc: bool = False,
        allow_server_quirks: bool = True,
        validate_dn_format: bool = True,
    ) -> Self:
        """Configure validation behavior.

        Args:
            strict_rfc: Enforce strict RFC 2849 compliance
            allow_server_quirks: Allow server-specific quirks in validation
            validate_dn_format: Validate DN format

        Returns:
            Self for method chaining

        """
        # Pydantic 2: Create config and update attributes directly
        self._validation_config = m.Ldif.Config.ValidationConfig()
        self._validation_config.strict_rfc = strict_rfc
        self._validation_config.allow_server_quirks = allow_server_quirks
        self._validation_config.validate_dn_format = validate_dn_format
        return self

    def preserve_metadata(
        self,
        *,
        preserve_original: bool = True,
        preserve_tracking: bool = True,
        preserve_validation: bool = False,
    ) -> Self:
        """Configure metadata handling.

        Args:
            preserve_original: Preserve original metadata
            preserve_tracking: Preserve transformation tracking
            preserve_validation: Preserve validation results

        Returns:
            Self for method chaining

        """
        # Pydantic 2: Create config and update attributes directly
        self._metadata_config = m.Ldif.Config.MetadataConfig()
        self._metadata_config.preserve_original = preserve_original
        self._metadata_config.preserve_tracking = preserve_tracking
        self._metadata_config.preserve_validation = preserve_validation
        return self

    def enable_dn_normalization(self, *, enabled: bool = True) -> Self:
        """Enable or disable DN normalization.

        Args:
            enabled: Whether to normalize DNs

        Returns:
            Self for method chaining

        """
        self._normalize_dns = enabled
        return self

    def enable_attr_normalization(self, *, enabled: bool = True) -> Self:
        """Enable or disable attribute normalization.

        Args:
            enabled: Whether to normalize attributes

        Returns:
            Self for method chaining

        """
        self._normalize_attrs = enabled
        return self

    def enable_acl_conversion(self, *, enabled: bool = True) -> Self:
        """Enable or disable ACL conversion.

        Args:
            enabled: Whether to convert ACLs

        Returns:
            Self for method chaining

        """
        self._convert_acls = enabled
        return self

    def build(self) -> m.Ldif.Config.ProcessConfig:
        """Build the ProcessConfig.

        Returns:
            Configured ProcessConfig instance

        """
        # Pydantic 2: Create config and update attributes directly
        config = m.Ldif.Config.ProcessConfig()
        config.source_server = self._source_server
        config.target_server = self._target_server or "rfc"
        config.dn_config = self._dn_config
        config.attr_config = self._attr_config
        config.acl_config = self._acl_config
        config.validation_config = self._validation_config
        config.metadata_config = self._metadata_config
        return config


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

    def fail_fast(self, *, enabled: bool = True) -> Self:
        """Set fail-fast behavior.

        Args:
            enabled: Stop on first error

        Returns:
            Self for method chaining

        """
        self._fail_fast = enabled
        return self

    def preserve_order(self, *, enabled: bool = True) -> Self:
        """Set order preservation.

        Args:
            enabled: Preserve entry order

        Returns:
            Self for method chaining

        """
        self._preserve_order = enabled
        return self

    def track_changes(self, *, enabled: bool = True) -> Self:
        """Set change tracking.

        Args:
            enabled: Track changes in metadata

        Returns:
            Self for method chaining

        """
        self._track_changes = enabled
        return self

    def build(self) -> m.Ldif.Config.TransformConfig:
        """Build the TransformConfig.

        Returns:
            Configured TransformConfig instance

        """
        # Pydantic 2: Create config and update attributes directly
        config = m.Ldif.Config.TransformConfig()
        config.fail_fast = self._fail_fast
        config.preserve_order = self._preserve_order
        config.track_changes = self._track_changes
        return config


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

    def case_sensitive(self, *, enabled: bool = True) -> Self:
        """Set case sensitivity.

        Args:
            enabled: Case-sensitive matching

        Returns:
            Self for method chaining

        """
        self._case_sensitive = enabled
        return self

    def include_metadata_matches(self, *, enabled: bool = True) -> Self:
        """Include metadata in matching.

        Args:
            enabled: Match against metadata fields

        Returns:
            Self for method chaining

        """
        self._include_metadata_matches = enabled
        return self

    def build(self) -> m.Ldif.Config.FilterConfig:
        """Build the FilterConfig.

        Returns:
            Configured FilterConfig instance

        """
        # Pydantic 2: Create config and update attributes directly
        config = m.Ldif.Config.FilterConfig()
        config.mode = self._mode
        config.case_sensitive = self._case_sensitive
        config.include_metadata_matches = self._include_metadata_matches
        return config


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
        self._format: m.Ldif.Config.OutputFormat = m.Ldif.Config.OutputFormat.LDIF
        self._line_width: int = 76
        self._fold_lines: bool = True
        self._base64_attrs: Sequence[str] | Literal["auto"] = "auto"
        self._sort_by: m.Ldif.Config.SortOption = m.Ldif.Config.SortOption.ALPHABETICAL
        self._attr_order: Sequence[str] | None = None
        self._include_metadata: bool = False
        self._server: m.Ldif.Config.ServerType | None = None

    def format(self, fmt: m.Ldif.Config.OutputFormat) -> Self:
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

    def fold_lines(self, *, enabled: bool = True) -> Self:
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

    def sort_by(self, field: m.Ldif.Config.SortOption) -> Self:
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

    def include_metadata(self, *, enabled: bool = True) -> Self:
        """Include metadata in output.

        Args:
            enabled: Whether to include metadata

        Returns:
            Self for method chaining

        """
        self._include_metadata = enabled
        return self

    def server(self, server: m.Ldif.Config.ServerType) -> Self:
        """Set target server for formatting.

        Args:
            server: Target server type

        Returns:
            Self for method chaining

        """
        self._server = server
        return self

    def build(self) -> m.Ldif.Config.WriteConfig:
        """Build the WriteConfig.

        Returns:
            Configured WriteConfig instance

        """
        # Pydantic 2: Create config and update attributes directly
        config = m.Ldif.Config.WriteConfig()
        config.format = self._format  # format is alias for output_format
        config.line_width = self._line_width
        config.fold_lines = self._fold_lines
        config.base64_attrs = self._base64_attrs
        config.sort_by = self._sort_by
        config.attr_order = self._attr_order
        config.include_metadata = self._include_metadata
        config.server = self._server
        return config


__all__ = [
    "FilterConfigBuilder",
    "ProcessConfigBuilder",
    "TransformConfigBuilder",
    "WriteConfigBuilder",
]
