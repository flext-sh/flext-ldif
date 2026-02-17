"""Power Method Builders - Fluent builders for configuration objects."""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum
from typing import Literal, Self

from flext_ldif._models.settings import (
    AclConversionConfig,
    AttrNormalizationConfig,
    DnNormalizationConfig,
    FilterConfig,
    MetadataConfig,
    ProcessConfig,
    TransformConfig,
    ValidationConfig,
    WriteConfig,
)
from flext_ldif.constants import c

# PROCESS CONFIG BUILDER


class ProcessConfigBuilder:
    """Fluent builder for ProcessConfig."""

    __slots__ = (
        "_acl_config",
        "_attr_config",
        "_dn_config",
        "_metadata_config",
        "_source_server",
        "_target_server",
        "_validation_config",
    )

    def __init__(self) -> None:
        """Initialize builder with default values."""
        self._source_server: c.Ldif.ServerTypes = c.Ldif.ServerTypes.RFC
        self._target_server: c.Ldif.ServerTypes | None = None
        self._dn_config: DnNormalizationConfig | None = None
        self._attr_config: AttrNormalizationConfig | None = None
        self._acl_config: AclConversionConfig | None = None
        self._validation_config: ValidationConfig | None = None
        self._metadata_config: MetadataConfig | None = None

    def source(self, server: c.Ldif.ServerTypes) -> Self:
        """Set the source server type."""
        self._source_server = server
        return self

    def target(self, server: c.Ldif.ServerTypes) -> Self:
        """Set the target server type."""
        self._target_server = server
        return self

    def normalize_dn(
        self,
        *,
        case: StrEnum | None = None,
        spaces: c.Ldif.SpaceHandlingOption | None = None,
        escapes: c.Ldif.EscapeHandlingOption | None = None,
    ) -> Self:
        """Configure DN normalization."""
        # Create config with values in constructor to avoid frozen model issues
        config_kwargs = {}
        if case is not None:
            config_kwargs["case_fold"] = case
        if spaces is not None:
            config_kwargs["space_handling"] = spaces
        if escapes is not None:
            config_kwargs["escape_handling"] = escapes

        self._dn_config = DnNormalizationConfig.model_validate(config_kwargs)
        return self

    def normalize_attrs(
        self,
        *,
        sort_attributes: c.Ldif.SortOption | None = None,
        sort_values: bool = True,
        normalize_whitespace: bool = True,
        lowercase_keys: bool = False,
    ) -> Self:
        """Configure attribute normalization."""
        # Create config with values in constructor to avoid frozen model issues
        config_kwargs = {
            "sort_values": sort_values,
            "normalize_whitespace": normalize_whitespace,
            "lowercase_keys": lowercase_keys,
            "sort_attributes": sort_attributes,
        }

        self._attr_config = AttrNormalizationConfig.model_validate(config_kwargs)
        return self

    def acl_conversion(
        self,
        *,
        convert_aci: bool = True,
        preserve_original_aci: bool = False,
        map_server_specific: bool = True,
    ) -> Self:
        """Configure ACL conversion."""
        # Create config with values in constructor to avoid frozen model issues
        self._acl_config = AclConversionConfig(
            convert_aci=convert_aci,
            preserve_original_aci=preserve_original_aci,
            map_server_specific=map_server_specific,
        )
        return self

    def validation(
        self,
        *,
        strict_rfc: bool = False,
        allow_server_quirks: bool = True,
        validate_dn_format: bool = True,
    ) -> Self:
        """Configure validation behavior."""
        # Create config with values in constructor to avoid frozen model issues
        self._validation_config = ValidationConfig(
            strict_mode=strict_rfc,
            validate_schema=allow_server_quirks,
            validate_acl=validate_dn_format,
        )
        return self

    def preserve_metadata(
        self,
        *,
        preserve_original: bool = True,
        preserve_tracking: bool = True,
        preserve_validation: bool = False,
    ) -> Self:
        """Configure metadata handling."""
        # Create config with values in constructor to avoid frozen model issues
        self._metadata_config = MetadataConfig(
            include_timestamps=preserve_original,
            include_processing_stats=preserve_tracking,
            preserve_validation=preserve_validation,
        )
        return self

    def build(self) -> ProcessConfig:
        """Build the ProcessConfig."""
        # Create config with all values in constructor to avoid frozen model issues
        return ProcessConfig(
            source_server=self._source_server,
            target_server=self._target_server or c.Ldif.ServerTypes.RFC,
            dn_config=self._dn_config or DnNormalizationConfig.model_validate({}),
            attr_config=self._attr_config or AttrNormalizationConfig.model_validate({}),
            acl_config=self._acl_config or AclConversionConfig.model_validate({}),
            validation_config=self._validation_config
            or ValidationConfig.model_validate({}),
            metadata_config=self._metadata_config or MetadataConfig.model_validate({}),
        )


# TRANSFORM CONFIG BUILDER


class TransformConfigBuilder:
    """Fluent builder for TransformConfig."""

    __slots__ = ("_fail_fast", "_preserve_order", "_track_changes")

    def __init__(self) -> None:
        """Initialize builder with default values."""
        self._fail_fast: bool = True
        self._preserve_order: bool = True
        self._track_changes: bool = True

    def fail_fast(self, *, enabled: bool = True) -> Self:
        """Set fail-fast behavior."""
        self._fail_fast = enabled
        return self

    def preserve_order(self, *, enabled: bool = True) -> Self:
        """Set order preservation."""
        self._preserve_order = enabled
        return self

    def track_changes(self, *, enabled: bool = True) -> Self:
        """Set change tracking."""
        self._track_changes = enabled
        return self

    def build(self) -> TransformConfig:
        """Build the TransformConfig."""
        # Create config with all values at construction time (frozen model)
        return TransformConfig(
            fail_fast=self._fail_fast,
            preserve_order=self._preserve_order,
            track_changes=self._track_changes,
        )


# FILTER CONFIG BUILDER


class FilterConfigBuilder:
    """Fluent builder for FilterConfig."""

    __slots__ = ("_case_sensitive", "_include_metadata_matches", "_mode")

    def __init__(self) -> None:
        """Initialize builder with default values."""
        self._mode: Literal["all", "any"] = "all"
        self._case_sensitive: bool = False
        self._include_metadata_matches: bool = False

    def mode(self, mode: Literal["all", "any"]) -> Self:
        """Set filter combination mode."""
        self._mode = mode
        return self

    def case_sensitive(self, *, enabled: bool = True) -> Self:
        """Set case sensitivity."""
        self._case_sensitive = enabled
        return self

    def include_metadata_matches(self, *, enabled: bool = True) -> Self:
        """Include metadata in matching."""
        self._include_metadata_matches = enabled
        return self

    def build(self) -> FilterConfig:
        """Build the FilterConfig."""
        # Create config with all values at construction time (frozen model)
        return FilterConfig(
            mode=self._mode,
            case_sensitive=self._case_sensitive,
            include_metadata_matches=self._include_metadata_matches,
        )


# WRITE CONFIG BUILDER


class WriteConfigBuilder:
    """Fluent builder for WriteConfig."""

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
        self._format: c.Ldif.Domain.OutputFormat = c.Ldif.Domain.OutputFormat.LDIF
        self._line_width: int = 76
        self._fold_lines: bool = True
        self._base64_attrs: Sequence[str] | Literal["auto"] = "auto"
        self._sort_by: c.Ldif.SortOption = c.Ldif.SortOption.ALPHABETICAL
        self._attr_order: Sequence[str] | None = None
        self._include_metadata: bool = False
        self._server: c.Ldif.ServerTypes | None = None

    def format(self, fmt: c.Ldif.Domain.OutputFormat) -> Self:
        """Set output format."""
        self._format = fmt
        return self

    def line_width(self, width: int) -> Self:
        """Set line width for folding."""
        self._line_width = width
        return self

    def fold_lines(self, *, enabled: bool = True) -> Self:
        """Enable or disable line folding."""
        self._fold_lines = enabled
        return self

    def base64_attrs(self, attrs: Sequence[str] | Literal["auto"]) -> Self:
        """Set attributes to base64 encode."""
        self._base64_attrs = attrs
        return self

    def sort_by(self, field: c.Ldif.SortOption) -> Self:
        """Set sorting field."""
        self._sort_by = field
        return self

    def attr_order(self, order: Sequence[str]) -> Self:
        """Set preferred attribute order."""
        self._attr_order = order
        return self

    def include_metadata(self, *, enabled: bool = True) -> Self:
        """Include metadata in output."""
        self._include_metadata = enabled
        return self

    def server(self, server: c.Ldif.ServerTypes) -> Self:
        """Set target server for formatting."""
        self._server = server
        return self

    def build(self) -> WriteConfig:
        """Build the WriteConfig."""
        # Create config with all values at construction time (frozen model)
        # Convert types to match WriteConfig expectations
        base64_attrs_value = (
            list(self._base64_attrs)
            if isinstance(self._base64_attrs, (list, tuple))
            else None
        )
        attr_order_value = (
            list(self._attr_order) if self._attr_order is not None else None
        )

        return WriteConfig(
            format=self._format.value,  # format is alias for output_format
            line_width=self._line_width,
            fold_lines=self._fold_lines,
            base64_attrs=base64_attrs_value,
            sort_by=self._sort_by.value,
            attr_order=attr_order_value,
            include_metadata=self._include_metadata,
            server=self._server,
        )


__all__ = [
    "FilterConfigBuilder",
    "ProcessConfigBuilder",
    "TransformConfigBuilder",
    "WriteConfigBuilder",
]
