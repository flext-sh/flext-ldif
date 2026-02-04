"""Configuration models for flext-ldif utilities.

Provides configuration classes for LDIF processing:
    - ProcessConfig: Main process configuration
    - TransformConfig: Transformation pipeline configuration
    - FilterConfig: Entry filtering configuration
    - WriteConfig: LDIF output configuration
    - And related configuration options (TypedDicts, etc.)

Python 3.13+ features:
    - PEP 695 type parameter syntax
    - Keyword-only arguments

NOTE: All StrEnums are centralized in constants.py per FLEXT pattern.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from flext_ldif.constants import c

# =========================================================================
# ENUM ALIASES FROM CONSTANTS (CENTRALIZED SOURCE OF TRUTH)
# =========================================================================
# Per FLEXT pattern: StrEnums are ONLY in constants.py
# These aliases provide backward compatibility for existing usages

# Domain options from constants
CaseFoldOption = c.Ldif.CaseFoldOption
SpaceHandlingOption = c.Ldif.SpaceHandlingOption
EscapeHandlingOption = c.Ldif.EscapeHandlingOption


# =========================================================================
# TYPE ALIASES
# =========================================================================


# Type aliases for common configuration types - temporarily commented due to missing constants
# class DNNormalizationParams(TypedDict, total=False):
#     case: CaseFoldOption
#     spaces: SpaceHandlingOption
#     escapes: EscapeHandlingOption


class MetadataPreserveConfig(BaseModel):
    """Configuration for metadata preservation. Replaces TypedDict."""

    model_config = ConfigDict(frozen=False)

    original: bool = Field(default=False)
    tracking: bool = Field(default=False)
    validation: bool = Field(default=False)


# Backward compatibility
MetadataPreserveParams = MetadataPreserveConfig


# =========================================================================
# PYDANTIC CONFIGURATION MODELS
# =========================================================================


class DnNormalizationConfig(BaseModel):
    """DN (Distinguished Name) normalization configuration."""

    model_config = ConfigDict(frozen=False, validate_assignment=True)

    case_fold: CaseFoldOption = Field(default=CaseFoldOption.LOWER)
    space_handling: SpaceHandlingOption = Field(default=SpaceHandlingOption.PRESERVE)
    # escape_handling: EscapeHandlingOption = Field(default=EscapeHandlingOption.ENABLE)
    validate_before: bool = Field(
        default=True,
        description="Validate DN before normalization",
    )


class AttrNormalizationConfig(BaseModel):
    """Attribute normalization configuration."""

    model_config = ConfigDict(frozen=False, validate_assignment=True)

    # sort_attributes: SortOption = Field(default=SortOption.ALPHABETICAL)
    sort_values: bool = Field(default=True)
    normalize_whitespace: bool = Field(default=True)
    case_fold_names: bool = Field(default=True, description="Lowercase attribute names")
    trim_values: bool = Field(default=True, description="Trim whitespace from values")
    remove_empty: bool = Field(
        default=False,
        description="Remove empty attribute values",
    )


class AclConversionConfig(BaseModel):
    """ACL (Access Control List) conversion configuration."""

    model_config = ConfigDict(frozen=False, validate_assignment=True)

    convert_aci: bool = Field(default=True)
    preserve_original_aci: bool = Field(default=False)
    map_server_specific: bool = Field(default=True)


class MetadataConfig(BaseModel):
    """Metadata preservation configuration."""

    model_config = ConfigDict(frozen=False, validate_assignment=True)

    preserve_original: bool = Field(default=True)
    preserve_tracking: bool = Field(default=True)
    preserve_validation: bool = Field(default=False)


class ValidationConfig(BaseModel):
    """Validation configuration."""

    model_config = ConfigDict(frozen=False, validate_assignment=True)

    strict_rfc: bool = Field(default=False)
    allow_server_quirks: bool = Field(default=True)
    validate_dn_format: bool = Field(default=True)


class FilterConfig(BaseModel):
    """Entry filtering configuration."""

    model_config = ConfigDict(frozen=False, validate_assignment=True)

    filter_expression: str | None = Field(default=None)
    exclude_filter: str | None = Field(default=None)
    include_operational: bool = Field(default=False)
    mode: Literal["all", "any"] = Field(
        default="all",
        description="Filter combination mode (all=AND, any=OR)",
    )
    case_sensitive: bool = Field(default=False, description="Case-sensitive matching")
    include_metadata_matches: bool = Field(
        default=False,
        description="Match against metadata fields",
    )


class ProcessConfig(BaseModel):
    """Main process configuration."""

    model_config = ConfigDict(frozen=False, validate_assignment=True)

    # source_server: ServerType = Field(default=ServerType.RFC)
    # target_server: ServerType = Field(default=ServerType.RFC)
    dn_config: DnNormalizationConfig = Field(default_factory=DnNormalizationConfig)
    attr_config: AttrNormalizationConfig = Field(
        default_factory=AttrNormalizationConfig,
    )
    acl_config: AclConversionConfig = Field(default_factory=AclConversionConfig)
    validation_config: ValidationConfig = Field(default_factory=ValidationConfig)
    metadata_config: MetadataConfig = Field(default_factory=MetadataConfig)


class TransformConfig(BaseModel):
    """Transformation pipeline configuration."""

    model_config = ConfigDict(frozen=False, validate_assignment=True)

    process_config: ProcessConfig = Field(default_factory=ProcessConfig)
    filter_config: FilterConfig = Field(default_factory=FilterConfig)
    normalize_dns: bool = Field(default=True)
    normalize_attrs: bool = Field(default=True)
    convert_acls: bool = Field(default=True)
    fail_fast: bool = Field(default=True, description="Stop on first error")
    preserve_order: bool = Field(default=True, description="Preserve entry order")
    track_changes: bool = Field(default=True, description="Track changes in metadata")


class WriteConfig(BaseModel):
    """LDIF output/write configuration."""

    model_config = ConfigDict(frozen=False, validate_assignment=True)

    # output_format: OutputFormat = Field(default=OutputFormat.LDIF)
    version: int = Field(default=1, ge=1)
    wrap_lines: bool = Field(default=True)
    line_length: int = Field(default=76, ge=10)
    # format: OutputFormat = Field(
    #     default=OutputFormat.LDIF,
    #     description="Alias for output_format",
    # )
    line_width: int = Field(default=76, ge=10, description="Alias for line_length")
    fold_lines: bool = Field(default=True, description="Alias for wrap_lines")
    base64_attrs: Sequence[str] | Literal["auto"] = Field(
        default="auto",
        description="Attributes to encode in base64",
    )
    # sort_by: SortOption = Field(
    #     default=SortOption.ALPHABETICAL,
    #     description="Sort entries by field",
    # )
    attr_order: Sequence[str] | None = Field(
        default=None,
        description="Preferred attribute order",
    )
    include_metadata: bool = Field(
        default=False,
        description="Include metadata in output",
    )
    # server field temporarily removed due to constant reorganization


class LoadConfig(BaseModel):
    """LDIF file loading configuration."""

    model_config = ConfigDict(frozen=False, validate_assignment=True)

    file_path: str = Field(default="")
    encoding: str = Field(default="utf-8")
    ignore_errors: bool = Field(default=False)
    skip_comments: bool = Field(default=False)


class SchemaParseConfig(BaseModel):
    """Schema parsing configuration."""

    model_config = ConfigDict(frozen=False, validate_assignment=True)

    parse_attributes: bool = Field(default=True)
    parse_objectclasses: bool = Field(default=True)
    parse_matching_rules: bool = Field(default=False)
    parse_syntaxes: bool = Field(default=False)


class ValidationRuleSet(BaseModel):
    """Validation rule set configuration."""

    model_config = ConfigDict(frozen=False, validate_assignment=True)

    name: str = Field(default="default")
    strict_mode: bool = Field(default=False)
    allow_undefined_attrs: bool = Field(default=True)
    allow_undefined_ocs: bool = Field(default=True)


__all__: list[str] = [
    "AclConversionConfig",
    "AttrNormalizationConfig",
    # "CaseFoldOption",
    "DnNormalizationConfig",
    # "EscapeHandlingOption",
    "FilterConfig",
    "LoadConfig",
    "MetadataConfig",
    # "OutputFormat",
    "ProcessConfig",
    "SchemaParseConfig",
    # "ServerType",
    # "SortOption",
    # "SpaceHandlingOption",
    "TransformConfig",
    "ValidationConfig",
    "ValidationRuleSet",
    "WriteConfig",
]
