"""Configuration models for flext-ldif utilities.

Provides configuration classes for LDIF processing:
    - ProcessConfig: Main process configuration
    - TransformConfig: Transformation pipeline configuration
    - FilterConfig: Entry filtering configuration
    - WriteConfig: LDIF output configuration
    - And related configuration options (Enums, TypedDicts, etc.)

Python 3.13+ features:
    - PEP 695 type parameter syntax
    - Keyword-only arguments
"""

from __future__ import annotations

from enum import StrEnum
from typing import TypedDict

from pydantic import BaseModel, ConfigDict, Field

# =========================================================================
# ENUMS FOR SERVER TYPES AND OPTIONS
# =========================================================================


class ServerType(StrEnum):
    """LDAP server type enumeration."""

    AUTO = "auto"
    OID = "oid"
    OUD = "oud"
    OPENLDAP = "openldap"
    OPENLDAP1 = "openldap1"
    AD = "ad"
    DS389 = "ds389"
    NOVELL = "novell"
    TIVOLI = "tivoli"
    RELAXED = "relaxed"
    RFC = "rfc"


class OutputFormat(StrEnum):
    """Output format enumeration."""

    LDIF = "ldif"
    JSON = "json"
    CSV = "csv"
    YAML = "yaml"


class CaseFoldOption(StrEnum):
    """Case folding options for DN normalization."""

    NONE = "none"
    LOWER = "lower"
    UPPER = "upper"


class SpaceHandlingOption(StrEnum):
    """Space handling options for DN normalization."""

    PRESERVE = "preserve"
    TRIM = "trim"
    NORMALIZE = "normalize"


class EscapeHandlingOption(StrEnum):
    """Escape sequence handling options."""

    PRESERVE = "preserve"
    UNESCAPE = "unescape"
    NORMALIZE = "normalize"


class SortOption(StrEnum):
    """Attribute sorting options."""

    NONE = "none"
    ALPHABETICAL = "alphabetical"
    HIERARCHICAL = "hierarchical"


# =========================================================================
# TYPE ALIASES
# =========================================================================


# Type aliases for common configuration types
class DNNormalizationParams(TypedDict, total=False):
    case: CaseFoldOption
    spaces: SpaceHandlingOption
    escapes: EscapeHandlingOption


class MetadataPreserveParams(TypedDict, total=False):
    original: bool
    tracking: bool
    validation: bool


# =========================================================================
# PYDANTIC CONFIGURATION MODELS
# =========================================================================


class DnNormalizationConfig(BaseModel):
    """DN (Distinguished Name) normalization configuration."""

    model_config = ConfigDict(frozen=False, validate_assignment=True)

    case_fold: CaseFoldOption = Field(default=CaseFoldOption.LOWER)
    space_handling: SpaceHandlingOption = Field(default=SpaceHandlingOption.TRIM)
    escape_handling: EscapeHandlingOption = Field(default=EscapeHandlingOption.PRESERVE)


class AttrNormalizationConfig(BaseModel):
    """Attribute normalization configuration."""

    model_config = ConfigDict(frozen=False, validate_assignment=True)

    sort_attributes: SortOption = Field(default=SortOption.ALPHABETICAL)
    sort_values: bool = Field(default=True)
    normalize_whitespace: bool = Field(default=True)


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


class ProcessConfig(BaseModel):
    """Main process configuration."""

    model_config = ConfigDict(frozen=False, validate_assignment=True)

    source_server: ServerType = Field(default=ServerType.RFC)
    target_server: ServerType = Field(default=ServerType.RFC)
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


class WriteConfig(BaseModel):
    """LDIF output/write configuration."""

    model_config = ConfigDict(frozen=False, validate_assignment=True)

    output_format: OutputFormat = Field(default=OutputFormat.LDIF)
    version: int = Field(default=1, ge=1)
    wrap_lines: bool = Field(default=True)
    line_length: int = Field(default=76, ge=10)


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
    "CaseFoldOption",
    "DnNormalizationConfig",
    "EscapeHandlingOption",
    "FilterConfig",
    "LoadConfig",
    "MetadataConfig",
    "OutputFormat",
    "ProcessConfig",
    "SchemaParseConfig",
    "ServerType",
    "SortOption",
    "SpaceHandlingOption",
    "TransformConfig",
    "ValidationConfig",
    "ValidationRuleSet",
    "WriteConfig",
]
