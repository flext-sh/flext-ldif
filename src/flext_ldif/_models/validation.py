"""Validation models for LDIF processing."""

from __future__ import annotations

from flext_core._models.entity import FlextModelsEntity
from pydantic import Field

from flext_ldif.constants import c


class EncodingRules(FlextModelsEntity.Value):
    """Generic encoding rules - server classes provide values."""

    default_encoding: str
    allowed_encodings: list[c.Ldif.LiteralTypes.EncodingLiteral] = Field(
        default_factory=list,
    )


class DnCaseRules(FlextModelsEntity.Value):
    """Generic DN case rules - server classes provide values."""

    preserve_case: bool
    normalize_to: str | None = Field(default=None)


class AclFormatRules(FlextModelsEntity.Value):
    """Generic ACL format rules - server classes provide values."""

    format: str
    attribute_name: str
    requires_target: bool
    requires_subject: bool


class ServerValidationRules(FlextModelsEntity.Value):
    """Generic server validation rules - server classes provide values."""

    requires_objectclass: bool
    requires_naming_attr: bool
    requires_binary_option: bool
    encoding_rules: EncodingRules
    dn_case_rules: DnCaseRules
    acl_format_rules: AclFormatRules
    track_deletions: bool
    track_modifications: bool
    track_conversions: bool
