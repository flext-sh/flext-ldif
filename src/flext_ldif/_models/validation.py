from typing import Annotated, Literal

from flext_core._models.entity import FlextModelsEntity
from pydantic import Field, StringConstraints

from flext_ldif._models.rfc_validation_types import Rfc4512Descriptor
from flext_ldif.constants import c


class EncodingRules(FlextModelsEntity.Value):
    default_encoding: Annotated[
        str,
        StringConstraints(
            min_length=1,
            max_length=50,
            pattern=r"^[A-Za-z0-9._-]+$",
        ),
    ]
    allowed_encodings: list[c.Ldif.LiteralTypes.EncodingLiteral] = Field(
        default_factory=list,
    )


class DnCaseRules(FlextModelsEntity.Value):
    preserve_case: bool
    normalize_to: Literal["lower", "upper"] | None = Field(default=None)


class AclFormatRules(FlextModelsEntity.Value):
    format: str
    attribute_name: Rfc4512Descriptor
    requires_target: bool
    requires_subject: bool


class ServerValidationRules(FlextModelsEntity.Value):
    requires_objectclass: bool
    requires_naming_attr: bool
    requires_binary_option: bool
    encoding_rules: EncodingRules
    dn_case_rules: DnCaseRules
    acl_format_rules: AclFormatRules
    track_deletions: bool
    track_modifications: bool
    track_conversions: bool


__all__ = [
    "EncodingRules",
    "DnCaseRules",
    "AclFormatRules",
    "ServerValidationRules",
]
