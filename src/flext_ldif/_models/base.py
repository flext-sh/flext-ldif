"""Base classes for flext-ldif models."""

from __future__ import annotations

from flext_core._models.base import FlextModelsBase
from pydantic import ConfigDict, Field, computed_field

from flext_ldif._shared import normalize_server_type
from flext_ldif.constants import c


class FlextLdifModelsBase(FlextModelsBase.ArbitraryTypesModel):
    """Base class for all FLEXT-LDIF models (events, configs, processing results)."""

    model_config = ConfigDict(
        strict=True,
        validate_assignment=True,
        extra="forbid",
        validate_default=True,
        use_enum_values=True,
        str_strip_whitespace=True,
    )


class SchemaElement(FlextModelsBase.ArbitraryTypesModel):
    """Base class for all LDAP schema elements (attributes, objectClasses, syntaxes)."""

    model_config = ConfigDict(
        strict=True,
        validate_assignment=True,
        extra="forbid",
        validate_default=True,
        use_enum_values=True,
        str_strip_whitespace=True,
    )

    @computed_field
    def has_metadata(self) -> bool:
        """Check if schema element has quirk metadata."""
        metadata = getattr(self, "metadata", None)
        return metadata is not None

    @computed_field
    def server_type(self) -> str:
        """Get server type from metadata, default to RFC."""
        metadata = getattr(self, "metadata", None)
        if metadata is not None and hasattr(metadata, "quirk_type"):
            quirk_type = getattr(metadata, "quirk_type", None)
            if isinstance(quirk_type, str):
                try:
                    return normalize_server_type(quirk_type)
                except ValueError:
                    pass
        return "rfc"

    @computed_field
    def has_server_extensions(self) -> bool:
        """Check if element has server-specific extensions."""
        metadata = getattr(self, "metadata", None)
        if metadata is None:
            return False
        if hasattr(metadata, "extensions"):
            extensions = metadata.extensions
            return bool(extensions)
        return False


class AclElement(FlextModelsBase.ArbitraryTypesModel):
    """Base class for all ACL-related models."""

    model_config = ConfigDict(
        strict=True,
        frozen=False,
        extra="forbid",
        validate_default=True,
        use_enum_values=True,
        str_strip_whitespace=True,
    )

    server_type: c.Ldif.LiteralTypes.ServerTypeLiteral = Field(
        default="rfc",
        description="LDAP server type (oid, oud, openldap, rfc, etc.)",
    )

    validation_violations: list[str] = Field(
        default_factory=list,
        description="Validation violations captured during parsing/processing",
    )

    @computed_field
    def is_valid(self) -> bool:
        """Check if ACL element passed validation."""
        return len(self.validation_violations) == 0

    @computed_field
    def has_server_quirks(self) -> bool:
        """Check if element uses server-specific quirks."""
        return self.server_type != "rfc"
