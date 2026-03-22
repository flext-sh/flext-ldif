"""Base classes for flext-ldif models."""

from __future__ import annotations

from typing import Annotated

from flext_core.models import FlextModels as m
from pydantic import ConfigDict, Field, computed_field

from flext_ldif import c
from flext_ldif.shared import FlextLdifShared
from flext_ldif.typings import t as ldif_t


class FlextLdifModelsBase(m.ArbitraryTypesModel):
    """Base class for all FLEXT-LDIF models (events, configs, processing results)."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        strict=True,
        validate_assignment=True,
        extra="forbid",
        validate_default=True,
        use_enum_values=True,
        str_strip_whitespace=True,
    )


class SchemaElement(FlextLdifModelsBase):
    """Base class for all LDAP schema elements (attributes, objectClasses, syntaxes)."""

    validation_metadata: Annotated[
        ldif_t.ConfigMap | None,
        Field(
            default=None,
            description="Validation metadata captured during schema processing.",
        ),
    ]

    @computed_field
    def has_metadata(self) -> bool:
        """Check if schema element has quirk metadata."""
        metadata = getattr(self, "metadata", None)
        return metadata is not None

    @computed_field
    def has_server_extensions(self) -> bool:
        """Check if element has server-specific extensions."""
        metadata = getattr(self, "metadata", None)
        if metadata is None:
            return False
        extensions = getattr(metadata, "extensions", None)
        return bool(extensions)

    @computed_field
    def server_type(self) -> str:
        """Get server type from metadata, default to RFC."""
        metadata = getattr(self, "metadata", None)
        if metadata is not None:
            quirk_type = getattr(metadata, "quirk_type", None)
            if quirk_type is not None:
                try:
                    return FlextLdifShared.normalize_server_type(str(quirk_type))
                except ValueError:
                    pass
        return "rfc"


class FrozenLdifModel(FlextLdifModelsBase):
    """Immutable LDIF model — FlextLdifModelsBase with frozen=True."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)


class FrozenIgnoreLdifModel(m.ArbitraryTypesModel):
    """Immutable LDIF model that silently ignores extra fields."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="ignore")


class MutableIgnoreLdifModel(FlextLdifModelsBase):
    """Mutable LDIF model that silently ignores extra fields."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=False, extra="ignore")


class AclElement(m.ArbitraryTypesModel):
    """Base class for all ACL-related models."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        strict=True,
        frozen=False,
        extra="forbid",
        validate_default=True,
        use_enum_values=True,
        str_strip_whitespace=True,
    )
    server_type: Annotated[
        c.Ldif.LiteralTypes.ServerTypeLiteral,
        Field(
            default="rfc",
            description="LDAP server type (oid, oud, openldap, rfc, etc.)",
        ),
    ]
    validation_violations: Annotated[
        list[str],
        Field(
            default_factory=list,
            description="Validation violations captured during parsing/processing",
        ),
    ]
    validation_metadata: Annotated[
        ldif_t.ConfigMap | None,
        Field(
            default=None,
            description="Validation metadata captured during ACL processing.",
        ),
    ]

    @computed_field
    def has_server_quirks(self) -> bool:
        """Check if element uses server-specific quirks."""
        return self.server_type != "rfc"

    @computed_field
    def is_valid(self) -> bool:
        """Check if ACL element passed validation."""
        return len(self.validation_violations) == 0


class FlextLdifModelsBases:
    """Facade namespace for all FLEXT-LDIF base model classes.

    Follows AGENTS.md §2: each module organizes domain logic into
    a single nested class hierarchy using MRO inheritance.

    Usage::
        from flext_ldif._models.base import FlextLdifModelsBases

        FlextLdifModelsBase = FlextLdifModelsBases.FlextLdifModelsBase
    """

    FlextLdifModelsBase = FlextLdifModelsBase
    SchemaElement = SchemaElement
    FrozenLdifModel = FrozenLdifModel
    FrozenIgnoreLdifModel = FrozenIgnoreLdifModel
    MutableIgnoreLdifModel = MutableIgnoreLdifModel
    AclElement = AclElement


__all__ = [
    "AclElement",
    "FlextLdifModelsBase",
    "FlextLdifModelsBases",
    "FrozenIgnoreLdifModel",
    "FrozenLdifModel",
    "MutableIgnoreLdifModel",
    "SchemaElement",
]
