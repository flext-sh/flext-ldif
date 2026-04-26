"""Base classes for flext-ldif models."""

from __future__ import annotations

from collections.abc import (
    MutableSequence,
)
from typing import Annotated

from flext_core import m, u
from flext_ldif import FlextLdifShared, c


class FlextLdifModelsBases:
    """Facade namespace for all FLEXT-LDIF base model classes.

    Follows AGENTS.md §2: each module organizes domain logic into
    a single nested class hierarchy using MRO inheritance.

    Usage::
        from flext_core import m
        from flext_ldif import FlextLdifModelsBases

        Base = m.StrictModel
    """

    class SchemaElement(m.StrictModel):
        """Base class for all LDAP schema elements (attributes, objectClasses, syntaxes)."""

        validation_metadata: Annotated[
            m.ConfigMap | None,
            u.Field(
                description="Validation metadata captured during schema processing.",
            ),
        ] = None

        @u.computed_field()
        @property
        def has_metadata(self) -> bool:
            """Check if schema element has quirk metadata."""
            metadata = getattr(self, "metadata", None)
            return metadata is not None

        @u.computed_field()
        @property
        def has_server_extensions(self) -> bool:
            """Check if element has server-specific extensions."""
            metadata = getattr(self, "metadata", None)
            if metadata is None:
                return False
            extensions = getattr(metadata, "extensions", None)
            return bool(extensions)

        @u.computed_field()
        @property
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

    class AclElement(m.StrictModel):
        """Base class for all ACL-related models."""

        server_type: Annotated[
            c.Ldif.ServerTypes,
            u.Field(
                description="LDAP server type (oid, oud, openldap, rfc, etc.)",
            ),
        ] = c.Ldif.ServerTypes.RFC
        validation_violations: Annotated[
            MutableSequence[str],
            u.Field(
                default_factory=list,
                description="Validation violations recorded while normalizing ACL data.",
            ),
        ] = u.Field(default_factory=list)
        validation_metadata: Annotated[
            m.ConfigMap | None,
            u.Field(
                description="Validation metadata captured during ACL processing.",
            ),
        ] = None

        @u.computed_field()
        @property
        def has_server_quirks(self) -> bool:
            """Check if element uses server-specific quirks."""
            return self.server_type != "rfc"

        @u.computed_field()
        @property
        def valid(self) -> bool:
            """Check if ACL element passed validation."""
            return not self.validation_violations

        @u.field_validator("server_type", mode="before")
        @classmethod
        def _coerce_server_type(
            cls,
            value: c.Ldif.ServerTypes | str,
        ) -> c.Ldif.ServerTypes:
            if isinstance(value, c.Ldif.ServerTypes):
                return value
            return FlextLdifShared.normalize_server_type(value)


__all__: list[str] = ["FlextLdifModelsBases"]
