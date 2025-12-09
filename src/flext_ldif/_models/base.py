"""Base classes for flext-ldif models.

This module provides common base classes that unify patterns across domain,
result, config, and event models. These base classes eliminate duplication
and provide consistent interfaces.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core._models.base import FlextModelsBase
from pydantic import ConfigDict, Field, computed_field

from flext_ldif._shared import normalize_server_type
from flext_ldif.constants import c


class FlextLdifModelsBase(FlextModelsBase.ArbitraryTypesModel):
    """Base class for all FLEXT-LDIF models (events, configs, processing results).

    Extends FlextModelsBase.ArbitraryTypesModel to provide a consistent base
    for LDIF-specific models, ensuring:
    - Proper Pydantic v2 configuration inheritance
    - Consistency with flext-core architecture
    - Type safety without using BaseModel directly
    - Support for advanced Pydantic v2 features

    Usage:
        class MyLdifModel(FlextLdifModelsBase):
            '''My LDIF domain model.'''
            field1: str
            field2: int = Field(default=0)

    """

    model_config = ConfigDict(
        strict=True,
        validate_assignment=True,
        extra="forbid",
        validate_default=True,
        use_enum_values=True,
        str_strip_whitespace=True,
    )


class SchemaElement(FlextModelsBase.ArbitraryTypesModel):
    """Base class for all LDAP schema elements (attributes, objectClasses, syntaxes).

    Provides common metadata handling, server type tracking, and validation patterns
    for RFC 4512 schema definitions. All schema models (SchemaAttribute,
    SchemaObjectClass, Syntax) inherit from this base.

    Example:
        class SchemaAttribute(SchemaElement):
            name: str
            oid: str
            # Inherits: metadata, has_metadata, server_type, has_server_extensions

    """

    model_config = ConfigDict(
        strict=True,
        validate_assignment=True,
        extra="forbid",
        validate_default=True,
        use_enum_values=True,
        str_strip_whitespace=True,
    )

    # NOTE: metadata field is defined in subclasses with proper type
    # (QuirkMetadata | None) to avoid circular imports and type override issues

    @computed_field
    def has_metadata(self) -> bool:
        """Check if schema element has quirk metadata."""
        metadata = getattr(self, "metadata", None)
        return metadata is not None

    @computed_field
    def server_type(self) -> str:
        """Get server type from metadata, default to RFC.

        Returns:
            Server type string (oid, oud, openldap, etc.) or "rfc" if no metadata
            (guaranteed to be a valid ServerTypeLiteral value)

        """
        metadata = getattr(self, "metadata", None)
        if metadata is not None and hasattr(metadata, "quirk_type"):
            quirk_type = getattr(metadata, "quirk_type", None)
            if isinstance(quirk_type, str):
                # Type narrowing: quirk_type is str, validate against ServerTypeLiteral
                # normalize_server_type validates and returns ServerTypeLiteral when valid
                # or raises ValueError for invalid values
                try:
                    # normalize_server_type returns ServerTypeLiteral
                    # (validated by TypeGuard)
                    return normalize_server_type(quirk_type)
                except ValueError:
                    # Invalid server type, default to RFC
                    pass
        return "rfc"

    @computed_field
    def has_server_extensions(self) -> bool:
        """Check if element has server-specific extensions.

        Returns:
            True if metadata exists and has non-empty extensions dict

        """
        metadata = getattr(self, "metadata", None)
        if metadata is None:
            return False
        if hasattr(metadata, "extensions"):
            extensions = metadata.extensions
            return bool(extensions)
        return False


class AclElement(FlextModelsBase.ArbitraryTypesModel):
    """Base class for all ACL-related models.

    Provides common validation, server type handling, and metadata
    for Access Control List processing across all LDAP servers.

    All ACL models (Acl, AclPermissions, AclTarget, AclSubject) inherit from this base.

    Example:
        class Acl(AclElement):
            target: str
            permissions: list[str]
            # Inherits: server_type, metadata, validation_violations, is_valid

    """

    model_config = ConfigDict(
        strict=True,
        frozen=True,
        extra="forbid",
        validate_default=True,
        use_enum_values=True,
        str_strip_whitespace=True,
    )

    server_type: c.Ldif.LiteralTypes.ServerTypeLiteral = Field(
        default="rfc",
        description="LDAP server type (oid, oud, openldap, rfc, etc.)",
    )

    # NOTE: metadata field is defined in subclasses with proper type
    # (QuirkMetadata | None) to avoid circular imports and type override issues

    validation_violations: list[str] = Field(
        default_factory=list,
        description="Validation violations captured during parsing/processing",
    )

    @computed_field
    def is_valid(self) -> bool:
        """Check if ACL element passed validation.

        Returns:
            True if no validation violations exist

        """
        return len(self.validation_violations) == 0

    @computed_field
    def has_server_quirks(self) -> bool:
        """Check if element uses server-specific quirks.

        Returns:
            True if server_type is not RFC (uses vendor-specific features)

        """
        # Compare with string literal "rfc" to match ServerTypeLiteral type
        return self.server_type != "rfc"
