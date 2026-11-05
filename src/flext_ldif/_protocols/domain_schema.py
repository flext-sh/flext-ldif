# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/domain_schema
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableSequence
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_ldif._protocols import FlextLdifProtocolsElements

if TYPE_CHECKING:
    from flext_ldif import c
    from flext_ldif._protocols import FlextLdifProtocolsDomainMetadata


class FlextLdifProtocolsDomainSchema:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class SchemaAttribute(FlextLdifProtocolsElements.SchemaElement, Protocol):
        """Structural data contract projected from the owning model."""

        name: str
        oid: str
        desc: str | None
        sup: str | None
        equality: str | None
        ordering: str | None
        substr: str | None
        syntax: str | None
        length: int | None
        usage: str | None
        single_value: bool
        collective: bool
        no_user_modification: bool
        immutable: bool
        user_modification: bool
        obsolete: bool
        x_origin: str | None
        x_file_ref: str | None
        x_name: str | None
        x_alias: str | None
        x_oid: str | None

        @property
        def metadata(self) -> FlextLdifProtocolsDomainMetadata.ServerMetadata | None:
            """Server-specific metadata for schema attribute."""
            ...

    @runtime_checkable
    class Syntax(FlextLdifProtocolsElements.SchemaElement, Protocol):
        """Structural data contract projected from the owning model."""

        oid: str
        name: str | None
        desc: str | None
        type_category: str
        is_binary: bool
        max_length: int | None
        case_insensitive: bool
        allows_multivalued: bool
        encoding: c.Ldif.Encoding
        validation_pattern: str | None

        @property
        def metadata(self) -> FlextLdifProtocolsDomainMetadata.ServerMetadata | None:
            """Server-specific server metadata."""
            ...

    @runtime_checkable
    class SchemaObjectClass(FlextLdifProtocolsElements.SchemaElement, Protocol):
        """Structural data contract projected from the owning model."""

        name: str
        oid: str
        desc: str | None
        sup: str | MutableSequence[str] | None
        kind: str
        must: MutableSequence[str] | None
        may: MutableSequence[str] | None

        @property
        def metadata(self) -> FlextLdifProtocolsDomainMetadata.ServerMetadata | None:
            """Server-specific metadata for schema object class."""
            ...


__all__: list[str] = [
    "FlextLdifProtocolsDomainSchema",
]
