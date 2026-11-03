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
    from flext_ldif._constants import FlextLdifConstantsBaseParts
    from flext_ldif._protocols import (
        FlextLdifLdifProtocolsGeneratedModelsServerMetadata,
    )


class FlextLdifProtocolsDomainSchema:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class SchemaAttribute(FlextLdifProtocolsElements.SchemaElement, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def name(self) -> str:
            """Attribute name."""
            ...

        @property
        def oid(self) -> str:
            """Attribute OID."""
            ...

        @property
        def desc(self) -> str | None:
            """Attribute description (RFC 4512 DESC)."""
            ...

        @property
        def sup(self) -> str | None:
            """Superior attribute type (RFC 4512 SUP)."""
            ...

        @property
        def equality(self) -> str | None:
            """Equality matching rule (RFC 4512 EQUALITY)."""
            ...

        @property
        def ordering(self) -> str | None:
            """Ordering matching rule (RFC 4512 ORDERING)."""
            ...

        @property
        def substr(self) -> str | None:
            """Substring matching rule (RFC 4512 SUBSTR)."""
            ...

        @property
        def syntax(self) -> str | None:
            """Attribute syntax OID (RFC 4512 SYNTAX)."""
            ...

        @property
        def length(self) -> int | None:
            """Maximum length constraint."""
            ...

        @property
        def usage(self) -> str | None:
            """Attribute usage (RFC 4512 USAGE)."""
            ...

        @property
        def single_value(self) -> bool:
            """Whether attribute is single-valued (RFC 4512 SINGLE-VALUE)."""
            ...

        @property
        def collective(self) -> bool:
            """Whether attribute is collective (RFC 4512 COLLECTIVE)."""
            ...

        @property
        def no_user_modification(self) -> bool:
            """Structural member projected from the owning model.

            Whether users can modify this attribute (RFC 4512 NO-USER-MODIFICATION).
            """
            ...

        @property
        def immutable(self) -> bool:
            """Whether attribute is immutable (OUD extension)."""
            ...

        @property
        def user_modification(self) -> bool:
            """Whether users can modify this attribute (OUD extension)."""
            ...

        @property
        def obsolete(self) -> bool:
            """Whether attribute is obsolete (OUD extension)."""
            ...

        @property
        def x_origin(self) -> str | None:
            """Structural member projected from the owning model.

            Origin of attribute definition (server-specific X-ORIGIN extension).
            """
            ...

        @property
        def x_file_ref(self) -> str | None:
            """Structural member projected from the owning model.

            File reference for attribute definition (server-specific X-FILE-REF
            extension).
            """
            ...

        @property
        def x_name(self) -> str | None:
            """Extended name for attribute (server-specific X-NAME extension)."""
            ...

        @property
        def x_alias(self) -> str | None:
            """Extended alias for attribute (server-specific X-ALIAS extension)."""
            ...

        @property
        def x_oid(self) -> str | None:
            """Extended OID for attribute (server-specific X-OID extension)."""
            ...

        @property
        def metadata(
            self,
        ) -> FlextLdifLdifProtocolsGeneratedModelsServerMetadata.ServerMetadata | None:
            """Server-specific metadata for schema attribute."""
            ...

    @runtime_checkable
    class Syntax(FlextLdifProtocolsElements.SchemaElement, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def oid(self) -> str:
            """Syntax OID (RFC 4517, format: 1.3.6.1.4.1.1466.115.121.1.X)."""
            ...

        @property
        def name(self) -> str | None:
            """Human-readable syntax name (e.g., 'Boolean', 'Integer')."""
            ...

        @property
        def desc(self) -> str | None:
            """Syntax description and purpose."""
            ...

        @property
        def type_category(self) -> str:
            """Syntax type category: string, integer, binary, dn, time, boolean."""
            ...

        @property
        def is_binary(self) -> bool:
            """Whether this syntax uses binary encoding."""
            ...

        @property
        def max_length(self) -> int | None:
            """Maximum length in bytes (if applicable)."""
            ...

        @property
        def case_insensitive(self) -> bool:
            """Whether comparisons are case-insensitive."""
            ...

        @property
        def allows_multivalued(self) -> bool:
            """Whether attributes using this syntax can be multivalued."""
            ...

        @property
        def encoding(
            self,
        ) -> FlextLdifConstantsBaseParts.FlextLdifConstantsEnums.Encoding:
            """Expected character encoding (utf-8, ascii, iso-8859-1, etc.)."""
            ...

        @property
        def validation_pattern(self) -> str | None:
            """Optional regex pattern for value validation."""
            ...

        @property
        def metadata(
            self,
        ) -> FlextLdifLdifProtocolsGeneratedModelsServerMetadata.ServerMetadata | None:
            """Server-specific server metadata."""
            ...

    @runtime_checkable
    class SchemaObjectClass(FlextLdifProtocolsElements.SchemaElement, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def name(self) -> str:
            """Object class name."""
            ...

        @property
        def oid(self) -> str:
            """Object class OID."""
            ...

        @property
        def desc(self) -> str | None:
            """Object class description (RFC 4512 DESC)."""
            ...

        @property
        def sup(self) -> str | MutableSequence[str] | None:
            """Superior object class(es) (RFC 4512 SUP)."""
            ...

        @property
        def kind(self) -> str:
            """Object class kind (RFC 4512: STRUCTURAL, AUXILIARY, ABSTRACT)."""
            ...

        @property
        def must(self) -> MutableSequence[str] | None:
            """Required attributes (RFC 4512 MUST)."""
            ...

        @property
        def may(self) -> MutableSequence[str] | None:
            """Optional attributes (RFC 4512 MAY)."""
            ...

        @property
        def metadata(
            self,
        ) -> FlextLdifLdifProtocolsGeneratedModelsServerMetadata.ServerMetadata | None:
            """Server-specific metadata for schema object class."""
            ...


__all__: list[str] = [
    "FlextLdifProtocolsDomainSchema",
]
