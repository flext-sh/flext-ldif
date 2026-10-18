"""SchemaServer protocol - Schema server contract.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing TYPE_CHECKING, Protocol, runtime_checkable

from flext_ldif import p, t

if TYPE_CHECKING:
    from flext_ldif._protocols._server_parts import (
        SchemaAttributeProtocol,
        SchemaObjectClassProtocol,
    )


@runtime_checkable
class SchemaServerProtocol(Protocol):
    """Schema server contract."""

    def parse_server(
        self,
        value: str,
    ) -> p.Result[SchemaAttributeProtocol | SchemaObjectClassProtocol]:
        """Parse a schema definition into a schema item."""
        ...

    def parse_input(
        self,
        schema_text: str,
    ) -> p.Result[SchemaAttributeProtocol | SchemaObjectClassProtocol]:
        """Parse a schema definition (compatibility entrypoint)."""
        ...

    def parse_attribute(self, definition: str) -> p.Result[SchemaAttributeProtocol]:
        """Parse an attributeType definition."""
        ...

    def parse_objectclass(
        self,
        definition: str,
    ) -> p.Result[SchemaObjectClassProtocol]:
        """Parse an objectClass definition."""
        ...

    def can_handle_attribute(
        self,
        attr_definition: str | SchemaAttributeProtocol,
    ) -> bool:
        """Check if this server can handle a schema attribute."""
        ...

    def can_handle_objectclass(
        self,
        oc_definition: str | SchemaObjectClassProtocol,
    ) -> bool:
        """Check if this server can handle a schema objectClass."""
        ...

    def write(
        self,
        model: SchemaAttributeProtocol | SchemaObjectClassProtocol,
    ) -> p.Result[str]:
        """Serialize a schema item."""
        ...

    def write_attribute(self, attr_data: SchemaAttributeProtocol) -> p.Result[str]:
        """Serialize an attributeType definition."""
        ...

    def write_objectclass(self, oc_data: SchemaObjectClassProtocol) -> p.Result[str]:
        """Serialize an objectClass definition."""
        ...


__all__: tuple[str, ...] = ("SchemaServerProtocol",)