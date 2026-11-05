# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/elements
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableSequence
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_cli import FlextCliProtocols

if TYPE_CHECKING:
    from flext_cli import p

    from flext_ldif import c


class FlextLdifProtocolsElements:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class SchemaElement(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def validation_metadata(self) -> p.ConfigMap | None:
            """Validation metadata captured during schema processing."""
            ...

        @property
        def has_metadata(self) -> bool:
            """Whether schema element has server metadata."""
            ...

        @property
        def has_server_extensions(self) -> bool:
            """Whether element has server-specific extensions."""
            ...

        @property
        def server_type(self) -> str:
            """The server type from metadata, default to RFC."""
            ...

    @runtime_checkable
    class AclElement(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        server_type: c.Ldif.ServerTypes
        validation_violations: MutableSequence[str]

        @property
        def validation_metadata(self) -> p.ConfigMap | None:
            """Validation metadata captured during ACL processing."""
            ...

        @property
        def has_server_servers(self) -> bool:
            """Whether element uses server-specific servers."""
            ...

        @property
        def valid(self) -> bool:
            """Whether ACL element passed validation."""
            ...


__all__: list[str] = [
    "FlextLdifProtocolsElements",
]
