"""ServerServer protocol - Structured server contract.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_ldif import c, p, t

if TYPE_CHECKING:
    from flext_ldif._protocols._server_parts import (
        SchemaServerProtocol,
        AclServerProtocol,
        EntryServerProtocol,
    )


@runtime_checkable
class ServerServerProtocol(Protocol):
    """Structured server contract used by services and tests."""

    server_type: str
    priority: int

    @property
    def schema_server(self) -> SchemaServerProtocol:
        """The schema server implementation."""
        ...

    @property
    def acl_server(self) -> AclServerProtocol:
        """ACL server implementation."""
        ...

    @property
    def entry_server(self) -> EntryServerProtocol:
        """The entry server implementation."""
        ...

    def parse_ldif(self, value: str) -> p.Result[p.Ldif.ParseResponse]:
        """Parse LDIF text through the server's entry implementation."""
        ...

    def write(
        self,
        entries: t.MutableSequenceOf[p.Ldif.Entry],
        write_options: p.Ldif.WriteFormatOptions | None = None,
    ) -> p.Result[str]:
        """Write canonical entries through the server's entry implementation."""
        ...


__all__: tuple[str, ...] = ("ServerServerProtocol",)
