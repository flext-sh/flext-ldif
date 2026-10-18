"""ServerConstants protocol - Constants class for a server type.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Protocol, runtime_checkable

from flext_ldif import c, p

if TYPE_CHECKING:
    from flext_ldif._protocols._server_parts import (
        SchemaServerProtocol,
        AclServerProtocol,
        EntryServerProtocol,
    )


@runtime_checkable
class ServerConstantsProtocol(Protocol):
    """Constants class for a server type."""

    server_type: ClassVar[str]
    priority: ClassVar[int]

    SchemaServer: ClassVar[type[SchemaServerProtocol]]
    AclServer: ClassVar[type[AclServerProtocol]]
    EntryServer: ClassVar[type[EntryServerProtocol]]


__all__: tuple[str, ...] = ("ServerConstantsProtocol",)
