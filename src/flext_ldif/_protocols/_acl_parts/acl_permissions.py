"""AclPermissions protocol - ACL permission flag set.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_ldif import c, t

if TYPE_CHECKING:
    from flext_ldif._protocols import FlextLdifProtocolsBase


@runtime_checkable
class AclPermissionsProtocol(Protocol):
    """ACL permission flag set."""

    @property
    def read(self) -> bool:
        """Whether read is allowed."""
        ...

    @property
    def write(self) -> bool:
        """Whether write is allowed."""
        ...

    @property
    def delete(self) -> bool:
        """Whether delete is allowed."""
        ...

    @property
    def add(self) -> bool:
        """Whether add is allowed."""
        ...

    @property
    def search(self) -> bool:
        """Whether search is allowed."""
        ...

    @property
    def compare(self) -> bool:
        """Whether compare is allowed."""
        ...


__all__: tuple[str, ...] = ("AclPermissionsProtocol",)
