"""AclServer protocol - ACL server contract.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_ldif import p, t

if TYPE_CHECKING:
    from flext_ldif._protocols._acl_parts import AclProtocol


@runtime_checkable
class AclServerProtocol(Protocol):
    """ACL server contract."""

    def resolve_acl_attributes(self) -> t.MutableSequenceOf[str]:
        """Return this server's ACL entry attributes in extraction order."""
        ...

    def parse_server(self, value: str) -> p.Result[AclProtocol]:
        """Parse an ACL line into an ACL model."""
        ...

    def can_handle_acl(self, acl_line: str | AclProtocol) -> bool:
        """Check if this server can handle an ACL line."""
        ...

    def write(self, acl_data: AclProtocol) -> p.Result[str]:
        """Serialize an ACL model."""
        ...


__all__: tuple[str, ...] = ("AclServerProtocol",)
