"""AclResponse protocol - ACL extraction response payload.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_ldif import c, t

if TYPE_CHECKING:
    from flext_ldif._protocols._acl_parts import AclProtocol


@runtime_checkable
class AclResponseProtocol(Protocol):
    """ACL extraction response payload."""

    @property
    def acls(self) -> t.SequenceOf[AclProtocol]:
        """The extracted ACLs."""
        ...


__all__: tuple[str, ...] = ("AclResponseProtocol",)
