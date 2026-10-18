"""AclEvaluationResult protocol - ACL evaluation result contract.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_ldif import c, t

if TYPE_CHECKING:
    from flext_ldif._protocols._acl_parts import AclProtocol


@runtime_checkable
class AclEvaluationResultProtocol(Protocol):
    """ACL evaluation result contract."""

    @property
    def granted(self) -> bool:
        """Whether the ACL granted access."""
        ...

    @property
    def matched_acl(self) -> AclProtocol | None:
        """ACL rule that matched the evaluation."""
        ...

    @property
    def message(self) -> str:
        """Human-readable evaluation result message."""
        ...


__all__: tuple[str, ...] = ("AclEvaluationResultProtocol",)
