"""ChangeOperation protocol - Structured modify block.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_ldif import c, t

if TYPE_CHECKING:
    from flext_ldif._protocols._entry_parts import ChangeOperationValueProtocol


@runtime_checkable
class ChangeOperationProtocol(Protocol):
    """Structured modify block."""

    @property
    def operation(self) -> c.Ldif.ChangeOperation:
        """The modify operation type."""
        ...

    @property
    def attribute(self) -> str:
        """Target attribute for the modify block."""
        ...

    @property
    def values(self) -> t.SequenceOf[ChangeOperationValueProtocol]:
        """Decoded values in the block."""
        ...


__all__: tuple[str, ...] = ("ChangeOperationProtocol",)
