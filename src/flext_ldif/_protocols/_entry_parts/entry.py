"""Entry model protocol - LDIF entry contract.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_ldif import c, t

if TYPE_CHECKING:
    from flext_ldif._protocols._entry_parts import (
        ChangeOperationProtocol,
        ControlProtocol,
    )


@runtime_checkable
class EntryProtocol(Protocol):
    """Entry model contract used across LDIF services."""

    @property
    def change_operations(self) -> t.SequenceOf[ChangeOperationProtocol]:
        """The change operations for modify records."""
        ...

    @property
    def dn(self) -> c.Ldif.ServerTypes | None:
        """The entry DN."""
        ...

    @property
    def attributes(self) -> t.MutableJsonMapping | None:
        """The entry attributes."""
        ...

    @property
    def changetype(self) -> c.Ldif.ChangeType | None:
        """The changetype when present."""
        ...

    @property
    def record_kind(self) -> c.Ldif.RecordKind:
        """Whether the record is content or change."""
        ...

    @property
    def controls(self) -> t.SequenceOf[ControlProtocol]:
        """The parsed LDIF controls."""
        ...

    @property
    def newrdn(self) -> str | None:
        """The newrdn for moddn/modrdn records."""
        ...

    @property
    def deleteoldrdn(self) -> bool | None:
        """The deleteoldrdn for moddn/modrdn records."""
        ...

    @property
    def newsuperior(self) -> str | None:
        """The newsuperior for moddn records."""
        ...


__all__: tuple[str, ...] = ("EntryProtocol",)
