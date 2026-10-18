"""SchemaObjectClass protocol - LDIF schema objectClass contract.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class SchemaObjectClassProtocol(Protocol):
    """LDIF schema objectClass contract."""

    @property
    def oid(self) -> str:
        """The objectClass OID."""
        ...

    @property
    def name(self) -> str:
        """The objectClass name."""
        ...


__all__: tuple[str, ...] = ("SchemaObjectClassProtocol",)
