"""SchemaAttribute protocol - LDIF schema attribute contract.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class SchemaAttributeProtocol(Protocol):
    """LDIF schema attribute contract."""

    @property
    def oid(self) -> str:
        """The attribute OID."""
        ...

    @property
    def name(self) -> str:
        """The attribute name."""
        ...


__all__: tuple[str, ...] = ("SchemaAttributeProtocol",)
