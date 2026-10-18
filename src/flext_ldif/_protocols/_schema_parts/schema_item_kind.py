"""SchemaItemKind protocol - Schema item kind enumeration.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class SchemaItemKindProtocol(Protocol):
    """Schema item kind enumeration."""

    ATTRIBUTE: str
    OBJECTCLASS: str


__all__: tuple[str, ...] = ("SchemaItemKindProtocol",)
