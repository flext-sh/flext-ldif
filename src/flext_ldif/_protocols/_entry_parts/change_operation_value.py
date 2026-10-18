"""ChangeOperationValue protocol - Single decoded value in a modify block.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from flext_ldif import c


@runtime_checkable
class ChangeOperationValueProtocol(Protocol):
    """Single decoded value in a modify block."""

    value: str
    value_origin: c.Ldif.ValueOrigin
    raw_value: str | None


__all__: tuple[str, ...] = ("ChangeOperationValueProtocol",)
