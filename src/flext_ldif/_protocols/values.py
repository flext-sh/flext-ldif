"""Structural contracts for model-backed LDIF values.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class FlextLdifProtocolsValues(Protocol):
    """Protocol-only view of canonical LDIF Pydantic values."""


__all__: list[str] = ["FlextLdifProtocolsValues"]
