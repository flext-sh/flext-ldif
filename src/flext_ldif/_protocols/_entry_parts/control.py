"""Control protocol - Structured LDIF control line.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class ControlProtocol(Protocol):
    """Structured LDIF control line."""

    @property
    def control_type(self) -> str:
        """Read the unchanged LDAP control identity."""
        ...

    @property
    def criticality(self) -> bool | None:
        """Read the declared criticality flag."""
        ...

    @property
    def control_value(self) -> str | None:
        """Read the optional decoded control value."""
        ...

    @property
    def control_value_origin(self) -> str | None:
        """Read the optional original encoding."""
        ...

    @property
    def raw_value(self) -> str | None:
        """Read the original serialized control payload."""
        ...


__all__: tuple[str, ...] = ("ControlProtocol",)
