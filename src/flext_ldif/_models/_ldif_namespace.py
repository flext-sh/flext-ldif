"""Ldif namespace module.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_models/_ldif_namespace
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_core import m


class FlextLdifNamespace(m.BaseModel):
    """Open, frozen namespace exposing every ``config/*.yaml`` domain model-less."""

    model_config: ClassVar[m.SettingsConfigDict] = m.SettingsConfigDict(
        extra="allow",
        frozen=True,
    )


__all__: list[str] = ["FlextLdifNamespace"]
