"""Config namespace module for flext-ldif.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_cli import m


class FlextLdifModelsConfig:
    """Config models for flext-ldif."""

    class ConfigNamespace(m.BaseModel):
        """Open, frozen namespace exposing every ``config/*.yaml`` domain."""

        model_config: ClassVar[m.ConfigDict] = m.ConfigDict(
            extra="allow",
            frozen=True,
        )


__all__: list[str] = ["FlextLdifModelsConfig"]
