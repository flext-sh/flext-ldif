"""Config namespace module for flext-ldif.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_ldif import FlextLdifConfig


class FlextLdifModelsConfig:
    """Publish the configuration schema from its independent layer-zero owner."""

    ConfigNamespace: ClassVar[type[FlextLdifConfig.ConfigNamespace]] = (
        FlextLdifConfig.ConfigNamespace
    )


__all__: list[str] = ["FlextLdifModelsConfig"]
