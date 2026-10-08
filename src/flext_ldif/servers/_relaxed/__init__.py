# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif.servers. Relaxed package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.servers._relaxed.server_constants import (
        FlextLdifServersRelaxedConstants,
    )


__all__: tuple[str, ...] = ("FlextLdifServersRelaxedConstants",)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({"FlextLdifServersRelaxedConstants": ".server_constants"}),
    public_exports=__all__,
)
