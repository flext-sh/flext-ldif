# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Utilities. Server package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._utilities._server.config import FlextLdifUtilitiesServerConfig
    from flext_ldif._utilities._server.detect import FlextLdifUtilitiesServerDetect
    from flext_ldif._utilities._server.server_type import (
        FlextLdifUtilitiesServerServerType,
    )


__all__: tuple[str, ...] = (
    "FlextLdifUtilitiesServerConfig",
    "FlextLdifUtilitiesServerDetect",
    "FlextLdifUtilitiesServerServerType",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdifUtilitiesServerConfig": ".config",
        "FlextLdifUtilitiesServerDetect": ".detect",
        "FlextLdifUtilitiesServerServerType": ".server_type",
    }),
    public_exports=__all__,
)
