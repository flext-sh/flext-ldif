# AUTO-GENERATED FILE — Regenerate with: make gen
"""Internal package for object_class.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._utilities._object_class.fix import FlextLdifUtilitiesObjectClassFix

__all__: tuple[str, ...] = ("FlextLdifUtilitiesObjectClassFix",)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdifUtilitiesObjectClassFix": ".fix",
    }),
    public_exports=__all__,
)
