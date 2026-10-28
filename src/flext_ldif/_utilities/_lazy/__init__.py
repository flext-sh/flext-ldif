# AUTO-GENERATED FILE — Regenerate with: make gen
"""Internal package for lazy.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._utilities._lazy.meta import FlextLdifUtilitiesLazyMeta
    from flext_ldif._utilities._lazy.tree import FlextLdifUtilitiesLazyTree

__all__: tuple[str, ...] = (
    "FlextLdifUtilitiesLazyMeta",
    "FlextLdifUtilitiesLazyTree",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdifUtilitiesLazyMeta": ".meta",
        "FlextLdifUtilitiesLazyTree": ".tree",
    }),
    public_exports=__all__,
)
