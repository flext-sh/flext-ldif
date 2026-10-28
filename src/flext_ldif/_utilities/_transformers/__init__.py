# AUTO-GENERATED FILE — Regenerate with: make gen
"""Internal package for transformers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._utilities._transformers.attrs import (
        FlextLdifUtilitiesTransformersAttrs,
    )
    from flext_ldif._utilities._transformers.dn import FlextLdifUtilitiesTransformersDn

__all__: tuple[str, ...] = (
    "FlextLdifUtilitiesTransformersAttrs",
    "FlextLdifUtilitiesTransformersDn",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdifUtilitiesTransformersAttrs": ".attrs",
        "FlextLdifUtilitiesTransformersDn": ".dn",
    }),
    public_exports=__all__,
)
