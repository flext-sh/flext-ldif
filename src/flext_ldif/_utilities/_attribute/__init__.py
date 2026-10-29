# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Utilities. Attribute package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._utilities._attribute.validation import (
        FlextLdifUtilitiesAttributeValidation,
    )


__all__: tuple[str, ...] = ("FlextLdifUtilitiesAttributeValidation",)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({"FlextLdifUtilitiesAttributeValidation": ".validation"}),
    public_exports=__all__,
)
