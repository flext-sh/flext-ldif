"""Extracted facade class for lazy.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._utilities._lazy import (
    FlextLdifUtilitiesLazyMeta,
    FlextLdifUtilitiesLazyTree,
)


class FlextLdifUtilitiesLazy(
    FlextLdifUtilitiesLazyMeta,
    FlextLdifUtilitiesLazyTree,
):
    """Facade for lazy."""


__all__: list[str] = ["FlextLdifUtilitiesLazy"]
