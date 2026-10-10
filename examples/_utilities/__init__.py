# AUTO-GENERATED FILE — Regenerate with: make gen
"""Examples. Utilities package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import install_lazy_exports

if TYPE_CHECKING:
    from examples._utilities.base import ExamplesFlextLdifUtilitiesBase


__all__: tuple[str, ...] = ("ExamplesFlextLdifUtilitiesBase",)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({"ExamplesFlextLdifUtilitiesBase": ".base"}),
    public_exports=__all__,
)
