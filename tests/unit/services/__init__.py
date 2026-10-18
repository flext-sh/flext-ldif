# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests.unit.services package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from tests.unit.services.typings import TestsFlextLdifServiceTypings


__all__: tuple[str, ...] = ("TestsFlextLdifServiceTypings",)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({"TestsFlextLdifServiceTypings": ".typings"}),
    public_exports=__all__,
)
