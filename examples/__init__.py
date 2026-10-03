# AUTO-GENERATED FILE — Regenerate with: make gen
"""Examples package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from examples.constants import ExamplesFlextLdifConstants
    from examples.models import ExamplesFlextLdifModels
    from examples.protocols import ExamplesFlextLdifProtocols
    from examples.typings import ExamplesFlextLdifTypes
    from examples.utilities import ExamplesFlextLdifUtilities
    from flext_ldif import c, d, e, h, m, p, r, s, t, u, x


__all__: tuple[str, ...] = (
    "ExamplesFlextLdifConstants",
    "ExamplesFlextLdifModels",
    "ExamplesFlextLdifProtocols",
    "ExamplesFlextLdifTypes",
    "ExamplesFlextLdifUtilities",
    "c",
    "d",
    "e",
    "h",
    "m",
    "p",
    "r",
    "s",
    "t",
    "u",
    "x",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".constants": ("ExamplesFlextLdifConstants",),
            ".models": ("ExamplesFlextLdifModels",),
            ".protocols": ("ExamplesFlextLdifProtocols",),
            ".typings": ("ExamplesFlextLdifTypes",),
            ".utilities": ("ExamplesFlextLdifUtilities",),
            "flext_ldif": ("c", "d", "e", "h", "m", "p", "r", "s", "t", "u", "x"),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    ),
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
