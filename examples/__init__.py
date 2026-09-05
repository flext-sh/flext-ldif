# AUTO-GENERATED FILE — Regenerate with: make gen
"""Examples package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_core import (
        FlextLdifConstants,
        FlextLdifConstants as c,
        d,
        e,
        h,
        m,
        p,
        r,
        s,
        t,
        u,
        x,
    )

    from .constants import ExamplesFlextLdifConstants
    from .models import ExamplesFlextLdifModels
    from .protocols import ExamplesFlextLdifProtocols
    from .typings import ExamplesFlextLdifTypes
    from .utilities import ExamplesFlextLdifUtilities
__all__: tuple[str, ...] = (
    "ExamplesFlextLdifConstants",
    "ExamplesFlextLdifModels",
    "ExamplesFlextLdifProtocols",
    "ExamplesFlextLdifTypes",
    "ExamplesFlextLdifUtilities",
    "FlextLdifConstants",
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
            "flext_core": (
                "FlextLdifConstants",
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
            ),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
