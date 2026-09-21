# AUTO-GENERATED FILE — Regenerate with: make gen
"""Examples package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_core import d, e, h, r, x
    from flext_ldif import FlextLdifConstants, s

    from .constants import ExamplesFlextLdifConstants, ExamplesFlextLdifConstants as c
    from .models import ExamplesFlextLdifModels, ExamplesFlextLdifModels as m
    from .protocols import ExamplesFlextLdifProtocols, ExamplesFlextLdifProtocols as p
    from .typings import ExamplesFlextLdifTypes, ExamplesFlextLdifTypes as t
    from .utilities import ExamplesFlextLdifUtilities, ExamplesFlextLdifUtilities as u
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
            ".constants": ("ExamplesFlextLdifConstants", "c"),
            ".models": ("ExamplesFlextLdifModels", "m"),
            ".protocols": ("ExamplesFlextLdifProtocols", "p"),
            ".typings": ("ExamplesFlextLdifTypes", "t"),
            ".utilities": ("ExamplesFlextLdifUtilities", "u"),
            "flext_core": ("d", "e", "h", "r", "x"),
            "flext_ldif": ("FlextLdifConstants", "s"),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
