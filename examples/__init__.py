# AUTO-GENERATED FILE — Regenerate with: make gen
"""Examples package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
<<<<<<< HEAD
    from flext_cli import cli

    from flext_core import (
        core,
        d,
        e,
        h,
        lazy,
        lazy_attribute,
        normalize_lazy_imports,
        r,
        x,
    )
    from flext_ldif import c, config, ldif, m, main, p, s, settings, t, u
=======
    from flext_ldif import c, d, e, h, m, p, r, s, t, u, x
>>>>>>> recovery/rope-automation-20260921

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
    "c",
    "d",
    "e",
    "h",
<<<<<<< HEAD
    "lazy",
    "lazy_attribute",
    "ldif",
    "m",
    "main",
    "normalize_lazy_imports",
    "p",
    "r",
    "s",
    "settings",
=======
    "m",
    "p",
    "r",
    "s",
>>>>>>> recovery/rope-automation-20260921
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
<<<<<<< HEAD
            "flext_cli": ("cli",),
            "flext_core": (
                "core",
                "d",
                "e",
                "h",
                "lazy",
                "lazy_attribute",
                "normalize_lazy_imports",
                "r",
                "x",
            ),
            "flext_ldif": (
                "c",
                "config",
                "ldif",
                "m",
                "main",
                "p",
                "s",
                "settings",
                "t",
                "u",
            ),
=======
            "flext_ldif": ("c", "d", "e", "h", "m", "p", "r", "s", "t", "u", "x"),
>>>>>>> recovery/rope-automation-20260921
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
