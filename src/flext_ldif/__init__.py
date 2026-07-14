# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports
from flext_ldif.__version__ import (
    __author__,
    __author_email__,
    __description__,
    __license__,
    __title__,
    __url__,
    __version__,
    __version_info__,
)

if TYPE_CHECKING:
    from flext_cli import d, e, h, r, x

    from ._settings import FlextLdifSettings, settings
    from .api import FlextLdif, ldif
    from .base import FlextLdifServiceBase, s
    from .constants import FlextLdifConstants, FlextLdifConstants as c
    from .models import FlextLdifModels, FlextLdifModels as m
    from .protocols import FlextLdifProtocols, FlextLdifProtocols as p
    from .shared import FlextLdifShared
    from .typings import FlextLdifTypes, FlextLdifTypes as t
    from .utilities import FlextLdifUtilities, FlextLdifUtilities as u

    _ = (
        c,
        FlextLdifConstants,
        t,
        FlextLdifTypes,
        p,
        FlextLdifProtocols,
        m,
        FlextLdifModels,
        u,
        FlextLdifUtilities,
        d,
        e,
        h,
        r,
        x,
        s,
        FlextLdifServiceBase,
        FlextLdifSettings,
        settings,
        FlextLdif,
        ldif,
        FlextLdifShared,
    )


_LAZY_MODULES: dict[str, tuple[str, ...]] = {
    "._settings": (
        "FlextLdifSettings",
        "settings",
    ),
    ".api": (
        "FlextLdif",
        "ldif",
    ),
    ".base": (
        "FlextLdifServiceBase",
        "s",
    ),
    ".constants": (
        "FlextLdifConstants",
        "c",
    ),
    ".models": (
        "FlextLdifModels",
        "m",
    ),
    ".protocols": (
        "FlextLdifProtocols",
        "p",
    ),
    ".shared": ("FlextLdifShared",),
    ".typings": (
        "FlextLdifTypes",
        "t",
    ),
    ".utilities": (
        "FlextLdifUtilities",
        "u",
    ),
    "flext_cli": (
        "d",
        "e",
        "h",
        "r",
        "x",
    ),
}


_LAZY_ALIAS_GROUPS: dict[str, tuple[tuple[str, str], ...]] = {}


_LAZY_IMPORTS = build_lazy_import_map(
    _LAZY_MODULES,
    alias_groups=_LAZY_ALIAS_GROUPS,
    sort_keys=False,
)

_DIRECT_IMPORTS: tuple[str, ...] = (
    "FlextLdif",
    "FlextLdifConstants",
    "FlextLdifModels",
    "FlextLdifProtocols",
    "FlextLdifServiceBase",
    "FlextLdifSettings",
    "FlextLdifShared",
    "FlextLdifTypes",
    "FlextLdifUtilities",
    "__author__",
    "__author_email__",
    "__description__",
    "__license__",
    "__title__",
    "__url__",
    "__version__",
    "__version_info__",
    "build_lazy_import_map",
    "c",
    "d",
    "e",
    "h",
    "install_lazy_exports",
    "ldif",
    "m",
    "p",
    "r",
    "s",
    "settings",
    "t",
    "u",
    "x",
)

__all__: tuple[str, ...] = (
    "FlextLdif",
    "FlextLdifConstants",
    "FlextLdifModels",
    "FlextLdifProtocols",
    "FlextLdifServiceBase",
    "FlextLdifSettings",
    "FlextLdifShared",
    "FlextLdifTypes",
    "FlextLdifUtilities",
    "__author__",
    "__author_email__",
    "__description__",
    "__license__",
    "__title__",
    "__url__",
    "__version__",
    "__version_info__",
    "c",
    "d",
    "e",
    "h",
    "ldif",
    "m",
    "p",
    "r",
    "s",
    "settings",
    "t",
    "u",
    "x",
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    public_exports=__all__,
)
