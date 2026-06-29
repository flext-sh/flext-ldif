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
    from flext_cli import d as d, h as h, x as x
    from flext_ldif.api import FlextLdif as FlextLdif, ldif as ldif
    from flext_ldif.base import FlextLdifServiceBase as FlextLdifServiceBase, s as s
    from flext_ldif.constants import FlextLdifConstants as FlextLdifConstants, c as c
    from flext_ldif.exceptions import FlextLdifExceptions as FlextLdifExceptions, e as e
    from flext_ldif.models import FlextLdifModels as FlextLdifModels, m as m
    from flext_ldif.protocols import FlextLdifProtocols as FlextLdifProtocols, p as p
    from flext_ldif.result import FlextLdifResult as FlextLdifResult, r as r
    from flext_ldif.settings import FlextLdifSettings as FlextLdifSettings
    from flext_ldif.shared import FlextLdifShared as FlextLdifShared
    from flext_ldif.typings import FlextLdifTypes as FlextLdifTypes, t as t
    from flext_ldif.utilities import FlextLdifUtilities as FlextLdifUtilities, u as u
_LAZY_IMPORTS = build_lazy_import_map(
    {
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
        ".exceptions": (
            "FlextLdifExceptions",
            "e",
        ),
        ".models": (
            "FlextLdifModels",
            "m",
        ),
        ".protocols": (
            "FlextLdifProtocols",
            "p",
        ),
        ".result": (
            "FlextLdifResult",
            "r",
        ),
        ".settings": ("FlextLdifSettings",),
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
            "h",
            "x",
        ),
    },
)


__all__: tuple[str, ...] = (
    "FlextLdif",
    "FlextLdifConstants",
    "FlextLdifExceptions",
    "FlextLdifModels",
    "FlextLdifProtocols",
    "FlextLdifResult",
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
