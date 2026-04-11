# AUTO-GENERATED FILE — Regenerate with: make gen
"""Examples package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if _t.TYPE_CHECKING:
    from flext_core.decorators import d
    from flext_core.exceptions import e
    from flext_core.handlers import h
    from flext_core.mixins import x
    from flext_core.result import r
    from flext_ldif.base import s
    from flext_ldif.constants import c
    from flext_ldif.models import m
    from flext_ldif.protocols import p
    from flext_ldif.typings import t
    from flext_ldif.utilities import u
_LAZY_IMPORTS = build_lazy_import_map(
    {
        "flext_core.decorators": ("d",),
        "flext_core.exceptions": ("e",),
        "flext_core.handlers": ("h",),
        "flext_core.mixins": ("x",),
        "flext_core.result": ("r",),
        "flext_ldif.base": ("s",),
        "flext_ldif.constants": ("c",),
        "flext_ldif.models": ("m",),
        "flext_ldif.protocols": ("p",),
        "flext_ldif.typings": ("t",),
        "flext_ldif.utilities": ("u",),
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)

__all__ = [
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
]
