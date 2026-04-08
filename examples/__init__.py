# AUTO-GENERATED FILE — Regenerate with: make gen
"""Examples package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if _t.TYPE_CHECKING:
    from flext_core.constants import FlextConstants as c
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.models import FlextModels as m
    from flext_core.protocols import FlextProtocols as p
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
    from flext_core.typings import FlextTypes as t
    from flext_core.utilities import FlextUtilities as u
_LAZY_IMPORTS = build_lazy_import_map(
    {},
    alias_groups={
        "flext_core.constants": (("c", "FlextConstants"),),
        "flext_core.decorators": (("d", "FlextDecorators"),),
        "flext_core.exceptions": (("e", "FlextExceptions"),),
        "flext_core.handlers": (("h", "FlextHandlers"),),
        "flext_core.mixins": (("x", "FlextMixins"),),
        "flext_core.models": (("m", "FlextModels"),),
        "flext_core.protocols": (("p", "FlextProtocols"),),
        "flext_core.result": (("r", "FlextResult"),),
        "flext_core.service": (("s", "FlextService"),),
        "flext_core.typings": (("t", "FlextTypes"),),
        "flext_core.utilities": (("u", "FlextUtilities"),),
    },
)

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


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
