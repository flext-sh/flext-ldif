# AUTO-GENERATED FILE — Regenerate with: make gen
"""Examples package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif import (
        c as c,
        d as d,
        e as e,
        h as h,
        m as m,
        p,
        r as r,
        s as s,
        t as t,
        u,
        x as x,
    )
_LAZY_IMPORTS = build_lazy_import_map({
    ".demo_structured_migration": ("demo_structured_migration",),
    "flext_ldif": ("c", "d", "e", "h", "m", "p", "r", "s", "t", "u", "x"),
})


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
