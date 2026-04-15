# AUTO-GENERATED FILE — Regenerate with: make gen
"""Servers package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".test_apache_quirks": ("test_apache_quirks",),
        ".test_ds389_quirks": ("test_ds389_quirks",),
        ".test_edge_cases": ("test_edge_cases",),
        ".test_novell_quirks": ("test_novell_quirks",),
        ".test_oid_quirks": ("test_oid_quirks",),
        ".test_relaxed_quirks": ("test_relaxed_quirks",),
        ".test_schema_transformer": ("test_schema_transformer",),
        "flext_ldif": (
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
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
