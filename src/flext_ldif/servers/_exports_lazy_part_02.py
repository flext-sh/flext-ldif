# AUTO-GENERATED FILE — Regenerate with: make gen
"""Lazy export map part."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map

FLEXT_LDIF_SERVERS_LAZY_IMPORTS_PART_02 = build_lazy_import_map(
    {
        "._base": ("_base",),
        "._oid": ("_oid",),
        "._oud": ("_oud",),
        "._oud.transform": ("FlextLdifServersOudTransformMixin",),
        "._oud.utilities": ("FlextLdifServersOudUtilities",),
        "._rfc": ("_rfc",),
        "._rfc.acl": ("FlextLdifServersRfcAcl",),
        "._rfc.constants": ("FlextLdifServersRfcConstants",),
        "._rfc.entry": ("FlextLdifServersRfcEntry",),
        "._rfc.schema": ("FlextLdifServersRfcSchema",),
        ".relaxed": ("FlextLdifServersRelaxed",),
        ".rfc": ("FlextLdifServersRfc",),
        ".tivoli": ("FlextLdifServersTivoli",),
    },
)

__all__: list[str] = ["FLEXT_LDIF_SERVERS_LAZY_IMPORTS_PART_02"]
