# AUTO-GENERATED FILE — Regenerate with: make gen
"""Rfc package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.servers._rfc.acl import FlextLdifServersRfcAcl
    from flext_ldif.servers._rfc.constants import FlextLdifServersRfcConstants
    from flext_ldif.servers._rfc.entry import FlextLdifServersRfcEntry
    from flext_ldif.servers._rfc.schema import FlextLdifServersRfcSchema
_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".acl": ("FlextLdifServersRfcAcl",),
        ".constants": ("FlextLdifServersRfcConstants",),
        ".entry": ("FlextLdifServersRfcEntry",),
        ".schema": ("FlextLdifServersRfcSchema",),
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
