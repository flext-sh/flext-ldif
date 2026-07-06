# AUTO-GENERATED FILE — Regenerate with: make gen
"""Protocols package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._protocols.base import FlextLdifProtocolsBase
    from flext_ldif._protocols.domain import FlextLdifProtocolsDomain
_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".base": ("FlextLdifProtocolsBase",),
        ".domain": ("FlextLdifProtocolsDomain",),
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
