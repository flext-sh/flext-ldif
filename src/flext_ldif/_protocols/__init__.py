# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Protocols package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports

if _t.TYPE_CHECKING:
    import flext_ldif._protocols.base as _flext_ldif__protocols_base

    base = _flext_ldif__protocols_base
    import flext_ldif._protocols.domain as _flext_ldif__protocols_domain
    from flext_ldif._protocols.base import FlextLdifProtocolsBase

    domain = _flext_ldif__protocols_domain
    from flext_ldif._protocols.domain import FlextLdifProtocolsDomain
_LAZY_IMPORTS = {
    "FlextLdifProtocolsBase": ("flext_ldif._protocols.base", "FlextLdifProtocolsBase"),
    "FlextLdifProtocolsDomain": (
        "flext_ldif._protocols.domain",
        "FlextLdifProtocolsDomain",
    ),
    "base": "flext_ldif._protocols.base",
    "domain": "flext_ldif._protocols.domain",
}

__all__ = [
    "FlextLdifProtocolsBase",
    "FlextLdifProtocolsDomain",
    "base",
    "domain",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
