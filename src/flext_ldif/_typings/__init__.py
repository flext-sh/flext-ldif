# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Typings package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports

if _t.TYPE_CHECKING:
    import flext_ldif._typings.base as _flext_ldif__typings_base

    base = _flext_ldif__typings_base
    import flext_ldif._typings.domain as _flext_ldif__typings_domain
    from flext_ldif._typings.base import FlextLdifTypesBase

    domain = _flext_ldif__typings_domain
    from flext_ldif._typings.domain import FlextLdifTypesDomain
_LAZY_IMPORTS = {
    "FlextLdifTypesBase": ("flext_ldif._typings.base", "FlextLdifTypesBase"),
    "FlextLdifTypesDomain": ("flext_ldif._typings.domain", "FlextLdifTypesDomain"),
    "base": "flext_ldif._typings.base",
    "domain": "flext_ldif._typings.domain",
}

__all__ = [
    "FlextLdifTypesBase",
    "FlextLdifTypesDomain",
    "base",
    "domain",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
