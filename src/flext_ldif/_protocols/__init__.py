# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Protocols package."""

from __future__ import annotations

from flext_core.lazy import install_lazy_exports

_LAZY_IMPORTS = {
    "FlextLdifProtocolsBase": ("flext_ldif._protocols.base", "FlextLdifProtocolsBase"),
    "FlextLdifProtocolsDomain": (
        "flext_ldif._protocols.domain",
        "FlextLdifProtocolsDomain",
    ),
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
