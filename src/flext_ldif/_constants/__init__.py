# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Constants package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports

if _t.TYPE_CHECKING:
    import flext_ldif._constants.base as _flext_ldif__constants_base

    base = _flext_ldif__constants_base
    import flext_ldif._constants.enums as _flext_ldif__constants_enums
    from flext_ldif._constants.base import FlextLdifConstantsBase

    enums = _flext_ldif__constants_enums
    from flext_ldif._constants.enums import FlextLdifConstantsEnums
_LAZY_IMPORTS = {
    "FlextLdifConstantsBase": ("flext_ldif._constants.base", "FlextLdifConstantsBase"),
    "FlextLdifConstantsEnums": (
        "flext_ldif._constants.enums",
        "FlextLdifConstantsEnums",
    ),
    "base": "flext_ldif._constants.base",
    "enums": "flext_ldif._constants.enums",
}

__all__ = [
    "FlextLdifConstantsBase",
    "FlextLdifConstantsEnums",
    "base",
    "enums",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
