# AUTO-GENERATED FILE — Regenerate with: make gen
"""Base package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.servers._base.acl import FlextLdifServersBaseSchemaAcl
    from flext_ldif.servers._base.constants import FlextLdifServersBaseConstants
    from flext_ldif.servers._base.entry import FlextLdifServersBaseEntry
    from flext_ldif.servers._base.mixins import FlextLdifServerMethodsMixin
    from flext_ldif.servers._base.schema import FlextLdifServersBaseSchema
_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".acl": ("FlextLdifServersBaseSchemaAcl",),
        ".constants": ("FlextLdifServersBaseConstants",),
        ".entry": ("FlextLdifServersBaseEntry",),
        ".mixins": ("FlextLdifServerMethodsMixin",),
        ".schema": ("FlextLdifServersBaseSchema",),
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
