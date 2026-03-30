# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Base server classes for LDIF/LDAP processing."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.servers._base import (
        acl as acl,
        constants as constants,
        entry as entry,
        schema as schema,
    )
    from flext_ldif.servers._base.acl import (
        FlextLdifServersBaseSchemaAcl as FlextLdifServersBaseSchemaAcl,
    )
    from flext_ldif.servers._base.constants import (
        FlextLdifQuirkMethodsMixin as FlextLdifQuirkMethodsMixin,
        FlextLdifServersBaseConstants as FlextLdifServersBaseConstants,
        FlextLdifServersBaseQuirkHelpers as FlextLdifServersBaseQuirkHelpers,
    )
    from flext_ldif.servers._base.entry import (
        FlextLdifServersBaseEntry as FlextLdifServersBaseEntry,
    )
    from flext_ldif.servers._base.schema import (
        FlextLdifServersBaseSchema as FlextLdifServersBaseSchema,
        logger as logger,
    )

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "FlextLdifQuirkMethodsMixin": [
        "flext_ldif.servers._base.constants",
        "FlextLdifQuirkMethodsMixin",
    ],
    "FlextLdifServersBaseConstants": [
        "flext_ldif.servers._base.constants",
        "FlextLdifServersBaseConstants",
    ],
    "FlextLdifServersBaseEntry": [
        "flext_ldif.servers._base.entry",
        "FlextLdifServersBaseEntry",
    ],
    "FlextLdifServersBaseQuirkHelpers": [
        "flext_ldif.servers._base.constants",
        "FlextLdifServersBaseQuirkHelpers",
    ],
    "FlextLdifServersBaseSchema": [
        "flext_ldif.servers._base.schema",
        "FlextLdifServersBaseSchema",
    ],
    "FlextLdifServersBaseSchemaAcl": [
        "flext_ldif.servers._base.acl",
        "FlextLdifServersBaseSchemaAcl",
    ],
    "acl": ["flext_ldif.servers._base.acl", ""],
    "constants": ["flext_ldif.servers._base.constants", ""],
    "entry": ["flext_ldif.servers._base.entry", ""],
    "logger": ["flext_ldif.servers._base.schema", "logger"],
    "schema": ["flext_ldif.servers._base.schema", ""],
}

_EXPORTS: Sequence[str] = [
    "FlextLdifQuirkMethodsMixin",
    "FlextLdifServersBaseConstants",
    "FlextLdifServersBaseEntry",
    "FlextLdifServersBaseQuirkHelpers",
    "FlextLdifServersBaseSchema",
    "FlextLdifServersBaseSchemaAcl",
    "acl",
    "constants",
    "entry",
    "logger",
    "schema",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
