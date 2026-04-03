# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Base package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from flext_ldif import acl, constants, entry, schema
    from flext_ldif.acl import FlextLdifServersBaseSchemaAcl, acl_attribute_name
    from flext_ldif.constants import FlextLdifServersBaseConstants
    from flext_ldif.entry import FlextLdifServersBaseEntry
    from flext_ldif.schema import (
        FlextLdifServersBaseSchema,
        description,
        exclude,
        logger,
        priority,
        repr as repr_,
        server_type,
    )

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "FlextLdifServersBaseConstants": "flext_ldif.constants",
    "FlextLdifServersBaseEntry": "flext_ldif.entry",
    "FlextLdifServersBaseSchema": "flext_ldif.schema",
    "FlextLdifServersBaseSchemaAcl": "flext_ldif.acl",
    "acl": "flext_ldif.acl",
    "acl_attribute_name": "flext_ldif.acl",
    "constants": "flext_ldif.constants",
    "description": "flext_ldif.schema",
    "entry": "flext_ldif.entry",
    "exclude": "flext_ldif.schema",
    "logger": "flext_ldif.schema",
    "priority": "flext_ldif.schema",
    "repr": "flext_ldif.schema",
    "schema": "flext_ldif.schema",
    "server_type": "flext_ldif.schema",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
