# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Oud package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from flext_ldif import acl, constants, entry, schema, utilities
    from flext_ldif.acl import FlextLdifServersOudAcl
    from flext_ldif.constants import FlextLdifServersOudConstants, c
    from flext_ldif.entry import FlextLdifServersOudEntry
    from flext_ldif.schema import FlextLdifServersOudSchema, logger
    from flext_ldif.utilities import FlextLdifServersOudUtilities

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "FlextLdifServersOudAcl": "flext_ldif.acl",
    "FlextLdifServersOudConstants": "flext_ldif.constants",
    "FlextLdifServersOudEntry": "flext_ldif.entry",
    "FlextLdifServersOudSchema": "flext_ldif.schema",
    "FlextLdifServersOudUtilities": "flext_ldif.utilities",
    "acl": "flext_ldif.acl",
    "c": "flext_ldif.constants",
    "constants": "flext_ldif.constants",
    "entry": "flext_ldif.entry",
    "logger": "flext_ldif.schema",
    "schema": "flext_ldif.schema",
    "utilities": "flext_ldif.utilities",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
