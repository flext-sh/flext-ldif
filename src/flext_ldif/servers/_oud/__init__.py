# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""OUD (Oracle Unified Directory) Server Classes."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from flext_ldif.servers._oud import acl, constants, entry, schema, utilities
    from flext_ldif.servers._oud.acl import FlextLdifServersOudAcl
    from flext_ldif.servers._oud.constants import FlextLdifServersOudConstants, c
    from flext_ldif.servers._oud.entry import FlextLdifServersOudEntry
    from flext_ldif.servers._oud.schema import FlextLdifServersOudSchema, logger
    from flext_ldif.servers._oud.utilities import FlextLdifServersOudUtilities

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "FlextLdifServersOudAcl": "flext_ldif.servers._oud.acl",
    "FlextLdifServersOudConstants": "flext_ldif.servers._oud.constants",
    "FlextLdifServersOudEntry": "flext_ldif.servers._oud.entry",
    "FlextLdifServersOudSchema": "flext_ldif.servers._oud.schema",
    "FlextLdifServersOudUtilities": "flext_ldif.servers._oud.utilities",
    "acl": "flext_ldif.servers._oud.acl",
    "c": "flext_ldif.servers._oud.constants",
    "constants": "flext_ldif.servers._oud.constants",
    "entry": "flext_ldif.servers._oud.entry",
    "logger": "flext_ldif.servers._oud.schema",
    "schema": "flext_ldif.servers._oud.schema",
    "utilities": "flext_ldif.servers._oud.utilities",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
