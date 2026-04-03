# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Rfc package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from flext_ldif import acl, constants, entry, schema
    from flext_ldif.acl import FlextLdifServersRfcAcl
    from flext_ldif.constants import FlextLdifServersRfcConstants, c
    from flext_ldif.entry import FlextLdifServersRfcEntry
    from flext_ldif.schema import FlextLdifServersRfcSchema, logger

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "FlextLdifServersRfcAcl": "flext_ldif.acl",
    "FlextLdifServersRfcConstants": "flext_ldif.constants",
    "FlextLdifServersRfcEntry": "flext_ldif.entry",
    "FlextLdifServersRfcSchema": "flext_ldif.schema",
    "acl": "flext_ldif.acl",
    "c": "flext_ldif.constants",
    "constants": "flext_ldif.constants",
    "entry": "flext_ldif.entry",
    "logger": "flext_ldif.schema",
    "schema": "flext_ldif.schema",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
