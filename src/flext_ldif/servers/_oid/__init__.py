# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Oid package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from flext_ldif.servers._oid import acl, constants, entry, schema
    from flext_ldif.servers._oid.acl import FlextLdifServersOidAcl
    from flext_ldif.servers._oid.constants import FlextLdifServersOidConstants, c
    from flext_ldif.servers._oid.entry import FlextLdifServersOidEntry
    from flext_ldif.servers._oid.schema import FlextLdifServersOidSchema, logger

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "FlextLdifServersOidAcl": "flext_ldif.servers._oid.acl",
    "FlextLdifServersOidConstants": "flext_ldif.servers._oid.constants",
    "FlextLdifServersOidEntry": "flext_ldif.servers._oid.entry",
    "FlextLdifServersOidSchema": "flext_ldif.servers._oid.schema",
    "acl": "flext_ldif.servers._oid.acl",
    "c": "flext_ldif.servers._oid.constants",
    "constants": "flext_ldif.servers._oid.constants",
    "entry": "flext_ldif.servers._oid.entry",
    "logger": "flext_ldif.servers._oid.schema",
    "schema": "flext_ldif.servers._oid.schema",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
