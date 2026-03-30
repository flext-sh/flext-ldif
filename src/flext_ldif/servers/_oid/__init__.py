# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""OID (Oracle Internet Directory) Server Classes."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.servers._oid import (
        acl as acl,
        constants as constants,
        entry as entry,
        schema as schema,
    )
    from flext_ldif.servers._oid.acl import (
        FlextLdifServersOidAcl as FlextLdifServersOidAcl,
    )
    from flext_ldif.servers._oid.constants import (
        FlextLdifServersOidConstants as FlextLdifServersOidConstants,
        c as c,
    )
    from flext_ldif.servers._oid.entry import (
        FlextLdifServersOidEntry as FlextLdifServersOidEntry,
    )
    from flext_ldif.servers._oid.schema import (
        FlextLdifServersOidSchema as FlextLdifServersOidSchema,
        logger as logger,
    )

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "FlextLdifServersOidAcl": ["flext_ldif.servers._oid.acl", "FlextLdifServersOidAcl"],
    "FlextLdifServersOidConstants": [
        "flext_ldif.servers._oid.constants",
        "FlextLdifServersOidConstants",
    ],
    "FlextLdifServersOidEntry": [
        "flext_ldif.servers._oid.entry",
        "FlextLdifServersOidEntry",
    ],
    "FlextLdifServersOidSchema": [
        "flext_ldif.servers._oid.schema",
        "FlextLdifServersOidSchema",
    ],
    "acl": ["flext_ldif.servers._oid.acl", ""],
    "c": ["flext_ldif.servers._oid.constants", "c"],
    "constants": ["flext_ldif.servers._oid.constants", ""],
    "entry": ["flext_ldif.servers._oid.entry", ""],
    "logger": ["flext_ldif.servers._oid.schema", "logger"],
    "schema": ["flext_ldif.servers._oid.schema", ""],
}

_EXPORTS: Sequence[str] = [
    "FlextLdifServersOidAcl",
    "FlextLdifServersOidConstants",
    "FlextLdifServersOidEntry",
    "FlextLdifServersOidSchema",
    "acl",
    "c",
    "constants",
    "entry",
    "logger",
    "schema",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
