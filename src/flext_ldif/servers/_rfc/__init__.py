# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""RFC 4512 Compliant Server Classes for LDIF/LDAP processing."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.servers._rfc import (
        acl as acl,
        constants as constants,
        entry as entry,
        schema as schema,
    )
    from flext_ldif.servers._rfc.acl import (
        FlextLdifServersRfcAcl as FlextLdifServersRfcAcl,
    )
    from flext_ldif.servers._rfc.constants import (
        FlextLdifServersRfcConstants as FlextLdifServersRfcConstants,
        c as c,
    )
    from flext_ldif.servers._rfc.entry import (
        FlextLdifServersRfcEntry as FlextLdifServersRfcEntry,
    )
    from flext_ldif.servers._rfc.schema import (
        FlextLdifServersRfcSchema as FlextLdifServersRfcSchema,
        logger as logger,
    )

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "FlextLdifServersRfcAcl": ["flext_ldif.servers._rfc.acl", "FlextLdifServersRfcAcl"],
    "FlextLdifServersRfcConstants": [
        "flext_ldif.servers._rfc.constants",
        "FlextLdifServersRfcConstants",
    ],
    "FlextLdifServersRfcEntry": [
        "flext_ldif.servers._rfc.entry",
        "FlextLdifServersRfcEntry",
    ],
    "FlextLdifServersRfcSchema": [
        "flext_ldif.servers._rfc.schema",
        "FlextLdifServersRfcSchema",
    ],
    "acl": ["flext_ldif.servers._rfc.acl", ""],
    "c": ["flext_ldif.servers._rfc.constants", "c"],
    "constants": ["flext_ldif.servers._rfc.constants", ""],
    "entry": ["flext_ldif.servers._rfc.entry", ""],
    "logger": ["flext_ldif.servers._rfc.schema", "logger"],
    "schema": ["flext_ldif.servers._rfc.schema", ""],
}

_EXPORTS: Sequence[str] = [
    "FlextLdifServersRfcAcl",
    "FlextLdifServersRfcConstants",
    "FlextLdifServersRfcEntry",
    "FlextLdifServersRfcSchema",
    "acl",
    "c",
    "constants",
    "entry",
    "logger",
    "schema",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
