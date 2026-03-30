# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""OUD (Oracle Unified Directory) Server Classes."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.servers._oud import (
        acl as acl,
        constants as constants,
        entry as entry,
        schema as schema,
        utilities as utilities,
    )
    from flext_ldif.servers._oud.acl import (
        FlextLdifServersOudAcl as FlextLdifServersOudAcl,
    )
    from flext_ldif.servers._oud.constants import (
        FlextLdifServersOudConstants as FlextLdifServersOudConstants,
        c as c,
    )
    from flext_ldif.servers._oud.entry import (
        FlextLdifServersOudEntry as FlextLdifServersOudEntry,
    )
    from flext_ldif.servers._oud.schema import (
        FlextLdifServersOudSchema as FlextLdifServersOudSchema,
        logger as logger,
    )
    from flext_ldif.servers._oud.utilities import (
        FlextLdifServersOudUtilities as FlextLdifServersOudUtilities,
    )

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "FlextLdifServersOudAcl": ["flext_ldif.servers._oud.acl", "FlextLdifServersOudAcl"],
    "FlextLdifServersOudConstants": [
        "flext_ldif.servers._oud.constants",
        "FlextLdifServersOudConstants",
    ],
    "FlextLdifServersOudEntry": [
        "flext_ldif.servers._oud.entry",
        "FlextLdifServersOudEntry",
    ],
    "FlextLdifServersOudSchema": [
        "flext_ldif.servers._oud.schema",
        "FlextLdifServersOudSchema",
    ],
    "FlextLdifServersOudUtilities": [
        "flext_ldif.servers._oud.utilities",
        "FlextLdifServersOudUtilities",
    ],
    "acl": ["flext_ldif.servers._oud.acl", ""],
    "c": ["flext_ldif.servers._oud.constants", "c"],
    "constants": ["flext_ldif.servers._oud.constants", ""],
    "entry": ["flext_ldif.servers._oud.entry", ""],
    "logger": ["flext_ldif.servers._oud.schema", "logger"],
    "schema": ["flext_ldif.servers._oud.schema", ""],
    "utilities": ["flext_ldif.servers._oud.utilities", ""],
}

_EXPORTS: Sequence[str] = [
    "FlextLdifServersOudAcl",
    "FlextLdifServersOudConstants",
    "FlextLdifServersOudEntry",
    "FlextLdifServersOudSchema",
    "FlextLdifServersOudUtilities",
    "acl",
    "c",
    "constants",
    "entry",
    "logger",
    "schema",
    "utilities",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
