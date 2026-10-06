# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif.servers. Rfc package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.servers._rfc.acl import FlextLdifServersRfcAcl
    from flext_ldif.servers._rfc.entry import FlextLdifServersRfcEntry
    from flext_ldif.servers._rfc.schema import FlextLdifServersRfcSchema
    from flext_ldif.servers._rfc.schema_parse import FlextLdifServersRfcSchemaParseMixin
    from flext_ldif.servers._rfc.schema_values import (
        FlextLdifServersRfcSchemaValuesMixin,
    )
    from flext_ldif.servers._rfc.schema_write import FlextLdifServersRfcSchemaWriteMixin
    from flext_ldif.servers._rfc.server_constants import FlextLdifServersRfcConstants


__all__: tuple[str, ...] = (
    "FlextLdifServersRfcAcl",
    "FlextLdifServersRfcConstants",
    "FlextLdifServersRfcEntry",
    "FlextLdifServersRfcSchema",
    "FlextLdifServersRfcSchemaParseMixin",
    "FlextLdifServersRfcSchemaValuesMixin",
    "FlextLdifServersRfcSchemaWriteMixin",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdifServersRfcAcl": ".acl",
        "FlextLdifServersRfcConstants": ".server_constants",
        "FlextLdifServersRfcEntry": ".entry",
        "FlextLdifServersRfcSchema": ".schema",
        "FlextLdifServersRfcSchemaParseMixin": ".schema_parse",
        "FlextLdifServersRfcSchemaValuesMixin": ".schema_values",
        "FlextLdifServersRfcSchemaWriteMixin": ".schema_write",
    }),
    public_exports=__all__,
)
