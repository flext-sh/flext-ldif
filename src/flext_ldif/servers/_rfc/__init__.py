# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif.servers. Rfc package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.servers._rfc.acl import FlextLdifServersRfcAcl
    from flext_ldif.servers._rfc.entry import FlextLdifServersRfcEntry
    from flext_ldif.servers._rfc.schema import FlextLdifServersRfcSchema
    from flext_ldif.servers._rfc.schema_parse import FlextLdifServersRfcSchemaParse
    from flext_ldif.servers._rfc.schema_values import FlextLdifServersRfcSchemaValues
    from flext_ldif.servers._rfc.schema_write import FlextLdifServersRfcSchemaWrite
    from flext_ldif.servers._rfc.server_constants import FlextLdifConstantsServersRfc


__all__: tuple[str, ...] = (
    "FlextLdifConstantsServersRfc",
    "FlextLdifServersRfcAcl",
    "FlextLdifServersRfcEntry",
    "FlextLdifServersRfcSchema",
    "FlextLdifServersRfcSchemaParse",
    "FlextLdifServersRfcSchemaValues",
    "FlextLdifServersRfcSchemaWrite",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdifServersRfcAcl": ".acl",
        "FlextLdifConstantsServersRfc": ".server_constants",
        "FlextLdifServersRfcEntry": ".entry",
        "FlextLdifServersRfcSchema": ".schema",
        "FlextLdifServersRfcSchemaParse": ".schema_parse",
        "FlextLdifServersRfcSchemaValues": ".schema_values",
        "FlextLdifServersRfcSchemaWrite": ".schema_write",
    }),
    public_exports=__all__,
)
