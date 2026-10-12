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
    from flext_ldif.servers._rfc.entry import FlextLdifServersRfcEntry
    from flext_ldif.servers._rfc.schema_parse import FlextLdifServersRfcSchemaParseMixin
    from flext_ldif.servers._rfc.schema_values import (
        FlextLdifServersRfcSchemaValuesMixin,
    )
    from flext_ldif.servers._rfc.schema_write import FlextLdifServersRfcSchemaWriteMixin


__all__: tuple[str, ...] = (
    "FlextLdifServersRfcEntry",
    "FlextLdifServersRfcSchemaParseMixin",
    "FlextLdifServersRfcSchemaValuesMixin",
    "FlextLdifServersRfcSchemaWriteMixin",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdifServersRfcEntry": ".entry",
        "FlextLdifServersRfcSchemaParseMixin": ".schema_parse",
        "FlextLdifServersRfcSchemaValuesMixin": ".schema_values",
        "FlextLdifServersRfcSchemaWriteMixin": ".schema_write",
    }),
    public_exports=__all__,
)
