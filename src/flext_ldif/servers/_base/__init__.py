# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif.servers. Base package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.servers._base.dialect_schema import FlextLdifServersDialectSchema
    from flext_ldif.servers._base.entry_lines import FlextLdifServersEntryLineEmitter
    from flext_ldif.servers._base.entry_write import FlextLdifServersEntryWriteContext
    from flext_ldif.servers._base.entry_write_body import (
        FlextLdifServersEntryWriteBodyEmitter,
    )
    from flext_ldif.servers._base.entry_write_options import (
        FlextLdifServersEntryWriteOptions,
    )
    from flext_ldif.servers._base.execute_params import (
        FlextLdifServersBaseExecuteParamsMixin,
    )
    from flext_ldif.servers._base.mixins import FlextLdifServerMethodsMixin
    from flext_ldif.servers._base.schema_metadata import (
        FlextLdifServersBaseSchemaMetadataMixin,
    )
    from flext_ldif.servers._base.schema_values import (
        FlextLdifServersBaseSchemaValuesMixin,
    )
    from flext_ldif.servers._base.server_io import FlextLdifServersBaseIoMixin
    from flext_ldif.servers._base.server_type import FlextLdifServersBaseMroMixin


__all__: tuple[str, ...] = (
    "FlextLdifServerMethodsMixin",
    "FlextLdifServersBaseExecuteParamsMixin",
    "FlextLdifServersBaseIoMixin",
    "FlextLdifServersBaseMroMixin",
    "FlextLdifServersBaseSchemaMetadataMixin",
    "FlextLdifServersBaseSchemaValuesMixin",
    "FlextLdifServersDialectSchema",
    "FlextLdifServersEntryLineEmitter",
    "FlextLdifServersEntryWriteBodyEmitter",
    "FlextLdifServersEntryWriteContext",
    "FlextLdifServersEntryWriteOptions",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdifServerMethodsMixin": ".mixins",
        "FlextLdifServersBaseExecuteParamsMixin": ".execute_params",
        "FlextLdifServersBaseIoMixin": ".server_io",
        "FlextLdifServersBaseMroMixin": ".server_type",
        "FlextLdifServersBaseSchemaMetadataMixin": ".schema_metadata",
        "FlextLdifServersBaseSchemaValuesMixin": ".schema_values",
        "FlextLdifServersDialectSchema": ".dialect_schema",
        "FlextLdifServersEntryLineEmitter": ".entry_lines",
        "FlextLdifServersEntryWriteBodyEmitter": ".entry_write_body",
        "FlextLdifServersEntryWriteContext": ".entry_write",
        "FlextLdifServersEntryWriteOptions": ".entry_write_options",
    }),
    public_exports=__all__,
)
