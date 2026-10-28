# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif.servers. Base package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.servers._base.acl import FlextLdifServersBaseSchemaAcl
    from flext_ldif.servers._base.dialect_schema import FlextLdifServersDialectSchema
    from flext_ldif.servers._base.entry import FlextLdifServersBaseEntry
    from flext_ldif.servers._base.entry_lines import FlextLdifServersEntryLineEmitter
    from flext_ldif.servers._base.entry_write import FlextLdifServersEntryWriteContext
    from flext_ldif.servers._base.entry_write_body import (
        FlextLdifServersEntryWriteBodyEmitter,
    )
    from flext_ldif.servers._base.entry_write_options import (
        FlextLdifServersEntryWriteOptions,
    )
    from flext_ldif.servers._base.execute_params import (
        FlextLdifServersBaseExecuteParams,
    )
    from flext_ldif.servers._base.mixins import FlextLdifServerMethods
    from flext_ldif.servers._base.schema import FlextLdifServersBaseSchema
    from flext_ldif.servers._base.schema_metadata import (
        FlextLdifServersBaseSchemaMetadata,
    )
    from flext_ldif.servers._base.schema_values import FlextLdifServersBaseSchemaValues
    from flext_ldif.servers._base.server_constants import FlextLdifConstantsServersBase
    from flext_ldif.servers._base.server_io import FlextLdifServersBaseIo
    from flext_ldif.servers._base.server_type import FlextLdifServersBaseMro


__all__: tuple[str, ...] = (
    "FlextLdifConstantsServersBase",
    "FlextLdifServerMethods",
    "FlextLdifServersBaseEntry",
    "FlextLdifServersBaseExecuteParams",
    "FlextLdifServersBaseIo",
    "FlextLdifServersBaseMro",
    "FlextLdifServersBaseSchema",
    "FlextLdifServersBaseSchemaAcl",
    "FlextLdifServersBaseSchemaMetadata",
    "FlextLdifServersBaseSchemaValues",
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
        "FlextLdifServerMethods": ".mixins",
        "FlextLdifConstantsServersBase": ".server_constants",
        "FlextLdifServersBaseEntry": ".entry",
        "FlextLdifServersBaseExecuteParams": ".execute_params",
        "FlextLdifServersBaseIo": ".server_io",
        "FlextLdifServersBaseMro": ".server_type",
        "FlextLdifServersBaseSchema": ".schema",
        "FlextLdifServersBaseSchemaAcl": ".acl",
        "FlextLdifServersBaseSchemaMetadata": ".schema_metadata",
        "FlextLdifServersBaseSchemaValues": ".schema_values",
        "FlextLdifServersDialectSchema": ".dialect_schema",
        "FlextLdifServersEntryLineEmitter": ".entry_lines",
        "FlextLdifServersEntryWriteBodyEmitter": ".entry_write_body",
        "FlextLdifServersEntryWriteContext": ".entry_write",
        "FlextLdifServersEntryWriteOptions": ".entry_write_options",
    }),
    public_exports=__all__,
)
