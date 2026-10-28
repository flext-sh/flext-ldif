# AUTO-GENERATED FILE — Regenerate with: make gen
"""Internal package for schema.

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
    from flext_ldif._utilities._schema.build import FlextLdifUtilitiesSchemaBuild
    from flext_ldif._utilities._schema.extract import FlextLdifUtilitiesSchemaExtract
    from flext_ldif._utilities._schema.format import FlextLdifUtilitiesSchemaFormat
    from flext_ldif._utilities._schema.normalize import (
        FlextLdifUtilitiesSchemaNormalize,
    )
    from flext_ldif._utilities._schema.parse import FlextLdifUtilitiesSchemaParse

__all__: tuple[str, ...] = (
    "FlextLdifUtilitiesSchemaBuild",
    "FlextLdifUtilitiesSchemaExtract",
    "FlextLdifUtilitiesSchemaFormat",
    "FlextLdifUtilitiesSchemaNormalize",
    "FlextLdifUtilitiesSchemaParse",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdifUtilitiesSchemaBuild": ".build",
        "FlextLdifUtilitiesSchemaExtract": ".extract",
        "FlextLdifUtilitiesSchemaFormat": ".format",
        "FlextLdifUtilitiesSchemaNormalize": ".normalize",
        "FlextLdifUtilitiesSchemaParse": ".parse",
    }),
    public_exports=__all__,
)
