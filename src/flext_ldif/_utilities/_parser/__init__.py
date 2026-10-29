# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Utilities. Parser package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._utilities._parser.metadata import FlextLdifUtilitiesParserMetadata
    from flext_ldif._utilities._parser.record import FlextLdifUtilitiesParserRecord
    from flext_ldif._utilities._parser.records import FlextLdifUtilitiesParserRecords
    from flext_ldif._utilities._parser.schema_fields import (
        FlextLdifUtilitiesParserSchemaFields,
    )
    from flext_ldif._utilities._parser.values import FlextLdifUtilitiesParserValues


__all__: tuple[str, ...] = (
    "FlextLdifUtilitiesParserMetadata",
    "FlextLdifUtilitiesParserRecord",
    "FlextLdifUtilitiesParserRecords",
    "FlextLdifUtilitiesParserSchemaFields",
    "FlextLdifUtilitiesParserValues",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdifUtilitiesParserMetadata": ".metadata",
        "FlextLdifUtilitiesParserRecord": ".record",
        "FlextLdifUtilitiesParserRecords": ".records",
        "FlextLdifUtilitiesParserSchemaFields": ".schema_fields",
        "FlextLdifUtilitiesParserValues": ".values",
    }),
    public_exports=__all__,
)
