"""Schema utilities facade for FLEXT-LDIF.

Composed from focused MRO mixins; public API remains ``FlextLdifUtilitiesSchema``.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._utilities import (
    FlextLdifUtilitiesSchemaBuild,
    FlextLdifUtilitiesSchemaExtract,
    FlextLdifUtilitiesSchemaFormat,
    FlextLdifUtilitiesSchemaNormalize,
    FlextLdifUtilitiesSchemaParse,
)


class FlextLdifUtilitiesSchema(
    FlextLdifUtilitiesSchemaFormat,
    FlextLdifUtilitiesSchemaExtract,
    FlextLdifUtilitiesSchemaNormalize,
    FlextLdifUtilitiesSchemaBuild,
    FlextLdifUtilitiesSchemaParse,
):
    """Generic schema-definition normalization utilities."""


__all__: list[str] = ["FlextLdifUtilitiesSchema"]
