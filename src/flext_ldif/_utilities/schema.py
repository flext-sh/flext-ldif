"""Extracted facade class from FlextLdifUtilities.

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

from flext_ldif._utilities._schema import (
    FlextLdifUtilitiesSchemaBuild,
    FlextLdifUtilitiesSchemaExtract,
    FlextLdifUtilitiesSchemaFormat,
    FlextLdifUtilitiesSchemaNormalize,
    FlextLdifUtilitiesSchemaParse,
)


class FlextLdifUtilitiesSchema(
    FlextLdifUtilitiesSchemaBuild,
    FlextLdifUtilitiesSchemaExtract,
    FlextLdifUtilitiesSchemaFormat,
    FlextLdifUtilitiesSchemaNormalize,
    FlextLdifUtilitiesSchemaParse,
):
    """Facade for schema utilities."""


__all__: list[str] = ["FlextLdifUtilitiesSchema"]
