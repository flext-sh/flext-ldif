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

from flext_ldif._utilities._parser import (
    FlextLdifUtilitiesParserMetadata,
    FlextLdifUtilitiesParserRecord,
    FlextLdifUtilitiesParserRecords,
    FlextLdifUtilitiesParserSchemaFields,
    FlextLdifUtilitiesParserValues,
)


class FlextLdifUtilitiesParser(
    FlextLdifUtilitiesParserMetadata,
    FlextLdifUtilitiesParserRecord,
    FlextLdifUtilitiesParserRecords,
    FlextLdifUtilitiesParserSchemaFields,
    FlextLdifUtilitiesParserValues,
):
    """Facade for parser utilities."""


__all__: list[str] = ["FlextLdifUtilitiesParser"]
