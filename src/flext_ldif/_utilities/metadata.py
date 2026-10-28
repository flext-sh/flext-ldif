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

from flext_ldif._utilities._metadata import (
    FlextLdifUtilitiesMetadataBuilders,
    FlextLdifUtilitiesMetadataEntryStats,
    FlextLdifUtilitiesMetadataJsonCore,
    FlextLdifUtilitiesMetadataMatch,
    FlextLdifUtilitiesMetadataNameDesc,
    FlextLdifUtilitiesMetadataPrefix,
    FlextLdifUtilitiesMetadataSchemaAnalysis,
    FlextLdifUtilitiesMetadataSpacing,
    FlextLdifUtilitiesMetadataSyntaxOrigin,
    FlextLdifUtilitiesMetadataTracking,
)


class FlextLdifUtilitiesMetadata(
    FlextLdifUtilitiesMetadataBuilders,
    FlextLdifUtilitiesMetadataEntryStats,
    FlextLdifUtilitiesMetadataJsonCore,
    FlextLdifUtilitiesMetadataMatch,
    FlextLdifUtilitiesMetadataNameDesc,
    FlextLdifUtilitiesMetadataPrefix,
    FlextLdifUtilitiesMetadataSchemaAnalysis,
    FlextLdifUtilitiesMetadataSpacing,
    FlextLdifUtilitiesMetadataSyntaxOrigin,
    FlextLdifUtilitiesMetadataTracking,
):
    """Facade for metadata utilities."""


__all__: list[str] = ["FlextLdifUtilitiesMetadata"]
