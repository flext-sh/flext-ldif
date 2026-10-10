"""LDIF Metadata Utilities - Helpers for Validation Metadata Management.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._utilities import (
    FlextLdifMetadataBuilders,
    FlextLdifMetadataEntryStats,
    FlextLdifMetadataJsonCore,
    FlextLdifMetadataMatchDetails,
    FlextLdifMetadataNameDescDetails,
    FlextLdifMetadataPrefixDetails,
    FlextLdifMetadataSchemaAnalysis,
    FlextLdifMetadataSyntaxOriginDetails,
    FlextLdifMetadataTracking,
)


class FlextLdifUtilitiesMetadata(
    FlextLdifMetadataJsonCore,
    FlextLdifMetadataEntryStats,
    FlextLdifMetadataBuilders,
    FlextLdifMetadataTracking,
    FlextLdifMetadataPrefixDetails,
    FlextLdifMetadataNameDescDetails,
    FlextLdifMetadataSyntaxOriginDetails,
    FlextLdifMetadataMatchDetails,
    FlextLdifMetadataSchemaAnalysis,
):
    """Metadata utilities for LDIF validation metadata management."""


__all__: list[str] = ["FlextLdifUtilitiesMetadata"]
