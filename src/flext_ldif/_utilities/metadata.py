"""LDIF Metadata Utilities - Helpers for Validation Metadata Management.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._utilities import FlextLdifMetadataBuilders
from flext_ldif._utilities import FlextLdifMetadataEntryStats
from flext_ldif._utilities import FlextLdifMetadataJsonCore
from flext_ldif._utilities import FlextLdifMetadataMatchDetails
from flext_ldif._utilities import FlextLdifMetadataNameDescDetails
from flext_ldif._utilities import FlextLdifMetadataPrefixDetails
from flext_ldif._utilities import FlextLdifMetadataSchemaAnalysis
from flext_ldif._utilities import FlextLdifMetadataSyntaxOriginDetails
from flext_ldif._utilities import FlextLdifMetadataTracking


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
