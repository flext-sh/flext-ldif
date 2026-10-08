"""LDIF Metadata Utilities - Helpers for Validation Metadata Management.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._utilities._metadata_builders import FlextLdifMetadataBuilders
from flext_ldif._utilities._metadata_entry_stats import FlextLdifMetadataEntryStats
from flext_ldif._utilities._metadata_json_core import FlextLdifMetadataJsonCore
from flext_ldif._utilities._metadata_match import FlextLdifMetadataMatchDetails
from flext_ldif._utilities._metadata_name_desc import FlextLdifMetadataNameDescDetails
from flext_ldif._utilities._metadata_prefix import FlextLdifMetadataPrefixDetails
from flext_ldif._utilities._metadata_schema_analysis import (
    FlextLdifFlextUtilitiesMetadataSchemaAnalysis,
)
from flext_ldif._utilities._metadata_syntax_origin import (
    FlextLdifMetadataSyntaxOriginDetails,
)
from flext_ldif._utilities._metadata_tracking import FlextLdifMetadataTracking


class FlextLdifUtilitiesMetadata(
    FlextLdifMetadataJsonCore,
    FlextLdifMetadataEntryStats,
    FlextLdifMetadataBuilders,
    FlextLdifMetadataTracking,
    FlextLdifMetadataPrefixDetails,
    FlextLdifMetadataNameDescDetails,
    FlextLdifMetadataSyntaxOriginDetails,
    FlextLdifMetadataMatchDetails,
    FlextLdifFlextUtilitiesMetadataSchemaAnalysis.FlextLdifMetadataSchemaAnalysis,
):
    """Metadata utilities for LDIF validation metadata management."""


__all__: list[str] = ["FlextLdifUtilitiesMetadata"]
