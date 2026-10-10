"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._utilities import (
    FlextLdifParserMetadataBuilders,
    FlextLdifParserRecord,
    FlextLdifParserRecordSplitter,
    FlextLdifParserSchemaFields,
    FlextLdifParserValues,
)


class FlextLdifUtilitiesParser(
    FlextLdifParserRecord,
    FlextLdifParserRecordSplitter,
    FlextLdifParserValues,
    FlextLdifParserSchemaFields,
    FlextLdifParserMetadataBuilders,
):
    """Generic LDIF parsing utilities - simple helper functions."""


__all__: list[str] = ["FlextLdifUtilitiesParser"]
