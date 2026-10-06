"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._utilities._parser_metadata import (
    FlextLdifParserMetadataBuilders,
)
from flext_ldif._utilities._parser_record import FlextLdifParserRecord
from flext_ldif._utilities._parser_records import FlextLdifParserRecordSplitter
from flext_ldif._utilities._parser_schema_fields import (
    FlextLdifParserSchemaFields,
)
from flext_ldif._utilities._parser_values import FlextLdifParserValues


class FlextLdifUtilitiesParser(
    FlextLdifParserRecord,
    FlextLdifParserRecordSplitter,
    FlextLdifParserValues,
    FlextLdifParserSchemaFields,
    FlextLdifParserMetadataBuilders,
):
    """Generic LDIF parsing utilities - simple helper functions."""


__all__: list[str] = ["FlextLdifUtilitiesParser"]
