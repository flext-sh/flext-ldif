"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._utilities._writer_chars import FlextLdifWriterRfcChars
from flext_ldif._utilities._writer_fold import FlextLdifWriterLineFolding
from flext_ldif._utilities._writer_schema import FlextLdifWriterSchemaParts


class FlextLdifUtilitiesWriter(
    FlextLdifWriterSchemaParts,
    FlextLdifWriterLineFolding,
    FlextLdifWriterRfcChars,
):
    """Pure LDIF Formatting Operations - No Models, No Side Effects."""


__all__: list[str] = ["FlextLdifUtilitiesWriter"]
