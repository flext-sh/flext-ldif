"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._utilities import (
    FlextLdifACLExtensionFormatting,
    FlextLdifACLExtraction,
    FlextLdifACLFormatting,
    FlextLdifACLParsing,
    FlextLdifACLPermissions,
)


class FlextLdifUtilitiesACL(
    FlextLdifACLExtraction,
    FlextLdifACLExtensionFormatting,
    FlextLdifACLPermissions,
    FlextLdifACLFormatting,
    FlextLdifACLParsing,
):
    """Generic ACL parsing and writing utilities."""


__all__: list[str] = ["FlextLdifUtilitiesACL"]
