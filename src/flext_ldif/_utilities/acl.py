# AUTO-GENERATED FILE — Regenerate with: make gen
"""Extracted facade class from FlextLdifUtilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._utilities._acl import (
    FlextLdifUtilitiesACLExtensions,
    FlextLdifUtilitiesACLExtract,
    FlextLdifUtilitiesACLFormat,
    FlextLdifUtilitiesACLParse,
    FlextLdifUtilitiesACLPermissions,
)


class FlextLdifUtilitiesACL(
    FlextLdifUtilitiesACLExtensions,
    FlextLdifUtilitiesACLExtract,
    FlextLdifUtilitiesACLFormat,
    FlextLdifUtilitiesACLParse,
    FlextLdifUtilitiesACLPermissions,
):
    """Facade for acl utilities."""


__all__: list[str] = ["FlextLdifUtilitiesACL"]
