"""FlextLdif validator using flext-core patterns.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext-core root namespace imports
from flext_core import FlextResult

if TYPE_CHECKING:
    from .models import FlextLdifEntry


class FlextLdifValidator:
    """LDIF validator using flext-core patterns."""

    DN_PATTERN = re.compile(r"^[a-zA-Z]+=.+")
    ATTR_NAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9-]*$")

    def validate_entry(self, entry: FlextLdifEntry) -> FlextResult[Any]:
        """Validate LDIF entry.

        Args:
            entry: LDIFEntry to validate

        Returns:
            FlextResult indicating validation success

        """
        try:
            # Validate DN format
            if not self.DN_PATTERN.match(str(entry.dn)):
                return FlextResult.fail(
                    f"Invalid DN format: {entry.dn}",
                )

            # Validate attribute names
            for attr_name in entry.attributes.attributes:
                if not self.ATTR_NAME_PATTERN.match(attr_name):
                    return FlextResult.fail(
                        f"Invalid attribute name: {attr_name}",
                    )

            # Validate required objectClass attribute
            if not entry.has_attribute("objectClass"):
                return FlextResult.fail(
                    "Entry missing required objectClass attribute",
                )

            return FlextResult.ok(True)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(
                f"Validation error: {e}",
            )

    def validate_entries(self, entries: list[FlextLdifEntry]) -> FlextResult[Any]:
        """Validate multiple LDIF entries.

        Args:
            entries: List of FlextLdifEntry objects to validate

        Returns:
            FlextResult indicating validation success

        """
        try:
            for i, entry in enumerate(entries):
                result = self.validate_entry(entry)
                if not result.success:
                    return FlextResult.fail(
                        f"Entry {i} validation failed: {result.error}",
                    )

            return FlextResult.ok(True)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(
                f"Batch validation error: {e}",
            )


__all__ = [
    "FlextLdifValidator",
]
