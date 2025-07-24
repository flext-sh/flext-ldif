"""FlextLdif Service Adapter using flext-core patterns.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext-core root namespace imports
from flext_core import FlextResult

from flext_ldif.processor import FlextLdifProcessor

if TYPE_CHECKING:
    from pathlib import Path

    from flext_ldif.models import FlextLdifEntry


class FlextLdifAdapter:
    """FlextLdif adapter using flext-core patterns."""

    def __init__(self) -> None:
        """Initialize FlextLdif adapter."""
        self._processor = FlextLdifProcessor()

    async def read_entries(self, file_path: Path) -> FlextResult[Any]:
        """Read entries from LDIF file.

        Args:
            file_path: Path to LDIF file

        Returns:
            FlextResult containing list of FlextLdifEntry objects

        """
        try:
            result = self._processor.parse_ldif_file(file_path)
            if result.success and result.data:
                return FlextResult.ok(result.data)
            return FlextResult.fail(f"Failed to read LDIF file: {result.error}")

        except Exception as e:
            return FlextResult.fail(f"LDIF read error: {e}")

    async def write_entries(
        self,
        entries: list[FlextLdifEntry],
        file_path: Path,
    ) -> FlextResult[Any]:
        """Write entries to LDIF file.

        Args:
            entries: List of FlextLdifEntry objects to write
            file_path: Path where to write LDIF file

        Returns:
            FlextResult indicating success or failure

        """
        try:
            result = self._processor.write_ldif_file(entries, file_path)
            if result.success:
                return FlextResult.ok(True)
            return FlextResult.fail(f"Failed to write LDIF file: {result.error}")

        except Exception as e:
            return FlextResult.fail(f"LDIF write error: {e}")

    async def validate_entries(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[Any]:
        """Validate LDIF entries.

        Args:
            entries: List of FlextLdifEntry objects to validate

        Returns:
            FlextResult indicating validation success or failure

        """
        try:
            result = self._processor.validate_entries(entries)
            if result.success:
                return FlextResult.ok(True)
            return FlextResult.fail(f"Validation failed: {result.error}")

        except Exception as e:
            return FlextResult.fail(f"LDIF validation error: {e}")


__all__ = [
    "FlextLdifAdapter",
]
