"""LDIF parser using flext-core patterns.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from flext_core.domain.shared_types import ServiceResult

from .models import LDIFEntry

if TYPE_CHECKING:
    from .types import LDIFContent


class LDIFParser:
    """LDIF parser using flext-core patterns."""

    def parse_ldif_content(
        self,
        content: str | LDIFContent,
    ) -> ServiceResult[Any]:
        """Parse LDIF content into entries.

        Args:
            content: LDIF content string

        Returns:
            ServiceResult containing list of LDIFEntry objects

        """
        try:
            entries = []

            # Convert to string if it's a LDIFContent NewType
            content_str = str(content)

            # Split into entry blocks (separated by empty lines)
            entry_blocks = re.split(r"\n\s*\n", content_str.strip())

            for block in entry_blocks:
                if block.strip():
                    try:
                        entry = LDIFEntry.from_ldif_block(block)
                        entries.append(entry)
                    except ValueError as e:
                        return ServiceResult.fail(
                            f"Failed to parse LDIF entry: {e}",
                        )

            return ServiceResult.ok(entries)

        except (ValueError, TypeError, AttributeError) as e:
            return ServiceResult.fail(
                f"Failed to parse LDIF content: {e}",
            )

    def parse_ldif_file(self, file_path: str) -> ServiceResult[Any]:
        """Parse LDIF file into entries.

        Args:
            file_path: Path to LDIF file

        Returns:
            ServiceResult containing list of LDIFEntry objects

        """
        try:
            with Path(file_path).open(encoding="utf-8") as f:
                content = f.read()
            from .types import LDIFContent

            return self.parse_ldif_content(LDIFContent(content))

        except OSError as e:
            return ServiceResult.fail(
                f"Failed to read LDIF file {file_path}: {e}",
            )


__all__ = [
    "LDIFParser",
]
