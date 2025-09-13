"""FLEXT LDIF Parser Service - LDIF parsing service implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

from flext_core import FlextResult

from flext_ldif.base_service import FlextLDIFBaseService
from flext_ldif.format_handlers import FlextLDIFFormatHandler
from flext_ldif.models import FlextLDIFModels


class FlextLDIFParserService(FlextLDIFBaseService[list[FlextLDIFModels.Entry]]):
    """LDIF Parser Service - Single Responsibility.

    Handles all LDIF parsing operations with enterprise-grade error handling.
    Uses flext-core SOURCE OF TRUTH exclusively.
    """

    def __init__(self, format_handler: FlextLDIFFormatHandler | None = None) -> None:
        """Initialize parser service."""
        super().__init__("FlextLDIFParserService", "parser")
        self._format_handler = format_handler or FlextLDIFFormatHandler()

        # Register capabilities
        self._add_capability("parse_ldif_file")
        self._add_capability("parse_content")
        self._add_capability("validate_ldif_syntax")
        self._add_capability("_parse_entry_block")

    def parse_ldif_file(
        self, file_path: str | Path
    ) -> FlextResult[list[FlextLDIFModels.Entry]]:
        """Parse LDIF file using format handler."""
        try:
            with Path(file_path).open(encoding="utf-8") as f:
                content = f.read()
            return self.parse_content(content)
        except Exception as e:
            return self._handle_error("File read", e)

    def parse_content(self, content: str) -> FlextResult[list[FlextLDIFModels.Entry]]:
        """Parse LDIF content using format handler."""
        if not content.strip():
            return FlextResult[list[FlextLDIFModels.Entry]].ok([])

        try:
            result = self._format_handler.parse_ldif(content)
            if result.is_success:
                return result
            return self._handle_error("Parse", result.error or "Unknown error")
        except Exception as e:
            return self._handle_error("Parse", e)

    def validate_ldif_syntax(self, content: str) -> FlextResult[bool]:
        """Validate LDIF syntax without parsing entries."""
        try:
            if not content.strip():
                return FlextResult[bool].fail("Empty LDIF content")

            lines = content.strip().split("\n")

            # Check if first non-empty line starts with dn:
            for line in lines:
                stripped_line = line.strip()
                if stripped_line:
                    if not stripped_line.startswith("dn:"):
                        return FlextResult[bool].fail("LDIF must start with dn:")
                    break

            return FlextResult[bool].ok(data=True)
        except Exception as e:
            return self._handle_error_bool("Syntax validation", e)

    def _parse_entry_block(
        self, block: str
    ) -> FlextResult[list[FlextLDIFModels.Entry]]:
        """Parse a single LDIF entry block."""
        try:
            if not block.strip():
                return FlextResult[list[FlextLDIFModels.Entry]].fail("No entries found")

            # Use the format handler to parse the block
            result = self._format_handler.parse_ldif(block)
            if result.is_success:
                return result
            return self._handle_error_list(
                "Block parse", result.error or "Unknown error"
            )
        except Exception as e:
            return self._handle_error_list("Block parse", e)

    def execute(self) -> FlextResult[list[FlextLDIFModels.Entry]]:
        """Execute parser service operation."""
        # Return empty list to match the type parameter
        return FlextResult[list[FlextLDIFModels.Entry]].ok([])


__all__ = ["FlextLDIFParserService"]
