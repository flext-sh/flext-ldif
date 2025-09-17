"""FLEXT LDIF Parser Service - LDIF parsing service implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

from flext_core import FlextDomainService, FlextLogger, FlextResult
from flext_ldif.config import FlextLdifConfig
from flext_ldif.format_handlers import FlextLdifFormatHandler
from flext_ldif.models import FlextLdifModels


class FlextLdifParserService(FlextDomainService[list[FlextLdifModels.Entry]]):
    """LDIF Parser Service - Simplified with direct flext-core usage.

    Handles LDIF parsing operations with minimal complexity.
    Uses flext-core patterns directly without unnecessary abstractions.
    """

    def __init__(self, format_handler: FlextLdifFormatHandler | None = None) -> None:
        """Initialize parser service."""
        super().__init__()
        self._logger = FlextLogger(__name__)
        self._format_handler = format_handler or FlextLdifFormatHandler()

    def get_config_info(self) -> dict[str, object]:
        """Get service configuration information."""
        return {
            "service": "FlextLdifParserService",
            "config": {
                "service_type": "parser",
                "status": "ready",
                "capabilities": [
                    "parse_ldif_file",
                    "parse_content",
                    "validate_ldif_syntax",
                ],
            },
        }

    def get_service_info(self) -> dict[str, object]:
        """Get service information."""
        return {
            "service_name": "FlextLdifParserService",
            "service_type": "parser",
            "capabilities": [
                "parse_ldif_file",
                "parse_content",
                "validate_ldif_syntax",
            ],
            "status": "ready",
        }

    def parse_ldif_file(
        self, file_path: str | Path
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF file using format handler."""
        try:
            try:
                config = FlextLdifConfig.get_global_ldif_config()
            except RuntimeError:
                # Global config not initialized, create default one
                config = FlextLdifConfig()
            encoding = config.ldif_encoding
            content = Path(file_path).read_text(encoding=encoding)
            return self.parse_content(content)
        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"File read failed: {e}"
            )

    def parse_content(self, content: str) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF content using format handler."""
        if not content.strip():
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

        try:
            # Delegate to format handler directly
            return self._format_handler.parse_ldif(content)
        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(f"Parse error: {e}")

    def validate_ldif_syntax(self, content: str) -> FlextResult[bool]:
        """Validate LDIF syntax using centralized FlextModels validation."""
        try:
            # Use centralized FlextLdifModels.LdifContent for validation
            FlextLdifModels.LdifContent(content=content)
            return FlextResult[bool].ok(data=True)
        except Exception as e:
            return FlextResult[bool].fail(str(e))

    def _parse_entry_block(
        self, block: str
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse a single LDIF entry block."""
        if not block.strip():
            return FlextResult[list[FlextLdifModels.Entry]].fail("No entries found")

        # Use format handler directly - no extra exception handling needed
        return self._format_handler.parse_ldif(block)

    def execute(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Execute parser service operation."""
        # Return empty list to match the type parameter
        return FlextResult[list[FlextLdifModels.Entry]].ok([])


__all__ = ["FlextLdifParserService"]
