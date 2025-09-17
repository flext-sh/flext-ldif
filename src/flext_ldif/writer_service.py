"""FLEXT LDIF Writer Service - LDIF writing service implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

from flext_core import FlextDomainService, FlextLogger, FlextResult
from flext_ldif.config import FlextLdifConfig
from flext_ldif.format_handlers import FlextLdifFormatHandler
from flext_ldif.models import FlextLdifModels


class FlextLdifWriterService(FlextDomainService[str]):
    """LDIF Writer Service - Simplified with direct flext-core usage.

    Handles all LDIF writing operations with minimal complexity.
    Uses flext-core patterns directly without unnecessary abstractions.
    """

    def __init__(
        self, format_handler: FlextLdifFormatHandler | None = None, cols: int = 76
    ) -> None:
        """Initialize writer service."""
        super().__init__()
        self._logger = FlextLogger(__name__)
        self._format_handler = format_handler or FlextLdifFormatHandler()
        self._output_buffer: list[str] = []
        self._cols = cols

    def get_config_info(self) -> dict[str, object]:
        """Get service configuration information."""
        return {
            "service": "FlextLdifWriterService",
            "config": {
                "service_type": "writer",
                "status": "ready",
                "capabilities": [
                    "write_entries_to_string",
                    "write_entries_to_file",
                    "write_entry",
                ],
            },
        }

    def get_service_info(self) -> dict[str, object]:
        """Get service information."""
        return {
            "service_name": "FlextLdifWriterService",
            "service_type": "writer",
            "capabilities": [
                "write_entries_to_string",
                "write_entries_to_file",
                "write_entry",
            ],
            "status": "ready",
        }

    def write_entries_to_string(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[str]:
        """Write LDIF entries to string using format handler."""
        result = self._format_handler.write_ldif(entries)
        if result.is_success:
            return result
        return FlextResult[str].fail(
            f"String write failed: {result.error or 'Unknown error'}"
        )

    def write_entries_to_file(
        self, entries: list[FlextLdifModels.Entry], file_path: str | Path
    ) -> FlextResult[bool]:
        """Write LDIF entries to file."""
        content_result = self.write_entries_to_string(entries)
        if content_result.is_failure:
            return FlextResult[bool].fail(
                content_result.error or "Content generation failed"
            )

        try:
            try:
                config = FlextLdifConfig.get_global_ldif_config()
            except RuntimeError:
                # Global config not initialized, create default one
                config = FlextLdifConfig()
            encoding = config.ldif_encoding
            with Path(file_path).open("w", encoding=encoding) as f:
                f.write(content_result.value)
            return FlextResult[bool].ok(data=True)
        except Exception as e:
            return FlextResult[bool].fail(f"File write failed: {e}")

    def execute(self) -> FlextResult[str]:
        """Execute writer service operation."""
        return FlextResult[str].ok("Writer service ready")

    def write_entry(self, entry: FlextLdifModels.Entry) -> FlextResult[str]:
        """Write single LDIF entry to string."""
        return self.write_entries_to_string([entry])

    def unparse(self, dn: str, record: dict[str, list[str]]) -> None:
        """Add an entry to the output buffer with line wrapping."""
        # Add DN line
        self._output_buffer.append(f"dn: {dn}")

        # Add attributes with line wrapping
        for attr_name, attr_values in record.items():
            for value in attr_values:
                line = f"{attr_name}: {value}"
                # If line is too long, wrap it
                if len(line) > self._cols:
                    self._output_buffer.append(line[: self._cols])
                    remaining = line[self._cols :]
                    while remaining:
                        chunk = remaining[
                            : self._cols - 1
                        ]  # Leave space for leading space
                        self._output_buffer.append(f" {chunk}")
                        remaining = remaining[self._cols - 1 :]
                else:
                    self._output_buffer.append(line)

        # Add empty line to separate entries
        self._output_buffer.append("")

    def get_output(self) -> str:
        """Get the accumulated output from the buffer."""
        return "\n".join(self._output_buffer)


__all__ = ["FlextLdifWriterService"]
