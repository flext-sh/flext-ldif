"""FLEXT LDIF Writer Service - LDIF writing service implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

from flext_core import FlextResult

from flext_ldif.base_service import FlextLDIFBaseService
from flext_ldif.format_handlers import FlextLDIFFormatHandler
from flext_ldif.models import FlextLDIFModels


class FlextLDIFWriterService(FlextLDIFBaseService[str]):
    """LDIF Writer Service - Single Responsibility.

    Handles all LDIF writing operations with enterprise-grade error handling.
    Uses flext-core SOURCE OF TRUTH exclusively.
    """

    def __init__(
        self, format_handler: FlextLDIFFormatHandler | None = None, cols: int = 76
    ) -> None:
        """Initialize writer service with format handler."""
        super().__init__("FlextLDIFWriterService", "writer")
        self._format_handler = format_handler or FlextLDIFFormatHandler()
        self._output_buffer: list[str] = []
        self._cols = cols

        # Register capabilities
        self._add_capability("write_entries_to_string")
        self._add_capability("write_entries_to_file")
        self._add_capability("write_entry")

    def write_entries_to_string(
        self, entries: list[FlextLDIFModels.Entry]
    ) -> FlextResult[str]:
        """Write LDIF entries to string."""
        try:
            result = self._format_handler.write_ldif(entries)
            if result.is_success:
                return result
            return self._handle_error_str(
                "String write", result.error or "Unknown error"
            )
        except Exception as e:
            return self._handle_error_str("String write", e)

    def write_entries_to_file(
        self, entries: list[FlextLDIFModels.Entry], file_path: str | Path
    ) -> FlextResult[bool]:
        """Write LDIF entries to file."""
        try:
            content_result = self.write_entries_to_string(entries)
            if content_result.is_failure:
                return FlextResult[bool].fail(
                    content_result.error or "Content generation failed"
                )

            with Path(file_path).open("w", encoding="utf-8") as f:
                f.write(content_result.value)

            return FlextResult[bool].ok(data=True)
        except Exception as e:
            return self._handle_error_bool("File write", e)

    def execute(self) -> FlextResult[str]:
        """Execute writer service operation."""
        return FlextResult[str].ok("Writer service ready")

    def write_entry(self, entry: FlextLDIFModels.Entry) -> FlextResult[str]:
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


__all__ = ["FlextLDIFWriterService"]
