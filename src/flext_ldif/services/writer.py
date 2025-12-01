"""Writer Service - Direct LDIF Writing with flext-core APIs.

This service provides direct LDIF writing using flext-core and flext-ldif APIs:
- Direct use of FlextLdifServer entry quirks for writing
- No unnecessary routing or complex nested classes
- Railway-oriented error handling with FlextResult

Single Responsibility: Write LDIF entries using direct APIs.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path

from flext_core import FlextResult

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.results import FlextLdifModelsResults
from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.typings import FlextLdifTypes


class FlextLdifWriter(FlextLdifServiceBase[FlextLdifModelsResults.WriteResponse]):
    """Direct LDIF writing service using flext-core APIs.

    This service provides minimal, direct LDIF writing by delegating
    to FlextLdifServer entry quirks which handle all server-specific quirks.
    No unnecessary abstraction layers or routing logic.
    """

    _server: FlextLdifServer

    def __init__(self, server: FlextLdifServer | None = None) -> None:
        """Initialize writer with optional server instance."""
        super().__init__()
        self._server = server if server is not None else FlextLdifServer()

    def write_to_string(
        self,
        entries: list[FlextLdifModels.Entry],
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral | None = None,
        format_options: (
            FlextLdifModels.WriteFormatOptions | FlextLdifModelsDomains.WriteOptions | None
        ) = None,
    ) -> FlextResult[str]:
        """Write entries to LDIF string format.

        Args:
            entries: Entries to write
            server_type: Server type for quirk selection
            format_options: Write options (WriteFormatOptions or WriteOptions)

        Returns:
            FlextResult containing LDIF string

        """
        # Get entry quirk for writing
        effective_server_type = server_type or "rfc"

        entry_quirk = self._server.entry(effective_server_type)
        if entry_quirk is None:
            return FlextResult.fail(
                f"No entry quirk found for server type: {effective_server_type}",
            )

        # Use default format options if none provided
        # Entry quirk accepts WriteFormatOptions directly (has all fields including ldif_changetype)
        if format_options is None:
            options = FlextLdifModels.WriteFormatOptions()
        elif isinstance(format_options, type):
            # If class is passed instead of instance, create instance
            options = format_options()
        elif isinstance(format_options, FlextLdifModels.WriteFormatOptions):
            options = format_options
        elif isinstance(format_options, FlextLdifModelsDomains.WriteOptions):
            # Convert WriteOptions to WriteFormatOptions
            options = FlextLdifModels.WriteFormatOptions.model_validate(format_options.model_dump())
        elif isinstance(format_options, dict):
            # Convert dict to WriteFormatOptions
            options = FlextLdifModels.WriteFormatOptions.model_validate(format_options)
        else:
            msg = f"Expected WriteFormatOptions | WriteOptions | dict | None, got {type(format_options)}"
            raise TypeError(msg)

        # Direct call to entry quirk write method
        write_result = entry_quirk.write(entries, options)

        if write_result.is_failure:
            return FlextResult.fail(write_result.error or "LDIF writing failed")

        return write_result

    def write_to_file(
        self,
        entries: list[FlextLdifModels.Entry],
        path: Path,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral | None = None,
        format_options: (
            FlextLdifModels.WriteFormatOptions | FlextLdifModelsDomains.WriteOptions | None
        ) = None,
    ) -> FlextResult[FlextLdifModelsResults.WriteResponse]:
        """Write entries to LDIF file.

        Args:
            entries: Entries to write
            path: Output file path
            server_type: Server type for quirk selection
            format_options: Write options

        Returns:
            FlextResult containing write response

        """
        # First get the LDIF string
        string_result = self.write_to_string(entries, server_type, format_options)
        if string_result.is_failure:
            return FlextResult.fail(
                string_result.error or "Failed to generate LDIF content",
            )

        ldif_content = string_result.unwrap()

        # Write to file
        try:
            path.write_text(ldif_content, encoding="utf-8")
        except (OSError, UnicodeEncodeError) as e:
            return FlextResult.fail(f"Failed to write LDIF file {path}: {e}")

        # Create response with basic statistics
        response = FlextLdifModelsResults.WriteResponse(
            content=ldif_content,
            statistics=FlextLdifModels.Statistics(
                total_entries=len(entries),
                processed_entries=len(entries),
            ),
        )

        return FlextResult.ok(response)

    def write(
        self,
        entries: list[FlextLdifModels.Entry],
        target_server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral
        | None = None,
        _output_target: str | None = None,
        output_path: Path | None = None,
        format_options: (
            FlextLdifModels.WriteFormatOptions | FlextLdifModelsDomains.WriteOptions | None
        ) = None,
        _template_data: dict[str, FlextLdifTypes.TemplateValue] | None = None,
    ) -> FlextResult[str | FlextLdifModelsResults.WriteResponse]:
        """Write entries to LDIF format (string or file).

        Args:
            entries: Entries to write
            target_server_type: Server type for quirk selection
            _output_target: Output target type ("string" or "file") - for compatibility
            output_path: If provided, write to file; otherwise return string
            format_options: Write options

        Returns:
            FlextResult containing LDIF string (if no output_path) or WriteResponse (if output_path)

        """
        if output_path is not None:
            # Write to file
            file_result = self.write_to_file(
                entries, output_path, target_server_type, format_options,
            )
            if file_result.is_failure:
                return FlextResult.fail(file_result.error or "File write failed")
            return FlextResult.ok(file_result.unwrap())
        # Return string
        string_result = self.write_to_string(
            entries, target_server_type, format_options,
        )
        if string_result.is_failure:
            return FlextResult.fail(string_result.error or "String write failed")
        return FlextResult.ok(string_result.unwrap())

    def execute(self, params: dict) -> FlextResult[FlextLdifModelsResults.WriteResponse]:
        """Execute write operation with parameters.

        This is the main entry point for the service.
        """
        entries = params.get("entries", [])
        target_server_type = params.get("target_server_type", "rfc")
        output_path = params.get("output_path")
        format_options = params.get("format_options")

        return self.write(
            entries=entries,
            target_server_type=target_server_type,
            output_path=output_path,
            format_options=format_options,
        )


__all__ = ["FlextLdifWriter"]
