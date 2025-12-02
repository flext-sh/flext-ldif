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

    Business Rule: Writer service delegates directly to server-specific entry quirks
    for LDIF writing. All server-specific formatting and transformations are handled
    by quirks, ensuring RFC 2849 compliance with server enhancements.

    Implication: Writing uses the same quirk system as parsing, ensuring round-trip
    compatibility. Format options control output formatting (changetype, encoding, etc.)
    while quirks handle server-specific attribute transformations.

    This service provides minimal, direct LDIF writing by delegating
    to FlextLdifServer entry quirks which handle all server-specific quirks.
    No unnecessary abstraction layers or routing logic.
    """

    _server: FlextLdifServer

    def __init__(self, server: FlextLdifServer | None = None) -> None:
        """Initialize writer with optional server instance.

        Business Rule: Server registry is optional - defaults to global instance if not provided.
        This enables dependency injection for testing while maintaining convenience defaults.

        Args:
            server: Optional FlextLdifServer instance (defaults to global instance)

        """
        super().__init__()
        # Use object.__setattr__ for frozen model
        object.__setattr__(
            self, "_server", server if server is not None else FlextLdifServer()
        )

    def write_to_string(
        self,
        entries: list[FlextLdifModels.Entry],
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral | None = None,
        format_options: (
            FlextLdifModels.WriteFormatOptions
            | FlextLdifModelsDomains.WriteOptions
            | None
        ) = None,
    ) -> FlextResult[str]:
        """Write entries to LDIF string format.

        Business Rule: String writing uses server-specific entry quirks for formatting.
        Format options control output style (changetype, encoding, attribute ordering).
        Invalid server types result in fail-fast error responses. Empty entry lists
        result in empty LDIF strings (valid per RFC 2849).

        Implication: Server type selection determines quirk used for formatting.
        Format options can override default formatting behavior. WriteOptions can be
        converted to WriteFormatOptions for compatibility.

        Args:
            entries: Entries to write (empty list results in empty LDIF)
            server_type: Server type for quirk selection (defaults to "rfc")
            format_options: Write options (WriteFormatOptions or WriteOptions)

        Returns:
            FlextResult containing LDIF string (RFC 2849 format)

        """
        # Get entry quirk for writing
        effective_server_type = server_type or "rfc"

        try:
            entry_quirk = self._server.entry(effective_server_type)
        except ValueError as e:
            # Invalid server type - return error instead of raising
            return FlextResult.fail(
                f"Invalid server type: {effective_server_type}. {e!s}",
            )

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
            # WriteOptions has different fields, so we need to map them
            write_opts_dict = format_options.model_dump(exclude_none=True)
            # Map WriteOptions fields to WriteFormatOptions
            # WriteOptions fields: format, base_dn, hidden_attrs, sort_entries, include_comments, base64_encode_binary
            # WriteFormatOptions doesn't have format, base_dn, hidden_attrs, sort_entries, include_comments
            # Only base64_encode_binary is common
            format_opts_dict_mapped: dict[
                str,
                bool | int | str | frozenset[str] | list[str] | dict[str, int] | None,
            ] = {}
            if "base64_encode_binary" in write_opts_dict:
                base64_val = write_opts_dict["base64_encode_binary"]
                if isinstance(base64_val, bool):
                    format_opts_dict_mapped["base64_encode_binary"] = base64_val
            # Create WriteFormatOptions with only valid fields
            options = FlextLdifModels.WriteFormatOptions.model_validate(
                format_opts_dict_mapped
            )
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
            FlextLdifModels.WriteFormatOptions
            | FlextLdifModelsDomains.WriteOptions
            | None
        ) = None,
    ) -> FlextResult[FlextLdifModelsResults.WriteResponse]:
        """Write entries to LDIF file.

        Business Rule: File writing delegates to write_to_string() then writes content
        to file using UTF-8 encoding per RFC 2849. File write errors (OSError, UnicodeEncodeError)
        result in fail-fast error responses. Response includes statistics for processed entries.

        Implication: File writing maintains RFC compliance with UTF-8 encoding. Directory
        creation is not handled - parent directories must exist or write will fail.

        Args:
            entries: Entries to write
            path: Output file path (parent directory must exist)
            server_type: Server type for quirk selection (defaults to "rfc")
            format_options: Write options (WriteFormatOptions or WriteOptions)

        Returns:
            FlextResult containing WriteResponse with content and statistics

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
        # Statistics is a PEP 695 type alias - use the underlying class directly
        response = FlextLdifModelsResults.WriteResponse(
            content=ldif_content,
            statistics=FlextLdifModelsResults.Statistics(
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
            FlextLdifModels.WriteFormatOptions
            | FlextLdifModelsDomains.WriteOptions
            | None
        ) = None,
        _template_data: dict[str, FlextLdifTypes.TemplateValue] | None = None,
    ) -> FlextResult[str | FlextLdifModelsResults.WriteResponse]:
        """Write entries to LDIF format (string or file).

        Business Rule: Unified write method routes to string or file writing based on
        output_path parameter. If output_path is provided, delegates to write_to_file().
        Otherwise delegates to write_to_string(). This provides convenient unified interface
        for both output formats.

        Implication: Return type varies based on output target - string for string output,
        WriteResponse for file output. Callers must handle union type appropriately.

        Args:
            entries: Entries to write
            target_server_type: Server type for quirk selection (defaults to "rfc")
            _output_target: Output target type (deprecated, use output_path instead)
            output_path: If provided, write to file; otherwise return string
            format_options: Write options (WriteFormatOptions or WriteOptions)
            _template_data: Template data (unused, for compatibility)

        Returns:
            FlextResult containing LDIF string (if no output_path) or WriteResponse (if output_path)

        """
        if output_path is not None:
            # Write to file
            file_result = self.write_to_file(
                entries,
                output_path,
                target_server_type,
                format_options,
            )
            if file_result.is_failure:
                return FlextResult.fail(file_result.error or "File write failed")
            return FlextResult.ok(file_result.unwrap())
        # Return string
        string_result = self.write_to_string(
            entries,
            target_server_type,
            format_options,
        )
        if string_result.is_failure:
            return FlextResult.fail(string_result.error or "String write failed")
        return FlextResult.ok(string_result.unwrap())

    def execute(
        self, params: dict[str, object] | None = None
    ) -> FlextResult[FlextLdifModelsResults.WriteResponse]:
        """Execute write operation with parameters.

        Business Rule: Execute method provides parameter-based write execution for
        service protocol compliance. Parameters must include 'entries' key with list
        of Entry models. Optional parameters include 'output_path', 'server_type', and
        'format_options'. Missing required parameters result in fail-fast error responses.

        Implication: This method enables service-based execution patterns while maintaining
        type safety through parameter validation. Used internally by service orchestration
        layers.

        Args:
            params: Execution parameters dict with 'entries' (required) and optional
                   'output_path', 'server_type', 'format_options'

        Returns:
            FlextResult containing WriteResponse or error

        Note:
            This is the main entry point for the service.

        """
        if params is None:
            params = {}
        entries_raw = params.get("entries", [])
        entries: list[FlextLdifModels.Entry] = (
            entries_raw if isinstance(entries_raw, list) else []
        )
        target_server_type_raw = params.get("target_server_type", "rfc")
        target_server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral | None = (
            None
        )
        if isinstance(target_server_type_raw, str):
            normalized = FlextLdifConstants.normalize_server_type(
                target_server_type_raw
            )
            if normalized is not None:
                target_server_type = normalized
        output_path_raw = params.get("output_path")
        output_path: Path | None = (
            output_path_raw if isinstance(output_path_raw, Path) else None
        )
        format_options_raw = params.get("format_options")
        format_options: (
            FlextLdifModels.WriteFormatOptions
            | FlextLdifModelsDomains.WriteOptions
            | None
        ) = (
            format_options_raw
            if isinstance(
                format_options_raw,
                (
                    FlextLdifModels.WriteFormatOptions,
                    FlextLdifModelsDomains.WriteOptions,
                ),
            )
            else None
        )

        write_result = self.write(
            entries=entries,
            target_server_type=target_server_type,
            output_path=output_path,
            format_options=format_options,
        )

        # Convert result to WriteResponse format
        if write_result.is_failure:
            return FlextResult.fail(write_result.error)

        result_value = write_result.unwrap()
        if isinstance(result_value, FlextLdifModelsResults.WriteResponse):
            return FlextResult.ok(result_value)

        # Convert string result to WriteResponse
        # Statistics is a PEP 695 type alias - use the underlying class directly
        return FlextResult.ok(
            FlextLdifModelsResults.WriteResponse(
                content=str(result_value),
                statistics=FlextLdifModelsResults.Statistics(
                    total_entries=len(entries),
                    processed_entries=len(entries),
                ),
            )
        )


__all__ = ["FlextLdifWriter"]
