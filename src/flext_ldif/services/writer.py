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

from flext_core import r
from flext_core.runtime import FlextRuntime

from flext_ldif.base import s
from flext_ldif.models import m
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.typings import t
from flext_ldif.utilities import u


def _extract_pipe_value(
    pipe_result: r[object] | FlextRuntime.RuntimeResult[object],
) -> object | None:
    """Extract value from pipe result."""
    # Accept both FlextResult and RuntimeResult (compatible interfaces)
    return pipe_result.unwrap_or(None)


class FlextLdifWriter(s[m.Ldif.LdifResults.WriteResponse]):
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
            self,
            "_server",
            server if server is not None else FlextLdifServer(),
        )

    @staticmethod
    def _normalize_format_options(
        format_options: (
            m.Ldif.LdifResults.WriteFormatOptions
            | m.Ldif.LdifResults.WriteOptions
            | type
            | dict[str, t.GeneralValueType]
            | None
        ),
    ) -> m.Ldif.LdifResults.WriteFormatOptions:
        """Normalize format options to WriteFormatOptions."""
        # Pattern match on format_options type and convert to WriteFormatOptions
        if format_options is None:
            result_raw = m.Ldif.LdifResults.WriteFormatOptions()
        elif isinstance(format_options, type):
            result_raw = format_options()
        elif isinstance(format_options, m.Ldif.LdifResults.WriteFormatOptions):
            result_raw = format_options
        elif isinstance(format_options, m.Ldif.LdifResults.WriteOptions):
            result_raw = _extract_pipe_value(
                u.Reliability.pipe(
                    format_options.model_dump(exclude_none=True),
                    lambda d: (
                        {
                            "base64_encode_binary": (
                                d.get("base64_encode_binary")
                                if isinstance(d, dict)
                                else None
                            ),
                        }
                        if isinstance(d, dict)
                        and d.get("base64_encode_binary") is not None
                        else {}
                    ),
                    m.Ldif.LdifResults.WriteFormatOptions.model_validate,
                ),
            )
        elif isinstance(format_options, dict):
            result_raw = m.Ldif.LdifResults.WriteFormatOptions.model_validate(
                format_options
            )
        else:
            result_raw = None
        if result_raw is None:
            msg = f"Expected WriteFormatOptions | WriteOptions | dict | None, got {type(format_options)}"
            raise TypeError(msg)
        # Type narrowing: result_raw is object, check if WriteFormatOptions
        if isinstance(result_raw, m.Ldif.LdifResults.WriteFormatOptions):
            return result_raw
        # Fallback: should not happen, but handle gracefully
        msg = f"Unexpected type in match result: {type(result_raw)}"
        raise TypeError(msg)

    def write_to_string(
        self,
        entries: list[m.Ldif.Entry],
        server_type: str | None = None,
        format_options: (
            m.Ldif.LdifResults.WriteFormatOptions
            | m.Ldif.LdifResults.WriteOptions
            | None
        ) = None,
    ) -> r[str]:
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
            r containing LDIF string (RFC 2849 format)

        """
        # Get entry quirk for writing
        effective_server_type = server_type or "rfc"

        try:
            entry_quirk = self._server.entry(effective_server_type)
        except ValueError as e:
            # Invalid server type - return error instead of raising
            return r[str].fail(
                f"Invalid server type: {effective_server_type}. {e!s}",
            )

        if entry_quirk is None:
            return r[str].fail(
                f"No entry quirk found for server type: {effective_server_type}",
            )

        # Normalize format options
        options = self._normalize_format_options(format_options)

        # Direct call to entry quirk write method
        # Pass normalized options directly - model implements protocol via properties
        write_result = entry_quirk.write(entries, options)

        if write_result.is_failure:
            return r[str].fail(write_result.error or "LDIF writing failed")

        # Convert protocol result to concrete FlextResult (unwrap and re-wrap)
        return r[str].ok(write_result.value)

    def write_to_file(
        self,
        entries: list[m.Ldif.Entry],
        path: Path,
        server_type: str | None = None,
        format_options: (
            m.Ldif.LdifResults.WriteFormatOptions
            | m.Ldif.LdifResults.WriteOptions
            | None
        ) = None,
    ) -> r[m.Ldif.LdifResults.WriteResponse]:
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
            r containing WriteResponse with content and statistics

        """
        # First get the LDIF string
        string_result = self.write_to_string(entries, server_type, format_options)
        if string_result.is_failure:
            return r[m.Ldif.LdifResults.WriteResponse].fail(
                string_result.error or "Failed to generate LDIF content",
            )

        ldif_content = string_result.value

        # Create parent directories if they don't exist
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            return r[m.Ldif.LdifResults.WriteResponse].fail(
                f"Failed to create parent directories for {path}: {e}",
            )

        # Write to file
        try:
            path.write_text(ldif_content, encoding="utf-8")
        except (OSError, UnicodeEncodeError) as e:
            return r[m.Ldif.LdifResults.WriteResponse].fail(
                f"Failed to write LDIF file {path}: {e}",
            )

        # Create response with basic statistics
        # Use facade LdifResults.Statistics for LDIF-specific statistics
        response = m.Ldif.LdifResults.WriteResponse(
            content=ldif_content,
            statistics=m.Ldif.LdifResults.Statistics(
                total_entries=u.count(entries),
                processed_entries=u.count(entries),
            ),
        )

        return r[str].ok(response)

    def write(
        self,
        entries: list[m.Ldif.Entry],
        target_server_type: str | None = None,
        _output_target: str | None = None,
        output_path: Path | None = None,
        format_options: (
            m.Ldif.LdifResults.WriteFormatOptions
            | m.Ldif.LdifResults.WriteOptions
            | None
        ) = None,
        _template_data: dict[str, t.Ldif.TemplateValue] | None = None,
    ) -> r[str | m.Ldif.LdifResults.WriteResponse]:
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
            r containing LDIF string (if no output_path) or WriteResponse (if output_path)

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
                return r[str | m.Ldif.LdifResults.WriteResponse].fail(
                    file_result.error or "File write failed",
                )
            return r[str | m.Ldif.LdifResults.WriteResponse].ok(file_result.value)
        # Return string
        string_result = self.write_to_string(
            entries,
            target_server_type,
            format_options,
        )
        if string_result.is_failure:
            return r[str | m.Ldif.LdifResults.WriteResponse].fail(
                string_result.error or "String write failed",
            )
        return r[str | m.Ldif.LdifResults.WriteResponse].ok(string_result.value)

    def execute(
        self,
        params: dict[str, t.GeneralValueType] | None = None,
    ) -> r[m.Ldif.LdifResults.WriteResponse]:
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
            r containing WriteResponse or error

        Note:
            This is the main entry point for the service.

        """
        params = params or {}
        entries_raw = u.take(params, "entries", as_type=list, default=[])
        # Type narrowing: entries_raw is object, check if list[Entry]
        entries: list[m.Ldif.Entry] = (
            [entry for entry in entries_raw if isinstance(entry, m.Ldif.Entry)]
            if isinstance(entries_raw, list)
            else []
        )
        target_server_type_raw = u.take(
            params,
            "target_server_type",
            as_type=str,
            default="rfc",
        )
        # Normalize server type - normalize_server_type raises ValueError for invalid types
        target_server_type: str | None = None
        if isinstance(target_server_type_raw, str):
            try:
                target_server_type = u.Ldif.Server.normalize_server_type(
                    target_server_type_raw,
                )
            except ValueError:
                # Invalid server type - use None (will default to RFC in write method)
                target_server_type = None
        output_path_raw = u.take(params, "output_path", as_type=Path)
        # Type narrowing: output_path_raw is GeneralValueType, check if Path
        output_path: Path | None = (
            output_path_raw if isinstance(output_path_raw, Path) else None
        )
        format_options_raw: t.GeneralValueType = u.take(params, "format_options")
        # Type narrowing: format_options_raw is object, check if WriteFormatOptions or WriteOptions
        format_options: (
            m.Ldif.LdifResults.WriteFormatOptions
            | m.Ldif.LdifResults.WriteOptions
            | None
        ) = (
            format_options_raw
            if isinstance(
                format_options_raw,
                (
                    m.Ldif.LdifResults.WriteFormatOptions,
                    m.Ldif.LdifResults.WriteOptions,
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
            return r[m.Ldif.LdifResults.WriteResponse].fail(write_result.error)

        result_value = write_result.value
        if isinstance(result_value, m.Ldif.LdifResults.WriteResponse):
            return r[m.Ldif.LdifResults.WriteResponse].ok(result_value)

        # Convert string result to WriteResponse
        # Use facade LdifResults.Statistics for LDIF-specific statistics
        return r[m.Ldif.LdifResults.WriteResponse].ok(
            m.Ldif.LdifResults.WriteResponse(
                content=str(result_value),
                statistics=m.Ldif.LdifResults.Statistics(
                    total_entries=len(entries),
                    processed_entries=len(entries),
                ),
            ),
        )


__all__ = ["FlextLdifWriter"]
