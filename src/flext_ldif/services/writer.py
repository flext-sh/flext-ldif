"""Unified LDIF Writer Service.

Routes to quirks system via FlextLdifServer for RFC-compliant LDIF writing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import Any, Literal

from flext_core import FlextResult, FlextService

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.services.statistics import FlextLdifStatistics
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifWriter(FlextService[Any]):
    """Unified, stateless LDIF Writer Service.

    This service acts as a versatile serializer, converting Entry models into
    various output formats. It is stateless and relies on parameters passed
    to its `write` method for all configuration.

    Usage Pattern:
        This service uses the write() method directly (not execute()).
        For FlextService V2 patterns, use the execute() method which returns
        a health check response.

    Examples:
        # Direct write method (primary API)
        writer = FlextLdifWriter()
        result = writer.write(
            entries=entries,
            target_server_type="oud",
            output_target="file",
            output_path=Path("output.ldif")
        )

        # V2 Pattern: .result property on execute() (health check)
        response = FlextLdifWriter().result
        # Returns WriteResponse with 0 entries (health check)

        # V1 Pattern: .execute() returns FlextResult
        result = FlextLdifWriter().execute()
        response = result.unwrap()

    """

    def __init__(
        self,
        config: Any | None = None,  # Backward compatibility parameter (ignored)
        quirk_registry: Any | None = None,  # Backward compatibility parameter (ignored)
    ) -> None:
        """Initialize the writer service.

        Args:
            config: Deprecated parameter for backward compatibility (ignored)
            quirk_registry: Deprecated parameter for backward compatibility (ignored)

        """
        super().__init__()
        # The registry is a singleton, fetched at runtime.
        # Parameters are accepted for backward compatibility but not used
        self._quirk_registry = FlextLdifServer.get_global_instance()
        self._statistics_service = FlextLdifStatistics()

    def write(
        self,
        entries: Sequence[FlextLdifModels.Entry],
        target_server_type: str,
        output_target: Literal["string", "file", "ldap3", "model"],
        output_path: Path | None = None,
        format_options: FlextLdifModels.WriteFormatOptions | None = None,
        header_template: str | None = None,
        template_data: dict[str, Any] | None = None,
    ) -> FlextResult[Any]:
        """Write LDIF entries to a specified target with formatting options.

        Orchestrates the write pipeline:
        1. Validation
        2. Denormalization
        3. Header generation
        4. Output routing
        """
        # Pre-flight validation
        validation_result = self._validate_write_request(output_target, output_path)
        if validation_result.is_failure:
            return validation_result

        try:
            # format_options MUST be provided - we do NOT create defaults here
            # Default creation should happen at API level based on migration mode
            if format_options is None:
                msg = "format_options is required for write() method"
                return FlextResult.fail(msg)

            # Step 1: Denormalize entries
            denormalize_result = self._denormalize_entries(entries, target_server_type)
            if denormalize_result.is_failure:
                return denormalize_result
            denormalized_entries = denormalize_result.unwrap()

            # Step 2: Generate header
            header_result = self._generate_header(
                denormalized_entries, header_template, template_data
            )
            if header_result.is_failure:
                return header_result
            header_content = header_result.unwrap()

            # Step 3: Route to output
            return self._route_output(
                denormalized_entries,
                output_target,
                output_path,
                format_options,
                header_content,
                len(entries),
                target_server_type,
            )

        except Exception as e:
            return FlextResult.fail(f"An unexpected error occurred during write: {e}")

    def _serialize_entries_to_ldif(
        self,
        entries: Sequence[FlextLdifModels.Entry],
        format_options: FlextLdifModels.WriteFormatOptions | None,
        target_server_type: str,
    ) -> str:
        """Serialize a sequence of Entry models to a single LDIF string using quirks.

        This method delegates ALL serialization logic to server-specific quirks.
        The quirks handle DN conversion, attribute mapping, and server-specific formatting.
        """
        # CRITICAL: Do NOT create default options if None - this causes incorrect folding
        # If None, raise error - caller MUST provide options
        if format_options is None:
            msg = "format_options is required for _serialize_entries_to_ldif"
            raise ValueError(msg)
        options = format_options

        # Get quirks for target server (returns list, use first)
        quirks_list = self._quirk_registry.get_quirks(target_server_type)
        if not quirks_list:
            msg = (
                f"No quirk implementation found for server type: '{target_server_type}'"
            )
            raise ValueError(msg)

        # Use first quirk (highest priority)
        quirk = quirks_list[0]

        output = StringIO()

        # Include version header if requested
        if options.include_version_header:
            output.write(FlextLdifConstants.ConfigDefaults.LDIF_VERSION_STRING + "\n")

        # Include global timestamp comment if requested
        if options.include_timestamps:
            timestamp = datetime.now().isoformat()
            output.write(f"# Generated on: {timestamp}\n")
            output.write(f"# Total entries: {len(entries)}\n\n")

        # Delegate serialization to quirks - quirks handle ALL conversion logic
        for entry in entries:
            # Call quirk's Entry.write() method - this handles DN conversion, etc.
            write_result = quirk.Entry.write(entry)
            if write_result.is_failure:
                msg = f"Failed to write entry {entry.dn}: {write_result.error}"
                raise ValueError(msg)
            ldif_text = write_result.unwrap()
            output.write(ldif_text)

        content = output.getvalue()
        output.close()
        return content

    def _serialize_to_ldap3(
        self, entries: Sequence[FlextLdifModels.Entry]
    ) -> FlextResult[list[tuple[str, dict[str, list[str]]]]]:
        """Serialize a sequence of Entry models to the ldap3 format."""
        try:
            ldap3_entries = []
            for entry in entries:
                ldap3_attrs = {
                    key: [str(v) for v in values]
                    for key, values in entry.attributes.attributes.items()
                }
                ldap3_entries.append((entry.dn.value, ldap3_attrs))
            return FlextResult.ok(ldap3_entries)
        except Exception as e:
            return FlextResult.fail(f"Failed to serialize to ldap3 format: {e}")

    def execute(self) -> FlextResult[FlextLdifModels.WriteResponse]:
        """Execute service health check."""
        return FlextResult.ok(
            FlextLdifModels.WriteResponse(
                statistics=FlextLdifModels.WriteStatistics(entries_written=0)
            )
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # PRIVATE PIPELINE METHODS (V2 Pattern - Single Responsibility)
    # ═══════════════════════════════════════════════════════════════════════════

    def _validate_write_request(
        self, output_target: str, output_path: Path | None
    ) -> FlextResult[None]:
        """Validate write request parameters.

        Args:
            output_target: Output target type
            output_path: Output file path (required for file target)

        Returns:
            FlextResult indicating validation success or failure

        """
        if output_target == "file" and not output_path:
            return FlextResult.fail("An output_path is required for the 'file' target.")
        return FlextResult.ok(None)

    def _denormalize_entries(
        self, entries: Sequence[FlextLdifModels.Entry], target_server_type: str
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Denormalize entries to target server format.

        For RFC mode, entries are already in RFC format and don't need conversion.
        For other server types, entries are returned as-is (conversion happens during write).

        Args:
            entries: Entries to denormalize
            target_server_type: Target server type

        Returns:
            FlextResult with entries

        """
        quirks = self._quirk_registry.get_quirks(target_server_type)
        if not quirks:
            return FlextResult.fail(
                f"No quirk implementation found for server type: '{target_server_type}'"
            )

        # For RFC and other modes, entries don't need pre-denormalization
        # Conversion is handled during write() operations
        return FlextResult.ok(list(entries))

    def _generate_header(
        self,
        entries: list[FlextLdifModels.Entry],
        header_template: str | None,
        template_data: dict[str, Any] | None,
    ) -> FlextResult[str]:
        """Generate header content with statistics.

        Args:
            entries: Entries for statistics calculation
            header_template: Optional Jinja2 template
            template_data: Optional template data

        Returns:
            FlextResult with header content (empty string if no template)

        """
        if not header_template:
            return FlextResult.ok("")

        # Calculate statistics
        stats_result = self._statistics_service.calculate_for_entries(entries)
        statistics = stats_result.unwrap() if stats_result.is_success else {}

        # Render template
        template_context = {**(template_data or {}), "statistics": statistics}
        render_result = FlextLdifUtilities.Writer.render_template(
            header_template, template_context
        )
        if render_result.is_failure:
            return FlextResult.fail(
                f"Failed to render header template: {render_result.error}"
            )

        return render_result

    def _route_output(
        self,
        entries: list[FlextLdifModels.Entry],
        output_target: str,
        output_path: Path | None,
        format_options: FlextLdifModels.WriteFormatOptions,
        header_content: str,
        original_count: int,
        target_server_type: str,
    ) -> FlextResult[Any]:
        """Route output to appropriate handler.

        Args:
            entries: Denormalized entries
            output_target: Output target type
            output_path: Output file path (for file target)
            format_options: Formatting options
            header_content: Generated header
            original_count: Original entry count
            target_server_type: Target server type for quirk selection

        Returns:
            FlextResult with output-specific result

        """
        if output_target == "model":
            return FlextResult.ok(entries)

        if output_target == "ldap3":
            return self._serialize_to_ldap3(entries)

        if output_target in {"string", "file"}:
            return self._output_ldif_content(
                entries,
                output_target,
                output_path,
                format_options,
                header_content,
                original_count,
                target_server_type,
            )

        return FlextResult.fail(f"Unhandled output target: {output_target}")

    def _output_ldif_content(
        self,
        entries: list[FlextLdifModels.Entry],
        output_target: str,
        output_path: Path | None,
        format_options: FlextLdifModels.WriteFormatOptions,
        header_content: str,
        original_count: int,
        target_server_type: str,
    ) -> FlextResult[Any]:
        """Output LDIF content as string or file.

        Args:
            entries: Entries to serialize
            output_target: "string" or "file"
            output_path: Output file path (for file target)
            format_options: Formatting options
            header_content: Header to prepend
            original_count: Original entry count
            target_server_type: Target server type for quirk selection

        Returns:
            FlextResult with string content or WriteResponse

        """
        ldif_content = self._serialize_entries_to_ldif(
            entries, format_options, target_server_type
        )
        final_content = (
            f"{header_content}{ldif_content}" if header_content else ldif_content
        )

        if output_target == "string":
            return FlextResult.ok(final_content)

        # File output
        if not output_path:
            return FlextResult.fail("output_path is required for file target")

        write_result = FlextLdifUtilities.Writer.write_file(
            final_content,
            output_path,
            encoding=FlextLdifConstants.Encoding.DEFAULT_ENCODING,
        )
        if write_result.is_failure:
            return FlextResult.fail(f"Failed to write file: {write_result.error}")

        file_stats = write_result.unwrap()
        return FlextResult.ok(
            FlextLdifModels.WriteResponse(
                statistics=FlextLdifModels.WriteStatistics(
                    entries_written=original_count,
                    output_file=file_stats["path"],
                    file_size_bytes=file_stats["bytes_written"],
                    encoding=file_stats["encoding"],
                )
            )
        )


__all__ = ["FlextLdifWriter"]
