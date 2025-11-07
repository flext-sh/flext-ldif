"""Unified LDIF Writer Service.

Routes to quirks system via FlextLdifServer for RFC-compliant LDIF writing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64
from collections.abc import Sequence
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from typing import Any

from flext_core import FlextResult, FlextService

from flext_ldif.config import FlextLdifConfig
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
        config: FlextLdifConfig | None = None,
        quirk_registry: FlextLdifServer | None = None,
    ) -> None:
        """Initialize the writer service.

        Args:
            config: Optional configuration (primarily for testing/injection)
            quirk_registry: Optional quirk registry (primarily for testing/injection)

        """
        super().__init__()
        # Use injected registry for testing, fallback to singleton for production
        self._registry = quirk_registry or FlextLdifServer.get_global_instance()
        self._statistics_service = FlextLdifStatistics()
        # Store config for potential use (not currently utilized in write operations)
        self._config = config

    def write(
        self,
        entries: Sequence[FlextLdifModels.Entry],
        target_server_type: str,
        output_target: str,  # Literal["string", "file", "ldap3", "model"]
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
            # Create default format_options if not provided
            if format_options is None:
                format_options = FlextLdifModels.WriteFormatOptions()

            # Step 1: Denormalize entries
            denormalize_result = self._denormalize_entries(entries, target_server_type)
            if denormalize_result.is_failure:
                return denormalize_result
            denormalized_entries = denormalize_result.unwrap()

            # Step 2: Generate header
            header_result = self._generate_header(
                denormalized_entries,
                header_template,
                template_data,
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

        # Normalize attribute names if requested
        processed_entries = self._apply_write_formatting(entries, options)

        # Get quirks for target server (returns list, use first)
        quirks_list = self._registry.gets(target_server_type)
        if not quirks_list:
            msg = (
                f"No quirk implementation found for server type: '{target_server_type}'"
            )
            raise ValueError(msg)

        # Use first quirk (highest priority)
        quirk = quirks_list[0]

        output = StringIO()

        # Only include headers and metadata if there are entries to write
        if processed_entries:
            # Include version header if requested
            if options.include_version_header:
                output.write(
                    FlextLdifConstants.ConfigDefaults.LDIF_VERSION_STRING + "\n"
                )

            # Include global timestamp comment if requested
            if options.include_timestamps:
                timestamp = datetime.now(UTC).isoformat()
                output.write(f"# Generated on: {timestamp}\n")
                output.write(f"# Total entries: {len(processed_entries)}\n\n")

        # Delegate serialization to quirks - quirks handle ALL conversion logic
        entry_quirk = quirk.entry
        if entry_quirk is None:
            msg = f"No entry quirk available for server type: '{target_server_type}'"
            raise ValueError(msg)

        for entry in processed_entries:
            # Store write format options in entry metadata for quirk to access during write()
            # This follows the pattern used by RFC Entry._write_entry() method
            if entry.entry_metadata is None:
                entry.entry_metadata = {}
            entry.entry_metadata["_write_options"] = options

            # Call entry quirk's write() method - this handles DN conversion, etc.
            write_result = entry_quirk.write(entry)
            if write_result.is_failure:
                msg = f"Failed to write entry {entry.dn}: {write_result.error}"
                raise ValueError(msg)
            ldif_text = write_result.unwrap()
            output.write(ldif_text)
            # RFC 2849: Add blank line separator between entries
            output.write("\n")

        content = output.getvalue()
        output.close()
        return content

    def _serialize_to_ldap3(
        self,
        entries: Sequence[FlextLdifModels.Entry],
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
                content=None,
                statistics=FlextLdifModels.WriteStatistics(
                    entries_written=0,
                    output_file=None,
                ),
            ),
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # PRIVATE PIPELINE METHODS (V2 Pattern - Single Responsibility)
    # ═══════════════════════════════════════════════════════════════════════════

    def _apply_write_formatting(
        self,
        entries: Sequence[FlextLdifModels.Entry],
        options: FlextLdifModels.WriteFormatOptions,
    ) -> list[FlextLdifModels.Entry]:
        """Apply write formatting options to entries.

        Processes entries according to format options including:
        - normalize_attribute_names: Convert attribute names to lowercase
        - sort_attributes: Alphabetically sort attributes
        - base64_encode_binary: Base64 encode binary/special values
        - write_empty_values: Include/exclude empty string values
        - respect_attribute_order: Respect metadata attribute order

        Args:
            entries: Original entries
            options: Format options to apply

        Returns:
            List of processed entries with formatting applied

        """
        # Check if any formatting is needed
        needs_formatting = (
            options.normalize_attribute_names
            or options.sort_attributes
            or options.base64_encode_binary
            or not options.write_empty_values
            or options.respect_attribute_order
        )

        if not needs_formatting:
            # No formatting needed, return as list
            return list(entries)

        # Apply formatting options - delegate to helper method
        return [self._format_single_entry(entry, options) for entry in entries]

    def _format_single_entry(
        self,
        entry: FlextLdifModels.Entry,
        options: FlextLdifModels.WriteFormatOptions,
    ) -> FlextLdifModels.Entry:
        """Format a single entry according to write options.

        Args:
            entry: Entry to format
            options: Formatting options

        Returns:
            Formatted entry with options attached for quirk server consumption

        """
        formatted_attrs = self._format_attributes(
            entry.attributes.attributes,
            entry.metadata,
            options,
        )

        # Sort attributes by key if requested
        if options.sort_attributes:
            sorted_attrs: dict[str, list[str]] = {}
            for attr_name in sorted(formatted_attrs.keys(), key=str.lower):
                sorted_attrs[attr_name] = formatted_attrs[attr_name]
            formatted_attrs = sorted_attrs

        # Store format options in entry_metadata so quirk server can access them
        entry_metadata = entry.entry_metadata or {}
        entry_metadata["_write_options"] = options

        # Create new entry with formatted attributes
        return FlextLdifModels.Entry(
            dn=entry.dn,
            attributes=FlextLdifModels.LdifAttributes(attributes=formatted_attrs),
            metadata=entry.metadata,  # Preserve metadata
            entry_metadata=entry_metadata,  # Pass options to quirk server
        )

    def _format_attributes(
        self,
        attributes: dict[str, list[str]],
        metadata: FlextLdifModels.QuirkMetadata | None,
        options: FlextLdifModels.WriteFormatOptions,
    ) -> dict[str, list[str]]:
        """Format entry attributes according to options.

        Args:
            attributes: Original attributes
            metadata: Entry metadata for attribute ordering
            options: Formatting options

        Returns:
            Formatted attributes dictionary

        """
        formatted_attrs: dict[str, list[str]] = {}

        # Get attribute order from metadata
        attr_order: list[str] | None = None
        if options.respect_attribute_order and metadata:
            extensions = metadata.extensions or {}
            order_value = extensions.get("attribute_order")
            if isinstance(order_value, list):
                attr_order = order_value

        # Process attributes in order
        attrs_to_process = attributes
        if attr_order:
            ordered_attrs: dict[str, list[str]] = {}
            for attr_name in attr_order:
                if attr_name in attrs_to_process:
                    ordered_attrs[attr_name] = attrs_to_process[attr_name]
            for attr_name, values in attrs_to_process.items():
                if attr_name not in ordered_attrs:
                    ordered_attrs[attr_name] = values
            attrs_to_process = ordered_attrs

        for attr_name, values in attrs_to_process.items():
            # Normalize attribute name if requested
            final_attr_name = (
                attr_name.lower() if options.normalize_attribute_names else attr_name
            )

            # Process values
            processed_values = [
                self._format_value(v, options)
                for v in values
                if options.write_empty_values or v
            ]

            if processed_values or options.write_empty_values:
                formatted_attrs[final_attr_name] = processed_values

        return formatted_attrs

    def _format_value(
        self,
        value: str,
        options: FlextLdifModels.WriteFormatOptions,
    ) -> str:
        """Format a single attribute value.

        Args:
            value: Value to format
            options: Formatting options

        Returns:
            Formatted value

        """
        if not options.base64_encode_binary:
            return value

        # Check if value needs base64 encoding (binary, special chars, leading/trailing space)
        min_printable = 32
        max_printable = 126
        needs_encoding = (
            not isinstance(value, str)
            or any(ord(c) < min_printable or ord(c) > max_printable for c in value)
            or value.startswith((" ", ":"))
            or value.endswith(" ")
        )

        if needs_encoding:
            encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
            return f"__BASE64__:{encoded}"

        return value

    def _validate_write_request(
        self,
        output_target: str,
        output_path: Path | None,
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
        self,
        entries: Sequence[FlextLdifModels.Entry],
        target_server_type: str,
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
        quirks = self._registry.gets(target_server_type)
        if not quirks:
            return FlextResult.fail(
                f"No quirk implementation found for server type: '{target_server_type}'",
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
            header_template,
            template_context,
        )
        if render_result.is_failure:
            return FlextResult.fail(
                f"Failed to render header template: {render_result.error}",
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

    def _apply_format_options(
        self,
        ldif_content: str,
        format_options: FlextLdifModels.WriteFormatOptions,
    ) -> str:
        """Apply format options to LDIF content.

        Args:
            ldif_content: Raw LDIF content
            format_options: Formatting options to apply

        Returns:
            Formatted LDIF content

        """
        # Determine line width to use:
        # - If fold_long_lines=True: use format_options.line_width (customizable)
        # - If fold_long_lines=False: still must fold at 76 bytes (RFC 2849 requirement)
        line_width = (
            format_options.line_width
            if format_options.fold_long_lines
            else 76  # RFC 2849 mandatory limit
        )

        # Apply line folding
        lines = ldif_content.splitlines()
        folded_lines: list[str] = []

        for line in lines:
            if len(line) <= line_width:
                folded_lines.append(line)
            else:
                # Use utility method for RFC 2849 compliant folding
                folded = FlextLdifUtilities.Writer.fold(line, line_width)
                folded_lines.extend(folded)

        return "\n".join(folded_lines) + "\n" if folded_lines else ""

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
            entries,
            format_options,
            target_server_type,
        )

        # Apply format options (line folding, etc.) to LDIF content
        formatted_ldif = self._apply_format_options(ldif_content, format_options)

        final_content = (
            f"{header_content}{formatted_ldif}" if header_content else formatted_ldif
        )

        if output_target == "string":
            return FlextResult.ok(final_content)

        # File output
        if not output_path:
            return FlextResult.fail("output_path is required for file target")

        write_result = FlextLdifUtilities.Writer.write_file(
            final_content,
            output_path,
            encoding=FlextLdifConstants.Encoding.UTF8,
        )
        if write_result.is_failure:
            return FlextResult.fail(f"Failed to write file: {write_result.error}")

        file_stats = write_result.unwrap()
        bytes_written = file_stats.get("bytes_written", 0)
        file_size = int(bytes_written) if isinstance(bytes_written, (int, str)) else 0

        return FlextResult.ok(
            FlextLdifModels.WriteResponse(
                content=None,
                statistics=FlextLdifModels.WriteStatistics(
                    entries_written=original_count,
                    output_file=str(file_stats.get("path", "")),
                    file_size_bytes=file_size,
                    encoding=str(file_stats.get("encoding", "utf-8")),
                ),
            ),
        )


__all__ = ["FlextLdifWriter"]
