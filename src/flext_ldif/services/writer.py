"""Unified LDIF Writer Service.

Routes to quirks system via FlextLdifServer for RFC-compliant LDIF writing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from typing import TYPE_CHECKING, cast

from flext_core import FlextResult, FlextService

from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.services.statistics import FlextLdifStatistics

# Type alias to avoid Pydantic v2 forward reference resolution issues
# FlextLdifModels is a namespace class, not an importable module
if TYPE_CHECKING:
    _WriteResponseType = FlextLdifModels.WriteResponse
else:
    _WriteResponseType = object  # type: ignore[misc]


class FlextLdifWriter(FlextService[_WriteResponseType]):
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
            quirk_registry: Optional quirk registry (primarily for testing/injection).
                If None, creates a new FlextLdifServer instance.

        Raises:
            ValueError: If quirk_registry is provided but is None (invalid state)

        """
        super().__init__()
        # No fallback - create new instance if not provided
        if quirk_registry is None:
            self._registry = FlextLdifServer()
        else:
            self._registry = quirk_registry
        self._statistics_service = FlextLdifStatistics()
        # Store config for potential use (not currently utilized in write operations)
        self._config = config

    # ==================== NESTED HELPER CLASSES ====================
    # These replace private methods with composable, testable classes

    class LdifPostProcessor:
        """Applies format options to LDIF string output via post-processing."""

        @staticmethod
        def _fold_line(line: str, max_width: int) -> str:
            """Fold line according to RFC 2849 using UTF-8 byte length.

            Lines longer than max_width BYTES are folded with newline + space.
            RFC 2849 section 3: Lines must not exceed 76 bytes (not characters).
            """
            line_bytes = line.encode("utf-8")
            if len(line_bytes) <= max_width:
                return line

            # Fold by bytes, ensuring we don't split multibyte UTF-8 sequences
            result: list[str] = []
            pos = 0

            # First line: max_width bytes
            while pos < len(line_bytes):
                if not result:
                    # First line gets full max_width
                    chunk_end = min(pos + max_width, len(line_bytes))
                else:
                    # Continuation lines: max_width - 1 (space prefix takes 1 byte)
                    chunk_end = min(pos + max_width - 1, len(line_bytes))

                # Find valid UTF-8 boundary (don't split multibyte chars)
                while chunk_end > pos:
                    try:
                        chunk = line_bytes[pos:chunk_end].decode("utf-8")
                        break
                    except UnicodeDecodeError:
                        # Backup to previous byte to find valid boundary
                        chunk_end -= 1

                if chunk_end <= pos:
                    # Should not happen with valid UTF-8, but handle gracefully
                    chunk_end = pos + 1

                chunk = line_bytes[pos:chunk_end].decode("utf-8")

                if result:
                    # Continuation line: prefix with space
                    result.append(" " + chunk)
                else:
                    # First line: no prefix
                    result.append(chunk)

                pos = chunk_end

            return "\n".join(result)

        @staticmethod
        def _sort_entry_lines(entry_block: str) -> str:
            """Sort attribute lines alphabetically within entry."""
            lines = entry_block.split("\n")
            if not lines:
                return entry_block

            # Separate header (DN, comments, changetype) from attributes
            header_lines: list[str] = []
            attr_lines: list[str] = []

            for line in lines:
                if not line.strip():
                    continue
                if line.startswith(("#", "version:", "dn:", "changetype:")):
                    header_lines.append(line)
                elif line.startswith(" "):  # Folded continuation
                    if attr_lines:
                        attr_lines[-1] += "\n" + line
                else:
                    attr_lines.append(line)

            # Sort attributes while preserving folded lines
            attr_lines.sort()

            return "\n".join(header_lines + attr_lines)

        @staticmethod
        def _remove_empty_values(entry_block: str) -> str:
            """Remove attributes with empty values."""
            lines = entry_block.split("\n")
            result: list[str] = []

            skip_next_folded = False
            for line in lines:
                # Skip folded continuations of removed lines
                if skip_next_folded and line.startswith(" "):
                    continue
                skip_next_folded = False

                # Keep non-attribute lines
                if not line or line.startswith(("#", "dn:", "changetype:", "version:")):
                    result.append(line)
                    continue

                # Check attribute value
                if ":" in line and not line.startswith(" "):
                    _, _, value = line.partition(":")
                    if value.strip() or "::" in line:  # Keep non-empty or base64
                        result.append(line)
                    else:
                        skip_next_folded = True  # Remove folded lines too
                else:
                    result.append(line)

            return "\n".join(result)

        @classmethod
        def apply_format_options(
            cls,
            ldif_content: str,
            format_options: FlextLdifModels.WriteFormatOptions,
        ) -> str:
            """Apply format options to LDIF content.

            Implements RFC 2849 formatting via post-processing.
            IMPORTANT: RFC 2849 folding is ALWAYS applied when lines exceed 76 bytes,
            regardless of fold_long_lines setting.
            """
            if not ldif_content:
                return ldif_content

            # Split into entries (blank line separated)
            entries = ldif_content.split("\n\n")
            processed_entries: list[str] = []

            for entry_block in entries:
                if not entry_block.strip():
                    continue

                processed_block = entry_block

                # Apply sort_attributes
                if format_options.sort_attributes:
                    processed_block = cls._sort_entry_lines(processed_block)

                # Apply write_empty_values filtering
                if not format_options.write_empty_values:
                    processed_block = cls._remove_empty_values(processed_block)

                # RFC 2849 MANDATORY folding: ALWAYS apply when lines > 76 bytes
                # Python 3.13: Optimize with list comprehension and walrus operator
                max_width = format_options.line_width or 76
                lines = processed_block.split("\n")
                folded_lines = [
                    cls._fold_line(line, max_width)
                    if len(_line_bytes := line.encode("utf-8")) > max_width
                    else line
                    for line in lines
                ]
                processed_block = "\n".join(folded_lines)

                processed_entries.append(processed_block)

            return "\n\n".join(processed_entries)

    class LdifSerializer:
        """Handles LDIF and LDAP3 serialization - replaces _serialize_* methods."""

        def __init__(self, registry: FlextLdifServer) -> None:
            """Initialize with quirk registry."""
            self.registry = registry
            self.post_processor = FlextLdifWriter.LdifPostProcessor()

        def _write_headers(
            self,
            output: StringIO,
            format_options: FlextLdifModels.WriteFormatOptions,
            entry_count: int,
        ) -> None:
            """Write LDIF headers (version and timestamp) to output.

            Args:
                output: Output stream to write to
                format_options: Write format options
                entry_count: Number of entries for statistics

            """
            if format_options.include_version_header:
                output.write(
                    FlextLdifConstants.ConfigDefaults.LDIF_VERSION_STRING + "\n",
                )

            if format_options.include_timestamps:
                timestamp = datetime.now(UTC).isoformat()
                output.write(f"# Generated on: {timestamp}\n")
                output.write(f"# Total entries: {entry_count}\n\n")

        def _get_entry_quirk(self, target_server_type: str) -> FlextResult[object]:
            """Get entry quirk for target server type.

            Args:
                target_server_type: Server type identifier

            Returns:
                FlextResult with entry quirk or error

            """
            quirks_list = self.registry.gets(target_server_type)
            if not quirks_list:
                return FlextResult.fail(
                    f"Invalid server type: '{target_server_type}' - no quirk found",
                )

            quirk = quirks_list[0]
            entry_quirk = quirk.entry_quirk
            if not entry_quirk:
                return FlextResult.fail(
                    f"No entry quirk for server: '{target_server_type}'",
                )
            return FlextResult.ok(entry_quirk)

        def _write_all_entries(
            self,
            output: StringIO,
            entries: Sequence[FlextLdifModels.Entry],
            entry_quirk: object,
            format_options: FlextLdifModels.WriteFormatOptions,
        ) -> FlextResult[bool]:
            """Write all entries using quirk.

            Args:
                output: Output stream to write to
                entries: List of entries to write
                entry_quirk: Quirk for writing entries
                format_options: Write format options

            Returns:
                FlextResult with True on success or error

            """
            # Type narrowing: entry_quirk should be FlextLdifServersBase.Entry
            if not hasattr(entry_quirk, "write"):
                return FlextResult.fail("Entry quirk does not have write method")

            for entry in entries:
                # Type narrowing: entry_metadata is dict[str, object] | None
                # Use model_copy to update entry_metadata safely
                # RFC Compliance: write_options is processing metadata
                # Store WriteFormatOptions object in _write_options key for quirk extraction
                new_write_options = {
                    **entry.metadata.write_options,
                    "_write_options": format_options,
                }
                new_metadata = entry.metadata.model_copy(
                    update={"write_options": new_write_options}
                )
                updated_entry = entry.model_copy(update={"metadata": new_metadata})

                # Generate and write comments BEFORE the entry via quirk (DI)
                if hasattr(entry_quirk, "generate_entry_comments"):
                    entry_comments = entry_quirk.generate_entry_comments(
                        updated_entry, format_options
                    )
                    if entry_comments:
                        output.write(entry_comments)

                # Type narrowing: we've verified entry_quirk has write method
                write_method = entry_quirk.write
                write_result = write_method(updated_entry)
                if write_result.is_failure:
                    error_msg = f"Failed to write entry {updated_entry.dn}: {write_result.error}"
                    return FlextResult.fail(error_msg)

                output.write(write_result.unwrap())
                output.write("\n")

            return FlextResult.ok(True)

        def to_ldif_string(
            self,
            entries: Sequence[FlextLdifModels.Entry],
            target_server_type: str,
            format_options: FlextLdifModels.WriteFormatOptions,
        ) -> FlextResult[str]:
            """Serialize entries to LDIF string using quirks."""
            try:
                output = StringIO()

                # Write headers (even for empty entry lists)
                self._write_headers(output, format_options, len(entries))

                # RFC 2849: Empty entry list produces no entry content
                if not entries:
                    return FlextResult.ok(output.getvalue())

                # Get entry quirk for target server
                quirk_result = self._get_entry_quirk(target_server_type)
                if quirk_result.is_failure:
                    return FlextResult.fail(quirk_result.error or "Unknown error")
                entry_quirk = quirk_result.unwrap()

                # Write all entries
                write_result = self._write_all_entries(
                    output, entries, entry_quirk, format_options
                )
                if write_result.is_failure:
                    return FlextResult.fail(write_result.error or "Unknown error")

                # Apply post-processing for format options
                ldif_content = self.post_processor.apply_format_options(
                    output.getvalue(),
                    format_options,
                )

                return FlextResult.ok(ldif_content)

            except Exception as e:
                return FlextResult.fail(f"LDIF serialization failed: {e}")

        def to_ldap3_format(
            self,
            entries: Sequence[FlextLdifModels.Entry],
        ) -> FlextResult[list[tuple[str, dict[str, list[str]]]]]:
            """Convert entries to ldap3 format."""
            try:
                result = []
                for entry in entries:
                    if not entry.attributes:
                        continue

                    dn_str = str(entry.dn)
                    attrs_dict = entry.attributes.attributes
                    result.append((dn_str, attrs_dict))
                return FlextResult.ok(result)
            except Exception as e:
                return FlextResult.fail(f"LDAP3 conversion failed: {e}")

    class EntryFormatter:
        """Handles entry formatting via quirk delegation (DI pattern)."""

        def __init__(self, registry: FlextLdifServer) -> None:
            """Initialize with quirk registry for DI."""
            self.registry = registry

        def apply_formatting(
            self,
            entries: Sequence[FlextLdifModels.Entry],
            target_server_type: str,
            options: FlextLdifModels.WriteFormatOptions,
        ) -> Sequence[FlextLdifModels.Entry]:
            """Apply formatting options to entries via quirk delegation.

            All formatting/normalization is delegated to quirks via DI.
            No direct transformations are performed here.

            Args:
                entries: Entries to format
                target_server_type: Server type for quirk selection
                options: Write format options

            Returns:
                Formatted entries

            """
            # Get entry quirk for target server
            quirks_list = self.registry.gets(target_server_type)
            if not quirks_list:
                return entries

            quirk = quirks_list[0]
            entry_quirk = quirk.entry_quirk

            # Delegate formatting to quirk if method available
            if hasattr(entry_quirk, "format_entry_for_write"):
                return [
                    entry_quirk.format_entry_for_write(entry, options)
                    for entry in entries
                ]

            # Fallback: return entries unchanged if quirk doesn't support formatting
            return entries

    class OutputRouter:
        """Handles output routing - replaces _route_output and _output_ldif_content."""

        def __init__(self, serializer: FlextLdifWriter.LdifSerializer) -> None:
            """Initialize with LDIF serializer."""
            self.serializer = serializer

        def route_to_target(
            self,
            entries: Sequence[FlextLdifModels.Entry],
            output_target: str,
            output_path: Path | None,
            format_options: FlextLdifModels.WriteFormatOptions,
            header_content: str,
            target_server_type: str,
        ) -> FlextResult[
            str
            | FlextLdifModels.WriteResponse
            | list[tuple[str, dict[str, list[str]]]]
            | list[FlextLdifModels.Entry]
        ]:
            """Route output to appropriate target."""
            # Type alias for return type Union
            writer_result_union = (
                FlextLdifModels.WriteResponse
                | list[FlextLdifModels.Entry]
                | list[tuple[str, dict[str, list[str]]]]
                | str
            )

            if output_target == "string":
                string_result = self._to_string(
                    entries,
                    target_server_type,
                    format_options,
                    header_content,
                )
                if string_result.is_failure:
                    return FlextResult[writer_result_union].fail(string_result.error or "Unknown error")
                return FlextResult[writer_result_union].ok(string_result.unwrap())

            if output_target == "file":
                file_result = self._to_file(
                    entries,
                    output_path,
                    target_server_type,
                    format_options,
                    header_content,
                )
                if file_result.is_failure:
                    return FlextResult[writer_result_union].fail(file_result.error or "Unknown error")
                return FlextResult[writer_result_union].ok(file_result.unwrap())

            if output_target == "ldap3":
                ldap3_result = self.serializer.to_ldap3_format(entries)
                if ldap3_result.is_failure:
                    return FlextResult[writer_result_union].fail(ldap3_result.error or "Unknown error")
                return FlextResult[writer_result_union].ok(ldap3_result.unwrap())

            if output_target == "model":
                # Return list of entries directly (no WriteResponse for model mode)
                return FlextResult[writer_result_union].ok(list(entries))

            return FlextResult[writer_result_union].fail(
                f"Unsupported output target: {output_target}"
            )

        def _to_string(
            self,
            entries: Sequence[FlextLdifModels.Entry],
            target_server_type: str,
            format_options: FlextLdifModels.WriteFormatOptions,
            header: str,
        ) -> FlextResult[str]:
            """Write to string - returns LDIF content string directly (NEW API)."""
            ldif_result = self.serializer.to_ldif_string(
                entries,
                target_server_type,
                format_options,
            )
            if ldif_result.is_failure:
                return ldif_result

            ldif_content = ldif_result.unwrap()
            final_content = header + ldif_content if header else ldif_content

            # NEW API: Return string directly for string output mode
            # Event statistics are NOT tracked for string-only output
            return FlextResult.ok(final_content)

        def _to_file(
            self,
            entries: Sequence[FlextLdifModels.Entry],
            path: Path | None,
            target_server_type: str,
            format_options: FlextLdifModels.WriteFormatOptions,
            header: str,
        ) -> FlextResult[FlextLdifModels.WriteResponse]:
            """Write to file."""
            if not path:
                return FlextResult.fail("output_path required for file target")

            ldif_result = self.serializer.to_ldif_string(
                entries,
                target_server_type,
                format_options,
            )
            if ldif_result.is_failure:
                return cast("FlextResult[FlextLdifModels.WriteResponse]", ldif_result)

            try:
                ldif_content = ldif_result.unwrap()
                final_content = header + ldif_content if header else ldif_content

                # Create parent directories if they don't exist
                path.parent.mkdir(parents=True, exist_ok=True)

                path.write_text(final_content, encoding="utf-8")

                response = FlextLdifModels.WriteResponse(
                    content=final_content,  # File mode returns the content that was written
                    statistics=FlextLdifModels.Statistics(
                        total_entries=len(entries),
                        schema_entries=0,
                        data_entries=len(entries),
                        entries_written=len(
                            entries,
                        ),  # Count entries successfully written
                        parse_errors=0,
                        detected_server_type=target_server_type,
                    ),
                )
                return FlextResult.ok(response)

            except Exception as e:
                return FlextResult.fail(f"Failed to write file {path}: {e}")

    class HeaderBuilder:
        """Handles header generation - replaces _generate_header."""

        @staticmethod
        def build(
            entries: Sequence[FlextLdifModels.Entry],
            template: str | None,
            template_data: dict[str, object] | None,
            format_options: FlextLdifModels.WriteFormatOptions | None = None,
        ) -> FlextResult[str]:
            """Build header from template.

            Args:
                entries: List of entries being written
                template: Optional explicit template (overrides format_options)
                template_data: Data to populate template
                format_options: WriteFormatOptions with migration_header_template

            Returns:
                FlextResult with generated header string

            """
            # Determine template source (explicit > format_options > none)
            if not template and format_options:
                if (
                    format_options.write_migration_header
                    and format_options.migration_header_template
                ):
                    template = format_options.migration_header_template
                elif format_options.write_migration_header:
                    # Use default template from constants
                    template = FlextLdifConstants.MigrationHeaders.DEFAULT_TEMPLATE

            if not template:
                return FlextResult.ok("")

            try:
                # Build template data with defaults
                # No fallback - use empty dict only if template_data is explicitly None
                data: dict[str, object] = (
                    template_data if template_data is not None else {}
                )
                data.setdefault("entry_count", len(entries))
                data.setdefault("total_entries", len(entries))
                data.setdefault("timestamp", datetime.now(UTC).isoformat())
                data.setdefault("phase", "unknown")
                data.setdefault("source_server", "unknown")
                data.setdefault("target_server", "unknown")
                data.setdefault("base_dn", "")
                data.setdefault("processed_entries", len(entries))
                data.setdefault("rejected_entries", 0)

                # Calculate percentages
                total_entries = data.get("total_entries", len(entries))
                total_int = (
                    int(total_entries)
                    if isinstance(total_entries, (int, float, str))
                    else len(entries)
                )
                if total_int > 0:
                    processed_count = data.get("processed_entries", 0)
                    rejected_count = data.get("rejected_entries", 0)
                    processed_int = (
                        int(processed_count)
                        if isinstance(processed_count, (int, float, str))
                        else 0
                    )
                    rejected_int = (
                        int(rejected_count)
                        if isinstance(rejected_count, (int, float, str))
                        else 0
                    )
                    data.setdefault(
                        "processed_percentage",
                        (processed_int / total_int) * 100,
                    )
                    data.setdefault(
                        "rejected_percentage",
                        (rejected_int / total_int) * 100,
                    )
                else:
                    data.setdefault("processed_percentage", 0.0)
                    data.setdefault("rejected_percentage", 0.0)

                header = template.format(**data)
                return FlextResult.ok(header + "\n" if header else "")

            except Exception as e:
                return FlextResult.fail(f"Header generation failed: {e}")

    def write(
        self,
        entries: Sequence[FlextLdifModels.Entry],
        target_server_type: str,
        output_target: str,  # Literal["string", "file", "ldap3", "model"]
        output_path: Path | None = None,
        format_options: FlextLdifModels.WriteFormatOptions | None = None,
        header_template: str | None = None,
        template_data: dict[str, object] | None = None,
    ) -> FlextResult[
        str
        | FlextLdifModels.WriteResponse
        | list[tuple[str, dict[str, list[str]]]]
        | list[FlextLdifModels.Entry]
    ]:
        """Write LDIF entries using nested helper classes.

        Refactored to use composable nested classes instead of private methods.
        """
        start_time = time.perf_counter()
        entries_count = len(entries)

        # Validation
        if output_target == "file" and not output_path:
            return FlextResult.fail("output_path required for file target")

        if output_target not in {"string", "file", "ldap3", "model"}:
            return FlextResult.fail(f"Invalid output_target: {output_target}")

        try:
            # Initialize nested helpers
            serializer = self.LdifSerializer(self._registry)
            formatter = self.EntryFormatter(self._registry)
            router = self.OutputRouter(serializer)
            header_builder = self.HeaderBuilder()

            # Setup format options
            # RFC 2849: Use default options (includes version header) when not explicitly provided
            if format_options is None:
                options = FlextLdifModels.WriteFormatOptions()
            else:
                # Explicit format_options: respect user settings
                options = format_options

            # Pipeline: Format → Generate Header → Route Output
            # Only apply formatting for LDIF string/file outputs, not ldap3/model
            # All formatting delegated to quirks via DI
            if output_target in {"string", "file"}:
                formatted_entries = formatter.apply_formatting(
                    entries, target_server_type, options
                )
            else:
                formatted_entries = entries

            header_result = header_builder.build(
                formatted_entries,
                header_template,
                template_data,
                options,
            )
            if header_result.is_failure:
                # Convert FlextResult[str] to writer_result_union
                return FlextResult[
                    FlextLdifModels.WriteResponse
                    | list[FlextLdifModels.Entry]
                    | list[tuple[str, dict[str, list[str]]]]
                    | str
                ].fail(header_result.error or "Unknown error")
            header_content_str = header_result.unwrap()
            # Type narrowing: header_result.unwrap() returns str per HeaderBuilder.build()
            header_content: str = header_content_str

            result = router.route_to_target(
                formatted_entries,
                output_target,
                output_path,
                options,
                header_content,
                target_server_type,
            )

            # Add write event if successful
            if result.is_success:
                write_duration_ms = (time.perf_counter() - start_time) * 1000.0

                write_event = FlextLdifModels.WriteEvent(
                    write_operation="write_file",
                    target_type="file",
                    entries_written=entries_count,
                    write_duration_ms=write_duration_ms,
                    event_type="ldif.write",
                    aggregate_id=str(output_path)
                    if output_path
                    else f"write_{uuid.uuid4().hex[:8]}",
                )

                response = result.unwrap()
                if isinstance(response, FlextLdifModels.WriteResponse):
                    updated_stats = response.statistics.add_event(write_event)
                    response = response.model_copy(update={"statistics": updated_stats})
                    result = FlextResult.ok(response)

            return result

        except Exception as e:
            return FlextResult.fail(f"Write operation failed: {e}")

    def execute(self, **_kwargs: object) -> FlextResult[FlextLdifModels.WriteResponse]:
        """Execute service health check."""
        return FlextResult.ok(
            FlextLdifModels.WriteResponse(
                content=None,
                statistics=FlextLdifModels.Statistics(),
            ),
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # PRIVATE PIPELINE METHODS (V2 Pattern - Single Responsibility)
    # ═══════════════════════════════════════════════════════════════════════════
