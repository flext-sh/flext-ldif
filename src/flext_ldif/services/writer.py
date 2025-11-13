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
from typing import Any, cast

from flext_core import FlextResult, FlextService

from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.services.statistics import FlextLdifStatistics


class FlextLdifWriter(FlextService[FlextLdifModels.WriteResponse]):
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
                # This ensures RFC compliance regardless of fold_long_lines setting
                max_width = format_options.line_width or 76
                lines = processed_block.split("\n")
                folded_lines: list[str] = []
                for line in lines:
                    # Check byte length (RFC 2849 uses bytes, not characters)
                    if len(line.encode("utf-8")) > max_width:
                        # MUST fold per RFC 2849
                        folded_lines.append(cls._fold_line(line, max_width))
                    else:
                        folded_lines.append(line)

                processed_block = "\n".join(folded_lines)

                processed_entries.append(processed_block)

            return "\n\n".join(processed_entries)

    class LdifSerializer:
        """Handles LDIF and LDAP3 serialization - replaces _serialize_* methods."""

        def __init__(self, registry: FlextLdifServer) -> None:
            """Initialize with quirk registry."""
            self.registry = registry
            self.post_processor = FlextLdifWriter.LdifPostProcessor()

        @staticmethod
        def _generate_entry_comments(
            entry: FlextLdifModels.Entry,
            format_options: FlextLdifModels.WriteFormatOptions,
        ) -> str:
            """Generate LDIF comments for removed attributes and rejection reasons.

            Comments are written BEFORE the entry to document:
            - Attributes that were removed during migration (with original values)
            - Rejection reasons if entry was rejected

            Args:
                entry: Entry to generate comments for
                format_options: Write format options controlling comment generation

            Returns:
                String containing comment lines (with trailing newline if non-empty)

            """
            comment_lines: list[str] = []

            # Add rejection reason comments if enabled
            if format_options.write_rejection_reasons and entry.statistics:
                rejection_reason = entry.statistics.rejection_reason
                if rejection_reason:
                    comment_lines.extend([
                        FlextLdifConstants.CommentFormats.SEPARATOR_DOUBLE,
                        FlextLdifConstants.CommentFormats.HEADER_REJECTION_REASON,
                        FlextLdifConstants.CommentFormats.SEPARATOR_DOUBLE,
                        f"{FlextLdifConstants.CommentFormats.PREFIX_COMMENT}{rejection_reason}",
                        FlextLdifConstants.CommentFormats.SEPARATOR_EMPTY,
                    ])

            # Add removed attributes comments if enabled
            if (
                format_options.write_removed_attributes_as_comments
                and entry.entry_metadata
            ):
                removed_attrs = entry.entry_metadata.get(
                    "removed_attributes_with_values", {}
                )
                if removed_attrs and isinstance(removed_attrs, dict):
                    if (
                        comment_lines
                    ):  # Add separator if we already have rejection comments
                        comment_lines.append(
                            FlextLdifConstants.CommentFormats.SEPARATOR_EMPTY
                        )
                    comment_lines.extend([
                        FlextLdifConstants.CommentFormats.SEPARATOR_SINGLE,
                        FlextLdifConstants.CommentFormats.HEADER_REMOVED_ATTRIBUTES,
                        FlextLdifConstants.CommentFormats.SEPARATOR_SINGLE,
                    ])
                    # Generate attribute comment lines with explicit type safety
                    comment_lines.extend([
                        f"{FlextLdifConstants.CommentFormats.PREFIX_COMMENT}{attr_name}: {value}"
                        for attr_name, attr_values in removed_attrs.items()
                        for value in (
                            attr_values
                            if isinstance(attr_values, list)
                            else [attr_values]
                        )
                    ])
                    comment_lines.append(
                        FlextLdifConstants.CommentFormats.SEPARATOR_EMPTY
                    )

            # Return comments with trailing newline if non-empty
            if comment_lines:
                return "\n".join(comment_lines) + "\n"
            return ""

        def to_ldif_string(  # noqa: C901 - Acceptable complexity for serialization logic
            self,
            entries: Sequence[FlextLdifModels.Entry],
            target_server_type: str,
            format_options: FlextLdifModels.WriteFormatOptions,
        ) -> FlextResult[str]:
            """Serialize entries to LDIF string using quirks."""
            try:
                output = StringIO()

                # Include headers if requested, even for empty entry lists
                if format_options.include_version_header:
                    output.write(
                        FlextLdifConstants.ConfigDefaults.LDIF_VERSION_STRING + "\n"
                    )

                if format_options.include_timestamps:
                    timestamp = datetime.now(UTC).isoformat()
                    output.write(f"# Generated on: {timestamp}\n")
                    output.write(f"# Total entries: {len(entries)}\n\n")

                # RFC 2849: Empty entry list produces no entry content
                # But headers should still be included if requested
                if not entries:
                    ldif_content = output.getvalue()
                    return FlextResult.ok(ldif_content)

                quirks_list = self.registry.gets(target_server_type)
                if not quirks_list:
                    return FlextResult.fail(
                        f"Invalid server type: '{target_server_type}' - no quirk found"
                    )

                quirk = quirks_list[0]
                entry_quirk = quirk.entry_quirk
                if not entry_quirk:
                    return FlextResult.fail(
                        f"No entry quirk for server: '{target_server_type}'"
                    )

                for entry in entries:
                    if entry.entry_metadata is None:
                        entry.entry_metadata = {}
                    entry.entry_metadata["_write_options"] = format_options

                    # Generate and write comments BEFORE the entry
                    entry_comments = self._generate_entry_comments(
                        entry, format_options
                    )
                    if entry_comments:
                        output.write(entry_comments)

                    write_result = entry_quirk.write(entry)
                    if write_result.is_failure:
                        return FlextResult.fail(
                            f"Failed to write entry {entry.dn}: {write_result.error}"
                        )

                    output.write(write_result.unwrap())
                    output.write("\n")

                ldif_content = output.getvalue()

                # Apply post-processing for format options
                ldif_content = self.post_processor.apply_format_options(
                    ldif_content, format_options
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
        """Handles entry formatting - replaces _apply_write_formatting and _apply_format_options."""

        @staticmethod
        def apply_formatting(
            entries: Sequence[FlextLdifModels.Entry],
            options: FlextLdifModels.WriteFormatOptions,
        ) -> Sequence[FlextLdifModels.Entry]:
            """Apply formatting options to entries."""
            if not options.normalize_attribute_names:
                return entries

            processed = []
            for entry in entries:
                if not entry.attributes:
                    processed.append(entry)
                    continue

                new_attrs = {}
                for attr_name, attr_values in entry.attributes.attributes.items():
                    normalized_name = (
                        attr_name.lower()
                        if options.normalize_attribute_names
                        else attr_name
                    )
                    new_attrs[normalized_name] = attr_values

                processed_entry = FlextLdifModels.Entry(
                    dn=entry.dn,
                    attributes=FlextLdifModels.LdifAttributes(attributes=new_attrs),
                    entry_metadata=entry.entry_metadata,
                )
                processed.append(processed_entry)

            return processed

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
        ) -> FlextResult[Any]:
            """Route output to appropriate target."""
            if output_target == "string":
                return self._to_string(
                    entries, target_server_type, format_options, header_content
                )

            if output_target == "file":
                return self._to_file(
                    entries,
                    output_path,
                    target_server_type,
                    format_options,
                    header_content,
                )

            if output_target == "ldap3":
                return self.serializer.to_ldap3_format(entries)

            if output_target == "model":
                # Return list of entries directly (no WriteResponse for model mode)
                return FlextResult.ok(list(entries))

            return FlextResult.fail(f"Unsupported output target: {output_target}")

        def _to_string(
            self,
            entries: Sequence[FlextLdifModels.Entry],
            target_server_type: str,
            format_options: FlextLdifModels.WriteFormatOptions,
            header: str,
        ) -> FlextResult[str]:
            """Write to string - returns LDIF content string directly (NEW API)."""
            ldif_result = self.serializer.to_ldif_string(
                entries, target_server_type, format_options
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
                entries, target_server_type, format_options
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
                            entries
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
            template_data: dict[str, Any] | None,
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
                data = template_data or {}
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
                total = data.get("total_entries", len(entries))
                if total > 0:
                    data.setdefault(
                        "processed_percentage",
                        (data.get("processed_entries", 0) / total) * 100,
                    )
                    data.setdefault(
                        "rejected_percentage",
                        (data.get("rejected_entries", 0) / total) * 100,
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
        template_data: dict[str, Any] | None = None,
    ) -> FlextResult[Any]:
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
            formatter = self.EntryFormatter()
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
            if output_target in {"string", "file"}:
                formatted_entries = formatter.apply_formatting(entries, options)
            else:
                formatted_entries = entries

            header_result = header_builder.build(
                formatted_entries, header_template, template_data, options
            )
            if header_result.is_failure:
                return header_result
            header_content = header_result.unwrap()

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
                    unique_id=f"write_{uuid.uuid4().hex[:8]}",
                    event_type="ldif.write",
                    aggregate_id=str(output_path)
                    if output_path
                    else f"write_{uuid.uuid4().hex[:8]}",
                    write_operation="write_file",
                    target_type="file",
                    entries_written=entries_count,
                    write_duration_ms=write_duration_ms,
                )

                response = result.unwrap()
                if isinstance(response, FlextLdifModels.WriteResponse):
                    updated_stats = response.statistics.add_event(write_event)
                    response = response.model_copy(update={"statistics": updated_stats})
                    result = FlextResult.ok(response)

            return result

        except Exception as e:
            return FlextResult.fail(f"Write operation failed: {e}")

    def execute(self) -> FlextResult[FlextLdifModels.WriteResponse]:
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
