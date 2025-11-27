"""Writer Service - LDIF Entry Writing and Serialization.

Provides unified LDIF writing service routing to quirks system via FlextLdifServer
for RFC-compliant LDIF writing with multiple output formats (file, string, ldap3, model).

Scope: LDIF entry serialization, output routing, format options application,
header generation, post-processing (folding, sorting), RFC 2849 compliance.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from io import StringIO
from pathlib import Path
from typing import TypeAlias, override

from flext_core import FlextLogger, FlextResult, FlextUtilities

from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.services.entries import FlextLdifEntries
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.services.statistics import FlextLdifStatistics
from flext_ldif.utilities import FlextLdifUtilities

# Type alias for writer result union - used throughout OutputRouter
WriterResult: TypeAlias = (
    str
    | FlextLdifModels.WriteResponse
    | list[tuple[str, dict[str, list[str]]]]
    | list[FlextLdifModels.Entry]
)


class FlextLdifWriter(
    FlextLdifServiceBase[FlextLdifModels.WriteResponse],
):
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
        quirk_registry: FlextLdifServer | None = None,
    ) -> None:
        """Initialize the writer service.

        Args:
            quirk_registry: Optional quirk registry (primarily for testing/injection).
                If None, creates a new FlextLdifServer instance.

        Config is accessed via self.config.ldif (inherited from FlextLdifServiceBase).

        """
        super().__init__()
        # No fallback - create new instance if not provided
        if quirk_registry is None:
            self._registry = FlextLdifServer()
        else:
            self._registry = quirk_registry
        self._statistics_service = FlextLdifStatistics()

    # ==================== NESTED HELPER CLASSES ====================
    # These replace private methods with composable, testable classes

    class LdifPostProcessor:
        """Applies format options to LDIF string output via post-processing."""

        @staticmethod
        def _fold_line(line: str, max_width: int) -> str:
            """Fold line according to RFC 2849 using UTF-8 byte length.

            Lines longer than max_width BYTES are folded with newline + space.
            RFC 2849 section 3: Lines must not exceed 76 bytes (not characters).

            Uses FlextLdifUtilitiesWriter.fold() for RFC 2849 compliance.
            """
            folded_lines = FlextLdifUtilities.Writer.fold(line, width=max_width)
            return "\n".join(folded_lines)

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

                # Apply write_empty_values filtering
                if not format_options.write_empty_values:
                    processed_block = cls._remove_empty_values(processed_block)

                # RFC 2849 MANDATORY folding: ALWAYS apply when lines > 76 bytes
                max_width = (
                    format_options.line_width or FlextLdifConstants.Rfc.LINE_FOLD_WIDTH
                )
                lines = processed_block.split("\n")
                folded_lines: list[str] = []
                for line in lines:
                    # Use utility for folding (handles UTF-8 byte boundaries correctly)
                    folded = FlextLdifUtilities.Writer.fold(line, width=max_width)
                    folded_lines.extend(folded)
                processed_block = "\n".join(folded_lines)

                processed_entries.append(processed_block)

            return "\n\n".join(processed_entries)

    class LdifSerializer:
        """Handles LDIF and LDAP3 serialization - replaces _serialize_* methods."""

        def __init__(
            self,
            registry: FlextLdifServer,
            parent_logger: FlextLogger,
        ) -> None:
            """Initialize with quirk registry and logger."""
            self.registry = registry
            self.post_processor = FlextLdifWriter.LdifPostProcessor()
            self.logger = parent_logger

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
                timestamp = FlextUtilities.Generators.generate_iso_timestamp()
                output.write(f"# Generated on: {timestamp}\n")
                output.write(f"# Total entries: {entry_count}\n\n")

        def _get_entry_quirk(
            self,
            target_server_type: str,
        ) -> FlextResult[FlextLdifProtocols.Quirks.EntryProtocol]:
            """Get entry quirk for target server type.

            Args:
                target_server_type: Server type identifier

            Returns:
                FlextResult with entry quirk or error

            """
            quirk_result = self.registry.quirk(target_server_type)
            if quirk_result.is_failure:
                self.logger.error(
                    "Quirk not found",
                    target_server_type=target_server_type,
                    available_quirks=self.registry.list_registered_servers(),
                )
                return FlextResult.fail(
                    f"Invalid server type: '{target_server_type}' - no quirk found",
                )

            quirk = quirk_result.unwrap()
            entry_quirk = quirk.entry_quirk
            if not entry_quirk:
                self.logger.error(
                    "Entry quirk not found",
                    target_server_type=target_server_type,
                )
                return FlextResult.fail(
                    f"No entry quirk for server: '{target_server_type}'",
                )

            return FlextResult.ok(entry_quirk)

        def _restore_original_ldif_if_available(
            self,
            output: StringIO,
            entry: FlextLdifModels.Entry,
            format_options: FlextLdifModels.WriteFormatOptions,
        ) -> bool:
            """Restore original LDIF if available and enabled using Entry + Metadata pattern.

            Uses FlextLdifUtilities.Metadata and FlextLdifConstants.MetadataKeys for
            standardized metadata access.
            """
            if not entry.metadata or not entry.metadata.original_strings:
                return False

            # Use original_strings dict directly (Entry + Metadata pattern)
            # original_strings is a dict[str, str] in QuirkMetadata model
            # Key "entry_original_ldif" is defined in parser when preserving original LDIF
            original_ldif = entry.metadata.original_strings.get("entry_original_ldif")
            restore_enabled = getattr(format_options, "restore_original_format", False)
            if original_ldif and restore_enabled:
                output.write(original_ldif)
                if not original_ldif.endswith("\n"):
                    output.write("\n")
                return True
            return False

        def _update_entry_metadata_with_write_options(
            self,
            entry: FlextLdifModels.Entry,
            format_options: FlextLdifModels.WriteFormatOptions,
        ) -> FlextLdifModels.Entry:
            """Update entry metadata with write options using Entry + Metadata pattern.

            Uses FlextLdifConstants.MetadataKeys for standardized metadata keys.
            """
            # Use constant for metadata key
            new_write_options = {
                **entry.metadata.write_options,
                FlextLdifConstants.MetadataKeys.WRITE_OPTIONS: format_options,
            }
            new_metadata = entry.metadata.model_copy(
                update={"write_options": new_write_options},
            )
            return entry.model_copy(update={"metadata": new_metadata})

        def _restore_original_formatting_from_metadata(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextLdifModels.Entry:
            """Restore original DN formatting from metadata using Entry + Metadata pattern.

            Uses Entry + Metadata pattern - accesses metadata.extensions directly
            with standardized constant keys from FlextLdifConstants.MetadataKeys.
            """
            if not entry.metadata:
                return entry

            # Use Entry + Metadata pattern - access via metadata.extensions with constant key
            original_dn = entry.metadata.extensions.get(
                FlextLdifConstants.MetadataKeys.ORIGINAL_DN_COMPLETE,
            )
            if not original_dn or not entry.dn:
                return entry

            original_dn_str = (
                str(original_dn) if not isinstance(original_dn, str) else original_dn
            )
            return entry.model_copy(
                update={
                    "dn": FlextLdifModels.DistinguishedName(value=original_dn_str),
                },
            )

        def _write_entry_with_quirk(
            self,
            output: StringIO,
            entry: FlextLdifModels.Entry,
            entry_quirk: FlextLdifProtocols.Quirks.EntryProtocol,
            format_options: FlextLdifModels.WriteFormatOptions,
            idx: int,
            total: int,
        ) -> FlextResult[bool]:
            """Write single entry using quirk."""
            # Generate and write comments BEFORE the entry via quirk
            generate_comments = getattr(entry_quirk, "generate_entry_comments", None)
            if generate_comments:
                entry_comments = generate_comments(
                    entry,
                    format_options,
                )
                if entry_comments:
                    output.write(entry_comments)

            # Write entry via quirk (pass format_options for changetype/modify_operation)
            write_result = entry_quirk.write(entry, format_options)
            if write_result.is_failure:
                error_msg = f"Failed to write entry {entry.dn}: {write_result.error}"
                self.logger.error(
                    "Entry write failed",
                    entry_dn=str(entry.dn) if entry.dn else None,
                    entry_index=idx + 1,
                    total_entries=total,
                    error=str(write_result.error),
                )
                return FlextResult.fail(error_msg)

            # Write LDIF string to output
            ldif_str: str = str(write_result.unwrap())
            output.write(ldif_str)
            output.write("\n")

            self.logger.debug(
                "Wrote entry",
                entry_dn=str(entry.dn) if entry.dn else None,
                entry_index=idx + 1,
                total_entries=total,
            )
            return FlextResult.ok(True)

        def _write_all_entries(
            self,
            output: StringIO,
            entries: Sequence[FlextLdifModels.Entry],
            entry_quirk: FlextLdifProtocols.Quirks.EntryProtocol | None,
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
            # Write each entry
            for idx, entry in enumerate(entries):
                # Try to restore original LDIF first
                if self._restore_original_ldif_if_available(
                    output,
                    entry,
                    format_options,
                ):
                    continue

                # Update entry with write options
                updated_entry = self._update_entry_metadata_with_write_options(
                    entry,
                    format_options,
                )

                # Restore original formatting from metadata
                updated_entry = self._restore_original_formatting_from_metadata(
                    updated_entry,
                )

                # SRP: Apply marked attribute visibility based on format_options
                # Uses FlextLdifEntries service via DI (Entry + Metadata pattern via service)
                # Service handles metadata checking internally - no direct metadata access needed
                if (
                    updated_entry.metadata
                    and not format_options.write_removed_attributes_as_comments
                ):
                    # Use service for applying removals (SRP - service handles metadata access)
                    updated_entry = FlextLdifEntries.apply_marked_removals(
                        updated_entry,
                    )

                # Write entry using quirk
                if entry_quirk is None:
                    return FlextResult.fail("Entry quirk is required but not available")
                write_result = self._write_entry_with_quirk(
                    output,
                    updated_entry,
                    entry_quirk,
                    format_options,
                    idx,
                    len(entries),
                )
                if write_result.is_failure:
                    return write_result

            self.logger.info(
                "Wrote all entries",
                total_entries=len(entries),
            )
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
                    self.logger.error(
                        "Failed to get entry quirk",
                        target_server_type=target_server_type,
                        error=str(quirk_result.error),
                    )
                    return FlextResult.fail(quirk_result.error or "Unknown error")
                entry_quirk = quirk_result.unwrap()

                # Write all entries
                write_result = self._write_all_entries(
                    output,
                    entries,
                    entry_quirk,
                    format_options,
                )
                if write_result.is_failure:
                    self.logger.error(
                        "Failed to write entries",
                        target_server_type=target_server_type,
                        error=str(write_result.error),
                    )
                    return FlextResult.fail(write_result.error or "Unknown error")

                # Apply post-processing for format options
                ldif_content = self.post_processor.apply_format_options(
                    output.getvalue(),
                    format_options,
                )

                self.logger.info(
                    "Serialized entries to LDIF string",
                    entries_count=len(entries),
                    target_server_type=target_server_type,
                    ldif_length=len(ldif_content),
                )

                return FlextResult.ok(ldif_content)

            except Exception as e:
                self.logger.exception(
                    "Serialization failed",
                    target_server_type=target_server_type,
                    entries_count=len(entries),
                    error=str(e),
                )
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
                self.logger.exception(
                    "LDAP3 format conversion exception",
                    error=str(e),
                )
                return FlextResult.fail(f"LDAP3 conversion failed: {e}")

    class OutputRouter:
        """Handles output routing - replaces _route_output and _output_ldif_content."""

        def __init__(
            self,
            serializer: FlextLdifWriter.LdifSerializer,
            parent_logger: FlextLogger,
        ) -> None:
            """Initialize with LDIF serializer and logger."""
            self.serializer = serializer
            self.logger = parent_logger

        def route_to_target(
            self,
            entries: Sequence[FlextLdifModels.Entry],
            output_target: str,
            output_path: Path | None,
            format_options: FlextLdifModels.WriteFormatOptions,
            header_content: str,
            target_server_type: str,
        ) -> FlextResult[WriterResult]:
            """Route output to appropriate target."""
            # Python 3.13: DRY with match statement
            match output_target:
                case "string":
                    string_result = self._to_string(
                        entries,
                        target_server_type,
                        format_options,
                        header_content,
                    )
                    if string_result.is_failure:
                        return FlextResult[WriterResult].fail(
                            string_result.error or "Unknown error",
                        )
                    return FlextResult[WriterResult].ok(string_result.unwrap())
                case "file":
                    file_result = self._to_file(
                        entries,
                        output_path,
                        target_server_type,
                        format_options,
                        header_content,
                    )
                    if file_result.is_failure:
                        return FlextResult[WriterResult].fail(
                            file_result.error or "Unknown error",
                        )
                    return FlextResult[WriterResult].ok(file_result.unwrap())
                case "ldap3":
                    ldap3_result = self.serializer.to_ldap3_format(entries)
                    if ldap3_result.is_failure:
                        return FlextResult[WriterResult].fail(
                            ldap3_result.error or "Unknown error",
                        )
                    return FlextResult[WriterResult].ok(ldap3_result.unwrap())
                case "model":
                    return FlextResult[WriterResult].ok(list(entries))
                case _:
                    self.logger.error(
                        "Unsupported output target",
                        output_target=output_target,
                        supported_targets=["string", "file", "ldap3", "model"],
                    )
                    return FlextResult[WriterResult].fail(
                        f"Unsupported output target: {output_target}",
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

            # Python 3.13: DRY - extract content once
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
                self.logger.error(
                    "Output path required for file target",
                )
                return FlextResult.fail("output_path required for file target")

            ldif_result = self.serializer.to_ldif_string(
                entries,
                target_server_type,
                format_options,
            )
            if ldif_result.is_failure:
                self.logger.error(
                    "Failed to serialize LDIF string",
                    file_path=str(path),
                    error=str(ldif_result.error),
                )
                return FlextResult.fail(
                    ldif_result.error or "Unknown error",
                )

            try:
                # Python 3.13: DRY - extract content once
                ldif_content = ldif_result.unwrap()
                final_content = header + ldif_content if header else ldif_content

                # Use FlextLdifUtilitiesWriter.write_file() for consistency
                write_result = FlextLdifUtilities.Writer.write_file(
                    final_content,
                    path,
                    encoding="utf-8",
                )
                if write_result.is_failure:
                    return FlextResult.fail(
                        f"Failed to write file {path}: {write_result.error}",
                    )

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

                self.logger.info(
                    "Wrote entries to file",
                    file_path=str(path),
                    entries_count=len(entries),
                    file_size_bytes=len(final_content),
                )

                return FlextResult.ok(response)

            except Exception as e:
                self.logger.exception(
                    "Failed to write file",
                    file_path=str(path),
                    error=str(e),
                )
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
                data.setdefault(
                    "timestamp",
                    FlextUtilities.Generators.generate_iso_timestamp(),
                )
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

                # Use FlextLdifUtilitiesWriter.render_template for Jinja2 support
                # Falls back to str.format for simple templates
                if "{{" in template or "{%" in template:
                    render_result = FlextLdifUtilities.Writer.render_template(
                        template,
                        data,
                    )
                    if render_result.is_failure:
                        return FlextResult.fail(
                            f"Template rendering failed: {render_result.error}",
                        )
                    header = render_result.unwrap()
                else:
                    header = template.format(**data)
                return FlextResult.ok(header + "\n" if header else "")

            except Exception as e:
                return FlextResult.fail(f"Header generation failed: {e}")

    def _validate_write_params(
        self,
        output_target: str,
        output_path: Path | None,
    ) -> FlextResult[bool]:
        """Validate write parameters."""
        if output_target == "file" and not output_path:
            return FlextResult.fail("output_path required for file target")
        if output_target not in {"string", "file", "ldap3", "model"}:
            return FlextResult.fail(f"Invalid output_target: {output_target}")
        return FlextResult.ok(True)

    def _format_entries_for_write(
        self,
        entries: Sequence[FlextLdifModels.Entry],
        target_server_type: str,
        output_target: str,
        format_options: FlextLdifModels.WriteFormatOptions,
    ) -> Sequence[FlextLdifModels.Entry]:
        """Format entries for writing using quirk if needed."""
        # Only apply formatting for LDIF string/file outputs, not ldap3/model
        if output_target not in {"string", "file"}:
            return entries

        quirk_result = self._registry.quirk(target_server_type)
        if quirk_result.is_failure:
            return entries

        quirk = quirk_result.unwrap()
        entry_quirk = quirk.entry_quirk
        format_method = getattr(entry_quirk, "format_entry_for_write", None)
        if format_method:
            return [format_method(entry, format_options) for entry in entries]

        return entries

    def _add_write_event(
        self,
        result: FlextResult[WriterResult],
        start_time: float,
        entries_count: int,
        output_path: Path | None,
    ) -> FlextResult[WriterResult]:
        """Add write event to response statistics if applicable."""
        if not result.is_success:
            return result

        response = result.unwrap()
        if not isinstance(response, FlextLdifModels.WriteResponse):
            return result

        write_duration_ms = (time.perf_counter() - start_time) * 1000.0
        write_event = FlextLdifModels.WriteEvent(
            write_operation="write_file",
            target_type="file",
            entries_written=entries_count,
            write_duration_ms=write_duration_ms,
            event_type="ldif.write",
            aggregate_id=str(output_path)
            if output_path
            else f"write_{FlextUtilities.Generators.generate_short_id(8)}",
        )

        updated_stats = response.statistics.add_event(write_event)
        updated_response = response.model_copy(update={"statistics": updated_stats})
        return FlextResult.ok(updated_response)

    def write(
        self,
        entries: Sequence[FlextLdifModels.Entry],
        target_server_type: str,
        output_target: str,  # Literal["string", "file", "ldap3", "model"]
        output_path: Path | None = None,
        format_options: FlextLdifProtocols.Models.WriteFormatOptionsProtocol
        | None = None,
        header_template: str | None = None,
        template_data: dict[str, object] | None = None,
    ) -> FlextResult[WriterResult]:
        """Write LDIF entries using nested helper classes.

        Refactored to use composable nested classes instead of private methods.
        """
        start_time = time.perf_counter()
        entries_count = len(entries)

        # Validation
        validation_result = self._validate_write_params(output_target, output_path)
        if validation_result.is_failure:
            return FlextResult[WriterResult].fail(
                validation_result.error or "Validation failed"
            )

        try:
            # Initialize nested helpers
            serializer = self.LdifSerializer(self._registry, self.logger)
            router = self.OutputRouter(serializer, self.logger)
            header_builder = self.HeaderBuilder()

            # Setup format options
            options = format_options or FlextLdifModels.WriteFormatOptions()

            # Format entries if needed (Entry Model + Metadata based formatting)
            formatted_entries = self._format_entries_for_write(
                entries,
                target_server_type,
                output_target,
                options,
            )

            # Generate header
            header_result = header_builder.build(
                formatted_entries,
                header_template,
                template_data,
                options,
            )
            if header_result.is_failure:
                return FlextResult[WriterResult].fail(
                    header_result.error or "Unknown error",
                )
            header_content = header_result.unwrap()

            # Route output
            result = router.route_to_target(
                formatted_entries,
                output_target,
                output_path,
                options,
                header_content,
                target_server_type,
            )

            # Add write event to statistics if applicable
            result = self._add_write_event(
                result,
                start_time,
                entries_count,
                output_path,
            )

            # Log completion
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            if result.is_success:
                self.logger.info(
                    "Write operation completed",
                    entries_count=entries_count,
                    target_server_type=target_server_type,
                    output_target=output_target,
                    duration_ms=duration_ms,
                )
            else:
                self.logger.error(
                    "Write operation failed",
                    entries_count=entries_count,
                    target_server_type=target_server_type,
                    output_target=output_target,
                    error=str(result.error),
                    duration_ms=duration_ms,
                )

            return result

        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            self.logger.exception(
                "Write operation failed",
                entries_count=entries_count,
                target_server_type=target_server_type,
                output_target=output_target,
                error=str(e),
                duration_ms=duration_ms,
            )
            return FlextResult.fail(f"Write operation failed: {e}")

    @override
    def execute(self) -> FlextResult[FlextLdifModels.WriteResponse]:
        """Execute service health check."""
        return FlextResult[FlextLdifModels.WriteResponse].ok(
            FlextLdifModels.WriteResponse(
                content=None,
                statistics=FlextLdifModels.Statistics(),
            ),
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # PRIVATE PIPELINE METHODS (V2 Pattern - Single Responsibility)
    # ═══════════════════════════════════════════════════════════════════════════
