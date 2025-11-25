"""Unified LDIF Writer Service.

Routes to quirks system via FlextLdifServer for RFC-compliant LDIF writing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
import time
from collections.abc import Sequence
from io import StringIO
from pathlib import Path
from typing import cast

from flext_core import FlextLogger, FlextResult, FlextUtilities

from flext_ldif.base import LdifServiceBase
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.services.statistics import FlextLdifStatistics
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifWriter(LdifServiceBase):
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

        Config is accessed via self.config.ldif (inherited from LdifServiceBase).

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
        def _sort_entry_lines(
            entry_block: str,
            use_rfc_order: bool = False,  # noqa: FBT001, FBT002
            priority_attrs: list[str] | None = None,
        ) -> str:
            """Sort attribute lines within entry.

            Args:
                entry_block: LDIF entry block to sort
                use_rfc_order: If True, use RFC 2849 ordering (priority attrs first, then alphabetical)
                priority_attrs: List of attribute names to prioritize (default: ['objectClass'])

            Returns:
                Sorted entry block

            """
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

            # Sort attributes based on RFC order or alphabetical
            if use_rfc_order:
                # RFC 2849 ordering: priority attributes first, then alphabetical
                priority_list = priority_attrs or ["objectClass"]
                priority_lower = [attr.lower() for attr in priority_list]

                def sort_key(line: str) -> tuple[int, str]:
                    """Sort key: priority attrs first (by index), then alphabetical."""
                    attr_name = (
                        line.split(":", maxsplit=1)[0].lower()
                        if ":" in line
                        else line.lower()
                    )
                    try:
                        # Priority attribute: use its index as priority (0, 1, 2, ...)
                        priority_idx = priority_lower.index(attr_name)
                        return (priority_idx, attr_name)
                    except ValueError:
                        # Non-priority attribute: sort alphabetically after priorities
                        return (len(priority_list), attr_name)

                attr_lines.sort(key=sort_key)
            else:
                # Simple alphabetical sort (backward compatible)
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
                    processed_block = cls._sort_entry_lines(
                        processed_block,
                        use_rfc_order=format_options.use_rfc_attribute_order,
                        priority_attrs=format_options.rfc_order_priority_attributes,
                    )

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

        def _get_entry_quirk(self, target_server_type: str) -> FlextResult[object]:
            """Get entry quirk for target server type.

            Args:
                target_server_type: Server type identifier

            Returns:
                FlextResult with entry quirk or error

            """
            quirk = self.registry.quirk(target_server_type)
            if quirk is None:
                self.logger.error(
                    "Quirk not found",
                    target_server_type=target_server_type,
                    available_quirks=self.registry.list_registered_servers(),
                )
                return FlextResult.fail(
                    f"Invalid server type: '{target_server_type}' - no quirk found",
                )

            # Debug: trace the entry_quirk retrieval
            self.logger.debug(
                "DEBUG: Retrieved quirk from registry",
                quirk_type=type(quirk).__name__,
                target_server_type=target_server_type,
            )
            entry_quirk = quirk.entry_quirk
            self.logger.debug(
                "DEBUG: Retrieved entry_quirk",
                entry_quirk_type=type(entry_quirk).__name__,
                entry_quirk_repr=repr(entry_quirk)[:100],
            )
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
            """Restore original LDIF if available and enabled. Returns True if restored."""
            if not entry.metadata or not entry.metadata.original_strings:
                return False

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
            """Update entry metadata with write options."""
            new_write_options = {
                **entry.metadata.write_options,
                "_write_options": format_options,
            }
            new_metadata = entry.metadata.model_copy(
                update={"write_options": new_write_options},
            )
            return entry.model_copy(update={"metadata": new_metadata})

        def _restore_original_formatting_from_metadata(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextLdifModels.Entry:
            """Restore original DN formatting from metadata if available."""
            if not entry.metadata:
                return entry

            # Restore original DN if metadata has it
            if "original_dn_complete" in entry.metadata.extensions:
                original_dn = entry.metadata.extensions["original_dn_complete"]
                if original_dn and entry.dn:
                    original_dn_str = (
                        str(original_dn)
                        if not isinstance(original_dn, str)
                        else original_dn
                    )
                    return entry.model_copy(
                        update={
                            "dn": FlextLdifModels.DistinguishedName(
                                value=original_dn_str,
                            ),
                        },
                    )
            return entry

        def _apply_original_acl_format_as_name(
            self,
            entry: FlextLdifModels.Entry,
            format_options: FlextLdifModels.WriteFormatOptions,
        ) -> FlextLdifModels.Entry:
            """Apply original ACL format as ACI name if option is enabled.

            When use_original_acl_format_as_name=True and entry has 'aci' attribute,
            replaces the ACI name with the sanitized original ACL format from metadata.

            Args:
                entry: Entry to process
                format_options: Write format options

            Returns:
                Entry with ACI names replaced if applicable, otherwise unchanged entry

            """
            # Check if option is enabled
            if not format_options.use_original_acl_format_as_name:
                return entry

            # Check if entry has aci attribute
            if not entry.attributes:
                return entry

            aci_attr_name = "aci"
            if aci_attr_name not in entry.attributes.attributes:
                return entry

            # Get original ACL format from metadata
            if not entry.metadata or not entry.metadata.extensions:
                return entry

            original_format = entry.metadata.extensions.get(
                FlextLdifConstants.MetadataKeys.ACL_ORIGINAL_FORMAT,
            )
            if not original_format:
                return entry

            # Sanitize the original format for use as ACL name
            original_format_str = (
                str(original_format)
                if not isinstance(original_format, str)
                else original_format
            )
            sanitized_name, was_sanitized = FlextLdifUtilities.ACL.sanitize_acl_name(
                original_format_str,
            )

            if not sanitized_name:
                return entry

            # Replace ACI names in all aci attribute values
            aci_values = entry.attributes.attributes[aci_attr_name]
            new_aci_values: list[str] = []

            # Pattern to match acl "name" in ACI format
            aci_name_pattern = re.compile(r'acl\s+"[^"]*"')

            for aci_value in aci_values:
                # Replace the acl "name" part with the sanitized original format
                new_value = aci_name_pattern.sub(
                    f'acl "{sanitized_name}"',
                    aci_value,
                )
                new_aci_values.append(new_value)

            # Update entry with new aci values
            new_attrs = dict(entry.attributes.attributes)
            new_attrs[aci_attr_name] = new_aci_values

            # Store sanitization metadata if name was sanitized
            new_metadata = entry.metadata
            if was_sanitized:
                new_extensions = dict(entry.metadata.extensions)
                new_extensions[FlextLdifConstants.MetadataKeys.ACL_NAME_SANITIZED] = (
                    True
                )
                new_extensions[
                    FlextLdifConstants.MetadataKeys.ACL_ORIGINAL_NAME_RAW
                ] = original_format_str
                new_metadata = entry.metadata.model_copy(
                    update={"extensions": new_extensions},
                )

            return entry.model_copy(
                update={
                    "attributes": FlextLdifModels.LdifAttributes(attributes=new_attrs),
                    "metadata": new_metadata,
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
            # For compatibility with code that expects entry_quirk_typed
            # entry_quirk_typed = entry_quirk  # Removed unused variable

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

                # Apply original ACL format as ACI name if option is enabled
                updated_entry = self._apply_original_acl_format_as_name(
                    updated_entry,
                    format_options,
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
                    cast("FlextLdifProtocols.Quirks.EntryProtocol | None", entry_quirk),
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
        ) -> FlextResult[
            str
            | FlextLdifModels.WriteResponse
            | list[tuple[str, dict[str, list[str]]]]
            | list[FlextLdifModels.Entry]
        ]:
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
                        return FlextResult[
                            str
                            | FlextLdifModels.WriteResponse
                            | list[tuple[str, dict[str, list[str]]]]
                            | list[FlextLdifModels.Entry]
                        ].fail(
                            string_result.error or "Unknown error",
                        )
                    return FlextResult[
                        str
                        | FlextLdifModels.WriteResponse
                        | list[tuple[str, dict[str, list[str]]]]
                        | list[FlextLdifModels.Entry]
                    ].ok(
                        cast(
                            "str | FlextLdifModels.WriteResponse | list[tuple[str, dict[str, list[str]]]] | list[FlextLdifModels.Entry]",
                            string_result.unwrap(),
                        ),
                    )
                case "file":
                    file_result = self._to_file(
                        entries,
                        output_path,
                        target_server_type,
                        format_options,
                        header_content,
                    )
                    if file_result.is_failure:
                        return FlextResult[
                            str
                            | FlextLdifModels.WriteResponse
                            | list[tuple[str, dict[str, list[str]]]]
                            | list[FlextLdifModels.Entry]
                        ].fail(
                            file_result.error or "Unknown error",
                        )
                    return FlextResult[
                        str
                        | FlextLdifModels.WriteResponse
                        | list[tuple[str, dict[str, list[str]]]]
                        | list[FlextLdifModels.Entry]
                    ].ok(
                        cast(
                            "str | FlextLdifModels.WriteResponse | list[tuple[str, dict[str, list[str]]]] | list[FlextLdifModels.Entry]",
                            file_result.unwrap(),
                        ),
                    )
                case "ldap3":
                    ldap3_result = self.serializer.to_ldap3_format(entries)
                    if ldap3_result.is_failure:
                        return FlextResult[
                            str
                            | FlextLdifModels.WriteResponse
                            | list[tuple[str, dict[str, list[str]]]]
                            | list[FlextLdifModels.Entry]
                        ].fail(
                            ldap3_result.error or "Unknown error",
                        )
                    return FlextResult[
                        str
                        | FlextLdifModels.WriteResponse
                        | list[tuple[str, dict[str, list[str]]]]
                        | list[FlextLdifModels.Entry]
                    ].ok(
                        cast(
                            "str | FlextLdifModels.WriteResponse | list[tuple[str, dict[str, list[str]]]] | list[FlextLdifModels.Entry]",
                            ldap3_result.unwrap(),
                        ),
                    )
                case "model":
                    return FlextResult[
                        str
                        | FlextLdifModels.WriteResponse
                        | list[tuple[str, dict[str, list[str]]]]
                        | list[FlextLdifModels.Entry]
                    ].ok(list(entries))
                case _:
                    self.logger.error(
                        "Unsupported output target",
                        output_target=output_target,
                        supported_targets=["string", "file", "ldap3", "model"],
                    )
                    return FlextResult[
                        str
                        | FlextLdifModels.WriteResponse
                        | list[tuple[str, dict[str, list[str]]]]
                        | list[FlextLdifModels.Entry]
                    ].fail(
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
                return cast("FlextResult[FlextLdifModels.WriteResponse]", ldif_result)

            try:
                # Python 3.13: DRY - extract content once
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

                header = template.format(**data)
                return FlextResult.ok(header + "\n" if header else "")

            except Exception as e:
                return FlextResult.fail(f"Header generation failed: {e}")

    class OutputOptionsProcessor:
        """Processes entry attributes based on WriteOutputOptions (SRP).

        SRP Architecture:
            - filters.py: MARKS attributes with status (never removes)
            - entry.py: REMOVES attributes based on markers
            - writer.py: Uses WriteOutputOptions to determine output visibility

        This class decides how to render each attribute based on its marker status
        and the WriteOutputOptions configuration (show/hide/comment).
        """

        @staticmethod
        def apply_output_options(
            entry: FlextLdifModels.Entry,
            output_options: FlextLdifModels.WriteOutputOptions,
        ) -> FlextLdifModels.Entry:
            """Apply output options to entry based on marked attributes.

            Args:
                entry: Entry with marked attributes in metadata
                output_options: Options controlling visibility

            Returns:
                Entry with attributes filtered/commented based on options
            """
            if not entry.metadata or not entry.attributes:
                return entry

            # Get marked attributes and objectclasses from metadata
            marked_attrs = entry.metadata.extensions.get("marked_attributes", {})
            marked_ocs = entry.metadata.extensions.get("marked_objectclasses", {})

            if not marked_attrs and not marked_ocs:
                return entry

            # Build new attributes dict based on output options
            new_attrs = dict(entry.attributes.attributes)
            comments: list[str] = []

            # Process marked attributes
            for attr_name, marker_info in marked_attrs.items():
                if not isinstance(marker_info, dict):
                    continue

                status = marker_info.get("status", "")
                original_values = marker_info.get("original_value", [])

                # Determine output mode based on status
                output_mode = "show"  # default
                if status == FlextLdifConstants.AttributeMarkerStatus.FILTERED:
                    output_mode = output_options.show_filtered_attributes
                elif status == FlextLdifConstants.AttributeMarkerStatus.MARKED_FOR_REMOVAL:
                    output_mode = output_options.show_removed_attributes
                elif status == FlextLdifConstants.AttributeMarkerStatus.HIDDEN:
                    output_mode = output_options.show_hidden_attributes
                elif status == FlextLdifConstants.AttributeMarkerStatus.RENAMED:
                    output_mode = output_options.show_renamed_original

                # Apply the output mode
                if output_mode == "hide":
                    # Remove attribute from output
                    if attr_name in new_attrs:
                        del new_attrs[attr_name]
                elif output_mode == "comment":
                    # Move to comments and remove from normal output
                    if attr_name in new_attrs:
                        for val in new_attrs[attr_name]:
                            comments.append(f"# [{status.upper()}] {attr_name}: {val}")
                        del new_attrs[attr_name]
                # else "show" - keep as is

            # Process marked objectClasses (similar logic)
            if "objectClass" in new_attrs and marked_ocs:
                remaining_ocs: list[str] = []
                for oc_value in new_attrs["objectClass"]:
                    if oc_value in marked_ocs:
                        marker_info = marked_ocs[oc_value]
                        status = marker_info.get("status", "") if isinstance(marker_info, dict) else ""
                        output_mode = output_options.show_filtered_attributes
                        if output_mode == "hide":
                            continue  # Skip this objectClass
                        elif output_mode == "comment":
                            comments.append(f"# [{status.upper()}] objectClass: {oc_value}")
                            continue
                    remaining_ocs.append(oc_value)
                new_attrs["objectClass"] = remaining_ocs

            # Update entry with new attributes and store comments in metadata
            if comments:
                new_extensions = dict(entry.metadata.extensions)
                new_extensions["_output_comments"] = comments
                new_metadata = entry.metadata.model_copy(
                    update={"extensions": new_extensions},
                )
                return entry.model_copy(
                    update={
                        "attributes": FlextLdifModels.LdifAttributes(attributes=new_attrs),
                        "metadata": new_metadata,
                    },
                )

            return entry.model_copy(
                update={
                    "attributes": FlextLdifModels.LdifAttributes(attributes=new_attrs),
                },
            )

    def write(
        self,
        entries: Sequence[FlextLdifModels.Entry],
        target_server_type: str,
        output_target: str,  # Literal["string", "file", "ldap3", "model"]
        output_path: Path | None = None,
        format_options: FlextLdifModels.WriteFormatOptions | None = None,
        header_template: str | None = None,
        template_data: dict[str, object] | None = None,
        output_options: FlextLdifModels.WriteOutputOptions | None = None,
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

        # DEBUG: Trace entry into FlextLdifWriter.write()
        self.logger.debug(
            "DEBUG: FlextLdifWriter.write() ENTRY",
            entries_count=entries_count,
            target_server_type=target_server_type,
            output_target=output_target,
            output_path=str(output_path) if output_path else None,
            registry_type=type(self._registry).__name__,
            has_quirk=self._registry.quirk(target_server_type) is not None,
        )

        # Validation
        if output_target == "file" and not output_path:
            return FlextResult.fail("output_path required for file target")

        if output_target not in {"string", "file", "ldap3", "model"}:
            return FlextResult.fail(f"Invalid output_target: {output_target}")

        try:
            # Initialize nested helpers
            serializer = self.LdifSerializer(self._registry, self.logger)
            router = self.OutputRouter(serializer, self.logger)
            header_builder = self.HeaderBuilder()

            # Setup format options
            # Architecture: Config is source of truth, CLI can override via format_options
            if format_options is None:
                # Create WriteFormatOptions with default values
                options = FlextLdifModels.WriteFormatOptions(
                    line_width=78,  # RFC default
                    respect_attribute_order=True,
                    sort_attributes=False,
                    write_hidden_attributes_as_comments=False,
                    write_metadata_as_comments=False,
                    include_version_header=True,
                    include_timestamps=False,
                    base64_encode_binary=False,
                    fold_long_lines=True,
                    restore_original_format=False,
                    write_empty_values=True,
                    normalize_attribute_names=False,
                    include_dn_comments=False,
                    write_removed_attributes_as_comments=False,
                    write_migration_header=False,
                    migration_header_template=None,
                    write_rejection_reasons=False,
                    write_transformation_comments=False,
                    include_removal_statistics=False,
                    ldif_changetype=None,
                    ldif_modify_operation="add",
                    write_original_entry_as_comment=False,
                    entry_category=None,
                    acl_attribute_names=frozenset(),
                    comment_acl_in_non_acl_phases=True,
                    use_rfc_attribute_order=False,
                    rfc_order_priority_attributes=["objectClass"],
                )
            else:
                # Explicit format_options: respect user settings (CLI override)
                options = format_options

            # Pipeline: Format → Generate Header → Route Output
            # Only apply formatting for LDIF string/file outputs, not ldap3/model
            # All formatting delegated to quirks via DI (Python 3.13: inline comprehension)
            formatted_entries: Sequence[FlextLdifModels.Entry]
            if output_target in {"string", "file"}:
                quirk = self._registry.quirk(target_server_type)
                # Type narrowing: quirk can be FlextLdifServersBase | bool | None
                # Only proceed if it's not None or bool
                if (
                    quirk is not None
                    and not isinstance(quirk, bool)
                    and hasattr(
                        (entry_quirk := quirk.entry_quirk),
                        "format_entry_for_write",
                    )
                ):
                    format_method = getattr(entry_quirk, "format_entry_for_write", None)
                    formatted_entries = [
                        format_method(entry, options) if format_method else entry
                        for entry in entries
                    ]
                else:
                    formatted_entries = entries
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
                    else f"write_{FlextUtilities.Generators.generate_short_id(8)}",
                )

                response = result.unwrap()
                if isinstance(response, FlextLdifModels.WriteResponse):
                    updated_stats = response.statistics.add_event(write_event)
                    response = response.model_copy(update={"statistics": updated_stats})
                    result = FlextResult.ok(response)

                self.logger.info(
                    "Write operation completed",
                    entries_count=entries_count,
                    target_server_type=target_server_type,
                    output_target=output_target,
                    duration_ms=write_duration_ms,
                )
            else:
                write_duration_at_error = (time.perf_counter() - start_time) * 1000.0
                self.logger.error(
                    "Write operation failed",
                    entries_count=entries_count,
                    target_server_type=target_server_type,
                    output_target=output_target,
                    error=str(result.error),
                    duration_ms=write_duration_at_error,
                )

            return result

        except Exception as e:
            write_duration_at_error = (time.perf_counter() - start_time) * 1000.0
            self.logger.exception(
                "Write operation failed",
                entries_count=entries_count,
                target_server_type=target_server_type,
                output_target=output_target,
                error=str(e),
                duration_ms=write_duration_at_error,
            )
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
