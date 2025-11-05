"""Unified LDIF Writer Service.

Routes to quirks system via FlextLdifRegistry for RFC-compliant LDIF writing.

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
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.services.registry import FlextLdifRegistry
from flext_ldif.services.sorting import FlextLdifSortingService
from flext_ldif.services.statistics import FlextLdifStatisticsService
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifWriterService(FlextService[Any]):
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
        writer = FlextLdifWriterService()
        result = writer.write(
            entries=entries,
            target_server_type="oud",
            output_target="file",
            output_path=Path("output.ldif")
        )

        # V2 Pattern: .result property on execute() (health check)
        response = FlextLdifWriterService().result
        # Returns WriteResponse with 0 entries (health check)

        # V1 Pattern: .execute() returns FlextResult
        result = FlextLdifWriterService().execute()
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
        self._quirk_registry = FlextLdifRegistry.get_global_instance()
        self._statistics_service = FlextLdifStatisticsService()

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
            format_options = format_options or FlextLdifModels.WriteFormatOptions()

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
            )

        except Exception as e:
            return FlextResult.fail(f"An unexpected error occurred during write: {e}")

    def _serialize_entries_to_ldif(
        self,
        entries: Sequence[FlextLdifModels.Entry],
        format_options: FlextLdifModels.WriteFormatOptions | None,
    ) -> str:
        """Serialize a sequence of Entry models to a single LDIF string."""
        # CRITICAL: Do NOT create default options if None - this causes incorrect folding
        # If None, raise error - caller MUST provide options
        if format_options is None:
            msg = "format_options is required for _serialize_entries_to_ldif"
            raise ValueError(msg)
        options = format_options
        output = StringIO()

        # Include version header if requested
        if options.include_version_header:
            output.write(FlextLdifConstants.ConfigDefaults.LDIF_VERSION_STRING + "\n")

        # Include global timestamp comment if requested
        if options.include_timestamps:
            timestamp = datetime.now().isoformat()
            output.write(f"# Generated on: {timestamp}\n")
            output.write(f"# Total entries: {len(entries)}\n\n")

        for entry in entries:
            # Check if modify add format is requested
            if options.ldif_changetype == "modify" and options.attributes:
                ldif_text = self._serialize_entry_as_modify_add(
                    entry, options, options.attributes
                )
            else:
                ldif_text = self._serialize_entry_to_ldif(entry, options)
            output.write(ldif_text)

        content = output.getvalue()
        output.close()
        return content

    def _serialize_entry_to_ldif(
        self,
        entry: FlextLdifModels.Entry,
        format_options: FlextLdifModels.WriteFormatOptions | None = None,
    ) -> str:
        """Serialize a single Entry model to a compliant LDIF string with OID→OUD conversion support."""
        if not entry.dn:
            msg = "Cannot write entry to LDIF: DN is missing."
            raise ValueError(msg)

        # CRITICAL: Do NOT create default options if None - this causes incorrect folding
        # If None, raise error - caller MUST provide options
        if format_options is None:
            msg = "format_options is required for _serialize_entry_to_ldif"
            raise ValueError(msg)
        options = format_options
        ldif_lines = []

        # **OID→OUD Conversion: Include ACL conversion comments**
        ldif_lines.extend(self._extract_acl_conversion_comments(entry, options))

        # Add DN and comments using reusable methods
        ldif_lines.extend(self._format_dn_lines(entry.dn.value, options))
        ldif_lines.extend(self._generate_comment_lines(entry, options))

        # Prepare attributes for writing - apply quirk attribute mappings if available
        attribute_items = list(entry.attributes.attributes.items())

        # Apply quirk-specific attribute name mappings (e.g., orclaci → aci for OUD)
        attribute_items = self._apply_attribute_name_mapping(attribute_items, entry)

        # Handle attribute ordering
        attribute_items = self._apply_attribute_ordering(
            attribute_items, entry, options
        )

        # Process each attribute
        for attr_name, attr_values in attribute_items:
            for value in attr_values:
                lines = self._process_attribute_value(attr_name, value, entry, options)
                ldif_lines.extend(lines)

        return "\n".join(ldif_lines) + "\n\n"

    def _format_dn_lines(
        self,
        dn_value: str,
        options: FlextLdifModels.WriteFormatOptions,
    ) -> list[str]:
        """Format DN line using FlextLdifUtilities.Writer.

        Args:
            dn_value: DN string to format
            options: Format options

        Returns:
            List containing single DN line or multiple folded lines

        """
        # Early return if folding is explicitly disabled
        if options.disable_line_folding:
            return [f"dn: {dn_value}"]

        # Use utility with folding configuration
        return FlextLdifUtilities.Writer.fmt_dn(
            dn_value, width=options.line_width, fold=options.fold_long_lines
        )

    def _fold_line(
        self,
        line: str,
        options: FlextLdifModels.WriteFormatOptions,
    ) -> list[str]:
        """Apply line folding using FlextLdifUtilities.Writer.

        Args:
            line: Line to potentially fold
            options: Format options

        Returns:
            List containing single line or multiple folded lines

        """
        # Early return if folding is explicitly disabled
        if options.disable_line_folding:
            return [line]

        # Apply folding if requested AND not disabled
        if options.fold_long_lines:
            return FlextLdifUtilities.Writer.fold(line, width=options.line_width)

        # No folding: return as-is
        return [line]

    def _normalize_value_whitespace(
        self,
        value_str: str,
        options: FlextLdifModels.WriteFormatOptions,
    ) -> str:
        """Normalize whitespace using FlextLdifUtilities.Writer.

        When line folding is disabled, we normalize whitespace to ensure
        proper formatting without relying on folding logic.

        Args:
            value_str: Value string to normalize
            options: Format options

        Returns:
            Normalized or original string

        """
        # When folding is disabled, normalize whitespace for clean output
        if options.disable_line_folding:
            return FlextLdifUtilities.Writer.norm_ws(value_str)

        # When folding is enabled, keep original (folding will handle it)
        return value_str

    def _generate_comment_lines(
        self,
        entry: FlextLdifModels.Entry,
        options: FlextLdifModels.WriteFormatOptions,
        per_entry: bool = False,
    ) -> list[str]:
        """Generate comment lines for an entry based on options.

        Args:
            entry: Entry with metadata
            options: Format options
            per_entry: If True, include per-entry timestamp

        Returns:
            List of comment lines

        """
        comments = []

        # Per-entry timestamp (for modify add format)
        if options.include_timestamps and per_entry:
            comments.append(f"# Entry written at: {datetime.now().isoformat()}")

        # Removed attributes
        if (
            options.write_removed_attributes_as_comments
            and entry.metadata
            and entry.metadata.removed_attributes
        ):
            comments.append("# Removed attributes during migration:")
            comments.extend(
                f"#   - {attr}" for attr in entry.metadata.removed_attributes
            )

        # Entry metadata
        if options.write_metadata_as_comments and entry.metadata:
            comments.append("# Entry Metadata:")
            if entry.metadata.server_type:
                comments.append(f"# Server Type: {entry.metadata.server_type}")
            if entry.metadata.extensions:
                for key, value in entry.metadata.extensions.items():
                    if key == "source_file":
                        comments.append(f"# Source File: {value}")
                    elif (
                        key != "aci_conversion_comments"
                    ):  # Skip ACI comments (handled separately)
                        comments.append(f"# {key}: {value}")

        # DN comment
        if options.include_dn_comments and len(entry.dn.value) > 50:
            comments.append(f"# Complex DN: {entry.dn.value}")

        return comments

    def _format_attribute_value_line(
        self,
        display_attr_name: str,
        value_str: str,
        options: FlextLdifModels.WriteFormatOptions,
    ) -> str:
        """Format attribute:value line using FlextLdifUtilities.Writer."""
        return FlextLdifUtilities.Writer.fmt_attr(
            display_attr_name, value_str, use_base64=options.base64_encode_binary
        )

    def _serialize_entry_as_modify_add(
        self,
        entry: FlextLdifModels.Entry,
        format_options: FlextLdifModels.WriteFormatOptions | None,
        attributes: list[str],
    ) -> str:
        """Serialize an entry in LDIF modify add format.

        This method writes entries in modify add format, including only the specified
        schema attributes. Used for schema entries where only specific attributes
        (attributetypes, objectclasses, matchingrules, ldapsyntaxes) should be written.

        Format:
        dn: cn=subschemasubentry
        changetype: modify
        add: attributetypes
        attributetypes: ( OID ... )
        -
        add: objectclasses
        objectclasses: ( OID ... )
        -

        Args:
            entry: Entry to serialize
            format_options: Format options
            attributes: List of schema attribute names to include (e.g., ['attributetypes', 'objectclasses'])

        Returns:
            LDIF string in modify add format

        """
        options = format_options or FlextLdifModels.WriteFormatOptions()
        ldif_lines = []

        # Add comments and DN using reusable methods
        ldif_lines.extend(self._generate_comment_lines(entry, options, per_entry=True))
        ldif_lines.extend(self._format_dn_lines(entry.dn.value, options))

        # Write changetype
        ldif_lines.append("changetype: modify")

        # Write each schema attribute in modify add format
        for attr_name in attributes:
            # Normalize attribute name if requested
            display_attr_name = (
                attr_name.lower() if options.normalize_attribute_names else attr_name
            )

            # Find the attribute in entry (case-insensitive)
            attr_values = None

            # Check both lowercase and original case
            for key, values in entry.attributes.attributes.items():
                if key.lower() == attr_name.lower():
                    attr_values = values
                    break

            if attr_values:
                # Convert to list if not already
                if not isinstance(attr_values, list):
                    attr_values = [attr_values]

                # Filter and normalize values
                filtered_values = []
                for value in attr_values:
                    value_str = self._normalize_value_whitespace(
                        str(value).strip(), options
                    )

                    # Skip empty values if not requested to write them
                    if not options.write_empty_values and not value_str:
                        continue

                    # Remove attribute name prefix if present (from schema definitions)
                    if value_str.startswith((f"{attr_name}:", f"{display_attr_name}:")):
                        value_str = value_str.split(":", 1)[1].strip()

                    filtered_values.append(value_str)

                if filtered_values:
                    # Write "add: attrname" directive
                    add_line = f"add: {display_attr_name}"
                    ldif_lines.extend(self._fold_line(add_line, options))

                    # Write each value with proper formatting
                    for value_str in filtered_values:
                        attr_line = self._format_attribute_value_line(
                            display_attr_name, value_str, options
                        )
                        ldif_lines.extend(self._fold_line(attr_line, options))

                    # Write separator "-"
                    ldif_lines.append("-")

        # Add empty line between entries
        ldif_lines.append("")
        return "\n".join(ldif_lines) + "\n"

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

    def _apply_attribute_name_mapping(
        self,
        attribute_items: list[tuple[str, Any]],
        entry: FlextLdifModels.Entry,
    ) -> list[tuple[str, Any]]:
        """Apply quirk-specific attribute name mappings to attribute list.

        Args:
            attribute_items: List of (attr_name, attr_values) tuples
            entry: Entry with metadata containing server type

        Returns:
            List of (attr_name, attr_values) with mapped names

        """
        # Get the quirk for the entry's server type
        quirks = self._quirk_registry.get_quirks(
            entry.metadata.server_type
            if entry.metadata and entry.metadata.server_type
            else "rfc"
        )

        if not quirks:
            return attribute_items

        quirk = quirks[0]
        quirk_entry = getattr(quirk, "entry", None)

        if quirk_entry is None or not hasattr(quirk_entry, "ATTRIBUTE_CASE_MAP"):
            return attribute_items

        # Apply attribute name mapping
        attr_map = quirk_entry.ATTRIBUTE_CASE_MAP
        mapped_items = []
        for attr_name, attr_values in attribute_items:
            mapped_name = attr_map.get(attr_name.lower(), attr_name)
            mapped_items.append((mapped_name, attr_values))

        return mapped_items

    def _apply_attribute_ordering(
        self,
        attribute_items: list[tuple[str, Any]],
        entry: FlextLdifModels.Entry,
        options: FlextLdifModels.WriteFormatOptions,
    ) -> list[tuple[str, Any]]:
        """Apply attribute ordering based on format options using FlextLdifSortingService.

        Priority: respect_attribute_order > sort_attributes > original order

        Args:
            attribute_items: List of (attr_name, attr_values) tuples
            entry: Entry with metadata
            options: Format options

        Returns:
            List of (attr_name, attr_values) with ordering applied

        """
        # Priority 1: Respect metadata ordering if requested
        if (
            options.respect_attribute_order
            and entry.metadata
            and entry.metadata.extensions
        ):
            order = entry.metadata.extensions.get("attribute_order")
            if isinstance(order, list):
                return FlextLdifSortingService.attributes_by_order(
                    attribute_items, order
                )

        # Priority 2: Alphabetical sorting if requested
        if options.sort_attributes:
            return FlextLdifSortingService.attributes_alphabetically(
                attribute_items, case_sensitive=False
            )

        # Priority 3: Keep original order
        return attribute_items

    def _extract_acl_conversion_comments(
        self,
        entry: FlextLdifModels.Entry,
        options: FlextLdifModels.WriteFormatOptions,
    ) -> list[str]:
        """Extract ACL conversion comments from entry metadata.

        Args:
            entry: Entry with metadata
            options: Format options

        Returns:
            List of comment lines

        """
        ldif_lines = []

        if not (options.write_metadata_as_comments and entry.metadata):
            return ldif_lines

        # Check for ACL conversion comments in entry metadata
        for attr_name in entry.attributes.attributes:
            # Check if attribute is an ACL attribute using constants
            acl_attrs_lower = {
                attr.lower()
                for attr in FlextLdifConstants.AclAttributes.ALL_ACL_ATTRIBUTES
            }
            if attr_name.lower() not in acl_attrs_lower:
                continue

            # Check if this attribute has conversion metadata
            if not (
                hasattr(entry.metadata, "extensions")
                and entry.metadata.extensions
                and entry.metadata.extensions.get("aci_conversion_comments")
            ):
                continue

            comments = entry.metadata.extensions["aci_conversion_comments"]
            if isinstance(comments, list):
                ldif_lines.extend(
                    comment for comment in comments if isinstance(comment, str)
                )
            elif isinstance(comments, str):
                ldif_lines.append(comments)

            if ldif_lines:
                ldif_lines.append("")  # Empty line after comments
            break  # Only process once

        return ldif_lines

    def _process_attribute_value(
        self,
        attr_name: str,
        value: Any,
        entry: FlextLdifModels.Entry,
        options: FlextLdifModels.WriteFormatOptions,
    ) -> list[str]:
        """Process a single attribute value and return LDIF lines.

        Args:
            attr_name: Attribute name
            value: Attribute value
            entry: Entry (for metadata)
            options: Format options

        Returns:
            List of LDIF lines (may be empty, single line, or folded lines)

        """
        # Normalize attribute name if requested
        display_attr_name = (
            attr_name.lower() if options.normalize_attribute_names else attr_name
        )

        value_str = self._normalize_value_whitespace(str(value), options)

        # Skip empty values if not requested to write them
        if not options.write_empty_values and not value_str.strip():
            return []

        # Check if attribute is marked as hidden
        is_hidden = False
        if entry.metadata and entry.metadata.extensions:
            hidden_attrs = entry.metadata.extensions.get("hidden_attributes", [])
            is_hidden = isinstance(hidden_attrs, list) and attr_name in hidden_attrs

        # Write hidden attributes as comments or format as attribute:value
        if is_hidden and options.write_hidden_attributes_as_comments:
            return [f"# {display_attr_name}: {value_str}"]

        line = self._format_attribute_value_line(display_attr_name, value_str, options)
        return self._fold_line(line, options)

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
    ) -> FlextResult[Any]:
        """Route output to appropriate handler.

        Args:
            entries: Denormalized entries
            output_target: Output target type
            output_path: Output file path (for file target)
            format_options: Formatting options
            header_content: Generated header
            original_count: Original entry count

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
    ) -> FlextResult[Any]:
        """Output LDIF content as string or file.

        Args:
            entries: Entries to serialize
            output_target: "string" or "file"
            output_path: Output file path (for file target)
            format_options: Formatting options
            header_content: Header to prepend
            original_count: Original entry count

        Returns:
            FlextResult with string content or WriteResponse

        """
        ldif_content = self._serialize_entries_to_ldif(entries, format_options)
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


__all__ = ["FlextLdifWriterService"]
