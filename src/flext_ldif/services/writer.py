"""Unified LDIF Writer Service.

Routes to quirks system via FlextLdifRegistry for RFC-compliant LDIF writing.

The FlextLdifWriterService is the single unified interface for all LDIF writing
operations. It uses FlextLdifRegistry to find and route EACH entry to the
appropriate quirk which handles server-specific entry processing.

The writer ONLY:
1. Uses registry.find_entry_quirk() to find appropriate quirk for EACH entry
2. Calls quirk.process_entry() for server-specific entry transformations
3. Formats processed attributes to LDIF text (simple key:value format)
4. Writes LDIF text to output stream

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import textwrap
from collections.abc import Sequence
from io import StringIO
from pathlib import Path
from typing import Any, Literal

import jinja2
from flext_core import FlextResult, FlextService

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.services.registry import FlextLdifRegistry
from flext_ldif.services.statistics import FlextLdifStatisticsService


class FlextLdifWriterService(FlextService[Any]):
    """Unified, stateless LDIF Writer Service.

    This service acts as a versatile serializer, converting Entry models into
    various output formats. It is stateless and relies on parameters passed

    to its `write` method for all configuration.
    """

    def __init__(self) -> None:
        """Initialize the writer service."""
        super().__init__()
        # The registry is a singleton, fetched at runtime.
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
        """Write LDIF entries to a specified target with formatting options."""
        if output_target == "file" and not output_path:
            return FlextResult.fail("An output_path is required for the 'file' target.")

        try:
            # 1. Get the appropriate quirk for the target server.
            quirks = self._quirk_registry.get_quirks(target_server_type)
            if not quirks:
                return FlextResult.fail(
                    f"No quirk implementation found for server type: '{target_server_type}'"
                )
            quirk: FlextLdifProtocols.Quirks.QuirksPort = quirks[0]

            # 2. Denormalize all entries to the target format.
            denormalized_entries: list[FlextLdifModels.Entry] = []
            for entry in entries:
                result = quirk.denormalize_entry_from_rfc(entry)
                if result.is_failure:
                    return FlextResult.fail(
                        f"Failed to denormalize entry {entry.dn.value}: {result.error}"
                    )
                denormalized_entries.append(result.unwrap())

            # 3. Generate statistics for the header.
            stats_result = self._statistics_service.calculate_for_entries(
                denormalized_entries
            )
            statistics = stats_result.unwrap() if stats_result.is_success else {}

            # 4. Render the header template, if provided.
            header_content = ""
            if header_template:
                template_context = {**(template_data or {}), "statistics": statistics}
                try:
                    template = jinja2.Template(header_template)
                    header_content = template.render(template_context)
                except Exception as e:
                    return FlextResult.fail(
                        f"Failed to render Jinja2 header template: {e}"
                    )

            # 5. Route to the appropriate serializer based on the output target.
            if output_target == "model":
                return FlextResult.ok(denormalized_entries)

            if output_target == "ldap3":
                return self._serialize_to_ldap3(denormalized_entries)

            ldif_content = self._serialize_entries_to_ldif(
                denormalized_entries, format_options
            )

            final_content = (
                f"{header_content}{ldif_content}" if header_content else ldif_content
            )

            if output_target == "string":
                return FlextResult.ok(final_content)

            if output_target == "file" and output_path:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(
                    final_content, encoding=FlextLdifConstants.Encoding.DEFAULT_ENCODING
                )
                return FlextResult.ok(
                    FlextLdifModels.WriteResponse(
                        statistics=FlextLdifModels.WriteStatistics(
                            entries_written=len(entries),
                            output_file=str(output_path),
                            file_size_bytes=len(final_content.encode("utf-8")),
                            encoding=FlextLdifConstants.Encoding.DEFAULT_ENCODING,
                        )
                    )
                )

            return FlextResult.fail(f"Unhandled output target: {output_target}")

        except Exception as e:
            return FlextResult.fail(f"An unexpected error occurred during write: {e}")

    def _serialize_entries_to_ldif(
        self,
        entries: Sequence[FlextLdifModels.Entry],
        format_options: FlextLdifModels.WriteFormatOptions | None,
    ) -> str:
        """Serialize a sequence of Entry models to a single LDIF string."""
        options = format_options or FlextLdifModels.WriteFormatOptions()
        output = StringIO()

        # Include version header if requested
        if options.include_version_header:
            output.write(FlextLdifConstants.ConfigDefaults.LDIF_VERSION_STRING + "\n")

        # Include timestamp comment if requested
        if options.include_timestamps:
            from datetime import datetime

            timestamp = datetime.now().isoformat()
            output.write(f"# Generated on: {timestamp}\n")
            output.write(f"# Total entries: {len(entries)}\n\n")

        for entry in entries:
            ldif_text = self._serialize_entry_to_ldif(entry, format_options)
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

        options = format_options or FlextLdifModels.WriteFormatOptions()
        ldif_lines = []

        # **OID→OUD Conversion: Include ACL conversion comments**
        if options.write_metadata_as_comments and entry.metadata:
            # Check for ACL conversion comments in entry metadata or attributes
            for attr_name, attr_values in entry.attributes.attributes.items():
                # Check if attribute is an ACL attribute using constants
                acl_attrs_lower = {
                    attr.lower()
                    for attr in FlextLdifConstants.AclAttributes.ALL_ACL_ATTRIBUTES
                }
                if attr_name.lower() in acl_attrs_lower:  # ACL attribute (OUD/OID/etc.)
                    # Check if this attribute has conversion metadata
                    if (
                        hasattr(entry.metadata, "extensions")
                        and entry.metadata.extensions
                        and entry.metadata.extensions.get("aci_conversion_comments")
                    ):
                        comments = entry.metadata.extensions["aci_conversion_comments"]
                        if isinstance(comments, list):
                            ldif_lines.extend(
                                comment
                                for comment in comments
                                if isinstance(comment, str)
                            )
                        elif isinstance(comments, str):
                            ldif_lines.append(comments)
                        ldif_lines.append("")  # Empty line after comments

        # Include DN comment if requested
        if options.include_dn_comments and len(entry.dn.value) > 50:
            ldif_lines.append(f"# Complex DN: {entry.dn.value}")

        # Write DN line with RFC 2849-compliant folding
        dn_line = f"dn: {entry.dn.value}"
        if options.disable_line_folding or len(dn_line) <= options.line_width:
            # No folding needed or disabled
            ldif_lines.append(dn_line)
        elif options.fold_long_lines:
            # RFC 2849-compliant folding: Break at DN component boundaries (commas)
            # This preserves DN structure integrity
            prefix = "dn: "
            dn_value = entry.dn.value

            # Split DN into components
            components = dn_value.split(",")

            # Build lines respecting width limit
            current_line = prefix
            for i, component in enumerate(components):
                component_with_comma = component + (
                    "," if i < len(components) - 1 else ""
                )

                # Check if adding this component would exceed limit
                test_line = current_line + component_with_comma

                if len(test_line) <= options.line_width or current_line == prefix:
                    # Fits on current line or is first component
                    current_line += component_with_comma
                else:
                    # Start new line with continuation space
                    ldif_lines.append(current_line)
                    current_line = " " + component_with_comma

            # Add final line
            if current_line.strip():
                ldif_lines.append(current_line)
        else:
            ldif_lines.append(dn_line)

        # Write removed attributes as comments if requested
        if (
            options.write_removed_attributes_as_comments
            and entry.metadata
            and entry.metadata.removed_attributes
        ):
            ldif_lines.append("# Removed attributes during migration:")
            ldif_lines.extend(
                f"#   - {attr}" for attr in entry.metadata.removed_attributes
            )

        # Write metadata as comments if requested
        if options.write_metadata_as_comments and entry.metadata:
            ldif_lines.append("# Entry Metadata:")
            if entry.metadata.server_type:
                ldif_lines.append(f"# Server Type: {entry.metadata.server_type}")
            if entry.metadata.extensions:
                for key, value in entry.metadata.extensions.items():
                    if key == "source_file":
                        ldif_lines.append(f"# Source File: {value}")
                    else:
                        ldif_lines.append(f"# {key}: {value}")

        # Prepare attributes for writing - apply quirk attribute mappings if available
        attribute_items = list(entry.attributes.attributes.items())

        # Apply quirk-specific attribute name mappings (e.g., orclaci → aci for OUD)
        # Get the quirk that was used for denormalization
        quirks = self._quirk_registry.get_quirks(
            entry.metadata.server_type
            if entry.metadata and entry.metadata.server_type
            else "rfc"
        )
        if quirks:
            quirk = quirks[0]
            # Check if quirk has Entry class with ATTRIBUTE_CASE_MAP
            # Type narrowing: check if quirk has 'entry' attribute
            quirk_entry = getattr(quirk, "entry", None)
            if quirk_entry is not None and hasattr(quirk_entry, "ATTRIBUTE_CASE_MAP"):
                attr_map = quirk_entry.ATTRIBUTE_CASE_MAP
                # Apply mapping to attribute names
                mapped_items = []
                for attr_name, attr_values in attribute_items:
                    mapped_name = attr_map.get(attr_name.lower(), attr_name)
                    mapped_items.append((mapped_name, attr_values))
                attribute_items = mapped_items

        # Handle attribute ordering
        if options.respect_attribute_order and entry.metadata:
            order = entry.metadata.extensions.get("attribute_order")
            if isinstance(order, list):
                attr_map = dict(attribute_items)
                ordered_items = [
                    (key, attr_map[key]) for key in order if key in attr_map
                ]
                remaining_items = [
                    item for item in attribute_items if item[0] not in order
                ]
                attribute_items = ordered_items + remaining_items
        elif options.sort_attributes:
            # Sort alphabetically if requested (only if not respecting order)
            attribute_items.sort(key=lambda x: x[0].lower())

        # Process each attribute
        for attr_name, attr_values in attribute_items:
            # Normalize attribute name if requested
            display_attr_name = (
                attr_name.lower() if options.normalize_attribute_names else attr_name
            )

            # Check if attribute is marked as hidden
            is_hidden = False
            if entry.metadata and entry.metadata.extensions:
                hidden_attrs = entry.metadata.extensions.get("hidden_attributes", [])
                is_hidden = isinstance(hidden_attrs, list) and attr_name in hidden_attrs

            for value in attr_values:
                value_str = str(value)

                # Skip empty values if not requested to write them
                if not options.write_empty_values and not value_str.strip():
                    continue

                # Write hidden attributes as comments if requested
                if is_hidden and options.write_hidden_attributes_as_comments:
                    line = f"# {display_attr_name}: {value_str}"
                else:
                    # Determine if base64 encoding is needed
                    needs_encoding = (
                        options.base64_encode_binary
                        and self.__needs_base64_encoding(value_str)
                    )

                    if needs_encoding:
                        import base64

                        encoded = base64.b64encode(value_str.encode("utf-8")).decode(
                            "utf-8"
                        )
                        line = f"{display_attr_name}:: {encoded}"
                    else:
                        line = f"{display_attr_name}: {value_str}"

                # Apply line folding if requested
                if options.disable_line_folding:
                    # No line folding at all
                    ldif_lines.append(line)
                elif options.fold_long_lines and len(line) > options.line_width:
                    wrapped_lines = textwrap.wrap(
                        line,
                        width=options.line_width,
                        initial_indent="",
                        subsequent_indent=" ",
                        break_long_words=False,
                        break_on_hyphens=False,
                    )
                    ldif_lines.extend(wrapped_lines)
                else:
                    ldif_lines.append(line)

        return "\n".join(ldif_lines) + "\n\n"

    def __needs_base64_encoding(self, value: str) -> bool:
        """Check if a value needs base64 encoding for LDIF."""
        if not value:
            return False
        if value.startswith(" ") or value.endswith(" "):
            return True
        if value.startswith(":"):
            return True
        return any(ord(char) < 32 or ord(char) > 126 for char in value)

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


__all__ = ["FlextLdifWriterService"]
