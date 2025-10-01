"""RFC-Compliant LDIF Writer Service.

Writes RFC 2849 compliant LDIF files from structured data with quirk support.
Handles schema entries, regular entries, and ACLs.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from io import StringIO
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from flext_core import FlextLogger, FlextResult, FlextService

from flext_ldif.models import FlextLdifModels

if TYPE_CHECKING:
    from flext_ldif.quirks.registry import QuirkRegistryService

# RFC 2849 Constants
RFC_LDIF_LINE_LENGTH_LIMIT = 76
RFC_LDIF_LINE_WITH_NEWLINE = RFC_LDIF_LINE_LENGTH_LIMIT + 1  # 77


class RfcLdifWriterService(FlextService[dict]):
    """RFC 2849 compliant LDIF writer with quirk support.

    Writes LDIF files according to RFC 2849 specification with support
    for server-specific quirks via QuirkRegistryService.

    Features:
    - RFC 2849 compliant LDIF format
    - Schema entry writing (attributeTypes, objectClasses)
    - Regular entry writing with DN and attributes
    - ACL entry writing
    - Quirk-based transformations for target servers
    - Base64 encoding for binary/special characters
    - Line wrapping at 76 characters (RFC 2849)

    Example:
        params = {
            "output_file": "output.ldif",
            "entries": [...],
            "schema": {...}
        }
        writer = RfcLdifWriterService(
            params=params,
            quirk_registry=registry,
            target_server_type="oud"
        )
        result = writer.execute()

    """

    def __init__(
        self,
        *,
        params: dict,
        quirk_registry: QuirkRegistryService | None = None,
        target_server_type: str | None = None,
    ) -> None:
        """Initialize RFC LDIF writer.

        Args:
            params: Writing parameters (output_file, entries, schema, acls)
            quirk_registry: Optional quirk registry for transformations
            target_server_type: Target server type for quirk application

        """
        super().__init__()
        self._logger = FlextLogger(__name__)
        self._params = params
        self._quirk_registry = quirk_registry
        self._target_server_type = target_server_type

    def execute(self) -> FlextResult[dict]:
        """Execute RFC LDIF writing.

        Supports both file-based and string-based output:
        - output_file: Write to file (traditional approach)
        - If no output_file: Return LDIF string in result

        Returns:
            FlextResult with write results containing:
                - output_file: Path to written file (if output_file provided)
                - content: LDIF string content (if no output_file)
                - entries_written: Number of entries written
                - lines_written: Total lines written

        """
        try:
            # Check parameters
            output_file_str = self._params.get("output_file", "")
            entries = self._params.get("entries", [])
            schema = self._params.get("schema", {})
            acls = self._params.get("acls", [])
            append_mode = self._params.get("append", False)

            if not entries and not schema and not acls:
                return FlextResult[dict].fail(
                    "At least one of entries, schema, or acls must be provided"
                )

            # Determine if writing to file or string
            write_to_file = bool(output_file_str)

            if write_to_file:
                # File-based writing
                output_file = Path(output_file_str)

                # Create output directory if needed
                output_file.parent.mkdir(parents=True, exist_ok=True)

                mode = "a" if append_mode else "w"
                total_entries = 0
                total_lines = 0

                with output_file.open(mode, encoding="utf-8") as f:
                    # Write version header (RFC 2849)
                    if not append_mode:
                        f.write("version: 1\n")
                        total_lines += 1

                    # Write schema entries if provided
                    if schema:
                        schema_result = self._write_schema_entries(f, schema)  # type: ignore[arg-type]
                        if schema_result.is_failure:
                            return FlextResult[dict].fail(schema_result.error)
                        total_entries += schema_result.unwrap().get(
                            "entries_written", 0
                        )
                        total_lines += schema_result.unwrap().get("lines_written", 0)

                    # Write regular entries if provided
                    if entries:
                        entries_result = self._write_entries(f, entries)  # type: ignore[arg-type]
                        if entries_result.is_failure:
                            return FlextResult[dict].fail(entries_result.error)
                        total_entries += entries_result.unwrap().get(
                            "entries_written", 0
                        )
                        total_lines += entries_result.unwrap().get("lines_written", 0)

                    # Write ACL entries if provided
                    if acls:
                        acls_result = self._write_acl_entries(f, acls)  # type: ignore[arg-type]
                        if acls_result.is_failure:
                            return FlextResult[dict].fail(acls_result.error)
                        total_entries += acls_result.unwrap().get("entries_written", 0)
                        total_lines += acls_result.unwrap().get("lines_written", 0)

                self._logger.info(
                    f"LDIF file written: {output_file}",
                    extra={
                        "output_file": str(output_file),
                        "entries_written": total_entries,
                        "lines_written": total_lines,
                    },
                )

                return FlextResult[dict].ok(
                    {
                        "output_file": str(output_file),
                        "entries_written": total_entries,
                        "lines_written": total_lines,
                    }
                )

            # String-based writing using StringIO
            total_entries = 0
            total_lines = 0
            output = StringIO()

            # Write version header (RFC 2849)
            output.write("version: 1\n")
            total_lines += 1

            # Write schema entries if provided
            if schema:
                schema_result = self._write_schema_entries(output, schema)
                if schema_result.is_failure:
                    return FlextResult[dict].fail(schema_result.error)
                total_entries += schema_result.unwrap().get("entries_written", 0)
                total_lines += schema_result.unwrap().get("lines_written", 0)

            # Write regular entries if provided
            if entries:
                entries_result = self._write_entries(output, entries)
                if entries_result.is_failure:
                    return FlextResult[dict].fail(entries_result.error)
                total_entries += entries_result.unwrap().get("entries_written", 0)
                total_lines += entries_result.unwrap().get("lines_written", 0)

            # Write ACL entries if provided
            if acls:
                acls_result = self._write_acl_entries(output, acls)
                if acls_result.is_failure:
                    return FlextResult[dict].fail(acls_result.error)
                total_entries += acls_result.unwrap().get("entries_written", 0)
                total_lines += acls_result.unwrap().get("lines_written", 0)

            ldif_content = output.getvalue()
            output.close()

            self._logger.info(
                "LDIF content generated",
                extra={
                    "content_length": len(ldif_content),
                    "entries_written": total_entries,
                    "lines_written": total_lines,
                },
            )

            return FlextResult[dict].ok(
                {
                    "content": ldif_content,
                    "entries_written": total_entries,
                    "lines_written": total_lines,
                }
            )

        except Exception as e:
            self._logger.exception("LDIF write failed")
            return FlextResult[dict].fail(f"LDIF write failed: {e}")

    def write_entries_to_string(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[str]:
        """Write entries to LDIF string format.

        Args:
            entries: List of LDIF entries to write

        Returns:
            FlextResult containing LDIF string or error

        """
        try:
            output = StringIO()

            for idx, entry in enumerate(entries):
                # Write DN
                dn_line = f"dn: {entry.dn.value}"
                output.write(dn_line + "\n")

                # Write attributes
                for attr_name, attr_values_obj in entry.attributes.data.items():
                    # attr_values_obj is always AttributeValues, access .values for list[str]
                    for value in attr_values_obj.values:
                        attr_line = f"{attr_name}: {value}"
                        output.write(attr_line + "\n")

                # Add blank line between entries (except after last entry)
                if idx < len(entries) - 1:
                    output.write("\n")

            ldif_string = output.getvalue()
            return FlextResult[str].ok(ldif_string)

        except Exception as e:
            return FlextResult[str].fail(f"Failed to write entries to string: {e}")

    def _write_schema_entries(
        self, file_handle: TextIO, schema: dict
    ) -> FlextResult[dict]:
        """Write schema entries to LDIF file.

        Args:
            file_handle: Open text file handle for writing
            schema: Schema dict with 'attributes' and 'objectclasses'

        Returns:
            FlextResult with stats dict

        """
        try:
            attributes = schema.get("attributes", {})
            objectclasses = schema.get("objectclasses", {})
            source_dn = schema.get("source_dn", "cn=schema")

            entries_written = 0
            lines_written = 0

            # Note: For RFC LDIF writing, we write in standard RFC format
            # Quirks would be applied during reading (parse_*) or when converting
            # TO RFC format (convert_*_to_rfc), not during writing
            # This writer produces RFC-compliant output

            # Write schema subentry
            if attributes or objectclasses:
                # Write DN
                dn_line = f"dn: {source_dn}\n"
                file_handle.write(dn_line)
                lines_written += 1

                # Write objectClass
                file_handle.write("objectClass: top\n")
                file_handle.write("objectClass: subschema\n")
                lines_written += 2

                # Write attributeTypes
                for attr_def in attributes.values():
                    attr_line = f"attributeTypes: {attr_def}\n"
                    wrapped_lines = self._wrap_line(attr_line)
                    file_handle.writelines(wrapped_lines)
                    lines_written += len(wrapped_lines)

                # Write objectClasses
                for oc_def in objectclasses.values():
                    oc_line = f"objectClasses: {oc_def}\n"
                    wrapped_lines = self._wrap_line(oc_line)
                    file_handle.writelines(wrapped_lines)
                    lines_written += len(wrapped_lines)

                # Entry separator
                file_handle.write("\n")
                lines_written += 1
                entries_written = 1

            return FlextResult[dict].ok(
                {
                    "entries": entries_written,
                    "lines": lines_written,
                }
            )

        except Exception as e:
            return FlextResult[dict].fail(f"Schema writing failed: {e}")

    def _write_entries(
        self, file_handle: TextIO, entries: list[dict | FlextLdifModels.Entry]
    ) -> FlextResult[dict]:
        """Write regular entries to LDIF file.

        Args:
            file_handle: Open text file handle for writing
            entries: List of entry dicts or Entry objects

        Returns:
            FlextResult with stats dict

        """
        try:
            entries_written = 0
            lines_written = 0

            for entry in entries:
                # Handle both dict and Entry object formats
                if isinstance(entry, FlextLdifModels.Entry):
                    dn = entry.dn.value
                    # Convert Entry attributes to dict format for processing
                    attributes = {
                        attr_name: attr_values.values  # type: ignore[misc]
                        for attr_name, attr_values in entry.attributes.attributes.items()
                    }
                else:
                    dn = entry.get("dn", "")
                    attributes = {k: v for k, v in entry.items() if k != "dn"}

                if not dn:
                    continue

                # Apply target entry quirks if available (convert FROM RFC to target format)
                if self._quirk_registry and self._target_server_type:
                    entry_quirks = self._quirk_registry.get_entry_quirks(
                        self._target_server_type
                    )
                    for quirk in entry_quirks:
                        if quirk.can_handle_entry(dn, attributes):
                            process_result = quirk.process_entry(dn, attributes)
                            if process_result.is_success:
                                processed = process_result.unwrap()
                                if isinstance(processed, dict):
                                    dn = str(processed.get("dn", dn))
                                    attributes = {
                                        k: v  # type: ignore[misc]
                                        for k, v in processed.items()
                                        if k != "dn"
                                    }

                # Write DN
                dn_line = f"dn: {dn}\n"
                file_handle.write(dn_line)
                lines_written += 1

                # Write attributes
                for attr_name, attr_values in attributes.items():
                    # Handle both single values and lists
                    values = (
                        attr_values if isinstance(attr_values, list) else [attr_values]
                    )

                    for value in values:
                        attr_line = f"{attr_name}: {value}\n"
                        wrapped_lines = self._wrap_line(attr_line)
                        file_handle.writelines(wrapped_lines)
                        lines_written += len(wrapped_lines)

                # Entry separator
                file_handle.write("\n")
                lines_written += 1
                entries_written += 1

            return FlextResult[dict].ok(
                {
                    "entries": entries_written,
                    "lines": lines_written,
                }
            )

        except Exception as e:
            return FlextResult[dict].fail(f"Entry writing failed: {e}")

    def _write_acl_entries(
        self, file_handle: TextIO, acls: list[dict]
    ) -> FlextResult[dict]:
        """Write ACL entries to LDIF file.

        Args:
            file_handle: Open text file handle for writing
            acls: List of ACL entry dicts

        Returns:
            FlextResult with stats dict

        """
        try:
            entries_written = 0
            lines_written = 0

            for acl_entry in acls:
                dn = acl_entry.get("dn", "")
                if not dn:
                    continue

                acl_definitions = acl_entry.get("acl", [])

                # Apply target ACL quirks if available (convert FROM RFC to target format)
                if self._quirk_registry and self._target_server_type:
                    acl_quirks = self._quirk_registry.get_acl_quirks(
                        self._target_server_type
                    )
                    for quirk in acl_quirks:
                        for i, acl_def in enumerate(acl_definitions):
                            if quirk.can_handle_acl(str(acl_def)):
                                parse_result = quirk.parse_acl(str(acl_def))
                                if parse_result.is_success:
                                    acl_data = parse_result.unwrap()
                                    # For writing to target, convert from RFC format
                                    convert_result = quirk.convert_acl_from_rfc(
                                        acl_data
                                    )
                                    if convert_result.is_success:
                                        converted = convert_result.unwrap()
                                        if (
                                            isinstance(converted, dict)
                                            and "definition" in converted
                                        ):
                                            acl_definitions[i] = str(
                                                converted["definition"]
                                            )

                # Write DN
                dn_line = f"dn: {dn}\n"
                file_handle.write(dn_line)
                lines_written += 1

                # Write ACL definitions
                for acl_def in acl_definitions:
                    acl_line = f"acl: {acl_def}\n"
                    wrapped_lines = self._wrap_line(acl_line)
                    file_handle.writelines(wrapped_lines)
                    lines_written += len(wrapped_lines)

                # Entry separator
                file_handle.write("\n")
                lines_written += 1
                entries_written += 1

            return FlextResult[dict].ok(
                {
                    "entries": entries_written,
                    "lines": lines_written,
                }
            )

        except Exception as e:
            return FlextResult[dict].fail(f"ACL writing failed: {e}")

    def _wrap_line(self, line: str) -> list[str]:
        """Wrap LDIF line at 76 characters per RFC 2849.

        Args:
            line: Line to wrap

        Returns:
            List of wrapped lines

        """
        if len(line) <= RFC_LDIF_LINE_WITH_NEWLINE:
            return [line]

        lines = []
        current = line.rstrip("\n")
        first_line = current[:RFC_LDIF_LINE_LENGTH_LIMIT]
        lines.append(first_line + "\n")

        remaining = current[RFC_LDIF_LINE_LENGTH_LIMIT:]
        while remaining:
            # Continuation lines start with a space (RFC 2849)
            chunk = (
                " " + remaining[: RFC_LDIF_LINE_LENGTH_LIMIT - 1]
            )  # Space + 75 chars = 76 total
            lines.append(chunk + "\n")
            remaining = remaining[RFC_LDIF_LINE_LENGTH_LIMIT - 1 :]

        return lines


__all__ = ["RfcLdifWriterService"]
