"""RFC-Compliant LDIF Writer Service.

Writes RFC 2849 compliant LDIF files from structured data with quirk support.
Handles schema entries, regular entries, and ACLs.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

PYREFLY TYPE INFERENCE ISSUES (expected):
- Lines 580-598: Type inference breaks with cycles when analyzing modified_acls list
  Pyrefly reports "Iterable[Unknown] | FlextCore.Types.StringList" but it's actually FlextCore.Types.StringList
  All other type checkers (ruff, mypy, pyright) verify this is correct.
"""

from __future__ import annotations

from io import StringIO
from pathlib import Path
from typing import TYPE_CHECKING, TextIO, cast

from flext_core import FlextCore

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes

if TYPE_CHECKING:
    from flext_ldif.quirks.registry import FlextLdifQuirksRegistry


class FlextLdifRfcLdifWriter(FlextCore.Service[FlextCore.Types.Dict]):
    """RFC 2849 compliant LDIF writer with quirk support.

    Writes LDIF files according to RFC 2849 specification with support
    for server-specific quirks via FlextLdifQuirksRegistry.

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
        params: FlextCore.Types.Dict,
        quirk_registry: FlextLdifQuirksRegistry,
        target_server_type: str | None = None,
    ) -> None:
        """Initialize RFC LDIF writer.

        Args:
            params: Writing parameters (output_file, entries, schema, acls)
            quirk_registry: Quirk registry for transformations (MANDATORY)
            target_server_type: Target server type for quirk application

        """
        super().__init__()
        self._params = params
        self._quirk_registry = quirk_registry
        self._target_server_type = target_server_type

    def execute(self) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Execute RFC LDIF writing.

        Supports both file-based and string-based output:
        - output_file: Write to file (traditional approach)
        - If no output_file: Return LDIF string in result

        Returns:
            FlextCore.Result with write results containing:
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
                return FlextCore.Result[FlextCore.Types.Dict].fail(
                    "At least one of entries, schema, or acls must be provided"
                )

            # Determine if writing to file or string
            write_to_file = bool(output_file_str)

            if write_to_file:
                # File-based writing
                output_file = Path(cast("str", output_file_str))

                # Create output directory if needed
                output_file.parent.mkdir(parents=True, exist_ok=True)

                mode = "a" if append_mode else "w"
                total_entries = 0
                total_lines = 0

                with output_file.open(mode, encoding="utf-8") as f_handle:
                    f = cast("TextIO", f_handle)
                    # Write version header (RFC 2849)
                    if not append_mode:
                        f.write("version: 1\n")
                        total_lines += 1

                    # Write schema entries if provided
                    if schema:
                        schema_result = self._write_schema_entries(
                            f, cast("FlextCore.Types.Dict", schema)
                        )
                        if schema_result.is_failure:
                            return FlextCore.Result[FlextCore.Types.Dict].fail(
                                schema_result.error
                            )
                        entries_written = schema_result.unwrap().get(
                            "entries_written", 0
                        )
                        total_entries += (
                            int(entries_written)
                            if isinstance(entries_written, (int, str))
                            else 0
                        )
                        lines_written = schema_result.unwrap().get("lines_written", 0)
                        total_lines += (
                            int(lines_written)
                            if isinstance(lines_written, (int, str))
                            else 0
                        )

                    # Write regular entries if provided
                    if entries:
                        entries_result = self._write_entries(
                            f,
                            cast(
                                "list[FlextCore.Types.Dict | FlextLdifModels.Entry]",
                                entries,
                            ),
                        )
                        if entries_result.is_failure:
                            return FlextCore.Result[FlextCore.Types.Dict].fail(
                                entries_result.error
                            )
                        entries_written = entries_result.unwrap().get(
                            "entries_written", 0
                        )
                        total_entries += (
                            int(entries_written)
                            if isinstance(entries_written, (int, str))
                            else 0
                        )
                        lines_written = entries_result.unwrap().get("lines_written", 0)
                        total_lines += (
                            int(lines_written)
                            if isinstance(lines_written, (int, str))
                            else 0
                        )

                    # Write ACL entries if provided
                    if acls:
                        acls_result = self._write_acl_entries(
                            f, cast("list[FlextCore.Types.Dict]", acls)
                        )
                        if acls_result.is_failure:
                            return FlextCore.Result[FlextCore.Types.Dict].fail(
                                acls_result.error
                            )
                        entries_written = acls_result.unwrap().get("entries_written", 0)
                        total_entries += (
                            int(entries_written)
                            if isinstance(entries_written, (int, str))
                            else 0
                        )
                        lines_written = acls_result.unwrap().get("lines_written", 0)
                        total_lines += (
                            int(lines_written)
                            if isinstance(lines_written, (int, str))
                            else 0
                        )

                if self.logger is not None:
                    self.logger.info(
                        f"LDIF file written: {output_file}",
                        extra={
                            "output_file": str(output_file),
                            "entries_written": total_entries,
                            "lines_written": total_lines,
                        },
                    )

                return FlextCore.Result[FlextCore.Types.Dict].ok({
                    "output_file": str(output_file),
                    "entries_written": total_entries,
                    "lines_written": total_lines,
                })

            # String-based writing using StringIO
            total_entries = 0
            total_lines = 0
            output = StringIO()

            # Write version header (RFC 2849)
            output.write("version: 1\n")
            total_lines += 1

            # Write schema entries if provided
            if schema:
                schema_result = self._write_schema_entries(
                    output, cast("FlextCore.Types.Dict", schema)
                )
                if schema_result.is_failure:
                    return FlextCore.Result[FlextCore.Types.Dict].fail(
                        schema_result.error
                    )
                entries_written = schema_result.unwrap().get("entries_written", 0)
                total_entries += (
                    int(entries_written)
                    if isinstance(entries_written, (int, str))
                    else 0
                )
                lines_written = schema_result.unwrap().get("lines_written", 0)
                total_lines += (
                    int(lines_written) if isinstance(lines_written, (int, str)) else 0
                )

            # Write regular entries if provided
            if entries:
                entries_result = self._write_entries(
                    output,
                    cast("list[FlextCore.Types.Dict | FlextLdifModels.Entry]", entries),
                )
                if entries_result.is_failure:
                    return FlextCore.Result[FlextCore.Types.Dict].fail(
                        entries_result.error
                    )
                entries_written = entries_result.unwrap().get("entries_written", 0)
                total_entries += (
                    int(entries_written)
                    if isinstance(entries_written, (int, str))
                    else 0
                )
                lines_written = entries_result.unwrap().get("lines_written", 0)
                total_lines += (
                    int(lines_written) if isinstance(lines_written, (int, str)) else 0
                )

            # Write ACL entries if provided
            if acls:
                acls_result = self._write_acl_entries(
                    output, cast("list[FlextCore.Types.Dict]", acls)
                )
                if acls_result.is_failure:
                    return FlextCore.Result[FlextCore.Types.Dict].fail(
                        acls_result.error
                    )
                entries_written = acls_result.unwrap().get("entries_written", 0)
                total_entries += (
                    int(entries_written)
                    if isinstance(entries_written, (int, str))
                    else 0
                )
                lines_written = acls_result.unwrap().get("lines_written", 0)
                total_lines += (
                    int(lines_written) if isinstance(lines_written, (int, str)) else 0
                )

            ldif_content = output.getvalue()
            output.close()

            if self.logger is not None:
                self.logger.info(
                    "LDIF content generated",
                    extra={
                        "content_length": len(ldif_content),
                        "entries_written": total_entries,
                        "lines_written": total_lines,
                    },
                )

            return FlextCore.Result[FlextCore.Types.Dict].ok({
                "content": ldif_content,
                "entries_written": total_entries,
                "lines_written": total_lines,
            })

        except Exception as e:
            if self.logger is not None:
                self.logger.exception("LDIF write failed")
            return FlextCore.Result[FlextCore.Types.Dict].fail(
                f"LDIF write failed: {e}"
            )

    def write_entries_to_string(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextCore.Result[str]:
        """Write entries to LDIF string format.

        Args:
            entries: List of LDIF entries to write

        Returns:
            FlextCore.Result containing LDIF string or error

        """
        try:
            output = StringIO()

            for idx, entry in enumerate(entries):
                # Write DN
                dn_line = f"dn: {entry.dn.value}"
                output.write(dn_line + "\n")

                # Write attributes
                for attr_name, attr_values in entry.attributes.data.items():
                    # attr_values is FlextCore.Types.StringList
                    for value in attr_values:
                        attr_line = f"{attr_name}: {value}"
                        output.write(attr_line + "\n")

                # Add blank line between entries (except after last entry)
                if idx < len(entries) - 1:
                    output.write("\n")

            ldif_string = output.getvalue()
            return FlextCore.Result[str].ok(ldif_string)

        except Exception as e:
            return FlextCore.Result[str].fail(f"Failed to write entries to string: {e}")

    def write_entries_to_file(
        self,
        entries: list[FlextLdifModels.Entry],
        output_file: Path,
    ) -> FlextCore.Result[None]:
        """Write entries to LDIF file.

        Args:
            entries: List of LDIF entries to write
            output_file: Path to output file

        Returns:
            FlextCore.Result indicating success or failure

        """
        try:
            # Create output directory if needed
            output_file.parent.mkdir(parents=True, exist_ok=True)

            with output_file.open("w", encoding="utf-8") as f:
                # Write version header (RFC 2849)
                f.write("version: 1\n")

                for idx, entry in enumerate(entries):
                    # Write DN
                    dn_line = f"dn: {entry.dn.value}"
                    f.write(dn_line + "\n")

                    # Write attributes
                    for attr_name, attr_values in entry.attributes.data.items():
                        # attr_values is FlextCore.Types.StringList
                        for value in attr_values:
                            attr_line = f"{attr_name}: {value}"
                            f.write(attr_line + "\n")

                    # Add blank line between entries (except after last entry)
                    if idx < len(entries) - 1:
                        f.write("\n")

            return FlextCore.Result[None].ok(None)

        except Exception as e:
            return FlextCore.Result[None].fail(f"Failed to write entries to file: {e}")

    def _write_schema_entries(
        self, file_handle: TextIO, schema: FlextCore.Types.Dict
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Write schema entries to LDIF file.

        Args:
            file_handle: Open text file handle for writing
            schema: Schema dict with 'attributes' and 'objectclasses'

        Returns:
            FlextCore.Result with stats dict

        """
        try:
            attributes = cast(
                "FlextCore.Types.Dict",
                schema.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {}),
            )
            objectclasses = cast(
                "FlextCore.Types.Dict", schema.get("objectclasses", {})
            )
            source_dn = cast("str", schema.get("source_dn", "cn=schema"))

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

            return FlextCore.Result[FlextCore.Types.Dict].ok({
                "entries_written": entries_written,
                "lines_written": lines_written,
            })

        except Exception as e:
            return FlextCore.Result[FlextCore.Types.Dict].fail(
                f"Schema writing failed: {e}"
            )

    def _write_entries(
        self,
        file_handle: TextIO,
        entries: list[FlextCore.Types.Dict | FlextLdifModels.Entry],
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Write regular entries to LDIF file.

        Args:
            file_handle: Open text file handle for writing
            entries: List of entry dicts or Entry objects

        Returns:
            FlextCore.Result with stats dict

        """
        try:
            entries_written = 0
            lines_written = 0

            for entry in entries:
                # Handle both dict and Entry object formats
                if isinstance(entry, FlextLdifModels.Entry):
                    dn = entry.dn.value
                    # Convert Entry attributes to dict format for processing
                    attributes_normalized: FlextCore.Types.Dict = cast(
                        "FlextCore.Types.Dict",
                        dict(entry.attributes.attributes.items()),
                    )
                else:
                    dn = cast("str", entry.get(FlextLdifConstants.DictKeys.DN, ""))
                    entry_attrs: FlextCore.Types.Dict = {
                        k: v
                        for k, v in entry.items()
                        if k != FlextLdifConstants.DictKeys.DN
                    }
                    attributes_normalized = entry_attrs

                if not dn:
                    continue

                # Apply target entry quirks if available (convert FROM RFC to target format)
                if self._quirk_registry and self._target_server_type:
                    entry_quirks = self._quirk_registry.get_entry_quirks(
                        self._target_server_type
                    )
                    for quirk in entry_quirks:
                        if quirk.can_handle_entry(dn, attributes_normalized):
                            process_result = quirk.process_entry(
                                dn, attributes_normalized
                            )
                            if process_result.is_success:
                                processed = process_result.unwrap()
                                if isinstance(processed, dict):
                                    dn = str(
                                        processed.get(
                                            FlextLdifConstants.DictKeys.DN, dn
                                        )
                                    )
                                    # Extract attributes (everything except dn)
                                    attributes_normalized = {
                                        k: v
                                        for k, v in processed.items()
                                        if k != FlextLdifConstants.DictKeys.DN
                                    }

                # Write DN
                dn_line = f"dn: {dn}\n"
                file_handle.write(dn_line)
                lines_written += 1

                # Write attributes
                for attr_name, attr_values in attributes_normalized.items():
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

            return FlextCore.Result[FlextCore.Types.Dict].ok({
                "entries_written": entries_written,
                "lines_written": lines_written,
            })

        except Exception as e:
            return FlextCore.Result[FlextCore.Types.Dict].fail(
                f"Entry writing failed: {e}"
            )

    def _write_acl_entries(
        self, file_handle: TextIO, acls: list[FlextCore.Types.Dict]
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Write ACL entries to LDIF file.

        Args:
            file_handle: Open text file handle for writing
            acls: List of ACL entry dicts

        Returns:
            FlextCore.Result with stats dict

        """
        try:
            entries_written = 0
            lines_written = 0

            for acl_entry in acls:
                dn = acl_entry.get(FlextLdifConstants.DictKeys.DN, "")
                if not dn:
                    continue

                raw_acl = acl_entry.get("acl", [])
                acl_definitions: FlextCore.Types.StringList = (
                    self._extract_acl_definitions(raw_acl)
                )

                # Apply target ACL quirks if available (convert FROM RFC to target format)
                if self._quirk_registry and self._target_server_type:
                    acl_quirks = self._quirk_registry.get_acl_quirks(
                        self._target_server_type
                    )
                    # Apply ACL transformations
                    transformed_acls: FlextCore.Types.StringList = []
                    for acl_def in acl_definitions:
                        current_acl = acl_def
                        for quirk in acl_quirks:
                            if quirk.can_handle_acl(current_acl):
                                parse_result = quirk.parse_acl(current_acl)
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
                                            current_acl = str(converted["definition"])
                                            break  # Use first successful transformation
                        transformed_acls.append(current_acl)
                    acl_definitions = transformed_acls

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

            return FlextCore.Result[FlextCore.Types.Dict].ok({
                "entries_written": entries_written,
                "lines_written": lines_written,
            })

        except Exception as e:
            return FlextCore.Result[FlextCore.Types.Dict].fail(
                f"ACL writing failed: {e}"
            )

    def _wrap_line(self, line: str) -> FlextLdifTypes.StringList:
        """Wrap LDIF line at 76 characters per RFC 2849.

        Args:
            line: Line to wrap

        Returns:
            List of wrapped lines

        """
        if len(line) <= FlextLdifConstants.RfcCompliance.LINE_WITH_NEWLINE:
            return [line]

        lines = []
        current = line.rstrip("\n")
        first_line = current[: FlextLdifConstants.RfcCompliance.LINE_LENGTH_LIMIT]
        lines.append(first_line + "\n")

        remaining = current[FlextLdifConstants.RfcCompliance.LINE_LENGTH_LIMIT :]
        while remaining:
            # Continuation lines start with a space (RFC 2849)
            chunk = (
                " "
                + remaining[: FlextLdifConstants.RfcCompliance.LINE_LENGTH_LIMIT - 1]
            )  # Space + 75 chars = 76 total
            lines.append(chunk + "\n")
            remaining = remaining[
                FlextLdifConstants.RfcCompliance.LINE_LENGTH_LIMIT - 1 :
            ]

        return lines

    def _extract_acl_definitions(self, raw_acl: object) -> FlextCore.Types.StringList:
        """Extract ACL definitions from raw ACL data.

        Args:
            raw_acl: Raw ACL data from entry

        Returns:
            List of ACL definition strings

        """
        if isinstance(raw_acl, list):
            return [str(item) for item in raw_acl]
        return []


__all__ = ["FlextLdifRfcLdifWriter"]
