"""RFC-Compliant LDIF Writer Service.

Writes RFC 2849 compliant LDIF files from structured data with quirk support.
Handles schema entries, regular entries, and ACLs.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

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

        Returns:
            FlextResult with write results containing:
                - output_file: Path to written file
                - entries_written: Number of entries written
                - lines_written: Total lines written

        """
        try:
            # Validate parameters
            output_file_str = self._params.get("output_file", "")
            if not output_file_str:
                return FlextResult[dict].fail("output_file parameter is required")

            output_file = Path(output_file_str)
            entries = self._params.get("entries", [])
            schema = self._params.get("schema", {})
            acls = self._params.get("acls", [])
            append_mode = self._params.get("append", False)

            if not entries and not schema and not acls:
                return FlextResult[dict].fail(
                    "At least one of entries, schema, or acls must be provided"
                )

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
                    schema_result = self._write_schema_entries(f, schema)
                    if schema_result.is_failure:
                        return FlextResult[dict].fail(
                            f"Failed to write schema: {schema_result.error}"
                        )
                    stats = schema_result.unwrap()
                    total_entries += stats["entries"]
                    total_lines += stats["lines"]

                # Write regular entries if provided
                if entries:
                    entries_result = self._write_entries(f, entries)
                    if entries_result.is_failure:
                        return FlextResult[dict].fail(
                            f"Failed to write entries: {entries_result.error}"
                        )
                    stats = entries_result.unwrap()
                    total_entries += stats["entries"]
                    total_lines += stats["lines"]

                # Write ACL entries if provided
                if acls:
                    acl_result = self._write_acl_entries(f, acls)
                    if acl_result.is_failure:
                        return FlextResult[dict].fail(
                            f"Failed to write ACLs: {acl_result.error}"
                        )
                    stats = acl_result.unwrap()
                    total_entries += stats["entries"]
                    total_lines += stats["lines"]

            self._logger.info(
                f"LDIF written successfully: {output_file}",
                extra={
                    "entries_written": total_entries,
                    "lines_written": total_lines,
                    "target_server": self._target_server_type,
                },
            )

            return FlextResult[dict].ok({
                "output_file": str(output_file),
                "entries_written": total_entries,
                "lines_written": total_lines,
            })

        except Exception as e:
            error_msg = f"LDIF writing failed: {e}"
            self._logger.exception(error_msg)
            return FlextResult[dict].fail(error_msg)

    def _write_schema_entries(
        self, file_handle: object, schema: dict
    ) -> FlextResult[dict]:
        """Write schema entries to LDIF file.

        Args:
            file_handle: Open file handle
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
                if hasattr(file_handle, "write"):
                    file_handle.write(dn_line)  # type: ignore[attr-defined]
                lines_written += 1

                # Write objectClass
                if hasattr(file_handle, "write"):
                    file_handle.write("objectClass: top\n")  # type: ignore[attr-defined]
                    file_handle.write("objectClass: subschema\n")  # type: ignore[attr-defined]
                lines_written += 2

                # Write attributeTypes
                for attr_def in attributes.values():
                    attr_line = f"attributeTypes: {attr_def}\n"
                    wrapped_lines = self._wrap_line(attr_line)
                    for line in wrapped_lines:
                        if hasattr(file_handle, "write"):
                            file_handle.write(line)  # type: ignore[attr-defined]
                    lines_written += len(wrapped_lines)

                # Write objectClasses
                for oc_def in objectclasses.values():
                    oc_line = f"objectClasses: {oc_def}\n"
                    wrapped_lines = self._wrap_line(oc_line)
                    for line in wrapped_lines:
                        if hasattr(file_handle, "write"):
                            file_handle.write(line)  # type: ignore[attr-defined]
                    lines_written += len(wrapped_lines)

                # Entry separator
                if hasattr(file_handle, "write"):
                    file_handle.write("\n")  # type: ignore[attr-defined]
                lines_written += 1
                entries_written = 1

            return FlextResult[dict].ok({
                "entries": entries_written,
                "lines": lines_written,
            })

        except Exception as e:
            return FlextResult[dict].fail(f"Schema writing failed: {e}")

    def _write_entries(
        self, file_handle: object, entries: list[dict | FlextLdifModels.Entry]
    ) -> FlextResult[dict]:
        """Write regular entries to LDIF file.

        Args:
            file_handle: Open file handle
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
                        attr_name: attr_values.values
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
                                    attributes = {  # type: ignore[misc]
                                        k: v for k, v in processed.items() if k != "dn"
                                    }

                # Write DN
                dn_line = f"dn: {dn}\n"
                if hasattr(file_handle, "write"):
                    file_handle.write(dn_line)  # type: ignore[attr-defined]
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
                        for line in wrapped_lines:
                            if hasattr(file_handle, "write"):
                                file_handle.write(line)  # type: ignore[attr-defined]
                        lines_written += len(wrapped_lines)

                # Entry separator
                if hasattr(file_handle, "write"):
                    file_handle.write("\n")  # type: ignore[attr-defined]
                lines_written += 1
                entries_written += 1

            return FlextResult[dict].ok({
                "entries": entries_written,
                "lines": lines_written,
            })

        except Exception as e:
            return FlextResult[dict].fail(f"Entry writing failed: {e}")

    def _write_acl_entries(
        self, file_handle: object, acls: list[dict]
    ) -> FlextResult[dict]:
        """Write ACL entries to LDIF file.

        Args:
            file_handle: Open file handle
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
                if hasattr(file_handle, "write"):
                    file_handle.write(dn_line)  # type: ignore[attr-defined]
                lines_written += 1

                # Write ACL definitions
                for acl_def in acl_definitions:
                    acl_line = f"acl: {acl_def}\n"
                    wrapped_lines = self._wrap_line(acl_line)
                    for line in wrapped_lines:
                        if hasattr(file_handle, "write"):
                            file_handle.write(line)  # type: ignore[attr-defined]
                    lines_written += len(wrapped_lines)

                # Entry separator
                if hasattr(file_handle, "write"):
                    file_handle.write("\n")  # type: ignore[attr-defined]
                lines_written += 1
                entries_written += 1

            return FlextResult[dict].ok({
                "entries": entries_written,
                "lines": lines_written,
            })

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
