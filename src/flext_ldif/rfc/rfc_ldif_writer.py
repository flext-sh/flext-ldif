"""RFC-Compliant LDIF Writer Service.

Writes RFC 2849 compliant LDIF files from structured data with quirk support.
Handles schema entries, regular entries, and ACLs.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import base64
from collections.abc import Sequence
from io import StringIO
from pathlib import Path
from typing import TextIO, cast

from flext_core import FlextResult, FlextService, FlextTypes

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.registry import FlextLdifQuirksRegistry
from flext_ldif.services.dn_service import DnService
from flext_ldif.typings import FlextLdifTypes


class FlextLdifRfcLdifWriter(FlextService[FlextTypes.Dict]):
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
        params: FlextTypes.Dict,
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
        self._dn_service = DnService()  # RFC 4514 DN normalization

    def execute(self) -> FlextResult[FlextTypes.Dict]:
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
            # Check parameters with type narrowing
            output_file_raw: object = self._params.get("output_file", "")
            entries_raw: object = self._params.get("entries", [])
            schema_raw: object = self._params.get("schema", {})
            acls_raw: object = self._params.get("acls", [])
            append_mode = self._params.get("append", False)

            # Type narrow parameters
            output_file_str: str = (
                output_file_raw if isinstance(output_file_raw, str) else ""
            )
            entries: list[FlextTypes.Dict | FlextLdifModels.Entry] = (
                entries_raw if isinstance(entries_raw, list) else []
            )
            schema: FlextTypes.Dict = schema_raw if isinstance(schema_raw, dict) else {}
            acls: list[FlextTypes.Dict] = cast(
                "list[FlextTypes.Dict]",
                acls_raw if isinstance(acls_raw, list) else [],
            )

            if not entries and not schema and not acls:
                return FlextResult[FlextTypes.Dict].fail(
                    "At least one of entries, schema, or acls must be provided"
                )

            # Determine if writing to file or string
            write_to_file = bool(output_file_str)

            if write_to_file:
                # File-based writing (output_file_str already type-narrowed to str)
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

                    # Write schema entries if provided (schema already type-narrowed)
                    if schema:
                        schema_result = self._write_schema_entries(f, schema)
                        if schema_result.is_failure:
                            return FlextResult[FlextTypes.Dict].fail(
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

                    # Write regular entries if provided (entries already type-narrowed)
                    if entries:
                        entries_result = self._write_entries(f, entries)
                        if entries_result.is_failure:
                            return FlextResult[FlextTypes.Dict].fail(
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

                    # Write ACL entries if provided (acls already type-narrowed)
                    if acls:
                        acls_result = self._write_acl_entries(f, acls)
                        if acls_result.is_failure:
                            return FlextResult[FlextTypes.Dict].fail(acls_result.error)
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

                return FlextResult[FlextTypes.Dict].ok(
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

            # Write schema entries if provided (schema already type-narrowed)
            if schema:
                schema_result = self._write_schema_entries(output, schema)
                if schema_result.is_failure:
                    return FlextResult[FlextTypes.Dict].fail(schema_result.error)
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

            # Write regular entries if provided (entries already type-narrowed)
            if entries:
                entries_result = self._write_entries(output, entries)
                if entries_result.is_failure:
                    return FlextResult[FlextTypes.Dict].fail(entries_result.error)
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

            # Write ACL entries if provided (acls already type-narrowed)
            if acls:
                acls_result = self._write_acl_entries(output, acls)
                if acls_result.is_failure:
                    return FlextResult[FlextTypes.Dict].fail(acls_result.error)
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

            return FlextResult[FlextTypes.Dict].ok(
                {
                    "content": ldif_content,
                    "entries_written": total_entries,
                    "lines_written": total_lines,
                }
            )

        except Exception as e:
            if self.logger is not None:
                self.logger.exception("LDIF write failed")
            return FlextResult[FlextTypes.Dict].fail(f"LDIF write failed: {e}")

    def write_entries_to_string(
        self,
        entries: Sequence[object],
    ) -> FlextResult[str]:
        """Write entries to LDIF string format.

        Args:
            entries: Sequence of LDIF entries to write

        Returns:
            FlextResult containing LDIF string or error

        """
        try:
            output = StringIO()

            # Write RFC 2849 version header only if there are entries
            # (empty LDIF files don't need version header)
            if entries:
                output.write("version: 1\n")

            for entry in entries:
                if isinstance(entry, dict):
                    # Handle dictionary entries
                    entry_dn = str(entry.get("dn", ""))
                    normalized_dn = self._normalize_dn(entry_dn)
                    dn_line = f"dn: {normalized_dn}"
                    output.write(dn_line + "\n")

                    # Write attributes
                    attributes = entry["attributes"]
                    if isinstance(attributes, dict):
                        for attr_name, attr_values in attributes.items():
                            if isinstance(attr_values, list):
                                for value in attr_values:
                                    # Format value according to RFC 2849 (base64 if needed)
                                    attr_line = self._format_attribute_value(
                                        attr_name, str(value)
                                    )
                                    output.write(attr_line + "\n")
                # Handle Entry objects
                elif hasattr(entry, "dn") and hasattr(entry, "attributes"):
                    # This is an Entry object
                    entry_obj = cast("FlextLdifModels.Entry", entry)
                    normalized_dn = self._normalize_dn(entry_obj.dn.value)
                    dn_line = f"dn: {normalized_dn}"
                    output.write(dn_line + "\n")

                    # Write attributes with RFC 2849 compliant encoding
                    for (
                        attr_name,
                        attr_values,
                    ) in entry_obj.attributes.attributes.items():
                        # attr_values is AttributeValues, need to access .values property
                        for value in attr_values.values:
                            # Format value according to RFC 2849 (base64 if needed)
                            attr_line = self._format_attribute_value(attr_name, value)
                            output.write(attr_line + "\n")
                else:
                    # Fallback - shouldn't happen with proper usage
                    msg = f"Unsupported entry type: {type(entry)}"
                    raise ValueError(msg)

                # Add blank line after each entry (including last for RFC 2849 compliance)
                output.write("\n")

            ldif_string = output.getvalue()
            return FlextResult[str].ok(ldif_string)

        except Exception as e:
            return FlextResult[str].fail(f"Failed to write entries to string: {e}")

    def write_entries_to_file(
        self,
        entries: Sequence[object],
        output_file: Path,
    ) -> FlextResult[None]:
        """Write entries to LDIF file.

        Args:
            entries: Sequence of LDIF entries to write
            output_file: Path to output file

        Returns:
            FlextResult indicating success or failure

        """
        try:
            # Create output directory if needed
            output_file.parent.mkdir(parents=True, exist_ok=True)

            with output_file.open("w", encoding="utf-8") as f:
                # Write version header (RFC 2849)
                f.write("version: 1\n")

                for idx, entry in enumerate(entries):
                    if isinstance(entry, dict):
                        # Handle dictionary entries
                        entry_dn = str(entry.get("dn", ""))
                        normalized_dn = self._normalize_dn(entry_dn)
                        dn_line = f"dn: {normalized_dn}"
                        f.write(dn_line + "\n")

                        # Write attributes
                        attributes = entry["attributes"]
                        if isinstance(attributes, dict):
                            for attr_name, attr_values in attributes.items():
                                if isinstance(attr_values, list):
                                    for value in attr_values:
                                        attr_line = f"{attr_name}: {value}"
                                        f.write(attr_line + "\n")
                    # Handle Entry objects
                    elif hasattr(entry, "dn") and hasattr(entry, "attributes"):
                        # This is an Entry object
                        entry_obj = cast("FlextLdifModels.Entry", entry)
                        normalized_dn = self._normalize_dn(entry_obj.dn.value)
                        dn_line = f"dn: {normalized_dn}"
                        f.write(dn_line + "\n")

                        # Write attributes
                        for (
                            attr_name,
                            attr_values,
                        ) in entry_obj.attributes.attributes.items():
                            # attr_values is AttributeValues, need to access .values property
                            for value in attr_values.values:
                                attr_line = f"{attr_name}: {value}"
                                f.write(attr_line + "\n")
                    else:
                        # Fallback - shouldn't happen with proper usage
                        msg = f"Unsupported entry type: {type(entry)}"
                        raise ValueError(msg)

                    # Add blank line between entries (except after last entry)
                    if idx < len(entries) - 1:
                        f.write("\n")

            return FlextResult[None].ok(None)

        except Exception as e:
            return FlextResult[None].fail(f"Failed to write entries to file: {e}")

    def _write_schema_entries(
        self, file_handle: TextIO, schema: FlextTypes.Dict
    ) -> FlextResult[FlextTypes.Dict]:
        """Write schema entries to LDIF file.

        Args:
            file_handle: Open text file handle for writing
            schema: Schema dict[str, object] with 'attributes' and 'objectclasses'

        Returns:
            FlextResult with stats dict

        """
        try:
            # Type narrow schema fields
            attributes_raw: object = schema.get(
                FlextLdifConstants.DictKeys.ATTRIBUTES, {}
            )
            attributes: FlextTypes.Dict = (
                attributes_raw if isinstance(attributes_raw, dict) else {}
            )

            objectclasses_raw: object = schema.get("objectclasses", {})
            objectclasses: FlextTypes.Dict = (
                objectclasses_raw if isinstance(objectclasses_raw, dict) else {}
            )

            source_dn_raw: object = schema.get("source_dn", "cn=schema")
            source_dn: str = (
                source_dn_raw if isinstance(source_dn_raw, str) else "cn=schema"
            )

            entries_written = 0
            lines_written = 0

            # Note: For RFC LDIF writing, we write in standard RFC format
            # Quirks would be applied during reading (parse_*) or when converting
            # TO RFC format (convert_*_to_rfc), not during writing
            # This writer produces RFC-compliant output

            # Write schema subentry
            if attributes or objectclasses:
                # Write DN (with RFC 4514 normalization)
                normalized_dn = self._normalize_dn(source_dn)
                dn_line = f"dn: {normalized_dn}\n"
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

            return FlextResult[FlextTypes.Dict].ok(
                {
                    "entries_written": entries_written,
                    "lines_written": lines_written,
                }
            )

        except Exception as e:
            return FlextResult[FlextTypes.Dict].fail(f"Schema writing failed: {e}")

    def _write_entries(
        self,
        file_handle: TextIO,
        entries: list[FlextTypes.Dict | FlextLdifModels.Entry],
    ) -> FlextResult[FlextTypes.Dict]:
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
                # Handle both dict[str, object] and Entry object formats
                if isinstance(entry, FlextLdifModels.Entry):
                    dn = entry.dn.value
                    # Convert Entry attributes to dict[str, object] format for processing
                    # dict[str, object]() builtin already returns correct type
                    attributes_normalized: FlextTypes.Dict = dict[str, object](
                        entry.attributes.attributes.items()
                    )
                else:
                    # Type narrow DN from dict.get()
                    dn_raw: object = entry.get(FlextLdifConstants.DictKeys.DN, "")
                    dn: str = dn_raw if isinstance(dn_raw, str) else ""

                    entry_attrs: FlextTypes.Dict = {
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

                # Write DN (with RFC 4514 normalization)
                normalized_dn = self._normalize_dn(dn)
                dn_line = f"dn: {normalized_dn}\n"
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

            return FlextResult[FlextTypes.Dict].ok(
                {
                    "entries_written": entries_written,
                    "lines_written": lines_written,
                }
            )

        except Exception as e:
            return FlextResult[FlextTypes.Dict].fail(f"Entry writing failed: {e}")

    def _write_acl_entries(
        self, file_handle: TextIO, acls: list[FlextTypes.Dict]
    ) -> FlextResult[FlextTypes.Dict]:
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
                dn = acl_entry.get(FlextLdifConstants.DictKeys.DN, "")
                if not dn:
                    continue

                raw_acl: object = acl_entry.get("acl", [])
                acl_definitions: FlextTypes.StringList = self._extract_acl_definitions(
                    raw_acl
                )

                # Apply target ACL quirks if available (convert FROM RFC to target format)
                if self._quirk_registry and self._target_server_type:
                    acl_quirks = self._quirk_registry.get_acl_quirks(
                        self._target_server_type
                    )
                    # Apply ACL transformations
                    transformed_acls: FlextTypes.StringList = []
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

                # Write DN (with RFC 4514 normalization)
                normalized_dn = self._normalize_dn(str(dn))
                dn_line = f"dn: {normalized_dn}\n"
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

            return FlextResult[FlextTypes.Dict].ok(
                {
                    "entries_written": entries_written,
                    "lines_written": lines_written,
                }
            )

        except Exception as e:
            return FlextResult[FlextTypes.Dict].fail(f"ACL writing failed: {e}")

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

    def _extract_acl_definitions(self, raw_acl: object) -> FlextTypes.StringList:
        """Extract ACL definitions from raw ACL data.

        Args:
            raw_acl: Raw ACL data from entry

        Returns:
            List of ACL definition strings

        """
        if isinstance(raw_acl, list):
            return [str(item) for item in raw_acl]
        return []

    def _normalize_dn(self, dn: str) -> str:
        """Normalize DN using RFC 4514 compliant normalization.

        This method ensures DNs are properly escaped according to RFC 4514,
        which fixes LDAPInvalidDnError issues with spaces and special characters.

        Args:
            dn: Distinguished name to normalize

        Returns:
            Normalized DN string (or original if normalization fails)

        """
        if not dn:
            return dn

        # Use DN service for RFC 4514 normalization
        normalize_result = self._dn_service.normalize(dn)
        if normalize_result.is_success:
            return normalize_result.unwrap()

        # Log warning but continue with original DN
        if self.logger is not None:
            self.logger.warning(
                f"DN normalization failed, using original: {normalize_result.error}"
            )
        return dn

    def _needs_base64_encoding(self, value: str) -> bool:
        r"""Check if attribute value needs base64 encoding per RFC 2849.

        RFC 2849 Section 2: A value must be base64-encoded if it:
        - Contains NULL byte (\\x00)
        - Starts with space, colon, or less-than (<)
        - Ends with space
        - Contains non-ASCII characters (> 127)
        - Contains newline (\\n) or carriage return (\\r)

        Args:
            value: Attribute value to check

        Returns:
            True if value needs base64 encoding

        """
        if not value:
            return False

        # Check for NULL byte
        if "\x00" in value:
            return True

        # Check start characters
        if value[0] in {" ", ":", "<"}:
            return True

        # Check trailing space
        if value.endswith(" "):
            return True

        # Check for newlines or carriage returns (actual characters, not escaped)
        if "\n" in value or "\r" in value:
            return True

        # Check for non-ASCII characters
        try:
            value.encode("ascii")
        except UnicodeEncodeError:
            return True

        return False

    def _format_attribute_value(self, attr_name: str, value: str) -> str:
        """Format attribute value according to RFC 2849.

        Args:
            attr_name: Attribute name
            value: Attribute value

        Returns:
            Formatted LDIF attribute line (without trailing newline)

        """
        if self._needs_base64_encoding(value):
            # Base64 encode and use :: separator per RFC 2849
            encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
            return f"{attr_name}:: {encoded}"

        return f"{attr_name}: {value}"


__all__ = ["FlextLdifRfcLdifWriter"]
