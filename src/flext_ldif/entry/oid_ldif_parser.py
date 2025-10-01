"""Oracle OID LDIF Parser - Handles OID LDIF files without version headers.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Oracle OID exports LDIF files without the "version: 1" header required by RFC 2849.
This parser extends the RFC parser to accept Oracle OID format.
"""

from __future__ import annotations

import base64
from pathlib import Path

from pydantic import ConfigDict

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif.models import FlextLdifModels


class OidLdifParserService(FlextService[dict]):
    """Oracle OID LDIF parser - accepts files without version header.

    Oracle OID LDIF exports don't include the RFC 2849 "version: 1" header.
    This parser accepts both RFC-compliant files and Oracle OID files.

    Example:
        params = {"file_path": "oid_export.ldif", "parse_changes": False}
        parser = OidLdifParserService(params=params)
        result = parser.execute()
        if result.is_success:
            entries = result.value["entries"]

    """

    model_config = ConfigDict()

    def __init__(self, *, params: dict) -> None:
        """Initialize OID LDIF parser.

        Args:
            params: Parsing parameters (file_path, parse_changes, encoding)

        """
        super().__init__()
        self._logger = FlextLogger(__name__)
        self._params = params

    def execute(self) -> FlextResult[dict]:
        """Execute OID LDIF parsing.

        Returns:
            FlextResult with parsed LDIF data containing:
                - entries: List of LDIF entries
                - changes: List of change records (if parse_changes=True)
                - comments: List of comments found
                - stats: Parsing statistics

        """
        try:
            # Extract parameters
            file_path_str = self._params.get("file_path", "")
            if not file_path_str:
                return FlextResult[dict].fail("file_path parameter is required")

            file_path = Path(file_path_str)
            if not file_path.exists():
                return FlextResult[dict].fail(f"LDIF file not found: {file_path}")

            parse_changes = self._params.get("parse_changes", False)
            encoding = self._params.get("encoding", "utf-8")

            self._logger.info(
                f"Parsing Oracle OID LDIF file: {file_path}",
                extra={
                    "file_path": str(file_path),
                    "parse_changes": parse_changes,
                    "encoding": encoding,
                },
            )

            # Parse LDIF file using OID-compatible logic
            parse_result = self._parse_ldif_file(
                file_path, parse_changes=parse_changes, encoding=encoding
            )

            if parse_result.is_failure:
                return FlextResult[dict].fail(parse_result.error)

            data = parse_result.value

            self._logger.info(
                "Oracle OID LDIF parsed successfully",
                extra={
                    "total_entries": len(data["entries"]),
                    "total_changes": len(data["changes"]),
                    "total_comments": len(data["comments"]),
                },
            )

            return FlextResult[dict].ok(data)

        except Exception as e:
            error_msg = f"Failed to execute OID LDIF parser: {e}"
            self._logger.exception(error_msg)
            return FlextResult[dict].fail(error_msg)

    def _parse_ldif_file(
        self, file_path: Path, *, parse_changes: bool, encoding: str
    ) -> FlextResult[dict]:
        """Parse LDIF file with OID compatibility.

        Args:
            file_path: Path to LDIF file
            parse_changes: Whether to parse change records
            encoding: File encoding

        Returns:
            FlextResult with parsed LDIF data

        """
        try:
            entries: list[FlextLdifModels.Entry] = []
            changes: list[dict] = []
            comments: list[str] = []

            # Use instance variables to track state across method calls
            self._current_entry: dict[str, object] | None = None
            self._current_dn: str = ""

            with file_path.open("r", encoding=encoding) as f:
                current_line = ""

                for raw_line in f:
                    line = raw_line.rstrip("\n\r")

                    # Handle line folding (RFC 2849: lines starting with single space)
                    if line.startswith(" "):
                        current_line += line[1:]  # Remove leading space
                        continue

                    # Process previous complete line
                    if current_line:
                        self._process_ldif_line(
                            current_line,
                            entries,
                            changes,
                            comments,
                            parse_changes=parse_changes,
                        )

                    # Start new line
                    current_line = line

                # Process last line
                if current_line:
                    self._process_ldif_line(
                        current_line,
                        entries,
                        changes,
                        comments,
                        parse_changes=parse_changes,
                    )

            # Add last entry if exists
            if self._current_entry:
                entry_result = self._create_entry(self._current_entry)
                if entry_result.is_success:
                    entries.append(entry_result.value)

            return FlextResult[dict].ok(
                {
                    "entries": entries,
                    "changes": changes,
                    "comments": comments,
                    "stats": {
                        "total_entries": len(entries),
                        "total_changes": len(changes),
                        "total_comments": len(comments),
                    },
                }
            )

        except Exception as e:
            return FlextResult[dict].fail(f"Failed to parse OID LDIF file: {e}")

    def _process_ldif_line(
        self,
        line: str,
        entries: list[FlextLdifModels.Entry],
        changes: list[dict],
        comments: list[str],
        *,
        parse_changes: bool,
    ) -> None:
        """Process a single complete LDIF line with OID compatibility.

        Oracle OID quirk: Accept files without "version:" header.

        Args:
            line: Complete LDIF line (after folding)
            entries: List to append parsed entries
            changes: List to append change records
            comments: List to append comments
            parse_changes: Whether to parse change records

        """
        # Comments start with '#'
        if line.startswith("#"):
            comments.append(line[1:].strip())
            return

        # Empty line separates entries
        if not line.strip():
            if self._current_entry:
                entry_result = self._create_entry(self._current_entry)
                if entry_result.is_success:
                    entries.append(entry_result.value)
                self._current_entry = None
            return

        # OID QUIRK: Accept version header but don't require it
        # Oracle OID files don't include "version: 1" header
        if line.startswith("version:"):
            version = line[8:].strip()
            self._logger.debug(f"LDIF version: {version}")
            return

        # DN line starts entry
        if line.startswith("dn:"):
            if self._current_entry:
                entry_result = self._create_entry(self._current_entry)
                if entry_result.is_success:
                    entries.append(entry_result.value)

            self._current_dn = self._parse_attribute_value(line[3:])
            self._current_entry = {"dn": self._current_dn, "attributes": {}}
            return

        # Change records
        if parse_changes and line.startswith("changetype:"):
            changetype = line[11:].strip()
            if self._current_entry:
                self._current_entry["changetype"] = changetype
                # Add to changes list for change tracking
                changes.append({"dn": self._current_dn, "changetype": changetype})
            return

        # Attribute-value pair
        if ":" in line:
            attr_name, attr_value = self._parse_attribute_line(line)
            if self._current_entry and attr_name:
                attrs = self._current_entry.get("attributes", {})
                if not isinstance(attrs, dict):
                    attrs = {}
                if attr_name not in attrs:
                    attrs[attr_name] = []
                attrs[attr_name].append(attr_value)
                self._current_entry["attributes"] = attrs

    def _parse_attribute_line(self, line: str) -> tuple[str, str]:
        """Parse attribute-value line according to RFC 2849.

        RFC 2849 formats:
        - attr: value
        - attr:: base64_value
        - attr:< url

        Args:
            line: LDIF attribute line

        Returns:
            Tuple of (attribute_name, attribute_value)

        """
        # Find first colon
        colon_pos = line.find(":")
        if colon_pos == -1:
            return ("", "")

        attr_name = line[:colon_pos].strip()
        value_part = line[colon_pos + 1 :]

        # Base64 encoding (::)
        if value_part.startswith(":"):
            base64_value = value_part[1:].strip()
            try:
                decoded = base64.b64decode(base64_value).decode("utf-8")
                return (attr_name, decoded)
            except Exception:
                return (attr_name, base64_value)

        # URL reference (:<)
        if value_part.startswith("<"):
            url = value_part[1:].strip()
            return (attr_name, f"<URL>{url}")

        # Regular value
        return (attr_name, value_part.strip())

    def _parse_attribute_value(self, value_str: str) -> str:
        """Parse attribute value handling base64 encoding.

        Args:
            value_str: Raw attribute value string

        Returns:
            Decoded attribute value

        """
        value = value_str.strip()

        # Base64 encoded value
        if value.startswith(":"):
            base64_value = value[1:].strip()
            try:
                return base64.b64decode(base64_value).decode("utf-8")
            except Exception:
                return base64_value

        return value

    def _create_entry(
        self, entry_data: dict[str, object]
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Create LDIF entry from parsed data.

        Args:
            entry_data: Parsed entry data

        Returns:
            FlextResult with Entry model

        """
        # Use Entry.create() which handles value object conversion
        return FlextLdifModels.Entry.create(data=entry_data)


__all__ = ["OidLdifParserService"]
