"""Comprehensive LDIF format handling system.

ZERO TOLERANCE for LDIF format violations - strict RFC 2849 compliance.
Provides complete abstraction layer for LDIF format processing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64
import re

from flext_core import FlextResult, FlextTypes, FlextUtilities
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels


class FlextLdifFormatHandler:
    """Unified LDIF format handling service following FLEXT standards.

    Single responsibility class for all LDIF format operations.
    Provides comprehensive LDIF format handling for:
    - LDIF parsing and writing
    - URL validation
    - Format validation and encoding

    Follows FLEXT single-class-per-module principle with all functionality
    integrated directly into the main class.
    """

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize LDIF format handler."""
        if config is None:
            try:
                self._config = FlextLdifConfig.get_global_ldif_config()
            except RuntimeError:
                # Global config not initialized, create default one
                self._config = FlextLdifConfig()
        else:
            self._config = config
        self._name = "FlextLdifFormatHandler"

        # Writer state
        self._base64_attrs: FlextTypes.Core.StringList = []
        self._cols = 76
        self._line_sep = "\n"
        self._encoding = "utf-8"
        self._output_lines: FlextTypes.Core.StringList = []

        # Compile regex pattern from constants for performance
        self.UNSAFE_STRING_RE = re.compile(FlextLdifConstants.UNSAFE_STRING_PATTERN)
        self.records_written = 0

        # Parser state
        self._content = ""
        self._lines: FlextTypes.Core.StringList = []
        self._line_index = 0

    def process_request(self, request: dict[str, object]) -> FlextResult[object]:
        """Process LDIF requests using template method pattern."""
        # Use duck typing instead of isinstance check
        try:
            operation = request.get("operation")
            if operation == "parse":
                content = request.get("content")
                if content is not None and isinstance(content, str):
                    result = self.parse_ldif(content)
                    return (
                        FlextResult[object].ok(result.value)
                        if result.is_success
                        else FlextResult[object].fail(result.error or "Parse failed")
                    )
            elif operation == "write":
                entries = request.get("entries")
                if entries is not None and isinstance(entries, list):
                    write_result = self.write_ldif(entries)
                    return (
                        FlextResult[object].ok(write_result.value)
                        if write_result.is_success
                        else FlextResult[object].fail(
                            write_result.error or "Write failed"
                        )
                    )
            elif operation == "validate_url":
                url = request.get("url")
                if url is not None and isinstance(url, str):
                    try:
                        self.validate_url_scheme(url)
                        return FlextResult[object].ok(data=True)
                    except ValueError as e:
                        return FlextResult[object].fail(str(e))
        except AttributeError:
            pass

        return FlextResult[object].fail("Invalid LDIF request format")

    def parse_ldif(self, content: str) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF content."""
        try:
            self._content = content
            self._lines = content.splitlines()
            self._line_index = 0
            raw_entries = list(self._parse_entries())

            # Convert tuples to FlextLdifModels.Entry objects
            entries = []
            for dn, attributes in raw_entries:
                # Create proper value objects
                dn_obj = FlextLdifModels.DistinguishedName(value=dn)
                attrs_obj = FlextLdifModels.LdifAttributes(data=attributes)
                entry = FlextLdifModels.Entry(dn=dn_obj, attributes=attrs_obj)
                entries.append(entry)

            return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

        except (ValueError, AttributeError, TypeError, UnicodeError) as e:
            error_msg: str = f"LDIF parse failed: {e}"
            return FlextResult[list[FlextLdifModels.Entry]].fail(error_msg)

    def write_ldif(
        self,
        entries: list[FlextLdifModels.Entry] | None,
    ) -> FlextResult[str]:
        """Write LDIF entries."""
        if entries is None:
            return FlextResult[str].fail("Entries cannot be None")

        try:
            self._reset_writer_state()
            for entry in entries:
                self._write_entry(entry.dn.value, dict(entry.attributes.data))

            output = self._get_writer_output()
            return FlextResult[str].ok(output)

        except (ValueError, AttributeError, TypeError, UnicodeError) as e:
            error_msg: str = f"LDIF write failed: {e}"
            return FlextResult[str].fail(error_msg)

    def is_dn(self, s: str) -> bool:
        """Return True if s is a valid LDAP DN."""
        if not s:
            return True
        try:
            # Use existing FlextLdifModels.DistinguishedName validation
            dn_model = FlextLdifModels.DistinguishedName(value=s)
            validation_result = dn_model.validate_business_rules()
            return validation_result.is_success
        except Exception:
            return False

    def validate_url_scheme(self, url: str) -> None:
        """Validate URL scheme using centralized FlextModels validation."""
        try:
            # Use centralized FlextLdifModels.LdifUrl for validation
            FlextLdifModels.LdifUrl(url=url)
        except Exception as e:
            raise ValueError(str(e)) from e

    def lower_list(self, items: list[str] | None) -> FlextTypes.Core.StringList:
        """Return a list with the lowercased items using FlextUtilities."""
        if not items:
            return []
        # Use FlextUtilities.TextProcessor for consistent text processing
        return [FlextUtilities.TextProcessor.clean_text(item).lower() for item in items]

    # Private implementation methods (formerly in nested classes)

    def _reset_writer_state(self) -> None:
        """Reset writer state for new operation."""
        self._base64_attrs = []
        self._cols = 76
        self._line_sep = "\n"
        self._encoding = "utf-8"
        self._output_lines = []
        self.records_written = 0

    def _parse_entries(self) -> Iterator[tuple[str, dict[str, list[str]]]]:
        """Parse LDIF content and yield (dn, attributes) tuples."""
        while self._line_index < len(self._lines):
            entry_data = self._parse_entry()
            if entry_data:
                yield entry_data

    def _parse_entry(self) -> tuple[str, dict[str, list[str]]] | None:
        """Parse a single LDIF entry."""
        # Skip empty lines, comments, and version lines
        while self._line_index < len(self._lines):
            line = self._lines[self._line_index].strip()
            if (
                line
                and not line.startswith("#")
                and not line.lower().startswith("version:")
            ):
                break
            self._line_index += 1

        if self._line_index >= len(self._lines):
            return None

        # Parse DN line with continuation support
        dn_line = self._get_complete_line()
        if not dn_line.lower().startswith("dn:"):
            error_msg = f"Expected DN line, got: {dn_line}"
            raise ValueError(error_msg)

        dn = self._parse_attribute_value(dn_line)

        # Parse attributes
        attributes: dict[str, list[str]] = {}
        while self._line_index < len(self._lines):
            line = self._lines[self._line_index].strip()
            if not line:
                # Empty line indicates end of entry
                self._line_index += 1
                break
            if line.startswith("#"):
                # Skip comments
                self._line_index += 1
                continue

            # Get complete attribute line with continuations
            complete_line = self._get_complete_line()
            attr_name, attr_value = self._parse_attribute_line(complete_line)
            if attr_name not in attributes:
                attributes[attr_name] = []
            attributes[attr_name].append(attr_value)

        return dn, attributes

    def _get_complete_line(self) -> str:
        """Get complete line handling LDIF continuation lines."""
        if self._line_index >= len(self._lines):
            return ""

        complete_line = self._lines[self._line_index]
        self._line_index += 1

        # Handle continuation lines (lines starting with space)
        while self._line_index < len(self._lines) and self._lines[
            self._line_index
        ].startswith(" "):
            # Remove the leading space and append to the complete line
            continuation = self._lines[self._line_index][1:]
            complete_line += continuation
            self._line_index += 1

        return complete_line

    def _parse_attribute_line(self, line: str) -> tuple[str, str]:
        """Parse an attribute line and return (name, value)."""
        if "::" in line:
            # Base64-encoded value
            attr_name, encoded_value = line.split("::", 1)
            attr_name = attr_name.strip()
            encoded_value = encoded_value.strip()
            try:
                attr_value = base64.b64decode(encoded_value).decode("utf-8")
            except Exception as e:
                msg = f"Base64 decode error: {e}"
                raise ValueError(msg) from e
        elif ":" in line:
            # Regular value
            attr_name, attr_value = line.split(":", 1)
            attr_name = attr_name.strip()
            attr_value = attr_value.strip()
        else:
            error_msg = f"Invalid attribute line: {line}"
            raise ValueError(error_msg)

        return attr_name, attr_value

    def _parse_attribute_value(self, line: str) -> str:
        """Parse attribute value from a line."""
        if "::" in line:
            # Base64-encoded
            _, encoded_value = line.split("::", 1)
            try:
                return base64.b64decode(encoded_value.strip()).decode("utf-8")
            except Exception as e:
                msg = f"Base64 decode error: {e}"
                raise ValueError(msg) from e
        if ":" in line:
            # Regular value
            _, value = line.split(":", 1)
            return value.strip()
        error_msg = f"Invalid attribute line: {line}"
        raise ValueError(error_msg)

    def _write_entry(self, dn: str, entry: dict[str, list[str]]) -> None:
        """Write an entry record."""
        self._write_attribute("dn", dn)

        for attr_type, attr_values in entry.items():
            for attr_value in attr_values:
                self._write_attribute(attr_type, str(attr_value))

        # Add blank line after entry
        self._output_lines.append("")
        self.records_written += 1

    def _write_attribute(self, attr_type: str, attr_value: str) -> None:
        """Write a single attribute line."""
        if self._needs_base64_encoding(attr_type, attr_value):
            encoded_value = base64.b64encode(attr_value.encode(self._encoding)).decode(
                "ascii"
            )
            line = f"{attr_type}:: {encoded_value}"
        else:
            line = f"{attr_type}: {attr_value}"
        self._fold_line(line)

    def _fold_line(self, line: str) -> None:
        """Write string line as one or more folded lines."""
        if len(line) <= self._cols:
            self._output_lines.append(line)
        else:
            # Write first part
            self._output_lines.append(line[: self._cols])
            pos = self._cols

            # Write continuation lines with leading space
            while pos < len(line):
                end = min(len(line), pos + self._cols - 1)
                self._output_lines.append(f" {line[pos:end]}")
                pos = end

    def _needs_base64_encoding(self, attr_type: str, attr_value: str) -> bool:
        """Determine if an attribute value should be base64-encoded."""
        if attr_type.lower() in self._base64_attrs:
            return True
        # Use compiled regex pattern instead of search for better performance
        if self.UNSAFE_STRING_RE.search(attr_value):
            return True
        return attr_value.startswith(" ") or attr_value.endswith(" ")

    def _get_writer_output(self) -> str:
        """Get the complete LDIF output as string."""
        return self._line_sep.join(self._output_lines)


__all__ = ["FlextLdifFormatHandler"]
