"""Comprehensive LDIF format handling system.

ZERO TOLERANCE for LDIF format violations - strict RFC 2849 compliance.
Provides complete abstraction layer for LDIF format processing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64
import re
from collections.abc import Iterator, Sequence
from typing import ClassVar
from urllib.parse import urlparse

import urllib3
from flext_core import FlextResult, FlextTypes, FlextUtilities

from flext_ldif.config import FlextLDIFConfig, get_ldif_config
from flext_ldif.models import FlextLDIFModels


class FlextLDIFFormatHandler:
    """Unified LDIF format handling service with nested helpers.

    Single responsibility class for all LDIF format operations.
    Provides comprehensive LDIF format handling with nested helpers for:
    - LDIF parsing and writing
    - URL validation and fetching
    - Format validation and encoding
    """

    # LDIF Pattern Constants
    ATTRTYPE_PATTERN: ClassVar[str] = r"[\w;.-]+(;[\w_-]+)*"
    ATTRVALUE_PATTERN: ClassVar[str] = r'(([^,]|\\,)+|".*?")'
    ATTR_PATTERN: ClassVar[str] = ATTRTYPE_PATTERN + r"[ ]*=[ ]*" + ATTRVALUE_PATTERN
    RDN_PATTERN: ClassVar[str] = (
        ATTR_PATTERN + r"([ ]*\+[ ]*" + ATTR_PATTERN + r")*[ ]*"
    )
    DN_PATTERN: ClassVar[str] = RDN_PATTERN + r"([ ]*,[ ]*" + RDN_PATTERN + r")*[ ]*"

    LDIF_PATTERN: ClassVar[str] = (
        f"^((dn(:|::) {DN_PATTERN})|({ATTRTYPE_PATTERN}(:|::) .*)$)+"
    )

    MOD_OPS: ClassVar[FlextTypes.Core.StringList] = ["add", "delete", "replace"]
    CHANGE_TYPES: ClassVar[FlextTypes.Core.StringList] = [
        "add",
        "delete",
        "modify",
        "modrdn",
    ]

    UNSAFE_STRING_PATTERN = (
        r"(^[^\x01-\x09\x0b-\x0c\x0e-\x1f\x21-\x39\x3b\x3d-\x7f]"
        r"|[^\x01-\x09\x0b-\x0c\x0e-\x7f])"
    )
    UNSAFE_STRING_RE = re.compile(UNSAFE_STRING_PATTERN)

    # Allowed URL schemes for LDIF URL references
    ALLOWED_URL_SCHEMES: ClassVar[set[str]] = {"http", "https"}

    # HTTP status codes
    HTTP_OK = 200

    def __init__(self, config: FlextLDIFConfig | None = None) -> None:
        """Initialize LDIF format handler."""
        if config is None:
            try:
                self._config = get_ldif_config()
            except RuntimeError:
                # Global config not initialized, create default one
                self._config = FlextLDIFConfig()
        else:
            self._config = config
        self._name = "FlextLDIFFormatHandler"

    class _UrlHelper:
        """Nested helper for URL operations."""

        @staticmethod
        def validate_url_scheme(url: str) -> None:
            """Validate URL scheme for security."""
            parsed = urlparse(url)
            if parsed.scheme not in FlextLDIFFormatHandler.ALLOWED_URL_SCHEMES:
                schemes_str = ", ".join(FlextLDIFFormatHandler.ALLOWED_URL_SCHEMES)
                msg = (
                    f"URL scheme '{parsed.scheme}' not allowed. "
                    f"Only {schemes_str} schemes are permitted."
                )
                raise ValueError(msg)

        @staticmethod
        def safe_url_fetch(url: str, encoding: str) -> str:
            """Safely fetch URL content using urllib3."""
            FlextLDIFFormatHandler._UrlHelper.validate_url_scheme(url)

            http = urllib3.PoolManager()

            try:
                response = http.request("GET", url)
                if response.status != FlextLDIFFormatHandler.HTTP_OK:
                    msg: str = f"HTTP {response.status}: Failed to fetch {url}"
                    raise ValueError(msg)
                return response.data.decode(encoding)
            except (ValueError, TypeError, OSError) as e:
                error_msg: str = f"urllib3 fetch error for {url}: {e}"
                raise ValueError(error_msg) from e

    class _ValidationHelper:
        """Nested helper for validation operations."""

        @classmethod
        def is_dn(cls, s: str) -> bool:
            """Return True if s is a valid LDAP DN."""
            if s == "":
                return True
            dn_regex = re.compile(f"^{FlextLDIFFormatHandler.DN_PATTERN}$")
            match = dn_regex.match(s)
            return match is not None and match.group(0) == s

        @staticmethod
        def lower_list(items: Sequence[str] | None) -> FlextTypes.Core.StringList:
            """Return a list with the lowercased items using FlextUtilities."""
            if not items:
                return []
            # Use FlextUtilities.TextProcessor for consistent text processing
            return [
                FlextUtilities.TextProcessor.clean_text(item).lower() for item in items
            ]

    # ASCII printable character range constants
    ASCII_PRINTABLE_MIN = 32
    ASCII_PRINTABLE_MAX = 126

    class _WriterHelper:
        """Nested helper for LDIF writing operations."""

        def __init__(
            self,
            base64_attrs: FlextTypes.Core.StringList | None = None,
            cols: int = 76,
            line_sep: str = "\n",
            encoding: str = "utf-8",
        ) -> None:
            """Initialize LDIF writer helper."""
            self._base64_attrs = FlextLDIFFormatHandler._ValidationHelper.lower_list(
                base64_attrs
            )
            self._cols = cols
            self._line_sep = line_sep
            self._encoding = encoding
            self._output_lines: FlextTypes.Core.StringList = []
            self.records_written = 0

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
            if FlextLDIFFormatHandler.UNSAFE_STRING_RE.search(attr_value):
                return True
            return attr_value.startswith(" ") or attr_value.endswith(" ")

        def _write_attribute(self, attr_type: str, attr_value: str) -> None:
            """Write a single attribute line."""
            if self._needs_base64_encoding(attr_type, attr_value):
                encoded_value = base64.b64encode(
                    attr_value.encode(self._encoding)
                ).decode("ascii")
                line = f"{attr_type}:: {encoded_value}"
            else:
                line = f"{attr_type}: {attr_value}"
            self._fold_line(line)

        def unparse(self, dn: str, entry: dict[str, list[str]]) -> None:
            """Write an entry record."""
            self._write_attribute("dn", dn)

            for attr_type, attr_values in entry.items():
                for attr_value in attr_values:
                    self._write_attribute(attr_type, str(attr_value))

            # Add blank line after entry
            self._output_lines.append("")
            self.records_written += 1

        def get_output(self) -> str:
            """Get the complete LDIF output as string."""
            return self._line_sep.join(self._output_lines)

    class _ParserHelper:
        """Nested helper for LDIF parsing operations."""

        def __init__(self, content: str) -> None:
            """Initialize LDIF parser helper."""
            self._content = content
            self._lines = content.splitlines()
            self._line_index = 0

        def parse(self) -> Iterator[tuple[str, dict[str, list[str]]]]:
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

    def process_request(self, request: object) -> FlextResult[object]:
        """Process LDIF requests using template method pattern."""
        if isinstance(request, dict):
            operation = request.get("operation")
            if operation == "parse":
                content = request.get("content")
                if content is not None:
                    result = self.parse_ldif(content)
                    return (
                        FlextResult[object].ok(result.value)
                        if result.is_success
                        else FlextResult[object].fail(result.error or "Parse failed")
                    )
            elif operation == "write":
                entries = request.get("entries")
                if entries is not None:
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
                if url is not None:
                    try:
                        self._UrlHelper.validate_url_scheme(url)
                        return FlextResult[object].ok(data=True)
                    except ValueError as e:
                        return FlextResult[object].fail(str(e))

        return FlextResult[object].fail("Invalid LDIF request format")

    def parse_ldif(self, content: str) -> FlextResult[list[FlextLDIFModels.Entry]]:
        """Parse LDIF content using parser helper."""
        try:
            parser = self._ParserHelper(content)
            raw_entries = list(parser.parse())

            # Convert tuples to FlextLDIFModels.Entry objects
            entries = []
            for dn, attributes in raw_entries:
                # Create proper value objects
                dn_obj = FlextLDIFModels.DistinguishedName(value=dn)
                attrs_obj = FlextLDIFModels.LdifAttributes(data=attributes)
                entry = FlextLDIFModels.Entry(dn=dn_obj, attributes=attrs_obj)
                entries.append(entry)

            return FlextResult[list[FlextLDIFModels.Entry]].ok(entries)

        except (ValueError, AttributeError, TypeError, UnicodeError) as e:
            error_msg: str = f"LDIF parse failed: {e}"
            return FlextResult[list[FlextLDIFModels.Entry]].fail(error_msg)

    def write_ldif(
        self,
        entries: list[FlextLDIFModels.Entry] | None,
    ) -> FlextResult[str]:
        """Write LDIF entries using writer helper."""
        if entries is None:
            return FlextResult[str].fail("Entries cannot be None")

        try:
            writer = self._WriterHelper()
            for entry in entries:
                writer.unparse(str(entry.dn), dict(entry.attributes))

            output = writer.get_output()
            return FlextResult[str].ok(output)

        except (ValueError, AttributeError, TypeError, UnicodeError) as e:
            error_msg: str = f"LDIF write failed: {e}"
            return FlextResult[str].fail(error_msg)

    def is_dn(self, s: str) -> bool:
        """Return True if s is a valid LDAP DN."""
        return self._ValidationHelper.is_dn(s)

    def validate_url_scheme(self, url: str) -> None:
        """Validate URL scheme for security."""
        self._UrlHelper.validate_url_scheme(url)

    def safe_url_fetch(self, url: str, encoding: str | None = None) -> str:
        """Safely fetch URL content."""
        if encoding is None:
            encoding = self._config.ldif_encoding
        return self._UrlHelper.safe_url_fetch(url, encoding)


__all__ = ["FlextLDIFFormatHandler"]
