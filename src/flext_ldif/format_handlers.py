"""FLEXT-LDIF Format Handler - Class-based LDIF parsing and writing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64
import re
from collections import OrderedDict
from collections.abc import Iterator, Sequence
from typing import ClassVar
from urllib.parse import urlparse

import urllib3
from flext_core import FlextLogger, FlextResult, FlextTypes

from flext_ldif.models import FlextLDIFModels

logger = FlextLogger(__name__)


class FlextLDIFFormatHandler:
    """LDIF format handling using FlextLDIF[Module] pattern.

    Centralized parsing and writing for all LDIF format operations.
    No helper functions - all functionality through class methods.
    """

    # LDIF Pattern Constants
    ATTRTYPE_PATTERN = r"[\w;.-]+(;[\w_-]+)*"
    ATTRVALUE_PATTERN = r'(([^,]|\\,)+|".*?")'
    ATTR_PATTERN = ATTRTYPE_PATTERN + r"[ ]*=[ ]*" + ATTRVALUE_PATTERN
    RDN_PATTERN = ATTR_PATTERN + r"([ ]*\+[ ]*" + ATTR_PATTERN + r")*[ ]*"
    DN_PATTERN = RDN_PATTERN + r"([ ]*,[ ]*" + RDN_PATTERN + r")*[ ]*"
    DN_REGEX = re.compile(f"^{DN_PATTERN}$")

    LDIF_PATTERN = f"^((dn(:|::) {DN_PATTERN})|({ATTRTYPE_PATTERN}s(:|::) .*)$)+"

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

    @classmethod
    def validate_url_scheme(cls, url: str) -> None:
        """Validate URL scheme for security.

        Args:
          url: URL to validate

        Raises:
          ValueError: If URL scheme is not allowed

        Returns:
            object: Description of return value.

        """
        parsed = urlparse(url)
        if parsed.scheme not in cls.ALLOWED_URL_SCHEMES:
            schemes_str = ", ".join(cls.ALLOWED_URL_SCHEMES)
            msg = (
                f"URL scheme '{parsed.scheme}' not allowed. "
                f"Only {schemes_str} schemes are permitted."
            )
            raise ValueError(msg)

    @classmethod
    def safe_url_fetch(cls, url: str, encoding: str = "utf-8") -> str:
        """Safely fetch URL content using urllib3.

        Args:
          url: URL to fetch
          encoding: Character encoding for response

        Returns:
          Decoded content as string

        Raises:
          ValueError: If fetch fails

        """
        cls.validate_url_scheme(url)

        # Use urllib3 for better security and modern HTTP handling
        http = urllib3.PoolManager()

        def _handle_http_error(status: int, url: str) -> None:
            """Handle HTTP error responses."""
            msg: str = f"HTTP {status}: Failed to fetch {url}"
            raise ValueError(msg)

        try:
            response = http.request("GET", url)
            if response.status != cls.HTTP_OK:
                _handle_http_error(response.status, url)
            return response.data.decode(encoding)
        except (ValueError, TypeError, OSError) as e:
            msg: str = f"urllib3 fetch error for {url}: {e}"
            raise ValueError(msg) from e

    @classmethod
    def is_dn(cls, s: str) -> bool:
        """Return True if s is a valid LDAP DN.

        Returns:
            bool: True if s is a valid DN, False otherwise.

        """
        if s == "":
            return True
        match = cls.DN_REGEX.match(s)
        return match is not None and match.group(0) == s

    @staticmethod
    def lower_list(items: Sequence[str] | None) -> FlextTypes.Core.StringList:
        """Return a list with the lowercased items.

        Args:
          items: List of strings to lowercase

        Returns:
          List of lowercased strings

        """
        return [item.lower() for item in items or []]

    @classmethod
    def parse_ldif(cls, content: str) -> FlextResult[list[FlextLDIFModels.Entry]]:
        """Parse LDIF content using modernized parser.

        Args:
          content: LDIF content as string

        Returns:
          FlextResult containing list of FlextLDIFModels.Entry objects

        """
        try:
            parser = FlextLDIFParser(content)
            raw_entries = list(parser.parse())

            # Convert tuples to FlextLDIFModels.Entry objects
            entries = []
            for dn, attributes in raw_entries:
                # Create proper value objects
                dn_obj = FlextLDIFModels.DistinguishedName(value=dn)
                attrs_obj = FlextLDIFModels.LdifAttributes(data=attributes)
                entry = FlextLDIFModels.Entry(dn=dn_obj, attributes=attrs_obj)
                entries.append(entry)

            logger.info(f"LDIF parsed successfully: {len(entries)} entries")
            return FlextResult.ok(entries)

        except (ValueError, AttributeError, TypeError, UnicodeError) as e:
            error_msg: str = f"Modernized LDIF parse failed: {e}"
            logger.exception(
"LDIF parsing failed"
            )
            return FlextResult.fail(error_msg)

    @classmethod
    def write_ldif(
        cls, entries: list[FlextLDIFModels.Entry] | None
    ) -> FlextResult[str]:
        """Write LDIF entries using modernized writer.

        Args:
          entries: List of FlextLDIFModels.Entry objects

        Returns:
          FlextResult containing LDIF string

        """
        if entries is None:
            logger.error("Cannot write None entries")
            return FlextResult.fail(
"Entries cannot be None"
            )

        try:
            writer = FlextLDIFWriter()
            for entry in entries:
                writer.unparse(str(entry.dn), dict(entry.attributes))

            output = writer.get_output()
            logger.info(f"LDIF written successfully: {writer.records_written} entries")
            return FlextResult.ok(output)

        except (ValueError, AttributeError, TypeError, UnicodeError) as e:
            error_msg: str = f"Modernized LDIF write failed: {e}"
            logger.exception(
"LDIF writing failed"
            )
            return FlextResult.fail(error_msg)


class FlextLDIFWriter:
    """Modernized LDIF writer with full string compatibility.

    Writes LDIF entry or change records to string output with proper
    encoding handling and zero bytes/string compatibility issues.
    """

    def __init__(
        self,
        base64_attrs: FlextTypes.Core.StringList | None = None,
        cols: int = 76,
        line_sep: str = "\n",
        encoding: str = "utf-8",
    ) -> None:
        """Initialize LDIF writer.

        Args:
            base64_attrs: List of attribute types to be base64-encoded
            cols: Maximum columns before line folding
            line_sep: Line separator string
            encoding: Character encoding to use

        """
        self._base64_attrs = FlextLDIFFormatHandler.lower_list(base64_attrs)
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
                self._output_lines.append(" " + line[pos:end])
                pos = end

    def _needs_base64_encoding(self, attr_type: str, attr_value: str) -> bool:
        """Return True if attr_value needs base64 encoding.

        Args:
            attr_type: Attribute type name
            attr_value: Attribute value

        Returns:
            True if base64 encoding is needed

        """
        return (
            attr_type.lower() in self._base64_attrs
            or FlextLDIFFormatHandler.UNSAFE_STRING_RE.search(attr_value) is not None
        )

    def _unparse_attr(self, attr_type: str, attr_value: str) -> None:
        """Write a single attribute type/value pair."""
        if self._needs_base64_encoding(attr_type, attr_value):
            # Encode to bytes then base64
            attr_bytes = attr_value.encode(self._encoding)
            encoded = base64.b64encode(attr_bytes).decode("ascii")
            line = f"{attr_type}:: {encoded}"
        else:
            line = f"{attr_type}: {attr_value}"

        self._fold_line(line)

    def _unparse_entry_record(
        self, entry: dict[str, FlextTypes.Core.StringList]
    ) -> None:
        """Write entry record.

        Args:
            entry: Dictionary holding entry attributes

        """
        for attr_type in sorted(entry.keys()):
            for attr_value in entry[attr_type]:
                self._unparse_attr(attr_type, attr_value)

    def unparse(self, dn: str, record: dict[str, FlextTypes.Core.StringList]) -> None:
        """Write an entry record.

        Args:
            dn: Distinguished name
            record: Dictionary holding entry attributes

        Returns:
            object: Description of return value.

        """
        self._unparse_attr("dn", dn)
        self._unparse_entry_record(record)
        self._output_lines.append("")  # Blank line separator
        self.records_written += 1

    def get_output(self) -> str:
        """Get the complete LDIF output as string."""
        return self._line_sep.join(self._output_lines)


class FlextLDIFParser:
    """Modernized LDIF parser with full string compatibility.

    Reads LDIF entry records from string input with enhanced error handling
    and zero bytes/string compatibility issues.

    Returns:
        str: Parsing result.

    """

    def __init__(
        self,
        input_content: str,
        ignored_attr_types: FlextTypes.Core.StringList | None = None,
        encoding: str = "utf-8",
        *,
        strict: bool = True,
    ) -> None:
        """Initialize LDIF parser.

        Args:
            input_content: LDIF content as string
            ignored_attr_types: List of attribute types to ignore
            encoding: Character encoding
            strict: If False, log warnings instead of raising exceptions

        """
        self._input_lines = input_content.splitlines()
        self._ignored_attr_types = FlextLDIFFormatHandler.lower_list(ignored_attr_types)
        self._encoding = encoding
        self._strict = strict

        self.line_counter = 0
        self.records_read = 0

    def _strip_line_sep(self, line: str) -> str:
        """Strip trailing line separators from string."""
        return line.rstrip("\r\n")

    def _iter_unfolded_lines(self) -> Iterator[str]:
        """Iterate input unfolded lines, skipping comments.

        Returns:
            Iterator[str]: Iterator of unfolded lines.

        """
        i = 0
        while i < len(self._input_lines):
            line = self._strip_line_sep(self._input_lines[i])
            self.line_counter += 1

            # Handle line continuation (lines starting with space)
            i += 1
            while i < len(self._input_lines) and self._input_lines[i].startswith(" "):
                continuation = self._strip_line_sep(self._input_lines[i])
                line += continuation[1:]  # Remove leading space
                i += 1

            # Skip comments
            if not line.startswith("#"):
                yield line

    def _iter_blocks(self) -> Iterator[FlextTypes.Core.StringList]:
        """Iterate input lines in blocks separated by blank lines."""
        lines: FlextTypes.Core.StringList = []

        for line in self._iter_unfolded_lines():
            if line.strip():  # Non-empty line
                lines.append(line)
            elif lines:  # Empty line and we have accumulated lines
                self.records_read += 1
                yield lines
                lines = []

        # Handle final block if no trailing empty line
        if lines:
            self.records_read += 1
            yield lines

    def _decode_value(self, attr_type: str, attr_value: str) -> tuple[str, str]:
        """Decode attribute value, handling encoding issues.

        Args:
            attr_type: Attribute type name
            attr_value: Raw attribute value

        Returns:
            tuple[str, str]: Tuple of (attr_type, decoded_value)

        """
        # For DN attributes, ensure UTF-8 compliance
        if attr_type == "dn":
            # Value is already a string, just validate UTF-8 encoding
            try:
                attr_value.encode("utf-8").decode("utf-8")
            except UnicodeError as err:
                if self._strict:
                    msg: str = f"Invalid UTF-8 in {attr_type}: {err}"
                    raise ValueError(msg) from err
                return attr_type, attr_value
            else:
                return attr_type, attr_value

        return attr_type, attr_value

    def _parse_attr(self, line: str) -> tuple[str, str]:
        """Parse a single attribute type/value pair.

        Args:
            line: LDIF line to parse

        Returns:
            Tuple of (attr_type, attr_value)

        """
        if ":" not in line:
            msg: str = f"Invalid LDIF line format: {line}"
            raise ValueError(msg)

        colon_pos = line.index(":")
        attr_type = line[:colon_pos].strip()

        # Handle base64 encoded values (::)
        if line[colon_pos:].startswith("::"):
            encoded_value = line[colon_pos + 2 :].strip()
            try:
                attr_value = base64.b64decode(encoded_value).decode(self._encoding)
            except (ValueError, TypeError) as e:
                base64_error_msg: str = f"Base64 decode error: {e}"
                raise ValueError(base64_error_msg) from e

        # Handle URL references (:<)
        elif line[colon_pos:].startswith(":<"):
            url = line[colon_pos + 2 :].strip()
            try:
                attr_value = FlextLDIFFormatHandler.safe_url_fetch(url, self._encoding)
            except (ValueError, TypeError, OSError) as e:
                url_fetch_error_msg: str = f"URL fetch error: {e}"
                raise ValueError(url_fetch_error_msg) from e

        # Handle regular values (:)
        else:
            attr_value = line[colon_pos + 1 :].strip()

        return self._decode_value(attr_type, attr_value)

    def _error(self, msg: str) -> None:
        """Handle parsing errors based on strict mode."""
        if self._strict:
            raise ValueError(msg)
        logger.warning("LDIF parsing warning: %s", msg)

    def _check_dn(self, dn: str | None, attr_value: str) -> None:
        """Check DN attribute for validity.

        Args:
            dn: Current DN (should be None for first occurrence)
            attr_value: DN value to validate

        """
        if dn is not None:
            self._error("Multiple dn: lines in one record.")

        if not FlextLDIFFormatHandler.is_dn(attr_value):
            self._error(f"Invalid distinguished name format: {attr_value}")

    def _handle_dn_attribute(self, dn: str | None, attr_value: str) -> str:
        """Handle DN attribute processing and validation."""
        self._check_dn(dn, attr_value)
        return attr_value

    def _handle_version_attribute(self, dn: str | None) -> bool:
        """Handle version attribute processing.

        Returns:
            True if should skip processing, False otherwise.

        """
        return dn is None  # Skip version lines when no DN yet

    def _validate_attribute_ordering(self, dn: str | None, attr_type: str) -> None:
        """Validate that attributes come after DN."""
        if dn is None:
            self._error(f"Attribute before dn: line: {attr_type}")

    def _should_include_attribute(self, attr_type: str) -> bool:
        """Check if attribute should be included based on ignore list.

        Returns:
            object: Description of return value.

        """
        return attr_type.lower() not in self._ignored_attr_types

    def _add_attribute_to_entry(
        self,
        entry: dict[str, FlextTypes.Core.StringList],
        attr_type: str,
        attr_value: str,
    ) -> None:
        """Add attribute value to entry dictionary."""
        if attr_type in entry:
            entry[attr_type].append(attr_value)
        else:
            entry[attr_type] = [attr_value]

    def _process_standard_attribute(
        self,
        entry: dict[str, FlextTypes.Core.StringList],
        attr_type: str,
        attr_value: str,
        dn: str | None,
    ) -> None:
        """Process a standard LDIF attribute."""
        self._validate_attribute_ordering(dn, attr_type)

        if self._should_include_attribute(attr_type):
            self._add_attribute_to_entry(entry, attr_type, attr_value)

    def _process_line_attribute(
        self,
        line: str,
        dn: str | None,
        entry: dict[str, FlextTypes.Core.StringList],
    ) -> str | None:
        """Process a single line and return updated DN if applicable."""
        if not line.strip():
            return dn

        attr_type, attr_value = self._parse_attr(line)

        if attr_type == "dn":
            return self._handle_dn_attribute(dn, attr_value)
        if attr_type == "version" and self._handle_version_attribute(dn):
            return dn  # Skip version lines
        self._process_standard_attribute(entry, attr_type, attr_value, dn)
        return dn

    def _parse_entry_record(
        self, lines: FlextTypes.Core.StringList
    ) -> tuple[str, dict[str, FlextTypes.Core.StringList]]:
        """Parse a single entry record from lines.

        Args:
            lines: List of LDIF lines for one record

        Returns:
            Tuple of (dn, entry_dict)

        """
        dn: str | None = None
        entry: dict[str, FlextTypes.Core.StringList] = OrderedDict()

        for line in lines:
            dn = self._process_line_attribute(line, dn, entry)

        if dn is None:
            msg = "Record missing DN"
            raise ValueError(msg)

        return dn, entry

    def parse(self) -> Iterator[tuple[str, dict[str, FlextTypes.Core.StringList]]]:
        """Iterate LDIF entry records.

        Yields:
            Tuple of (dn, entry_dict) for each record

        Returns:
            Iterator[tuple[str, dict[str, FlextTypes.Core.StringList]]]: Iterator of parsed entries.

        """
        try:
            for block in self._iter_blocks():
                if block:  # Skip empty blocks
                    yield self._parse_entry_record(block)
        except (ValueError, AttributeError, TypeError, UnicodeError):
            logger.exception("LDIF parsing failed")
            raise


# All format handling functionality is now available through class methods:
# - FlextLDIFFormatHandler.parse_ldif()
# - FlextLDIFFormatHandler.write_ldif()
# - FlextLDIFFormatHandler.is_dn()
# - FlextLDIFFormatHandler.validate_url_scheme()
# - FlextLDIFFormatHandler.safe_url_fetch()
# - FlextLDIFFormatHandler.lower_list()
# No helper functions - use class methods instead

__all__: FlextTypes.Core.StringList = [
    "FlextLDIFFormatHandler",
    "FlextLDIFParser",
    "FlextLDIFWriter",
]
