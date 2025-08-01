"""Modernized LDIF parser and writer based on ldif3 library.

This module provides a modernized implementation of LDIF parsing and writing
capabilities based on ldif3 3.2.2, enhanced with:

- Python 3.13+ type hints and modern syntax
- Full string/bytes compatibility fixes
- Integration with flext-core patterns
- Enhanced error handling and validation
- Zero-tolerance for bytes/string compatibility issues

Copyright (c) 2025 FLEXT Contributors
Original ldif3 library: Copyright (c) ldif3 contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64
import re
from collections import OrderedDict
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import urllib3
from flext_core import FlextResult, get_logger

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

logger = get_logger(__name__)

# LDIF Pattern Constants
ATTRTYPE_PATTERN = r"[\w;.-]+(;[\w_-]+)*"
ATTRVALUE_PATTERN = r'(([^,]|\\,)+|".*?")'
ATTR_PATTERN = ATTRTYPE_PATTERN + r"[ ]*=[ ]*" + ATTRVALUE_PATTERN
RDN_PATTERN = ATTR_PATTERN + r"([ ]*\+[ ]*" + ATTR_PATTERN + r")*[ ]*"
DN_PATTERN = RDN_PATTERN + r"([ ]*,[ ]*" + RDN_PATTERN + r")*[ ]*"
DN_REGEX = re.compile(f"^{DN_PATTERN}$")

LDIF_PATTERN = f"^((dn(:|::) {DN_PATTERN})|({ATTRTYPE_PATTERN}s(:|::) .*)$)+"

MOD_OPS = ["add", "delete", "replace"]
CHANGE_TYPES = ["add", "delete", "modify", "modrdn"]

UNSAFE_STRING_PATTERN = (
    r"(^[^\x01-\x09\x0b-\x0c\x0e-\x1f\x21-\x39\x3b\x3d-\x7f]"
    r"|[^\x01-\x09\x0b-\x0c\x0e-\x7f])"
)
UNSAFE_STRING_RE = re.compile(UNSAFE_STRING_PATTERN)

# Allowed URL schemes for LDIF URL references
ALLOWED_URL_SCHEMES = {"http", "https"}

# HTTP status codes
HTTP_OK = 200


def _validate_url_scheme(url: str) -> None:
    """Validate URL scheme for security.

    Args:
        url: URL to validate

    Raises:
        ValueError: If URL scheme is not allowed

    """
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_URL_SCHEMES:
        schemes_str = ", ".join(ALLOWED_URL_SCHEMES)
        msg = (
            f"URL scheme '{parsed.scheme}' not allowed. "
            f"Only {schemes_str} schemes are permitted."
        )
        raise ValueError(msg)


def _safe_url_fetch(url: str, encoding: str = "utf-8") -> str:
    """Safely fetch URL content using urllib3.

    Args:
        url: URL to fetch
        encoding: Character encoding for response

    Returns:
        Decoded content as string

    Raises:
        ValueError: If fetch fails

    """
    _validate_url_scheme(url)

    # Use urllib3 for better security and modern HTTP handling
    http = urllib3.PoolManager()

    def _handle_http_error(status: int, url: str) -> None:
        """Handle HTTP error responses."""
        msg = f"HTTP {status}: Failed to fetch {url}"
        raise ValueError(msg)

    try:
        response = http.request("GET", url)
        if response.status != HTTP_OK:
            _handle_http_error(response.status, url)
        return response.data.decode(encoding)
    except Exception as e:
        msg = f"urllib3 fetch error for {url}: {e}"
        raise ValueError(msg) from e


def is_dn(s: str) -> bool:
    """Return True if s is a valid LDAP DN.

    Args:
        s: String to validate as DN

    Returns:
        True if valid DN format

    """
    if s == "":
        return True
    match = DN_REGEX.match(s)
    return match is not None and match.group(0) == s


def lower_list(items: Sequence[str] | None) -> list[str]:
    """Return a list with the lowercased items.

    Args:
        items: List of strings to lowercase

    Returns:
        List of lowercased strings

    """
    return [item.lower() for item in items or []]


class FlextLDIFWriter:
    """Modernized LDIF writer with full string compatibility.

    Writes LDIF entry or change records to string output with proper
    encoding handling and zero bytes/string compatibility issues.
    """

    def __init__(
        self,
        base64_attrs: list[str] | None = None,
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
        self._base64_attrs = lower_list(base64_attrs)
        self._cols = cols
        self._line_sep = line_sep
        self._encoding = encoding
        self._output_lines: list[str] = []
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
            or UNSAFE_STRING_RE.search(attr_value) is not None
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

    def _unparse_entry_record(self, entry: dict[str, list[str]]) -> None:
        """Write entry record.

        Args:
            entry: Dictionary holding entry attributes

        """
        for attr_type in sorted(entry.keys()):
            for attr_value in entry[attr_type]:
                self._unparse_attr(attr_type, attr_value)

    def unparse(self, dn: str, record: dict[str, list[str]]) -> None:
        """Write an entry record.

        Args:
            dn: Distinguished name
            record: Dictionary holding entry attributes

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
    """

    def __init__(
        self,
        input_content: str,
        ignored_attr_types: list[str] | None = None,
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
        self._ignored_attr_types = lower_list(ignored_attr_types)
        self._encoding = encoding
        self._strict = strict

        self.line_counter = 0
        self.records_read = 0

    def _strip_line_sep(self, line: str) -> str:
        """Strip trailing line separators from string."""
        return line.rstrip("\r\n")

    def _iter_unfolded_lines(self) -> Iterator[str]:
        """Iterate input unfolded lines, skipping comments."""
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

    def _iter_blocks(self) -> Iterator[list[str]]:
        """Iterate input lines in blocks separated by blank lines."""
        lines: list[str] = []

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
            Tuple of (attr_type, decoded_value)

        """
        # For DN attributes, ensure UTF-8 compliance
        if attr_type == "dn":
            # Value is already a string, just validate UTF-8 encoding
            try:
                attr_value.encode("utf-8").decode("utf-8")
            except UnicodeError as err:
                if self._strict:
                    msg = f"Invalid UTF-8 in {attr_type}: {err}"
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
            msg = f"Invalid LDIF line format: {line}"
            raise ValueError(msg)

        colon_pos = line.index(":")
        attr_type = line[:colon_pos].strip()

        # Handle base64 encoded values (::)
        if line[colon_pos:].startswith("::"):
            encoded_value = line[colon_pos + 2 :].strip()
            try:
                attr_value = base64.b64decode(encoded_value).decode(self._encoding)
            except Exception as e:
                msg = f"Base64 decode error: {e}"
                raise ValueError(msg) from e

        # Handle URL references (:<)
        elif line[colon_pos:].startswith(":<"):
            url = line[colon_pos + 2 :].strip()
            try:
                attr_value = _safe_url_fetch(url, self._encoding)
            except Exception as e:
                msg = f"URL fetch error: {e}"
                raise ValueError(msg) from e

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

        if not is_dn(attr_value):
            self._error(f"Invalid distinguished name format: {attr_value}")

    def _parse_entry_record(self, lines: list[str]) -> tuple[str, dict[str, list[str]]]:
        """Parse a single entry record from lines.

        Args:
            lines: List of LDIF lines for one record

        Returns:
            Tuple of (dn, entry_dict)

        """
        dn: str | None = None
        entry: dict[str, list[str]] = OrderedDict()

        for line in lines:
            if not line.strip():
                continue

            attr_type, attr_value = self._parse_attr(line)

            if attr_type == "dn":
                self._check_dn(dn, attr_value)
                dn = attr_value
            elif attr_type == "version" and dn is None:
                # Skip version lines
                continue
            else:
                # Standard attribute processing
                if dn is None:
                    self._error(f"Attribute before dn: line: {attr_type}")

                if attr_type.lower() not in self._ignored_attr_types:
                    if attr_type in entry:
                        entry[attr_type].append(attr_value)
                    else:
                        entry[attr_type] = [attr_value]

        if dn is None:
            msg = "Record missing dn: line"
            raise ValueError(msg)

        return dn, entry

    def parse(self) -> Iterator[tuple[str, dict[str, list[str]]]]:
        """Iterate LDIF entry records.

        Yields:
            Tuple of (dn, entry_dict) for each record

        """
        try:
            for block in self._iter_blocks():
                if block:  # Skip empty blocks
                    yield self._parse_entry_record(block)
        except Exception:
            logger.exception("LDIF parsing failed")
            raise


def modernized_ldif_parse(
    content: str,
) -> FlextResult[list[tuple[str, dict[str, list[str]]]]]:
    """Parse LDIF content using modernized parser.

    Args:
        content: LDIF content as string

    Returns:
        FlextResult containing list of (dn, attributes) tuples

    """
    logger.debug("Starting modernized LDIF parsing")
    logger.trace("Content length: %d characters", len(content))
    logger.trace("Content lines count: %d", len(content.splitlines()))

    try:
        logger.debug("Creating FlextLDIFParser with strict=True")
        parser = FlextLDIFParser(content, strict=True)
        logger.trace("Parser initialized successfully")

        logger.debug("Parsing LDIF content into entries")
        entries = list(parser.parse())

        logger.debug("Successfully parsed %d LDIF entries", len(entries))
        logger.trace(
            "Entry DNs: %s",
            [dn for dn, _ in entries[:5]],
        )  # First 5 for trace
        logger.info("Successfully parsed %d LDIF entries", len(entries))
        return FlextResult.ok(entries)

    except Exception as e:
        error_msg = f"Modernized LDIF parse failed: {e}"
        logger.exception("Modernized LDIF parsing failed")
        logger.debug("Exception type: %s", type(e).__name__)
        logger.trace("Full parsing exception details", exc_info=True)
        return FlextResult.fail(error_msg)


def modernized_ldif_write(
    entries: list[tuple[str, dict[str, list[str]]]] | None,
) -> FlextResult[str]:
    """Write LDIF entries using modernized writer.

    Args:
        entries: List of (dn, attributes) tuples

    Returns:
        FlextResult containing LDIF string

    """
    if entries is None:
        logger.error("Cannot write None entries")
        return FlextResult.fail("Entries cannot be None")

    logger.debug("Starting modernized LDIF writing for %d entries", len(entries))
    logger.trace(
        "Entry DNs to write: %s",
        [dn for dn, _ in entries[:5]],
    )  # First 5 for trace

    try:
        logger.debug("Creating FlextLDIFWriter")
        writer = FlextLDIFWriter()
        logger.trace("Writer initialized successfully")

        logger.debug("Writing %d entries to LDIF format", len(entries))
        for i, (dn, attrs) in enumerate(entries):
            logger.trace("Writing entry %d: DN=%s, attrs_count=%d", i, dn, len(attrs))
            writer.unparse(dn, attrs)

        logger.debug("Getting output from writer")
        output = writer.get_output()
        output_size = len(output)

        logger.debug(
            "Successfully wrote %d LDIF entries, output size: %d chars",
            writer.records_written,
            output_size,
        )
        logger.trace("Output preview: %s...", output[:100].replace("\n", "\\n"))
        logger.info("Successfully wrote %d LDIF entries", writer.records_written)
        return FlextResult.ok(output)

    except Exception as e:
        error_msg = f"Modernized LDIF write failed: {e}"
        logger.exception("Modernized LDIF writing failed")
        logger.debug("Exception type: %s", type(e).__name__)
        logger.trace("Full writing exception details", exc_info=True)
        return FlextResult.fail(error_msg)


__all__ = [
    "FlextLDIFParser",
    "FlextLDIFWriter",
    "is_dn",
    "modernized_ldif_parse",
    "modernized_ldif_write",
]
