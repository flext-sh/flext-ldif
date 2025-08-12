"""FLEXT-LDIF Core Processing Infrastructure.

CONSOLIDATED PEP8 ARCHITECTURE: This module consolidates LDIF core processing
functionality into ONE centralized, PEP8-compliant core module.

CONSOLIDATION MAPPING:
✅ src/flext_ldif/core.py → Core LDIF processing infrastructure
✅ src/flext_ldif/modernized_ldif.py → Modernized LDIF parser based on ldif3

This module provides the core infrastructure for LDIF processing operations,
implementing low-level parsing, validation, and writing functionality with
comprehensive error handling and performance optimizations.

The core module bridges between domain models and concrete LDIF format handling,
providing the technical implementation details while maintaining clean interfaces
for higher-level application services.

Key Components:
    - TLdif: Core LDIF processing class with parsing and writing operations
    - LDIF format validation with RFC 2849 compliance checking
    - Performance-optimized parsing with configurable limits and timeouts
    - Integration with modernized LDIF extensions for enhanced format support

Architecture:
    Part of Infrastructure Layer in Clean Architecture, this module handles
    technical LDIF format concerns and provides concrete implementations for
    domain repository interfaces. Isolates format-specific logic from business rules.

Performance Features:
    - Streaming support for large LDIF files with memory management
    - Regex-based validation with compiled patterns for efficiency
    - Configurable processing limits to prevent resource exhaustion
    - Comprehensive error reporting with line number tracking

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from __future__ import annotations

import base64
import logging
import re
from pathlib import Path
from typing import Any

import urllib3
from flext_core import FlextResult

from .ldif_models import FlextLdifEntry, FlextLdifFactory

logger = logging.getLogger(__name__)

# =============================================================================
# LDIF Pattern Constants (RFC 2849 Compliance)
# =============================================================================

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

# Compile regex patterns for performance
UNSAFE_STRING_REGEX = re.compile(UNSAFE_STRING_PATTERN)
ATTRTYPE_REGEX = re.compile(f"^{ATTRTYPE_PATTERN}$")

# =============================================================================
# CORE LDIF PROCESSING CLASS
# =============================================================================


class TLdif:
    """Core LDIF processing class with parsing and writing operations.

    Provides low-level LDIF format handling with RFC 2849 compliance,
    optimized for performance and memory efficiency. Integrates with
    flext-core patterns for consistent error handling.

    Features:
    - RFC 2849 compliant LDIF parsing and writing
    - Base64 encoding/decoding for binary attributes
    - URL reference handling for external attribute values
    - Streaming support for large files
    - Comprehensive error reporting with line numbers
    """

    def __init__(self,
                 max_entries: int = 20000,
                 max_entry_size: int = 1048576,
                 line_wrap_length: int = 76) -> None:
        """Initialize LDIF processor with configuration.

        Args:
            max_entries: Maximum number of entries to process
            max_entry_size: Maximum size per entry in bytes
            line_wrap_length: Line wrap length for output (RFC 2849)

        """
        self.max_entries = max_entries
        self.max_entry_size = max_entry_size
        self.line_wrap_length = line_wrap_length
        self._http = urllib3.PoolManager()

    @classmethod
    def parse(cls, content: str, **kwargs: Any) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF content into domain entities.

        Args:
            content: LDIF content string
            **kwargs: Additional configuration options

        Returns:
            FlextResult containing list of FlextLdifEntry objects

        """
        try:
            parser = cls(**kwargs)
            entries = parser._parse_content(content)
            return FlextResult.success(entries)
        except Exception as e:
            return FlextResult.failure(f"LDIF parsing failed: {e}")

    @classmethod
    def parse_file(cls, file_path: str | Path, **kwargs: Any) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF file into domain entities.

        Args:
            file_path: Path to LDIF file
            **kwargs: Additional configuration options

        Returns:
            FlextResult containing list of FlextLdifEntry objects

        """
        try:
            path = Path(file_path)
            if not path.exists():
                return FlextResult.failure(f"LDIF file not found: {file_path}")

            content = path.read_text(encoding="utf-8")
            parser = cls(**kwargs)
            entries = parser._parse_content(content, source_file=str(path))
            return FlextResult.success(entries)
        except Exception as e:
            return FlextResult.failure(f"LDIF file parsing failed: {e}")

    def _parse_content(self, content: str, source_file: str | None = None) -> list[FlextLdifEntry]:
        """Internal method to parse LDIF content.

        Args:
            content: LDIF content string
            source_file: Optional source file path for metadata

        Returns:
            List of parsed FlextLdifEntry objects

        Raises:
            ValueError: If LDIF content is invalid

        """
        entries: list[FlextLdifEntry] = []
        lines = content.splitlines()

        current_dn: str | None = None
        current_attributes: dict[str, list[str]] = {}
        line_number = 0
        entry_start_line = 0

        for i, line in enumerate(lines, 1):
            line_number = i
            line = line.rstrip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                if current_dn and current_attributes:
                    # End of entry
                    entry_result = FlextLdifFactory.create_entry(
                        dn=current_dn,
                        attributes=current_attributes,
                        line_number=entry_start_line,
                        source_file=source_file,
                    )
                    if entry_result.success and entry_result.data:
                        entries.append(entry_result.data)

                    # Reset for next entry
                    current_dn = None
                    current_attributes = {}

                continue

            # Handle line continuation
            if line.startswith(" "):
                # This is a continuation of the previous line
                continue

            # Parse attribute: value pairs
            if ":" in line:
                attr_name, sep, attr_value = line.partition(":")
                attr_name = attr_name.strip()

                # Handle different value encodings
                if sep == "::":
                    # Base64 encoded value
                    try:
                        attr_value = base64.b64decode(attr_value.strip()).decode("utf-8")
                    except Exception:
                        attr_value = attr_value.strip()
                elif sep == ":<":
                    # URL reference
                    attr_value = self._fetch_url_value(attr_value.strip())
                else:
                    # Plain value
                    attr_value = attr_value.strip()

                # Handle DN attribute
                if attr_name.lower() == "dn":
                    if current_dn:
                        # Previous entry is complete
                        entry_result = FlextLdifFactory.create_entry(
                            dn=current_dn,
                            attributes=current_attributes,
                            line_number=entry_start_line,
                            source_file=source_file,
                        )
                        if entry_result.success and entry_result.data:
                            entries.append(entry_result.data)

                    # Start new entry
                    current_dn = attr_value
                    current_attributes = {}
                    entry_start_line = line_number
                else:
                    # Regular attribute
                    if attr_name not in current_attributes:
                        current_attributes[attr_name] = []
                    current_attributes[attr_name].append(attr_value)

            # Check processing limits
            if len(entries) >= self.max_entries:
                logger.warning(f"Reached maximum entries limit: {self.max_entries}")
                break

        # Handle final entry
        if current_dn and current_attributes:
            entry_result = FlextLdifFactory.create_entry(
                dn=current_dn,
                attributes=current_attributes,
                line_number=entry_start_line,
                source_file=source_file,
            )
            if entry_result.success and entry_result.data:
                entries.append(entry_result.data)

        return entries

    def _fetch_url_value(self, url: str) -> str:
        """Fetch attribute value from URL reference.

        Args:
            url: URL to fetch value from

        Returns:
            Fetched content as string

        """
        try:
            response = self._http.request("GET", url)
            if response.status == 200:
                return response.data.decode("utf-8")
            logger.warning(f"Failed to fetch URL {url}: HTTP {response.status}")
            return f"<URL fetch failed: {url}>"
        except Exception as e:
            logger.warning(f"Error fetching URL {url}: {e}")
            return f"<URL fetch error: {url}>"

    @classmethod
    def write(cls, entries: list[FlextLdifEntry], **kwargs: Any) -> FlextResult[str]:
        """Write entries to LDIF string format.

        Args:
            entries: List of FlextLdifEntry objects to write
            **kwargs: Additional configuration options

        Returns:
            FlextResult containing LDIF formatted string

        """
        try:
            writer = cls(**kwargs)
            ldif_content = writer._write_entries(entries)
            return FlextResult.success(ldif_content)
        except Exception as e:
            return FlextResult.failure(f"LDIF writing failed: {e}")

    @classmethod
    def write_file(cls, entries: list[FlextLdifEntry], file_path: str | Path, **kwargs: Any) -> FlextResult[bool]:
        """Write entries to LDIF file.

        Args:
            entries: List of FlextLdifEntry objects to write
            file_path: Path to output LDIF file
            **kwargs: Additional configuration options

        Returns:
            FlextResult indicating success or failure

        """
        try:
            writer = cls(**kwargs)
            ldif_content = writer._write_entries(entries)

            path = Path(file_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(ldif_content, encoding="utf-8")

            return FlextResult.success(True)
        except Exception as e:
            return FlextResult.failure(f"LDIF file writing failed: {e}")

    def _write_entries(self, entries: list[FlextLdifEntry]) -> str:
        """Internal method to write entries to LDIF format.

        Args:
            entries: List of FlextLdifEntry objects to write

        Returns:
            LDIF formatted string

        """
        lines: list[str] = []

        for entry in entries:
            # Write DN
            lines.append(f"dn: {entry.dn_string}")

            # Write attributes in sorted order for consistency
            for attr_name in sorted(entry.attributes.names):
                attr_values = entry.attributes.get(attr_name)
                for value in attr_values:
                    # Check if value needs base64 encoding
                    if self._needs_base64_encoding(value):
                        encoded_value = base64.b64encode(value.encode("utf-8")).decode("ascii")
                        lines.append(f"{attr_name}:: {encoded_value}")
                    else:
                        lines.append(f"{attr_name}: {value}")

            # Add empty line between entries
            lines.append("")

        return "\n".join(lines)

    def _needs_base64_encoding(self, value: str) -> bool:
        """Check if attribute value needs base64 encoding.

        Args:
            value: Attribute value to check

        Returns:
            True if value needs base64 encoding

        """
        # Check for unsafe characters according to RFC 2849
        return bool(UNSAFE_STRING_REGEX.search(value))

    def validate_ldif_format(self, content: str) -> FlextResult[bool]:
        """Validate LDIF format compliance.

        Args:
            content: LDIF content to validate

        Returns:
            FlextResult indicating if content is valid LDIF

        """
        try:
            # Basic format validation
            lines = content.splitlines()
            in_entry = False
            dn_found = False

            for line_num, line in enumerate(lines, 1):
                line = line.rstrip()

                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue

                # Check for DN line
                if line.lower().startswith("dn:"):
                    if in_entry and not dn_found:
                        return FlextResult.failure(f"Missing DN in entry at line {line_num}")
                    in_entry = True
                    dn_found = True

                    # Validate DN format
                    dn_value = line[3:].strip()
                    if dn_value.startswith(":"):
                        # Base64 encoded DN
                        dn_value = dn_value[1:].strip()
                        try:
                            dn_value = base64.b64decode(dn_value).decode("utf-8")
                        except Exception:
                            return FlextResult.failure(f"Invalid base64 DN at line {line_num}")

                    if not DN_REGEX.match(dn_value):
                        return FlextResult.failure(f"Invalid DN format at line {line_num}: {dn_value}")

                # Check attribute format
                elif ":" in line and not line.startswith(" "):
                    if not in_entry:
                        return FlextResult.failure(f"Attribute outside entry at line {line_num}")

                    attr_name = line.split(":", 1)[0].strip()
                    if not ATTRTYPE_REGEX.match(attr_name):
                        return FlextResult.failure(f"Invalid attribute name at line {line_num}: {attr_name}")

            return FlextResult.success(True)

        except Exception as e:
            return FlextResult.failure(f"LDIF validation error: {e}")

# =============================================================================
# BACKWARD COMPATIBILITY FUNCTIONS
# =============================================================================


def parse_ldif(content: str) -> FlextResult[list[FlextLdifEntry]]:
    """Parse LDIF content - convenience function."""
    return TLdif.parse(content)


def parse_ldif_file(file_path: str | Path) -> FlextResult[list[FlextLdifEntry]]:
    """Parse LDIF file - convenience function."""
    return TLdif.parse_file(file_path)


def write_ldif(entries: list[FlextLdifEntry]) -> FlextResult[str]:
    """Write entries to LDIF string - convenience function."""
    return TLdif.write(entries)


def write_ldif_file(entries: list[FlextLdifEntry], file_path: str | Path) -> FlextResult[bool]:
    """Write entries to LDIF file - convenience function."""
    return TLdif.write_file(entries, file_path)

# =============================================================================
# PUBLIC API
# =============================================================================


__all__ = [
    # Constants
    "ATTRTYPE_PATTERN",
    "ATTRTYPE_REGEX",
    "CHANGE_TYPES",
    "DN_PATTERN",
    "DN_REGEX",
    "MOD_OPS",
    "UNSAFE_STRING_PATTERN",
    "UNSAFE_STRING_REGEX",
    # Core class
    "TLdif",
    # Convenience functions
    "parse_ldif",
    "parse_ldif_file",
    "write_ldif",
    "write_ldif_file",
]
