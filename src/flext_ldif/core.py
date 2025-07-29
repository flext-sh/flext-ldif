"""FlextLdif core functionality using flext-core patterns.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

from flext_core import FlextResult, get_logger

from .models import FlextLdifEntry
from .modernized_ldif import modernized_ldif_parse, modernized_ldif_write

if TYPE_CHECKING:
    from .models import LDIFContent

logger = get_logger(__name__)


class TLdif:
    """Core LDIF processing functionality using flext-core patterns."""

    # Validation patterns
    DN_PATTERN = re.compile(r"^[a-zA-Z]+=.+")
    ATTR_NAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9-]*$")

    @classmethod
    def parse(cls, content: str | LDIFContent) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF content into entries.

        Args:
            content: LDIF content string

        Returns:
            FlextResult containing list of FlextLdifEntry objects

        """
        try:
            content_str = str(content)

            # Use modernized LDIF parser (no external dependencies)
            return cls._parse_with_modernized_ldif(content_str)

        except (ValueError, TypeError, AttributeError, OSError, ImportError) as e:
            return FlextResult.fail(f"Parse failed: {e}")

    @classmethod
    def _parse_with_modernized_ldif(cls, content: str) -> FlextResult[list[FlextLdifEntry]]:
        """Parse using modernized LDIF parser with full string compatibility."""
        try:
            # Use modernized parser that handles all string/bytes issues internally
            parse_result = modernized_ldif_parse(content)
            
            if not parse_result.is_success:
                return FlextResult.fail(parse_result.error or "Modernized LDIF parse failed")
            
            raw_entries = parse_result.data or []
            entries = []
            
            # Convert to FlextLdifEntry objects
            for dn, attrs in raw_entries:
                entry = FlextLdifEntry.from_ldif_dict(dn, attrs)
                entries.append(entry)
            
            return FlextResult.ok(entries)

        except (ValueError, TypeError, AttributeError, ImportError) as e:
            return FlextResult.fail(f"Modernized LDIF parse failed: {e}")


    @classmethod
    def validate(cls, entry: FlextLdifEntry) -> FlextResult[bool]:
        """Validate LDIF entry.

        Args:
            entry: FlextLdifEntry to validate

        Returns:
            FlextResult indicating validation success

        """
        try:
            # Validate DN format
            if not cls.DN_PATTERN.match(str(entry.dn)):
                return FlextResult.fail(f"Invalid DN format: {entry.dn}")

            # Validate attribute names
            for attr_name in entry.attributes.attributes:
                if not cls.ATTR_NAME_PATTERN.match(attr_name):
                    return FlextResult.fail(f"Invalid attribute name: {attr_name}")

            # Validate required objectClass attribute
            if not entry.has_attribute("objectClass"):
                return FlextResult.fail("Entry missing required objectClass attribute")

            return FlextResult.ok(data=True)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Validation failed: {e}")

    @classmethod
    def validate_entries(cls, entries: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate multiple LDIF entries.

        Args:
            entries: List of FlextLdifEntry objects

        Returns:
            FlextResult indicating validation success

        """
        try:
            for i, entry in enumerate(entries):
                result = cls.validate(entry)
                if not result.is_success:
                    return FlextResult.fail(f"Entry {i}: {result.error}")

            return FlextResult.ok(data=True)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Bulk validation failed: {e}")

    @classmethod
    def write(cls, entries: list[FlextLdifEntry]) -> FlextResult[str]:
        """Write entries to LDIF string.

        Args:
            entries: List of FlextLdifEntry objects

        Returns:
            FlextResult containing LDIF string

        """
        try:
            # Use modernized LDIF writer (no external dependencies)
            return cls._write_with_modernized_ldif(entries)

        except (ValueError, TypeError, AttributeError, OSError, ImportError) as e:
            return FlextResult.fail(f"Write failed: {e}")

    @classmethod
    def _write_with_modernized_ldif(cls, entries: list[FlextLdifEntry]) -> FlextResult[str]:
        """Write using modernized LDIF writer with full string compatibility."""
        try:
            # Convert FlextLdifEntry objects to (dn, attrs) tuples
            raw_entries = []
            for entry in entries:
                dn = str(entry.dn)
                attrs = entry.attributes.attributes
                raw_entries.append((dn, attrs))
            
            # Use modernized writer
            write_result = modernized_ldif_write(raw_entries)
            
            if not write_result.is_success:
                return FlextResult.fail(write_result.error or "Modernized LDIF write failed")
            
            return FlextResult.ok(write_result.data or "")

        except (ValueError, TypeError, AttributeError, ImportError) as e:
            return FlextResult.fail(f"Modernized LDIF write failed: {e}")


    @classmethod
    def write_file(cls, entries: list[FlextLdifEntry], file_path: str | Path) -> FlextResult[bool]:
        """Write entries to LDIF file.

        Args:
            entries: List of FlextLdifEntry objects
            file_path: Output file path

        Returns:
            FlextResult indicating success

        """
        try:
            file_path = Path(file_path)

            # Get LDIF content
            content_result = cls.write(entries)
            if not content_result.is_success:
                return FlextResult.fail(content_result.error or "Write failed")

            # Write to file
            if content_result.data is None:
                return FlextResult.fail("No content to write")

            with file_path.open("w", encoding="utf-8") as f:
                f.write(content_result.data)

            return FlextResult.ok(data=True)

        except (OSError, ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"File write failed: {e}")

    @classmethod
    def read_file(cls, file_path: str | Path) -> FlextResult[list[FlextLdifEntry]]:
        """Read and parse LDIF file.

        Args:
            file_path: Input file path

        Returns:
            FlextResult containing list of FlextLdifEntry objects

        """
        try:
            file_path = Path(file_path)

            if not file_path.exists():
                return FlextResult.fail(f"File not found: {file_path}")

            # Read file content
            with file_path.open("r", encoding="utf-8") as f:
                content = f.read()

            # Parse content
            return cls.parse(content)

        except (OSError, ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"File read failed: {e}")


__all__ = [
    "TLdif",
]
