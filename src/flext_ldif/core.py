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
        logger.debug("TLdif.parse called with content type: %s", type(content).__name__)
        logger.trace("Content length: %d characters", len(str(content)))
        try:
            content_str = str(content)
            logger.debug("Content converted to string, length: %d", len(content_str))
            logger.trace("Content preview: %s...", content_str[:200].replace("\n", "\\n"))

            # Use modernized LDIF parser (no external dependencies)
            logger.debug("Delegating to modernized LDIF parser")
            return cls._parse_with_modernized_ldif(content_str)

        except (ValueError, TypeError, AttributeError, OSError, ImportError) as e:
            logger.debug("Exception type: %s", type(e).__name__)
            logger.trace("Full exception details", exc_info=True)
            logger.exception("Exception in TLdif.parse")
            return FlextResult.fail(f"Parse failed: {e}")

    @classmethod
    def _parse_with_modernized_ldif(
        cls,
        content: str,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Parse using modernized LDIF parser with full string compatibility."""
        logger.debug("Starting modernized LDIF parsing")
        logger.trace("Content lines count: %d", len(content.splitlines()))
        try:
            # Use modernized parser that handles all string/bytes issues internally
            logger.debug("Calling modernized_ldif_parse")
            parse_result = modernized_ldif_parse(content)

            if not parse_result.is_success:
                logger.warning("Modernized LDIF parse failed: %s", parse_result.error)
                logger.debug("Returning failure from modernized parser")
                return FlextResult.fail(
                    parse_result.error or "Modernized LDIF parse failed",
                )

            raw_entries = parse_result.data or []
            logger.debug("Modernized parser returned %d raw entries", len(raw_entries))
            logger.trace("Raw entries DNs: %s", [dn for dn, _ in raw_entries[:5]])  # First 5 for trace

            entries = []

            # Convert to FlextLdifEntry objects
            logger.debug("Converting raw entries to FlextLdifEntry objects")
            for i, (dn, attrs) in enumerate(raw_entries):
                logger.trace("Processing entry %d: DN=%s, attrs_count=%d", i, dn, len(attrs))
                entry = FlextLdifEntry.from_ldif_dict(dn, attrs)
                entries.append(entry)

            logger.debug("Successfully converted %d entries to FlextLdifEntry objects", len(entries))
            logger.info("Modernized LDIF parsing completed successfully",
                       raw_entries_count=len(raw_entries),
                       converted_entries_count=len(entries))
            return FlextResult.ok(entries)

        except (ValueError, TypeError, AttributeError, ImportError) as e:
            logger.debug("Exception type: %s", type(e).__name__)
            logger.trace("Full exception details", exc_info=True)
            logger.exception("Exception in modernized LDIF parsing")
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
            if entry is None:
                logger.error("Cannot validate None entry")  # type: ignore[unreachable]
                return FlextResult.fail("Entry cannot be None")

            logger.debug("Validating LDIF entry: %s", entry.dn)
            logger.trace("Entry attributes count: %d", len(entry.attributes.attributes))
            # Validate DN format
            dn_str = str(entry.dn)
            logger.trace("Validating DN format: %s", dn_str)
            if not cls.DN_PATTERN.match(dn_str):
                logger.warning("Invalid DN format: %s", dn_str)
                logger.debug("DN failed regex pattern match")
                return FlextResult.fail(f"Invalid DN format: {entry.dn}")
            logger.trace("DN format validation passed")

            # Validate attribute names
            logger.debug("Validating %d attribute names", len(entry.attributes.attributes))
            for attr_name in entry.attributes.attributes:
                logger.trace("Validating attribute name: %s", attr_name)
                if not cls.ATTR_NAME_PATTERN.match(attr_name):
                    logger.warning("Invalid attribute name: %s", attr_name)
                    logger.debug("Attribute name failed regex pattern match")
                    return FlextResult.fail(f"Invalid attribute name: {attr_name}")
            logger.debug("All attribute names validated successfully")

            # Validate required objectClass attribute
            logger.trace("Checking for required objectClass attribute")
            if not entry.has_attribute("objectClass"):
                logger.warning("Entry missing required objectClass attribute: %s", entry.dn)
                logger.debug("objectClass attribute is required but not found")
                return FlextResult.fail("Entry missing required objectClass attribute")

            object_classes = entry.get_attribute("objectClass")
            logger.trace("Found objectClass values: %s", object_classes)
            logger.debug("Entry validation passed for: %s", entry.dn)
            logger.info("LDIF entry validation successful",
                       dn=str(entry.dn),
                       attributes_count=len(entry.attributes.attributes),
                       object_classes=object_classes)

            return FlextResult.ok(data=True)

        except (ValueError, TypeError, AttributeError) as e:
            logger.debug("Exception type: %s", type(e).__name__)
            logger.trace("Validation exception details", exc_info=True)
            logger.exception("Exception during entry validation")
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
    def _write_with_modernized_ldif(
        cls,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[str]:
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
                return FlextResult.fail(
                    write_result.error or "Modernized LDIF write failed",
                )

            return FlextResult.ok(write_result.data or "")

        except (ValueError, TypeError, AttributeError, ImportError) as e:
            return FlextResult.fail(f"Modernized LDIF write failed: {e}")

    @classmethod
    def write_file(
        cls,
        entries: list[FlextLdifEntry],
        file_path: str | Path,
        encoding: str = "utf-8",
    ) -> FlextResult[bool]:
        """Write entries to LDIF file.

        Args:
            entries: List of FlextLdifEntry objects
            file_path: Output file path
            encoding: File encoding (default: utf-8)

        Returns:
            FlextResult indicating success

        """
        logger.debug("Writing %d entries to file: %s", len(entries), file_path)
        logger.trace("File encoding: %s", encoding)
        try:
            file_path = Path(file_path)
            logger.debug("Resolved file path: %s", file_path.absolute())
            logger.trace("File path exists: %s", file_path.exists())

            # Get LDIF content
            logger.debug("Converting entries to LDIF content")
            content_result = cls.write(entries)
            if not content_result.is_success:
                logger.error("Failed to convert entries to LDIF content: %s", content_result.error)
                logger.debug("Content generation failed, aborting file write")
                return FlextResult.fail(content_result.error or "Write failed")

            # Write to file
            if content_result.data is None:
                logger.error("Content generation succeeded but returned None data")
                logger.debug("No content available to write to file")
                return FlextResult.fail("No content to write")

            content_size = len(content_result.data)
            logger.debug("Writing %d characters to file", content_size)
            logger.trace("Content preview: %s...", content_result.data[:100].replace("\n", "\\n"))

            with file_path.open("w", encoding=encoding) as f:
                f.write(content_result.data)

            logger.debug("File write completed successfully: %s", file_path)
            logger.info("LDIF entries written to file",
                       entries_count=len(entries),
                       file_path=str(file_path),
                       content_size_chars=content_size,
                       encoding=encoding)

            return FlextResult.ok(data=True)

        except (OSError, ValueError, TypeError, AttributeError) as e:
            logger.debug("Exception type: %s", type(e).__name__)
            logger.trace("File write exception details", exc_info=True)
            logger.exception("Exception during file write")
            return FlextResult.fail(f"File write failed: {e}")

    @classmethod
    def read_file(cls, file_path: str | Path, encoding: str = "utf-8") -> FlextResult[list[FlextLdifEntry]]:
        """Read and parse LDIF file.

        Args:
            file_path: Input file path
            encoding: File encoding (default: utf-8)

        Returns:
            FlextResult containing list of FlextLdifEntry objects

        """
        logger.debug("Reading LDIF file: %s", file_path)
        logger.trace("File encoding: %s", encoding)
        try:
            file_path = Path(file_path)
            logger.debug("Resolved file path: %s", file_path.absolute())

            if not file_path.exists():
                logger.error("File not found: %s", file_path)
                logger.debug("File existence check failed")
                return FlextResult.fail(f"File not found: {file_path}")

            logger.trace("File exists, checking file stats")
            file_size = file_path.stat().st_size
            logger.debug("File size: %d bytes", file_size)

            # Read file content
            logger.debug("Reading file content with encoding: %s", encoding)
            with file_path.open("r", encoding=encoding) as f:
                content = f.read()

            content_size = len(content)
            lines_count = len(content.splitlines())
            logger.debug("File content read: %d characters, %d lines", content_size, lines_count)
            logger.trace("Content preview: %s...", content[:200].replace("\n", "\\n"))

            # Parse content
            logger.debug("Delegating to parse method for content processing")
            result = cls.parse(content)

            if result.is_success:
                entries_count = len(result.data or [])
                logger.debug("File read and parse successful: %d entries", entries_count)
                logger.info("LDIF file processed successfully",
                           file_path=str(file_path),
                           file_size_bytes=file_size,
                           content_size_chars=content_size,
                           lines_count=lines_count,
                           entries_parsed=entries_count,
                           encoding=encoding)
                return result
            logger.error("File content parsing failed: %s", result.error)
            logger.debug("Parse method returned failure after successful file read")
            return result

        except (OSError, ValueError, TypeError, AttributeError) as e:
            logger.debug("Exception type: %s", type(e).__name__)
            logger.trace("File read exception details", exc_info=True)
            logger.exception("Exception during file read")
            return FlextResult.fail(f"File read failed: {e}")


__all__ = [
    "TLdif",
]
