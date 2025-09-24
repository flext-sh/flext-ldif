"""FLEXT LDIF Utilities - Unified utilities class following FLEXT standards.

Provides LDIF-specific utility methods extending flext-core FlextUtilities.
Single FlextLdifUtilities class with nested utility subclasses following FLEXT pattern.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from flext_core import FlextResult, FlextUtilities
from flext_ldif.protocols import FlextLdifProtocols


class FlextLdifUtilities(FlextUtilities):
    """Single unified LDIF utilities class following FLEXT standards.

    Contains all utility subclasses for LDIF domain operations.
    Follows FLEXT pattern: one class per module with nested subclasses.
    Extends FlextUtilities with LDIF-specific functionality.
    """

    # =========================================================================
    # TIME UTILITIES - Timestamp and time-related operations
    # =========================================================================

    class TimeUtilities:
        """Time-related utility methods for LDIF operations."""

        @staticmethod
        def get_timestamp() -> str:
            """Get current timestamp string.

            Returns:
                str: ISO format timestamp string.

            """
            return datetime.now(UTC).isoformat()

        @staticmethod
        def get_formatted_timestamp(format_string: str = "%Y-%m-%d %H:%M:%S") -> str:
            """Get formatted timestamp string.

            Args:
                format_string: Format string for timestamp

            Returns:
                str: Formatted timestamp string.

            """
            return datetime.now(UTC).strftime(format_string)

    # =========================================================================
    # FILE UTILITIES - File and path-related operations
    # =========================================================================

    class FileUtilities:
        """File-related utility methods for LDIF operations."""

        @staticmethod
        def validate_file_path(file_path: Path) -> FlextResult[None]:
            """Validate file path for write operations.

            Args:
                file_path: Path to validate

            Returns:
                FlextResult[None]: Success if path is valid, failure with error message

            """
            try:
                # Check if parent directory exists or can be created
                parent_dir = file_path.parent
                if not parent_dir.exists():
                    try:
                        parent_dir.mkdir(parents=True, exist_ok=True)
                    except PermissionError:
                        return FlextResult[None].fail(
                            f"Permission denied creating directory: {parent_dir}"
                        )
                    except OSError as e:
                        return FlextResult[None].fail(
                            f"Failed to create directory {parent_dir}: {e}"
                        )

                # Check if file is writable (if it exists)
                if file_path.exists():
                    if not file_path.is_file():
                        return FlextResult[None].fail(
                            f"Path exists but is not a file: {file_path}"
                        )
                    if not file_path.stat().st_mode & 0o200:  # Check write permission
                        return FlextResult[None].fail(
                            f"File is not writable: {file_path}"
                        )
                # Check if we can write to the parent directory
                elif not parent_dir.stat().st_mode & 0o200:
                    return FlextResult[None].fail(
                        f"Parent directory is not writable: {parent_dir}"
                    )

                return FlextResult[None].ok(None)
            except Exception as e:  # pragma: no cover
                return FlextResult[None].fail(f"File path validation failed: {e}")

        @staticmethod
        def ensure_file_extension(file_path: Path, extension: str) -> Path:
            """Ensure file has the specified extension.

            Args:
                file_path: File path to check
                extension: Extension to ensure (with or without dot)

            Returns:
                Path: File path with correct extension

            """
            if not extension.startswith("."):
                extension = f".{extension}"

            if file_path.suffix.lower() != extension.lower():
                return file_path.with_suffix(extension)
            return file_path

    # =========================================================================
    # TEXT UTILITIES - Text processing and formatting operations
    # =========================================================================

    class TextUtilities:
        """Text processing utility methods for LDIF operations."""

        @staticmethod
        def format_bytes(byte_count: int) -> str:
            """Format byte count in human-readable format.

            Args:
                byte_count: Number of bytes

            Returns:
                str: Human-readable byte count (e.g., "1.5 KB")

            """
            if byte_count == 0:
                return "0 B"

            size_names = ["B", "KB", "MB", "GB", "TB"]
            size_index = 0
            size = float(byte_count)

            bytes_per_kb = 1024.0
            while size >= bytes_per_kb and size_index < len(size_names) - 1:
                size /= bytes_per_kb
                size_index += 1

            if size_index == 0:
                return f"{int(size)} {size_names[size_index]}"
            return f"{size:.1f} {size_names[size_index]}"

        @staticmethod
        def truncate_string(text: str, max_length: int, suffix: str = "...") -> str:
            """Truncate string to maximum length with suffix.

            Args:
                text: Text to truncate
                max_length: Maximum length including suffix
                suffix: Suffix to add when truncating

            Returns:
                str: Truncated string with suffix if needed

            """
            if len(text) <= max_length:
                return text

            if max_length <= len(suffix):
                return suffix[:max_length]

            return text[: max_length - len(suffix)] + suffix

    # =========================================================================
    # LDIF UTILITIES - LDIF-specific utility operations
    # =========================================================================

    class LdifUtilities:
        """LDIF-specific utility methods."""

        @staticmethod
        def count_entries_with_attribute(
            entries: list[FlextLdifProtocols.LdifEntryProtocol], attribute_name: str
        ) -> int:
            """Count entries that have a specific attribute.

            Args:
                entries: List of entries to check
                attribute_name: Name of the attribute to check for

            Returns:
                int: Number of entries with the attribute

            """
            count = 0
            for entry in entries:
                if (
                    hasattr(entry, "has_attribute")
                    and entry.has_attribute(attribute_name)
                ) or (
                    hasattr(entry, "attributes") and attribute_name in entry.attributes
                ):
                    count += 1
            return count

        @staticmethod
        def extract_dns_from_entries(
            entries: list[FlextLdifProtocols.LdifEntryProtocol],
        ) -> list[str]:
            """Extract DN values from a list of entries.

            Args:
                entries: List of entries to extract DNs from

            Returns:
                list[str]: List of DN strings

            """
            return [entry.dn for entry in entries if hasattr(entry, "dn")]

        @staticmethod
        def get_unique_attribute_names(
            entries: list[FlextLdifProtocols.LdifEntryProtocol],
        ) -> set[str]:
            """Get unique attribute names from all entries.

            Args:
                entries: List of entries to analyze

            Returns:
                set[str]: Set of unique attribute names

            """
            attribute_names: set[str] = set()
            for entry in entries:
                if hasattr(entry, "attributes"):
                    attribute_names.update(entry.attributes.keys())
            return attribute_names
