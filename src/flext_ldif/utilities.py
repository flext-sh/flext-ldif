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
    Provides proxy methods for backward compatibility.
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
        def validate_file_path(
            file_path: Path, *, check_writable: bool = False
        ) -> FlextResult[Path]:
            """Validate file path for read/write operations.

            Args:
                file_path: Path to validate
                check_writable: If True, check if file/parent directory is writable

            Returns:
                FlextResult[Path]: Success with validated path (resolved), failure with error message

            """
            try:
                # Resolve the path to absolute
                resolved_path = file_path.resolve()

                # Check if path exists
                if not resolved_path.exists():
                    # If file doesn't exist, check if we can create it
                    if check_writable:
                        # Check if parent directory exists and is writable
                        parent_dir = resolved_path.parent
                        if not parent_dir.exists():
                            return FlextResult[Path].fail(
                                f"Parent directory does not exist: {parent_dir}"
                            )

                        if (
                            not parent_dir.stat().st_mode & 0o200
                        ):  # Check write permission
                            return FlextResult[Path].fail(
                                f"Parent directory is not writable: {parent_dir}"
                            )

                        # For write operations, allow creating new files
                        return FlextResult[Path].ok(resolved_path)
                    # For read operations, file must exist
                    return FlextResult[Path].fail(
                        f"Path does not exist: {resolved_path}"
                    )

                # Check if it's a directory
                if resolved_path.is_dir():
                    return FlextResult[Path].fail(
                        f"Path is a directory: {resolved_path}"
                    )

                # Check if it's a file
                if not resolved_path.is_file():
                    return FlextResult[Path].fail(
                        f"Path exists but is not a file: {resolved_path}"
                    )

                # Check writable permissions if requested
                if check_writable:
                    # Check if file is writable
                    if (
                        not resolved_path.stat().st_mode & 0o200
                    ):  # Check write permission
                        return FlextResult[Path].fail(
                            f"File is not writable: {resolved_path}"
                        )

                    # Check if parent directory is writable
                    parent_dir = resolved_path.parent
                    if not parent_dir.stat().st_mode & 0o200:
                        return FlextResult[Path].fail(
                            f"Parent directory is not writable: {parent_dir}"
                        )

                return FlextResult[Path].ok(resolved_path)
            except Exception as e:  # pragma: no cover
                return FlextResult[Path].fail(f"File path validation failed: {e}")

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

        @staticmethod
        def count_lines_in_file(file_path: Path) -> FlextResult[int]:
            """Count lines in a text file.

            Args:
                file_path: Path to the file to count lines in

            Returns:
                FlextResult[int]: Success with line count, failure with error message

            """
            try:
                # Check if file exists
                if not file_path.exists():
                    return FlextResult[int].fail(f"File does not exist: {file_path}")

                # Check if it's a file
                if not file_path.is_file():
                    return FlextResult[int].fail(f"Path is not a file: {file_path}")

                # Count lines
                line_count = 0
                with Path(file_path).open("r", encoding="utf-8") as file:
                    for _ in file:
                        line_count += 1

                return FlextResult[int].ok(line_count)
            except UnicodeDecodeError as e:
                return FlextResult[int].fail(
                    f"Encoding error reading file {file_path}: {e}"
                )
            except Exception as e:  # pragma: no cover
                return FlextResult[int].fail(
                    f"Error counting lines in file {file_path}: {e}"
                )

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
            if not isinstance(byte_count, int):
                msg = f"Expected int, got {type(byte_count).__name__}"
                raise TypeError(msg)

            if byte_count <= 0:
                return "0 B"

            size_names = ["B", "KB", "MB", "GB", "TB"]
            size_index = 0
            size = float(byte_count)

            bytes_per_kb = 1024.0
            while size >= bytes_per_kb and size_index < len(size_names) - 1:
                size /= bytes_per_kb
                size_index += 1

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

        @staticmethod
        def format_byte_size(byte_count: int) -> str:
            """Format byte count in human-readable format (alias for format_bytes).

            Args:
                byte_count: Number of bytes

            Returns:
                str: Human-readable byte count (e.g., "1.5 KB")

            """
            if not isinstance(byte_count, int):
                msg = f"Expected int, got {type(byte_count).__name__}"
                raise TypeError(msg)

            if byte_count <= 0:
                return "0 B"

            size_names = ["B", "KB", "MB", "GB", "TB"]
            size_index = 0
            size = float(byte_count)

            bytes_per_kb = 1024.0
            while size >= bytes_per_kb and size_index < len(size_names) - 1:
                size /= bytes_per_kb
                size_index += 1

            return f"{size:.1f} {size_names[size_index]}"

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
            return [
                getattr(entry.dn, "value", str(entry.dn))
                for entry in entries
                if hasattr(entry, "dn")
            ]

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

    # =========================================================================
    # PROXY METHODS - Direct access to nested utility methods for compatibility
    # =========================================================================

    @classmethod
    def get_timestamp(cls) -> str:
        """Proxy method for TimeUtilities.get_timestamp()."""
        return cls.TimeUtilities.get_timestamp()

    @classmethod
    def get_formatted_timestamp(cls, format_string: str = "%Y-%m-%d %H:%M:%S") -> str:
        """Proxy method for TimeUtilities.get_formatted_timestamp()."""
        return cls.TimeUtilities.get_formatted_timestamp(format_string)

    @classmethod
    def validate_file_path(
        cls, file_path: Path, *, check_writable: bool = False
    ) -> FlextResult[Path]:
        """Proxy method for FileUtilities.validate_file_path()."""
        return cls.FileUtilities.validate_file_path(
            file_path, check_writable=check_writable
        )

    @classmethod
    def ensure_file_extension(cls, file_path: Path, extension: str) -> Path:
        """Proxy method for FileUtilities.ensure_file_extension()."""
        return cls.FileUtilities.ensure_file_extension(file_path, extension)

    @classmethod
    def count_lines_in_file(cls, file_path: Path) -> FlextResult[int]:
        """Proxy method for FileUtilities.count_lines_in_file()."""
        return cls.FileUtilities.count_lines_in_file(file_path)

    @classmethod
    def format_bytes(cls, byte_count: int) -> str:
        """Proxy method for TextUtilities.format_bytes()."""
        return cls.TextUtilities.format_bytes(byte_count)

    @classmethod
    def format_byte_size(cls, byte_count: int) -> str:
        """Proxy method for TextUtilities.format_byte_size()."""
        return cls.TextUtilities.format_byte_size(byte_count)

    @classmethod
    def truncate_string(cls, text: str, max_length: int, suffix: str = "...") -> str:
        """Proxy method for TextUtilities.truncate_string()."""
        return cls.TextUtilities.truncate_string(text, max_length, suffix)

    @classmethod
    def count_entries_with_attribute(
        cls, entries: list[FlextLdifProtocols.LdifEntryProtocol], attribute_name: str
    ) -> int:
        """Proxy method for LdifUtilities.count_entries_with_attribute()."""
        return cls.LdifUtilities.count_entries_with_attribute(entries, attribute_name)

    @classmethod
    def extract_dns_from_entries(
        cls, entries: list[FlextLdifProtocols.LdifEntryProtocol]
    ) -> list[str]:
        """Proxy method for LdifUtilities.extract_dns_from_entries()."""
        return cls.LdifUtilities.extract_dns_from_entries(entries)

    @classmethod
    def get_unique_attribute_names(
        cls, entries: list[FlextLdifProtocols.LdifEntryProtocol]
    ) -> set[str]:
        """Proxy method for LdifUtilities.get_unique_attribute_names()."""
        return cls.LdifUtilities.get_unique_attribute_names(entries)
