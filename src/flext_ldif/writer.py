"""FLEXT LDIF Writer - Enterprise LDIF file writing utilities.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

Enterprise-grade LDIF file writing utilities following FLEXT patterns.
Provides centralized, standardized LDIF file operations for all FLEXT projects.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, TextIO

if TYPE_CHECKING:
    from io import StringIO
    from pathlib import Path

from flext_core.domain.shared_types import ServiceResult

logger = logging.getLogger(__name__)


class FlextLDIFWriter:
    """Enterprise LDIF writer utility following FLEXT patterns.

    Provides standardized LDIF file writing operations with hierarchical sorting,
    proper error handling, and ServiceResult patterns. Designed for use across
    all FLEXT projects to eliminate code duplication.
    """

    @staticmethod
    def write_entries_to_file(
        file_path: Path,
        entries: list[dict[str, Any]],
        *,
        sort_hierarchically: bool = True,
        include_comments: bool = True,
        buffering: int = 8192,
    ) -> ServiceResult[Any]:
        """Write LDIF entries to file with standardized formatting.

        Args:
            file_path: Path to output file
            entries: List of entries to write
            sort_hierarchically: Whether to sort entries hierarchically by DN depth
            include_comments: Whether to include _comments fields in output
            buffering: Buffer size for file operations

        Returns:
            ServiceResult with number of entries written or error

        """
        try:
            # Ensure parent directory exists
            file_path.parent.mkdir(parents=True, exist_ok=True)

            # Sort entries if requested
            entries_to_write = entries
            if sort_hierarchically:
                entries_to_write = _sort_entries_hierarchically(entries)

            with file_path.open("w", encoding="utf-8", buffering=buffering) as f:
                FlextLDIFWriter._write_entries_to_stream(
                    f,
                    entries_to_write,
                    include_comments=include_comments,
                )

            logger.info("Wrote %d entries to %s", len(entries_to_write), file_path)
            return ServiceResult.ok(len(entries_to_write))

        except Exception as e:
            logger.exception("Failed to write LDIF file: %s", file_path)
            return ServiceResult.fail(f"Failed to write LDIF: {e!s}")

    @staticmethod
    def _write_entries_to_stream(
        stream: TextIO | StringIO,
        entries: list[dict[str, Any]],
        *,
        include_comments: bool,
    ) -> None:
        """Write entries to a file stream."""
        for i, entry in enumerate(entries):
            if i > 0:
                stream.write("\n")

            FlextLDIFWriter._write_single_entry(
                stream,
                entry,
                include_comments=include_comments,
            )
            stream.write("\n")

    @staticmethod
    def _write_single_entry(
        stream: TextIO | StringIO,
        entry: dict[str, Any],
        *,
        include_comments: bool,
    ) -> None:
        """Write a single entry to stream."""
        # Write DN first
        dn = entry.get("dn", "")
        stream.write(f"dn: {dn}\n")

        # Write comments if enabled and present
        if include_comments:
            comments = entry.get("_comments", [])
            for comment in comments:
                stream.write(f"{comment}\n")

        # Write other attributes
        for attr, value in entry.items():
            if attr in {"dn", "_comments", "_has_acl_attributes"}:
                continue

            if isinstance(value, list):
                for v in value:
                    stream.write(f"{attr}: {v}\n")
            else:
                stream.write(f"{attr}: {value}\n")

    @staticmethod
    def write_schema_to_file(
        file_path: Path,
        schema_content: str,
        header_comment: str | None = None,
    ) -> ServiceResult[Any]:
        """Write schema content to file with standardized format.

        Args:
            file_path: Path to output file
            schema_content: Schema content to write
            header_comment: Optional header comment

        Returns:
            ServiceResult with success status or error

        """
        try:
            # Ensure parent directory exists
            file_path.parent.mkdir(parents=True, exist_ok=True)

            with file_path.open("w", encoding="utf-8") as f:
                # Write header comment if provided
                if header_comment:
                    f.write(f"# {header_comment}\n")
                    f.write("#\n")

                # Write schema entry
                f.write("dn: cn=schema\n")
                f.write("changetype: modify\n")
                f.write(schema_content)

            logger.info("Wrote schema content to %s", file_path)
            return ServiceResult.ok(True)

        except Exception as e:
            logger.exception("Failed to write schema file: %s", file_path)
            return ServiceResult.fail(f"Failed to write schema: {e!s}")

    @staticmethod
    def write_text_lines_to_file(
        file_path: Path,
        lines: list[str],
        header_comment: str | None = None,
    ) -> ServiceResult[Any]:
        """Write text lines to file with optional header.

        Args:
            file_path: Path to output file
            lines: List of text lines to write
            header_comment: Optional header comment

        Returns:
            ServiceResult with number of lines written or error

        """
        try:
            # Ensure parent directory exists
            file_path.parent.mkdir(parents=True, exist_ok=True)

            with file_path.open("w", encoding="utf-8") as f:
                # Write header comment if provided
                if header_comment:
                    f.write(f"# {header_comment}\n")
                    f.write("#\n")

                # Write lines
                for line in lines:
                    f.write(f"{line}\n")

            logger.info("Wrote %d lines to %s", len(lines), file_path)
            return ServiceResult.ok(len(lines))

        except Exception as e:
            logger.exception("Failed to write text file: %s", file_path)
            return ServiceResult.fail(f"Failed to write text: {e!s}")


class LDIFHierarchicalSorter:
    """Utility class for hierarchical sorting of LDIF entries by DN depth."""

    @staticmethod
    def sort_entries_hierarchically(
        entries: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Sort entries hierarchically by DN depth and alphabetically.

        Args:
            entries: List of entries to sort

        Returns:
            List of entries sorted hierarchically

        """

        def get_dn_depth(entry: dict[str, Any]) -> int:
            """Get the depth of a DN (number of components)."""
            dn = entry.get("dn", "")
            if not dn:
                return 0
            # Handle both string and list DNs
            if isinstance(dn, list):
                dn = dn[0] if dn else ""
            if not isinstance(dn, str):
                dn = str(dn)
            # Count the number of components in the DN
            return len([c for c in dn.split(",") if c.strip()])

        def get_dn_sort_key(entry: dict[str, Any]) -> tuple[int, str]:
            """Get sort key for DN-based hierarchical sorting."""
            dn = entry.get("dn", "")
            # Handle both string and list DNs
            if isinstance(dn, list):
                dn = dn[0] if dn else ""
            if not isinstance(dn, str):
                dn = str(dn)
            depth = get_dn_depth(entry)
            # Sort by depth first (shallower first), then alphabetically
            return (depth, dn.lower())

        # Sort entries hierarchically: parents before children
        return sorted(entries, key=get_dn_sort_key)


def _sort_entries_hierarchically(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort entries hierarchically by DN depth and alphabetically.

    Args:
        entries: List of entries to sort

    Returns:
        List of entries sorted hierarchically

    """
    return LDIFHierarchicalSorter.sort_entries_hierarchically(entries)


# Convenience alias for backward compatibility
LDIFWriter = FlextLDIFWriter
