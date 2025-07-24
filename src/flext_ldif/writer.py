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

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext-core root namespace imports
from flext_core import FlextResult

try:
    from ldif3 import LDIFWriter as Ldif3Writer
except ImportError:
    Ldif3Writer = None

logger = logging.getLogger(__name__)


class FlextLdifWriter:
    """Enterprise LDIF writer utility following FLEXT patterns.

    Provides standardized LDIF file writing operations with hierarchical sorting,
    proper error handling, and ServiceResult patterns. Uses ldif3 library for
    proper LDIF formatting, base64 encoding, and line folding when available.
    Designed for use across all FLEXT projects to eliminate code duplication.
    """

    @staticmethod
    def write_entries_to_file(
        file_path: Path,
        entries: list[dict[str, Any]],
        *,
        sort_hierarchically: bool = True,
        include_comments: bool = True,
        buffering: int = 8192,
        cols: int = 78,
        base64_attrs: set[str] | None = None,
    ) -> FlextResult[Any]:
        """Write LDIF entries to file with standardized formatting.

        Args:
            file_path: Path to output file
            entries: List of entries to write
            sort_hierarchically: Whether to sort entries hierarchically by DN depth
            include_comments: Whether to include _comments fields in output
            buffering: Buffer size for file operations
            cols: Column width for line folding (default 78)
            base64_attrs: Set of attribute names to force base64 encoding

        Returns:
            FlextResult with number of entries written or error

        """
        try:
            # Ensure parent directory exists
            file_path.parent.mkdir(parents=True, exist_ok=True)

            # Sort entries if requested
            entries_to_write = entries
            if sort_hierarchically:
                entries_to_write = _flext_ldif_sort_entries_hierarchically(entries)

            # Check ldif3 availability and Python 3.13 compatibility
            use_ldif3 = False
            if Ldif3Writer is not None:
                import base64

                if hasattr(base64, "encodestring"):
                    use_ldif3 = True
                else:
                    logger.warning(
                        "ldif3 is not compatible with Python 3.13+, using fallback writer",
                    )

            if use_ldif3:
                # ldif3 requires binary mode
                with file_path.open("wb", buffering=buffering) as f:
                    FlextLdifWriter._write_entries_with_ldif3(
                        f,
                        entries_to_write,
                        include_comments=include_comments,
                        cols=cols,
                        base64_attrs=base64_attrs or set(),
                    )
            else:
                # Fallback to simple writer with text mode if ldif3 not available or incompatible
                with file_path.open("w", encoding="utf-8", buffering=buffering) as f:
                    FlextLdifWriter._write_entries_to_stream(
                        f,
                        entries_to_write,
                        include_comments=include_comments,
                    )

            logger.info("Wrote %d entries to %s", len(entries_to_write), file_path)
            return FlextResult.ok(len(entries_to_write))

        except Exception as e:
            logger.exception("Failed to write LDIF file: %s", file_path)
            return FlextResult.fail(f"Failed to write LDIF: {e!s}")

    @staticmethod
    def write_flext_entries_to_file(
        file_path: Path,
        entries: list[Any],  # FlextLdifEntry objects
        *,
        sort_hierarchically: bool = True,
        cols: int = 78,
        base64_attrs: set[str] | None = None,
    ) -> FlextResult[Any]:
        """Write FlextLdifEntry objects to file using ldif3 formatting.

        Args:
            file_path: Path to output file
            entries: List of FlextLdifEntry objects
            sort_hierarchically: Whether to sort entries hierarchically by DN depth
            cols: Column width for line folding (default 78)
            base64_attrs: Set of attribute names to force base64 encoding

        Returns:
            FlextResult with number of entries written or error

        """
        try:
            # Convert FlextLdifEntry objects to dict format
            dict_entries = []
            for entry in entries:
                entry_dict = {"dn": str(entry.dn)}
                # Add all attributes from the entry
                entry_dict.update(entry.attributes.items())
                dict_entries.append(entry_dict)

            # Use the existing write_entries_to_file method
            return FlextLdifWriter.write_entries_to_file(
                file_path,
                dict_entries,
                sort_hierarchically=sort_hierarchically,
                include_comments=False,  # FlextLdifEntry doesn't have comments
                cols=cols,
                base64_attrs=base64_attrs,
            )

        except Exception as e:
            logger.exception("Failed to write FlextLdifEntry objects: %s", file_path)
            return FlextResult.fail(f"Failed to write LDIF entries: {e!s}")

    @staticmethod
    def _write_entries_with_ldif3(
        stream: Any,  # Binary stream for ldif3
        entries: list[dict[str, Any]],
        *,
        include_comments: bool,
        cols: int,
        base64_attrs: set[str],
    ) -> None:
        """Write entries using ldif3 LDIFWriter for proper formatting."""
        try:
            # Check for Python 3.13 compatibility issues with ldif3
            import base64

            if not hasattr(base64, "encodestring"):
                # ldif3 is not compatible with Python 3.13+, fall back to simple writer
                logger.warning(
                    "ldif3 is not compatible with Python 3.13+, using fallback writer",
                )
                raise ImportError("ldif3 not compatible with Python 3.13")

            # Create ldif3 writer with enhanced options
            writer = Ldif3Writer(
                output_file=stream,
                cols=cols,  # Line folding at specified column width
                base64_attrs=base64_attrs,  # Force base64 encoding for specific attributes
            )

            for entry in entries:
                # Extract DN
                dn = entry.get("dn", "")
                if isinstance(dn, list):
                    dn = dn[0] if dn else ""

                # Prepare attributes dictionary for ldif3
                attrs = {}

                # Add comments if enabled and present
                if include_comments and "_comments" in entry:
                    # ldif3 doesn't handle comments directly, so add as comment lines
                    comments = entry.get("_comments", [])
                    for comment in comments:
                        stream.write(f"{comment}\n".encode())

                # Process all attributes except special ones
                for attr, value in entry.items():
                    if attr in {"dn", "_comments", "_has_acl_attributes"}:
                        continue

                    # Convert single values to lists for ldif3 compatibility
                    if isinstance(value, list):
                        attrs[attr] = value
                    else:
                        attrs[attr] = [str(value)]

                # Write entry using ldif3
                writer.unparse(dn, attrs)

        except Exception as e:
            logger.exception("Failed to write with ldif3: %s", e)
            # Convert binary stream to text stream for fallback
            from io import TextIOWrapper

            if hasattr(stream, "mode") and "b" in getattr(stream, "mode", ""):
                # Stream is binary, wrap it as text for fallback writer
                text_stream = TextIOWrapper(stream, encoding="utf-8", newline="\n")
                try:
                    FlextLdifWriter._write_entries_to_stream(
                        text_stream,
                        entries,
                        include_comments=include_comments,
                    )
                finally:
                    text_stream.detach()  # Don't close the underlying binary stream
            else:
                # Fallback to simple writer if ldif3 fails
                FlextLdifWriter._write_entries_to_stream(
                    stream,
                    entries,
                    include_comments=include_comments,
                )

    @staticmethod
    def _write_entries_to_stream(
        stream: TextIO | StringIO,
        entries: list[dict[str, Any]],
        *,
        include_comments: bool,
    ) -> None:
        """Write entries to a file stream using simple formatting."""
        for i, entry in enumerate(entries):
            if i > 0:
                stream.write("\n")

            FlextLdifWriter._write_single_entry(
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
    ) -> FlextResult[Any]:
        """Write schema content to file with standardized format.

        Args:
            file_path: Path to output file
            schema_content: Schema content to write
            header_comment: Optional header comment

        Returns:
            FlextResult with success status or error

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
            return FlextResult.ok(True)

        except Exception as e:
            logger.exception("Failed to write schema file: %s", file_path)
            return FlextResult.fail(f"Failed to write schema: {e!s}")

    @staticmethod
    def write_text_lines_to_file(
        file_path: Path,
        lines: list[str],
        header_comment: str | None = None,
    ) -> FlextResult[Any]:
        """Write text lines to file with optional header.

        Args:
            file_path: Path to output file
            lines: List of text lines to write
            header_comment: Optional header comment

        Returns:
            FlextResult with number of lines written or error

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
            return FlextResult.ok(len(lines))

        except Exception as e:
            logger.exception("Failed to write text file: %s", file_path)
            return FlextResult.fail(f"Failed to write text: {e!s}")


class FlextLdifHierarchicalSorter:
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


def _flext_ldif_sort_entries_hierarchically(
    entries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Sort entries hierarchically by DN depth and alphabetically.

    Args:
        entries: List of entries to sort

    Returns:
        List of entries sorted hierarchically

    """
    return FlextLdifHierarchicalSorter.sort_entries_hierarchically(entries)


# Convenience alias for backward compatibility
LDIFWriter = FlextLdifWriter
