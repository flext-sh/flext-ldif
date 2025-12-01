"""Master class for all LDIF writing utilities.

Python 3.13+ optimized implementation using:
- Nested classes for organized structure
- Protocol-based hooks for server customization
- Generator expressions for lazy evaluation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import structlog
from flext_core import FlextResult, FlextRuntime

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes

logger = structlog.get_logger(__name__)

# Use types directly from FlextLdifTypes (no local aliases)
EntryAttrs = FlextLdifTypes.Entry.EntryAttrs


class FlextLdifUtilitiesWriters:
    """Master class for all LDIF writing utilities.

    Contains nested classes for each writing operation:
    - Entry: Write individual entries
    - Attribute: Write attribute definitions
    - ObjectClass: Write objectClass definitions
    - Content: Write multiple entries

    Example:
        >>> result = FlextLdifUtilitiesWriters.Entry.write(
        ...     entry, "oud", write_attrs_hook
        ... )

    """

    # =========================================================================
    # ENTRY WRITER - Write individual LDIF entries
    # =========================================================================

    class Entry:
        """Generalized entry writer with hook-based customization."""

        # ===== NESTED PROTOCOL DEFINITIONS =====

        class WriteCommentsHook(Protocol):
            """Protocol for writing comments and metadata."""

            def __call__(
                self,
                entry: FlextLdifModels.Entry,
                lines: list[str],
            ) -> None: ...

        class WriteAttributesHook(Protocol):
            """Protocol for writing attributes."""

            def __call__(
                self,
                entry: FlextLdifModels.Entry,
                lines: list[str],
            ) -> None: ...

        class FormatValueHook(Protocol):
            """Protocol for formatting attribute values."""

            def __call__(self, attr_name: str, value: str) -> str: ...

        class TransformEntryHook(Protocol):
            """Protocol for entry transformation before write."""

            def __call__(
                self,
                entry: FlextLdifModels.Entry,
            ) -> FlextLdifModels.Entry: ...

        class WriteDnHook(Protocol):
            """Protocol for writing DN line."""

            def __call__(self, dn: str, lines: list[str]) -> None: ...

        # ===== NESTED STATISTICS DATACLASS =====

        @dataclass(slots=True)
        class Stats:
            """Statistics for entry writing."""

            total_entries: int = 0
            successful: int = 0
            failed: int = 0
            total_attributes: int = 0
            folded_lines: int = 0

        # ===== STATIC METHODS =====

        @staticmethod
        def write(
            entry: FlextLdifModels.Entry,
            server_type: str,
            write_attributes_hook: WriteAttributesHook,
            *,
            write_comments_hook: WriteCommentsHook | None = None,
            transform_entry_hook: TransformEntryHook | None = None,
            write_dn_hook: WriteDnHook | None = None,
            include_comments: bool = True,
        ) -> FlextResult[str]:
            """Write entry to LDIF string using hooks.

            Args:
                entry: Entry model to write
                server_type: Server type identifier
                write_attributes_hook: Core attributes writing
                write_comments_hook: Optional comments writing
                transform_entry_hook: Optional entry transformation
                write_dn_hook: Optional DN writing
                include_comments: Include metadata comments

            Returns:
                FlextResult with LDIF string

            """
            try:
                lines: list[str] = []

                # Transform entry if hook provided
                if transform_entry_hook:
                    entry = transform_entry_hook(entry)

                # Write comments if hook provided and enabled
                if include_comments and write_comments_hook:
                    write_comments_hook(entry, lines)

                # Write DN
                if hasattr(entry.dn, "value"):
                    dn_str = entry.dn.value or (str(entry.dn) if entry.dn else "")
                else:
                    dn_str = str(entry.dn) if entry.dn else ""
                if write_dn_hook:
                    write_dn_hook(dn_str, lines)
                else:
                    lines.append(f"dn: {dn_str}")

                # Write attributes using hook
                write_attributes_hook(entry, lines)

                # Join lines and return
                ldif_str = "\n".join(lines) + "\n"
                return FlextResult[str].ok(ldif_str)

            except Exception as e:
                if hasattr(entry.dn, "value") and entry.dn.value:
                    dn_error: str | None = entry.dn.value[:50]
                elif entry.dn:
                    dn_error = str(entry.dn)[:50]
                else:
                    dn_error = None
                logger.exception(
                    "Failed to write entry",
                    server_type=server_type,
                    dn=dn_error,
                )
                return FlextResult[str].fail(f"Failed to write entry: {e}")

    # =========================================================================
    # ATTRIBUTE WRITER - Write attribute type definitions
    # =========================================================================

    class Attribute:
        """Generalized attribute definition writer."""

        # ===== NESTED PROTOCOL DEFINITIONS =====

        class BuildPartsHook(Protocol):
            """Protocol for building attribute definition parts."""

            def __call__(
                self,
                attribute: FlextLdifModelsDomains.SchemaAttribute,
            ) -> list[str]: ...

        class TransformHook(Protocol):
            """Protocol for attribute transformation."""

            def __call__(
                self,
                attribute: FlextLdifModelsDomains.SchemaAttribute,
            ) -> FlextLdifModelsDomains.SchemaAttribute: ...

        class FormatOidHook(Protocol):
            """Protocol for OID formatting."""

            def __call__(self, oid: str) -> str: ...

        # ===== STATIC METHODS =====

        @staticmethod
        def write(
            attribute: FlextLdifModelsDomains.SchemaAttribute,
            server_type: str,
            build_parts_hook: BuildPartsHook,
            *,
            transform_hook: TransformHook | None = None,
            format_oid_hook: FormatOidHook | None = None,
        ) -> FlextResult[str]:
            """Write attribute definition using hooks.

            Args:
                attribute: Attribute model to write
                server_type: Server type identifier
                build_parts_hook: Core parts building
                transform_hook: Optional attribute transformation
                format_oid_hook: Optional OID formatting

            Returns:
                FlextResult with definition string

            """
            try:
                # Transform if hook provided
                if transform_hook:
                    attribute = transform_hook(attribute)

                # Build parts using hook
                parts = build_parts_hook(attribute)

                # Format OID if hook provided
                if format_oid_hook and attribute.oid:
                    parts[0] = format_oid_hook(attribute.oid)

                # Join parts into definition
                definition = "( " + " ".join(parts) + " )"
                return FlextResult[str].ok(definition)

            except Exception as e:
                logger.exception("Failed to write attribute", server_type=server_type)
                return FlextResult[str].fail(f"Failed to write attribute: {e}")

    # =========================================================================
    # OBJECTCLASS WRITER - Write objectClass definitions
    # =========================================================================

    class ObjectClass:
        """Generalized objectClass definition writer."""

        # ===== NESTED PROTOCOL DEFINITIONS =====

        class BuildPartsHook(Protocol):
            """Protocol for building objectClass definition parts."""

            def __call__(
                self,
                objectclass: FlextLdifModelsDomains.SchemaObjectClass,
            ) -> list[str]: ...

        class TransformHook(Protocol):
            """Protocol for objectClass transformation."""

            def __call__(
                self,
                objectclass: FlextLdifModelsDomains.SchemaObjectClass,
            ) -> FlextLdifModelsDomains.SchemaObjectClass: ...

        class TransformSupHook(Protocol):
            """Protocol for SUP clause transformation."""

            def __call__(self, sup: list[str]) -> list[str]: ...

        # ===== STATIC METHODS =====

        @staticmethod
        def write(
            objectclass: FlextLdifModelsDomains.SchemaObjectClass,
            server_type: str,
            build_parts_hook: BuildPartsHook,
            *,
            transform_hook: TransformHook | None = None,
            transform_sup_hook: TransformSupHook | None = None,
        ) -> FlextResult[str]:
            """Write objectClass definition using hooks.

            Args:
                objectclass: ObjectClass model to write
                server_type: Server type identifier
                build_parts_hook: Core parts building
                transform_hook: Optional objectClass transformation
                transform_sup_hook: Optional SUP transformation

            Returns:
                FlextResult with definition string

            """
            try:
                # Transform if hook provided
                if transform_hook:
                    objectclass = transform_hook(objectclass)

                # Transform SUP if hook provided
                if transform_sup_hook and objectclass.sup:
                    # Convert sup to list[str] if it's a string
                    sup_value = objectclass.sup
                    if FlextRuntime.is_list_like(sup_value):
                        sup_list: list[str] = [str(item) for item in sup_value]
                    elif isinstance(sup_value, str):
                        sup_list = [sup_value]
                    else:
                        sup_list = [str(sup_value)]
                    objectclass.sup = transform_sup_hook(sup_list)

                # Build parts using hook
                parts = build_parts_hook(objectclass)

                # Join parts into definition
                definition = "( " + " ".join(parts) + " )"
                return FlextResult[str].ok(definition)

            except Exception as e:
                logger.exception("Failed to write objectClass", server_type=server_type)
                return FlextResult[str].fail(f"Failed to write objectClass: {e}")

    # =========================================================================
    # CONTENT WRITER - Write multiple entries
    # =========================================================================

    class Content:
        """Generalized content writer for multiple entries."""

        # ===== NESTED PROTOCOL DEFINITIONS =====

        class WriteEntryHook(Protocol):
            """Protocol for writing individual entries."""

            def __call__(self, entry: FlextLdifModels.Entry) -> FlextResult[str]: ...

        class WriteHeaderHook(Protocol):
            """Protocol for writing LDIF header."""

            def __call__(self) -> str: ...

        # ===== NESTED STATISTICS DATACLASS =====

        @dataclass(slots=True)
        class Stats:
            """Statistics for content writing."""

            total_entries: int = 0
            successful: int = 0
            failed: int = 0

        # ===== STATIC METHODS =====

        @staticmethod
        def write(
            entries: list[FlextLdifModels.Entry],
            server_type: str,
            write_entry_hook: WriteEntryHook,
            *,
            write_header_hook: WriteHeaderHook | None = None,
            include_header: bool = True,
            entry_separator: str = "\n",
        ) -> FlextResult[str]:
            """Write multiple entries to LDIF string.

            Args:
                entries: List of entries to write
                server_type: Server type identifier
                write_entry_hook: Entry writing logic
                write_header_hook: Optional header writing
                include_header: Include LDIF header
                entry_separator: Separator between entries

            Returns:
                FlextResult with complete LDIF string

            """
            try:
                parts: list[str] = []

                # Write header if enabled
                if include_header and write_header_hook:
                    header = write_header_hook()
                    if header:
                        parts.append(header)

                # Write each entry
                stats = FlextLdifUtilitiesWriters.Content.Stats(
                    total_entries=len(entries),
                )

                for entry in entries:
                    result = write_entry_hook(entry)
                    if result.is_success:
                        parts.append(result.unwrap())
                        stats.successful += 1
                    else:
                        stats.failed += 1
                        if hasattr(entry.dn, "value") and entry.dn.value:
                            dn_str: str | None = entry.dn.value[:50]
                        elif entry.dn:
                            dn_str = str(entry.dn)[:50]
                        else:
                            dn_str = None
                        logger.error(
                            "Failed to write entry",
                            dn=dn_str,
                            error=str(result.error),
                        )

                # Join with separator
                content = entry_separator.join(parts)
                return FlextResult[str].ok(content)

            except Exception as e:
                logger.exception("Failed to write content", server_type=server_type)
                return FlextResult[str].fail(f"Failed to write content: {e}")
