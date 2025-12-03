"""Master class for all LDIF writing utilities.

Python 3.13+ optimized implementation using:
- Nested classes for organized structure
- Protocol-based hooks for server customization
- Generator expressions for lazy evaluation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

import structlog
from flext_core import FlextResult, FlextRuntime, u

from flext_ldif._models.config import FlextLdifModelsConfig
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
        def get_dn_string(entry: FlextLdifModels.Entry) -> str:
            """Extract DN string from entry."""
            if entry.dn is None:
                return ""
            if hasattr(entry.dn, "value"):
                return entry.dn.value or (str(entry.dn) if entry.dn else "")
            return str(entry.dn) if entry.dn else ""

        @staticmethod
        def write_entry_parts(
            entry: FlextLdifModels.Entry,
            config: FlextLdifModelsConfig.EntryWriteConfig,
            lines: list[str],
        ) -> None:
            """Write entry parts (comments, DN, attributes)."""
            # Write comments if hook provided and enabled
            if config.include_comments and config.write_comments_hook:
                config.write_comments_hook(entry, lines)

            # Write DN
            dn_str = FlextLdifUtilitiesWriters.Entry.get_dn_string(entry)
            if config.write_dn_hook:
                config.write_dn_hook(dn_str, lines)
            else:
                lines.append(f"dn: {dn_str}")

            # Write attributes using hook
            config.write_attributes_hook(entry, lines)

        @staticmethod
        def write(
            *,
            config: FlextLdifModelsConfig.EntryWriteConfig | None = None,
            **kwargs: object,
        ) -> FlextResult[str]:
            """Write entry to LDIF string using hooks.

            Args:
                config: EntryWriteConfig with all writing parameters (preferred)
                **kwargs: Optional parameters for EntryWriteConfig (entry, server_type,
                    write_attributes_hook, write_comments_hook, transform_entry_hook,
                    write_dn_hook, include_comments) - used only if config is None

            Returns:
                FlextResult with LDIF string

            """
            # Use provided config or build from kwargs
            if config is None:
                config = FlextLdifModelsConfig.EntryWriteConfig(**kwargs)  # type: ignore[arg-type]

            try:
                lines: list[str] = []
                entry = config.entry

                # Transform entry if hook provided
                if config.transform_entry_hook:
                    entry = config.transform_entry_hook(entry)

                # Write entry parts
                FlextLdifUtilitiesWriters.Entry.write_entry_parts(entry, config, lines)

                # Join lines and return
                ldif_str = "\n".join(lines) + "\n"
                return FlextResult[str].ok(ldif_str)

            except Exception as e:
                entry_for_error = config.entry
                dn_error_raw = FlextLdifUtilitiesWriters.Entry.get_dn_string(
                    entry_for_error
                )
                dn_error: str | None = dn_error_raw[:50] if dn_error_raw else None
                logger.exception(
                    "Failed to write entry",
                    server_type=config.server_type,
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
                        sup_list = [str(item) for item in sup_value]
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
        def get_entry_dn_for_error(entry: FlextLdifModels.Entry) -> str | None:
            """Get DN string for error logging."""
            if entry.dn is None:
                return None
            if hasattr(entry.dn, "value") and entry.dn.value:
                return entry.dn.value[:50]
            return str(entry.dn)[:50] if entry.dn else None

        @staticmethod
        def write_single_entry_with_stats(
            entry: FlextLdifModels.Entry,
            write_entry_hook: Callable[[FlextLdifModels.Entry], FlextResult[str]],
            stats: Stats,
        ) -> str | None:
            """Write single entry with stats tracking."""
            result = write_entry_hook(entry)
            if result.is_success:
                stats.successful += 1
                return result.unwrap()
            stats.failed += 1
            dn_str = FlextLdifUtilitiesWriters.Content.get_entry_dn_for_error(entry)
            logger.error(
                "Failed to write entry",
                dn=dn_str,
                error=str(result.error),
            )
            return None

        @staticmethod
        def write_entries_fallback(
            entries: list[FlextLdifModels.Entry],
            write_entry_hook: Callable[[FlextLdifModels.Entry], FlextResult[str]],
            stats: Stats,
        ) -> list[str]:
            """Fallback manual processing if batch fails."""

            def process_entry(entry: FlextLdifModels.Entry) -> str | None:
                """Process single entry."""
                return FlextLdifUtilitiesWriters.Content.write_single_entry_with_stats(
                    entry,
                    write_entry_hook,
                    stats,
                )

            processed_result = u.process(
                entries,
                processor=process_entry,
                on_error="skip",
            )
            if processed_result.is_success and isinstance(processed_result.value, list):
                filtered_result = u.filter(
                    processed_result.value,
                    predicate=lambda item: item is not None and isinstance(item, str),
                )
                return filtered_result if isinstance(filtered_result, list) else []
            return []

        @staticmethod
        def write(
            *,
            config: FlextLdifModelsConfig.BatchWriteConfig | None = None,
            **kwargs: object,
        ) -> FlextResult[str]:
            """Write multiple entries to LDIF string.

            Args:
                config: BatchWriteConfig with all writing parameters (preferred)
                **kwargs: Optional parameters for BatchWriteConfig (entries, server_type,
                    write_entry_hook, write_header_hook, include_header, entry_separator) -
                    used only if config is None

            Returns:
                FlextResult with complete LDIF string

            """
            # Use provided config or build from kwargs
            if config is None:
                config = FlextLdifModelsConfig.BatchWriteConfig(**kwargs)  # type: ignore[arg-type]

            try:
                parts: list[str] = []

                # Write header if enabled
                if config.include_header and config.write_header_hook:
                    header = config.write_header_hook()
                    if header:
                        parts.append(header)

                # Write each entry using u.batch
                stats = FlextLdifUtilitiesWriters.Content.Stats(
                    total_entries=len(config.entries),
                )

                def write_single_entry(entry: FlextLdifModels.Entry) -> str | None:
                    """Write single entry, return None on error."""
                    return (
                        FlextLdifUtilitiesWriters.Content.write_single_entry_with_stats(
                            entry,
                            config.write_entry_hook,
                            stats,
                        )
                    )

                batch_result = u.batch(
                    list(config.entries),
                    operation=write_single_entry,
                    on_error="collect",
                    post_validate=lambda r: r is not None,
                )
                if batch_result.is_success:
                    batch_data = batch_result.value
                    filtered_results = u.filter(
                        batch_data["results"],
                        predicate=lambda r: isinstance(r, str),
                    )
                    if isinstance(filtered_results, list):
                        parts.extend(filtered_results)
                else:
                    # Fallback to manual processing if batch fails
                    parts.extend(
                        FlextLdifUtilitiesWriters.Content.write_entries_fallback(
                            config.entries,
                            config.write_entry_hook,
                            stats,
                        )
                    )

                # Join with separator
                content = config.entry_separator.join(parts)
                return FlextResult[str].ok(content)

            except Exception as e:
                logger.exception(
                    "Failed to write content", server_type=config.server_type
                )
                return FlextResult[str].fail(f"Failed to write content: {e}")
