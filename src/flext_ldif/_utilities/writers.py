"""Master class for all LDIF writing utilities.

Python 3.13+ optimized implementation using:
- Nested classes for organized structure
- Protocol-based hooks for server customization
- Generator expressions for lazy evaluation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol

import structlog
from flext_core import FlextRuntime, r

from flext_ldif._models.config import FlextLdifModelsConfig
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif.protocols import p

# Use flext_core utilities directly to avoid circular import with flext_ldif.utilities

# REMOVED: Type aliases for nested objects - use m.* or FlextLdifModelsDomains.* directly
# type Entry = FlextLdifModelsDomains.Entry  # Use p.Ldif.EntryProtocol or FlextLdifModelsDomains.Entry directly
# type SchemaAttribute = FlextLdifModelsDomains.SchemaAttribute  # Use p.Ldif.SchemaAttributeProtocol or FlextLdifModelsDomains.SchemaAttribute directly
# type SchemaObjectClass = FlextLdifModelsDomains.SchemaObjectClass  # Use p.Ldif.SchemaObjectClassProtocol or FlextLdifModelsDomains.SchemaObjectClass directly

logger = structlog.get_logger(__name__)

# REMOVED: EntryAttrs alias - use t.Entry.EntryAttrs directly (no redundant aliases for nested objects)
# EntryAttrs = t.Entry.EntryAttrs


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
                entry: p.Ldif.EntryProtocol,
                lines: list[str],
            ) -> None: ...

        class WriteAttributesHook(Protocol):
            """Protocol for writing attributes."""

            def __call__(
                self,
                entry: p.Ldif.EntryProtocol,
                lines: list[str],
            ) -> None: ...

        class FormatValueHook(Protocol):
            """Protocol for formatting attribute values."""

            def __call__(self, attr_name: str, value: str) -> str: ...

        class TransformEntryHook(Protocol):
            """Protocol for entry transformation before write."""

            def __call__(
                self,
                entry: p.Ldif.EntryProtocol,
            ) -> p.Ldif.EntryProtocol: ...

        class WriteDnHook(Protocol):
            """Protocol for writing DN line."""

            def __call__(self, dn: str, lines: list[str]) -> None: ...

        # ===== NESTED STATISTICS DATACLASS =====

        @dataclass
        class Stats:
            """Statistics for entry writing."""

            total_entries: int = 0
            successful: int = 0
            failed: int = 0
            total_attributes: int = 0
            folded_lines: int = 0

        # ===== STATIC METHODS =====

        @staticmethod
        def get_dn_string(entry: p.Ldif.EntryProtocol) -> str:
            """Extract DN string from entry."""
            if entry.dn is None:
                return ""
            if hasattr(entry.dn, "value"):
                return entry.dn.value or (str(entry.dn) if entry.dn else "")
            return str(entry.dn) if entry.dn else ""

        @staticmethod
        def write_entry_parts(
            entry: p.Ldif.EntryProtocol,
            config: FlextLdifModelsConfig.EntryWriteConfig,
            lines: list[str],
        ) -> None:
            """Write entry parts (comments, DN, attributes)."""
            # entry is Entry which satisfies EntryProtocol structurally (Protocols are structural)
            # Write comments if hook provided and enabled
            if config.include_comments and config.write_comments_hook:
                # config.write_comments_hook expects EntryProtocol, entry satisfies it structurally
                config.write_comments_hook(entry, lines)

            # Write DN
            dn_str = FlextLdifUtilitiesWriters.Entry.get_dn_string(entry)
            if config.write_dn_hook:
                config.write_dn_hook(dn_str, lines)
            else:
                lines.append(f"dn: {dn_str}")

            # Write attributes using hook
            # config.write_attributes_hook expects EntryProtocol, entry satisfies it structurally
            config.write_attributes_hook(entry, lines)

        @staticmethod
        def write(
            *,
            config: FlextLdifModelsConfig.EntryWriteConfig | None = None,
            **kwargs: object,
        ) -> r[str]:
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
                # Use model_validate which accepts dict[str, object] and validates at runtime
                config = FlextLdifModelsConfig.EntryWriteConfig.model_validate(kwargs)

            try:
                lines: list[str] = []
                # Type narrowing: config.entry is EntryProtocol, convert to Entry if needed
                entry_raw = config.entry
                # Check if it's already Entry model instance
                if isinstance(entry_raw, FlextLdifModelsDomains.Entry):
                    entry = entry_raw
                else:
                    # Convert EntryProtocol to Entry via model_validate
                    entry = FlextLdifModelsDomains.Entry.model_validate({
                        "dn": (
                            entry_raw.dn.value
                            if hasattr(entry_raw.dn, "value")
                            else str(entry_raw.dn)
                            if entry_raw.dn
                            else None
                        ),
                        "attributes": (
                            entry_raw.attributes.attributes
                            if hasattr(entry_raw.attributes, "attributes")
                            else entry_raw.attributes or None
                        ),
                    })

                # Transform entry if hook provided
                if config.transform_entry_hook:
                    # transform_entry_hook accepts EntryProtocol (entry satisfies it structurally)
                    entry_transformed = config.transform_entry_hook(entry)
                    # Check if transformed result is already Entry model instance
                    if isinstance(entry_transformed, FlextLdifModelsDomains.Entry):
                        entry = entry_transformed
                    else:
                        # Convert EntryProtocol to Entry via model_validate
                        entry = FlextLdifModelsDomains.Entry.model_validate({
                            "dn": (
                                entry_transformed.dn.value
                                if hasattr(entry_transformed.dn, "value")
                                else str(entry_transformed.dn)
                                if entry_transformed.dn
                                else None
                            ),
                            "attributes": (
                                entry_transformed.attributes.attributes
                                if hasattr(entry_transformed.attributes, "attributes")
                                else entry_transformed.attributes or None
                            ),
                        })

                # Write entry parts
                FlextLdifUtilitiesWriters.Entry.write_entry_parts(entry, config, lines)

                # Join lines and return
                ldif_str = "\n".join(lines) + "\n"
                return r[str].ok(ldif_str)

            except Exception as e:
                # Type narrowing: config.entry is EntryProtocol, extract DN for error message
                entry_for_error_raw = config.entry
                # Extract DN string directly from EntryProtocol
                dn_for_error: str | None = None
                if entry_for_error_raw and entry_for_error_raw.dn:
                    if hasattr(entry_for_error_raw.dn, "value"):
                        dn_for_error = str(entry_for_error_raw.dn.value)
                    else:
                        dn_for_error = str(entry_for_error_raw.dn)
                dn_error_raw = dn_for_error or ""
                dn_error: str | None = dn_error_raw[:50] if dn_error_raw else None
                logger.exception(
                    "Failed to write entry",
                    server_type=config.server_type,
                    dn=dn_error,
                )
                return r[str].fail(f"Failed to write entry: {e}")

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
                attribute: p.Ldif.SchemaAttributeProtocol,
            ) -> list[str]: ...

        class TransformHook(Protocol):
            """Protocol for attribute transformation."""

            def __call__(
                self,
                attribute: p.Ldif.SchemaAttributeProtocol,
            ) -> p.Ldif.SchemaAttributeProtocol: ...

        class FormatOidHook(Protocol):
            """Protocol for OID formatting."""

            def __call__(self, oid: str) -> str: ...

        # ===== STATIC METHODS =====

        @staticmethod
        def write(
            attribute: p.Ldif.SchemaAttributeProtocol,
            server_type: str,
            build_parts_hook: BuildPartsHook,
            *,
            transform_hook: TransformHook | None = None,
            format_oid_hook: FormatOidHook | None = None,
        ) -> r[str]:
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
                return r[str].ok(definition)

            except Exception as e:
                logger.exception("Failed to write attribute", server_type=server_type)
                return r[str].fail(f"Failed to write attribute: {e}")

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
        ) -> r[str]:
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
                return r[str].ok(definition)

            except Exception as e:
                logger.exception("Failed to write objectClass", server_type=server_type)
                return r[str].fail(f"Failed to write objectClass: {e}")

    # =========================================================================
    # CONTENT WRITER - Write multiple entries
    # =========================================================================

    class Content:
        """Generalized content writer for multiple entries."""

        # ===== NESTED PROTOCOL DEFINITIONS =====

        class WriteEntryHook(Protocol):
            """Protocol for writing individual entries."""

            def __call__(self, entry: p.Ldif.EntryProtocol) -> r[str]: ...

        class WriteHeaderHook(Protocol):
            """Protocol for writing LDIF header."""

            def __call__(self) -> str: ...

        # ===== NESTED STATISTICS DATACLASS =====

        @dataclass
        class Stats:
            """Statistics for content writing."""

            total_entries: int = 0
            successful: int = 0
            failed: int = 0

        # ===== STATIC METHODS =====

        @staticmethod
        def get_entry_dn_for_error(entry: p.Ldif.EntryProtocol) -> str | None:
            """Get DN string for error logging."""
            if entry.dn is None:
                return None
            if hasattr(entry.dn, "value"):
                dn_obj = entry.dn
                value = getattr(dn_obj, "value", None)
                if value:
                    return str(value)[:50]
            return str(entry.dn)[:50] if entry.dn else None

        @staticmethod
        def write_single_entry_with_stats(
            entry: p.Ldif.EntryProtocol,
            write_entry_hook: Callable[[p.Ldif.EntryProtocol], r[str]],
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
            entries: Sequence[p.Ldif.EntryProtocol],
            write_entry_hook: Callable[[p.Ldif.EntryProtocol], r[str]],
            stats: Stats,
        ) -> list[str]:
            """Fallback manual processing if batch fails."""
            # Manually process entries instead of using u.Collection.process
            # to avoid complex generic type inference issues
            results: list[str] = []
            for entry in entries:
                result = (
                    FlextLdifUtilitiesWriters.Content.write_single_entry_with_stats(
                        entry,
                        write_entry_hook,
                        stats,
                    )
                )
                if result is not None:
                    results.append(result)
            return results

        @staticmethod
        def write(
            *,
            config: FlextLdifModelsConfig.BatchWriteConfig | None = None,
            **kwargs: object,
        ) -> r[str]:
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
                # Use model_validate which accepts dict[str, object] and validates at runtime
                config = FlextLdifModelsConfig.BatchWriteConfig.model_validate(kwargs)

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

                # Convert EntryProtocol entries to Entry for type compatibility
                entries_typed: list[FlextLdifModelsDomains.Entry] = []
                for entry in config.entries:
                    # Check if it's already Entry model instance
                    if isinstance(entry, FlextLdifModelsDomains.Entry):
                        entries_typed.append(entry)
                    else:
                        # Convert EntryProtocol to Entry via model_validate
                        entries_typed.append(
                            FlextLdifModelsDomains.Entry.model_validate({
                                "dn": (
                                    entry.dn.value
                                    if hasattr(entry.dn, "value")
                                    else str(entry.dn)
                                    if entry.dn
                                    else None
                                ),
                                "attributes": (
                                    entry.attributes.attributes
                                    if hasattr(entry.attributes, "attributes")
                                    else entry.attributes or None
                                ),
                            }),
                        )

                # Write each entry using manual loop for clear type inference
                # (avoiding complex generic type inference issues with u.Collection.batch)
                for entry in entries_typed:
                    result = (
                        FlextLdifUtilitiesWriters.Content.write_single_entry_with_stats(
                            entry,
                            config.write_entry_hook,
                            stats,
                        )
                    )
                    if result is not None:
                        parts.append(result)

                # Join with separator
                content = config.entry_separator.join(parts)
                return r[str].ok(content)

            except Exception as e:
                logger.exception(
                    "Failed to write content",
                    server_type=config.server_type,
                )
                return r[str].fail(f"Failed to write content: {e}")
