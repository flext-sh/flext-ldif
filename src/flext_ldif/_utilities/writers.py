"""Master class for all LDIF writing utilities."""

from __future__ import annotations

import struct
from collections.abc import Callable
from typing import Protocol

from flext_core import FlextLogger, r
from pydantic import BaseModel, ConfigDict, Field

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.settings import FlextLdifModelsSettings
from flext_ldif.models import m

# Use flext_core utilities directly to avoid circular import with flext_ldif.utilities

# REMOVED: Type aliases for nested objects - use m.* or FlextLdifModelsDomains.* directly
# type Entry = FlextLdifModelsDomains.Entry  # Use m.Ldif.Entry or FlextLdifModelsDomains.Entry directly
# type SchemaAttribute = FlextLdifModelsDomains.SchemaAttribute  # Use m.Ldif.SchemaAttribute or FlextLdifModelsDomains.SchemaAttribute directly
# type SchemaObjectClass = FlextLdifModelsDomains.SchemaObjectClass  # Use m.Ldif.SchemaObjectClass or FlextLdifModelsDomains.SchemaObjectClass directly

logger = FlextLogger.create_module_logger(__name__)

# REMOVED: EntryAttrs alias - use t.Entry.EntryAttrs directly (no redundant aliases for nested objects)
# EntryAttrs = t.Entry.EntryAttrs


class FlextLdifUtilitiesWriters:
    """Master class for all LDIF writing utilities."""

    # ENTRY WRITER - Write individual LDIF entries

    class Entry:
        """Generalized entry writer with hook-based customization."""

        # ===== NESTED PROTOCOL DEFINITIONS =====

        class WriteCommentsHook(Protocol):
            """Protocol for writing comments and metadata."""

            def __call__(
                self,
                entry: m.Ldif.Entry,
                lines: list[str],
            ) -> None: ...

        class WriteAttributesHook(Protocol):
            """Protocol for writing attributes."""

            def __call__(
                self,
                entry: m.Ldif.Entry,
                lines: list[str],
            ) -> None: ...

        class FormatValueHook(Protocol):
            """Protocol for formatting attribute values."""

            def __call__(self, attr_name: str, value: str) -> str: ...

        class TransformEntryHook(Protocol):
            """Protocol for entry transformation before write."""

            def __call__(
                self,
                entry: m.Ldif.Entry,
            ) -> m.Ldif.Entry: ...

        class WriteDnHook(Protocol):
            """Protocol for writing DN line."""

            def __call__(self, dn: str, lines: list[str]) -> None: ...

        # ===== NESTED STATISTICS MODEL =====

        class Stats(BaseModel):
            """Statistics for entry writing."""

            model_config = ConfigDict(extra="forbid")

            total_entries: int = Field(default=0, description="Total entries written")
            successful: int = Field(
                default=0, description="Successfully written entries"
            )
            failed: int = Field(default=0, description="Failed entries")
            total_attributes: int = Field(
                default=0, description="Total attributes written"
            )
            folded_lines: int = Field(default=0, description="Folded lines")

        # ===== STATIC METHODS =====

        @staticmethod
        def get_dn_string(entry: FlextLdifModelsDomains.Entry) -> str:
            """Extract DN string from entry."""
            dn = entry.dn
            if dn is None:
                return ""
            if getattr(dn, "value", None) is not None:
                return dn.value or str(dn) if dn else ""
            return str(dn) if dn else ""

        @staticmethod
        def write_entry_parts(
            entry: FlextLdifModelsDomains.Entry,
            config: FlextLdifModelsSettings.EntryWriteConfig,
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
            config: FlextLdifModelsSettings.EntryWriteConfig | None = None,
            **kwargs: t.GeneralValueType,
        ) -> r[str]:
            """Write entry to LDIF string using hooks."""
            # Use provided config or build from kwargs
            if config is None:
                # Use model_validate which accepts dict[str, t.GeneralValueType] and validates at runtime
                config = FlextLdifModelsSettings.EntryWriteConfig.model_validate(kwargs)

            try:
                lines: list[str] = []
                # config.entry is the correct Entry type
                entry: FlextLdifModelsDomains.Entry = config.entry

                # Transform entry if hook provided
                if config.transform_entry_hook:
                    entry = config.transform_entry_hook(
                        entry,
                    )  # Returns core Entry, assign to domain Entry

                # Write entry parts (expects m.Ldif.Entry)
                FlextLdifUtilitiesWriters.Entry.write_entry_parts(entry, config, lines)

                # Join lines and return
                ldif_str = "\n".join(lines) + "\n"
                return r[str].ok(ldif_str)

            except (
                ValueError,
                KeyError,
                AttributeError,
                UnicodeDecodeError,
                struct.error,
            ) as e:
                # Type narrowing: config.entry is Entry, extract DN for error message
                entry_for_error: FlextLdifModelsDomains.Entry | None = config.entry
                # Extract DN string
                dn_for_error: str | None = None
                try:
                    entry_dn = entry_for_error.dn if entry_for_error else None
                    if entry_for_error and entry_dn:
                        if getattr(entry_dn, "value", None) is not None:
                            dn_for_error = str(entry_dn.value)
                        else:
                            dn_for_error = str(entry_dn)
                except (AttributeError, TypeError):
                    dn_for_error = None
                dn_error_raw = dn_for_error or ""
                dn_error: str | None = dn_error_raw[:50] if dn_error_raw else None
                logger.exception(
                    "Failed to write entry",
                    server_type=config.server_type,
                    dn=dn_error,
                )
                return r[str].fail(f"Failed to write entry: {e}")

    # ATTRIBUTE WRITER - Write attribute type definitions

    class Attribute:
        """Generalized attribute definition writer."""

        # ===== NESTED PROTOCOL DEFINITIONS =====

        class BuildPartsHook(Protocol):
            """Protocol for building attribute definition parts."""

            def __call__(
                self,
                attribute: m.Ldif.SchemaAttribute,
            ) -> list[str]: ...

        class TransformHook(Protocol):
            """Protocol for attribute transformation."""

            def __call__(
                self,
                attribute: m.Ldif.SchemaAttribute,
            ) -> m.Ldif.SchemaAttribute: ...

        class FormatOidHook(Protocol):
            """Protocol for OID formatting."""

            def __call__(self, oid: str) -> str: ...

        # ===== STATIC METHODS =====

        @staticmethod
        def write(
            attribute: m.Ldif.SchemaAttribute,
            server_type: str,
            build_parts_hook: BuildPartsHook,
            *,
            transform_hook: TransformHook | None = None,
            format_oid_hook: FormatOidHook | None = None,
        ) -> r[str]:
            """Write attribute definition using hooks."""
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

            except (
                ValueError,
                KeyError,
                AttributeError,
                UnicodeDecodeError,
                struct.error,
            ) as e:
                logger.exception("Failed to write attribute", server_type=server_type)
                return r[str].fail(f"Failed to write attribute: {e}")

    # OBJECTCLASS WRITER - Write objectClass definitions

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
            """Write objectClass definition using hooks."""
            try:
                # Transform if hook provided
                if transform_hook:
                    objectclass = transform_hook(objectclass)

                # Transform SUP if hook provided
                if transform_sup_hook and objectclass.sup:
                    # Convert sup to list[str] if it's a string
                    sup_value = objectclass.sup
                    sup_list: list[str]
                    if isinstance(sup_value, list | tuple):
                        sup_list = [str(item) for item in sup_value]
                    else:
                        sup_list = [sup_value]
                    objectclass.sup = transform_sup_hook(sup_list)

                # Build parts using hook
                parts = build_parts_hook(objectclass)

                # Join parts into definition
                definition = "( " + " ".join(parts) + " )"
                return r[str].ok(definition)

            except (
                ValueError,
                KeyError,
                AttributeError,
                UnicodeDecodeError,
                struct.error,
            ) as e:
                logger.exception("Failed to write objectClass", server_type=server_type)
                return r[str].fail(f"Failed to write objectClass: {e}")

    # CONTENT WRITER - Write multiple entries

    class Content:
        """Generalized content writer for multiple entries."""

        # ===== NESTED PROTOCOL DEFINITIONS =====

        class WriteEntryHook(Protocol):
            """Protocol for writing individual entries."""

            def __call__(self, entry: FlextLdifModelsDomains.Entry) -> r[str]: ...

        class WriteHeaderHook(Protocol):
            """Protocol for writing LDIF header."""

            def __call__(self) -> str: ...

        # ===== NESTED STATISTICS MODEL =====

        class Stats(BaseModel):
            """Statistics for content writing."""

            model_config = ConfigDict(extra="forbid")

            total_entries: int = Field(default=0, description="Total entries written")
            successful: int = Field(
                default=0, description="Successfully written entries"
            )
            failed: int = Field(default=0, description="Failed entries")

        # ===== STATIC METHODS =====

        @staticmethod
        def get_entry_dn_for_error(entry: FlextLdifModelsDomains.Entry) -> str | None:
            """Get DN string for error logging."""
            dn_attr = entry.dn
            if dn_attr is None:
                return None
            if getattr(dn_attr, "value", None) is not None:
                value = getattr(dn_attr, "value", None)
                if value:
                    return str(value)[:50]
            return str(dn_attr)[:50] if dn_attr else None

        @staticmethod
        def write_single_entry_with_stats(
            entry: FlextLdifModelsDomains.Entry,
            write_entry_hook: Callable[[FlextLdifModelsDomains.Entry], r[str]],
            stats: Stats,
        ) -> str | None:
            """Write single entry with stats tracking."""
            result = write_entry_hook(entry)
            if result.is_success:
                stats.successful += 1
                return result.value
            stats.failed += 1
            dn_str = FlextLdifUtilitiesWriters.Content.get_entry_dn_for_error(entry)
            logger.error(
                "Failed to write entry",
                dn=dn_str,
                error=str(result.error),
            )
            return None

        @staticmethod
        def write(
            *,
            config: FlextLdifModelsSettings.BatchWriteConfig | None = None,
            **kwargs: t.GeneralValueType,
        ) -> r[str]:
            """Write multiple entries to LDIF string."""
            # Use provided config or build from kwargs
            if config is None:
                # Use model_validate which accepts dict[str, t.GeneralValueType] and validates at runtime
                config = FlextLdifModelsSettings.BatchWriteConfig.model_validate(kwargs)

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

                entries_typed: list[FlextLdifModelsDomains.Entry] = list(config.entries)

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

            except (
                ValueError,
                KeyError,
                AttributeError,
                UnicodeDecodeError,
                struct.error,
            ) as e:
                logger.exception(
                    "Failed to write content",
                    server_type=config.server_type,
                )
                return r[str].fail(f"Failed to write content: {e}")
