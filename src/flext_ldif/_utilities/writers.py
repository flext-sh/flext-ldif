"""Master class for all LDIF writing utilities."""

from __future__ import annotations

import struct
from collections.abc import Callable
from typing import Annotated

from flext_core import FlextLogger, r
from pydantic import BaseModel, ConfigDict, Field

from flext_ldif import m
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.settings import FlextLdifModelsSettings
from flext_ldif.typings import t

logger = FlextLogger.create_module_logger(__name__)


class FlextLdifUtilitiesWriters:
    """Master class for all LDIF writing utilities."""

    class Entry:
        """Generalized entry writer with hook-based customization."""

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
        def write(
            *,
            config: FlextLdifModelsSettings.EntryWriteConfig | None = None,
            **kwargs: t.Scalar,
        ) -> r[str]:
            """Write entry to LDIF string using hooks."""
            if config is None:
                config = FlextLdifModelsSettings.EntryWriteConfig.model_validate(kwargs)
            try:
                lines: list[str] = []
                entry: FlextLdifModelsDomains.Entry = config.entry
                if config.transform_entry_hook:
                    entry = config.transform_entry_hook(entry)
                FlextLdifUtilitiesWriters.Entry.write_entry_parts(entry, config, lines)
                ldif_str = "\n".join(lines) + "\n"
                return r[str].ok(ldif_str)
            except (
                ValueError,
                KeyError,
                AttributeError,
                UnicodeDecodeError,
                struct.error,
            ) as e:
                entry_for_error: FlextLdifModelsDomains.Entry | None = config.entry
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
                dn_error: str = dn_error_raw[:50] if dn_error_raw else ""
                logger.exception(
                    "Failed to write entry", server_type=config.server_type, dn=dn_error
                )
                return r[str].fail(f"Failed to write entry: {e}")

        @staticmethod
        def write_entry_parts(
            entry: FlextLdifModelsDomains.Entry,
            config: FlextLdifModelsSettings.EntryWriteConfig,
            lines: list[str],
        ) -> None:
            """Write entry parts (comments, DN, attributes)."""
            if config.include_comments and config.write_comments_hook:
                config.write_comments_hook(entry, lines)
            dn_str = FlextLdifUtilitiesWriters.Entry.get_dn_string(entry)
            if config.write_dn_hook:
                config.write_dn_hook(dn_str, lines)
            else:
                lines.append(f"dn: {dn_str}")
            config.write_attributes_hook(entry, lines)

    class Attribute:
        """Generalized attribute definition writer."""

        @staticmethod
        def write(
            attribute: m.Ldif.SchemaAttribute,
            server_type: str,
            build_parts_hook: Callable[[m.Ldif.SchemaAttribute], list[str]],
            *,
            transform_hook: Callable[[m.Ldif.SchemaAttribute], m.Ldif.SchemaAttribute]
            | None = None,
            format_oid_hook: Callable[[str], str] | None = None,
        ) -> r[str]:
            """Write attribute definition using hooks."""
            try:
                if transform_hook:
                    attribute = transform_hook(attribute)
                parts = build_parts_hook(attribute)
                if format_oid_hook and attribute.oid:
                    parts[0] = format_oid_hook(attribute.oid)
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

    class ObjectClass:
        """Generalized objectClass definition writer."""

        @staticmethod
        def write(
            objectclass: FlextLdifModelsDomains.SchemaObjectClass,
            server_type: str,
            build_parts_hook: Callable[
                [FlextLdifModelsDomains.SchemaObjectClass], list[str]
            ],
            *,
            transform_hook: Callable[
                [FlextLdifModelsDomains.SchemaObjectClass],
                FlextLdifModelsDomains.SchemaObjectClass,
            ]
            | None = None,
            transform_sup_hook: Callable[[list[str]], list[str]] | None = None,
        ) -> r[str]:
            """Write objectClass definition using hooks."""
            try:
                if transform_hook:
                    objectclass = transform_hook(objectclass)
                if transform_sup_hook and objectclass.sup:
                    sup_value = objectclass.sup
                    sup_list: list[str]
                    if isinstance(sup_value, (list, tuple)):
                        sup_list = [str(item) for item in sup_value]
                    else:
                        sup_list = [sup_value]
                    setattr(objectclass, "sup", transform_sup_hook(sup_list))
                parts = build_parts_hook(objectclass)
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

    class Content:
        """Generalized content writer for multiple entries."""

        class Stats(BaseModel):
            model_config = ConfigDict(validate_default=True)
            total_entries: Annotated[int, Field(default=0, ge=0)]
            successful: Annotated[int, Field(default=0, ge=0)]
            failed: Annotated[int, Field(default=0, ge=0)]

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
        def write(
            *,
            config: FlextLdifModelsSettings.BatchWriteConfig | None = None,
            **kwargs: t.Scalar,
        ) -> r[str]:
            """Write multiple entries to LDIF string."""
            if config is None:
                config = FlextLdifModelsSettings.BatchWriteConfig.model_validate(kwargs)
            try:
                parts: list[str] = []
                if config.include_header and config.write_header_hook:
                    header = config.write_header_hook()
                    if header:
                        parts.append(header)
                stats = FlextLdifUtilitiesWriters.Content.Stats(
                    total_entries=len(config.entries)
                )
                entries_typed: list[FlextLdifModelsDomains.Entry] = list(config.entries)
                for entry in entries_typed:
                    result = (
                        FlextLdifUtilitiesWriters.Content.write_single_entry_with_stats(
                            entry, config.write_entry_hook, stats
                        )
                    )
                    if result is not None:
                        parts.append(result)
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
                    "Failed to write content", server_type=config.server_type
                )
                return r[str].fail(f"Failed to write content: {e}")

        @staticmethod
        def write_single_entry_with_stats(
            entry: FlextLdifModelsDomains.Entry,
            write_entry_hook: Callable[[FlextLdifModelsDomains.Entry], r[str]],
            stats: FlextLdifUtilitiesWriters.Content.Stats,
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
                dn=dn_str or "",
                error=str(result.error),
            )
            return None
