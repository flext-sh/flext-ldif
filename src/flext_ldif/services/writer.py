"""Writer Service - Direct LDIF Writing with flext-core APIs."""

from __future__ import annotations

from collections.abc import Mapping, MutableSequence
from pathlib import Path

from flext_ldif import (
    FlextLdifConversion,
    FlextLdifServer,
    FlextLdifSettings,
    m,
    r,
    t,
    u,
)


class FlextLdifWriter:
    """Writer service methods for LDIF facade and standalone usage.

    Expects ``self._server: FlextLdifServer`` to be provided by the
    instantiated class (either FlextLdifWriter or FlextLdif).
    """

    _server: FlextLdifServer = FlextLdifServer.get_global_instance()

    def __init__(
        self,
        *,
        server: FlextLdifServer | None = None,
        settings: FlextLdifSettings | None = None,
    ) -> None:
        """Initialize writer with optional explicit server registry."""
        _ = settings
        self._server = server or FlextLdifServer.get_global_instance()

    @staticmethod
    def _normalize_format_options(
        format_options: m.Ldif.WriteFormatOptions
        | m.Ldif.WriteOptions
        | t.RecursiveContainer
        | None,
    ) -> m.Ldif.WriteFormatOptions:
        """Normalize format options to WriteFormatOptions."""
        result_raw: m.Ldif.WriteFormatOptions | None
        if format_options is None:
            result_raw = m.Ldif.WriteFormatOptions()
        elif isinstance(format_options, m.Ldif.WriteFormatOptions):
            result_raw = format_options
        elif isinstance(format_options, m.Ldif.WriteOptions):
            dumped = format_options.model_dump(exclude_none=True)
            mapped: t.MutableRecursiveContainerMapping = {
                "base64_encode_binary": dumped.get("base64_encode_binary"),
                "sort_attributes": dumped.get("sort_entries"),
                "include_dn_comments": dumped.get("include_comments"),
            }
            normalized = {
                key: value for key, value in mapped.items() if value is not None
            }
            result_raw = m.Ldif.WriteFormatOptions.model_validate(normalized)
        elif not isinstance(format_options, Mapping):
            result_raw = m.Ldif.WriteFormatOptions()
        else:
            result_raw = m.Ldif.WriteFormatOptions.model_validate(
                dict(format_options),
            )
        return m.Ldif.WriteFormatOptions.model_validate(result_raw)

    def write(
        self,
        entries: MutableSequence[m.Ldif.Entry] | m.Ldif.ParseResponse,
        *,
        server_type: str | None = None,
        format_options: m.Ldif.WriteFormatOptions | m.Ldif.WriteOptions | None = None,
    ) -> r[m.Ldif.WriteResponse]:
        """Write entries to LDIF format string with statistics."""
        effective_type = server_type or self._get_effective_server_type_value()
        server_type_typed: str = str(effective_type)
        normalized_entries = self._normalize_entries(entries)
        string_result = self.write_to_string(
            normalized_entries,
            server_type_typed,
            format_options,
        )
        if string_result.failure:
            return r[m.Ldif.WriteResponse].fail(
                string_result.error or "LDIF writing failed",
            )
        return r[m.Ldif.WriteResponse].ok(
            m.Ldif.WriteResponse(
                content=string_result.value,
                statistics=m.Ldif.Statistics(
                    total_entries=u.count(normalized_entries),
                    processed_entries=u.count(normalized_entries),
                ),
            ),
        )

    def write_ldif_file(
        self,
        entries: MutableSequence[m.Ldif.Entry] | m.Ldif.ParseResponse,
        path: Path,
        *,
        server_type: str | None = None,
        format_options: m.Ldif.WriteFormatOptions | m.Ldif.WriteOptions | None = None,
    ) -> r[m.Ldif.WriteResponse]:
        """Write entries to LDIF file with statistics."""
        return self.write_to_file(
            entries,
            path,
            server_type,
            format_options,
        )

    def write_to_file(
        self,
        entries: MutableSequence[m.Ldif.Entry] | m.Ldif.ParseResponse,
        path: Path,
        server_type: str | None = None,
        format_options: m.Ldif.WriteFormatOptions | m.Ldif.WriteOptions | None = None,
    ) -> r[m.Ldif.WriteResponse]:
        """Write entries to LDIF file with WriteResponse."""
        normalized_entries = self._normalize_entries(entries)
        string_result = self.write_to_string(
            normalized_entries,
            server_type,
            format_options,
        )
        if string_result.failure:
            return r[m.Ldif.WriteResponse].fail(
                string_result.error or "Failed to generate LDIF content",
            )
        ldif_content = string_result.value
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            return r[m.Ldif.WriteResponse].fail(
                f"Failed to create parent directories for {path}: {e}",
            )
        try:
            _ = path.write_text(ldif_content, encoding="utf-8")
        except (OSError, UnicodeEncodeError) as e:
            return r[m.Ldif.WriteResponse].fail(
                f"Failed to write LDIF file {path}: {e}",
            )
        response = m.Ldif.WriteResponse(
            content=ldif_content,
            output_path=str(path),
            statistics=m.Ldif.Statistics(
                total_entries=u.count(normalized_entries),
                processed_entries=u.count(normalized_entries),
            ),
        )
        return r[m.Ldif.WriteResponse].ok(response)

    def write_to_string(
        self,
        entries: MutableSequence[m.Ldif.Entry] | m.Ldif.ParseResponse,
        server_type: str | None = None,
        format_options: m.Ldif.WriteFormatOptions | m.Ldif.WriteOptions | None = None,
    ) -> r[str]:
        """Write entries to LDIF string format."""
        effective_server_type = server_type or "rfc"
        normalized_entries = self._normalize_entries(entries)
        try:
            entry_quirk = self._server.entry(effective_server_type)
        except ValueError as e:
            return r[str].fail(
                f"Invalid server type: {effective_server_type}. {e!s}",
            )
        if entry_quirk is None:
            return r[str].fail(
                f"No entry quirk found for server type: {effective_server_type}",
            )
        options = self._normalize_format_options(format_options)
        return (
            self
            ._prepare_entries_for_target_write(
                normalized_entries,
                effective_server_type,
            )
            .map_error(
                lambda error: error or "LDIF entry preparation failed",
            )
            .flat_map(
                lambda prepared_entries: entry_quirk.write(prepared_entries, options),
            )
            .map_error(
                lambda error: error or "LDIF writing failed",
            )
        )

    @staticmethod
    def _normalize_entries(
        entries: MutableSequence[m.Ldif.Entry] | m.Ldif.ParseResponse,
    ) -> MutableSequence[m.Ldif.Entry]:
        """Accept rich parse responses while keeping entry writing canonical."""
        if isinstance(entries, m.Ldif.ParseResponse):
            return entries.entries
        return entries

    def _get_effective_server_type_value(self) -> str:
        """Resolve effective server type (default: rfc, overridden by DetectorMixin)."""
        return "rfc"

    def _prepare_entries_for_target_write(
        self,
        entries: MutableSequence[m.Ldif.Entry],
        target_server_type: str,
    ) -> r[MutableSequence[m.Ldif.Entry]]:
        """Convert entries to target semantics when caller requests cross-server write."""
        normalized_target = u.Ldif.normalize_server_type(target_server_type)
        conversion_service = FlextLdifConversion()
        prepared_entries: MutableSequence[m.Ldif.Entry] = []
        for entry in entries:
            metadata = entry.metadata
            if metadata is None:
                prepared_entries.append(entry)
                continue
            current_server_raw = (
                metadata.target_server_type
                or metadata.original_server_type
                or metadata.quirk_type
            )
            current_server_text = str(current_server_raw)

            def normalize_current_server(
                current_server_text: str = current_server_text,
            ) -> str:
                return u.Ldif.normalize_server_type(current_server_text)

            normalized_current = u.try_(
                normalize_current_server,
                default=None,
            ).map_or(None)
            if normalized_current is None or normalized_current == normalized_target:
                prepared_entries.append(entry)
                continue
            conversion_result = conversion_service.convert_entry(
                normalized_current,
                normalized_target,
                entry,
            )
            if conversion_result.failure:
                return r[MutableSequence[m.Ldif.Entry]].fail(
                    conversion_result.error or "Entry conversion failed before write",
                )
            converted_entry = conversion_result.value
            if not isinstance(converted_entry, m.Ldif.Entry):
                return r[MutableSequence[m.Ldif.Entry]].fail(
                    f"Expected converted Entry, got {type(converted_entry).__name__}",
                )
            prepared_entries.append(converted_entry)
        return r[MutableSequence[m.Ldif.Entry]].ok(prepared_entries)


__all__: list[str] = ["FlextLdifWriter"]
