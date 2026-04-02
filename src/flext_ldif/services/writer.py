"""Writer Service - Direct LDIF Writing with flext-core APIs."""

from __future__ import annotations

from collections.abc import Mapping, MutableSequence, Sequence
from contextlib import suppress
from pathlib import Path
from typing import override

from flext_ldif import FlextLdifServer, m, r, s, t, u


class FlextLdifWriterMixin:
    """Writer methods for MRO composition on FlextLdif.

    Expects ``self._server: FlextLdifServer`` to be provided by the
    instantiated class (either FlextLdifWriter or FlextLdif).
    """

    _server: FlextLdifServer

    @staticmethod
    def _normalize_format_options(
        format_options: m.Ldif.WriteFormatOptions
        | m.Ldif.WriteOptions
        | t.NormalizedValue
        | None,
    ) -> m.Ldif.WriteFormatOptions:
        """Normalize format options to WriteFormatOptions."""
        result_raw: m.Ldif.WriteFormatOptions | None
        if format_options is None:
            result_raw = m.Ldif.WriteFormatOptions()
        elif isinstance(format_options, m.Ldif.WriteFormatOptions):
            result_raw = format_options
        elif isinstance(format_options, m.Ldif.WriteOptions):
            result_raw = FlextLdifWriterMixin._to_format_options(format_options)
        elif not isinstance(format_options, Mapping):
            result_raw = m.Ldif.WriteFormatOptions()
        else:
            result_raw = m.Ldif.WriteFormatOptions.model_validate(
                dict(format_options),
            )
        return m.Ldif.WriteFormatOptions.model_validate(result_raw)

    @staticmethod
    def _normalize_write_format(
        d: t.MutableContainerMapping,
    ) -> t.MutableContainerMapping:
        mapped: t.MutableContainerMapping = {
            "base64_encode_binary": d.get("base64_encode_binary"),
            "sort_attributes": d.get("sort_entries"),
            "include_dn_comments": d.get("include_comments"),
        }
        return {key: value for key, value in mapped.items() if value is not None}

    @staticmethod
    def _to_format_options(
        write_options: m.Ldif.WriteOptions,
    ) -> m.Ldif.WriteFormatOptions:
        dumped = write_options.model_dump(exclude_none=True)
        normalized = FlextLdifWriterMixin._normalize_write_format(dumped)
        return m.Ldif.WriteFormatOptions.model_validate(normalized)

    def write(
        self,
        entries: MutableSequence[m.Ldif.Entry],
        *,
        server_type: str | None = None,
        format_options: m.Ldif.WriteFormatOptions | m.Ldif.WriteOptions | None = None,
    ) -> r[str]:
        """Write entries to LDIF format string."""
        effective_type = server_type or self._get_effective_server_type_value()
        server_type_typed: str = str(effective_type)
        return self.write_to_string(
            entries,
            server_type_typed,
            format_options,
        )

    def write_ldif_file(
        self,
        entries: MutableSequence[m.Ldif.Entry],
        path: Path,
        *,
        server_type: str | None = None,
        format_options: m.Ldif.WriteFormatOptions | m.Ldif.WriteOptions | None = None,
    ) -> r[bool]:
        """Write entries to LDIF file."""
        write_result = self.write(
            entries,
            server_type=server_type,
            format_options=format_options,
        )
        if write_result.is_failure:
            return r[bool].fail(str(write_result.error))
        content = write_result.value
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            _ = path.write_text(content, encoding="utf-8")
            return r[bool].ok(value=True)
        except OSError as e:
            return r[bool].fail(f"Failed to write file: {e}")

    def write_to_file(
        self,
        entries: MutableSequence[m.Ldif.Entry],
        path: Path,
        server_type: str | None = None,
        format_options: m.Ldif.WriteFormatOptions | m.Ldif.WriteOptions | None = None,
    ) -> r[m.Ldif.WriteResponse]:
        """Write entries to LDIF file with WriteResponse."""
        string_result = self.write_to_string(entries, server_type, format_options)
        if string_result.is_failure:
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
            statistics=m.Ldif.Statistics(
                total_entries=u.count(entries),
                processed_entries=u.count(entries),
            ),
        )
        return r[m.Ldif.WriteResponse].ok(response)

    def write_to_string(
        self,
        entries: MutableSequence[m.Ldif.Entry],
        server_type: str | None = None,
        format_options: m.Ldif.WriteFormatOptions | m.Ldif.WriteOptions | None = None,
    ) -> r[str]:
        """Write entries to LDIF string format."""
        effective_server_type = server_type or "rfc"
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
        return entry_quirk.write(entries, options).fold(
            on_failure=lambda e: r[str].fail(e or "LDIF writing failed"),
            on_success=lambda v: r[str].ok(v),
        )

    def _get_effective_server_type_value(self) -> str:
        """Resolve effective server type (default: rfc, overridden by DetectorMixin)."""
        return "rfc"


class FlextLdifWriter(FlextLdifWriterMixin, s[m.Ldif.WriteResponse]):
    """Standalone writer service (also usable outside FlextLdif MRO)."""

    _server: FlextLdifServer

    def __init__(self, server: FlextLdifServer | None = None) -> None:
        """Initialize writer with optional server instance."""
        super().__init__()
        object.__setattr__(
            self,
            "_server",
            server if server is not None else FlextLdifServer.get_global_instance(),
        )

    @override
    def execute(
        self,
        params: t.ValueOrModel | None = None,
    ) -> r[m.Ldif.WriteResponse]:
        """Execute write operation with parameters."""
        params_mapping: t.MutableContainerMapping = {}
        if isinstance(params, Mapping):
            params_mapping = {str(k): v for k, v in params.items()}
        params_data = params_mapping
        entries_raw = u.take(params_data, "entries")
        entries: MutableSequence[m.Ldif.Entry] = []
        entry_candidates: tuple[t.NormalizedValue, ...] = ()
        with suppress(Exception):
            if isinstance(entries_raw, Sequence) and not isinstance(
                entries_raw,
                str | bytes,
            ):
                entry_candidates = tuple(entries_raw)
        for entry_candidate in entry_candidates:
            validated_entry: m.Ldif.Entry | None = None
            with suppress(Exception):
                validated_entry = m.Ldif.Entry.model_validate(entry_candidate)
            if validated_entry is not None:
                entries.append(validated_entry)
        target_server_type_raw = u.take(
            params_data,
            "target_server_type",
            as_type=str,
            default="rfc",
        )
        target_server_type: str | None = None
        try:
            target_server_type = u.Ldif.normalize_server_type(
                str(target_server_type_raw),
            )
        except ValueError:
            target_server_type = None
        output_path_raw = u.take(params_data, "output_path", as_type=Path)
        output_path: Path | None = None
        if output_path_raw is not None:
            try:
                output_path = Path(str(output_path_raw))
            except (TypeError, ValueError):
                output_path = None
        format_options_raw = u.take(params_data, "format_options")
        format_options: m.Ldif.WriteFormatOptions | m.Ldif.WriteOptions | None = None
        if format_options_raw is not None:
            validated_format_options: m.Ldif.WriteFormatOptions | None = None
            with suppress(Exception):
                validated_format_options = m.Ldif.WriteFormatOptions.model_validate(
                    format_options_raw,
                )
            if validated_format_options is not None:
                format_options = validated_format_options
            else:
                validated_write_options: m.Ldif.WriteOptions | None = None
                with suppress(Exception):
                    validated_write_options = m.Ldif.WriteOptions.model_validate(
                        format_options_raw,
                    )
                format_options = validated_write_options
        if output_path is not None:
            file_result = self.write_to_file(
                entries,
                output_path,
                target_server_type,
                format_options,
            )
            if file_result.is_failure:
                return r[m.Ldif.WriteResponse].fail(
                    file_result.error or "File write failed",
                )
            return r[m.Ldif.WriteResponse].ok(file_result.value)
        string_result = self.write_to_string(
            entries,
            target_server_type,
            format_options,
        )
        if string_result.is_failure:
            return r[m.Ldif.WriteResponse].fail(
                string_result.error or "String write failed",
            )
        result_value = string_result.value
        with suppress(Exception):
            result_response = m.Ldif.WriteResponse.model_validate(result_value)
            return r[m.Ldif.WriteResponse].ok(result_response)
        return r[m.Ldif.WriteResponse].ok(
            m.Ldif.WriteResponse(
                content=str(result_value),
                statistics=m.Ldif.Statistics(
                    total_entries=len(entries),
                    processed_entries=len(entries),
                ),
            ),
        )


__all__ = ["FlextLdifWriter", "FlextLdifWriterMixin"]
