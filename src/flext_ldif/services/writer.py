"""Writer Service - Direct LDIF Writing with flext-core APIs."""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import override

from flext_core import FlextRuntime, r

from flext_ldif.base import s
from flext_ldif.models import m
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.typings import t
from flext_ldif.utilities import u


class FlextLdifWriter(s[m.Ldif.Results.WriteResponse]):
    """Direct LDIF writing service using flext-core APIs."""

    _server: FlextLdifServer

    @staticmethod
    def _extract_pipe_value(
        pipe_result: r[t.GeneralValueType]
        | FlextRuntime.RuntimeResult[t.GeneralValueType],
    ) -> t.GeneralValueType | None:
        return pipe_result.unwrap_or(None)

        write_options: m.Ldif.WriteOptions,
    ) -> m.Ldif.WriteFormatOptions:
        dumped = write_options.model_dump(exclude_none=True)
        normalized = FlextLdifWriter._normalize_write_format(dumped)
        return m.Ldif.WriteFormatOptions.model_validate(normalized)

    def _normalize_write_format(
        d: Mapping[str, t.GeneralValueType],
    ) -> Mapping[str, t.GeneralValueType]:
        mapped: dict[str, t.GeneralValueType] = {
            "base64_encode_binary": d.get("base64_encode_binary"),
            "sort_attributes": d.get("sort_entries"),
            "include_dn_comments": d.get("include_comments"),
        }
        return {key: value for key, value in mapped.items() if value is not None}

    def __init__(self, server: FlextLdifServer | None = None) -> None:
        """Initialize writer with optional server instance."""
        super().__init__()

        object.__setattr__(
            self,
            "_server",
            (server if server is not None else FlextLdifServer.get_global_instance()),
        )

    @staticmethod
    def _normalize_format_options(
        format_options: (
            m.Ldif.WriteFormatOptions
            | m.Ldif.WriteOptions
            | Mapping[str, t.GeneralValueType]
            | None
        ),
    ) -> m.Ldif.WriteFormatOptions:
        """Normalize format options to WriteFormatOptions."""
        result_raw: m.Ldif.WriteFormatOptions | None
        if format_options is None:
            result_raw = m.Ldif.WriteFormatOptions()
        elif isinstance(format_options, m.Ldif.WriteFormatOptions):
            format_opts: m.Ldif.WriteFormatOptions = format_options
            result_raw = m.Ldif.WriteFormatOptions.model_validate(
                format_opts
            )
        #PP|        elif isinstance(format_options, m.Ldif.WriteOptions):
#ZN|            result_raw = m.Ldif.WriteFormatOptions.model_validate(
#QX|                format_options.model_dump(exclude_none=True)
#RK|            )
            write_options = m.Ldif.WriteOptions.model_validate(
                format_options
            )
            result_raw = FlextLdifWriter._extract_write_options(write_options)
        else:
            result_raw = m.Ldif.WriteFormatOptions.model_validate(
                dict(format_options)
            )
        return m.Ldif.WriteFormatOptions.model_validate(result_raw)

    def write_to_string(
        self,
        entries: list[m.Ldif.Entry],
        server_type: str | None = None,
        format_options: (
            m.Ldif.WriteFormatOptions
            | m.Ldif.WriteOptions
            | None
        ) = None,
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

        write_result = entry_quirk.write(entries, options)

        if write_result.is_failure:
            return r[str].fail(write_result.error or "LDIF writing failed")

        return r[str].ok(write_result.value)

    def write_to_file(
        self,
        entries: list[m.Ldif.Entry],
        path: Path,
        server_type: str | None = None,
        format_options: (
            m.Ldif.WriteFormatOptions
            | m.Ldif.WriteOptions
            | None
        ) = None,
    ) -> r[m.Ldif.Results.WriteResponse]:
        """Write entries to LDIF file."""
        string_result = self.write_to_string(entries, server_type, format_options)
        if string_result.is_failure:
            return r[m.Ldif.Results.WriteResponse].fail(
                string_result.error or "Failed to generate LDIF content",
            )

        ldif_content = string_result.value

        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            return r[m.Ldif.Results.WriteResponse].fail(
                f"Failed to create parent directories for {path}: {e}",
            )

        try:
            _ = path.write_text(ldif_content, encoding="utf-8")
        except (OSError, UnicodeEncodeError) as e:
            return r[m.Ldif.Results.WriteResponse].fail(
                f"Failed to write LDIF file {path}: {e}",
            )

        response = m.Ldif.Results.WriteResponse(
            content=ldif_content,
            statistics=m.Ldif.Results.Statistics(
                total_entries=u.count(entries),
                processed_entries=u.count(entries),
            ),
        )

        return r[m.Ldif.Results.WriteResponse].ok(response)

    def write(
        self,
        entries: list[m.Ldif.Entry],
        target_server_type: str | None = None,
        _output_target: str | None = None,
        output_path: Path | None = None,
        format_options: (
            m.Ldif.WriteFormatOptions
            | m.Ldif.WriteOptions
            | None
        ) = None,
        _template_data: Mapping[str, t.Ldif.TemplateValue] | None = None,
    ) -> r[str | m.Ldif.Results.WriteResponse]:
        """Write entries to LDIF format (string or file)."""
        if output_path is not None:
            file_result = self.write_to_file(
                entries,
                output_path,
                target_server_type,
                format_options,
            )
            if file_result.is_failure:
                return r[str | m.Ldif.Results.WriteResponse].fail(
                    file_result.error or "File write failed",
                )
            return r[str | m.Ldif.Results.WriteResponse].ok(file_result.value)

        string_result = self.write_to_string(
            entries,
            target_server_type,
            format_options,
        )
        if string_result.is_failure:
            return r[str | m.Ldif.Results.WriteResponse].fail(
                string_result.error or "String write failed",
            )
        return r[str | m.Ldif.Results.WriteResponse].ok(string_result.value)

    @override
    def execute(
        self,
        params: Mapping[str, t.GeneralValueType] | None = None,
    ) -> r[m.Ldif.Results.WriteResponse]:
        """Execute write operation with parameters."""
        params = params or {}
        entries_raw = u.take(params, "entries", as_type=list, default=[])
        entries: list[m.Ldif.Entry] = []
        entry_candidates: tuple[object, ...] = ()
        with suppress(Exception):
            entry_candidates = tuple(t.ObjectList.model_validate(entries_raw).root)
        for entry_candidate in entry_candidates:
            validated_entry: m.Ldif.Entry | None = None
            with suppress(Exception):
                validated_entry = m.Ldif.Entry.model_validate(entry_candidate)
            if validated_entry is not None:
                entries.append(validated_entry)
        target_server_type_raw = u.take(
            params,
            "target_server_type",
            as_type=str,
            default="rfc",
        )

        target_server_type: str | None = None
        try:
            target_server_type = u.Ldif.Server.normalize_server_type(
                str(target_server_type_raw),
            )
        except ValueError:
            target_server_type = None
        output_path_raw = u.take(params, "output_path", as_type=Path)

        output_path: Path | None = None
        if output_path_raw is not None:
            try:
                output_path = Path(str(output_path_raw))
            except (TypeError, ValueError):
                output_path = None
        format_options_raw = u.take(params, "format_options")

        format_options: (
            m.Ldif.WriteFormatOptions
            | m.Ldif.WriteOptions
            | None
        ) = None
        if format_options_raw is not None:
            validated_format_options: m.Ldif.WriteFormatOptions | None = (
                None
            )
            with suppress(Exception):
                validated_format_options = (
                    m.Ldif.WriteFormatOptions.model_validate(
                        format_options_raw,
                    )
                )
            if validated_format_options is not None:
                format_options = validated_format_options
            else:
                validated_write_options: m.Ldif.WriteOptions | None = None
                with suppress(Exception):
                    validated_write_options = (
                        m.Ldif.WriteOptions.model_validate(
                            format_options_raw,
                        )
                    )
                format_options = validated_write_options

        write_result = self.write(
            entries=entries,
            target_server_type=target_server_type,
            output_path=output_path,
            format_options=format_options,
        )

        if write_result.is_failure:
            return r[m.Ldif.Results.WriteResponse].fail(write_result.error)

        result_value = write_result.value
        with suppress(Exception):
            result_response = m.Ldif.Results.WriteResponse.model_validate(
                result_value
            )
            return r[m.Ldif.Results.WriteResponse].ok(result_response)

        return r[m.Ldif.Results.WriteResponse].ok(
            m.Ldif.Results.WriteResponse(
                content=str(result_value),
                statistics=m.Ldif.Results.Statistics(
                    total_entries=len(entries),
                    processed_entries=len(entries),
                ),
            ),
        )


__all__ = ["FlextLdifWriter"]
