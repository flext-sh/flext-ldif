"""Writer Service - Direct LDIF Writing with flext-core APIs."""

from __future__ import annotations

from pathlib import Path

from flext_core import r
from flext_core.runtime import FlextRuntime

from flext_ldif.base import s
from flext_ldif.models import m
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.typings import t
from flext_ldif.utilities import u


def _extract_pipe_value(
    pipe_result: r[t.GeneralValueType] | FlextRuntime.RuntimeResult[t.GeneralValueType],
) -> t.GeneralValueType | None:
    """Extract value from pipe result."""
    return pipe_result.unwrap_or(None)


def _extract_write_options(
    write_options: m.Ldif.LdifResults.WriteOptions,
) -> m.Ldif.LdifResults.WriteFormatOptions | None:
    """Extract write format options from WriteOptions model."""
    dumped = write_options.model_dump(exclude_none=True)
    normalized = _normalize_write_format(dumped)
    return m.Ldif.LdifResults.WriteFormatOptions.model_validate(normalized)


def _normalize_write_format(d: t.GeneralValueType) -> dict[str, t.GeneralValueType]:
    """Normalize write format from dict."""
    if not isinstance(d, dict):
        return {}
    return (
        {
            "base64_encode_binary": (
                d.get("base64_encode_binary") if isinstance(d, dict) else None
            ),
        }
        if isinstance(d, dict) and d.get("base64_encode_binary") is not None
        else {}
    )


class FlextLdifWriter(s[m.Ldif.LdifResults.WriteResponse]):
    """Direct LDIF writing service using flext-core APIs."""

    _server: FlextLdifServer

    def __init__(self, server: FlextLdifServer | None = None) -> None:
        """Initialize writer with optional server instance."""
        super().__init__()

        object.__setattr__(
            self,
            "_server",
            server if server is not None else FlextLdifServer(),
        )

    @staticmethod
    def _normalize_format_options(
        format_options: (
            m.Ldif.LdifResults.WriteFormatOptions
            | m.Ldif.LdifResults.WriteOptions
            | type
            | dict[str, t.GeneralValueType]
            | None
        ),
    ) -> m.Ldif.LdifResults.WriteFormatOptions:
        """Normalize format options to WriteFormatOptions."""
        if format_options is None:
            result_raw = m.Ldif.LdifResults.WriteFormatOptions()
        elif isinstance(format_options, type):
            result_raw = format_options()
        elif isinstance(format_options, m.Ldif.LdifResults.WriteFormatOptions):
            result_raw = format_options
        elif isinstance(format_options, m.Ldif.LdifResults.WriteOptions):
            extracted = _extract_write_options(format_options)
            if extracted is None:
                msg = f"Failed to extract write options from {type(format_options)}"
                raise TypeError(msg)
            result_raw = extracted
        elif isinstance(format_options, dict):
            result_raw = m.Ldif.LdifResults.WriteFormatOptions.model_validate(
                format_options
            )
        else:
            result_raw = None
        if result_raw is None:
            msg = f"Expected WriteFormatOptions | WriteOptions | dict | None, got {type(format_options)}"
            raise TypeError(msg)

        if isinstance(result_raw, m.Ldif.LdifResults.WriteFormatOptions):
            return result_raw

        msg = f"Unexpected type in match result: {type(result_raw)}"
        raise TypeError(msg)

    def write_to_string(
        self,
        entries: list[m.Ldif.Entry],
        server_type: str | None = None,
        format_options: (
            m.Ldif.LdifResults.WriteFormatOptions
            | m.Ldif.LdifResults.WriteOptions
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
            m.Ldif.LdifResults.WriteFormatOptions
            | m.Ldif.LdifResults.WriteOptions
            | None
        ) = None,
    ) -> r[m.Ldif.LdifResults.WriteResponse]:
        """Write entries to LDIF file."""
        string_result = self.write_to_string(entries, server_type, format_options)
        if string_result.is_failure:
            return r[m.Ldif.LdifResults.WriteResponse].fail(
                string_result.error or "Failed to generate LDIF content",
            )

        ldif_content = string_result.value

        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            return r[m.Ldif.LdifResults.WriteResponse].fail(
                f"Failed to create parent directories for {path}: {e}",
            )

        try:
            path.write_text(ldif_content, encoding="utf-8")
        except (OSError, UnicodeEncodeError) as e:
            return r[m.Ldif.LdifResults.WriteResponse].fail(
                f"Failed to write LDIF file {path}: {e}",
            )

        response = m.Ldif.LdifResults.WriteResponse(
            content=ldif_content,
            statistics=m.Ldif.LdifResults.Statistics(
                total_entries=u.count(entries),
                processed_entries=u.count(entries),
            ),
        )

        return r[str].ok(response)

    def write(
        self,
        entries: list[m.Ldif.Entry],
        target_server_type: str | None = None,
        _output_target: str | None = None,
        output_path: Path | None = None,
        format_options: (
            m.Ldif.LdifResults.WriteFormatOptions
            | m.Ldif.LdifResults.WriteOptions
            | None
        ) = None,
        _template_data: dict[str, t.Ldif.TemplateValue] | None = None,
    ) -> r[str | m.Ldif.LdifResults.WriteResponse]:
        """Write entries to LDIF format (string or file)."""
        if output_path is not None:
            file_result = self.write_to_file(
                entries,
                output_path,
                target_server_type,
                format_options,
            )
            if file_result.is_failure:
                return r[str | m.Ldif.LdifResults.WriteResponse].fail(
                    file_result.error or "File write failed",
                )
            return r[str | m.Ldif.LdifResults.WriteResponse].ok(file_result.value)

        string_result = self.write_to_string(
            entries,
            target_server_type,
            format_options,
        )
        if string_result.is_failure:
            return r[str | m.Ldif.LdifResults.WriteResponse].fail(
                string_result.error or "String write failed",
            )
        return r[str | m.Ldif.LdifResults.WriteResponse].ok(string_result.value)

    def execute(
        self,
        params: dict[str, t.GeneralValueType] | None = None,
    ) -> r[m.Ldif.LdifResults.WriteResponse]:
        """Execute write operation with parameters."""
        params = params or {}
        entries_raw = u.take(params, "entries", as_type=list, default=[])

        entries: list[m.Ldif.Entry] = (
            [entry for entry in entries_raw if isinstance(entry, m.Ldif.Entry)]
            if isinstance(entries_raw, list)
            else []
        )
        target_server_type_raw = u.take(
            params,
            "target_server_type",
            as_type=str,
            default="rfc",
        )

        target_server_type: str | None = None
        if isinstance(target_server_type_raw, str):
            try:
                target_server_type = u.Ldif.Server.normalize_server_type(
                    target_server_type_raw,
                )
            except ValueError:
                target_server_type = None
        output_path_raw = u.take(params, "output_path", as_type=Path)

        output_path: Path | None = (
            output_path_raw if isinstance(output_path_raw, Path) else None
        )
        format_options_raw: t.GeneralValueType = u.take(params, "format_options")

        format_options: (
            m.Ldif.LdifResults.WriteFormatOptions
            | m.Ldif.LdifResults.WriteOptions
            | None
        ) = (
            format_options_raw
            if isinstance(
                format_options_raw,
                (
                    m.Ldif.LdifResults.WriteFormatOptions,
                    m.Ldif.LdifResults.WriteOptions,
                ),
            )
            else None
        )

        write_result = self.write(
            entries=entries,
            target_server_type=target_server_type,
            output_path=output_path,
            format_options=format_options,
        )

        if write_result.is_failure:
            return r[m.Ldif.LdifResults.WriteResponse].fail(write_result.error)

        result_value = write_result.value
        if isinstance(result_value, m.Ldif.LdifResults.WriteResponse):
            return r[m.Ldif.LdifResults.WriteResponse].ok(result_value)

        return r[m.Ldif.LdifResults.WriteResponse].ok(
            m.Ldif.LdifResults.WriteResponse(
                content=str(result_value),
                statistics=m.Ldif.LdifResults.Statistics(
                    total_entries=len(entries),
                    processed_entries=len(entries),
                ),
            ),
        )


__all__ = ["FlextLdifWriter"]
