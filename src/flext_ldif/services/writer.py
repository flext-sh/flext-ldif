"""Writer service for LDIF output orchestration."""

from __future__ import annotations

from pathlib import Path

from flext_ldif import (
    m,
    p,
    r,
    s,
    t,
    u,
)


class FlextLdifWriter(s):
    """LDIF writer orchestrator over the server server registry."""

    @staticmethod
    def _coerce_entries(
        entries: t.MutableSequenceOf[m.Ldif.Entry] | m.Ldif.ParseResponse,
    ) -> t.MutableSequenceOf[m.Ldif.Entry]:
        """Keep write inputs on canonical Entry models."""
        if isinstance(entries, m.Ldif.ParseResponse):
            return entries.entries
        as_entries: t.MutableSequenceOf[m.Ldif.Entry] = u.Ldif.as_entries(entries)
        return as_entries

    def write(
        self,
        entries: t.MutableSequenceOf[m.Ldif.Entry] | m.Ldif.ParseResponse,
        *,
        server_type: str | None = None,
        format_options: p.Ldif.WriteFormatOptions | None = None,
    ) -> p.Result[m.Ldif.WriteResponse]:
        """Write entries to LDIF text and return canonical write metadata."""
        normalized_entries = self._coerce_entries(entries)
        string_result = self.write_to_string(
            normalized_entries,
            server_type=server_type,
            format_options=format_options,
        )
        if string_result.failure:
            return r[m.Ldif.WriteResponse].fail_op(
                "write ldif entries",
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
        entries: t.MutableSequenceOf[m.Ldif.Entry] | m.Ldif.ParseResponse,
        path: Path,
        *,
        server_type: str | None = None,
        format_options: p.Ldif.WriteFormatOptions | None = None,
    ) -> p.Result[m.Ldif.WriteResponse]:
        """Write entries to an LDIF file and return canonical write metadata."""
        normalized_entries = self._coerce_entries(entries)
        string_result = self.write_to_string(
            normalized_entries,
            server_type=server_type,
            format_options=format_options,
        )
        if string_result.failure:
            return r[m.Ldif.WriteResponse].fail_op(
                "write ldif file",
                string_result.error or "Failed to generate LDIF content",
            )
        ldif_content = string_result.value
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            return r[m.Ldif.WriteResponse].fail_op(
                "prepare ldif output path",
                f"Failed to create parent directories for {path}: {error}",
            )
        try:
            _ = path.write_text(ldif_content, encoding="utf-8")
        except (OSError, UnicodeEncodeError) as error:
            return r[m.Ldif.WriteResponse].fail_op(
                "persist ldif output",
                f"Failed to write LDIF file {path}: {error}",
            )
        return r[m.Ldif.WriteResponse].ok(
            m.Ldif.WriteResponse(
                content=ldif_content,
                output_path=str(path),
                statistics=m.Ldif.Statistics(
                    total_entries=u.count(normalized_entries),
                    processed_entries=u.count(normalized_entries),
                ),
            ),
        )

    def write_to_string(
        self,
        entries: t.MutableSequenceOf[m.Ldif.Entry] | m.Ldif.ParseResponse,
        server_type: str | None = None,
        format_options: p.Ldif.WriteFormatOptions | None = None,
    ) -> p.Result[str]:
        """Write entries to LDIF text through the selected base server."""
        normalized_entries = self._coerce_entries(entries)
        effective_server_type = server_type or self._get_effective_server_type_value()
        concrete_options = (
            format_options
            if format_options is None
            or isinstance(format_options, m.Ldif.WriteFormatOptions)
            else m.Ldif.WriteFormatOptions.model_validate(format_options)
        )
        write_result = (
            self._server
            .server(effective_server_type)
            .map_error(
                lambda error: error or "Failed to resolve LDIF server server",
            )
            .flat_map(lambda server: server.write(normalized_entries, concrete_options))
            .map_error(lambda error: error or "LDIF writing failed")
        )
        return r[str].from_result(write_result)


__all__: list[str] = ["FlextLdifWriter"]
