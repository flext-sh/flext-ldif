"""Writer service for LDIF output orchestration."""

from __future__ import annotations

from collections.abc import (
    Mapping,
    MutableSequence,
)
from pathlib import Path

from flext_ldif import (
    FlextLdifServer,
    FlextLdifSettings,
    c,
    m,
    r,
    t,
    u,
)


class FlextLdifWriter:
    """LDIF writer orchestrator over the server quirk registry."""

    _server: FlextLdifServer = FlextLdifServer.get_global_instance()

    def __init__(
        self,
        *,
        server: FlextLdifServer | None = None,
        settings: FlextLdifSettings | None = None,
    ) -> None:
        """Initialize writer with optional explicit server registry."""
        _ = settings
        object.__setattr__(
            self,
            "_server",
            server or FlextLdifServer.get_global_instance(),
        )

    @staticmethod
    def _normalize_format_options(
        format_options: m.Ldif.WriteFormatOptions
        | m.Ldif.WriteOptions
        | t.Container
        | None,
    ) -> m.Ldif.WriteFormatOptions:
        """Normalize format options to the canonical write model."""
        if format_options is None:
            return m.Ldif.WriteFormatOptions()
        if isinstance(format_options, m.Ldif.WriteFormatOptions):
            return format_options
        if isinstance(format_options, m.Ldif.WriteOptions):
            dumped = format_options.model_dump(exclude_none=True)
            return m.Ldif.WriteFormatOptions.model_validate({
                "base64_encode_binary": dumped.get("base64_encode_binary"),
                "sort_attributes": dumped.get("sort_entries"),
                "include_dn_comments": dumped.get("include_comments"),
            })
        if isinstance(format_options, Mapping):
            return m.Ldif.WriteFormatOptions.model_validate(dict(format_options))
        return m.Ldif.WriteFormatOptions()

    @staticmethod
    def _coerce_entries(
        entries: MutableSequence[m.Ldif.Entry] | m.Ldif.ParseResponse,
    ) -> MutableSequence[m.Ldif.Entry]:
        """Keep write inputs on canonical Entry models."""
        if isinstance(entries, m.Ldif.ParseResponse):
            return entries.entries
        return u.Ldif.as_entries(entries)

    def write(
        self,
        entries: MutableSequence[m.Ldif.Entry] | m.Ldif.ParseResponse,
        *,
        server_type: str | None = None,
        format_options: m.Ldif.WriteFormatOptions | m.Ldif.WriteOptions | None = None,
    ) -> r[m.Ldif.WriteResponse]:
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
        entries: MutableSequence[m.Ldif.Entry] | m.Ldif.ParseResponse,
        path: Path,
        *,
        server_type: str | None = None,
        format_options: m.Ldif.WriteFormatOptions | m.Ldif.WriteOptions | None = None,
    ) -> r[m.Ldif.WriteResponse]:
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
        entries: MutableSequence[m.Ldif.Entry] | m.Ldif.ParseResponse,
        server_type: str | None = None,
        format_options: m.Ldif.WriteFormatOptions | m.Ldif.WriteOptions | None = None,
    ) -> r[str]:
        """Write entries to LDIF text through the selected base quirk."""
        normalized_entries = self._coerce_entries(entries)
        effective_server_type = server_type or self._get_effective_server_type_value()
        options = self._normalize_format_options(format_options)
        return (
            self._server
            .quirk(str(effective_server_type))
            .map_error(
                lambda error: error or "Failed to resolve LDIF server quirk",
            )
            .flat_map(lambda quirk: quirk.write(normalized_entries, options))
            .map_error(lambda error: error or "LDIF writing failed")
        )

    def _get_effective_server_type_value(self) -> str:
        """Resolve effective server type (default: rfc, overridden by DetectorMixin)."""
        return c.Ldif.ServerTypes.RFC.value


__all__: list[str] = ["FlextLdifWriter"]
