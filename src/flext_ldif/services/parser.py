"""Parser service for LDIF content."""

from __future__ import annotations

from pathlib import Path

from flext_ldif import m, r, s


class FlextLdifParser(s):
    """LDIF parser orchestrator over the server server registry."""

    def parse_ldif(
        self,
        value: str | Path,
        *,
        server_type: str | None = None,
    ) -> r[m.Ldif.ParseResponse]:
        """Parse LDIF content from string or file."""
        effective_type = server_type or self._get_effective_server_type_value()
        if isinstance(value, Path):
            return self.parse_ldif_file(value, server_type=effective_type)
        return self.parse_string(value, server_type=effective_type)

    def parse_ldif_file(
        self,
        path: Path,
        server_type: str | None = None,
        encoding: str = "utf-8",
    ) -> r[m.Ldif.ParseResponse]:
        """Parse LDIF content from a file path with optional encoding override."""
        resolved_path = path
        if not resolved_path.exists() and not resolved_path.is_absolute():
            project_root = Path(__file__).resolve().parents[2]
            candidate_path = project_root / resolved_path
            if candidate_path.exists():
                resolved_path = candidate_path
        if not resolved_path.exists():
            return r[m.Ldif.ParseResponse].fail_op(
                "resolve ldif path",
                f"File not found: {path}",
            )
        try:
            content = resolved_path.read_text(encoding=encoding)
        except (OSError, UnicodeDecodeError) as error:
            return r[m.Ldif.ParseResponse].fail_op("read ldif file", error)
        return self.parse_string(content, server_type=server_type)

    def parse_string(
        self,
        content: str,
        server_type: str | None = None,
    ) -> r[m.Ldif.ParseResponse]:
        """Parse LDIF content from a string through the selected base server."""
        effective_server_type = server_type or self._get_effective_server_type_value()
        return r[m.Ldif.ParseResponse].from_result(
            self._server
            .server(effective_server_type)
            .map_error(
                lambda error: error or "Failed to resolve LDIF server server",
            )
            .flat_map(lambda server: server.parse_ldif(content))
            .map_error(lambda error: error or "LDIF parsing failed"),
        )


__all__: list[str] = ["FlextLdifParser"]
