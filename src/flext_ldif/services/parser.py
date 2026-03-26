"""Parser service for LDIF content."""

from __future__ import annotations

from pathlib import Path
from typing import override

from pydantic import BeforeValidator, PrivateAttr

from flext_ldif import FlextLdifServer, c, m, r, s, u

_ = BeforeValidator


class FlextLdifParser(s[m.Ldif.ParseResponse]):
    """Parse LDIF sources using server-specific entry quirks."""

    _server: FlextLdifServer = PrivateAttr()

    def __init__(self, server: FlextLdifServer | None = None) -> None:
        """Initialize the parser with an optional server registry."""
        super().__init__()
        object.__setattr__(
            self,
            "_server",
            server if server is not None else FlextLdifServer.get_global_instance(),
        )

    @override
    def execute(self) -> r[m.Ldif.ParseResponse]:
        """Guard against invoking the service without input data."""
        return r[m.Ldif.ParseResponse].fail(
            "FlextLdifParser requires input data to parse. Use parse(), parse_string(), or parse_ldif_file() methods.",
        )

    def parse_source(
        self,
        source: str | Path,
        server_type: str | None = None,
    ) -> r[m.Ldif.ParseResponse]:
        """Parse LDIF from either raw text or a filesystem path."""
        if isinstance(source, Path):
            return self.parse_ldif_file(source, server_type)
        return self.parse_string(source, server_type)

    def parse_ldif_file(
        self,
        path: Path,
        server_type: str | None = None,
        encoding: str = "utf-8",
    ) -> r[m.Ldif.ParseResponse]:
        """Parse LDIF content from a file path with optional encoding override."""
        try:
            content = path.read_text(encoding=encoding)
        except (OSError, UnicodeDecodeError) as e:
            return r[m.Ldif.ParseResponse].fail(f"Failed to read LDIF file {path}: {e}")
        return self.parse_string(content, server_type)

    def parse_string(
        self,
        content: str,
        server_type: str | None = None,
    ) -> r[m.Ldif.ParseResponse]:
        """Parse LDIF content from a string using the requested server type."""
        effective_server_type_raw = server_type or "rfc"
        try:
            effective_server_type = u.Ldif.normalize_server_type(
                effective_server_type_raw,
            )
        except (ValueError, TypeError) as e:
            return r[m.Ldif.ParseResponse].fail(
                f"Invalid server type: {effective_server_type_raw} - {e}",
            )
        try:
            entry_quirk_raw = self._server.entry(effective_server_type)
        except ValueError as e:
            return r[m.Ldif.ParseResponse].fail(str(e))
        if entry_quirk_raw is None:
            return r[m.Ldif.ParseResponse].fail(
                f"No entry quirk found for server type: {effective_server_type}",
            )
        if not hasattr(entry_quirk_raw, "parse_quirk"):
            return r[m.Ldif.ParseResponse].fail(
                f"Entry quirk for server type {effective_server_type} does not have parse_quirk method",
            )
        parse_out = entry_quirk_raw.parse_quirk(content)
        if parse_out.is_failure:
            error_msg = parse_out.error or "LDIF parsing failed"
            return r[m.Ldif.ParseResponse].fail(str(error_msg))
        entries = parse_out.value
        detected_server_type = c.Ldif.ServerTypes(effective_server_type)
        response = m.Ldif.ParseResponse(
            entries=entries,
            statistics=m.Ldif.Statistics(total_entries=len(entries), parse_errors=0),
            detected_server_type=detected_server_type,
        )
        return r[m.Ldif.ParseResponse].ok(response)


__all__ = ["FlextLdifParser"]
