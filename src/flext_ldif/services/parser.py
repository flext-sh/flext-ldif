"""Parser service for LDIF content."""

from __future__ import annotations

from pathlib import Path
from typing import override

from pydantic import BeforeValidator, PrivateAttr

from flext_ldif import FlextLdifServer, c, m, r, s, u

_ = BeforeValidator


class FlextLdifParserMixin:
    """Parser methods for MRO composition on FlextLdif.

    Expects ``self._server: FlextLdifServer`` to be provided by the
    instantiated class (either FlextLdifParser or FlextLdif).
    """

    _server: FlextLdifServer

    def parse_ldif(
        self,
        value: str | Path,
        *,
        server_type: str | None = None,
    ) -> r[m.Ldif.ParseResponse]:
        """Parse LDIF content from string or file."""
        effective_type = server_type or self._get_effective_server_type_value()
        if isinstance(value, Path):
            return self._parse_ldif_path(value, server_type=effective_type)
        return self.parse_string(value, server_type=effective_type)

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
            return r[m.Ldif.ParseResponse].fail(
                f"Failed to read LDIF file {path}: {e}",
            )
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
        if parse_out.failure:
            error_msg = parse_out.error or "LDIF parsing failed"
            return r[m.Ldif.ParseResponse].fail(str(error_msg))
        entries = parse_out.value
        detected_server_type = c.Ldif.ServerTypes(effective_server_type)
        response = m.Ldif.ParseResponse(
            entries=entries,
            statistics=m.Ldif.Statistics(
                total_entries=len(entries),
                parse_errors=0,
            ),
            detected_server_type=detected_server_type,
        )
        return r[m.Ldif.ParseResponse].ok(response)

    def _get_effective_server_type_value(self) -> str:
        """Resolve effective server type (default: rfc, overridden by DetectorMixin)."""
        return "rfc"

    def _parse_ldif_path(
        self,
        path: Path,
        *,
        server_type: str | None = None,
    ) -> r[m.Ldif.ParseResponse]:
        """Parse LDIF file and return parse response."""
        resolved_path = path
        if not resolved_path.exists() and (not resolved_path.is_absolute()):
            project_root = Path(__file__).resolve().parents[2]
            candidate_path = project_root / resolved_path
            if candidate_path.exists():
                resolved_path = candidate_path
        if not resolved_path.exists():
            return r[m.Ldif.ParseResponse].fail(
                f"File not found: {path}",
            )
        try:
            content = resolved_path.read_text(encoding="utf-8")
        except OSError as e:
            return r[m.Ldif.ParseResponse].fail(
                f"Failed to read file: {e}",
            )
        return self.parse_ldif(value=content, server_type=server_type)


class FlextLdifParser(FlextLdifParserMixin, s[m.Ldif.ParseResponse]):
    """Standalone parser service (also usable outside FlextLdif MRO)."""

    _server: FlextLdifServer = PrivateAttr()

    def __init__(self, server: FlextLdifServer | None = None) -> None:
        """Initialize the parser with an optional server registry."""
        object.__setattr__(
            self,
            "_server",
            server if server is not None else FlextLdifServer.get_global_instance(),
        )

    @override
    def execute(self) -> r[m.Ldif.ParseResponse]:
        """Guard against invoking the service without input data."""
        return r[m.Ldif.ParseResponse].fail(
            "FlextLdifParser requires input data. Use parse_string() or parse_ldif_file().",
        )


__all__ = ["FlextLdifParser", "FlextLdifParserMixin"]
