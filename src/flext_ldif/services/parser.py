"""Parser service for LDIF content.

Converts LDIF text, files, or ldap3 search results into typed entries using
server-specific entry quirks resolved from :class:`FlextLdifServer`. Results are
wrapped in ``FlextResult`` to keep error handling explicit.
"""

from __future__ import annotations

from pathlib import Path

from flext_core import FlextResult

from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.server import FlextLdifServer


class FlextLdifParser(FlextLdifServiceBase[FlextLdifModels.ParseResponse]):
    """Parse LDIF sources using server-specific entry quirks."""

    _server: FlextLdifServer

    def __init__(self, server: FlextLdifServer | None = None) -> None:
        """Initialize the parser with an optional quirk registry."""
        super().__init__()
        self._server = server if server is not None else FlextLdifServer()

    def parse_string(
        self,
        content: str,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral | None = None,
    ) -> FlextResult[FlextLdifModels.ParseResponse]:
        """Parse LDIF content from a string using the requested server type."""
        # Use FlextLdifServer directly - get entry quirk and parse
        effective_server_type = server_type or "rfc"

        entry_quirk = self._server.entry(effective_server_type)
        if entry_quirk is None:
            return FlextResult.fail(
                f"No entry quirk found for server type: {effective_server_type}",
            )

        # Direct call to entry quirk parse method
        parse_result = entry_quirk.parse(content)

        if parse_result.is_failure:
            return FlextResult.fail(parse_result.error or "LDIF parsing failed")

        # Extract entries from server response
        raw_entries = parse_result.unwrap()

        # Convert to expected type (FlextLdifModels.Entry should be compatible with FlextLdifModelsDomains.Entry)
        entries: list[FlextLdifModels.Entry] = list(raw_entries)

        # Create response with minimal metadata
        response = FlextLdifModels.ParseResponse(
            entries=entries,
            statistics=FlextLdifModels.Statistics(
                total_entries=len(entries),
                parse_errors=0,
            ),
            detected_server_type=effective_server_type,
        )

        return FlextResult.ok(response)

    def parse_ldif_file(
        self,
        path: Path,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral | None = None,
        encoding: FlextLdifConstants.LiteralTypes.EncodingLiteral = "utf-8",
    ) -> FlextResult[FlextLdifModels.ParseResponse]:
        """Parse LDIF content from a file path with optional encoding override."""
        try:
            # Read file content directly
            content = path.read_text(encoding=encoding)
        except (OSError, UnicodeDecodeError) as e:
            return FlextResult.fail(f"Failed to read LDIF file {path}: {e}")

        # Delegate to string parsing
        return self.parse_string(content, server_type)

    def parse_ldap3_results(
        self,
        results: list[tuple[str, dict[str, list[str]]]],
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral | None = None,
    ) -> FlextResult[FlextLdifModels.ParseResponse]:
        """Parse ldap3 search results by converting them to LDIF text first."""
        # Convert ldap3 results to LDIF string format
        ldif_lines = []

        for dn, attrs in results:
            ldif_lines.append(f"dn: {dn}")
            for attr_name, values in attrs.items():
                ldif_lines.extend(f"{attr_name}: {value}" for value in values)
            ldif_lines.append("")  # Empty line between entries

        content = "\n".join(ldif_lines)

        # Parse the generated LDIF content
        return self.parse_string(content, server_type)

    def parse(
        self,
        source: str | Path,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral | None = None,
    ) -> FlextResult[FlextLdifModels.ParseResponse]:
        """Parse LDIF from either raw text or a filesystem path."""
        # Direct type-based routing without complex heuristics
        if isinstance(source, Path):
            return self.parse_ldif_file(source, server_type)
        if isinstance(source, str):
            return self.parse_string(source, server_type)
        return FlextResult.fail(f"Unsupported source type: {type(source)}")

    def execute(self) -> FlextResult[FlextLdifModels.ParseResponse]:
        """Guard against invoking the service without input data."""
        return FlextResult.fail(
            "FlextLdifParser requires input data to parse. "
            "Use parse(), parse_string(), parse_ldif_file(), or parse_ldap3_results() methods.",
        )


__all__ = ["FlextLdifParser"]
