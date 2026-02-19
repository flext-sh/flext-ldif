"""Parser service for LDIF content."""

from __future__ import annotations

from pathlib import Path
from typing import override

from flext_core import r
from pydantic import PrivateAttr

from flext_ldif.base import s
from flext_ldif.models import m
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.utilities import u


class FlextLdifParser(s[m.Ldif.LdifResults.ParseResponse]):
    """Parse LDIF sources using server-specific entry quirks."""

    _server: FlextLdifServer = PrivateAttr()

    def __init__(self, server: FlextLdifServer | None = None) -> None:
        """Initialize the parser with an optional server registry."""
        super().__init__()
        object.__setattr__(
            self,
            "_server",
            server if server is not None else FlextLdifServer(),
        )

    def parse_string(
        self,
        content: str,
        server_type: str | None = None,
    ) -> r[m.Ldif.LdifResults.ParseResponse]:
        """Parse LDIF content from a string using the requested server type."""
        effective_server_type_raw = server_type or "rfc"
        try:
            effective_server_type = u.Ldif.Server.normalize_server_type(
                effective_server_type_raw,
            )
        except (ValueError, TypeError) as e:
            return r[m.Ldif.LdifResults.ParseResponse].fail(
                f"Invalid server type: {effective_server_type_raw} - {e}",
            )

        try:
            entry_quirk_raw = self._server.entry(effective_server_type)
        except ValueError as e:
            return r[m.Ldif.LdifResults.ParseResponse].fail(str(e))
        if entry_quirk_raw is None:
            return r[m.Ldif.LdifResults.ParseResponse].fail(
                f"No entry quirk found for server type: {effective_server_type}",
            )

        if not hasattr(entry_quirk_raw, "parse"):
            return r[m.Ldif.LdifResults.ParseResponse].fail(
                f"Entry quirk for server type {effective_server_type} does not have parse method",
            )

        parse_attr = getattr(entry_quirk_raw, "parse", None)
        if parse_attr is None or not callable(parse_attr):
            return r[m.Ldif.LdifResults.ParseResponse].fail(
                f"Entry quirk for server type {effective_server_type} parse is not callable",
            )

        parse_result_raw = parse_attr(content)

        is_failure = getattr(parse_result_raw, "is_failure", None)
        if is_failure is None:
            return r[m.Ldif.LdifResults.ParseResponse].fail(
                "Invalid parse result from entry quirk",
            )
        if is_failure:
            error_msg = (
                getattr(parse_result_raw, "error", None) or "LDIF parsing failed"
            )
            return r[m.Ldif.LdifResults.ParseResponse].fail(
                error_msg if isinstance(error_msg, str) else str(error_msg),
            )

        entries_raw = getattr(parse_result_raw, "value", None)
        if entries_raw is None:
            return r[m.Ldif.LdifResults.ParseResponse].fail(
                "Parse result has no value",
            )
        entries = entries_raw if isinstance(entries_raw, list) else []

        response = m.Ldif.LdifResults.ParseResponse(
            entries=entries,
            statistics=m.Ldif.LdifResults.Statistics(
                total_entries=len(entries),
                parse_errors=0,
            ),
            detected_server_type=effective_server_type,
        )

        return r[str].ok(response)

    def parse_ldif_file(
        self,
        path: Path,
        server_type: str | None = None,
        encoding: str = "utf-8",
    ) -> r[m.Ldif.LdifResults.ParseResponse]:
        """Parse LDIF content from a file path with optional encoding override."""
        try:
            content = path.read_text(encoding=encoding)
        except (OSError, UnicodeDecodeError) as e:
            return r[m.Ldif.LdifResults.ParseResponse].fail(
                f"Failed to read LDIF file {path}: {e}",
            )

        return self.parse_string(content, server_type)

    def parse_ldap3_results(
        self,
        results: list[tuple[str, dict[str, list[str]]]],
        server_type: str | None = None,
    ) -> r[m.Ldif.LdifResults.ParseResponse]:
        """Parse ldap3 search results by converting them to LDIF text first."""
        ldif_lines: list[str] = []

        def convert_entry(dn_attrs: tuple[str, dict[str, list[str]]]) -> list[str]:
            """Convert single entry to LDIF lines."""
            dn, attrs = dn_attrs
            entry_lines: list[str] = [f"dn: {dn}"]
            for attr_name, values in attrs.items():
                attr_lines: list[str] = [f"{attr_name}: {value}" for value in values]
                entry_lines.extend(attr_lines)
            entry_lines.append("")
            return entry_lines

        batch_result = u.Collection.batch(
            results,
            convert_entry,
            on_error="skip",
        )
        if batch_result.is_success:
            processed_value = batch_result.value
            processed_list: list[list[str]] = []
            if isinstance(processed_value, dict) and "results" in processed_value:
                results_value = processed_value["results"]
                if isinstance(results_value, list):
                    processed_list = [
                        entry for entry in results_value if isinstance(entry, list)
                    ]
            elif isinstance(processed_value, list):
                processed_list = [
                    entry for entry in processed_value if isinstance(entry, list)
                ]

            for entry_lines in processed_list:
                ldif_lines.extend([str(line) for line in entry_lines])

        content = "\n".join(ldif_lines)

        return self.parse_string(content, server_type)

    def parse(
        self,
        source: str | Path,
        server_type: str | None = None,
    ) -> r[m.Ldif.LdifResults.ParseResponse]:
        """Parse LDIF from either raw text or a filesystem path."""
        if isinstance(source, Path):
            return self.parse_ldif_file(source, server_type)

        return self.parse_string(source, server_type)

    @override
    def execute(self) -> r[m.Ldif.LdifResults.ParseResponse]:
        """Guard against invoking the service without input data."""
        return r[m.Ldif.LdifResults.ParseResponse].fail(
            "FlextLdifParser requires input data to parse. "
            "Use parse(), parse_string(), parse_ldif_file(), or parse_ldap3_results() methods.",
        )


__all__ = ["FlextLdifParser"]
