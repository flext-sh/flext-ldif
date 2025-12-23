"""Parser service for LDIF content.

Converts LDIF text, files, or ldap3 search results into typed entries using
server-specific entry quirks resolved from :class:`FlextLdifServer`. Results are
wrapped in ``FlextResult`` to keep error handling explicit.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import cast, override

from flext_core import r
from pydantic import PrivateAttr

from flext_ldif._models.results import FlextLdifModelsResults
from flext_ldif._utilities.server import FlextLdifUtilitiesServer
from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.models import m
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.utilities import u


class FlextLdifParser(FlextLdifServiceBase[FlextLdifModelsResults.ParseResponse]):
    """Parse LDIF sources using server-specific entry quirks.

    Business Rule: Parser service uses server-specific entry quirks for LDIF parsing.
    Server type can be specified explicitly or auto-detected. All parsing follows
    RFC 2849 foundation with server-specific enhancements via quirks system.

    Implication: Parser delegates to FlextLdifServer for quirk resolution, ensuring
    consistent server-specific processing across the codebase. Invalid server types
    result in fail-fast error responses.
    """

    _server: FlextLdifServer = PrivateAttr()

    def __init__(self, server: FlextLdifServer | None = None) -> None:
        """Initialize the parser with an optional server registry.

        Business Rule: Server registry is optional - defaults to global instance if not provided.
        This enables dependency injection for testing while maintaining convenience defaults.

        Args:
            server: Optional FlextLdifServer instance (defaults to global instance)

        """
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
    ) -> r[FlextLdifModelsResults.ParseResponse]:
        """Parse LDIF content from a string using the requested server type.

        Business Rule: String parsing normalizes server type to canonical form before
        quirk resolution. Invalid server types result in fail-fast error responses.
        Parsing uses server-specific entry quirks for RFC-compliant processing with
        server enhancements.

        Implication: Server type normalization ensures consistent quirk selection.
        Auto-detection can be enabled by passing None, which defaults to RFC processing.

        Args:
            content: LDIF content as string (RFC 2849 format)
            server_type: Optional server type identifier (defaults to "rfc")

        Returns:
            FlextResult with ParseResponse containing entries and statistics

        """
        # Use FlextLdifServer directly - get entry quirk and parse
        # Normalize server_type to canonical form (e.g., "openldap" → "openldap2")
        effective_server_type_raw = server_type or "rfc"
        try:
            effective_server_type = FlextLdifUtilitiesServer.normalize_server_type(
                effective_server_type_raw,
            )
        except (ValueError, TypeError) as e:
            return r[str].fail(
                f"Invalid server type: {effective_server_type_raw} - {e}"
            )

        try:
            entry_quirk_raw = self._server.entry(effective_server_type)
        except ValueError as e:
            # Invalid server type validation error
            return r[str].fail(str(e))
        if entry_quirk_raw is None:
            return r[str].fail(
                f"No entry quirk found for server type: {effective_server_type}",
            )

        # Type narrowing: entry_quirk_raw is EntryProtocol (structural typing)
        # Use hasattr to check for parse method (structural typing check)
        if not hasattr(entry_quirk_raw, "parse"):
            return r[str].fail(
                f"Entry quirk for server type {effective_server_type} does not have parse method",
            )
        # Type narrowing: entry_quirk_raw has parse method
        # Direct call to entry quirk parse method using cast for type safety
        # Note: parse returns FlextResult[list[m.Ldif.Entry]] per EntryProtocol
        parse_method = cast(
            "Callable[[str], r[list[m.Ldif.Entry]]]", entry_quirk_raw.parse
        )
        if not callable(parse_method):
            return r[str].fail(
                f"Entry quirk for server type {effective_server_type} parse is not callable",
            )
        parse_result = parse_method(content)

        if parse_result.is_failure:
            return r[str].fail(parse_result.error or "LDIF parsing failed")

        # Extract entries from server response (list of Entry models)
        entries = parse_result.value

        # Create response with minimal metadata
        # Use facade LdifResults.Statistics for LDIF-specific statistics

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
    ) -> r[FlextLdifModelsResults.ParseResponse]:
        """Parse LDIF content from a file path with optional encoding override.

        Business Rule: File parsing reads content using specified encoding (defaults to UTF-8
        per RFC 2849). File read errors (OSError, UnicodeDecodeError) result in fail-fast
        error responses. Delegates to parse_string() after reading file content.

        Implication: Encoding specification enables handling of legacy LDIF files that may
        use non-UTF-8 encodings. Invalid encodings result in clear error messages.

        Args:
            path: Path to LDIF file
            server_type: Optional server type identifier (defaults to "rfc")
            encoding: Character encoding for file (defaults to "utf-8")

        Returns:
            FlextResult with ParseResponse containing entries and statistics

        """
        try:
            # Read file content directly
            content = path.read_text(encoding=encoding)
        except (OSError, UnicodeDecodeError) as e:
            return r[str].fail(f"Failed to read LDIF file {path}: {e}")

        # Delegate to string parsing
        return self.parse_string(content, server_type)

    def parse_ldap3_results(
        self,
        results: list[tuple[str, dict[str, list[str]]]],
        server_type: str | None = None,
    ) -> r[FlextLdifModelsResults.ParseResponse]:
        """Parse ldap3 search results by converting them to LDIF text first.

        Business Rule: LDAP3 results are converted to RFC 2849 LDIF format before parsing.
        Each result tuple (dn, attrs) is converted to LDIF entry format with proper
        attribute-value formatting. Empty lines separate entries per RFC specification.

        Implication: This method enables integration with ldap3 library search results.
        Conversion maintains RFC compliance, ensuring consistent parsing regardless of
        input source.

        Args:
            results: List of (dn, attrs) tuples from ldap3 search
            server_type: Optional server type identifier (defaults to "rfc")

        Returns:
            FlextResult with ParseResponse containing entries and statistics

        """
        # Convert ldap3 results to LDIF string format using u
        # Business Rule: LDIF lines are built dynamically from runtime data
        # Implication: Must use list[str] not list[LiteralString] for dynamic string construction
        ldif_lines: list[str] = []

        def convert_entry(dn_attrs: tuple[str, dict[str, list[str]]]) -> list[str]:
            """Convert single entry to LDIF lines."""
            dn, attrs = dn_attrs
            entry_lines: list[str] = [f"dn: {dn}"]
            for attr_name, values in attrs.items():
                # Business Rule: Attribute lines are built from runtime attribute names and values
                # Implication: Must use list[str] for dynamic string construction
                attr_lines: list[str] = [f"{attr_name}: {value}" for value in values]
                entry_lines.extend(attr_lines)
            entry_lines.append("")  # Empty line between entries
            return entry_lines

        # Use FlextLdifUtilities.process for batch processing with error handling
        # Use u.Collection.batch for processing
        batch_result = u.Collection.batch(
            results,
            convert_entry,
            _on_error="skip",
        )
        if batch_result.is_success:
            # u.Collection.batch returns BatchResult dict with 'results' key
            processed_value = batch_result.value
            if isinstance(processed_value, dict) and "results" in processed_value:
                # Extract results from BatchResult dict
                processed_list: list[list[str]] = cast(
                    "list[list[str]]", processed_value["results"]
                )
                for entry_lines in processed_list:
                    if isinstance(entry_lines, list):
                        ldif_lines.extend(entry_lines)

        content = "\n".join(ldif_lines)

        # Parse the generated LDIF content
        return self.parse_string(content, server_type)

    def parse(
        self,
        source: str | Path,
        server_type: str | None = None,
    ) -> r[FlextLdifModelsResults.ParseResponse]:
        """Parse LDIF from either raw text or a filesystem path.

        Business Rule: Unified parse method routes to appropriate parsing method based on
        source type. Path objects route to file parsing, strings route to string parsing.
        Unsupported source types result in fail-fast error responses.

        Implication: This method provides convenient unified interface for parsing from
        multiple sources. Type-based routing ensures correct handling without complex
        heuristics.

        Args:
            source: LDIF source (string content or file path)
            server_type: Optional server type identifier (defaults to "rfc")

        Returns:
            FlextResult with ParseResponse containing entries and statistics

        """
        # Direct type-based routing without complex heuristics
        if isinstance(source, Path):
            return self.parse_ldif_file(source, server_type)
        # Type narrowing: source is str here (str | Path - Path already handled)
        return self.parse_string(source, server_type)

    @override
    def execute(self) -> r[FlextLdifModelsResults.ParseResponse]:
        """Guard against invoking the service without input data.

        Business Rule: Parser service requires explicit input data via parse methods.
        This method prevents accidental execution without data, ensuring fail-fast
        behavior for misconfigured service calls.

        Implication: Services using FlextLdifParser must call parse(), parse_string(),
        parse_ldif_file(), or parse_ldap3_results() with appropriate input data.

        Returns:
            r.fail() with error message directing to correct usage

        """
        return r[str].fail(
            "FlextLdifParser requires input data to parse. "
            "Use parse(), parse_string(), parse_ldif_file(), or parse_ldap3_results() methods.",
        )


__all__ = ["FlextLdifParser"]
