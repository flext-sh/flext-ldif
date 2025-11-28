"""Parser Service - Direct LDIF Parsing with flext-core APIs.

This service provides direct LDIF parsing using flext-core and flext-ldif APIs:
- Direct use of FlextLdifServer for server-specific parsing
- No unnecessary routing or validation layers
- Railway-oriented error handling with FlextResult

Single Responsibility: Parse LDIF content to Entry models using direct APIs.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path

from collections.abc import Sequence
from typing import cast

from flext_core import FlextResult

from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.server import FlextLdifServer


class FlextLdifParser(FlextLdifServiceBase[FlextLdifModels.ParseResponse]):
    """Direct LDIF parsing service using flext-core APIs.

    This service provides minimal, direct LDIF parsing by delegating
    to FlextLdifServer which handles all server-specific quirks.
    No unnecessary abstraction layers or routing logic.
    """

    _server: FlextLdifServer

    def __init__(self, server: FlextLdifServer | None = None) -> None:
        """Initialize parser with optional server instance."""
        super().__init__()
        self._server = server if server is not None else FlextLdifServer()

    def parse_string(
        self,
        content: str,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral | None = None,
    ) -> FlextResult[FlextLdifModels.ParseResponse]:
        """Parse LDIF content from string.

        Args:
            content: LDIF content as string
            server_type: Server type for quirk selection

        Returns:
            FlextResult containing parsed entries

        """
        # Use FlextLdifServer directly - get entry quirk and parse
        effective_server_type = server_type or "rfc"

        entry_quirk = self._server.entry(effective_server_type)
        if entry_quirk is None:
            return FlextResult.fail(f"No entry quirk found for server type: {effective_server_type}")

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
            entries=entries,  # type: ignore[arg-type]
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
        """Parse LDIF content from file.

        Args:
            path: Path to LDIF file
            server_type: Server type for quirk selection
            encoding: File encoding

        Returns:
            FlextResult containing parsed entries

        """
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
        """Parse ldap3 search results.

        Args:
            results: ldap3 search results
            server_type: Server type for quirk selection

        Returns:
            FlextResult containing parsed entries

        """
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
        """Parse LDIF from source with automatic type detection.

        Args:
            source: LDIF content or file path
            server_type: Server type for quirk selection

        Returns:
            FlextResult containing parsed entries

        """
        # Direct type-based routing without complex heuristics
        if isinstance(source, Path):
            return self.parse_ldif_file(source, server_type)
        if isinstance(source, str):
            return self.parse_string(source, server_type)
        return FlextResult.fail(f"Unsupported source type: {type(source)}")


__all__ = ["FlextLdifParser"]
