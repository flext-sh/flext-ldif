"""Base server parse/write I/O operations mixin.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Self

from flext_ldif import c, m, p, r, t, u


class FlextLdifServersBaseIoMixin:
    """Parse/write I/O operations shared by every LDIF server."""

    @staticmethod
    def _ensure_trailing_newline(ldif: str) -> str:
        """Normalize a successful LDIF serialization to one trailing newline.

        Returns:
            The resulting ``str``.
        """
        return ldif if not ldif or ldif.endswith("\n") else f"{ldif}\n"

    def parse_ldif(
        self: Self,
        value: str,
    ) -> p.Result[m.Ldif.ParseResponse]:
        """Parse LDIF text to Entry models.

        Returns:
            The resulting ``p.Result[m.Ldif.ParseResponse]``.
        """
        entry_server = getattr(self, "entry_server", None)
        if entry_server is None:
            return r[m.Ldif.ParseResponse].fail("Entry server not available")
        detected_server = getattr(self, "server_type", None)
        detected_server_type: c.Ldif.ServerTypes | None = None
        if isinstance(detected_server, c.Ldif.ServerTypes):
            detected_server_type = detected_server
        elif isinstance(detected_server, str):
            try:
                detected_server_type = c.Ldif.ServerTypes(
                    u.Ldif.normalize_server_type(detected_server),
                )
            except ValueError:
                detected_server_type = None

        def normalize_parse_error(error: str) -> str:
            return error or "Entry parsing failed"

        def build_parse_response(
            parsed_entries: t.Ldif.EntrySequence,
        ) -> m.Ldif.ParseResponse:
            domain_entries = u.Ldif.as_entries(parsed_entries)
            for entry in domain_entries:
                if entry.metadata and detected_server_type is not None:
                    entry.metadata = entry.metadata.model_copy(
                        update={"original_server_type": detected_server_type},
                    )
            statistics = m.Ldif.Statistics(
                total_entries=len(domain_entries),
                processed_entries=len(domain_entries),
                detected_server_type=detected_server_type,
            )
            return m.Ldif.ParseResponse(
                entries=[entry.model_copy(deep=True) for entry in domain_entries],
                statistics=statistics,
                detected_server_type=detected_server_type,
            )

        parse_response_result: p.Result[m.Ldif.ParseResponse] = (
            entry_server
            .parse_server(value)
            .map_error(normalize_parse_error)
            .map(build_parse_response)
        )
        return parse_response_result

    def write(
        self: Self,
        entries: t.MutableSequenceOf[m.Ldif.Entry],
        write_options: m.Ldif.WriteFormatOptions | None = None,
    ) -> p.Result[str]:
        """Write Entry models to LDIF text.

        Returns:
            The resulting ``p.Result[str]``.
        """
        entry_server = getattr(self, "entry_server", None)
        if not entry_server:
            return r[str].fail("Entry server not available")
        write_result: p.Result[str] = entry_server.write(entries, write_options).map(
            FlextLdifServersBaseIoMixin._ensure_trailing_newline,
        )
        return write_result

    def _execute_parse(
        self: Self,
        ldif_text: str,
    ) -> p.Result[m.Ldif.Entry]:
        """Execute parse operation.

        Returns:
            The resulting ``p.Result[m.Ldif.Entry]``.
        """
        parse_result = self.parse_ldif(ldif_text)
        if not parse_result.success:
            return r[m.Ldif.Entry].fail(parse_result.error or "Parse failed")
        entries = u.Ldif.as_entries(parse_result.unwrap())
        if not entries:
            return r[m.Ldif.Entry].fail("No entries parsed")
        first_entry = entries[0]
        return r[m.Ldif.Entry].ok(first_entry)


__all__: list[str] = ["FlextLdifServersBaseIoMixin"]
