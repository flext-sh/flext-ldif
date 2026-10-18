"""Writer service for LDIF output orchestration.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_ldif import m, p, r, t, u
from flext_ldif.services import FlextLdifServer

if TYPE_CHECKING:
    from pathlib import Path


class FlextLdifWriter(FlextLdifServer):
    """LDIF writer orchestrator over the server server registry."""

    def write(
        self,
        entries: t.MutableSequenceOf[m.Ldif.Entry],
        *,
        server_type: str | None = None,
        format_options: p.Ldif.WriteFormatOptions | None = None,
    ) -> p.Result[m.Ldif.WriteResponse]:
        """Write entries to LDIF text and return canonical write metadata.

        Returns:
            The resulting ``p.Result[m.Ldif.WriteResponse]``.

        """
        content_result = self.write_to_string(
            entries,
            server_type=server_type,
            format_options=format_options,
        )
        if content_result.failure:
            return r[m.Ldif.WriteResponse].from_failure(content_result)
        return r[m.Ldif.WriteResponse].ok(
            m.Ldif.WriteResponse(
                content=content_result.value,
                statistics=m.Ldif.Statistics(
                    total_entries=u.count(entries),
                    processed_entries=u.count(entries),
                ),
            ),
        )

    def write_ldif_file(
        self,
        entries: t.MutableSequenceOf[m.Ldif.Entry],
        path: Path,
        *,
        server_type: str | None = None,
        format_options: p.Ldif.WriteFormatOptions | None = None,
    ) -> p.Result[m.Ldif.WriteResponse]:
        """Write entries to an LDIF file and return canonical write metadata.

        Returns:
            The resulting ``p.Result[m.Ldif.WriteResponse]``.

        """
        content_result = self.write_to_string(
            entries,
            server_type=server_type,
            format_options=format_options,
        )
        if content_result.failure:
            return r[m.Ldif.WriteResponse].from_failure(content_result)
        ldif_content = content_result.value
        write = u.Cli.atomic_write_text_file(path, ldif_content)
        if write.failure:
            return r[m.Ldif.WriteResponse].from_failure(write)
        return r[m.Ldif.WriteResponse].ok(
            m.Ldif.WriteResponse(
                content=ldif_content,
                output_path=str(path),
                statistics=m.Ldif.Statistics(
                    total_entries=u.count(entries),
                    processed_entries=u.count(entries),
                ),
            ),
        )

    def write_to_string(
        self,
        entries: t.MutableSequenceOf[m.Ldif.Entry],
        server_type: str | None = None,
        format_options: p.Ldif.WriteFormatOptions | None = None,
    ) -> p.Result[str]:
        """Write entries to LDIF text through the selected base server.

        Returns:
            The resulting ``p.Result[str]``.

        """
        effective_server_type = server_type or self._get_effective_server_type_value()
        concrete_options = (
            format_options
            if format_options is None
            or isinstance(format_options, m.Ldif.WriteFormatOptions)
            else m.Ldif.WriteFormatOptions.model_validate(format_options)
        )
        return self.server(effective_server_type).flat_map(
            lambda server: server.write(entries, concrete_options)
        )


__all__: list[str] = ["FlextLdifWriter"]
