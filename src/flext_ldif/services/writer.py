"""Writer service for LDIF output orchestration.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from flext_cli import r

from flext_ldif.models import m
from flext_ldif.protocols import p
from flext_ldif.services import FlextLdifServer
from flext_ldif.utilities import u

if TYPE_CHECKING:
    from os import PathLike


class FlextLdifWriter(FlextLdifServer):
    """LDIF writer orchestrator over the server server registry."""

    def write(
        self,
        entries: Sequence[p.Ldif.Entry] | m.Ldif.ParseResponse,
        *,
        server_type: str | None = None,
        format_options: p.Ldif.WriteFormatOptions | None = None,
    ) -> p.Result[p.Ldif.WriteResponse]:
        """Write entries to LDIF text and return canonical write metadata.

        Returns:
            The resulting ``p.Result[p.Ldif.WriteResponse]``.

        """
        batch = (
            entries.entries if isinstance(entries, m.Ldif.ParseResponse) else entries
        )
        content_result = self.write_to_string(
            batch,
            server_type=server_type,
            format_options=format_options,
        )
        if content_result.failure:
            return r[p.Ldif.WriteResponse].from_failure(content_result)
        return r[p.Ldif.WriteResponse].ok(
            m.Ldif.WriteResponse(
                content=content_result.value,
                statistics=m.Ldif.Statistics(
                    total_entries=u.count(batch),
                    processed_entries=u.count(batch),
                ),
            ),
        )

    def write_ldif_file(
        self,
        entries: Sequence[p.Ldif.Entry] | m.Ldif.ParseResponse,
        path: PathLike[str],
        *,
        server_type: str | None = None,
        format_options: p.Ldif.WriteFormatOptions | None = None,
    ) -> p.Result[p.Ldif.WriteResponse]:
        """Write entries to an LDIF file and return canonical write metadata.

        Relative paths use the current directory without resolving symbolic links.

        Returns:
            The resulting ``p.Result[p.Ldif.WriteResponse]``.

        """
        batch = (
            entries.entries if isinstance(entries, m.Ldif.ParseResponse) else entries
        )
        content_result = self.write_to_string(
            batch,
            server_type=server_type,
            format_options=format_options,
        )
        if content_result.failure:
            return r[p.Ldif.WriteResponse].from_failure(content_result)
        ldif_content = content_result.value
        write = u.Cli.atomic_write_text_file(Path(path).absolute(), ldif_content)
        if write.failure:
            return r[p.Ldif.WriteResponse].from_failure(write)
        return r[p.Ldif.WriteResponse].ok(
            m.Ldif.WriteResponse(
                content=ldif_content,
                output_path=str(path),
                statistics=m.Ldif.Statistics(
                    total_entries=u.count(batch),
                    processed_entries=u.count(batch),
                ),
            ),
        )

    def write_to_string(
        self,
        entries: Sequence[p.Ldif.Entry] | m.Ldif.ParseResponse,
        server_type: str | None = None,
        format_options: p.Ldif.WriteFormatOptions | None = None,
    ) -> p.Result[str]:
        """Write entries to LDIF text through the selected base server.

        Returns:
            The resulting ``p.Result[str]``.

        """
        effective_server_type = (
            self._get_effective_server_type_value()
            if server_type is None
            else server_type
        )
        batch = (
            entries.entries if isinstance(entries, m.Ldif.ParseResponse) else entries
        )
        request = m.Ldif.WriteRequest(
            entries=list(batch),
            format_options=format_options,
        )
        return self.server(effective_server_type).flat_map(
            lambda server: server.write(request.entries, request.format_options)
        )


__all__: list[str] = ["FlextLdifWriter"]
