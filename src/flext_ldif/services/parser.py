"""Parser service for LDIF content.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from flext_ldif import c, p, r
from flext_ldif.services import FlextLdifServer

if TYPE_CHECKING:
    from os import PathLike


class FlextLdifParser(FlextLdifServer):
    """LDIF parser orchestrator over the server server registry."""

    def parse_ldif(
        self,
        value: str | PathLike[str],
        *,
        server_type: str | None = None,
    ) -> p.Result[p.Ldif.ParseResponse]:
        """Parse LDIF content from string or file.

        Returns:
            The resulting ``p.Result[p.Ldif.ParseResponse]``.

        """
        effective_type = (
            self._get_effective_server_type_value() if server_type is None else server_type
        )
        if isinstance(value, str):
            return self.parse_string(value, server_type=effective_type)
        return self.parse_ldif_file(value, server_type=effective_type)

    def parse_ldif_file(
        self,
        path: PathLike[str],
        server_type: str | None = None,
        encoding: str = "utf-8",
    ) -> p.Result[p.Ldif.ParseResponse]:
        """Parse LDIF content from a file path with optional encoding override.

        Returns:
            The resulting ``p.Result[p.Ldif.ParseResponse]``.

        """
        resolved_path = Path(path)
        if not resolved_path.exists():
            return r[p.Ldif.ParseResponse].fail_op(
                "resolve ldif path",
                f"File not found: {path}",
            )
        try:
            content = resolved_path.read_text(encoding=encoding)
        except c.EXC_OS_DECODING as error:
            return r[p.Ldif.ParseResponse].fail_op("read ldif file", error)
        return self.parse_string(content, server_type=server_type)

    def parse_string(
        self,
        content: str,
        server_type: str | None = None,
    ) -> p.Result[p.Ldif.ParseResponse]:
        """Parse LDIF content from a string through the selected base server.

        Returns:
            The resulting ``p.Result[p.Ldif.ParseResponse]``.

        """
        effective_server_type = (
            self._get_effective_server_type_value() if server_type is None else server_type
        )
        return r[p.Ldif.ParseResponse].from_result(
            self.server(effective_server_type).flat_map(
                lambda server: server.parse_ldif(content)
            )
        )


__all__: list[str] = ["FlextLdifParser"]
