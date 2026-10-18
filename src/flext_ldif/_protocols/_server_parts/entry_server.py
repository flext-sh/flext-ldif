"""EntryServer protocol - Entry server contract.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_ldif import p, t

if TYPE_CHECKING:
    from flext_ldif._protocols._entry_parts import EntryProtocol


@runtime_checkable
class EntryServerProtocol(Protocol):
    """Entry server contract."""

    def parse_server(
        self,
        value: str,
    ) -> p.Result[t.MutableSequenceOf[EntryProtocol]]:
        """Parse LDIF text into entry models."""
        ...

    def parse_input(
        self,
        ldif_text: str,
    ) -> t.MutableSequenceOf[EntryProtocol] | None:
        """Compatibility parser entrypoint for direct entry server consumers."""
        ...

    def can_handle(
        self,
        entry_dn: str,
        attributes: t.MutableStrSequenceMapping,
    ) -> bool:
        """Check if this server can handle the entry."""
        ...

    def parse_entry(
        self,
        entry_dn: str,
        entry_attrs: t.Ldif.MutableEntryAttributesDict,
    ) -> p.Result[EntryProtocol]:
        """Parse a single entry from DN and attribute mapping."""
        ...

    def write(
        self,
        entry_data: t.MutableSequenceOf[EntryProtocol],
        write_options: p.Ldif.WriteFormatOptions | None = None,
    ) -> p.Result[str]:
        """Serialize one or more entries."""
        ...


__all__: tuple[str, ...] = ("EntryServerProtocol",)
