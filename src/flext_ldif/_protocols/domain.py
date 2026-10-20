"""Higher-level LDIF entry-processing contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_cli import p

if TYPE_CHECKING:
    from flext_ldif import m


@runtime_checkable
class FlextLdifProtocolsDomain(Protocol):
    """Service-level LDIF contracts; server capabilities belong to the base owner."""

    @runtime_checkable
    class EntryStep(Protocol):
        """Callable step contract for entry-processing pipelines."""

        def __call__(self, item: m.Ldif.Entry) -> p.Result[m.Ldif.Entry]:
            """Transform one entry and return the canonical result container."""
            del item


__all__: list[str] = ["FlextLdifProtocolsDomain"]
