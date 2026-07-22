"""LDIF protocol facade."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_cli import p
from flext_ldif._protocols.base import FlextLdifProtocolsBase
from flext_ldif._protocols.domain import FlextLdifProtocolsDomain

if TYPE_CHECKING:
    from flext_ldif import c


class FlextLdifProtocols(p):
    """Unified LDIF protocol facade."""

    @runtime_checkable
    class Ldif(FlextLdifProtocolsDomain, FlextLdifProtocolsBase, Protocol):
        """LDIF-specific structural protocol namespace."""

        @runtime_checkable
        class LdifSettings(Protocol):
            """Namespaced LDIF runtime settings branch.

            Plain ``Protocol`` (not ``p.Model``): pyrefly cannot reconcile the
            pydantic ``model_fields`` metaclass descriptor on this hot path —
            structural field access is the whole contract (same pattern as
            ``p.Cli.CliSettings`` in flext-cli).
            """

            # Read-only protocol properties: concrete settings models expose
            # covariant pydantic fields; read-write attrs would be invariant
            # and reject the concrete LdifSettings model (pyrefly).
            @property
            def ldif_encoding(self) -> c.Ldif.Encoding | str:
                """Default encoding for LDIF read/write operations."""
                ...

            @property
            def ldif_strict_validation(self) -> bool:
                """Enable strict LDIF validation rules."""
                ...

        @runtime_checkable
        class Settings(p.Cli.Settings, Protocol):
            """MRO-composed settings contract with the LDIF namespace."""

            @property
            def Ldif(self) -> FlextLdifProtocols.Ldif.LdifSettings:
                """Namespaced LDIF settings branch."""
                ...


p = FlextLdifProtocols

__all__: list[str] = ["FlextLdifProtocols", "p"]
