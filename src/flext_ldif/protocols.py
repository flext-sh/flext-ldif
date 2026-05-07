"""LDIF protocol facade."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_cli import FlextCliProtocols
from flext_ldif import FlextLdifProtocolsBase, FlextLdifProtocolsDomain

if TYPE_CHECKING:
    from flext_ldif import c


class FlextLdifProtocols(FlextCliProtocols):
    """Unified LDIF protocol facade."""

    @runtime_checkable
    class Ldif(
        FlextLdifProtocolsDomain,
        FlextLdifProtocolsBase,
        Protocol,
    ):
        """LDIF-specific structural protocol namespace."""

        @runtime_checkable
        class LdifSettings(FlextCliProtocols.Model, Protocol):
            """Namespaced LDIF runtime settings branch."""

            ldif_encoding: c.Ldif.Encoding | str
            """Default encoding for LDIF read/write operations."""

            ldif_strict_validation: bool
            """Enable strict LDIF validation rules."""

        @runtime_checkable
        class Settings(FlextCliProtocols.Cli.Settings, Protocol):
            """MRO-composed settings contract with the LDIF namespace."""

            Ldif: FlextLdifProtocols.Ldif.LdifSettings
            """Namespaced LDIF settings branch."""


p = FlextLdifProtocols

__all__: list[str] = ["FlextLdifProtocols", "p"]
