"""LDIF protocol facade."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Protocol, runtime_checkable

from flext_cli import p

from ._protocols.base import FlextLdifProtocolsBase
from ._protocols.domain import FlextLdifProtocolsDomain
from ._protocols.ldap3 import Protocols

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
            def ldif(self) -> FlextLdifProtocols.Ldif.LdifSettings:
                """Namespaced LDIF settings branch."""
                ...

        # ── Structural ldap3 contracts (SSOT: _protocols/ldap3.py) ──
        # Exposed as ClassVar so they appear as namespace attributes without
        # being treated as structural protocol members.

        Ldap3ServerInfo: ClassVar = Protocols.Ldap3ServerInfo
        Ldap3Server: ClassVar = Protocols.Ldap3Server
        Ldap3Entry: ClassVar = Protocols.Ldap3Entry
        Ldap3Attribute: ClassVar = Protocols.Ldap3Attribute
        Ldap3Connection: ClassVar = Protocols.Ldap3Connection
        Ldap3ParseResponse: ClassVar = Protocols.Ldap3ParseResponse
        RootDseEntry: ClassVar = Protocols.RootDseEntry
        RootDseConnection: ClassVar = Protocols.RootDseConnection


p = FlextLdifProtocols

__all__: list[str] = ["FlextLdifProtocols", "p"]
