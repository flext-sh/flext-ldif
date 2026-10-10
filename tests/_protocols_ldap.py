"""Structural contracts of the ldap3-compatible client used by the tests.

Focused protocols module split out of ``tests.protocols``; the public surface
is composed into the ``tests.protocols`` facade (see
``TestsFlextLdifLdapProtocols``).

flext-ldif is the base library the LDAP client builds on, so the client can
never be a declared dependency of this project. The tests describe only the
surface they drive and resolve the concrete implementation at runtime through
``tests.utilities`` (see ``u.Tests.require_ldap_client``).

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from flext_ldif import FlextLdifModels, FlextLdifProtocols


class TestsFlextLdifLdapProtocols:
    """ldap3 client contracts grouped for composition by the tests facade."""

    @runtime_checkable
    class Ldap3Server(Protocol):
        """Opaque ldap3-compatible server handle."""

        @property
        def name(self) -> str | None:
            """The configured server name."""
            ...

    # ── Shared structural contracts (SSOT: flext_ldif._protocols.ldap3) ──
    type Ldap3Attribute = FlextLdifProtocols.Ldif.Ldap3Attribute
    type Ldap3Entry = FlextLdifProtocols.Ldif.Ldap3Entry
    type Ldap3Connection = FlextLdifProtocols.Ldif.Ldap3Connection

    @runtime_checkable
    class Ldap3EntryAdapter(Protocol):
        """Structural contract for the ldap3 entry to LDIF entry adapter."""

        def ldap3_to_ldif_entry(
            self,
            ldap3_entry: TestsFlextLdifLdapProtocols.Ldap3Entry,
        ) -> FlextLdifProtocols.Result[FlextLdifModels.Ldif.Entry]:
            """Convert one ldap3 entry into the LDIF entry model."""
            ...


__all__: list[str] = ["TestsFlextLdifLdapProtocols"]
