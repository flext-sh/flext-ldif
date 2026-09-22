"""Structural protocols for ldap3-compatible runtime objects.

These protocols describe the ``ldap3`` library's runtime objects using
generic structural contracts so that both ``flext-LDAP`` (which wraps
ldap3) and ``flext-LDIF`` (which processes LDIF) share a single definition
without a cross-dependency.  ``flext-LDAP`` extends the base contracts here
with ldap3-specific additional members where needed.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from flext_ldif import t
__all__: list[str] = ["FlextLdifProtocolsLdap3"]


class FlextLdifProtocolsLdap3(Protocol):
    """Declared owner for ldap3-compatible structural protocol contracts."""

    @runtime_checkable
    class Ldap3Entry(Protocol):
        """Structural contract for ldap3-compatible entry objects."""

        @property
        def entry_dn(self) -> str | None:
            """The entry distinguished name."""
            ...

        @property
        def entry_attributes(self) -> t.StrSequence:
            """The attribute names present in this entry."""
            ...

        @property
        def entry_attributes_as_dict(
            self,
        ) -> t.MappingKV[str, t.SequenceOf[str | bytes]]:
            """The entry attributes as an LDAP attribute mapping."""
            ...

        def __getitem__(
            self, attribute_name: str
        ) -> FlextLdifProtocolsLdap3.Ldap3Attribute:
            """Return one ldap3 attribute object by attribute name."""
            ...

    @runtime_checkable
    class Ldap3Attribute(Protocol):
        """Structural contract for ldap3-compatible attribute objects."""

        @property
        def values(self) -> t.SequenceOf[str | bytes]:
            """The raw LDAP values for this attribute."""
            ...

        @property
        def value(
            self,
        ) -> (
            str
            | bytes
            | int
            | float
            | bool
            | t.SequenceOf[str | bytes | int | float | bool]
            | None
        ):
            """The resolved attribute value."""
            ...

    @runtime_checkable
    class Ldap3ServerInfo(Protocol):
        """Structural marker for ldap3-compatible server info payloads."""

        @property
        def naming_contexts(self) -> t.StrSequence | None:
            """The advertised naming contexts when available."""
            ...

        @property
        def other(self) -> t.MappingKV[str, t.JsonValue]:
            """The auxiliary ldap3 server info fields."""
            ...

    @runtime_checkable
    class Ldap3Server(Protocol):
        """Structural contract for ldap3-compatible server objects."""

        @property
        def info(self) -> FlextLdifProtocolsLdap3.Ldap3ServerInfo | None:
            """The ldap3 server-info payload when populated."""
            ...

        def __str__(self) -> str:
            """Return the server URL-style representation."""
            ...

    @runtime_checkable
    class Ldap3Connection(Protocol):
        """Structural contract for ldap3-compatible connection objects.

        ``flext-LDAP`` extends this base contract with additional ldap3-specific
        members (``server``, ``result``, ``start_tls``, ``disconnect``, etc.).
        """

        @property
        def bound(self) -> bool:
            """Whether the connection is currently bound."""
            ...

        def bind(self) -> bool:
            """Bind the connection using the configured credentials."""
            ...

        @property
        def entries(self) -> t.SequenceOf[FlextLdifProtocolsLdap3.Ldap3Entry]:
            """The entries produced by the last LDAP operation."""
            ...

        @property
        def add(self) -> Callable[..., bool]:
            """The callable implementing the add operation."""
            ...

        @property
        def delete(self) -> Callable[..., bool]:
            """The callable implementing the delete operation."""
            ...

        @property
        def modify(self) -> Callable[..., bool]:
            """The callable implementing the modify operation."""
            ...

        @property
        def search(self) -> Callable[..., bool | t.JsonValue | None]:
            """The callable implementing the search operation."""
            ...

        @property
        def unbind(
            self,
        ) -> Callable[..., bool | tuple[bool, t.JsonValue, t.JsonValue, t.JsonValue]]:
            """The callable implementing connection teardown.

            Thread-safe ldap3 strategies may return a ``(status, result,
            response, request)`` tuple; consumers only consume truthiness.
            """
            ...

    @runtime_checkable
    class Ldap3ParseResponse(Protocol):
        """Protocol for ldap3.ParseResponse objects (structural type)."""

        @property
        def entries(self) -> t.SequenceOf[FlextLdifProtocolsLdap3.Ldap3Entry]:
            """The list of entries."""
            ...

    @runtime_checkable
    class RootDseEntry(Protocol):
        """Structural protocol for entries exposing rootDSE attributes."""

        @property
        def entry_attributes_as_dict(
            self,
        ) -> t.MappingKV[
            str,
            str
            | bytes
            | int
            | float
            | bool
            | t.SequenceOf[str | bytes | int | float | bool],
        ]:
            """The raw ldap3-style attribute payloads."""
            ...

    @runtime_checkable
    class RootDseConnection(Protocol):
        """Structural protocol for connections that can query rootDSE."""

        @property
        def search(self) -> Callable[..., bool | t.JsonValue | None] | None:
            """The ldap3-compatible search callable when available."""
            ...

        @property
        def result(self) -> t.JsonMapping | None:
            """The raw ldap3 result payload for the last operation."""
            ...

        @property
        def entries(
            self,
        ) -> t.SequenceOf[
            FlextLdifProtocolsLdap3.RootDseEntry
            | str
            | bytes
            | int
            | float
            | bool
            | t.SequenceOf[str | bytes | int | float | bool]
        ]:
            """The entry payloads produced by the last search."""
            ...
