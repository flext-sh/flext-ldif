"""Shared service base that provides typed LDIF configuration access."""

from __future__ import annotations

from abc import ABC
from collections.abc import Sequence
from typing import override

from flext_core import FlextSettings, s
from flext_ldif import FlextLdifServer, FlextLdifSettings, m, t


class FlextLdifServiceBase[TDomainResult: t.ValueOrModel | Sequence[t.ValueOrModel]](
    s[TDomainResult],
    ABC,
):
    """Base class for LDIF services with typed settings helper."""

    def __init__(
        self,
        *,
        server: FlextLdifServer | None = None,
        settings: FlextLdifSettings | None = None,
    ) -> None:
        """Initialize the typed LDIF service runtime."""
        super().__init__(settings=settings)
        object.__setattr__(
            self,
            "_server",
            server or FlextLdifServer.get_global_instance(),
        )

    @property
    @override
    def settings(self) -> FlextLdifSettings:
        """Return the typed LDIF configuration namespace."""
        return FlextSettings.fetch_global().fetch_namespace("ldif", FlextLdifSettings)

    @classmethod
    @override
    def _runtime_bootstrap_options(cls) -> m.RuntimeBootstrapOptions:
        """Return runtime bootstrap options for LDIF services."""
        return m.RuntimeBootstrapOptions(settings_type=FlextLdifSettings)


s = FlextLdifServiceBase

__all__: list[str] = ["FlextLdifServiceBase", "s"]
