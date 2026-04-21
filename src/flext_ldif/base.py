"""Shared service base that provides typed LDIF configuration access."""

from __future__ import annotations

from abc import ABC
from typing import override

from flext_core import FlextSettings, s

from flext_ldif import FlextLdifServer, FlextLdifSettings, c, m, p, r, u


class FlextLdifServiceBase(s[m.Ldif.Response], ABC):
    """Base class for LDIF services with typed settings helper."""

    _server: FlextLdifServer = u.PrivateAttr()

    def __init__(
        self,
        *,
        server: FlextLdifServer | None = None,
        settings: FlextLdifSettings | None = None,
    ) -> None:
        """Initialize the typed LDIF service runtime."""
        super().__init__(runtime_settings=settings)
        object.__setattr__(
            self,
            "_server",
            server or FlextLdifServer.get_global_instance(),
        )

    @override
    def execute(self) -> p.Result[m.Ldif.Response]:
        """Return the canonical LDIF domain response for DSL service execution."""
        return r[m.Ldif.Response].ok(
            m.Ldif.Response(statistics=m.Ldif.Statistics()),
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

    @staticmethod
    def _get_effective_server_type_value() -> str:
        """Return the default server type used by parser and writer services."""
        return c.Ldif.ServerTypes.RFC.value


s = FlextLdifServiceBase

__all__: list[str] = ["FlextLdifServiceBase", "s"]
