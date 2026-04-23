"""Shared service base that provides typed LDIF configuration access."""

from __future__ import annotations

from abc import ABC
from typing import Annotated, override

from flext_core import FlextSettings, s

from flext_ldif import FlextLdifServer, FlextLdifSettings, c, m, t, u


class FlextLdifServiceBase(s[m.Ldif.Response], ABC):
    """Base class for LDIF services with typed settings helper."""

    _server: FlextLdifServer = u.PrivateAttr(
        default_factory=FlextLdifServer.get_global_instance,
    )
    server: Annotated[
        FlextLdifServer | None,
        u.Field(
            exclude=True,
            description="LDIF server registry used directly by service mixins.",
        ),
    ] = None

    @override
    def model_post_init(self, __context: t.JsonMapping | None, /) -> None:
        """Bind the shared LDIF server registry after Pydantic initialization."""
        super().model_post_init(__context)
        if self.server is not None:
            self._server = self.server

    @property
    @override
    def settings(self) -> FlextLdifSettings:
        """Return the typed LDIF configuration namespace."""
        return FlextSettings.fetch_global().fetch_namespace("ldif", FlextLdifSettings)

    @classmethod
    def _runtime_bootstrap_options(cls) -> m.RuntimeBootstrapOptions:
        """Return runtime bootstrap options for LDIF services."""
        return m.RuntimeBootstrapOptions(settings_type=FlextLdifSettings)

    def _get_effective_server_type_value(self) -> str:
        """Return the default server type used by parser and writer services."""
        return c.Ldif.ServerTypes.RFC.value


s = FlextLdifServiceBase

__all__: list[str] = ["FlextLdifServiceBase", "s"]
