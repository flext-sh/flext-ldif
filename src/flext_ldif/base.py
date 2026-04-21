"""Shared service base that provides typed LDIF configuration access."""

from __future__ import annotations

from abc import ABC
from collections.abc import Mapping
from typing import Annotated, override

from flext_core import FlextSettings, s

from flext_ldif import FlextLdifServer, FlextLdifSettings, c, m, p, r, t, u


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
    runtime_settings: Annotated[
        FlextLdifSettings | None,
        u.Field(
            exclude=True,
            description="Typed LDIF settings instance used for runtime bootstrap.",
        ),
    ] = None

    @override
    def model_post_init(self, __context: Mapping[str, t.Container] | None, /) -> None:
        """Bind the shared LDIF server registry after Pydantic initialization."""
        super().model_post_init(__context)
        if self.server is not None:
            self._server = self.server

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
