"""Shared service base that provides typed LDIF configuration access."""

from __future__ import annotations

from typing import Annotated, Self, override

from flext_core import s
from flext_ldif import FlextLdifServer, FlextLdifSettings, c, m, p, t, u


class FlextLdifServiceBase[TDomainResult = m.Ldif.Response](s[TDomainResult]):
    """Base class for LDIF services with typed settings helper."""

    _cached_settings: FlextLdifSettings | None = u.PrivateAttr(
        default_factory=lambda: None,
    )
    _server: p.Ldif.ServerRegistry = u.PrivateAttr(
        default_factory=FlextLdifServer.fetch_global_instance,
    )
    server: Annotated[
        p.Ldif.ServerRegistry | None,
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
        if self._cached_settings is None:
            self._cached_settings = FlextLdifSettings.fetch_global()
        return self._cached_settings

    def __call__(
        self,
        *,
        server: p.Ldif.ServerRegistry | None = None,
        settings: FlextLdifSettings | None = None,
        **fields: t.JsonValue,
    ) -> Self:
        """Return a cloned DSL instance preserving runtime registry/settings defaults."""
        payload: dict[str, t.JsonValue | p.Ldif.ServerRegistry | None] = dict(fields)
        payload["server"] = self._server if server is None else server
        instance: Self = type(self).model_validate(payload)
        if settings is not None:
            instance._cached_settings = settings
        return instance

    @classmethod
    def _runtime_bootstrap_options(cls) -> m.RuntimeBootstrapOptions:
        """Return runtime bootstrap options for LDIF services."""
        return m.RuntimeBootstrapOptions(settings_type=FlextLdifSettings)

    def _get_effective_server_type_value(self) -> str:
        """Return the default server type used by parser and writer services."""
        return c.Ldif.ServerTypes.RFC.value


s = FlextLdifServiceBase

__all__: list[str] = ["FlextLdifServiceBase", "s"]
