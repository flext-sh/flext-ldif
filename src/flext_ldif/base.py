"""Shared service base that provides typed LDIF configuration access."""

from __future__ import annotations

from typing import Annotated, Self, override

from flext_core import s
from flext_ldif import FlextLdifSettings, c, m, p, t, u
from flext_ldif.services.server import FlextLdifServer


class FlextLdifServiceBase[TDomainResult = m.Ldif.Response](s[TDomainResult]):
    """Base class for LDIF services with typed settings helper."""

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
    def settings(self) -> p.Ldif.Settings:
        """Return the typed LDIF configuration namespace."""
        resolved = super().settings
        if not isinstance(resolved, p.Ldif.Settings):
            msg = "Runtime settings do not satisfy the LDIF settings contract"
            raise TypeError(msg)
        return resolved

    def __call__(
        self,
        *,
        server: p.Ldif.ServerRegistry | None = None,
        settings: p.Ldif.Settings | None = None,
        **fields: t.JsonValue,
    ) -> Self | m.Ldif.Entry | str:
        """Return a cloned DSL instance preserving runtime registry/settings defaults."""
        payload: dict[
            str,
            t.JsonValue | p.Ldif.ServerRegistry | p.Ldif.Settings | None,
        ] = dict(fields)
        payload["server"] = self._server if server is None else server
        payload["runtime_settings"] = settings
        instance: Self = type(self).model_validate(payload)
        return instance

    def bind_runtime_settings(self, runtime_settings: p.Ldif.Settings | None) -> Self:
        """Bind typed LDIF settings through the inherited runtime bootstrap state."""
        if runtime_settings is not None:
            self._apply_runtime_bootstrap_state({"runtime_settings": runtime_settings})
        return self

    @classmethod
    def _runtime_bootstrap_options(cls) -> m.RuntimeBootstrapOptions:
        """Return runtime bootstrap options for LDIF services."""
        return m.RuntimeBootstrapOptions(settings_type=FlextLdifSettings)

    def _get_effective_server_type_value(self) -> str:
        """Return the default server type used by parser and writer services."""
        default_server_type: str = c.Ldif.ServerTypes.RFC.value
        return default_server_type


s = FlextLdifServiceBase

__all__: list[str] = ["FlextLdifServiceBase", "s"]
