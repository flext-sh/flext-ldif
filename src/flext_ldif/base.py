"""Shared service base that provides typed LDIF configuration access."""

from __future__ import annotations

from typing import Annotated, Self, override

from flext_core import s
from flext_ldif import FlextLdifSettings, c, m, p, t, u
from flext_ldif.services.server import FlextLdifServer


class FlextLdifServiceBase[TDomainResult = m.Ldif.Response](s[TDomainResult]):
    """Base class for LDIF services with typed settings helper."""

    server: Annotated[
        p.Ldif.ServerRegistry,
        u.Field(
            exclude=True,
            description="LDIF server registry used directly by service mixins.",
        ),
    ] = u.Field(default_factory=FlextLdifServer.fetch_global)

    @property
    @override
    def settings(self) -> p.Ldif.Settings:
        """Runtime settings after enforcement of the LDIF settings contract."""
        runtime_settings = super().settings
        if not isinstance(runtime_settings, p.Ldif.Settings):
            msg = "Runtime settings do not implement the LDIF settings contract"
            raise TypeError(msg)
        return runtime_settings

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
        payload["server"] = self.server if server is None else server
        payload["runtime_settings"] = settings
        instance: Self = type(self).model_validate(payload)
        return instance

    def bind_runtime_settings(self, runtime_settings: p.Ldif.Settings | None) -> Self:
        """Bind typed LDIF settings through the inherited runtime bootstrap field."""
        # NOTE (multi-agent): mro-i6nq.12 — FlextMixins runtime-bootstrap is now a
        # native Pydantic field; assign directly (validate_assignment enforces type).
        if runtime_settings is not None:
            self.runtime_settings = runtime_settings
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
