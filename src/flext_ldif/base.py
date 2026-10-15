"""Shared service base that provides typed LDIF configuration access.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Self, override

import flext_ldif
from flext_core import FlextService
from flext_ldif import FlextLdifSettings, c, m, p, t, u

if TYPE_CHECKING:
    from flext_ldif.services import FlextLdifServer


class FlextLdifServiceBase[TDomainResult](
    FlextService[TDomainResult],
):
    """Base class for LDIF services with typed settings helper."""

    @staticmethod
    def _default_ldif_server() -> p.Ldif.ServerRegistry:
        """Resolve the shared server lazily (cuts the base/server init cycle).

        Returns:
            The resulting value.
        """
        # The root facade resolves its exports lazily (PEP 562), so the
        # base/server init cycle stays cut: the server module loads on the
        # first default_factory call, never at import time.
        instance: FlextLdifServer = flext_ldif.FlextLdifServer.fetch_global_instance()
        return instance

    _server: p.Ldif.ServerRegistry = u.PrivateAttr(
        default_factory=_default_ldif_server,
    )
    registry: Annotated[
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
        if self.registry is not None:
            self._server = self.registry

    @property
    @override
    def settings(self) -> p.Ldif.Settings:
        """The typed LDIF configuration namespace.

        Raises:
            TypeError: If Runtime settings do not satisfy the LDIF settings contract.
        """
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
        """Return a cloned DSL instance preserving runtime registry/settings.

        defaults.
        """
        payload: t.MutableMappingKV[
            str,
            t.JsonValue | p.Ldif.ServerRegistry | p.Ldif.Settings | None,
        ] = dict(fields)
        payload["registry"] = self._server if server is None else server
        payload["runtime_settings"] = settings
        instance: Self = type(self).model_validate(payload)
        return instance

    def bind_runtime_settings(self, runtime_settings: p.Ldif.Settings | None) -> Self:
        """Bind typed LDIF settings through the inherited runtime bootstrap field.

        Returns:
            The resulting ``Self``.
        """
        # NOTE (multi-agent): mro-i6nq.12 — FlextMixins runtime-bootstrap is now a
        # native Pydantic field; assign directly (validate_assignment enforces type).
        if runtime_settings is not None:
            self.runtime_settings = runtime_settings
        return self

    @classmethod
    def runtime_bootstrap_options(cls) -> m.RuntimeBootstrapOptions:
        """Return runtime bootstrap options for LDIF services."""
        return m.RuntimeBootstrapOptions(settings_type=FlextLdifSettings)

    def _get_effective_server_type_value(self) -> str:
        """Return the default server type used by parser and writer services."""
        _ = self
        default_server_type: str = c.Ldif.ServerTypes.RFC.value
        return default_server_type


s = FlextLdifServiceBase

__all__: list[str] = ["FlextLdifServiceBase", "s"]
