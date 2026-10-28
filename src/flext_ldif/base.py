"""Shared service base that provides typed LDIF configuration access.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import Self, override

from flext_core import FlextService

from flext_ldif import FlextLdifSettings, c, m, p, t


class FlextLdifServiceBase[TDomainResult](
    FlextService[TDomainResult],
):
    """Base class for LDIF services with typed settings helper."""

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
        registry: p.Registry | None = None,
        **fields: t.JsonValue,
    ) -> Self | TDomainResult | p.Ldif.Entry | str:
        """Configure a service; domain processors may also return their payload.

        Returns:
            The configured service, or a payload supplied by a domain processor.

        """
        return self.configure_runtime(
            server=server, settings=settings, registry=registry, **fields
        )

    def configure_runtime(
        self,
        *,
        server: p.Ldif.ServerRegistry | None = None,
        settings: p.Ldif.Settings | None = None,
        registry: p.Registry | None = None,
        **fields: t.JsonValue,
    ) -> Self:
        """Return a cloned DSL instance preserving runtime registry/settings.

        Raises:
            ValueError: If both server and registry dependencies are supplied.

        """
        payload: MutableMapping[
            str,
            t.JsonValue | p.Registry | p.Ldif.Settings | None,
        ] = dict(fields)
        component: p.Model = self
        if server is not None and registry is not None:
            message = "Provide one explicit registry dependency"
            raise ValueError(message)
        if registry is not None:
            payload["registry"] = registry
        elif server is not None:
            payload["registry"] = server.registry
        elif isinstance(component, p.Ldif.RegistryBound):
            payload["registry"] = component.registry
        payload["runtime_settings"] = self.settings if settings is None else settings
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
    def runtime_bootstrap_options(cls) -> p.RuntimeBootstrapOptions:
        """Return runtime bootstrap options for LDIF services."""
        return m.RuntimeBootstrapOptions(settings_type=FlextLdifSettings)

    @staticmethod
    def _get_effective_server_type_value() -> str:
        """Return the default server type used by parser and writer services."""
        default_server_type: str = c.Ldif.ServerTypes.RFC.value
        return default_server_type


s = FlextLdifServiceBase

__all__: list[str] = ["FlextLdifServiceBase", "s"]
