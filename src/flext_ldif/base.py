"""Shared service base that provides typed LDIF configuration access.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

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
        **fields: t.JsonValue,
    ) -> Self | p.Ldif.Entry | str:
        """Return a cloned DSL instance preserving runtime registry/settings.

        defaults.
        """
        payload: t.MutableMappingKV[
            str,
            t.JsonValue | p.Registry | p.Ldif.Settings | None,
        ] = dict(fields)
        if server is not None:
            payload["registry"] = server.registry
        elif isinstance(self, p.Ldif.RegistryBound):
            payload["registry"] = self.registry
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

    def _get_effective_server_type_value(self) -> str:
        """Return the default server type used by parser and writer services."""
        default_server_type: str = c.Ldif.ServerTypes.RFC.value
        return default_server_type


s = FlextLdifServiceBase

__all__: list[str] = ["FlextLdifServiceBase", "s"]
