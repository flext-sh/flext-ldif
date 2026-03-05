"""Shared service base that provides typed LDIF configuration access."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from types import ModuleType
from typing import override

from pydantic_settings import BaseSettings

from flext_core import FlextService, FlextSettings, p, s, t

from flext_ldif.settings import FlextLdifSettings


class FlextLdifServiceBase[TDomainResult](FlextService[TDomainResult]):
    """Base class for LDIF services with typed config helper."""

    class RuntimeBootstrapOptions:
        """Concrete runtime bootstrap options compatible with core protocol."""

        def __init__(
            self,
            *,
            config_type: type[BaseSettings] | None = None,
        ) -> None:
            self.config_type: type[BaseSettings] | None = config_type
            self.config_overrides: Mapping[str, t.Scalar] | None = None
            self.context: p.Context | None = None
            self.subproject: str | None = None
            self.services: Mapping[str, t.RegisterableService] | None = None
            self.factories: Mapping[str, t.FactoryCallable] | None = None
            self.resources: Mapping[str, t.ResourceCallable] | None = None
            self.container_overrides: Mapping[str, t.Scalar] | None = None
            self.wire_modules: Sequence[ModuleType] | None = None
            self.wire_packages: Sequence[str] | None = None
            self.wire_classes: Sequence[type] | None = None

    @classmethod
    @override
    def _runtime_bootstrap_options(cls) -> p.RuntimeBootstrapOptions:
        """Return runtime bootstrap options for LDIF services."""
        options: p.RuntimeBootstrapOptions = cls.RuntimeBootstrapOptions(
            config_type=FlextLdifSettings,
        )
        return options

    @property
    def ldif_config(self) -> FlextLdifSettings:
        """Return the LDIF configuration namespace with proper typing."""
        return FlextSettings.get_global().get_namespace(
            "ldif",
            FlextLdifSettings,
        )


# Short alias for service base (s is FlextService from flext-core)
# Export s for consistency with other modules (u, m, c, t, p)
# s is already imported from flext_core, so we just need to export it
__all__ = ["FlextLdifServiceBase", "s"]
