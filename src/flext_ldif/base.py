"""Shared service base that provides typed LDIF configuration access."""

from __future__ import annotations

from typing import override

from flext_core import FlextService, FlextSettings, p, s, t

from flext_ldif.settings import FlextLdifSettings


class FlextLdifServiceBase[TDomainResult: t.ContainerValue](
    FlextService[TDomainResult]
):
    """Base class for LDIF services with typed config helper."""

    @property
    def ldif_config(self) -> FlextLdifSettings:
        """Return the LDIF configuration namespace with proper typing."""
        return FlextSettings.get_global().get_namespace("ldif", FlextLdifSettings)

    @classmethod
    @override
    def _runtime_bootstrap_options(cls) -> p.RuntimeBootstrapOptions:
        """Return runtime bootstrap options for LDIF services."""
        options = super()._runtime_bootstrap_options()
        model_copy = getattr(options, "model_copy", None)
        if model_copy:
            return model_copy(update={"config_type": FlextLdifSettings})
        options.config_type = FlextLdifSettings
        return options


__all__ = ["FlextLdifServiceBase", "s"]
