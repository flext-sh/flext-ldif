"""Shared service base that provides typed LDIF configuration access."""

from __future__ import annotations

from flext_core import FlextSettings, s
from flext_core.protocols import p
from flext_core.service import FlextService

from flext_ldif.settings import FlextLdifSettings


class FlextLdifServiceBase[TDomainResult](FlextService[TDomainResult]):
    """Base class for LDIF services with typed config helper."""

    @classmethod
    def _runtime_bootstrap_options(cls) -> p.RuntimeBootstrapOptions:
        """Return runtime bootstrap options for LDIF services."""
        return p.RuntimeBootstrapOptions(config_type=FlextLdifSettings)

    @property
    def ldif_config(self) -> FlextLdifSettings:
        """Return the LDIF configuration namespace with proper typing."""
        return FlextSettings.get_global_instance().get_namespace(
            "ldif", FlextLdifSettings
        )


# Short alias for service base (s is FlextService from flext-core)
# Export s for consistency with other modules (u, m, c, t, p)
# s is already imported from flext_core, so we just need to export it
__all__ = ["FlextLdifServiceBase", "s"]
