"""Shared service base that provides typed LDIF configuration access."""

from __future__ import annotations

import builtins
from abc import ABC
from typing import override

from flext_core import FlextService, FlextSettings

from flext_ldif import FlextLdifSettings, m


class FlextLdifServiceBase[TDomainResult: builtins.object](
    FlextService[TDomainResult],
    ABC,
):
    """Base class for LDIF services with typed config helper."""

    @property
    def ldif_config(self) -> FlextLdifSettings:
        """Return the LDIF configuration namespace with proper typing."""
        return FlextSettings.get_global().get_namespace("ldif", FlextLdifSettings)

    @classmethod
    @override
    def _runtime_bootstrap_options(cls) -> m.RuntimeBootstrapOptions:
        """Return runtime bootstrap options for LDIF services."""
        return m.RuntimeBootstrapOptions(config_type=FlextLdifSettings)


s = FlextLdifServiceBase
__all__ = ["FlextLdifServiceBase", "s"]
