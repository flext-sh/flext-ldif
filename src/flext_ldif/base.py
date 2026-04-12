"""Shared service base that provides typed LDIF configuration access."""

from __future__ import annotations

from abc import ABC
from collections.abc import Sequence
from typing import override

from flext_core import FlextSettings, FlextTypes, s
from flext_ldif import FlextLdifSettings, m


class FlextLdifServiceBase[
    TDomainResult: FlextTypes.ValueOrModel | Sequence[FlextTypes.ValueOrModel]
](
    s[TDomainResult],
    ABC,
):
    """Base class for LDIF services with typed settings helper."""

    def __init__(self, settings: FlextLdifSettings | None = None) -> None:
        """Expose the typed LDIF settings bootstrap on the concrete service base."""
        super().__init__(settings=settings)

    @property
    def ldif_config(self) -> FlextLdifSettings:
        """Return the LDIF configuration namespace with proper typing."""
        return FlextSettings.fetch_global().fetch_namespace("ldif", FlextLdifSettings)

    @classmethod
    @override
    def _runtime_bootstrap_options(cls) -> m.RuntimeBootstrapOptions:
        """Return runtime bootstrap options for LDIF services."""
        return m.RuntimeBootstrapOptions(settings_type=FlextLdifSettings)


s = FlextLdifServiceBase

__all__: list[str] = ["FlextLdifServiceBase", "s"]
