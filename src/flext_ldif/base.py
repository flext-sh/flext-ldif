"""Shared service base that provides typed LDIF configuration access."""

from __future__ import annotations

from flext_core import FlextService
from flext_core.typings import T

from flext_ldif.config import FlextLdifConfig


class FlextLdifServiceBase(FlextService[T]):
    """Base class for LDIF services with typed config helper."""

    @property
    def ldif_config(self) -> FlextLdifConfig:
        """Return the LDIF configuration namespace with proper typing."""
        return self.config.get_namespace("ldif", FlextLdifConfig)
