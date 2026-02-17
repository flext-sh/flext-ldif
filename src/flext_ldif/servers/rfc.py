"""RFC 4512 Compliant Server Quirks - Base LDAP Schema/ACL/Entry Implementation."""

from __future__ import annotations

from flext_core import FlextLogger, FlextResult

from flext_ldif.models import m
from flext_ldif.servers._rfc import (
    FlextLdifServersRfcAcl,
    FlextLdifServersRfcConstants,
    FlextLdifServersRfcEntry,
    FlextLdifServersRfcSchema,
)
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.typings import t

logger = FlextLogger(__name__)


class FlextLdifServersRfc(FlextLdifServersBase):
    """RFC-Compliant LDAP Server Implementation - STRICT Baseline."""

    def _handle_parse_operation(
        self,
        ldif_text: str,
    ) -> FlextResult[m.Ldif.Entry | str]:
        """Handle parse operation for main quirk."""
        return super()._handle_parse_operation(ldif_text)

    def _handle_write_operation(
        self,
        entries: list[m.Ldif.Entry],
    ) -> FlextResult[m.Ldif.Entry | str]:
        """Handle write operation for main quirk."""
        return super()._handle_write_operation(entries)

    def _route_model_to_write(
        self,
        model: t.Ldif.ConvertibleModel,
    ) -> FlextResult[str]:
        """Route a single model to appropriate write method."""
        return super()._route_model_to_write(model)

    class Constants(FlextLdifServersRfcConstants):
        """RFC baseline constants (RFC 4512 compliant)."""

    class Acl(FlextLdifServersRfcAcl):
        """Aclbaseline constants (RFC 4512 compliant)."""

    class Schema(FlextLdifServersRfcSchema):
        """RFC baseline constants (RFC 4512 compliant)."""

    class Entry(FlextLdifServersRfcEntry):
        """RFC baseline constants (RFC 4512 compliant)."""


__all__ = [
    "FlextLdifServersRfc",
]
