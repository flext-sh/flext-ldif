"""RFC 4512 Compliant Server Quirks - Base LDAP Schema/ACL/Entry Implementation."""

from __future__ import annotations

from typing import override

from flext_core import FlextLogger

from flext_ldif import (
    FlextLdifServersBase,
    FlextLdifServersRfcAcl,
    FlextLdifServersRfcConstants,
    FlextLdifServersRfcEntry,
    FlextLdifServersRfcSchema,
    m,
    r,
)

logger = FlextLogger(__name__)


class FlextLdifServersRfc(FlextLdifServersBase):
    """RFC-Compliant LDAP Server Implementation - STRICT Baseline."""

    @override
    def _handle_parse_operation(self, ldif_text: str) -> r[m.Ldif.Entry | str]:
        """Handle parse operation for main quirk."""
        return super()._handle_parse_operation(ldif_text)

    @override
    def _handle_write_operation(
        self,
        entries: list[m.Ldif.Entry],
    ) -> r[m.Ldif.Entry | str]:
        """Handle write operation for main quirk."""
        return super()._handle_write_operation(entries)

    @override
    def _route_model_to_write(
        self,
        model: m.Ldif.Entry
        | m.Ldif.SchemaAttribute
        | m.Ldif.SchemaObjectClass
        | m.Ldif.Acl,
    ) -> r[str]:
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


__all__ = ["FlextLdifServersRfc"]
