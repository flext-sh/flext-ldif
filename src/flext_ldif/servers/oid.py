"""Oracle Internet Directory (OID) Quirks."""

from __future__ import annotations

from collections.abc import MutableMapping, MutableSequence

from flext_core import FlextLogger

from flext_ldif import (
    FlextLdifServersOidAcl,
    FlextLdifServersOidConstants,
    FlextLdifServersOidEntry,
    FlextLdifServersOidSchema,
    FlextLdifServersRfc,
    m,
    r,
)

logger = FlextLogger(__name__)


class FlextLdifServersOid(FlextLdifServersRfc):
    """Oracle OID server quirks - implements t.NormalizedValue."""

    class Constants(FlextLdifServersOidConstants):
        """OID server constants."""

    class Acl(FlextLdifServersOidAcl):
        """OID ACL quirk."""

    class Schema(FlextLdifServersOidSchema):
        """OID Schema quirk."""

    class Entry(FlextLdifServersOidEntry):
        """OID Entry quirk."""
