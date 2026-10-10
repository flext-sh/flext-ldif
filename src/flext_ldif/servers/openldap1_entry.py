"""OpenLDAP 1.x legacy entry server.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_ldif import c, m, p, r, t
from flext_ldif.servers._rfc import FlextLdifServersRfcEntry


class FlextLdifServersOpenldap1Entry(FlextLdifServersRfcEntry):
    """OpenLDAP 1.x entry server."""

    @override
    def can_handle(
        self,
        entry_dn: str,
        attributes: t.MutableStrSequenceMapping,
    ) -> bool:
        """Check if this server should handle the entry.

        Returns:
            The resulting ``bool``.
        """
        if not entry_dn:
            return False
        config_marker = "cn=settings"
        is_config_dn = config_marker in entry_dn.lower()
        has_olc_attrs = any(
            attr_name.lower().startswith("olc") for attr_name in attributes
        )
        return not is_config_dn and (not has_olc_attrs)

    @staticmethod
    def process_entry(entry: m.Ldif.Entry) -> p.Result[m.Ldif.Entry]:
        """Process entry for OpenLDAP 1.x format.

        Returns:
            The resulting ``p.Result[m.Ldif.Entry]``.
        """
        try:
            metadata = entry.metadata or m.Ldif.ServerMetadata(
                server_type=c.Ldif.ServerTypes.OPENLDAP1,
            )
            metadata.extensions[c.Ldif.ServerMetadataKeys.IS_TRADITIONAL_DIT] = True
            processed_entry = m.Ldif.Entry(
                dn=entry.dn,
                attributes=entry.attributes,
                metadata=metadata,
            )
            return r[m.Ldif.Entry].ok(processed_entry)
        except c.Ldif.EXC_LDIF_PARSE as e:
            return r[m.Ldif.Entry].fail_op("OpenLDAP 1.x entry processing", e)


__all__: list[str] = ["FlextLdifServersOpenldap1Entry"]
