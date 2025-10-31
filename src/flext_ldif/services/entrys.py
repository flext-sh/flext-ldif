"""Entry quirks module for LDIF processing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import override

from flext_core import FlextResult, FlextService

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.dn import FlextLdifDnService
from flext_ldif.services.registry import FlextLdifRegistry


class FlextLdifEntrys(FlextService[dict[str, object]]):
    """Entry adaptation and validation for server-specific quirks."""

    @override
    def __init__(self) -> None:
        """Initialize entry quirks handler.

        Uses quirks registry for server-specific entry processing.

        """
        super().__init__()
        self._registry = FlextLdifRegistry.get_global_instance()

    @override
    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute entry quirks service."""
        return FlextResult[dict[str, object]].ok({
            "service": FlextLdifEntrys,
            "status": "ready",
        })

    def clean_dn(self, dn: str) -> str:
        """Clean a DN string before it's processed.

        This acts as a hook for server-specific quirks to fix common
        formatting issues in DNs from specific LDAP server exports.

        Fixes applied:
        - Removes spaces around '=' in RDN components (e.g., "cn = value" -> "cn=value")
        - Fixes malformed backslash escapes
        - Normalizes whitespace

        Args:
            dn: The original DN string from the LDIF file.

        Returns:
            The cleaned DN string.

        """
        # Use DN utils for proper RFC 4514 compliant cleaning
        return FlextLdifDnService.clean_dn(dn)

    def adapt_entry(
        self,
        entry: FlextLdifModels.Entry,
        _target_server: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Adapt entry for specific server type.

        Strips COMMON operational attributes to ensure portability across servers.
        Server-specific operational attributes are only stripped if known to be present
        in the entry's source server type.

        Args:
            entry: Entry to adapt
            _target_server: Target server type (required, reserved for future use)

        Returns:
            FlextResult containing adapted entry

        """
        # Only strip COMMON operational attributes by default
        # This is conservative: we only strip attributes that are universally operational
        # across all LDAP servers (createTimestamp, modifyTimestamp, etc.)
        # Server-specific attributes are only stripped if we explicitly know the source
        operational_attrs = set(FlextLdifConstants.OperationalAttributes.COMMON)

        adapted_attrs: dict[str, list[str]] = {}
        operational_attrs_lower = {attr.lower() for attr in operational_attrs}

        # Process attributes - strip operational ones
        for attr_name, attr_values in entry.attributes.attributes.items():
            # Skip operational attributes (case-insensitive check)
            if attr_name.lower() in operational_attrs_lower:
                if self.logger is not None:
                    self.logger.debug(
                        f"Stripped operational attribute '{attr_name}' from {entry.dn.value}",
                    )
                continue

            # Keep attribute as-is (no transformations needed for now)
            adapted_attrs[attr_name] = attr_values.copy()

        # Convert adapted_attrs to LdifAttributes
        ldif_attributes = FlextLdifModels.LdifAttributes(attributes=adapted_attrs)

        # Create adapted entry
        adapted_entry_result: FlextResult[FlextLdifModels.Entry] = (
            FlextLdifModels.Entry.create(
                dn=entry.dn,
                attributes=ldif_attributes,
            )
        )
        if adapted_entry_result.is_failure:
            error_msg = f"Failed to create adapted entry: {adapted_entry_result.error}"
            if self.logger is not None:
                self.logger.error(error_msg)
            return FlextResult[FlextLdifModels.Entry].fail(error_msg)

        return adapted_entry_result

    def _get_operational_attrs(self, server_type: str) -> list[str]:
        """Get operational attributes for specific server type.

        Combines COMMON operational attributes with server-specific ones.

        Args:
        server_type: Source LDAP server type (case-insensitive)

        Returns:
        List of operational attribute names to strip

        """
        # Start with common operational attributes
        operational_attrs = set(FlextLdifConstants.OperationalAttributes.COMMON)

        # Normalize server type for matching (case-insensitive)
        server_lower = server_type.lower()

        # Add server-specific operational attributes using ServerTypes constants
        # Check more specific patterns first to avoid substring matches
        # Use ServerTypes constants instead of string literals
        if (
            server_lower == FlextLdifConstants.ServerTypes.OPENLDAP.lower()
            or server_lower == FlextLdifConstants.ServerTypes.OPENLDAP1.lower()
            or server_lower == FlextLdifConstants.ServerTypes.OPENLDAP2.lower()
            or FlextLdifConstants.LdapServers.OPENLDAP in server_lower
        ):
            operational_attrs |= (
                FlextLdifConstants.OperationalAttributes.OPENLDAP_SPECIFIC
            )
        elif (
            server_lower == FlextLdifConstants.ServerTypes.OID.lower()
            or FlextLdifConstants.LdapServers.ORACLE_OID in server_lower
        ):
            operational_attrs |= FlextLdifConstants.OperationalAttributes.OID_SPECIFIC
        elif (
            server_lower == FlextLdifConstants.ServerTypes.OUD.lower()
            or FlextLdifConstants.LdapServers.ORACLE_OUD in server_lower
        ):
            operational_attrs |= FlextLdifConstants.OperationalAttributes.OUD_SPECIFIC
        elif (
            server_lower == FlextLdifConstants.ServerTypes.DS_389.lower()
            or FlextLdifConstants.LdapServers.DS_389 in server_lower
        ):
            operational_attrs |= (
                FlextLdifConstants.OperationalAttributes.DS_389_SPECIFIC
            )
        elif (
            server_lower == FlextLdifConstants.ServerTypes.AD.lower()
            or FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY in server_lower
        ):
            operational_attrs |= FlextLdifConstants.OperationalAttributes.AD_SPECIFIC
        elif FlextLdifConstants.LdapServers.NOVELL_EDIRECTORY in server_lower:
            operational_attrs |= (
                FlextLdifConstants.OperationalAttributes.NOVELL_SPECIFIC
            )
        elif FlextLdifConstants.LdapServers.IBM_TIVOLI in server_lower:
            operational_attrs |= (
                FlextLdifConstants.OperationalAttributes.IBM_TIVOLI_SPECIFIC
            )

        return list(operational_attrs)


__all__ = ["FlextLdifEntrys"]
