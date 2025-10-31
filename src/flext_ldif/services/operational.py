"""RFC 4512 Operational Attributes Service - Management and Filtering.

This module provides comprehensive operational attribute handling for LDAP directory
processing, implementing RFC 4512 operational attribute standards with server-specific
extensions.

RFC 4512: LDAP Schema - Operational Attributes
- Defines server-generated, read-only attributes (creatorsName, createTimestamp, etc.)
- Specifies operational attribute behavior across all LDAP servers
- Requires special handling during directory migration and synchronization

The FlextLdifOperationalService provides:
1. Operational attribute validation and detection
2. Server-specific operational attribute identification
3. Entry filtering to exclude operational attributes
4. Type-safe operational attribute management

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import override

from flext_core import FlextDecorators, FlextResult, FlextService

from flext_ldif.constants import FlextLdifConstants


class FlextLdifOperationalService(FlextService[dict[str, object]]):
    """RFC 4512 operational attributes validation and management service.

    Provides methods for identifying, validating, and filtering operational attributes
    (server-generated, read-only attributes) across different LDAP directory servers
    following RFC 4512 (LDAP Schema - Operational Attributes).

    Operational attributes are system-managed and cannot be directly modified:
    - creatorsName, createTimestamp - RFC 4512 standard
    - modifiersName, modifyTimestamp - RFC 4512 standard
    - entryUUID, entryCSN - Various server implementations
    - Server-specific: orclGUID (OID), ds-sync-* (OUD), etc.

    Example:
        >>> operational_service = FlextLdifOperationalService()
        >>>
        >>> # Check if attribute is operational
        >>> result = operational_service.is_operational("createTimestamp")
        >>> if result.is_success:
        >>>     is_op = result.unwrap()  # True
        >>>
        >>> # Get operational attributes for specific server
        >>> result = operational_service.get_server_operational_attributes("oud")
        >>> if result.is_success:
        >>>     attrs = result.unwrap()
        >>>
        >>> # Check if attribute is operational for specific server
        >>> result = operational_service.is_operational_for_server(
        ...     "ds-sync-hist", "oud"
        ... )
        >>> if result.is_success:
        >>>     is_op = result.unwrap()  # True

    """

    def __init__(self) -> None:
        """Initialize Operational Attributes service."""
        super().__init__()
        # Build operational attribute lookup tables from constants
        self._common_operational: frozenset[str] = (
            FlextLdifConstants.OperationalAttributes.COMMON
        )
        self._oid_specific: frozenset[str] = (
            FlextLdifConstants.OperationalAttributes.OID_SPECIFIC
        )
        self._oud_specific: frozenset[str] = (
            FlextLdifConstants.OperationalAttributes.OUD_SPECIFIC
        )
        self._openldap_specific: frozenset[str] = (
            FlextLdifConstants.OperationalAttributes.OPENLDAP_SPECIFIC
        )
        self._ds389_specific: frozenset[str] = (
            FlextLdifConstants.OperationalAttributes.DS_389_SPECIFIC
        )
        self._ad_specific: frozenset[str] = (
            FlextLdifConstants.OperationalAttributes.AD_SPECIFIC
        )
        self._novell_specific: frozenset[str] = (
            FlextLdifConstants.OperationalAttributes.NOVELL_SPECIFIC
        )
        self._ibm_tivoli_specific: frozenset[str] = (
            FlextLdifConstants.OperationalAttributes.IBM_TIVOLI_SPECIFIC
        )

    @override
    @FlextDecorators.log_operation("operational_service_check")
    @FlextDecorators.track_performance()
    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute Operational service self-check.

        FlextDecorators automatically:
        - Log operation start/completion/failure
        - Track performance metrics
        - Handle context propagation (correlation_id, operation_name)

        Returns:
            FlextResult containing service status

        """
        return FlextResult[dict[str, object]].ok({
            "service": "OperationalService",
            "status": "operational",
            "rfc_compliance": "RFC 4512",
            "common_operational_attributes": len(self._common_operational),
            "oid_specific_attributes": len(self._oid_specific),
            "oud_specific_attributes": len(self._oud_specific),
            "openldap_specific_attributes": len(self._openldap_specific),
            "ds389_specific_attributes": len(self._ds389_specific),
            "ad_specific_attributes": len(self._ad_specific),
            "novell_specific_attributes": len(self._novell_specific),
            "ibm_tivoli_specific_attributes": len(self._ibm_tivoli_specific),
        })

    def is_operational(self, attribute_name: str) -> FlextResult[bool]:
        """Check if attribute is operational (common across all servers).

        Args:
            attribute_name: Attribute name (case-sensitive)

        Returns:
            FlextResult containing True if attribute is RFC 4512 operational

        Example:
            >>> result = service.is_operational("createTimestamp")
            >>> if result.is_success:
            >>>     is_op = result.unwrap()  # True

        """
        if not attribute_name or not isinstance(attribute_name, str):
            return FlextResult[bool].ok(False)

        is_op = attribute_name in self._common_operational
        return FlextResult[bool].ok(is_op)

    def is_operational_for_server(
        self,
        attribute_name: str,
        server_type: str,
    ) -> FlextResult[bool]:
        """Check if attribute is operational for specific LDAP server.

        Includes both common RFC 4512 operational attributes and server-specific
        operational attributes.

        Args:
            attribute_name: Attribute name (case-sensitive)
            server_type: LDAP server type ("oid", "oud", "openldap", "ad", "ds389", "novell", "tivoli")

        Returns:
            FlextResult containing True if attribute is operational for that server

        Example:
            >>> result = service.is_operational_for_server("ds-sync-hist", "oud")
            >>> if result.is_success:
            >>>     is_op = result.unwrap()  # True

        """
        if not attribute_name or not isinstance(attribute_name, str):
            return FlextResult[bool].ok(False)

        # All servers have common operational attributes
        if attribute_name in self._common_operational:
            return FlextResult[bool].ok(True)

        # Check server-specific operational attributes
        server_lower = str(server_type).lower()

        server_specific_sets = {
            "oid": self._oid_specific,
            "oud": self._oud_specific,
            "openldap": self._openldap_specific,
            "openldap1": self._openldap_specific,
            "openldap2": self._openldap_specific,
            "ds389": self._ds389_specific,
            "389": self._ds389_specific,
            "ad": self._ad_specific,
            "active_directory": self._ad_specific,
            "novell": self._novell_specific,
            "edirectory": self._novell_specific,
            "tivoli": self._ibm_tivoli_specific,
            "ibm": self._ibm_tivoli_specific,
            "rfc": frozenset(),  # RFC has only common operational attributes
        }

        server_attrs = server_specific_sets.get(server_lower, frozenset())
        is_op = attribute_name in server_attrs
        return FlextResult[bool].ok(is_op)

    def get_common_operational_attributes(self) -> FlextResult[frozenset[str]]:
        """Get all RFC 4512 common operational attributes.

        Returns:
            FlextResult containing frozenset of common operational attribute names

        Example:
            >>> result = service.get_common_operational_attributes()
            >>> if result.is_success:
            >>>     attrs = result.unwrap()
            >>>     assert "createTimestamp" in attrs

        """
        return FlextResult[frozenset[str]].ok(self._common_operational)

    def get_server_operational_attributes(
        self,
        server_type: str,
    ) -> FlextResult[frozenset[str]]:
        """Get all operational attributes for specific LDAP server.

        Includes both common RFC 4512 operational attributes and server-specific
        operational attributes.

        Args:
            server_type: LDAP server type ("oid", "oud", "openldap", "ad", "ds389", "novell", "tivoli")

        Returns:
            FlextResult containing frozenset of operational attribute names

        Example:
            >>> result = service.get_server_operational_attributes("oud")
            >>> if result.is_success:
            >>>     attrs = result.unwrap()
            >>>     assert "ds-sync-hist" in attrs

        """
        server_lower = str(server_type).lower()

        server_specific_sets = {
            "oid": self._oid_specific,
            "oud": self._oud_specific,
            "openldap": self._openldap_specific,
            "openldap1": self._openldap_specific,
            "openldap2": self._openldap_specific,
            "ds389": self._ds389_specific,
            "389": self._ds389_specific,
            "ad": self._ad_specific,
            "active_directory": self._ad_specific,
            "novell": self._novell_specific,
            "edirectory": self._novell_specific,
            "tivoli": self._ibm_tivoli_specific,
            "ibm": self._ibm_tivoli_specific,
            "rfc": frozenset(),  # RFC has only common operational attributes
        }

        server_specific = server_specific_sets.get(server_lower, frozenset())

        # Combine common and server-specific operational attributes
        all_operational = frozenset(self._common_operational | server_specific)
        return FlextResult[frozenset[str]].ok(all_operational)

    def filter_operational_attributes(
        self,
        attributes: dict[str, list[str]],
        server_type: str = "rfc",
    ) -> FlextResult[dict[str, list[str]]]:
        """Filter out operational attributes from attribute dictionary.

        Returns a new dictionary with operational attributes removed.
        Preserves all user attributes while excluding system-generated attributes.

        Args:
            attributes: Dictionary mapping attribute names to lists of values
            server_type: LDAP server type for server-specific filtering

        Returns:
            FlextResult containing new dict with operational attributes filtered out

        Example:
            >>> attrs = {
            ...     "cn": ["John Doe"],
            ...     "mail": ["john@example.com"],
            ...     "createTimestamp": ["20250101120000Z"],
            ...     "modifiersName": ["cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"],
            ... }
            >>> result = service.filter_operational_attributes(attrs, "oud")
            >>> if result.is_success:
            >>>     filtered = result.unwrap()
            >>>     assert "cn" in filtered
            >>>     assert "createTimestamp" not in filtered

        """
        if not attributes:
            return FlextResult[dict[str, list[str]]].ok({})

        # Get operational attributes for this server
        operational_result = self.get_server_operational_attributes(server_type)
        if operational_result.is_failure:
            return FlextResult[dict[str, list[str]]].fail(
                f"Cannot filter - unknown server type: {server_type}",
            )

        operational_attrs = operational_result.unwrap()

        # Filter: keep only non-operational attributes
        filtered: dict[str, list[str]] = {
            attr_name: attr_values
            for attr_name, attr_values in attributes.items()
            if attr_name not in operational_attrs
        }

        return FlextResult[dict[str, list[str]]].ok(filtered)

    def get_operational_attribute_count(
        self,
        attributes: dict[str, list[str]],
        server_type: str = "rfc",
    ) -> FlextResult[int]:
        """Count how many operational attributes exist in attribute dictionary.

        Args:
            attributes: Dictionary mapping attribute names to lists of values
            server_type: LDAP server type for server-specific counting

        Returns:
            FlextResult containing count of operational attributes found

        Example:
            >>> attrs = {"cn": ["John"], "createTimestamp": ["20250101120000Z"]}
            >>> result = service.get_operational_attribute_count(attrs, "oud")
            >>> if result.is_success:
            >>>     count = result.unwrap()  # 1

        """
        if not attributes:
            return FlextResult[int].ok(0)

        # Get operational attributes for this server
        operational_result = self.get_server_operational_attributes(server_type)
        if operational_result.is_failure:
            return FlextResult[int].fail(
                f"Cannot count - unknown server type: {server_type}",
            )

        operational_attrs = operational_result.unwrap()

        # Count operational attributes present
        count = sum(1 for attr_name in attributes if attr_name in operational_attrs)

        return FlextResult[int].ok(count)


__all__ = [
    "FlextLdifOperationalService",
]
