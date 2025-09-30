"""Unified LDAP Server Quirks Manager.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks import constants


class FlextLdifQuirksManager(FlextService[dict[str, object]]):
    """Unified quirks manager for all LDAP server types.

    Coordinates server-specific handling for schemas, ACLs, and entries
    across different LDAP implementations.
    """

    @override
    def __init__(self, server_type: str | None = None) -> None:
        """Initialize quirks manager.

        Args:
            server_type: LDAP server type (defaults to generic)

        """
        super().__init__()
        self._logger = FlextLogger(__name__)
        self._server_type = server_type or constants.SERVER_TYPE_GENERIC
        self._quirks_registry: dict[str, dict[str, object]] = {}
        self._setup_quirks()

    @property
    def server_type(self) -> str:
        """Get the current server type."""
        return self._server_type

    def _setup_quirks(self) -> None:
        """Setup server-specific quirks registry."""
        self._quirks_registry = {
            constants.SERVER_TYPE_OPENLDAP: {
                "acl_attribute": "olcAccess",
                "acl_format": "openldap",
                "schema_subentry": "cn=subschema",
                "supports_operational_attrs": True,
            },
            constants.SERVER_TYPE_389DS: {
                "acl_attribute": "aci",
                "acl_format": "389ds",
                "schema_subentry": "cn=schema",
                "supports_operational_attrs": True,
            },
            constants.SERVER_TYPE_ORACLE_OID: {
                "acl_attribute": "orclaci",
                "acl_format": "oracle",
                "schema_subentry": "cn=subschemasubentry",
                "supports_operational_attrs": True,
            },
            constants.SERVER_TYPE_ORACLE_OUD: {
                "acl_attribute": "ds-privilege-name",
                "acl_format": "oracle",
                "schema_subentry": "cn=schema",
                "supports_operational_attrs": True,
            },
            constants.SERVER_TYPE_ACTIVE_DIRECTORY: {
                "acl_attribute": "nTSecurityDescriptor",
                "acl_format": "ad",
                "schema_subentry": "cn=schema,cn=configuration",
                "supports_operational_attrs": False,
            },
            constants.SERVER_TYPE_GENERIC: {
                "acl_attribute": "aci",
                "acl_format": "generic",
                "schema_subentry": "cn=subschema",
                "supports_operational_attrs": True,
            },
        }

    @override
    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute quirks manager service."""
        return FlextResult[dict[str, object]].ok(
            {
                "service": FlextLdifQuirksManager,
                "server_type": self._server_type,
                "quirks_loaded": len(self._quirks_registry),
            }
        )

    async def execute_async(self) -> FlextResult[dict[str, object]]:
        """Execute quirks manager service asynchronously."""
        return FlextResult[dict[str, object]].ok(
            {
                "service": FlextLdifQuirksManager,
                "server_type": self._server_type,
                "quirks_loaded": len(self._quirks_registry),
            }
        )

    def detect_server_type(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[str]:
        """Detect LDAP server type from entries.

        Args:
            entries: List of LDIF entries to analyze

        Returns:
            FlextResult containing detected server type

        """
        if not entries:
            return FlextResult[str].ok(constants.SERVER_TYPE_GENERIC)

        for entry in entries:
            object_classes_raw: object = entry.get_attribute("objectClass") or []
            object_classes: list[str] = (
                object_classes_raw if isinstance(object_classes_raw, list) else []
            )

            if "orclContainer" in object_classes or "orclUserV2" in object_classes:
                return FlextResult[str].ok(constants.SERVER_TYPE_ORACLE_OID)

            if "olcConfig" in object_classes or "olcDatabase" in object_classes:
                return FlextResult[str].ok(constants.SERVER_TYPE_OPENLDAP)

            if "nsContainer" in object_classes or "nsPerson" in object_classes:
                return FlextResult[str].ok(constants.SERVER_TYPE_389DS)

            if "top" in object_classes and entry.dn.value.lower().startswith(
                "cn=schema"
            ):
                if "olc" in entry.dn.value.lower():
                    return FlextResult[str].ok(constants.SERVER_TYPE_OPENLDAP)
                if "ds-cfg" in entry.dn.value.lower():
                    return FlextResult[str].ok(constants.SERVER_TYPE_ORACLE_OUD)

        return FlextResult[str].ok(constants.SERVER_TYPE_GENERIC)

    def get_server_quirks(
        self, server_type: str | None = None
    ) -> FlextResult[dict[str, object]]:
        """Get quirks for specified server type.

        Args:
            server_type: Server type to get quirks for (uses instance default if None)

        Returns:
            FlextResult containing server quirks dictionary

        """
        target_server = server_type or self._server_type

        if target_server not in self._quirks_registry:
            return FlextResult[dict[str, object]].fail(
                f"Unknown server type: {target_server}"
            )

        return FlextResult[dict[str, object]].ok(self._quirks_registry[target_server])

    def get_acl_attribute_name(
        self, server_type: str | None = None
    ) -> FlextResult[str]:
        """Get ACL attribute name for server type."""
        quirks_result: FlextResult[dict[str, object]] = self.get_server_quirks(
            server_type
        )
        if quirks_result.is_failure:
            return FlextResult[str].fail(
                quirks_result.error or "Failed to get server quirks"
            )

        quirks_data = quirks_result.value
        acl_attr = quirks_data.get("acl_attribute", "aci")
        return FlextResult[str].ok(str(acl_attr))

    def get_acl_format(self, server_type: str | None = None) -> FlextResult[str]:
        """Get ACL format for server type."""
        quirks_result: FlextResult[dict[str, object]] = self.get_server_quirks(
            server_type
        )
        if quirks_result.is_failure:
            return FlextResult[str].fail(
                quirks_result.error or "Failed to get server quirks"
            )

        quirks_data = quirks_result.value
        acl_format = quirks_data.get("acl_format", "generic")
        return FlextResult[str].ok(str(acl_format))


__all__ = ["FlextLdifQuirksManager"]
