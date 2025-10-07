"""Unified LDAP Server Quirks Manager.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_core import FlextResult, FlextService
from pydantic import Field

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes


class FlextLdifQuirksManager(FlextService[FlextLdifTypes.Dict]):
    """Unified quirks manager for all LDAP server types.

    Coordinates server-specific handling for schemas, ACLs, and entries
    across different LDAP implementations.
    """

    # Declare Pydantic fields at class level
    quirks_registry: FlextLdifTypes.NestedDict = Field(
        default_factory=dict, description="Registry of server-specific quirks"
    )

    @override
    def __init__(self, server_type: str | None = None) -> None:
        """Initialize quirks manager with Phase 1 context enrichment.

        Args:
            server_type: LDAP server type (defaults to generic)

        """
        super().__init__()
        # Logger and container inherited from FlextService via FlextMixins
        self._server_type = server_type or FlextLdifConstants.LdapServers.GENERIC
        self._setup_quirks()

    @property
    def server_type(self) -> str:
        """Get the current server type."""
        return self._server_type

    def _setup_quirks(self) -> None:
        """Setup server-specific quirks registry."""
        self.quirks_registry = {
            FlextLdifConstants.LdapServers.OPENLDAP_2: {
                FlextLdifConstants.DictKeys.ACL_ATTRIBUTE: FlextLdifConstants.DictKeys.OLCACCESS,
                FlextLdifConstants.DictKeys.ACL_FORMAT: FlextLdifConstants.AclFormats.OPENLDAP2_ACL,
                FlextLdifConstants.DictKeys.SCHEMA_SUBENTRY: FlextLdifConstants.DnPatterns.CN_SUBSCHEMA,
                FlextLdifConstants.DictKeys.SUPPORTS_OPERATIONAL_ATTRS: True,
            },
            FlextLdifConstants.LdapServers.OPENLDAP_1: {
                FlextLdifConstants.DictKeys.ACL_ATTRIBUTE: FlextLdifConstants.DictKeys.ACCESS,
                FlextLdifConstants.DictKeys.ACL_FORMAT: FlextLdifConstants.AclFormats.OPENLDAP1_ACL,
                FlextLdifConstants.DictKeys.SCHEMA_SUBENTRY: FlextLdifConstants.DnPatterns.CN_SUBSCHEMA,
                FlextLdifConstants.DictKeys.SUPPORTS_OPERATIONAL_ATTRS: True,
            },
            FlextLdifConstants.LdapServers.OPENLDAP: {
                FlextLdifConstants.DictKeys.ACL_ATTRIBUTE: FlextLdifConstants.DictKeys.OLCACCESS,
                FlextLdifConstants.DictKeys.ACL_FORMAT: FlextLdifConstants.AclFormats.OPENLDAP2_ACL,
                FlextLdifConstants.DictKeys.SCHEMA_SUBENTRY: FlextLdifConstants.DnPatterns.CN_SUBSCHEMA,
                FlextLdifConstants.DictKeys.SUPPORTS_OPERATIONAL_ATTRS: True,
            },
            FlextLdifConstants.LdapServers.DS_389: {
                FlextLdifConstants.DictKeys.ACL_ATTRIBUTE: FlextLdifConstants.DictKeys.ACI,
                FlextLdifConstants.DictKeys.ACL_FORMAT: FlextLdifConstants.AclFormats.DS389_ACL,
                FlextLdifConstants.DictKeys.SCHEMA_SUBENTRY: FlextLdifConstants.DnPatterns.CN_SCHEMA,
                FlextLdifConstants.DictKeys.SUPPORTS_OPERATIONAL_ATTRS: True,
            },
            FlextLdifConstants.LdapServers.ORACLE_OID: {
                FlextLdifConstants.DictKeys.ACL_ATTRIBUTE: FlextLdifConstants.DictKeys.ORCLACI,
                FlextLdifConstants.DictKeys.ACL_FORMAT: FlextLdifConstants.AclFormats.OID_ACL,
                FlextLdifConstants.DictKeys.SCHEMA_SUBENTRY: FlextLdifConstants.DnPatterns.CN_SUBSCHEMASUBENTRY,
                FlextLdifConstants.DictKeys.SUPPORTS_OPERATIONAL_ATTRS: True,
            },
            FlextLdifConstants.LdapServers.ORACLE_OUD: {
                FlextLdifConstants.DictKeys.ACL_ATTRIBUTE: FlextLdifConstants.DictKeys.DS_PRIVILEGE_NAME,
                FlextLdifConstants.DictKeys.ACL_FORMAT: FlextLdifConstants.AclFormats.OID_ACL,
                FlextLdifConstants.DictKeys.SCHEMA_SUBENTRY: FlextLdifConstants.DnPatterns.CN_SCHEMA,
                FlextLdifConstants.DictKeys.SUPPORTS_OPERATIONAL_ATTRS: True,
            },
            FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY: {
                FlextLdifConstants.DictKeys.ACL_ATTRIBUTE: FlextLdifConstants.DictKeys.NTSECURITYDESCRIPTOR,
                FlextLdifConstants.DictKeys.ACL_FORMAT: FlextLdifConstants.AclFormats.AD_ACL,
                FlextLdifConstants.DictKeys.SCHEMA_SUBENTRY: FlextLdifConstants.DnPatterns.CN_SCHEMA_CN_CONFIGURATION,
                FlextLdifConstants.DictKeys.SUPPORTS_OPERATIONAL_ATTRS: False,
            },
            FlextLdifConstants.LdapServers.GENERIC: {
                FlextLdifConstants.DictKeys.ACL_ATTRIBUTE: FlextLdifConstants.DictKeys.ACI,
                FlextLdifConstants.DictKeys.ACL_FORMAT: FlextLdifConstants.AclFormats.RFC_GENERIC,
                FlextLdifConstants.DictKeys.SCHEMA_SUBENTRY: FlextLdifConstants.DnPatterns.CN_SUBSCHEMA,
                FlextLdifConstants.DictKeys.SUPPORTS_OPERATIONAL_ATTRS: True,
            },
        }

    @override
    def execute(self) -> FlextResult[FlextLdifTypes.Dict]:
        """Execute quirks manager service."""
        return FlextResult[FlextLdifTypes.Dict].ok({
            "service": FlextLdifQuirksManager,
            "server_type": self._server_type,
            "quirks_loaded": len(self.quirks_registry),
        })

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
            return FlextResult[str].ok(FlextLdifConstants.LdapServers.GENERIC)

        for entry in entries:
            object_classes_raw: object = entry.get_attribute("objectClass") or []
            object_classes: FlextLdifTypes.StringList = (
                object_classes_raw if isinstance(object_classes_raw, list) else []
            )

            if "orclContainer" in object_classes or "orclUserV2" in object_classes:
                return FlextResult[str].ok(FlextLdifConstants.LdapServers.ORACLE_OID)

            # OpenLDAP 2.x detection (cn=config with olc* attributes)
            if "olcConfig" in object_classes or "olcDatabase" in object_classes:
                return FlextResult[str].ok(FlextLdifConstants.LdapServers.OPENLDAP_2)

            # Check for olc* attributes indicating OpenLDAP 2.x
            has_olc_attrs = any(
                attr.startswith("olc") for attr in entry.attributes.attributes
            )
            if has_olc_attrs:
                return FlextResult[str].ok(FlextLdifConstants.LdapServers.OPENLDAP_2)

            if "nsContainer" in object_classes or "nsPerson" in object_classes:
                return FlextResult[str].ok(FlextLdifConstants.LdapServers.DS_389)

            if "top" in object_classes and entry.dn.value.lower().startswith(
                FlextLdifConstants.DnPatterns.CN_SCHEMA
            ):
                if "olc" in entry.dn.value.lower():
                    return FlextResult[str].ok(
                        FlextLdifConstants.LdapServers.OPENLDAP_2
                    )
                if "ds-cfg" in entry.dn.value.lower():
                    return FlextResult[str].ok(
                        FlextLdifConstants.LdapServers.ORACLE_OUD
                    )

            # OpenLDAP 1.x detection (traditional attributes, no olc* prefix)
            if "attributetype" in str(entry.attributes).lower() and not has_olc_attrs:
                return FlextResult[str].ok(FlextLdifConstants.LdapServers.OPENLDAP_1)

        return FlextResult[str].ok(FlextLdifConstants.LdapServers.GENERIC)

    def get_server_quirks(
        self, server_type: str | None = None
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Get quirks for specified server type.

        Args:
            server_type: Server type to get quirks for (uses instance default if None)

        Returns:
            FlextResult containing server quirks dictionary

        """
        target_server = server_type or self._server_type

        if target_server not in self.quirks_registry:
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"Unknown server type: {target_server}"
            )

        return FlextResult[FlextLdifTypes.Dict].ok(self.quirks_registry[target_server])

    def get_acl_attribute_name(
        self, server_type: str | None = None
    ) -> FlextResult[str]:
        """Get ACL attribute name for server type."""
        quirks_result: FlextResult[FlextLdifTypes.Dict] = self.get_server_quirks(
            server_type
        )
        if quirks_result.is_failure:
            return FlextResult[str].fail(
                quirks_result.error or "Failed to get server quirks"
            )

        quirks_data = quirks_result.value
        acl_attr = quirks_data.get(
            FlextLdifConstants.DictKeys.ACL_ATTRIBUTE, FlextLdifConstants.DictKeys.ACI
        )
        return FlextResult[str].ok(str(acl_attr))

    def get_acl_format(self, server_type: str | None = None) -> FlextResult[str]:
        """Get ACL format for server type."""
        quirks_result: FlextResult[FlextLdifTypes.Dict] = self.get_server_quirks(
            server_type
        )
        if quirks_result.is_failure:
            return FlextResult[str].fail(
                quirks_result.error or "Failed to get server quirks"
            )

        quirks_data = quirks_result.value
        acl_format = quirks_data.get(
            FlextLdifConstants.DictKeys.ACL_FORMAT,
            FlextLdifConstants.AclFormats.RFC_GENERIC,
        )
        return FlextResult[str].ok(str(acl_format))


__all__ = ["FlextLdifQuirksManager"]
