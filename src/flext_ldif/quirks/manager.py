"""Unified LDAP Server Quirks Manager.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import cast, override

from flext_core import FlextResult, FlextService
from pydantic import PrivateAttr

from flext_ldif.constants import FlextLdifConstants


class FlextLdifQuirksManager(FlextService[dict[str, object]]):
    """Unified quirks manager for all LDAP server types.

    Coordinates server-specific handling for schemas, ACLs, and entries
    across different LDAP implementations.
    """

    _quirks_registry: dict[str, object] = PrivateAttr(default_factory=dict)

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

    @property
    def quirks_registry(self) -> dict[str, object]:
        """Get the quirks registry (read-only access)."""
        return self._quirks_registry

    def _setup_quirks(self) -> None:
        """Setup server-specific quirks registry."""
        # Use short names to reduce line lengths (not type aliases)
        dk = FlextLdifConstants.DictKeys
        ls = FlextLdifConstants.LdapServers
        af = FlextLdifConstants.AclFormats
        dn = FlextLdifConstants.DnPatterns

        self._quirks_registry = {
            ls.OPENLDAP_2: {
                dk.ACL_ATTRIBUTE: dk.OLCACCESS,
                dk.ACL_FORMAT: af.OPENLDAP2_ACL,
                dk.SCHEMA_SUBENTRY: dn.CN_SUBSCHEMA,
                dk.SUPPORTS_OPERATIONAL_ATTRS: True,
            },
            ls.OPENLDAP_1: {
                dk.ACL_ATTRIBUTE: dk.ACCESS,
                dk.ACL_FORMAT: af.OPENLDAP1_ACL,
                dk.SCHEMA_SUBENTRY: dn.CN_SUBSCHEMA,
                dk.SUPPORTS_OPERATIONAL_ATTRS: True,
            },
            ls.OPENLDAP: {
                dk.ACL_ATTRIBUTE: dk.OLCACCESS,
                dk.ACL_FORMAT: af.OPENLDAP2_ACL,
                dk.SCHEMA_SUBENTRY: dn.CN_SUBSCHEMA,
                dk.SUPPORTS_OPERATIONAL_ATTRS: True,
            },
            ls.APACHE_DIRECTORY: {
                dk.ACL_ATTRIBUTE: "ads-aci",
                dk.ACL_FORMAT: af.ACI,
                dk.SCHEMA_SUBENTRY: dn.CN_SUBSCHEMA,
                dk.SUPPORTS_OPERATIONAL_ATTRS: True,
                "dn_patterns": ["ou=config", "ou=services"],
                "required_object_classes": ["top", "ads-directoryService"],
                "special_attributes": [
                    "ads-directoryServiceId",
                    "ads-enabled",
                    "ads-aci",
                ],
                "dn_case_sensitive": False,
            },
            ls.DS_389: {
                dk.ACL_ATTRIBUTE: dk.ACI,
                dk.ACL_FORMAT: af.DS389_ACL,
                dk.SCHEMA_SUBENTRY: dn.CN_SCHEMA,
                dk.SUPPORTS_OPERATIONAL_ATTRS: True,
                "dn_patterns": ["cn=config", "cn=monitor"],
                "required_object_classes": ["top", "nsContainer"],
                "special_attributes": [
                    "nsslapd-rootdn",
                    "nsslapd-suffix",
                    dk.ACI,
                ],
                "dn_case_sensitive": False,
            },
            ls.NOVELL_EDIRECTORY: {
                dk.ACL_ATTRIBUTE: "acl",
                dk.ACL_FORMAT: af.ACI,
                dk.SCHEMA_SUBENTRY: dn.CN_SUBSCHEMA,
                dk.SUPPORTS_OPERATIONAL_ATTRS: True,
                "dn_patterns": ["ou=services", "ou=system"],
                "required_object_classes": ["top", "ndsperson"],
                "special_attributes": [
                    "nspmPasswordPolicyDN",
                    "loginDisabled",
                    "nspmPasswordPolicy",
                ],
                "dn_case_sensitive": False,
            },
            ls.IBM_TIVOLI: {
                dk.ACL_ATTRIBUTE: "ibm-slapdAccessControl",
                dk.ACL_FORMAT: af.RFC_GENERIC,
                dk.SCHEMA_SUBENTRY: dn.CN_SCHEMA,
                dk.SUPPORTS_OPERATIONAL_ATTRS: True,
                "dn_patterns": ["cn=ibm", "cn=configuration"],
                "required_object_classes": ["top", "ibm-LDAPServer"],
                "special_attributes": [
                    "ibm-slapdAccessControl",
                    "ibm-slapdBackend",
                ],
                "dn_case_sensitive": False,
            },
            ls.ORACLE_OID: {
                dk.ACL_ATTRIBUTE: dk.ORCLACI,
                dk.ACL_FORMAT: af.OID_ACL,
                dk.SCHEMA_SUBENTRY: dn.CN_SUBSCHEMASUBENTRY,
                dk.SUPPORTS_OPERATIONAL_ATTRS: True,
            },
            ls.ORACLE_OUD: {
                dk.ACL_ATTRIBUTE: dk.DS_PRIVILEGE_NAME,
                dk.ACL_FORMAT: af.OID_ACL,
                dk.SCHEMA_SUBENTRY: dn.CN_SCHEMA,
                dk.SUPPORTS_OPERATIONAL_ATTRS: True,
            },
            ls.ACTIVE_DIRECTORY: {
                dk.ACL_ATTRIBUTE: dk.NTSECURITYDESCRIPTOR,
                dk.ACL_FORMAT: af.AD_ACL,
                dk.SCHEMA_SUBENTRY: dn.CN_SCHEMA_CN_CONFIGURATION,
                dk.SUPPORTS_OPERATIONAL_ATTRS: False,
                "dn_patterns": list(ls.AD_DN_PATTERNS),
                "required_object_classes": list(ls.AD_REQUIRED_CLASSES),
                "special_attributes": [
                    "memberOf",
                    "userPrincipalName",
                    "sAMAccountName",
                    dk.NTSECURITYDESCRIPTOR,
                ],
                "dn_case_sensitive": False,
            },
            ls.GENERIC: {
                dk.ACL_ATTRIBUTE: dk.ACI,
                dk.ACL_FORMAT: af.RFC_GENERIC,
                dk.SCHEMA_SUBENTRY: dn.CN_SUBSCHEMA,
                dk.SUPPORTS_OPERATIONAL_ATTRS: True,
            },
        }

    @override
    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute quirks manager service."""
        return FlextResult[dict[str, object]].ok({
            "service": FlextLdifQuirksManager,
            "server_type": self._server_type,
            "quirks_loaded": len(self._quirks_registry),
        })

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

        # Cast registry value from object to dict[str, object] for type safety
        quirks = cast("dict[str, object]", self._quirks_registry[target_server])
        return FlextResult[dict[str, object]].ok(quirks)

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
        acl_attr = quirks_data.get(
            FlextLdifConstants.DictKeys.ACL_ATTRIBUTE, FlextLdifConstants.DictKeys.ACI
        )
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
        acl_format = quirks_data.get(
            FlextLdifConstants.DictKeys.ACL_FORMAT,
            FlextLdifConstants.AclFormats.RFC_GENERIC,
        )
        return FlextResult[str].ok(str(acl_format))


__all__ = ["FlextLdifQuirksManager"]
