"""Unified LDAP Server Quirks Manager.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import override

from flext_core import FlextCore
from pydantic import Field

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes


class FlextLdifQuirksManager(FlextCore.Service[FlextLdifTypes.Dict]):
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
        # Logger and container inherited from FlextCore.Service via FlextCore.Mixins
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
            FlextLdifConstants.LdapServers.APACHE_DIRECTORY: {
                FlextLdifConstants.DictKeys.ACL_ATTRIBUTE: "ads-aci",
                FlextLdifConstants.DictKeys.ACL_FORMAT: FlextLdifConstants.AclFormats.ACI,
                FlextLdifConstants.DictKeys.SCHEMA_SUBENTRY: FlextLdifConstants.DnPatterns.CN_SUBSCHEMA,
                FlextLdifConstants.DictKeys.SUPPORTS_OPERATIONAL_ATTRS: True,
                "dn_patterns": ["ou=config", "ou=services"],
                "required_object_classes": ["top", "ads-directoryService"],
                "special_attributes": [
                    "ads-directoryServiceId",
                    "ads-enabled",
                    "ads-aci",
                ],
                "dn_case_sensitive": False,
            },
            FlextLdifConstants.LdapServers.DS_389: {
                FlextLdifConstants.DictKeys.ACL_ATTRIBUTE: FlextLdifConstants.DictKeys.ACI,
                FlextLdifConstants.DictKeys.ACL_FORMAT: FlextLdifConstants.AclFormats.DS389_ACL,
                FlextLdifConstants.DictKeys.SCHEMA_SUBENTRY: FlextLdifConstants.DnPatterns.CN_SCHEMA,
                FlextLdifConstants.DictKeys.SUPPORTS_OPERATIONAL_ATTRS: True,
                "dn_patterns": ["cn=config", "cn=monitor"],
                "required_object_classes": ["top", "nsContainer"],
                "special_attributes": [
                    "nsslapd-rootdn",
                    "nsslapd-suffix",
                    FlextLdifConstants.DictKeys.ACI,
                ],
                "dn_case_sensitive": False,
            },
            FlextLdifConstants.LdapServers.NOVELL_EDIRECTORY: {
                FlextLdifConstants.DictKeys.ACL_ATTRIBUTE: "acl",
                FlextLdifConstants.DictKeys.ACL_FORMAT: FlextLdifConstants.AclFormats.ACI,
                FlextLdifConstants.DictKeys.SCHEMA_SUBENTRY: FlextLdifConstants.DnPatterns.CN_SUBSCHEMA,
                FlextLdifConstants.DictKeys.SUPPORTS_OPERATIONAL_ATTRS: True,
                "dn_patterns": ["ou=services", "ou=system"],
                "required_object_classes": ["top", "ndsperson"],
                "special_attributes": [
                    "nspmPasswordPolicyDN",
                    "loginDisabled",
                    "nspmPasswordPolicy",
                ],
                "dn_case_sensitive": False,
            },
            FlextLdifConstants.LdapServers.IBM_TIVOLI: {
                FlextLdifConstants.DictKeys.ACL_ATTRIBUTE: "ibm-slapdAccessControl",
                FlextLdifConstants.DictKeys.ACL_FORMAT: FlextLdifConstants.AclFormats.RFC_GENERIC,
                FlextLdifConstants.DictKeys.SCHEMA_SUBENTRY: FlextLdifConstants.DnPatterns.CN_SCHEMA,
                FlextLdifConstants.DictKeys.SUPPORTS_OPERATIONAL_ATTRS: True,
                "dn_patterns": ["cn=ibm", "cn=configuration"],
                "required_object_classes": ["top", "ibm-LDAPServer"],
                "special_attributes": [
                    "ibm-slapdAccessControl",
                    "ibm-slapdBackend",
                ],
                "dn_case_sensitive": False,
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
                "dn_patterns": list(FlextLdifConstants.LdapServers.AD_DN_PATTERNS),
                "required_object_classes": list(
                    FlextLdifConstants.LdapServers.AD_REQUIRED_CLASSES
                ),
                "special_attributes": [
                    "memberOf",
                    "userPrincipalName",
                    "sAMAccountName",
                    FlextLdifConstants.DictKeys.NTSECURITYDESCRIPTOR,
                ],
                "dn_case_sensitive": False,
            },
            FlextLdifConstants.LdapServers.GENERIC: {
                FlextLdifConstants.DictKeys.ACL_ATTRIBUTE: FlextLdifConstants.DictKeys.ACI,
                FlextLdifConstants.DictKeys.ACL_FORMAT: FlextLdifConstants.AclFormats.RFC_GENERIC,
                FlextLdifConstants.DictKeys.SCHEMA_SUBENTRY: FlextLdifConstants.DnPatterns.CN_SUBSCHEMA,
                FlextLdifConstants.DictKeys.SUPPORTS_OPERATIONAL_ATTRS: True,
            },
        }

    @override
    def execute(self) -> FlextCore.Result[FlextLdifTypes.Dict]:
        """Execute quirks manager service."""
        return FlextCore.Result[FlextLdifTypes.Dict].ok({
            "service": FlextLdifQuirksManager,
            "server_type": self._server_type,
            "quirks_loaded": len(self.quirks_registry),
        })

    def detect_server_type(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextCore.Result[str]:
        """Detect LDAP server type from entries.

        Args:
            entries: List of LDIF entries to analyze

        Returns:
            FlextCore.Result containing detected server type

        """
        if not entries:
            return FlextCore.Result[str].ok(FlextLdifConstants.LdapServers.GENERIC)

        for entry in entries:
            object_classes_raw: object = entry.get_attribute_values(
                FlextLdifConstants.DictKeys.OBJECTCLASS
            )
            object_classes: FlextLdifTypes.StringList = (
                object_classes_raw if isinstance(object_classes_raw, list) else []
            )
            dn_lower = entry.dn.value.lower()

            if "orclContainer" in object_classes or "orclUserV2" in object_classes:
                return FlextCore.Result[str].ok(
                    FlextLdifConstants.LdapServers.ORACLE_OID
                )

            # OpenLDAP 2.x detection (cn=config with olc* attributes)
            if "olcConfig" in object_classes or "olcDatabase" in object_classes:
                return FlextCore.Result[str].ok(
                    FlextLdifConstants.LdapServers.OPENLDAP_2
                )

            # Check for olc* attributes indicating OpenLDAP 2.x
            has_olc_attrs = any(
                attr.startswith("olc") for attr in entry.attributes.attributes
            )
            if has_olc_attrs:
                return FlextCore.Result[str].ok(
                    FlextLdifConstants.LdapServers.OPENLDAP_2
                )

            if "nsContainer" in object_classes or "nsPerson" in object_classes:
                return FlextCore.Result[str].ok(FlextLdifConstants.LdapServers.DS_389)

            if any(
                attr.startswith(("nsslapd-", "nsds"))
                for attr in entry.attributes.attributes
            ):
                return FlextCore.Result[str].ok(FlextLdifConstants.LdapServers.DS_389)

            if (
                any(
                    attr.startswith(("ads-", "apacheds"))
                    for attr in entry.attributes.attributes
                )
                or any(oc.lower() == "ads-directoryservice" for oc in object_classes)
                or any(marker in dn_lower for marker in ("ou=config", "ou=services"))
            ):
                return FlextCore.Result[str].ok(
                    FlextLdifConstants.LdapServers.APACHE_DIRECTORY
                )

            if "top" in object_classes and dn_lower.startswith(
                FlextLdifConstants.DnPatterns.CN_SCHEMA
            ):
                if "olc" in dn_lower:
                    return FlextCore.Result[str].ok(
                        FlextLdifConstants.LdapServers.OPENLDAP_2
                    )
                if "ds-cfg" in dn_lower:
                    return FlextCore.Result[str].ok(
                        FlextLdifConstants.LdapServers.ORACLE_OUD
                    )

            if (
                entry.has_attribute("nspmPasswordPolicyDN")
                or entry.has_attribute("loginDisabled")
                or any(
                    oc.lower() in {"ndsperson", "nspmpasswordpolicy"}
                    for oc in object_classes
                )
            ):
                return FlextCore.Result[str].ok(
                    FlextLdifConstants.LdapServers.NOVELL_EDIRECTORY
                )

            if any(
                attr.startswith(("ibm-", "ids-"))
                for attr in entry.attributes.attributes
            ) or any(oc.lower().startswith("ibm-") for oc in object_classes):
                return FlextCore.Result[str].ok(
                    FlextLdifConstants.LdapServers.IBM_TIVOLI
                )

            # Active Directory detection heuristics
            ad_attr_present = any(
                entry.has_attribute(attr_name)
                for attr_name in (
                    "objectGUID",
                    "objectSid",
                    "sAMAccountName",
                    "userPrincipalName",
                    FlextLdifConstants.DictKeys.NTSECURITYDESCRIPTOR,
                )
            )
            ad_object_classes = {
                cls.lower()
                for cls in FlextLdifConstants.LdapServers.AD_REQUIRED_CLASSES
            }
            has_ad_classes = any(
                oc.lower() in ad_object_classes for oc in object_classes
            )
            ad_dn_markers = {
                marker.lower()
                for marker in FlextLdifConstants.LdapServers.AD_DN_PATTERNS
            }
            dn_matches_ad = any(marker in dn_lower for marker in ad_dn_markers)

            if ad_attr_present or has_ad_classes or dn_matches_ad:
                return FlextCore.Result[str].ok(
                    FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY
                )

            # OpenLDAP 1.x detection (traditional attributes, no olc* prefix)
            if "attributetype" in str(entry.attributes).lower() and not has_olc_attrs:
                return FlextCore.Result[str].ok(
                    FlextLdifConstants.LdapServers.OPENLDAP_1
                )

        return FlextCore.Result[str].ok(FlextLdifConstants.LdapServers.GENERIC)

    def get_server_quirks(
        self, server_type: str | None = None
    ) -> FlextCore.Result[FlextLdifTypes.Dict]:
        """Get quirks for specified server type.

        Args:
            server_type: Server type to get quirks for (uses instance default if None)

        Returns:
            FlextCore.Result containing server quirks dictionary

        """
        target_server = server_type or self._server_type

        if target_server not in self.quirks_registry:
            return FlextCore.Result[FlextLdifTypes.Dict].fail(
                f"Unknown server type: {target_server}"
            )

        return FlextCore.Result[FlextLdifTypes.Dict].ok(
            self.quirks_registry[target_server]
        )

    def get_acl_attribute_name(
        self, server_type: str | None = None
    ) -> FlextCore.Result[str]:
        """Get ACL attribute name for server type."""
        quirks_result: FlextCore.Result[FlextLdifTypes.Dict] = self.get_server_quirks(
            server_type
        )
        if quirks_result.is_failure:
            return FlextCore.Result[str].fail(
                quirks_result.error or "Failed to get server quirks"
            )

        quirks_data = quirks_result.value
        acl_attr = quirks_data.get(
            FlextLdifConstants.DictKeys.ACL_ATTRIBUTE, FlextLdifConstants.DictKeys.ACI
        )
        return FlextCore.Result[str].ok(str(acl_attr))

    def get_acl_format(self, server_type: str | None = None) -> FlextCore.Result[str]:
        """Get ACL format for server type."""
        quirks_result: FlextCore.Result[FlextLdifTypes.Dict] = self.get_server_quirks(
            server_type
        )
        if quirks_result.is_failure:
            return FlextCore.Result[str].fail(
                quirks_result.error or "Failed to get server quirks"
            )

        quirks_data = quirks_result.value
        acl_format = quirks_data.get(
            FlextLdifConstants.DictKeys.ACL_FORMAT,
            FlextLdifConstants.AclFormats.RFC_GENERIC,
        )
        return FlextCore.Result[str].ok(str(acl_format))


__all__ = ["FlextLdifQuirksManager"]
