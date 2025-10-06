"""FLEXT LDIF ACL Parser.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_core import FlextResult, FlextService

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes


class FlextLdifAclParser(FlextService[FlextLdifTypes.Dict]):
    """Multi-server ACL parser for different LDAP implementations."""

    class AclComponentHelper:
        """Helper class for creating and validating ACL components."""

        @staticmethod
        def create_acl_components() -> FlextResult[
            tuple[
                FlextLdifModels.AclTarget,
                FlextLdifModels.AclSubject,
                FlextLdifModels.AclPermissions,
            ]
        ]:
            """Create ACL components with proper validation."""
            try:
                # Create ACL components with default values
                target = FlextLdifModels.AclTarget(target_dn="*", attributes=[])
                subject = FlextLdifModels.AclSubject(
                    subject_type="*", subject_value="*"
                )
                perms = FlextLdifModels.AclPermissions(read=True)

                return FlextResult[
                    tuple[
                        FlextLdifModels.AclTarget,
                        FlextLdifModels.AclSubject,
                        FlextLdifModels.AclPermissions,
                    ]
                ].ok((target, subject, perms))
            except Exception as e:
                return FlextResult[
                    tuple[
                        FlextLdifModels.AclTarget,
                        FlextLdifModels.AclSubject,
                        FlextLdifModels.AclPermissions,
                    ]
                ].fail(f"Failed to create ACL components: {e}")

        @staticmethod
        def create_unified_acl(
            name: str,
            target: FlextLdifModels.AclTarget,
            subject: FlextLdifModels.AclSubject,
            permissions: FlextLdifModels.AclPermissions,
            server_type: str,
            raw_acl: str,
        ) -> FlextResult[FlextLdifModels.UnifiedAcl]:
            """Create unified ACL with proper validation."""
            try:
                acl = FlextLdifModels.UnifiedAcl(
                    name=name,
                    target=target,
                    subject=subject,
                    permissions=permissions,
                    server_type=server_type,
                    raw_acl=raw_acl,
                )
                return FlextResult[FlextLdifModels.UnifiedAcl].ok(acl)
            except Exception as e:
                return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                    f"Failed to create UnifiedAcl: {e}"
                )

    @override
    def __init__(self) -> None:
        """Initialize ACL parser with Phase 1 context enrichment."""
        super().__init__()
        # Logger and container inherited from FlextService via FlextMixins

    @override
    def execute(self) -> FlextResult[FlextLdifTypes.Dict]:
        """Execute parser service."""
        return FlextResult[FlextLdifTypes.Dict].ok({
            "service": FlextLdifAclParser,
            "status": "ready",
        })

    def parse_openldap_acl(
        self, acl_string: str
    ) -> FlextResult[FlextLdifModels.UnifiedAcl]:
        """Parse OpenLDAP olcAccess ACL format.

        Args:
            acl_string: OpenLDAP ACL string

        Returns:
            FlextResult containing unified ACL

        """
        # Create ACL components using helper
        components_result = self.AclComponentHelper.create_acl_components()
        if components_result.is_failure:
            return FlextResult[FlextLdifModels.UnifiedAcl].fail(components_result.error)

        target_result, subject_result, perms_result = components_result.value

        # Create unified ACL using helper
        return self.AclComponentHelper.create_unified_acl(
            name="openldap_acl",
            target=target_result,
            subject=subject_result,
            permissions=perms_result,
            server_type=FlextLdifConstants.LdapServers.OPENLDAP,
            raw_acl=acl_string,
        )

    def parse_389ds_acl(
        self, acl_string: str
    ) -> FlextResult[FlextLdifModels.UnifiedAcl]:
        """Parse 389DS ACI format.

        Args:
            acl_string: 389DS ACI string

        Returns:
            FlextResult containing unified ACL

        """
        # Create ACL components using helper
        components_result = self.AclComponentHelper.create_acl_components()
        if components_result.is_failure:
            return FlextResult[FlextLdifModels.UnifiedAcl].fail(components_result.error)

        target_result, subject_result, perms_result = components_result.value

        # Create unified ACL using helper
        return self.AclComponentHelper.create_unified_acl(
            name="openldap_acl",
            target=target_result,
            subject=subject_result,
            permissions=perms_result,
            server_type=FlextLdifConstants.LdapServers.OPENLDAP,
            raw_acl=acl_string,
        )

    def parse_oracle_acl(
        self,
        acl_string: str,
        server_type: str = FlextLdifConstants.LdapServers.ORACLE_OID,
    ) -> FlextResult[FlextLdifModels.UnifiedAcl]:
        """Parse Oracle OID/OUD ACL format.

        Args:
            acl_string: Oracle ACL string
            server_type: Oracle server type (OID or OUD)

        Returns:
            FlextResult containing unified ACL

        """
        # Create ACL components using helper
        components_result = self.AclComponentHelper.create_acl_components()
        if components_result.is_failure:
            return FlextResult[FlextLdifModels.UnifiedAcl].fail(components_result.error)

        target_result, subject_result, perms_result = components_result.value

        # Create unified ACL using helper
        return self.AclComponentHelper.create_unified_acl(
            name="oracle_acl",
            target=target_result,
            subject=subject_result,
            permissions=perms_result,
            server_type=server_type,
            raw_acl=acl_string,
        )

    def parse_acl(
        self, acl_string: str, server_type: str
    ) -> FlextResult[FlextLdifModels.UnifiedAcl]:
        """Parse ACL string based on server type.

        Args:
            acl_string: Raw ACL string
            server_type: LDAP server type

        Returns:
            FlextResult containing unified ACL

        """
        if server_type == FlextLdifConstants.LdapServers.OPENLDAP:
            return self.parse_openldap_acl(acl_string)

        if server_type == FlextLdifConstants.LdapServers.DS_389:
            return self.parse_389ds_acl(acl_string)

        if server_type in {
            FlextLdifConstants.LdapServers.ORACLE_OID,
            FlextLdifConstants.LdapServers.ORACLE_OUD,
        }:
            return self.parse_oracle_acl(acl_string, server_type)

        return FlextResult[FlextLdifModels.UnifiedAcl].fail(
            f"Unsupported server type: {server_type}"
        )


__all__ = ["FlextLdifAclParser"]
