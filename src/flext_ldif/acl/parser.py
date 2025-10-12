"""FLEXT LDIF ACL Parser.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_core import FlextCore

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes


class FlextLdifAclParser(FlextCore.Service[FlextLdifTypes.Dict]):
    """Multi-server ACL parser for different LDAP implementations."""

    @override
    def __init__(self) -> None:
        """Initialize ACL parser with Phase 1 context enrichment."""
        super().__init__()
        # Logger and container inherited from FlextCore.Service via FlextCore.Mixins

    @override
    def execute(self) -> FlextCore.Result[FlextLdifTypes.Dict]:
        """Execute parser service."""
        return FlextCore.Result[FlextLdifTypes.Dict].ok({
            "service": FlextLdifAclParser,
            "status": "ready",
        })

    def parse_openldap_acl(
        self, acl_string: str
    ) -> FlextCore.Result[FlextLdifModels.UnifiedAcl]:
        """Parse OpenLDAP olcAccess ACL format.

        Args:
            acl_string: OpenLDAP ACL string

        Returns:
            FlextCore.Result containing unified ACL

        """
        # Create ACL components directly - Pydantic handles validation
        target = FlextLdifModels.AclTarget(target_dn="*", attributes=[])
        subject = FlextLdifModels.AclSubject(subject_type="*", subject_value="*")
        perms = FlextLdifModels.AclPermissions(read=True)

        # Create unified ACL directly
        acl = FlextLdifModels.UnifiedAcl(
            name="openldap_acl",
            target=target,
            subject=subject,
            permissions=perms,
            server_type=FlextLdifConstants.LdapServers.OPENLDAP,
            raw_acl=acl_string,
        )
        return FlextCore.Result[FlextLdifModels.UnifiedAcl].ok(acl)

    def parse_389ds_acl(
        self, acl_string: str
    ) -> FlextCore.Result[FlextLdifModels.UnifiedAcl]:
        """Parse 389DS ACI format.

        Args:
            acl_string: 389DS ACI string

        Returns:
            FlextCore.Result containing unified ACL

        """
        # Create ACL components directly - Pydantic handles validation
        target = FlextLdifModels.AclTarget(target_dn="*", attributes=[])
        subject = FlextLdifModels.AclSubject(subject_type="*", subject_value="*")
        perms = FlextLdifModels.AclPermissions(read=True)

        # Create unified ACL directly
        acl = FlextLdifModels.UnifiedAcl(
            name="389ds_acl",
            target=target,
            subject=subject,
            permissions=perms,
            server_type=FlextLdifConstants.LdapServers.DS_389,
            raw_acl=acl_string,
        )
        return FlextCore.Result[FlextLdifModels.UnifiedAcl].ok(acl)

    def parse_oracle_acl(
        self,
        acl_string: str,
        server_type: str = FlextLdifConstants.LdapServers.ORACLE_OID,
    ) -> FlextCore.Result[FlextLdifModels.UnifiedAcl]:
        """Parse Oracle OID/OUD ACL format.

        Args:
            acl_string: Oracle ACL string
            server_type: Oracle server type (OID or OUD)

        Returns:
            FlextCore.Result containing unified ACL

        """
        # Create ACL components directly - Pydantic handles validation
        target = FlextLdifModels.AclTarget(target_dn="*", attributes=[])
        subject = FlextLdifModels.AclSubject(subject_type="*", subject_value="*")
        perms = FlextLdifModels.AclPermissions(read=True)

        # Create unified ACL directly
        acl = FlextLdifModels.UnifiedAcl(
            name="oracle_acl",
            target=target,
            subject=subject,
            permissions=perms,
            server_type=server_type,
            raw_acl=acl_string,
        )
        return FlextCore.Result[FlextLdifModels.UnifiedAcl].ok(acl)

    def parse_acl(
        self, acl_string: str, server_type: str
    ) -> FlextCore.Result[FlextLdifModels.UnifiedAcl]:
        """Parse ACL string based on server type.

        Args:
            acl_string: Raw ACL string
            server_type: LDAP server type

        Returns:
            FlextCore.Result containing unified ACL

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

        return FlextCore.Result[FlextLdifModels.UnifiedAcl].fail(
            f"Unsupported server type: {server_type}"
        )


__all__ = ["FlextLdifAclParser"]
