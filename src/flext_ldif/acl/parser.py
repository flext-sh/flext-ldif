"""FLEXT LDIF ACL Parser.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_core import FlextLogger
from flext_core import FlextResult
from flext_core import FlextService

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels


class FlextLdifAclParser(FlextService[dict[str, object]]):
    """Multi-server ACL parser for different LDAP implementations."""

    @override
    def __init__(self) -> None:
        """Initialize ACL parser."""
        super().__init__()
        self._logger = FlextLogger(__name__)

    @override
    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute parser service."""
        return FlextResult[dict[str, object]].ok(
            {
                "service": FlextLdifAclParser,
                "status": "ready",
            }
        )

    async def execute_async(self) -> FlextResult[dict[str, object]]:
        """Execute parser service asynchronously."""
        return FlextResult[dict[str, object]].ok(
            {
                "service": FlextLdifAclParser,
                "status": "ready",
            }
        )

    def parse_openldap_acl(
        self, acl_string: str
    ) -> FlextResult[FlextLdifModels.UnifiedAcl]:
        """Parse OpenLDAP olcAccess ACL format.

        Args:
            acl_string: OpenLDAP ACL string

        Returns:
            FlextResult containing unified ACL

        """
        # Create ACL components and extract values safely
        target_creation = FlextLdifModels.AclTarget.create()
        subject_creation = FlextLdifModels.AclSubject.create()
        perms_creation = FlextLdifModels.AclPermissions.create(read=True)

        # Extract values with proper type checking
        if not target_creation.is_success:
            return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                "Failed to create AclTarget"
            )
        if not isinstance(target_creation.value, FlextLdifModels.AclTarget):
            return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                "Invalid AclTarget type"
            )

        if not subject_creation.is_success:
            return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                "Failed to create AclSubject"
            )
        if not isinstance(subject_creation.value, FlextLdifModels.AclSubject):
            return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                "Invalid AclSubject type"
            )

        if not perms_creation.is_success:
            return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                "Failed to create AclPermissions"
            )
        if not isinstance(perms_creation.value, FlextLdifModels.AclPermissions):
            return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                "Invalid AclPermissions type"
            )

        target_result = target_creation.value
        subject_result = subject_creation.value
        perms_result = perms_creation.value

        return FlextLdifModels.UnifiedAcl.create(
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
        # Create ACL components and extract values safely
        target_creation = FlextLdifModels.AclTarget.create()
        subject_creation = FlextLdifModels.AclSubject.create()
        perms_creation = FlextLdifModels.AclPermissions.create(read=True)

        # Extract values with proper type checking
        if not target_creation.is_success:
            return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                "Failed to create AclTarget"
            )
        if not isinstance(target_creation.value, FlextLdifModels.AclTarget):
            return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                "Invalid AclTarget type"
            )

        if not subject_creation.is_success:
            return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                "Failed to create AclSubject"
            )
        if not isinstance(subject_creation.value, FlextLdifModels.AclSubject):
            return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                "Invalid AclSubject type"
            )

        if not perms_creation.is_success:
            return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                "Failed to create AclPermissions"
            )
        if not isinstance(perms_creation.value, FlextLdifModels.AclPermissions):
            return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                "Invalid AclPermissions type"
            )

        target_result = target_creation.value
        subject_result = subject_creation.value
        perms_result = perms_creation.value

        return FlextLdifModels.UnifiedAcl.create(
            name="389ds_acl",
            target=target_result,
            subject=subject_result,
            permissions=perms_result,
            server_type=FlextLdifConstants.LdapServers.DS_389,
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
        # Create ACL components and extract values safely
        target_creation = FlextLdifModels.AclTarget.create()
        subject_creation = FlextLdifModels.AclSubject.create()
        perms_creation = FlextLdifModels.AclPermissions.create(read=True)

        # Extract values with proper type checking
        if not target_creation.is_success:
            return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                "Failed to create AclTarget"
            )
        if not isinstance(target_creation.value, FlextLdifModels.AclTarget):
            return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                "Invalid AclTarget type"
            )

        if not subject_creation.is_success:
            return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                "Failed to create AclSubject"
            )
        if not isinstance(subject_creation.value, FlextLdifModels.AclSubject):
            return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                "Invalid AclSubject type"
            )

        if not perms_creation.is_success:
            return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                "Failed to create AclPermissions"
            )
        if not isinstance(perms_creation.value, FlextLdifModels.AclPermissions):
            return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                "Invalid AclPermissions type"
            )

        target_result = target_creation.value
        subject_result = subject_creation.value
        perms_result = perms_creation.value

        return FlextLdifModels.UnifiedAcl.create(
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
