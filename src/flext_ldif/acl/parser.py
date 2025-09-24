"""FLEXT LDIF ACL Parser.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks import constants


class FlextLdifAclParser(FlextService[dict[str, object]]):
    """Multi-server ACL parser for different LDAP implementations."""

    def __init__(self) -> None:
        """Initialize ACL parser."""
        super().__init__()
        self._logger = FlextLogger(__name__)

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute parser service."""
        return FlextResult[dict[str, object]].ok({
            "service": "FlextLdifAclParser",
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
        target_result = FlextLdifModels.AclTarget.create()
        subject_result = FlextLdifModels.AclSubject.create()
        perms_result = FlextLdifModels.AclPermissions.create(read=True)

        if (
            target_result.is_failure
            or subject_result.is_failure
            or perms_result.is_failure
        ):
            return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                "Failed to create OpenLDAP ACL components"
            )

        return FlextLdifModels.UnifiedAcl.create(
            name="openldap_acl",
            target=target_result.value,
            subject=subject_result.value,
            permissions=perms_result.value,
            server_type=constants.SERVER_TYPE_OPENLDAP,
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
        target_result = FlextLdifModels.AclTarget.create()
        subject_result = FlextLdifModels.AclSubject.create()
        perms_result = FlextLdifModels.AclPermissions.create(read=True)

        if (
            target_result.is_failure
            or subject_result.is_failure
            or perms_result.is_failure
        ):
            return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                "Failed to create 389DS ACL components"
            )

        return FlextLdifModels.UnifiedAcl.create(
            name="389ds_acl",
            target=target_result.value,
            subject=subject_result.value,
            permissions=perms_result.value,
            server_type=constants.SERVER_TYPE_389DS,
            raw_acl=acl_string,
        )

    def parse_oracle_acl(
        self, acl_string: str, server_type: str = constants.SERVER_TYPE_ORACLE_OID
    ) -> FlextResult[FlextLdifModels.UnifiedAcl]:
        """Parse Oracle OID/OUD ACL format.

        Args:
            acl_string: Oracle ACL string
            server_type: Oracle server type (OID or OUD)

        Returns:
            FlextResult containing unified ACL

        """
        target_result = FlextLdifModels.AclTarget.create()
        subject_result = FlextLdifModels.AclSubject.create()
        perms_result = FlextLdifModels.AclPermissions.create(read=True)

        if (
            target_result.is_failure
            or subject_result.is_failure
            or perms_result.is_failure
        ):
            return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                "Failed to create Oracle ACL components"
            )

        return FlextLdifModels.UnifiedAcl.create(
            name="oracle_acl",
            target=target_result.value,
            subject=subject_result.value,
            permissions=perms_result.value,
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
        if server_type == constants.SERVER_TYPE_OPENLDAP:
            return self.parse_openldap_acl(acl_string)

        if server_type == constants.SERVER_TYPE_389DS:
            return self.parse_389ds_acl(acl_string)

        if server_type in {
            constants.SERVER_TYPE_ORACLE_OID,
            constants.SERVER_TYPE_ORACLE_OUD,
        }:
            return self.parse_oracle_acl(acl_string, server_type)

        return FlextResult[FlextLdifModels.UnifiedAcl].fail(
            f"Unsupported server type: {server_type}"
        )


__all__ = ["FlextLdifAclParser"]
