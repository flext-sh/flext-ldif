"""FLEXT LDIF ACL Parser.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import cast, override

from flext_core import FlextResult, FlextService

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes


class FlextLdifAclParser(FlextService[dict[str, object]]):
    """Multi-server ACL parser for different LDAP implementations."""

    @override
    def __init__(self) -> None:
        """Initialize ACL parser with Phase 1 context enrichment."""
        super().__init__()
        # Logger and container inherited from FlextService via FlextMixins

    @override
    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute parser service."""
        return FlextResult[dict[str, object]].ok({
            "service": FlextLdifAclParser,
            "status": "ready",
        })

    def parse_openldap_acl(self, acl_string: str) -> FlextResult[FlextLdifModels.Acl]:
        """Parse OpenLDAP olcAccess ACL format.

        Args:
            acl_string: OpenLDAP ACL string

        Returns:
            FlextResult containing unified ACL

        """
        # Create ACL using consolidated Acl model with server_type discriminator
        try:
            acl = FlextLdifModels.Acl(
                name="openldap_acl",
                target=FlextLdifModels.AclTarget(target_dn="*", attributes=[]),
                subject=FlextLdifModels.AclSubject(subject_type="*", subject_value="*"),
                permissions=FlextLdifModels.AclPermissions(read=True),
                server_type=FlextLdifConstants.LdapServers.OPENLDAP,
                raw_acl=acl_string,
            )
            return FlextResult[FlextLdifModels.Acl].ok(acl)
        except Exception as e:
            return FlextResult[FlextLdifModels.Acl].fail(
                f"Failed to parse OpenLDAP ACL: {e}"
            )

    def parse_389ds_acl(self, acl_string: str) -> FlextResult[FlextLdifModels.Acl]:
        """Parse 389DS ACI format.

        Args:
            acl_string: 389DS ACI string

        Returns:
            FlextResult containing unified ACL

        """
        # Create ACL using consolidated Acl model with server_type discriminator
        try:
            acl = FlextLdifModels.Acl(
                name="389ds_acl",
                target=FlextLdifModels.AclTarget(target_dn="*", attributes=[]),
                subject=FlextLdifModels.AclSubject(subject_type="*", subject_value="*"),
                permissions=FlextLdifModels.AclPermissions(read=True),
                server_type=FlextLdifConstants.LdapServers.DS_389,
                raw_acl=acl_string,
            )
            return FlextResult[FlextLdifModels.Acl].ok(acl)
        except Exception as e:
            return FlextResult[FlextLdifModels.Acl].fail(
                f"Failed to parse 389DS ACL: {e}"
            )

    def parse_oracle_acl(
        self,
        acl_string: str,
        server_type: FlextLdifTypes.AclServerType = FlextLdifConstants.LdapServers.ORACLE_OID,
    ) -> FlextResult[FlextLdifModels.Acl]:
        """Parse Oracle OID/OUD ACL format.

        Args:
            acl_string: Oracle ACL string
            server_type: Oracle server type (OID or OUD)

        Returns:
            FlextResult containing unified ACL

        """
        # Use consolidated Acl model with server_type discriminator
        try:
            # Validate Oracle server type
            if server_type not in {
                FlextLdifConstants.LdapServers.ORACLE_OID,
                FlextLdifConstants.LdapServers.ORACLE_OUD,
            }:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"Unknown Oracle server type: {server_type}"
                )

            acl = FlextLdifModels.Acl(
                name="oracle_acl",
                target=FlextLdifModels.AclTarget(target_dn="*", attributes=[]),
                subject=FlextLdifModels.AclSubject(subject_type="*", subject_value="*"),
                permissions=FlextLdifModels.AclPermissions(read=True),
                server_type=server_type,
                raw_acl=acl_string,
            )
            return FlextResult[FlextLdifModels.Acl].ok(acl)
        except Exception as e:
            return FlextResult[FlextLdifModels.Acl].fail(
                f"Failed to parse Oracle ACL: {e}"
            )

    def parse_acl(
        self, acl_string: str, server_type: str
    ) -> FlextResult[FlextLdifModels.Acl]:
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
            return self.parse_oracle_acl(
                acl_string, cast("FlextLdifTypes.AclServerType", server_type)
            )

        return FlextResult[FlextLdifModels.Acl].fail(
            f"Unsupported server type: {server_type}"
        )


__all__ = ["FlextLdifAclParser"]
