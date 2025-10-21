"""FLEXT-LDIF ACL Utilities - Shared helpers for ACL processing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextResult, FlextUtilities

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes


class FlextLdifAclUtils(FlextUtilities):
    """Unified ACL utilities with shared helper methods for ACL processing.

    This namespace class provides common ACL component creation and validation
    logic used across ACL parser and service modules, following FLEXT namespace
    class patterns for centralized utility functions.
    """

    class ComponentFactory:
        """Factory for creating and validating ACL components with railway pattern."""

        @staticmethod
        def create_acl_components() -> FlextResult[
            tuple[
                FlextLdifModels.AclTarget,
                FlextLdifModels.AclSubject,
                FlextLdifModels.AclPermissions,
            ]
        ]:
            """Create ACL components with proper validation using railway pattern.

            Returns:
                FlextResult containing tuple of (target, subject, permissions) on success,
                or failure with descriptive error message.

            """
            # Create ACL components using direct instantiation
            target_result = FlextResult.ok(FlextLdifModels.AclTarget(target_dn="*"))
            subject_result = FlextResult.ok(
                FlextLdifModels.AclSubject(subject_type="*", subject_value="*")
            )
            perms_result = FlextResult.ok(FlextLdifModels.AclPermissions(read=True))

            # Early return on first failure
            if target_result.is_failure:
                return FlextResult.fail(
                    f"Failed to create AclTarget: {target_result.error}"
                )

            if subject_result.is_failure:
                return FlextResult.fail(
                    f"Failed to create AclSubject: {subject_result.error}"
                )

            if perms_result.is_failure:
                return FlextResult.fail(
                    f"Failed to create AclPermissions: {perms_result.error}"
                )

            # Type safety validation
            target = target_result.unwrap()
            subject = subject_result.unwrap()
            permissions = perms_result.unwrap()

            if not isinstance(target, FlextLdifModels.AclTarget):
                return FlextResult.fail("Created object is not an AclTarget instance")

            if not isinstance(subject, FlextLdifModels.AclSubject):
                return FlextResult.fail("Created object is not an AclSubject instance")

            if not isinstance(permissions, FlextLdifModels.AclPermissions):
                return FlextResult.fail(
                    "Created object is not an AclPermissions instance"
                )

            return FlextResult.ok((target, subject, permissions))

        @staticmethod
        def create_unified_acl(
            name: str,
            target: FlextLdifModels.AclTarget,
            subject: FlextLdifModels.AclSubject,
            permissions: FlextLdifModels.AclPermissions,
            server_type: FlextLdifTypes.AclServerType,
            raw_acl: str,
        ) -> FlextResult[FlextLdifModels.AclBase]:
            """Create unified ACL with proper validation using railway pattern.

            Uses discriminated union pattern to route to correct ACL subtype based on server_type.

            Args:
                name: ACL name
                target: ACL target component
                subject: ACL subject component
                permissions: ACL permissions component
                server_type: Server type (openldap, oid, etc.)
                raw_acl: Original ACL string

            Returns:
                FlextResult containing AclBase subtype on success, failure otherwise.

            """
            try:
                # Map server_type to correct ACL subclass
                acl_class_map = {
                    FlextLdifConstants.LdapServers.OPENLDAP: FlextLdifModels.OpenLdapAcl,
                    FlextLdifConstants.LdapServers.OPENLDAP_2: FlextLdifModels.OpenLdap2Acl,
                    FlextLdifConstants.LdapServers.OPENLDAP_1: FlextLdifModels.OpenLdap1Acl,
                    FlextLdifConstants.LdapServers.ORACLE_OID: FlextLdifModels.OracleOidAcl,
                    FlextLdifConstants.LdapServers.ORACLE_OUD: FlextLdifModels.OracleOudAcl,
                    FlextLdifConstants.LdapServers.DS_389: FlextLdifModels.Ds389Acl,
                }

                # Default to OpenLDAP for generic/unknown server types
                acl_class = acl_class_map.get(server_type, FlextLdifModels.OpenLdapAcl)

                # Create ACL using the determined subclass
                unified_acl = acl_class(
                    name=name,
                    target=target,
                    subject=subject,
                    permissions=permissions,
                    server_type=server_type,
                    raw_acl=raw_acl,
                )

                # Verify created instance is correct type
                if not isinstance(unified_acl, FlextLdifModels.AclBase):
                    return FlextResult[FlextLdifModels.AclBase].fail(
                        "Created object is not an AclBase instance"
                    )

                return FlextResult[FlextLdifModels.AclBase].ok(unified_acl)
            except Exception as e:  # pragma: no cover
                return FlextResult[FlextLdifModels.AclBase].fail(
                    f"Failed to create ACL: {e}"
                )


__all__ = ["FlextLdifAclUtils"]
