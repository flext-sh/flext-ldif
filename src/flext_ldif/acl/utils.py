"""FLEXT-LDIF ACL Utilities - Shared helpers for ACL processing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextCore

from flext_ldif.models import FlextLdifModels


class FlextLdifAclUtils(FlextCore.Utilities):
    """Unified ACL utilities with shared helper methods for ACL processing.

    This namespace class provides common ACL component creation and validation
    logic used across ACL parser and service modules, following FLEXT namespace
    class patterns for centralized utility functions.
    """

    class ComponentFactory:
        """Factory for creating and validating ACL components with railway pattern."""

        @staticmethod
        def create_acl_components() -> FlextCore.Result[
            tuple[
                FlextLdifModels.AclTarget,
                FlextLdifModels.AclSubject,
                FlextLdifModels.AclPermissions,
            ]
        ]:
            """Create ACL components with proper validation using railway pattern.

            Returns:
                FlextCore.Result containing tuple of (target, subject, permissions) on success,
                or failure with descriptive error message.

            """
            # Create ACL components using direct instantiation
            target_result = FlextCore.Result.ok(
                FlextLdifModels.AclTarget(target_dn="*")
            )
            subject_result = FlextCore.Result.ok(
                FlextLdifModels.AclSubject(subject_type="*", subject_value="*")
            )
            perms_result = FlextCore.Result.ok(
                FlextLdifModels.AclPermissions(read=True)
            )

            # Railway pattern: early return on first failure
            if target_result.is_failure:
                return FlextCore.Result.fail(
                    f"Failed to create AclTarget: {target_result.error}"
                )

            if subject_result.is_failure:
                return FlextCore.Result.fail(
                    f"Failed to create AclSubject: {subject_result.error}"
                )

            if perms_result.is_failure:
                return FlextCore.Result.fail(
                    f"Failed to create AclPermissions: {perms_result.error}"
                )

            # Type safety validation
            target = target_result.unwrap()
            subject = subject_result.unwrap()
            permissions = perms_result.unwrap()

            if not isinstance(target, FlextLdifModels.AclTarget):
                return FlextCore.Result.fail(
                    "Created object is not an AclTarget instance"
                )

            if not isinstance(subject, FlextLdifModels.AclSubject):
                return FlextCore.Result.fail(
                    "Created object is not an AclSubject instance"
                )

            if not isinstance(permissions, FlextLdifModels.AclPermissions):
                return FlextCore.Result.fail(
                    "Created object is not an AclPermissions instance"
                )

            return FlextCore.Result.ok((target, subject, permissions))

        @staticmethod
        def create_unified_acl(
            name: str,
            target: FlextLdifModels.AclTarget,
            subject: FlextLdifModels.AclSubject,
            permissions: FlextLdifModels.AclPermissions,
            server_type: str,
            raw_acl: str,
        ) -> FlextCore.Result[FlextLdifModels.Acl]:
            """Create unified ACL with proper validation using railway pattern.

            Args:
                name: ACL name
                target: ACL target component
                subject: ACL subject component
                permissions: ACL permissions component
                server_type: Server type (openldap, oid, etc.)
                raw_acl: Original ACL string

            Returns:
                FlextCore.Result containing Acl on success, failure otherwise.

            """
            acl_result = FlextCore.Result.ok(
                FlextLdifModels.Acl(
                    name=name,
                    target=target,
                    subject=subject,
                    permissions=permissions,
                    server_type=server_type,
                    raw_acl=raw_acl,
                )
            )

            if acl_result.is_failure:
                return FlextCore.Result.fail(
                    f"Failed to create Acl: {acl_result.error}"
                )

            unified_acl = acl_result.unwrap()
            if not isinstance(unified_acl, FlextLdifModels.Acl):
                return FlextCore.Result.fail("Created object is not a Acl instance")

            return FlextCore.Result.ok(unified_acl)


__all__ = ["FlextLdifAclUtils"]
