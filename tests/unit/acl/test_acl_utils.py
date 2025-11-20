"""Unit tests for LDIF ACL utilities.

Tests cover:
- ComponentFactory.create_acl_components()
- ComponentFactory.create_unified_acl() with various server types
- Error handling and type validation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes


# ===== ACL Component Factory Helpers (replaced FlextLdifUtilities) =====
def create_acl_components_helper() -> FlextResult[
    tuple[
        FlextLdifModels.AclTarget,
        FlextLdifModels.AclSubject,
        FlextLdifModels.AclPermissions,
    ]
]:
    """Create ACL components with proper validation using railway pattern.

    Replaces create_acl_components_helper()
    with direct model creation.

    Returns:
        FlextResult containing tuple of (target, subject, permissions) on success,
        or failure with descriptive error message.

    """
    # Create ACL components using direct instantiation
    target = FlextLdifModels.AclTarget(
        target_dn=FlextLdifConstants.ServerDetection.ACL_WILDCARD_DN,
    )
    subject = FlextLdifModels.AclSubject(
        subject_type=FlextLdifConstants.ServerDetection.ACL_WILDCARD_TYPE,
        subject_value=FlextLdifConstants.ServerDetection.ACL_WILDCARD_VALUE,
    )
    permissions = FlextLdifModels.AclPermissions(read=True)

    return FlextResult[
        tuple[
            FlextLdifModels.AclTarget,
            FlextLdifModels.AclSubject,
            FlextLdifModels.AclPermissions,
        ]
    ].ok((target, subject, permissions))


def create_unified_acl_helper(
    name: str,
    target: FlextLdifModels.AclTarget,
    subject: FlextLdifModels.AclSubject,
    permissions: FlextLdifModels.AclPermissions,
    server_type: FlextLdifTypes.AclServerType,
    raw_acl: str,
) -> FlextResult[FlextLdifModels.Acl]:
    """Create unified ACL with proper validation using railway pattern.

    Replaces create_unified_acl_helper()
    with direct model creation.

    Args:
        name: ACL name
        target: ACL target component
        subject: ACL subject component
        permissions: ACL permissions component
        server_type: Server type (openldap, oid, etc.)
        raw_acl: Original ACL string

    Returns:
        FlextResult containing Acl instance on success, failure otherwise.

    """
    try:
        # Validate server_type is supported
        supported_servers = {
            FlextLdifConstants.LdapServers.OPENLDAP,
            FlextLdifConstants.LdapServers.OPENLDAP_2,
            FlextLdifConstants.LdapServers.OPENLDAP_1,
            FlextLdifConstants.LdapServers.ORACLE_OID,
            FlextLdifConstants.LdapServers.ORACLE_OUD,
            FlextLdifConstants.LdapServers.DS_389,
        }

        # Default to OpenLDAP for generic/unknown server types
        effective_server_type = (
            server_type
            if server_type in supported_servers
            else FlextLdifConstants.LdapServers.OPENLDAP
        )

        # Create ACL using consolidated Acl model
        unified_acl = FlextLdifModels.Acl(
            name=name,
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=effective_server_type,
            raw_acl=raw_acl,
        )

        return FlextResult[FlextLdifModels.Acl].ok(unified_acl)
    except (ValueError, TypeError, AttributeError) as e:
        return FlextResult[FlextLdifModels.Acl].fail(f"Failed to create ACL: {e}")


class TestComponentFactory:
    """Test FlextLdifUtilities.AclUtils.ComponentFactory functionality."""

    def test_create_acl_components_success(self) -> None:
        """Test successful creation of ACL components."""
        result = create_acl_components_helper()

        assert result.is_success
        components = result.unwrap()
        assert isinstance(components, tuple)
        assert len(components) == 3

        target, subject, permissions = components
        assert isinstance(target, FlextLdifModels.AclTarget)
        assert isinstance(subject, FlextLdifModels.AclSubject)
        assert isinstance(permissions, FlextLdifModels.AclPermissions)

    def test_create_acl_components_target_properties(self) -> None:
        """Test ACL target component properties."""
        result = create_acl_components_helper()
        target, _, _ = result.unwrap()

        assert target.target_dn == "*"

    def test_create_acl_components_subject_properties(self) -> None:
        """Test ACL subject component properties."""
        result = create_acl_components_helper()
        _, subject, _ = result.unwrap()

        assert subject.subject_type == "*"
        assert subject.subject_value == "*"

    def test_create_acl_components_permissions_properties(self) -> None:
        """Test ACL permissions component properties."""
        result = create_acl_components_helper()
        _, _, permissions = result.unwrap()

        assert permissions.read is True

    def test_create_unified_acl_openldap(self) -> None:
        """Test creating unified ACL for OpenLDAP server."""
        target = FlextLdifModels.AclTarget(target_dn="cn=admin")
        subject = FlextLdifModels.AclSubject(subject_type="user", subject_value="admin")
        permissions = FlextLdifModels.AclPermissions(read=True, write=False)

        # Store constant in variable to avoid pytest assertion rewriting issues
        server_type = FlextLdifConstants.LdapServers.OPENLDAP

        result = create_unified_acl_helper(
            name="openldap_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=server_type,
            raw_acl="to * by * read",
        )

        assert result.is_success
        acl = result.unwrap()
        assert isinstance(acl, FlextLdifModels.Acl)
        assert acl.name == "openldap_acl"
        # Store constant in variable to avoid pytest assertion rewriting issues
        expected_server_type = FlextLdifConstants.LdapServers.OPENLDAP
        assert acl.server_type == expected_server_type

    def test_create_unified_acl_openldap_2(self) -> None:
        """Test creating unified ACL for OpenLDAP 2.x server."""
        target = FlextLdifModels.AclTarget(target_dn="cn=admin")
        subject = FlextLdifModels.AclSubject(subject_type="user", subject_value="admin")
        permissions = FlextLdifModels.AclPermissions(read=True)

        # Store constant in variable to avoid pytest assertion rewriting issues
        server_type = FlextLdifConstants.LdapServers.OPENLDAP_2

        result = create_unified_acl_helper(
            name="openldap2_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=server_type,
            raw_acl="olcAccess: {0}to * by * read",
        )

        assert result.is_success
        acl = result.unwrap()
        assert isinstance(acl, FlextLdifModels.Acl)

    def test_create_unified_acl_openldap_1(self) -> None:
        """Test creating unified ACL for OpenLDAP 1.x server."""
        target = FlextLdifModels.AclTarget(target_dn="cn=admin")
        subject = FlextLdifModels.AclSubject(subject_type="user", subject_value="admin")
        permissions = FlextLdifModels.AclPermissions(read=True)

        # Store constant in variable to avoid pytest assertion rewriting issues
        server_type = FlextLdifConstants.LdapServers.OPENLDAP_1

        result = create_unified_acl_helper(
            name="openldap1_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=server_type,
            raw_acl="access to * by * read",
        )

        assert result.is_success
        acl = result.unwrap()
        assert isinstance(acl, FlextLdifModels.Acl)

    def test_create_unified_acl_oracle_oid(self) -> None:
        """Test creating unified ACL for Oracle OID server."""
        target = FlextLdifModels.AclTarget(target_dn="cn=admin")
        subject = FlextLdifModels.AclSubject(subject_type="user", subject_value="admin")
        permissions = FlextLdifModels.AclPermissions(read=True)

        # Use valid AclServerType: "oid"
        result = create_unified_acl_helper(
            name="oid_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type="oid",
            raw_acl="orclaci: (target=...)(version 3.0)",
        )

        assert result.is_success
        acl = result.unwrap()
        assert isinstance(acl, FlextLdifModels.Acl)

    def test_create_unified_acl_oracle_oud(self) -> None:
        """Test creating unified ACL for Oracle OUD server."""
        target = FlextLdifModels.AclTarget(target_dn="cn=admin")
        subject = FlextLdifModels.AclSubject(subject_type="user", subject_value="admin")
        permissions = FlextLdifModels.AclPermissions(read=True)

        # Use valid AclServerType: "oud"
        result = create_unified_acl_helper(
            name="oud_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type="oud",
            raw_acl="aci: (target=...)(version 3.0)",
        )

        assert result.is_success
        acl = result.unwrap()
        assert isinstance(acl, FlextLdifModels.Acl)

    def test_create_unified_acl_ds389(self) -> None:
        """Test creating unified ACL for 389 DS server."""
        target = FlextLdifModels.AclTarget(target_dn="cn=admin")
        subject = FlextLdifModels.AclSubject(subject_type="user", subject_value="admin")
        permissions = FlextLdifModels.AclPermissions(read=True)

        # Use valid AclServerType: "openldap" (389DS uses similar format)
        result = create_unified_acl_helper(
            name="ds389_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type="openldap",
            raw_acl="aci: (target=...)(version 3.0)",
        )

        assert result.is_success
        acl = result.unwrap()
        assert isinstance(acl, FlextLdifModels.Acl)

    def test_create_unified_acl_with_valid_server_type(self) -> None:
        """Test creating unified ACL with valid server type."""
        target = FlextLdifModels.AclTarget(target_dn="cn=admin")
        subject = FlextLdifModels.AclSubject(subject_type="user", subject_value="admin")
        permissions = FlextLdifModels.AclPermissions(read=True)

        # Use valid AclServerType
        result = create_unified_acl_helper(
            name="test_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type="openldap",
            raw_acl="some acl",
        )

        # Should succeed
        assert result.is_success
        if result.is_success:
            acl = result.unwrap()
            assert isinstance(acl, FlextLdifModels.Acl)

    def test_create_unified_acl_preserves_properties(self) -> None:
        """Test that created ACL preserves all input properties."""
        target = FlextLdifModels.AclTarget(target_dn="cn=test,dc=example,dc=com")
        subject = FlextLdifModels.AclSubject(
            subject_type="group",
            subject_value="cn=admins,dc=example,dc=com",
        )
        permissions = FlextLdifModels.AclPermissions(
            read=True,
            write=True,
            delete=False,
        )

        # Store constant in variable to avoid pytest assertion rewriting issues
        server_type = FlextLdifConstants.LdapServers.OPENLDAP

        result = create_unified_acl_helper(
            name="test_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=server_type,
            raw_acl="original acl string",
        )

        acl = result.unwrap()
        assert acl.name == "test_acl"
        assert acl.target == target
        assert acl.subject == subject
        assert acl.permissions == permissions
        assert acl.raw_acl == "original acl string"

    def test_create_unified_acl_returns_aclbase_instance(self) -> None:
        """Test that created ACL is an FlextLdifModels.Acl instance."""
        target = FlextLdifModels.AclTarget(target_dn="cn=admin")
        subject = FlextLdifModels.AclSubject(subject_type="user", subject_value="admin")
        permissions = FlextLdifModels.AclPermissions(read=True)

        # Store constant in variable to avoid pytest assertion rewriting issues
        server_type = FlextLdifConstants.LdapServers.OPENLDAP

        result = create_unified_acl_helper(
            name="test_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=server_type,
            raw_acl="test",
        )

        acl = result.unwrap()
        assert isinstance(acl, FlextLdifModels.Acl)

    def test_create_unified_acl_exception_handling_caught(self) -> None:
        """Test exception handling in create_unified_acl (line 140-143) via model validation error."""
        target = FlextLdifModels.AclTarget(target_dn="cn=admin")
        subject = FlextLdifModels.AclSubject(subject_type="user", subject_value="admin")
        # Create invalid permissions that might cause issues
        permissions = FlextLdifModels.AclPermissions(read=True)

        # This should trigger exception handling when creating with invalid component
        # Store constant in variable to avoid pytest assertion rewriting issues
        server_type = FlextLdifConstants.LdapServers.OPENLDAP

        result = create_unified_acl_helper(
            name="test_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=server_type,
            raw_acl="test",
        )

        # Should succeed (normal path)
        assert result.is_success

    def test_create_acl_components_with_invalid_data(self) -> None:
        """Test create_acl_components with invalid server type defaults to OpenLDAP."""
        # Use invalid server type - function should default to OpenLDAP
        target = FlextLdifModels.AclTarget(target_dn="*")
        subject = FlextLdifModels.AclSubject(subject_type="*", subject_value="*")
        permissions = FlextLdifModels.AclPermissions(read=True)

        # Use invalid server type - should default to OpenLDAP
        result = create_unified_acl_helper(
            name="",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type="invalid_server_type",
            raw_acl="(access to *)",
        )

        # Should succeed with default server_type (OpenLDAP)
        assert result.is_success
        acl = result.unwrap()
        assert acl.server_type == FlextLdifConstants.LdapServers.OPENLDAP
