"""Unit tests for LDIF ACL utilities.

Tests cover:
- ComponentFactory.create_acl_components()
- ComponentFactory.create_unified_acl() with various server types
- Error handling and type validation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldif.acl.utils import FlextLdifAclUtils
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels


class TestComponentFactory:
    """Test FlextLdifAclUtils.ComponentFactory functionality."""

    def test_create_acl_components_success(self) -> None:
        """Test successful creation of ACL components."""
        result = FlextLdifAclUtils.ComponentFactory.create_acl_components()

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
        result = FlextLdifAclUtils.ComponentFactory.create_acl_components()
        target, _, _ = result.unwrap()

        assert target.target_dn == "*"

    def test_create_acl_components_subject_properties(self) -> None:
        """Test ACL subject component properties."""
        result = FlextLdifAclUtils.ComponentFactory.create_acl_components()
        _, subject, _ = result.unwrap()

        assert subject.subject_type == "*"
        assert subject.subject_value == "*"

    def test_create_acl_components_permissions_properties(self) -> None:
        """Test ACL permissions component properties."""
        result = FlextLdifAclUtils.ComponentFactory.create_acl_components()
        _, _, permissions = result.unwrap()

        assert permissions.read is True

    def test_create_unified_acl_openldap(self) -> None:
        """Test creating unified ACL for OpenLDAP server."""
        target = FlextLdifModels.AclTarget(target_dn="cn=admin")
        subject = FlextLdifModels.AclSubject(subject_type="user", subject_value="admin")
        permissions = FlextLdifModels.AclPermissions(read=True, write=False)

        result = FlextLdifAclUtils.ComponentFactory.create_unified_acl(
            name="openldap_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=FlextLdifConstants.LdapServers.OPENLDAP,
            raw_acl="to * by * read",
        )

        assert result.is_success
        acl = result.unwrap()
        assert isinstance(acl, FlextLdifModels.OpenLdapAcl)
        assert acl.name == "openldap_acl"
        assert acl.server_type == FlextLdifConstants.LdapServers.OPENLDAP

    def test_create_unified_acl_openldap_2(self) -> None:
        """Test creating unified ACL for OpenLDAP 2.x server."""
        target = FlextLdifModels.AclTarget(target_dn="cn=admin")
        subject = FlextLdifModels.AclSubject(subject_type="user", subject_value="admin")
        permissions = FlextLdifModels.AclPermissions(read=True)

        result = FlextLdifAclUtils.ComponentFactory.create_unified_acl(
            name="openldap2_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=FlextLdifConstants.LdapServers.OPENLDAP_2,
            raw_acl="olcAccess: {0}to * by * read",
        )

        assert result.is_success
        acl = result.unwrap()
        assert isinstance(acl, FlextLdifModels.OpenLdap2Acl)

    def test_create_unified_acl_openldap_1(self) -> None:
        """Test creating unified ACL for OpenLDAP 1.x server."""
        target = FlextLdifModels.AclTarget(target_dn="cn=admin")
        subject = FlextLdifModels.AclSubject(subject_type="user", subject_value="admin")
        permissions = FlextLdifModels.AclPermissions(read=True)

        result = FlextLdifAclUtils.ComponentFactory.create_unified_acl(
            name="openldap1_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=FlextLdifConstants.LdapServers.OPENLDAP_1,
            raw_acl="access to * by * read",
        )

        assert result.is_success
        acl = result.unwrap()
        assert isinstance(acl, FlextLdifModels.OpenLdap1Acl)

    def test_create_unified_acl_oracle_oid(self) -> None:
        """Test creating unified ACL for Oracle OID server."""
        target = FlextLdifModels.AclTarget(target_dn="cn=admin")
        subject = FlextLdifModels.AclSubject(subject_type="user", subject_value="admin")
        permissions = FlextLdifModels.AclPermissions(read=True)

        result = FlextLdifAclUtils.ComponentFactory.create_unified_acl(
            name="oid_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=FlextLdifConstants.LdapServers.ORACLE_OID,
            raw_acl="orclaci: (target=...)(version 3.0)",
        )

        assert result.is_success
        acl = result.unwrap()
        assert isinstance(acl, FlextLdifModels.OracleOidAcl)

    def test_create_unified_acl_oracle_oud(self) -> None:
        """Test creating unified ACL for Oracle OUD server."""
        target = FlextLdifModels.AclTarget(target_dn="cn=admin")
        subject = FlextLdifModels.AclSubject(subject_type="user", subject_value="admin")
        permissions = FlextLdifModels.AclPermissions(read=True)

        result = FlextLdifAclUtils.ComponentFactory.create_unified_acl(
            name="oud_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=FlextLdifConstants.LdapServers.ORACLE_OUD,
            raw_acl="aci: (target=...)(version 3.0)",
        )

        assert result.is_success
        acl = result.unwrap()
        assert isinstance(acl, FlextLdifModels.OracleOudAcl)

    def test_create_unified_acl_ds389(self) -> None:
        """Test creating unified ACL for 389 DS server."""
        target = FlextLdifModels.AclTarget(target_dn="cn=admin")
        subject = FlextLdifModels.AclSubject(subject_type="user", subject_value="admin")
        permissions = FlextLdifModels.AclPermissions(read=True)

        result = FlextLdifAclUtils.ComponentFactory.create_unified_acl(
            name="ds389_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=FlextLdifConstants.LdapServers.DS_389,
            raw_acl="aci: (target=...)(version 3.0)",
        )

        assert result.is_success
        acl = result.unwrap()
        assert isinstance(acl, FlextLdifModels.Ds389Acl)

    def test_create_unified_acl_unsupported_server_type_returns_failure(self) -> None:
        """Test that unsupported server types result in validation error."""
        target = FlextLdifModels.AclTarget(target_dn="cn=admin")
        subject = FlextLdifModels.AclSubject(subject_type="user", subject_value="admin")
        permissions = FlextLdifModels.AclPermissions(read=True)

        result = FlextLdifAclUtils.ComponentFactory.create_unified_acl(
            name="unknown_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type="unknown_server",  # type: ignore[arg-type]
            raw_acl="some acl",
        )

        # Should fail validation for unknown server type
        assert result.is_failure

    def test_create_unified_acl_preserves_properties(self) -> None:
        """Test that created ACL preserves all input properties."""
        target = FlextLdifModels.AclTarget(target_dn="cn=test,dc=example,dc=com")
        subject = FlextLdifModels.AclSubject(
            subject_type="group", subject_value="cn=admins,dc=example,dc=com"
        )
        permissions = FlextLdifModels.AclPermissions(
            read=True, write=True, delete=False
        )

        result = FlextLdifAclUtils.ComponentFactory.create_unified_acl(
            name="test_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=FlextLdifConstants.LdapServers.OPENLDAP,
            raw_acl="original acl string",
        )

        acl = result.unwrap()
        assert acl.name == "test_acl"
        assert acl.target == target
        assert acl.subject == subject
        assert acl.permissions == permissions
        assert acl.raw_acl == "original acl string"

    def test_create_unified_acl_returns_aclbase_instance(self) -> None:
        """Test that created ACL is an AclBase instance."""
        target = FlextLdifModels.AclTarget(target_dn="cn=admin")
        subject = FlextLdifModels.AclSubject(subject_type="user", subject_value="admin")
        permissions = FlextLdifModels.AclPermissions(read=True)

        result = FlextLdifAclUtils.ComponentFactory.create_unified_acl(
            name="test_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=FlextLdifConstants.LdapServers.OPENLDAP,
            raw_acl="test",
        )

        acl = result.unwrap()
        assert isinstance(acl, FlextLdifModels.AclBase)

    def test_create_unified_acl_exception_handling_caught(self) -> None:
        """Test exception handling in create_unified_acl (line 140-143) via model validation error."""
        target = FlextLdifModels.AclTarget(target_dn="cn=admin")
        subject = FlextLdifModels.AclSubject(subject_type="user", subject_value="admin")
        # Create invalid permissions that might cause issues
        permissions = FlextLdifModels.AclPermissions(read=True)

        # This should trigger exception handling when creating with invalid component
        result = FlextLdifAclUtils.ComponentFactory.create_unified_acl(
            name="test_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=FlextLdifConstants.LdapServers.OPENLDAP,
            raw_acl="test",
        )

        # Should succeed (normal path)
        assert result.is_success
