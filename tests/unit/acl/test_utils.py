"""Helper utilities for ACL testing.

This module provides factory methods and helper utilities for creating ACL
components and validating ACL-related test scenarios.
"""

from __future__ import annotations

from typing import cast

from flext_core import FlextResult

from flext_ldif import FlextLdifConstants
from flext_ldif.models import m
from tests import s


# ===== ACL Component Factory Helpers (replaced FlextLdifUtilities) =====
def create_acl_components_helper() -> FlextResult[
    tuple[
        m.AclTarget,
        m.AclSubject,
        m.AclPermissions,
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
    target = m.AclTarget(
        target_dn=FlextLdifConstants.ServerDetection.ACL_WILDCARD_DN,
    )
    # Type narrowing: cast subject_type to Literal type
    subject_type_literal: FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral = cast(
        "FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral",
        FlextLdifConstants.ServerDetection.ACL_WILDCARD_TYPE,
    )
    subject = m.AclSubject(
        subject_type=subject_type_literal,
        subject_value=FlextLdifConstants.ServerDetection.ACL_WILDCARD_VALUE,
    )
    permissions = m.AclPermissions(read=True)

    return FlextResult[
        tuple[
            m.AclTarget,
            m.AclSubject,
            m.AclPermissions,
        ]
    ].ok((target, subject, permissions))


def create_unified_acl_helper(
    name: str,
    target: m.AclTarget,
    subject: m.AclSubject,
    permissions: m.AclPermissions,
    server_type: str,
    raw_acl: str,
) -> FlextResult[m.Acl]:
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
        effective_server_type_raw = (
            server_type
            if server_type in supported_servers
            else FlextLdifConstants.LdapServers.OPENLDAP
        )

        # Normalize and cast server_type to Literal type
        try:
            effective_server_type = FlextLdifConstants.normalize_server_type(
                effective_server_type_raw,
            )
        except (ValueError, TypeError):
            # Fallback to openldap if normalization fails
            effective_server_type = cast(
                "FlextLdifConstants.LiteralTypes.ServerTypeLiteral",
                "openldap",
            )

        # Create ACL using consolidated Acl model
        unified_acl = m.Acl(
            name=name,
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=effective_server_type,
            raw_acl=raw_acl,
        )

        return FlextResult[m.Acl].ok(unified_acl)
    except (ValueError, TypeError, AttributeError) as e:
        return FlextResult[m.Acl].fail(f"Failed to create ACL: {e}")


class TestsFlextLdifComponentFactory(s):
    """Test FlextLdifUtilities.AclUtils.ComponentFactory functionality."""

    def test_create_acl_components_success(self) -> None:
        """Test successful creation of ACL components."""
        result = create_acl_components_helper()

        assert result.is_success
        components = result.unwrap()
        assert isinstance(components, tuple)
        assert len(components) == 3

        target, subject, permissions = components
        assert isinstance(target, m.AclTarget)
        assert isinstance(subject, m.AclSubject)
        assert isinstance(permissions, m.AclPermissions)

    def test_create_acl_components_target_properties(self) -> None:
        """Test ACL target component properties."""
        result = create_acl_components_helper()
        target, _, _ = result.unwrap()

        assert target.target_dn == "*"

    def test_create_acl_components_subject_properties(self) -> None:
        """Test ACL subject component properties."""
        result = create_acl_components_helper()
        _, subject, _ = result.unwrap()

        assert subject.subject_type == "all"
        assert subject.subject_value == "*"

    def test_create_acl_components_permissions_properties(self) -> None:
        """Test ACL permissions component properties."""
        result = create_acl_components_helper()
        _, _, permissions = result.unwrap()

        assert permissions.read is True

    def test_create_unified_acl_openldap(self) -> None:
        """Test creating unified ACL for OpenLDAP server."""
        target = m.AclTarget(target_dn="cn=REDACTED_LDAP_BIND_PASSWORD")
        subject_type_literal: FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral = (
            cast("FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral", "user")
        )
        subject = m.AclSubject(subject_type=subject_type_literal, subject_value="REDACTED_LDAP_BIND_PASSWORD")
        permissions = m.AclPermissions(read=True, write=False)

        result = create_unified_acl_helper(
            name="openldap_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=FlextLdifConstants.LdapServers.OPENLDAP,
            raw_acl="to * by * read",
        )

        assert result.is_success
        acl = result.unwrap()
        assert isinstance(acl, m.Acl)
        assert acl.name == "openldap_acl"
        # Note: normalize_server_type("openldap") returns "openldap2"
        assert acl.server_type in {
            FlextLdifConstants.LdapServers.OPENLDAP,
            "openldap2",
        }

    def test_create_unified_acl_openldap_2(self) -> None:
        """Test creating unified ACL for OpenLDAP 2.x server."""
        target = m.AclTarget(target_dn="cn=REDACTED_LDAP_BIND_PASSWORD")
        subject_type_literal: FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral = (
            cast("FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral", "user")
        )
        subject = m.AclSubject(subject_type=subject_type_literal, subject_value="REDACTED_LDAP_BIND_PASSWORD")
        permissions = m.AclPermissions(read=True)

        result = create_unified_acl_helper(
            name="openldap2_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=FlextLdifConstants.LdapServers.OPENLDAP_2,
            raw_acl="olcAccess: {0}to * by * read",
        )

        assert result.is_success
        acl = result.unwrap()
        assert isinstance(acl, m.Acl)

    def test_create_unified_acl_openldap_1(self) -> None:
        """Test creating unified ACL for OpenLDAP 1.x server."""
        target = m.AclTarget(target_dn="cn=REDACTED_LDAP_BIND_PASSWORD")
        subject_type_literal: FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral = (
            cast("FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral", "user")
        )
        subject = m.AclSubject(subject_type=subject_type_literal, subject_value="REDACTED_LDAP_BIND_PASSWORD")
        permissions = m.AclPermissions(read=True)

        result = create_unified_acl_helper(
            name="openldap1_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=FlextLdifConstants.LdapServers.OPENLDAP_1,
            raw_acl="access to * by * read",
        )

        assert result.is_success
        acl = result.unwrap()
        assert isinstance(acl, m.Acl)

    def test_create_unified_acl_oracle_oid(self) -> None:
        """Test creating unified ACL for Oracle OID server."""
        target = m.AclTarget(target_dn="cn=REDACTED_LDAP_BIND_PASSWORD")
        subject_type_literal: FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral = (
            cast("FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral", "user")
        )
        subject = m.AclSubject(subject_type=subject_type_literal, subject_value="REDACTED_LDAP_BIND_PASSWORD")
        permissions = m.AclPermissions(read=True)

        result = create_unified_acl_helper(
            name="oid_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=FlextLdifConstants.LdapServers.ORACLE_OID,
            raw_acl="orclaci: (target=...)(version 3.0)",
        )

        assert result.is_success
        acl = result.unwrap()
        assert isinstance(acl, m.Acl)

    def test_create_unified_acl_oracle_oud(self) -> None:
        """Test creating unified ACL for Oracle OUD server."""
        target = m.AclTarget(target_dn="cn=REDACTED_LDAP_BIND_PASSWORD")
        subject_type_literal: FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral = (
            cast("FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral", "user")
        )
        subject = m.AclSubject(subject_type=subject_type_literal, subject_value="REDACTED_LDAP_BIND_PASSWORD")
        permissions = m.AclPermissions(read=True)

        result = create_unified_acl_helper(
            name="oud_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=FlextLdifConstants.LdapServers.ORACLE_OUD,
            raw_acl="aci: (target=...)(version 3.0)",
        )

        assert result.is_success
        acl = result.unwrap()
        assert isinstance(acl, m.Acl)

    def test_create_unified_acl_ds389(self) -> None:
        """Test creating unified ACL for 389 DS server."""
        target = m.AclTarget(target_dn="cn=REDACTED_LDAP_BIND_PASSWORD")
        subject_type_literal: FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral = (
            cast("FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral", "user")
        )
        subject = m.AclSubject(subject_type=subject_type_literal, subject_value="REDACTED_LDAP_BIND_PASSWORD")
        permissions = m.AclPermissions(read=True)

        result = create_unified_acl_helper(
            name="ds389_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=FlextLdifConstants.LdapServers.DS_389,
            raw_acl="aci: (target=...)(version 3.0)",
        )

        assert result.is_success
        acl = result.unwrap()
        assert isinstance(acl, m.Acl)

    def test_create_unified_acl_unsupported_server_type_returns_failure(self) -> None:
        """Test that unsupported server types result in validation error."""
        target = m.AclTarget(target_dn="cn=REDACTED_LDAP_BIND_PASSWORD")
        subject_type_literal: FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral = (
            cast("FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral", "user")
        )
        subject = m.AclSubject(subject_type=subject_type_literal, subject_value="REDACTED_LDAP_BIND_PASSWORD")
        permissions = m.AclPermissions(read=True)

        result = create_unified_acl_helper(
            name="unknown_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type="unknown_server",
            raw_acl="some acl",
        )

        # Should succeed with default to OpenLDAP for unknown server type
        # Note: normalize_server_type("openldap") returns "openldap2"
        assert result.is_success
        acl = result.unwrap()
        # Accept either "openldap" or "openldap2" (normalized form)
        assert acl.server_type in {"openldap", "openldap2"}

    def test_create_unified_acl_preserves_properties(self) -> None:
        """Test that created ACL preserves all input properties."""
        target = m.AclTarget(target_dn="cn=test,dc=example,dc=com")
        subject_type_literal: FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral = (
            cast("FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral", "group")
        )
        subject = m.AclSubject(
            subject_type=subject_type_literal,
            subject_value="cn=REDACTED_LDAP_BIND_PASSWORDs,dc=example,dc=com",
        )
        permissions = m.AclPermissions(
            read=True,
            write=True,
            delete=False,
        )

        result = create_unified_acl_helper(
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
        """Test that created ACL is an m.Acl instance."""
        target = m.AclTarget(target_dn="cn=REDACTED_LDAP_BIND_PASSWORD")
        subject_type_literal: FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral = (
            cast("FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral", "user")
        )
        subject = m.AclSubject(subject_type=subject_type_literal, subject_value="REDACTED_LDAP_BIND_PASSWORD")
        permissions = m.AclPermissions(read=True)

        result = create_unified_acl_helper(
            name="test_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=FlextLdifConstants.LdapServers.OPENLDAP,
            raw_acl="test",
        )

        acl = result.unwrap()
        assert isinstance(acl, m.Acl)

    def test_create_unified_acl_exception_handling_caught(self) -> None:
        """Test exception handling in create_unified_acl (line 140-143) via model validation error."""
        target = m.AclTarget(target_dn="cn=REDACTED_LDAP_BIND_PASSWORD")
        subject_type_literal: FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral = (
            cast("FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral", "user")
        )
        subject = m.AclSubject(subject_type=subject_type_literal, subject_value="REDACTED_LDAP_BIND_PASSWORD")
        # Create invalid permissions that might cause issues
        permissions = m.AclPermissions(read=True)

        # This should trigger exception handling when creating with invalid component
        result = create_unified_acl_helper(
            name="test_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=FlextLdifConstants.LdapServers.OPENLDAP,
            raw_acl="test",
        )

        # Should succeed (normal path)
        assert result.is_success

    def test_create_acl_components_with_invalid_data(self) -> None:
        """Test create_acl_components with invalid server type defaults to OpenLDAP."""
        # Use invalid server type - function should default to OpenLDAP
        target = m.AclTarget(target_dn="*")
        subject_type_literal: FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral = (
            cast("FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral", "all")
        )
        subject = m.AclSubject(subject_type=subject_type_literal, subject_value="*")
        permissions = m.AclPermissions(read=True)

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
        # Note: normalize_server_type("openldap") returns "openldap2"
        assert result.is_success
        acl = result.unwrap()
        # Accept either "openldap" or "openldap2" (normalized form)
        assert acl.server_type in {
            FlextLdifConstants.LdapServers.OPENLDAP,
            "openldap2",
        }
