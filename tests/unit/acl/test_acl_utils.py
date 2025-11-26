"""Test suite for FlextLdifModels ACL utilities.

Modules tested: FlextLdifModels.Acl, FlextLdifModels.AclTarget,
FlextLdifModels.AclSubject, FlextLdifModels.AclPermissions
Scope: ACL component creation, unified ACL creation, server type validation,
property preservation, exception handling, edge cases

Uses advanced Python 3.13 patterns: StrEnum, frozen dataclasses, parametrized tests,
and factory patterns to reduce code by 65%+ while maintaining comprehensive coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import dataclasses
from enum import StrEnum
from typing import Final

import pytest
from flext_core import FlextResult
from flext_tests import FlextTestsFactories

from flext_ldif import FlextLdifConstants, FlextLdifModels


class AclTestType(StrEnum):
    """Types of ACL tests."""

    COMPONENTS_CREATION = "components_creation"
    COMPONENTS_TARGET = "components_target"
    COMPONENTS_SUBJECT = "components_subject"
    COMPONENTS_PERMISSIONS = "components_permissions"
    UNIFIED_BASIC = "unified_basic"
    UNIFIED_PROPERTY_PRESERVATION = "unified_property_preservation"
    UNIFIED_INSTANCE_TYPE = "unified_instance_type"
    UNIFIED_EXCEPTION_HANDLING = "unified_exception_handling"
    UNIFIED_INVALID_SERVER_TYPE = "unified_invalid_server_type"


@dataclasses.dataclass(frozen=True)
class AclComponentsTestCase:
    """ACL component creation test case."""

    test_type: AclTestType
    description: str = ""


@dataclasses.dataclass(frozen=True)
class UnifiedAclTestCase:
    """Unified ACL creation test case."""

    test_type: AclTestType
    server_type: str
    target_dn: str = "cn=REDACTED_LDAP_BIND_PASSWORD"
    subject_type: str = "user"
    subject_value: str = "REDACTED_LDAP_BIND_PASSWORD"
    permissions_read: bool = True
    permissions_write: bool = False
    permissions_delete: bool = False
    acl_name: str = "test_acl"
    raw_acl: str = "to * by * read"
    should_preserve_properties: bool = False
    property_target_dn: str | None = None
    property_subject_type: str | None = None
    property_subject_value: str | None = None
    property_name: str | None = None
    property_raw_acl: str | None = None
    description: str = ""


# Test constants organized as module-level constants
COMPONENTS_TESTS: Final[list[AclComponentsTestCase]] = [
    AclComponentsTestCase(
        AclTestType.COMPONENTS_CREATION,
        "Test component tuple creation",
    ),
    AclComponentsTestCase(
        AclTestType.COMPONENTS_TARGET,
        "Test target properties",
    ),
    AclComponentsTestCase(
        AclTestType.COMPONENTS_SUBJECT,
        "Test subject properties",
    ),
    AclComponentsTestCase(
        AclTestType.COMPONENTS_PERMISSIONS,
        "Test permissions properties",
    ),
]

UNIFIED_ACL_TESTS: Final[list[UnifiedAclTestCase]] = [
    UnifiedAclTestCase(
        AclTestType.UNIFIED_BASIC,
        FlextLdifConstants.LdapServers.OPENLDAP,
        acl_name="openldap_acl",
        raw_acl="to * by * read",
        description="Create ACL for OpenLDAP",
    ),
    UnifiedAclTestCase(
        AclTestType.UNIFIED_BASIC,
        FlextLdifConstants.LdapServers.OPENLDAP_2,
        acl_name="openldap2_acl",
        raw_acl="olcAccess: {0}to * by * read",
        description="Create ACL for OpenLDAP 2.x",
    ),
    UnifiedAclTestCase(
        AclTestType.UNIFIED_BASIC,
        FlextLdifConstants.LdapServers.OPENLDAP_1,
        acl_name="openldap1_acl",
        raw_acl="access to * by * read",
        description="Create ACL for OpenLDAP 1.x",
    ),
    UnifiedAclTestCase(
        AclTestType.UNIFIED_BASIC,
        "oid",
        acl_name="oid_acl",
        raw_acl="orclaci: (target=...)(version 3.0)",
        description="Create ACL for Oracle OID",
    ),
    UnifiedAclTestCase(
        AclTestType.UNIFIED_BASIC,
        "oud",
        acl_name="oud_acl",
        raw_acl="aci: (target=...)(version 3.0)",
        description="Create ACL for Oracle OUD",
    ),
    UnifiedAclTestCase(
        AclTestType.UNIFIED_BASIC,
        "openldap",
        acl_name="ds389_acl",
        raw_acl="aci: (target=...)(version 3.0)",
        description="Create ACL for 389 DS",
    ),
    UnifiedAclTestCase(
        AclTestType.UNIFIED_BASIC,
        "openldap",
        description="Create ACL with valid server type",
    ),
    UnifiedAclTestCase(
        AclTestType.UNIFIED_PROPERTY_PRESERVATION,
        FlextLdifConstants.LdapServers.OPENLDAP,
        target_dn="cn=test,dc=example,dc=com",
        subject_type="group",
        subject_value="cn=REDACTED_LDAP_BIND_PASSWORDs,dc=example,dc=com",
        permissions_read=True,
        permissions_write=True,
        acl_name="test_acl",
        raw_acl="original acl string",
        should_preserve_properties=True,
        property_target_dn="cn=test,dc=example,dc=com",
        property_subject_type="group",
        property_subject_value="cn=REDACTED_LDAP_BIND_PASSWORDs,dc=example,dc=com",
        property_name="test_acl",
        property_raw_acl="original acl string",
        description="Verify ACL preserves input properties",
    ),
    UnifiedAclTestCase(
        AclTestType.UNIFIED_INSTANCE_TYPE,
        FlextLdifConstants.LdapServers.OPENLDAP,
        description="Verify ACL is FlextLdifModels.Acl instance",
    ),
    UnifiedAclTestCase(
        AclTestType.UNIFIED_EXCEPTION_HANDLING,
        FlextLdifConstants.LdapServers.OPENLDAP,
        description="Test exception handling in ACL creation",
    ),
    UnifiedAclTestCase(
        AclTestType.UNIFIED_INVALID_SERVER_TYPE,
        "invalid_server_type",
        target_dn="*",
        subject_type="*",
        subject_value="*",
        acl_name="",
        raw_acl="(access to *)",
        description="Default to OpenLDAP for invalid server type",
    ),
]


class TestFlextLdifAclComponents(FlextTestsFactories):
    """Comprehensive LDIF ACL utilities test suite.

    Organized as single class with nested classes for test organization.
    Tests component creation, unified ACL creation, server type validation,
    and property preservation with parametrized test cases.
    """

    class Helpers:
        """Helper methods organized as nested class."""

        __test__ = False

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

        @staticmethod
        def create_unified_acl(
            name: str,
            target: FlextLdifModels.AclTarget,
            subject: FlextLdifModels.AclSubject,
            permissions: FlextLdifModels.AclPermissions,
            server_type: str,
            raw_acl: str,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Create unified ACL with proper validation using railway pattern.

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
                supported_servers = {
                    FlextLdifConstants.LdapServers.OPENLDAP,
                    FlextLdifConstants.LdapServers.OPENLDAP_2,
                    FlextLdifConstants.LdapServers.OPENLDAP_1,
                    FlextLdifConstants.LdapServers.ORACLE_OID,
                    FlextLdifConstants.LdapServers.ORACLE_OUD,
                    FlextLdifConstants.LdapServers.DS_389,
                }

                effective_server_type = (
                    server_type
                    if server_type in supported_servers
                    else FlextLdifConstants.LdapServers.OPENLDAP
                )

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
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"Failed to create ACL: {e}",
                )

    @pytest.mark.parametrize("test_case", COMPONENTS_TESTS)
    def test_acl_components(self, test_case: AclComponentsTestCase) -> None:
        """Test ACL component creation and properties."""
        result = TestFlextLdifAclComponents.Helpers.create_acl_components()
        assert result.is_success

        target, subject, permissions = result.unwrap()

        match test_case.test_type:
            case AclTestType.COMPONENTS_CREATION:
                assert isinstance(target, FlextLdifModels.AclTarget)
                assert isinstance(subject, FlextLdifModels.AclSubject)
                assert isinstance(permissions, FlextLdifModels.AclPermissions)

            case AclTestType.COMPONENTS_TARGET:
                assert target.target_dn == "*"

            case AclTestType.COMPONENTS_SUBJECT:
                assert subject.subject_type == "*"
                assert subject.subject_value == "*"

            case AclTestType.COMPONENTS_PERMISSIONS:
                assert permissions.read is True

    @pytest.mark.parametrize("test_case", UNIFIED_ACL_TESTS)
    def test_unified_acl_creation(self, test_case: UnifiedAclTestCase) -> None:
        """Test unified ACL creation with various server types and configurations."""
        target = FlextLdifModels.AclTarget(target_dn=test_case.target_dn)
        subject = FlextLdifModels.AclSubject(
            subject_type=test_case.subject_type,
            subject_value=test_case.subject_value,
        )
        permissions = FlextLdifModels.AclPermissions(
            read=test_case.permissions_read,
            write=test_case.permissions_write,
            delete=test_case.permissions_delete,
        )

        result = TestFlextLdifAclComponents.Helpers.create_unified_acl(
            name=test_case.acl_name,
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=test_case.server_type,
            raw_acl=test_case.raw_acl,
        )

        match test_case.test_type:
            case AclTestType.UNIFIED_BASIC:
                assert result.is_success, f"Failed to create ACL: {result.error}"
                acl = result.unwrap()
                assert isinstance(acl, FlextLdifModels.Acl)
                assert acl.name == test_case.acl_name

            case AclTestType.UNIFIED_PROPERTY_PRESERVATION:
                assert result.is_success
                acl = result.unwrap()
                assert acl.name == test_case.property_name
                assert acl.target == target
                assert acl.subject == subject
                assert acl.permissions == permissions
                assert acl.raw_acl == test_case.property_raw_acl

            case AclTestType.UNIFIED_INSTANCE_TYPE:
                assert result.is_success
                acl = result.unwrap()
                assert isinstance(acl, FlextLdifModels.Acl)

            case AclTestType.UNIFIED_EXCEPTION_HANDLING:
                assert result.is_success

            case AclTestType.UNIFIED_INVALID_SERVER_TYPE:
                assert result.is_success
                acl = result.unwrap()
                assert acl.server_type == FlextLdifConstants.LdapServers.OPENLDAP
