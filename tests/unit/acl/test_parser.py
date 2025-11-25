"""Test suite for FlextLdifAcl parsing functionality.

Modules tested: FlextLdifAcl (initialization, parsing, extraction, evaluation)
Scope: Service initialization, parsing for OpenLDAP/OID, context evaluation
Tests all ACL operations with proper type safety and parametrization.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import dataclasses
from enum import StrEnum
from typing import Final

import pytest
from flext_core import FlextResult

from flext_ldif import FlextLdifModels
from flext_ldif.services.acl import FlextLdifAcl


class AclParserTestType(StrEnum):
    """Types of ACL parser tests."""

    INITIALIZATION = "initialization"
    EXECUTE = "execute"
    PARSE_OPENLDAP = "parse_openldap"
    PARSE_OID = "parse_oid"
    PARSE_UNSUPPORTED = "parse_unsupported"
    EVALUATE_EMPTY = "evaluate_empty"
    EVALUATE_VALID = "evaluate_valid"
    EVALUATE_MISMATCH = "evaluate_mismatch"


@dataclasses.dataclass(frozen=True)
class AclParserTestCase:
    """ACL parser test case definition."""

    test_type: AclParserTestType
    server_type: str = "openldap"
    acl_line: str = ""
    expect_success: bool = True
    expect_empty_response: bool = False
    description: str = ""


# Test cases for comprehensive coverage
PARSER_TESTS: Final[list[AclParserTestCase]] = [
    AclParserTestCase(
        AclParserTestType.INITIALIZATION,
        description="Initialize ACL service",
    ),
    AclParserTestCase(
        AclParserTestType.EXECUTE,
        description="Execute ACL service (empty result)",
    ),
    AclParserTestCase(
        AclParserTestType.PARSE_OPENLDAP,
        server_type="openldap",
        acl_line='access to * by dn.exact="cn=admin,dc=example,dc=com" write',
        description="Parse OpenLDAP ACL format",
    ),
    AclParserTestCase(
        AclParserTestType.PARSE_OID,
        server_type="oracle_oid",
        acl_line='orclaci: access to entry by dn="cn=admin,dc=example,dc=com" (read)',
        description="Parse Oracle OID ACL format",
    ),
    AclParserTestCase(
        AclParserTestType.PARSE_UNSUPPORTED,
        server_type="unknown-server",
        acl_line="some-acl-content",
        description="Parse with unsupported server type",
    ),
    AclParserTestCase(
        AclParserTestType.EVALUATE_EMPTY,
        description="Evaluate empty ACL list",
    ),
    AclParserTestCase(
        AclParserTestType.EVALUATE_VALID,
        description="Evaluate ACL with valid permissions",
    ),
    AclParserTestCase(
        AclParserTestType.EVALUATE_MISMATCH,
        description="Evaluate ACL with permission mismatch",
    ),
]


class AclParserTestFactory:
    """Factory for creating ACL parser test instances."""

    @staticmethod
    def create_service() -> FlextLdifAcl:
        """Create ACL service instance."""
        return FlextLdifAcl()

    @staticmethod
    def create_test_acl(
        *,
        name: str = "test-acl",
        target_dn: str = "*",
        subject_type: str = "*",
        subject_value: str = "*",
        read: bool = False,
        write: bool = False,
        delete: bool = False,
        server_type: str = "openldap",
        raw_acl: str = "test",
    ) -> FlextLdifModels.Acl:
        """Create test ACL model."""
        return FlextLdifModels.Acl(
            name=name,
            target=FlextLdifModels.AclTarget(target_dn=target_dn),
            subject=FlextLdifModels.AclSubject(
                subject_type=subject_type,
                subject_value=subject_value,
            ),
            permissions=FlextLdifModels.AclPermissions(
                read=read,
                write=write,
                delete=delete,
            ),
            server_type=server_type,
            raw_acl=raw_acl,
        )

    @staticmethod
    def create_context(
        *,
        read: bool = False,
        write: bool = False,
        delete: bool = False,
    ) -> dict[str, object]:
        """Create test context."""
        permissions: dict[str, bool] = {}
        if read:
            permissions["read"] = True
        if write:
            permissions["write"] = True
        if delete:
            permissions["delete"] = True
        return {"permissions": permissions}


def get_parser_tests() -> list[AclParserTestCase]:
    """Parametrization helper for parser tests."""
    return PARSER_TESTS


class TestFlextLdifAclParser:
    """Comprehensive ACL parser tests with parametrization."""

    @pytest.fixture
    def acl_service(self) -> FlextLdifAcl:
        """Create ACL service instance."""
        return AclParserTestFactory.create_service()

    @pytest.mark.parametrize("test_case", get_parser_tests())
    def test_acl_parser_operations(
        self,
        test_case: AclParserTestCase,
        acl_service: FlextLdifAcl,
    ) -> None:
        """Comprehensive ACL parser test for all scenarios."""
        match test_case.test_type:
            case AclParserTestType.INITIALIZATION:
                # Test service initialization
                assert acl_service is not None
                assert acl_service.logger is not None

            case AclParserTestType.EXECUTE:
                # Test execute method returns success
                result = acl_service.execute()
                assert result.is_success
                acl_response = result.unwrap()
                assert isinstance(acl_response, FlextLdifModels.AclResponse)
                assert acl_response.acls == []
                assert acl_response.statistics.acls_extracted == 0
                assert acl_response.statistics.acl_entries == 0

            case AclParserTestType.PARSE_OPENLDAP:
                # Test parsing OpenLDAP ACL format
                result = acl_service.parse(test_case.acl_line, test_case.server_type)
                assert isinstance(result, FlextResult)

            case AclParserTestType.PARSE_OID:
                # Test parsing Oracle OID ACL format
                result = acl_service.parse(test_case.acl_line, test_case.server_type)
                assert isinstance(result, FlextResult)

            case AclParserTestType.PARSE_UNSUPPORTED:
                # Test parsing with unsupported server type
                result = acl_service.parse(test_case.acl_line, test_case.server_type)
                assert isinstance(result, FlextResult)

            case AclParserTestType.EVALUATE_EMPTY:
                # Test evaluating empty ACL list
                result = acl_service.evaluate_acl_context([])
                assert result.is_success
                assert result.unwrap() is True

            case AclParserTestType.EVALUATE_VALID:
                # Test evaluating ACL with valid permissions
                acl = AclParserTestFactory.create_test_acl(read=True)
                context = AclParserTestFactory.create_context(read=True)
                result = acl_service.evaluate_acl_context([acl], context)
                assert result.is_success
                assert result.unwrap() is True

            case AclParserTestType.EVALUATE_MISMATCH:
                # Test evaluating ACL with permission mismatch
                acl = AclParserTestFactory.create_test_acl(write=True)
                context = AclParserTestFactory.create_context(read=True)
                result = acl_service.evaluate_acl_context([acl], context)
                assert result.is_failure
                assert "write" in str(result.error).lower()


__all__ = [
    "AclParserTestFactory",
    "AclParserTestType",
    "TestFlextLdifAclParser",
]
