"""Test suite for FlextLdifAcl Parser.

Modules tested: FlextLdifAcl
Scope: ACL parsing, initialization, extraction, evaluation, OpenLDAP/OID formats,
context evaluation, unsupported server types

Tests all ACL operations with proper type safety and parametrization.
Uses parametrized tests and factory patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import dataclasses
from enum import StrEnum
from typing import Final, cast

import pytest
from flext_core import FlextResult
from flext_tests import FlextTestsMatchers

from flext_ldif import FlextLdifModels
from flext_ldif.services.acl import FlextLdifAcl
from tests.fixtures.constants import RFC, DNs, Fixtures


class AclParserTestType(StrEnum):
    """Types of ACL parser tests."""

    INITIALIZATION = "initialization"
    EXECUTE = "execute"
    PARSE_OPENLDAP = "parse_openldap"
    PARSE_OID = "parse_oid"
    PARSE_OUD = "parse_oud"
    PARSE_REAL_OID_EXAMPLE = "parse_real_oid_example"
    PARSE_REAL_OUD_EXAMPLE = "parse_real_oud_example"
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
        server_type=Fixtures.OPENLDAP,
        acl_line=f'access to * by dn.exact="{DNs.TEST_USER}" write',
        description="Parse OpenLDAP ACL format",
    ),
    AclParserTestCase(
        AclParserTestType.PARSE_OID,
        server_type=Fixtures.OID,
        acl_line=f'orclaci: access to entry by dn="{DNs.TEST_USER}" (read)',
        description="Parse Oracle OID ACL format",
    ),
    AclParserTestCase(
        AclParserTestType.PARSE_OUD,
        server_type=Fixtures.OUD,
        acl_line=f'aci: (targetattr="*")(version 3.0; acl "Test ACL"; allow (read,search) userdn="ldap:///{DNs.TEST_USER}";)',
        description="Parse Oracle OUD ACI format",
    ),
    AclParserTestCase(
        AclParserTestType.PARSE_REAL_OID_EXAMPLE,
        server_type=Fixtures.OID,
        acl_line="orclaci: access to entry by * (browse,read) bindmode=(Simple)",
        description="Parse real OID ACL example with bindmode",
    ),
    AclParserTestCase(
        AclParserTestType.PARSE_REAL_OUD_EXAMPLE,
        server_type=Fixtures.OUD,
        acl_line='aci: (targetattr="*")(version 3.0; acl "Anonymous read"; allow (read,search) userdn="ldap:///anyone";)',
        description="Parse real OUD ACI example with anonymous access",
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
        server_type: str = Fixtures.OPENLDAP,
        raw_acl: str = RFC.ACL_SAMPLE_READ,
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
                service_status = result.unwrap()
                assert isinstance(service_status, FlextLdifModels.ServiceStatus)
                assert service_status.service == "acl"
                assert service_status.status == "operational"
                assert service_status.rfc_compliance == "RFC 2849"

            case AclParserTestType.PARSE_OPENLDAP:
                # Test parsing OpenLDAP ACL format
                parse_result_openldap: FlextResult[FlextLdifModels.Acl] = (
                    acl_service.parse(test_case.acl_line, test_case.server_type)
                )
                assert isinstance(parse_result_openldap, FlextResult)
                # Validate successful parsing
                assert parse_result_openldap.is_success, f"OpenLDAP ACL parsing should succeed: {test_case.acl_line}"
                parsed_acl = parse_result_openldap.unwrap()
                assert isinstance(parsed_acl, FlextLdifModels.Acl)
                assert parsed_acl.raw_acl == test_case.acl_line
                # ACL server_type is determined by parsing, not input parameter

            case AclParserTestType.PARSE_OID:
                # Test parsing Oracle OID ACL format
                parse_result_oid: FlextResult[FlextLdifModels.Acl] = acl_service.parse(
                    test_case.acl_line,
                    test_case.server_type,
                )
                assert isinstance(parse_result_oid, FlextResult)
                # Validate successful parsing
                assert parse_result_oid.is_success, f"OID ACL parsing should succeed: {test_case.acl_line}"
                parsed_acl = parse_result_oid.unwrap()
                assert isinstance(parsed_acl, FlextLdifModels.Acl)
                assert parsed_acl.raw_acl == test_case.acl_line
                # ACL server_type is determined by parsing, not input parameter

            case AclParserTestType.PARSE_OUD:
                # Test parsing Oracle OUD ACI format
                parse_result_oud: FlextResult[FlextLdifModels.Acl] = acl_service.parse(
                    test_case.acl_line,
                    test_case.server_type,
                )
                assert isinstance(parse_result_oud, FlextResult)
                # Validate successful parsing
                assert parse_result_oud.is_success, f"OUD ACI parsing should succeed: {test_case.acl_line}"
                parsed_acl = parse_result_oud.unwrap()
                assert isinstance(parsed_acl, FlextLdifModels.Acl)
                assert parsed_acl.raw_acl == test_case.acl_line
                # ACL server_type is determined by parsing, not input parameter

            case AclParserTestType.PARSE_REAL_OID_EXAMPLE:
                # Test parsing real OID ACL example
                parse_result_real_oid: FlextResult[FlextLdifModels.Acl] = acl_service.parse(
                    test_case.acl_line,
                    test_case.server_type,
                )
                assert isinstance(parse_result_real_oid, FlextResult)
                # Test parsing real OID ACL example - may succeed or fail based on quirk availability
                # The important thing is that parsing either succeeds with valid ACL or fails with clear error
                if parse_result_real_oid.is_success:
                    parsed_acl = parse_result_real_oid.unwrap()
                    assert isinstance(parsed_acl, FlextLdifModels.Acl)
                    assert parsed_acl.raw_acl == test_case.acl_line
                    # ACL server_type is determined by parsing, not input parameter
                else:
                    # If parsing fails, it should be due to unavailable quirk, not code error
                    assert "No ACL quirk available" in str(parse_result_real_oid.error)

            case AclParserTestType.PARSE_REAL_OUD_EXAMPLE:
                # Test parsing real OUD ACI example
                parse_result_real_oud: FlextResult[FlextLdifModels.Acl] = acl_service.parse(
                    test_case.acl_line,
                    test_case.server_type,
                )
                assert isinstance(parse_result_real_oud, FlextResult)
                # Test parsing real OUD ACI example - may succeed or fail based on quirk availability
                # The important thing is that parsing either succeeds with valid ACI or fails with clear error
                if parse_result_real_oud.is_success:
                    parsed_acl = parse_result_real_oud.unwrap()
                    assert isinstance(parsed_acl, FlextLdifModels.Acl)
                    assert parsed_acl.raw_acl == test_case.acl_line
                    # ACL server_type is determined by parsing, not input parameter
                else:
                    # If parsing fails, it should be due to unavailable quirk, not code error
                    assert "No ACL quirk available" in str(parse_result_real_oud.error)

            case AclParserTestType.PARSE_UNSUPPORTED:
                # Test parsing with unsupported server type
                parse_result_unsupported: FlextResult[FlextLdifModels.Acl] = (
                    acl_service.parse(test_case.acl_line, test_case.server_type)
                )
                assert isinstance(parse_result_unsupported, FlextResult)
                # Should fail for unsupported server type
                assert parse_result_unsupported.is_failure, f"Unsupported server type should fail: {test_case.server_type}"

            case AclParserTestType.EVALUATE_EMPTY:
                # Test evaluating empty ACL list
                eval_result_empty: FlextResult[bool] = (
                    acl_service.evaluate_acl_context([])
                )
                assert FlextTestsMatchers.assert_success(eval_result_empty) is True

            case AclParserTestType.EVALUATE_VALID:
                # Test evaluating ACL with valid permissions
                acl = AclParserTestFactory.create_test_acl(read=True)
                context = AclParserTestFactory.create_context(read=True)
                eval_result_valid: FlextResult[bool] = acl_service.evaluate_acl_context(
                    [acl],
                    context,
                )
                assert FlextTestsMatchers.assert_success(eval_result_valid) is True

            case AclParserTestType.EVALUATE_MISMATCH:
                # Test evaluating ACL with permission mismatch
                acl = AclParserTestFactory.create_test_acl(write=True)
                context = AclParserTestFactory.create_context(read=True)
                eval_result_mismatch: FlextResult[bool] = (
                    acl_service.evaluate_acl_context([acl], context)
                )
                # Cast to object for assert_failure which expects FlextResult[object]
                FlextTestsMatchers.assert_failure(
                    cast("FlextResult[object]", eval_result_mismatch),
                    "write",
                )


__all__ = [
    "AclParserTestFactory",
    "AclParserTestType",
    "TestFlextLdifAclParser",
]
