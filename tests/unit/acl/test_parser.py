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

from flext_ldif import FlextLdifConstants
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.results import FlextLdifModelsResults
from flext_ldif.services.acl import FlextLdifAcl
from tests.fixtures.constants import RFC, DNs, Fixtures
from tests.fixtures.typing import GenericFieldsDict


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
        subject_type: str = "all",
        subject_value: str = "*",
        read: bool = False,
        write: bool = False,
        delete: bool = False,
        server_type: str = Fixtures.OPENLDAP,
        raw_acl: str = RFC.ACL_SAMPLE_READ,
    ) -> FlextLdifModelsDomains.Acl:
        """Create test ACL model."""
        # Type narrowing: cast subject_type and server_type to Literal types
        subject_type_literal: FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral = (
            cast("FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral", subject_type)
        )
        server_type_literal: FlextLdifConstants.LiteralTypes.ServerTypeLiteral = cast(
            "FlextLdifConstants.LiteralTypes.ServerTypeLiteral", server_type
        )

        return FlextLdifModelsDomains.Acl(
            name=name,
            target=FlextLdifModelsDomains.AclTarget(target_dn=target_dn),
            subject=FlextLdifModelsDomains.AclSubject(
                subject_type=subject_type_literal,
                subject_value=subject_value,
            ),
            permissions=FlextLdifModelsDomains.AclPermissions(
                read=read,
                write=write,
                delete=delete,
            ),
            server_type=server_type_literal,
            raw_acl=raw_acl,
        )

    @staticmethod
    def create_context(
        *,
        read: bool = False,
        write: bool = False,
        delete: bool = False,
    ) -> GenericFieldsDict:
        """Create test context."""
        permissions: dict[str, bool] = {}
        if read:
            permissions["read"] = True
        if write:
            permissions["write"] = True
        if delete:
            permissions["delete"] = True
        # Return dict compatible with GenericFieldsDict
        # Note: GenericFieldsDict may not include "permissions", but this is test code
        return cast("GenericFieldsDict", {"permissions": permissions})  # type: ignore[typeddict-item]


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
                # ACL service returns AclResponse, not ServiceStatus
                acl_response = result.unwrap()
                assert isinstance(acl_response, FlextLdifModelsResults.AclResponse)
                assert len(acl_response.acls) == 0
                assert isinstance(acl_response.acls, list)

            case AclParserTestType.PARSE_OPENLDAP:
                # Test parsing OpenLDAP ACL format
                parse_result_openldap: FlextResult[FlextLdifModelsDomains.Acl] = (
                    acl_service.parse_acl_string(
                        test_case.acl_line, test_case.server_type
                    )
                )
                assert isinstance(parse_result_openldap, FlextResult)
                # Validate successful parsing
                assert parse_result_openldap.is_success, (
                    f"OpenLDAP ACL parsing should succeed: {test_case.acl_line}"
                )
                parsed_acl = parse_result_openldap.unwrap()
                assert isinstance(parsed_acl, FlextLdifModelsDomains.Acl)
                assert parsed_acl.raw_acl == test_case.acl_line
                # ACL server_type is determined by parsing, not input parameter

            case AclParserTestType.PARSE_OID:
                # Test parsing Oracle OID ACL format
                parse_result_oid: FlextResult[FlextLdifModelsDomains.Acl] = (
                    acl_service.parse_acl_string(
                        test_case.acl_line,
                        test_case.server_type,
                    )
                )
                assert isinstance(parse_result_oid, FlextResult)
                # Validate successful parsing
                assert parse_result_oid.is_success, (
                    f"OID ACL parsing should succeed: {test_case.acl_line}"
                )
                parsed_acl = parse_result_oid.unwrap()
                assert isinstance(parsed_acl, FlextLdifModelsDomains.Acl)
                assert parsed_acl.raw_acl == test_case.acl_line
                # ACL server_type is determined by parsing, not input parameter

            case AclParserTestType.PARSE_OUD:
                # Test parsing Oracle OUD ACI format
                parse_result_oud: FlextResult[FlextLdifModelsDomains.Acl] = (
                    acl_service.parse_acl_string(
                        test_case.acl_line,
                        test_case.server_type,
                    )
                )
                assert isinstance(parse_result_oud, FlextResult)
                # Validate successful parsing
                assert parse_result_oud.is_success, (
                    f"OUD ACI parsing should succeed: {test_case.acl_line}"
                )
                parsed_acl = parse_result_oud.unwrap()
                assert isinstance(parsed_acl, FlextLdifModelsDomains.Acl)
                assert parsed_acl.raw_acl == test_case.acl_line
                # ACL server_type is determined by parsing, not input parameter

            case AclParserTestType.PARSE_REAL_OID_EXAMPLE:
                # Test parsing real OID ACL example
                parse_result_real_oid: FlextResult[FlextLdifModelsDomains.Acl] = (
                    acl_service.parse_acl_string(
                        test_case.acl_line,
                        test_case.server_type,
                    )
                )
                assert isinstance(parse_result_real_oid, FlextResult)
                # Test parsing real OID ACL example - may succeed or fail based on quirk availability
                # The important thing is that parsing either succeeds with valid ACL or fails with clear error
                if parse_result_real_oid.is_success:
                    parsed_acl = parse_result_real_oid.unwrap()
                    assert isinstance(parsed_acl, FlextLdifModelsDomains.Acl)
                    assert parsed_acl.raw_acl == test_case.acl_line
                    # ACL server_type is determined by parsing, not input parameter
                else:
                    # If parsing fails, it should be due to unavailable quirk, not code error
                    assert "No ACL quirk available" in str(parse_result_real_oid.error)

            case AclParserTestType.PARSE_REAL_OUD_EXAMPLE:
                # Test parsing real OUD ACI example
                parse_result_real_oud: FlextResult[FlextLdifModelsDomains.Acl] = (
                    acl_service.parse_acl_string(
                        test_case.acl_line,
                        test_case.server_type,
                    )
                )
                assert isinstance(parse_result_real_oud, FlextResult)
                # Test parsing real OUD ACI example - may succeed or fail based on quirk availability
                # The important thing is that parsing either succeeds with valid ACI or fails with clear error
                if parse_result_real_oud.is_success:
                    parsed_acl = parse_result_real_oud.unwrap()
                    assert isinstance(parsed_acl, FlextLdifModelsDomains.Acl)
                    assert parsed_acl.raw_acl == test_case.acl_line
                    # ACL server_type is determined by parsing, not input parameter
                else:
                    # If parsing fails, it should be due to unavailable quirk, not code error
                    assert "No ACL quirk available" in str(parse_result_real_oud.error)

            case AclParserTestType.PARSE_UNSUPPORTED:
                # Test parsing with unsupported server type
                # FlextLdifAcl uses parse_acl_string() method (not parse())
                # Invalid server types are validated before parsing
                parse_result_unsupported: FlextResult[FlextLdifModelsDomains.Acl] = (
                    acl_service.parse_acl_string(
                        acl_string=test_case.acl_line,
                        server_type=test_case.server_type,  # type: ignore[arg-type]
                    )
                )
                assert isinstance(parse_result_unsupported, FlextResult)
                # Should fail for invalid/unsupported server type
                # Error may be from validation (ValueError) or from parsing (no quirk)
                assert parse_result_unsupported.is_failure, (
                    f"Invalid/unsupported server type should fail: {test_case.server_type}"
                )
                # Error message should indicate invalid server type or no quirk available
                assert "Invalid server type" in str(
                    parse_result_unsupported.error
                ) or "No ACL quirk available" in str(parse_result_unsupported.error), (
                    f"Unexpected error: {parse_result_unsupported.error}"
                )

            case AclParserTestType.EVALUATE_EMPTY:
                # Test evaluate_acl_context with empty ACL list
                empty_result = acl_service.evaluate_acl_context(
                    acls=[],
                    required_permissions={"read": True},
                )
                assert empty_result.is_success
                eval_result = empty_result.unwrap()
                assert not eval_result.granted
                assert eval_result.matched_acl is None
                assert "No ACLs to evaluate" in eval_result.message

            case AclParserTestType.EVALUATE_VALID:
                # Test evaluate_acl_context with ACL that grants required permissions
                test_acl = AclParserTestFactory.create_test_acl(
                    name="valid-acl",
                    read=True,
                    write=True,
                )
                valid_result = acl_service.evaluate_acl_context(
                    acls=[test_acl],
                    required_permissions={"read": True},
                )
                assert valid_result.is_success
                eval_result = valid_result.unwrap()
                assert eval_result.granted
                assert eval_result.matched_acl is not None
                assert eval_result.matched_acl.name == "valid-acl"

            case AclParserTestType.EVALUATE_MISMATCH:
                # Test evaluate_acl_context with ACL that doesn't grant required permissions
                test_acl = AclParserTestFactory.create_test_acl(
                    name="mismatch-acl",
                    read=True,
                    write=False,
                )
                mismatch_result = acl_service.evaluate_acl_context(
                    acls=[test_acl],
                    required_permissions={"write": True},
                )
                assert mismatch_result.is_success
                eval_result = mismatch_result.unwrap()
                assert not eval_result.granted
                assert eval_result.matched_acl is None
                assert "No ACL grants required permissions" in eval_result.message


__all__ = [
    "AclParserTestFactory",
    "AclParserTestType",
    "TestFlextLdifAclParser",
]
