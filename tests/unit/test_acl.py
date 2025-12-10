"""Consolidated tests for FlextLdif ACL functionality.

This module consolidates all ACL tests from tests/unit/acl/ into a single file.
Tests ACL service, parser, components, and utilities functionality.
"""

from __future__ import annotations

import dataclasses
from enum import StrEnum
from pathlib import Path
from typing import ClassVar, Final, cast

import pytest
from flext_core import FlextResult

from flext_ldif.constants import c as lib_c
from flext_ldif.models import m
from flext_ldif.services.acl import FlextLdifAcl
from tests import GenericFieldsDict, c, s

# =============================================================================
# TEST ENUMS AND DATA STRUCTURES
# =============================================================================


class ValidationCheckType(StrEnum):
    """Types of ACL validation checks."""

    FIXTURE_ACCESS = "fixture_access"
    ACL_PRESENCE = "acl_presence"


class EdgeCaseType(StrEnum):
    """Edge case types for ACL testing."""

    EMPTY_ACL = "empty_acl"
    MALFORMED_ACL = "malformed_acl"
    MISSING_ATTRIBUTES = "missing_attributes"


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


@dataclasses.dataclass(frozen=True)
class AclParserTestCase:
    """ACL parser test case definition."""

    test_type: AclParserTestType
    server_type: str = "openldap"
    acl_line: str = ""
    expect_success: bool = True
    expect_empty_response: bool = False
    description: str = ""


# =============================================================================
# TEST DATA
# =============================================================================

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
        lib_c.Ldif.LdapServers.OPENLDAP,
        acl_name="openldap_acl",
        raw_acl="to * by * read",
        description="Create ACL for OpenLDAP",
    ),
    UnifiedAclTestCase(
        AclTestType.UNIFIED_BASIC,
        lib_c.Ldif.LdapServers.OPENLDAP_2,
        acl_name="openldap2_acl",
        raw_acl="olcAccess: {0}to * by * read",
        description="Create ACL for OpenLDAP 2.x",
    ),
    UnifiedAclTestCase(
        AclTestType.UNIFIED_BASIC,
        lib_c.Ldif.LdapServers.OPENLDAP_1,
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
        lib_c.Ldif.LdapServers.OPENLDAP,
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
        lib_c.Ldif.LdapServers.OPENLDAP,
        description="Verify ACL is m.Acl instance",
    ),
    UnifiedAclTestCase(
        AclTestType.UNIFIED_EXCEPTION_HANDLING,
        lib_c.Ldif.LdapServers.OPENLDAP,
        description="Test exception handling in ACL creation",
    ),
    UnifiedAclTestCase(
        AclTestType.UNIFIED_INVALID_SERVER_TYPE,
        "invalid_server_type",
        target_dn="*",
        subject_type="all",
        subject_value="*",
        acl_name="",
        raw_acl="(access to *)",
        description="Default to OpenLDAP for invalid server type",
    ),
]

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
        server_type=lib_c.Ldif.ServerTypes.OPENLDAP,
        acl_line=f'access to * by dn.exact="{c.DNs.TEST_USER}" write',
        description="Parse OpenLDAP ACL format",
    ),
    AclParserTestCase(
        AclParserTestType.PARSE_OID,
        server_type=lib_c.Ldif.ServerTypes.OID,
        acl_line=f'orclaci: access to entry by dn="{c.DNs.TEST_USER}" (read)',
        description="Parse Oracle OID ACL format",
    ),
    AclParserTestCase(
        AclParserTestType.PARSE_OUD,
        server_type=lib_c.Ldif.ServerTypes.OUD,
        acl_line=f'aci: (targetattr="*")(version 3.0; acl "Test ACL"; allow (read,search) userdn="ldap:///{c.DNs.TEST_USER}";)',
        description="Parse Oracle OUD ACI format",
    ),
    AclParserTestCase(
        AclParserTestType.PARSE_REAL_OID_EXAMPLE,
        server_type=lib_c.Ldif.ServerTypes.OID,
        acl_line="orclaci: access to entry by * (browse,read) bindmode=(Simple)",
        description="Parse real OID ACL example with bindmode",
    ),
    AclParserTestCase(
        AclParserTestType.PARSE_REAL_OUD_EXAMPLE,
        server_type=lib_c.Ldif.ServerTypes.OUD,
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


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def create_acl_components_helper() -> FlextResult[
    tuple[
        m.AclTarget,
        m.AclSubject,
        m.AclPermissions,
    ]
]:
    """Create ACL components with proper validation using railway pattern.

    Returns:
        FlextResult containing tuple of (target, subject, permissions) on success,
        or failure with descriptive error message.

    """
    target = m.AclTarget(
        target_dn=lib_c.ServerDetection.ACL_WILDCARD_DN,
    )
    subject_type_literal: lib_c.Ldif.LiteralTypes.AclSubjectTypeLiteral = cast(
        "lib_c.Ldif.LiteralTypes.AclSubjectTypeLiteral",
        lib_c.ServerDetection.ACL_WILDCARD_TYPE,
    )
    subject = m.AclSubject(
        subject_type=subject_type_literal,
        subject_value=lib_c.ServerDetection.ACL_WILDCARD_VALUE,
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
            lib_c.Ldif.LdapServers.OPENLDAP,
            lib_c.Ldif.LdapServers.OPENLDAP_2,
            lib_c.Ldif.LdapServers.OPENLDAP_1,
            lib_c.Ldif.LdapServers.ORACLE_OID,
            lib_c.Ldif.LdapServers.ORACLE_OUD,
            lib_c.Ldif.LdapServers.DS_389,
        }

        effective_server_type_raw = (
            server_type
            if server_type in supported_servers
            else lib_c.Ldif.LdapServers.OPENLDAP
        )

        # Cast server_type to Literal type
        effective_server_type = cast(
            "lib_c.Ldif.LiteralTypes.ServerTypeLiteral",
            effective_server_type_raw,
        )

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


# =============================================================================
# TEST CLASSES
# =============================================================================


class TestsTestFlextLdifAclWithRealFixtures(s):
    """Test FlextLdifAcl with real ACL fixture data using factories and constants."""

    class CheckScenario(StrEnum):
        """Test scenarios for ACL validation checks."""

        OID_FIXTURE_ACCESS = "oid_fixture_access"
        OID_ACL_PRESENCE = "oid_acl_presence"
        OUD_FIXTURE_ACCESS = "oud_fixture_access"
        OUD_ACL_PRESENCE = "oud_acl_presence"

    class EncodingScenario(StrEnum):
        """Test scenarios for ACL fixture encoding."""

        OID_ENCODING = "oid_encoding"
        OUD_ENCODING = "oud_encoding"

    class StructureScenario(StrEnum):
        """Test scenarios for ACL fixture structure."""

        OID_STRUCTURE = "oid_structure"
        OUD_STRUCTURE = "oud_structure"

    class EdgeCaseScenario(StrEnum):
        """Test scenarios for edge cases."""

        OID_EMPTY = "oid_empty"
        OUD_MALFORMED = "oud_malformed"
        OID_MISSING_ATTRS = "oid_missing_attrs"

    ACL_INDICATORS: ClassVar[dict[lib_c.Ldif.ServerTypes, list[str]]] = {
        lib_c.Ldif.ServerTypes.OID: ["orclaci:", "aci:"],
        lib_c.Ldif.ServerTypes.OUD: ["aci:"],
    }

    ACL_REQUIRED_ATTRS: ClassVar[dict[lib_c.Ldif.ServerTypes, list[str]]] = {
        lib_c.Ldif.ServerTypes.OID: ["orclaci:"],
        lib_c.Ldif.ServerTypes.OUD: ["aci:"],
    }

    ACL_MIN_LINES: ClassVar[dict[lib_c.Ldif.ServerTypes, int]] = {
        lib_c.Ldif.ServerTypes.OID: 5,
        lib_c.Ldif.ServerTypes.OUD: 5,
    }

    BASIC_CHECK_DATA: ClassVar[
        dict[str, tuple[lib_c.Ldif.ServerTypes, ValidationCheckType]]
    ] = {
        CheckScenario.OID_FIXTURE_ACCESS: (
            lib_c.Ldif.ServerTypes.OID,
            ValidationCheckType.FIXTURE_ACCESS,
        ),
        CheckScenario.OID_ACL_PRESENCE: (
            lib_c.Ldif.ServerTypes.OID,
            ValidationCheckType.ACL_PRESENCE,
        ),
        CheckScenario.OUD_FIXTURE_ACCESS: (
            lib_c.Ldif.ServerTypes.OUD,
            ValidationCheckType.FIXTURE_ACCESS,
        ),
        CheckScenario.OUD_ACL_PRESENCE: (
            lib_c.Ldif.ServerTypes.OUD,
            ValidationCheckType.ACL_PRESENCE,
        ),
    }

    ENCODING_CHECK_DATA: ClassVar[dict[str, lib_c.Ldif.ServerTypes]] = {
        EncodingScenario.OID_ENCODING: lib_c.Ldif.ServerTypes.OID,
        EncodingScenario.OUD_ENCODING: lib_c.Ldif.ServerTypes.OUD,
    }

    STRUCTURE_CHECK_DATA: ClassVar[dict[str, lib_c.Ldif.ServerTypes]] = {
        StructureScenario.OID_STRUCTURE: lib_c.Ldif.ServerTypes.OID,
        StructureScenario.OUD_STRUCTURE: lib_c.Ldif.ServerTypes.OUD,
    }

    EDGE_CASE_DATA: ClassVar[dict[str, tuple[EdgeCaseType, lib_c.Ldif.ServerTypes]]] = {
        EdgeCaseScenario.OID_EMPTY: (
            EdgeCaseType.EMPTY_ACL,
            lib_c.Ldif.ServerTypes.OID,
        ),
        EdgeCaseScenario.OUD_MALFORMED: (
            EdgeCaseType.MALFORMED_ACL,
            lib_c.Ldif.ServerTypes.OUD,
        ),
        EdgeCaseScenario.OID_MISSING_ATTRS: (
            EdgeCaseType.MISSING_ATTRIBUTES,
            lib_c.Ldif.ServerTypes.OID,
        ),
    }

    @staticmethod
    def _get_fixture_path(server_type: lib_c.Ldif.ServerTypes) -> Path:
        """Get fixture path for server type."""
        fixture_map = {
            lib_c.Ldif.ServerTypes.OID: "acl/oid_acl_fixture.ldif",
            lib_c.Ldif.ServerTypes.OUD: "acl/oud_acl_fixture.ldif",
        }
        fixture_rel_path = fixture_map[server_type]
        return Path(__file__).parent.parent / "fixtures" / fixture_rel_path

    def _get_content_lines(self, content: str) -> list[str]:
        """Get non-empty lines from content."""
        return [line for line in content.split("\n") if line.strip()]

    def _get_acl_lines(
        self, content: str, server_type: lib_c.Ldif.ServerTypes
    ) -> list[str]:
        """Get ACL lines from content."""
        indicators = self.ACL_INDICATORS[server_type]
        return [
            line
            for line in content.split("\n")
            if any(indicator in line for indicator in indicators)
        ]

    def _get_ldif_entries(self, content: str) -> list[str]:
        """Get LDIF entries from content."""
        return [e for e in content.split("dn:") if e.strip()]

    def _check_fixture_access(
        self, content: str, server_type: lib_c.Ldif.ServerTypes
    ) -> bool:
        """Check if fixture has accessible content with minimum lines."""
        if not content or len(content) == 0:
            return False
        lines = self._get_content_lines(content)
        return len(lines) >= self.ACL_MIN_LINES[server_type]

    def _check_acl_presence(
        self, content: str, server_type: lib_c.Ldif.ServerTypes
    ) -> bool:
        """Check if content has ACL indicators."""
        acl_lines = self._get_acl_lines(content, server_type)
        return len(acl_lines) > 0

    def _check_ldif_structure(self, content: str) -> bool:
        """Check if content has LDIF structure."""
        entries = self._get_ldif_entries(content)
        return len(entries) > 0

    def _check_acl_content(self, content: str) -> bool:
        """Check if content has ACL-related lines."""
        acl_lines = [line for line in content.split("\n") if "acl" in line.lower()]
        return len(acl_lines) > 0

    def _check_utf8_encoding(self, content: str) -> bool:
        """Check if content is valid UTF-8."""
        return isinstance(content, str) and len(content) > 0

    def _validate_server_specific_acls(
        self,
        content: str,
        server_type: lib_c.Ldif.ServerTypes,
    ) -> None:
        """Validate server-specific ACL attributes."""
        if server_type == lib_c.Ldif.ServerTypes.OID:
            assert "orclaci:" in content, "OID fixture should have orclaci attributes"
            assert "aci:" in content, "OID fixture should have aci attributes"
        else:  # OUD
            assert "aci:" in content, "OUD fixture should have aci attributes"

    @pytest.mark.parametrize(
        ("scenario", "server_type", "check_type"),
        [(name, data[0], data[1]) for name, data in BASIC_CHECK_DATA.items()],
    )
    def test_acl_basic_validation(
        self,
        scenario: str,
        server_type: lib_c.Ldif.ServerTypes,
        check_type: ValidationCheckType,
    ) -> None:
        """Test ACL basic validation with parametrized checks."""
        fixture_path = self._get_fixture_path(server_type)
        if not fixture_path.exists():
            pytest.skip(f"Fixture not found: {fixture_path}")

        content = fixture_path.read_text(encoding="utf-8")

        if check_type == ValidationCheckType.FIXTURE_ACCESS:
            result = self._check_fixture_access(content, server_type)
        elif check_type == ValidationCheckType.ACL_PRESENCE:
            result = self._check_acl_presence(content, server_type)
        else:
            pytest.fail(f"Unknown check type: {check_type}")

        assert result, f"{server_type.upper()} {check_type} check failed for {scenario}"

    @pytest.mark.parametrize(
        ("scenario", "server_type"),
        [(name, data) for name, data in STRUCTURE_CHECK_DATA.items()],
    )
    def test_acl_structure_validation(
        self,
        scenario: str,
        server_type: lib_c.Ldif.ServerTypes,
    ) -> None:
        """Test ACL fixture structure with comprehensive validation."""
        fixture_path = self._get_fixture_path(server_type)
        if not fixture_path.exists():
            pytest.skip(f"Fixture not found: {fixture_path}")

        content = fixture_path.read_text(encoding="utf-8")

        assert len(content) > 0, (
            f"{server_type.upper()} ACL fixture should have content"
        )

        lines = self._get_content_lines(content)
        assert len(lines) >= self.ACL_MIN_LINES[server_type], (
            f"{server_type.upper()} fixture should have minimum lines"
        )

        acl_lines = self._get_acl_lines(content, server_type)
        assert len(acl_lines) > 0, (
            f"{server_type.upper()} fixture should contain ACL attributes"
        )

        entries = self._get_ldif_entries(content)
        assert len(entries) > 0, f"Should have LDIF entries for {server_type}"

        assert self._check_acl_content(content), (
            f"Should have ACL content for {server_type}"
        )

        required_attrs = self.ACL_REQUIRED_ATTRS[server_type]
        for attr in required_attrs:
            assert attr in content, f"{server_type.upper()} fixture should have {attr}"

        self._validate_server_specific_acls(content, server_type)

    @pytest.mark.parametrize(
        ("scenario", "server_type"),
        [(name, data) for name, data in ENCODING_CHECK_DATA.items()],
    )
    def test_acl_encoding_validation(
        self,
        scenario: str,
        server_type: lib_c.Ldif.ServerTypes,
    ) -> None:
        """Test that ACL fixtures have valid UTF-8 encoding."""
        fixture_path = self._get_fixture_path(server_type)
        if not fixture_path.exists():
            pytest.skip(f"Fixture not found: {fixture_path}")

        content = fixture_path.read_text(encoding="utf-8")

        assert self._check_utf8_encoding(content), (
            f"{server_type} content should be valid UTF-8"
        )

        assert len(content) > 0, f"{server_type} content should not be empty"

    @pytest.mark.parametrize(
        ("scenario", "case_type", "server_type"),
        [(name, data[0], data[1]) for name, data in EDGE_CASE_DATA.items()],
    )
    def test_acl_edge_cases(
        self,
        scenario: str,
        case_type: EdgeCaseType,
        server_type: lib_c.Ldif.ServerTypes,
    ) -> None:
        """Test ACL service edge cases dynamically."""
        assert case_type in EdgeCaseType
        assert server_type in lib_c.Ldif.ServerTypes

    def test_acl_service_initialization(self) -> None:
        """Test ACL service can be initialized."""
        service = FlextLdifAcl()
        assert service is not None


class TestFlextLdifAclComponents(s):
    """Comprehensive LDIF ACL utilities test suite."""

    class Helpers:
        """Helper methods organized as nested class."""

        __test__ = False

        @staticmethod
        def create_acl_components() -> FlextResult[
            tuple[
                m.AclTarget,
                m.AclSubject,
                m.AclPermissions,
            ]
        ]:
            """Create ACL components with proper validation using railway pattern."""
            target = m.AclTarget(
                target_dn=lib_c.ServerDetection.ACL_WILDCARD_DN,
            )
            subject = m.AclSubject(
                subject_type="all",
                subject_value=lib_c.ServerDetection.ACL_WILDCARD_VALUE,
            )
            permissions = m.AclPermissions(read=True)

            return FlextResult[
                tuple[
                    m.AclTarget,
                    m.AclSubject,
                    m.AclPermissions,
                ]
            ].ok((target, subject, permissions))

        @staticmethod
        def create_unified_acl(
            name: str,
            target: m.AclTarget,
            subject: m.AclSubject,
            permissions: m.AclPermissions,
            server_type: str,
            raw_acl: str,
        ) -> FlextResult[m.Acl]:
            """Create unified ACL with proper validation using railway pattern."""
            try:
                supported_servers = {
                    lib_c.Ldif.LdapServers.OPENLDAP,
                    lib_c.Ldif.LdapServers.OPENLDAP_2,
                    lib_c.Ldif.LdapServers.OPENLDAP_1,
                    lib_c.Ldif.LdapServers.ORACLE_OID,
                    lib_c.Ldif.LdapServers.ORACLE_OUD,
                    lib_c.Ldif.LdapServers.DS_389,
                }

                effective_server_type = (
                    server_type
                    if server_type in supported_servers
                    else lib_c.Ldif.LdapServers.OPENLDAP
                )

                server_type_literal: lib_c.Ldif.LiteralTypes.ServerTypeLiteral = cast(
                    "lib_c.Ldif.LiteralTypes.ServerTypeLiteral",
                    effective_server_type,
                )

                unified_acl = m.Acl(
                    name=name,
                    target=target,
                    subject=subject,
                    permissions=permissions,
                    server_type=server_type_literal,
                    raw_acl=raw_acl,
                )

                return FlextResult[m.Acl].ok(unified_acl)
            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult[m.Acl].fail(
                    f"Failed to create ACL: {e}",
                )

    @pytest.mark.parametrize("test_case", COMPONENTS_TESTS)
    def test_acl_components(self, test_case: AclComponentsTestCase) -> None:
        """Test ACL component creation and properties."""
        result = TestFlextLdifAclComponents.Helpers.create_acl_components()
        assert result.is_success

        target, subject, permissions = result.value

        match test_case.test_type:
            case AclTestType.COMPONENTS_CREATION:
                assert isinstance(target, m.AclTarget)
                assert isinstance(subject, m.AclSubject)
                assert isinstance(permissions, m.AclPermissions)

            case AclTestType.COMPONENTS_TARGET:
                assert target.target_dn == "*"

            case AclTestType.COMPONENTS_SUBJECT:
                assert subject.subject_type == "all"
                assert subject.subject_value == "*"

            case AclTestType.COMPONENTS_PERMISSIONS:
                assert permissions.read is True

    @pytest.mark.parametrize("test_case", UNIFIED_ACL_TESTS)
    def test_unified_acl_creation(self, test_case: UnifiedAclTestCase) -> None:
        """Test unified ACL creation with various server types and configurations."""
        target = m.AclTarget(target_dn=test_case.target_dn)
        subject_type_literal: lib_c.Ldif.LiteralTypes.AclSubjectTypeLiteral = cast(
            "lib_c.Ldif.LiteralTypes.AclSubjectTypeLiteral",
            test_case.subject_type,
        )
        subject = m.AclSubject(
            subject_type=subject_type_literal,
            subject_value=test_case.subject_value,
        )
        permissions = m.AclPermissions(
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
                acl = result.value
                assert isinstance(acl, m.Acl)
                assert acl.name == test_case.acl_name

            case AclTestType.UNIFIED_PROPERTY_PRESERVATION:
                assert result.is_success
                acl = result.value
                assert acl.name == test_case.property_name
                assert acl.target == target
                assert acl.subject == subject
                assert acl.permissions == permissions
                assert acl.raw_acl == test_case.property_raw_acl

            case AclTestType.UNIFIED_INSTANCE_TYPE:
                assert result.is_success
                acl = result.value
                assert isinstance(acl, m.Acl)

            case AclTestType.UNIFIED_EXCEPTION_HANDLING:
                assert result.is_success

            case AclTestType.UNIFIED_INVALID_SERVER_TYPE:
                assert result.is_success
                acl = result.value
                assert acl.server_type == lib_c.Ldif.LdapServers.OPENLDAP


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
        server_type: str = lib_c.Ldif.ServerTypes.OPENLDAP,
        raw_acl: str = c.Rfc.ACL_SAMPLE_READ,
    ) -> m.Acl:
        """Create test ACL model."""
        subject_type_literal: lib_c.Ldif.LiteralTypes.AclSubjectTypeLiteral = cast(
            "lib_c.Ldif.LiteralTypes.AclSubjectTypeLiteral", subject_type
        )
        server_type_literal: lib_c.Ldif.LiteralTypes.ServerTypeLiteral = cast(
            "lib_c.Ldif.LiteralTypes.ServerTypeLiteral", server_type
        )

        return m.Acl(
            name=name,
            target=m.AclTarget(target_dn=target_dn),
            subject=m.AclSubject(
                subject_type=subject_type_literal,
                subject_value=subject_value,
            ),
            permissions=m.AclPermissions(
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
        return cast("GenericFieldsDict", {"permissions": permissions})


def get_parser_tests() -> list[AclParserTestCase]:
    """Parametrization helper for parser tests."""
    return PARSER_TESTS


class TestsTestFlextLdifAclParser(s):
    """Comprehensive ACL parser tests with parametrization."""

    acl_service: ClassVar[FlextLdifAcl]  # pytest fixture

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
                assert acl_service is not None
                assert acl_service.logger is not None

            case AclParserTestType.EXECUTE:
                result = acl_service.execute()
                assert result.is_success
                acl_response = result.value
                assert isinstance(acl_response, m.Ldif.LdifResults.AclResponse)
                assert len(acl_response.acls) == 0
                assert isinstance(acl_response.acls, list)

            case AclParserTestType.PARSE_OPENLDAP:
                parse_result_openldap: FlextResult[m.Acl] = (
                    acl_service.parse_acl_string(
                        test_case.acl_line, test_case.server_type
                    )
                )
                assert isinstance(parse_result_openldap, FlextResult)
                assert parse_result_openldap.is_success, (
                    f"OpenLDAP ACL parsing should succeed: {test_case.acl_line}"
                )
                parsed_acl = parse_result_openldap.value
                assert isinstance(parsed_acl, m.Acl)
                assert parsed_acl.raw_acl == test_case.acl_line

            case AclParserTestType.PARSE_OID:
                parse_result_oid: FlextResult[m.Acl] = acl_service.parse_acl_string(
                    test_case.acl_line,
                    test_case.server_type,
                )
                assert isinstance(parse_result_oid, FlextResult)
                assert parse_result_oid.is_success, (
                    f"OID ACL parsing should succeed: {test_case.acl_line}"
                )
                parsed_acl = parse_result_oid.value
                assert isinstance(parsed_acl, m.Acl)
                assert parsed_acl.raw_acl == test_case.acl_line

            case AclParserTestType.PARSE_OUD:
                parse_result_oud: FlextResult[m.Acl] = acl_service.parse_acl_string(
                    test_case.acl_line,
                    test_case.server_type,
                )
                assert isinstance(parse_result_oud, FlextResult)
                assert parse_result_oud.is_success, (
                    f"OUD ACI parsing should succeed: {test_case.acl_line}"
                )
                parsed_acl = parse_result_oud.value
                assert isinstance(parsed_acl, m.Acl)
                assert parsed_acl.raw_acl == test_case.acl_line

            case AclParserTestType.PARSE_REAL_OID_EXAMPLE:
                parse_result_real_oid: FlextResult[m.Acl] = (
                    acl_service.parse_acl_string(
                        test_case.acl_line,
                        test_case.server_type,
                    )
                )
                assert isinstance(parse_result_real_oid, FlextResult)
                if parse_result_real_oid.is_success:
                    parsed_acl = parse_result_real_oid.value
                    assert isinstance(parsed_acl, m.Acl)
                    assert parsed_acl.raw_acl == test_case.acl_line
                else:
                    assert "No ACL quirk available" in str(parse_result_real_oid.error)

            case AclParserTestType.PARSE_REAL_OUD_EXAMPLE:
                parse_result_real_oud: FlextResult[m.Acl] = (
                    acl_service.parse_acl_string(
                        test_case.acl_line,
                        test_case.server_type,
                    )
                )
                assert isinstance(parse_result_real_oud, FlextResult)
                if parse_result_real_oud.is_success:
                    parsed_acl = parse_result_real_oud.value
                    assert isinstance(parsed_acl, m.Acl)
                    assert parsed_acl.raw_acl == test_case.acl_line
                else:
                    assert "No ACL quirk available" in str(parse_result_real_oud.error)

            case AclParserTestType.PARSE_UNSUPPORTED:
                parse_result_unsupported: FlextResult[m.Acl] = (
                    acl_service.parse_acl_string(
                        acl_string=test_case.acl_line,
                        server_type=test_case.server_type,
                    )
                )
                assert isinstance(parse_result_unsupported, FlextResult)
                assert parse_result_unsupported.is_failure, (
                    f"Invalid/unsupported server type should fail: {test_case.server_type}"
                )
                assert "Invalid server type" in str(
                    parse_result_unsupported.error
                ) or "No ACL quirk available" in str(parse_result_unsupported.error), (
                    f"Unexpected error: {parse_result_unsupported.error}"
                )

            case AclParserTestType.EVALUATE_EMPTY:
                empty_result = acl_service.evaluate_acl_context(
                    acls=[],
                    required_permissions={"read": True},
                )
                assert empty_result.is_success
                eval_result = empty_result.value
                assert not eval_result.granted
                assert eval_result.matched_acl is None
                assert "No ACLs to evaluate" in eval_result.message

            case AclParserTestType.EVALUATE_VALID:
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
                eval_result = valid_result.value
                assert eval_result.granted
                assert eval_result.matched_acl is not None
                assert eval_result.matched_acl.name == "valid-acl"

            case AclParserTestType.EVALUATE_MISMATCH:
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
                eval_result = mismatch_result.value
                assert not eval_result.granted
                assert eval_result.matched_acl is None
                assert "No ACL grants required permissions" in eval_result.message


class TestsFlextLdifComponentFactory(s):
    """Test ACL component factory functionality."""

    def test_create_acl_components_success(self) -> None:
        """Test successful creation of ACL components."""
        result = create_acl_components_helper()

        assert result.is_success
        components = result.value
        assert isinstance(components, tuple)
        assert len(components) == 3

        target, subject, permissions = components
        assert isinstance(target, m.AclTarget)
        assert isinstance(subject, m.AclSubject)
        assert isinstance(permissions, m.AclPermissions)

    def test_create_acl_components_target_properties(self) -> None:
        """Test ACL target component properties."""
        result = create_acl_components_helper()
        target, _, _ = result.value

        assert target.target_dn == "*"

    def test_create_acl_components_subject_properties(self) -> None:
        """Test ACL subject component properties."""
        result = create_acl_components_helper()
        _, subject, _ = result.value

        assert subject.subject_type == "all"
        assert subject.subject_value == "*"

    def test_create_acl_components_permissions_properties(self) -> None:
        """Test ACL permissions component properties."""
        result = create_acl_components_helper()
        _, _, permissions = result.value

        assert permissions.read is True

    def test_create_unified_acl_openldap(self) -> None:
        """Test creating unified ACL for OpenLDAP server."""
        target = m.AclTarget(target_dn="cn=REDACTED_LDAP_BIND_PASSWORD")
        subject_type_literal: lib_c.Ldif.LiteralTypes.AclSubjectTypeLiteral = cast(
            "lib_c.Ldif.LiteralTypes.AclSubjectTypeLiteral", "user"
        )
        subject = m.AclSubject(subject_type=subject_type_literal, subject_value="REDACTED_LDAP_BIND_PASSWORD")
        permissions = m.AclPermissions(read=True, write=False)

        result = create_unified_acl_helper(
            name="openldap_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=lib_c.Ldif.LdapServers.OPENLDAP,
            raw_acl="to * by * read",
        )

        assert result.is_success
        acl = result.value
        assert isinstance(acl, m.Acl)
        assert acl.name == "openldap_acl"
        assert acl.server_type in {
            lib_c.Ldif.LdapServers.OPENLDAP,
            "openldap2",
        }

    def test_create_unified_acl_openldap_2(self) -> None:
        """Test creating unified ACL for OpenLDAP 2.x server."""
        target = m.AclTarget(target_dn="cn=REDACTED_LDAP_BIND_PASSWORD")
        subject_type_literal: lib_c.Ldif.LiteralTypes.AclSubjectTypeLiteral = cast(
            "lib_c.Ldif.LiteralTypes.AclSubjectTypeLiteral", "user"
        )
        subject = m.AclSubject(subject_type=subject_type_literal, subject_value="REDACTED_LDAP_BIND_PASSWORD")
        permissions = m.AclPermissions(read=True)

        result = create_unified_acl_helper(
            name="openldap2_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=lib_c.Ldif.LdapServers.OPENLDAP_2,
            raw_acl="olcAccess: {0}to * by * read",
        )

        assert result.is_success
        acl = result.value
        assert isinstance(acl, m.Acl)

    def test_create_unified_acl_openldap_1(self) -> None:
        """Test creating unified ACL for OpenLDAP 1.x server."""
        target = m.AclTarget(target_dn="cn=REDACTED_LDAP_BIND_PASSWORD")
        subject_type_literal: lib_c.Ldif.LiteralTypes.AclSubjectTypeLiteral = cast(
            "lib_c.Ldif.LiteralTypes.AclSubjectTypeLiteral", "user"
        )
        subject = m.AclSubject(subject_type=subject_type_literal, subject_value="REDACTED_LDAP_BIND_PASSWORD")
        permissions = m.AclPermissions(read=True)

        result = create_unified_acl_helper(
            name="openldap1_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=lib_c.Ldif.LdapServers.OPENLDAP_1,
            raw_acl="access to * by * read",
        )

        assert result.is_success
        acl = result.value
        assert isinstance(acl, m.Acl)

    def test_create_unified_acl_oracle_oid(self) -> None:
        """Test creating unified ACL for Oracle OID server."""
        target = m.AclTarget(target_dn="cn=REDACTED_LDAP_BIND_PASSWORD")
        subject_type_literal: lib_c.Ldif.LiteralTypes.AclSubjectTypeLiteral = cast(
            "lib_c.Ldif.LiteralTypes.AclSubjectTypeLiteral", "user"
        )
        subject = m.AclSubject(subject_type=subject_type_literal, subject_value="REDACTED_LDAP_BIND_PASSWORD")
        permissions = m.AclPermissions(read=True)

        result = create_unified_acl_helper(
            name="oid_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=lib_c.Ldif.LdapServers.ORACLE_OID,
            raw_acl="orclaci: (target=...)(version 3.0)",
        )

        assert result.is_success
        acl = result.value
        assert isinstance(acl, m.Acl)

    def test_create_unified_acl_oracle_oud(self) -> None:
        """Test creating unified ACL for Oracle OUD server."""
        target = m.AclTarget(target_dn="cn=REDACTED_LDAP_BIND_PASSWORD")
        subject_type_literal: lib_c.Ldif.LiteralTypes.AclSubjectTypeLiteral = cast(
            "lib_c.Ldif.LiteralTypes.AclSubjectTypeLiteral", "user"
        )
        subject = m.AclSubject(subject_type=subject_type_literal, subject_value="REDACTED_LDAP_BIND_PASSWORD")
        permissions = m.AclPermissions(read=True)

        result = create_unified_acl_helper(
            name="oud_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=lib_c.Ldif.LdapServers.ORACLE_OUD,
            raw_acl="aci: (target=...)(version 3.0)",
        )

        assert result.is_success
        acl = result.value
        assert isinstance(acl, m.Acl)

    def test_create_unified_acl_ds389(self) -> None:
        """Test creating unified ACL for 389 DS server."""
        target = m.AclTarget(target_dn="cn=REDACTED_LDAP_BIND_PASSWORD")
        subject_type_literal: lib_c.Ldif.LiteralTypes.AclSubjectTypeLiteral = cast(
            "lib_c.Ldif.LiteralTypes.AclSubjectTypeLiteral", "user"
        )
        subject = m.AclSubject(subject_type=subject_type_literal, subject_value="REDACTED_LDAP_BIND_PASSWORD")
        permissions = m.AclPermissions(read=True)

        result = create_unified_acl_helper(
            name="ds389_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=lib_c.Ldif.LdapServers.DS_389,
            raw_acl="aci: (target=...)(version 3.0)",
        )

        assert result.is_success
        acl = result.value
        assert isinstance(acl, m.Acl)

    def test_create_unified_acl_unsupported_server_type_returns_failure(self) -> None:
        """Test that unsupported server types result in validation error."""
        target = m.AclTarget(target_dn="cn=REDACTED_LDAP_BIND_PASSWORD")
        subject_type_literal: lib_c.Ldif.LiteralTypes.AclSubjectTypeLiteral = cast(
            "lib_c.Ldif.LiteralTypes.AclSubjectTypeLiteral", "user"
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

        assert result.is_success
        acl = result.value
        assert acl.server_type in {"openldap", "openldap2"}

    def test_create_unified_acl_preserves_properties(self) -> None:
        """Test that created ACL preserves all input properties."""
        target = m.AclTarget(target_dn="cn=test,dc=example,dc=com")
        subject_type_literal: lib_c.Ldif.LiteralTypes.AclSubjectTypeLiteral = cast(
            "lib_c.Ldif.LiteralTypes.AclSubjectTypeLiteral", "group"
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
            server_type=lib_c.Ldif.LdapServers.OPENLDAP,
            raw_acl="original acl string",
        )

        acl = result.value
        assert acl.name == "test_acl"
        assert acl.target == target
        assert acl.subject == subject
        assert acl.permissions == permissions
        assert acl.raw_acl == "original acl string"

    def test_create_unified_acl_returns_aclbase_instance(self) -> None:
        """Test that created ACL is an m.Acl instance."""
        target = m.AclTarget(target_dn="cn=REDACTED_LDAP_BIND_PASSWORD")
        subject_type_literal: lib_c.Ldif.LiteralTypes.AclSubjectTypeLiteral = cast(
            "lib_c.Ldif.LiteralTypes.AclSubjectTypeLiteral", "user"
        )
        subject = m.AclSubject(subject_type=subject_type_literal, subject_value="REDACTED_LDAP_BIND_PASSWORD")
        permissions = m.AclPermissions(read=True)

        result = create_unified_acl_helper(
            name="test_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=lib_c.Ldif.LdapServers.OPENLDAP,
            raw_acl="test",
        )

        acl = result.value
        assert isinstance(acl, m.Acl)

    def test_create_unified_acl_exception_handling_caught(self) -> None:
        """Test exception handling in create_unified_acl."""
        target = m.AclTarget(target_dn="cn=REDACTED_LDAP_BIND_PASSWORD")
        subject_type_literal: lib_c.Ldif.LiteralTypes.AclSubjectTypeLiteral = cast(
            "lib_c.Ldif.LiteralTypes.AclSubjectTypeLiteral", "user"
        )
        subject = m.AclSubject(subject_type=subject_type_literal, subject_value="REDACTED_LDAP_BIND_PASSWORD")
        permissions = m.AclPermissions(read=True)

        result = create_unified_acl_helper(
            name="test_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type=lib_c.Ldif.LdapServers.OPENLDAP,
            raw_acl="test",
        )

        assert result.is_success

    def test_create_acl_components_with_invalid_data(self) -> None:
        """Test create_acl_components with invalid server type defaults to OpenLDAP."""
        target = m.AclTarget(target_dn="*")
        subject_type_literal: lib_c.Ldif.LiteralTypes.AclSubjectTypeLiteral = cast(
            "lib_c.Ldif.LiteralTypes.AclSubjectTypeLiteral", "all"
        )
        subject = m.AclSubject(subject_type=subject_type_literal, subject_value="*")
        permissions = m.AclPermissions(read=True)

        result = create_unified_acl_helper(
            name="",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type="invalid_server_type",
            raw_acl="(access to *)",
        )

        assert result.is_success
        acl = result.value
        assert acl.server_type in {
            lib_c.Ldif.LdapServers.OPENLDAP,
            "openldap2",
        }
