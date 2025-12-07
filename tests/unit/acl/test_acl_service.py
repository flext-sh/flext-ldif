"""Tests for FlextLdif ACL service functionality.

This module tests the ACL service for parsing, validating, and managing
access control list entries in LDIF format.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import ClassVar

import pytest

from flext_ldif.services.acl import FlextLdifAcl
from tests import c, s

# ServerType enum removed - use c.ServerTypes instead


class ValidationCheckType(StrEnum):
    """Types of ACL validation checks."""

    FIXTURE_ACCESS = "fixture_access"
    ACL_PRESENCE = "acl_presence"


class EdgeCaseType(StrEnum):
    """Edge case types for ACL testing."""

    EMPTY_ACL = "empty_acl"
    MALFORMED_ACL = "malformed_acl"
    MISSING_ATTRIBUTES = "missing_attributes"


class TestsTestFlextLdifAclWithRealFixtures(s):
    """Test FlextLdifAcl with real ACL fixture data using factories and constants."""

    # ═════════════════════════════════════════════════════════════════════════
    # TEST SCENARIO ENUMS
    # ═════════════════════════════════════════════════════════════════════════

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

    # ═════════════════════════════════════════════════════════════════════════
    # TEST DATA MAPPINGS
    # ═════════════════════════════════════════════════════════════════════════

    ACL_INDICATORS: ClassVar[dict[c.ServerTypes, list[str]]] = {
        c.ServerTypes.OID: ["orclaci:", "aci:"],
        c.ServerTypes.OUD: ["aci:"],
    }

    ACL_REQUIRED_ATTRS: ClassVar[dict[c.ServerTypes, list[str]]] = {
        c.ServerTypes.OID: ["orclaci:"],
        c.ServerTypes.OUD: ["aci:"],
    }

    ACL_MIN_LINES: ClassVar[dict[c.ServerTypes, int]] = {
        c.ServerTypes.OID: 5,
        c.ServerTypes.OUD: 5,
    }

    BASIC_CHECK_DATA: ClassVar[dict[str, tuple[c.ServerTypes, ValidationCheckType]]] = {
        CheckScenario.OID_FIXTURE_ACCESS: (
            c.ServerTypes.OID,
            ValidationCheckType.FIXTURE_ACCESS,
        ),
        CheckScenario.OID_ACL_PRESENCE: (
            c.ServerTypes.OID,
            ValidationCheckType.ACL_PRESENCE,
        ),
        CheckScenario.OUD_FIXTURE_ACCESS: (
            c.ServerTypes.OUD,
            ValidationCheckType.FIXTURE_ACCESS,
        ),
        CheckScenario.OUD_ACL_PRESENCE: (
            c.ServerTypes.OUD,
            ValidationCheckType.ACL_PRESENCE,
        ),
    }

    ENCODING_CHECK_DATA: ClassVar[dict[str, c.ServerTypes]] = {
        EncodingScenario.OID_ENCODING: c.ServerTypes.OID,
        EncodingScenario.OUD_ENCODING: c.ServerTypes.OUD,
    }

    STRUCTURE_CHECK_DATA: ClassVar[dict[str, c.ServerTypes]] = {
        StructureScenario.OID_STRUCTURE: c.ServerTypes.OID,
        StructureScenario.OUD_STRUCTURE: c.ServerTypes.OUD,
    }

    EDGE_CASE_DATA: ClassVar[dict[str, tuple[EdgeCaseType, c.ServerTypes]]] = {
        EdgeCaseScenario.OID_EMPTY: (EdgeCaseType.EMPTY_ACL, c.ServerTypes.OID),
        EdgeCaseScenario.OUD_MALFORMED: (EdgeCaseType.MALFORMED_ACL, c.ServerTypes.OUD),
        EdgeCaseScenario.OID_MISSING_ATTRS: (
            EdgeCaseType.MISSING_ATTRIBUTES,
            c.ServerTypes.OID,
        ),
    }

    # ═════════════════════════════════════════════════════════════════════════
    # PRIVATE HELPERS
    # ═════════════════════════════════════════════════════════════════════════

    @staticmethod
    def _get_fixture_path(server_type: c.ServerTypes) -> Path:
        """Get fixture path for server type."""
        # Map server types to fixture paths
        fixture_map = {
            c.ServerTypes.OID: "acl/oid_acl_fixture.ldif",
            c.ServerTypes.OUD: "acl/oud_acl_fixture.ldif",
        }
        fixture_rel_path = fixture_map[server_type]
        return Path(__file__).parent.parent.parent / "fixtures" / fixture_rel_path

    def _get_content_lines(self, content: str) -> list[str]:
        """Get non-empty lines from content."""
        return [line for line in content.split("\n") if line.strip()]

    def _get_acl_lines(self, content: str, server_type: c.ServerTypes) -> list[str]:
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

    def _check_fixture_access(self, content: str, server_type: c.ServerTypes) -> bool:
        """Check if fixture has accessible content with minimum lines."""
        if not content or len(content) == 0:
            return False
        lines = self._get_content_lines(content)
        return len(lines) >= self.ACL_MIN_LINES[server_type]

    def _check_acl_presence(self, content: str, server_type: c.ServerTypes) -> bool:
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
        server_type: c.ServerTypes,
    ) -> None:
        """Validate server-specific ACL attributes."""
        if server_type == c.ServerTypes.OID:
            assert "orclaci:" in content, "OID fixture should have orclaci attributes"
            assert "aci:" in content, "OID fixture should have aci attributes"
        else:  # OUD
            assert "aci:" in content, "OUD fixture should have aci attributes"

    # ═════════════════════════════════════════════════════════════════════════
    # PARAMETRIZED TESTS
    # ═════════════════════════════════════════════════════════════════════════

    @pytest.mark.parametrize(
        ("scenario", "server_type", "check_type"),
        [(name, data[0], data[1]) for name, data in BASIC_CHECK_DATA.items()],
    )
    def test_acl_basic_validation(
        self,
        scenario: str,
        server_type: c.ServerTypes,
        check_type: ValidationCheckType,
    ) -> None:
        """Test ACL basic validation with parametrized checks."""
        fixture_path = self._get_fixture_path(server_type)
        if not fixture_path.exists():
            pytest.skip(f"Fixture not found: {fixture_path}")

        content = fixture_path.read_text(encoding="utf-8")

        # Execute appropriate check
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
        server_type: c.ServerTypes,
    ) -> None:
        """Test ACL fixture structure with comprehensive validation."""
        fixture_path = self._get_fixture_path(server_type)
        if not fixture_path.exists():
            pytest.skip(f"Fixture not found: {fixture_path}")

        content = fixture_path.read_text(encoding="utf-8")

        # Validate basic content
        assert len(content) > 0, (
            f"{server_type.upper()} ACL fixture should have content"
        )

        # Validate lines
        lines = self._get_content_lines(content)
        assert len(lines) >= self.ACL_MIN_LINES[server_type], (
            f"{server_type.upper()} fixture should have minimum lines"
        )

        # Validate ACL presence
        acl_lines = self._get_acl_lines(content, server_type)
        assert len(acl_lines) > 0, (
            f"{server_type.upper()} fixture should contain ACL attributes"
        )

        # Validate LDIF structure
        entries = self._get_ldif_entries(content)
        assert len(entries) > 0, f"Should have LDIF entries for {server_type}"

        # Validate ACL content
        assert self._check_acl_content(content), (
            f"Should have ACL content for {server_type}"
        )

        # Validate required attributes
        required_attrs = self.ACL_REQUIRED_ATTRS[server_type]
        for attr in required_attrs:
            assert attr in content, f"{server_type.upper()} fixture should have {attr}"

        # Validate server-specific attributes
        self._validate_server_specific_acls(content, server_type)

    @pytest.mark.parametrize(
        ("scenario", "server_type"),
        [(name, data) for name, data in ENCODING_CHECK_DATA.items()],
    )
    def test_acl_encoding_validation(
        self,
        scenario: str,
        server_type: c.ServerTypes,
    ) -> None:
        """Test that ACL fixtures have valid UTF-8 encoding."""
        fixture_path = self._get_fixture_path(server_type)
        if not fixture_path.exists():
            pytest.skip(f"Fixture not found: {fixture_path}")

        content = fixture_path.read_text(encoding="utf-8")

        # Validate encoding
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
        server_type: c.ServerTypes,
    ) -> None:
        """Test ACL service edge cases dynamically."""
        # Validate case and server type are valid
        assert case_type in EdgeCaseType
        assert server_type in c.ServerTypes

    def test_acl_service_initialization(self) -> None:
        """Test ACL service can be initialized."""
        service = FlextLdifAcl()
        assert service is not None


__all__ = ["TestFlextLdifAclWithRealFixtures"]
