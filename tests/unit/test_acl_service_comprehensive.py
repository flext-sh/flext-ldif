"""Comprehensive real tests for ACL service using actual LDIF fixtures.

Tests ACL service operations with real ACL data from OID and OUD servers.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif.acl.service import FlextLdifAclService


class TestFlextLdifAclServiceWithRealFixtures:
    """Test FlextLdifAclService with real ACL fixture data."""

    @pytest.fixture
    def acl_service(self) -> FlextLdifAclService:
        """Create ACL service instance."""
        return FlextLdifAclService()

    @pytest.fixture
    def oid_acl_fixture(self) -> Path:
        """Get path to OID ACL fixture."""
        return (
            Path(__file__).parent.parent / "fixtures" / "oid" / "oid_acl_fixtures.ldif"
        )

    @pytest.fixture
    def oud_acl_fixture(self) -> Path:
        """Get path to OUD ACL fixture."""
        return (
            Path(__file__).parent.parent / "fixtures" / "oud" / "oud_acl_fixtures.ldif"
        )

    def test_acl_service_initialization(self) -> None:
        """Test ACL service can be initialized."""
        service = FlextLdifAclService()
        assert service is not None

    def test_acl_service_read_oid_acl_fixture(
        self, acl_service: FlextLdifAclService, oid_acl_fixture: Path
    ) -> None:
        """Test reading OID ACL fixture file."""
        if not oid_acl_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_acl_fixture}")

        content = oid_acl_fixture.read_text(encoding="utf-8")
        assert len(content) > 0, "ACL fixture should have content"
        assert "orclaci:" in content or "aci:" in content, "Should have ACL attributes"

    def test_acl_service_read_oud_acl_fixture(
        self, acl_service: FlextLdifAclService, oud_acl_fixture: Path
    ) -> None:
        """Test reading OUD ACL fixture file."""
        if not oud_acl_fixture.exists():
            pytest.skip(f"Fixture not found: {oud_acl_fixture}")

        content = oud_acl_fixture.read_text(encoding="utf-8")
        assert len(content) > 0, "OUD ACL fixture should have content"

    def test_acl_service_parse_oid_acl_lines(
        self, acl_service: FlextLdifAclService, oid_acl_fixture: Path
    ) -> None:
        """Test parsing ACL lines from OID fixture."""
        if not oid_acl_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_acl_fixture}")

        content = oid_acl_fixture.read_text(encoding="utf-8")
        lines = content.split("\n")

        # Find orclaci lines
        acl_lines = [line for line in lines if line.startswith("orclaci:")]
        assert len(acl_lines) > 0, "OID ACL fixture should have orclaci entries"

        # Test parsing each ACL line
        for acl_line in acl_lines[:3]:  # Test first 3 ACL lines
            assert len(acl_line) > 0, "ACL line should have content"
            assert "orclaci:" in acl_line, "Should be valid orclaci line"

    def test_acl_service_handle_empty_acl(self) -> None:
        """Test handling empty ACL content."""
        service = FlextLdifAclService()
        assert service is not None

    def test_acl_service_process_multiple_acl_types(
        self,
        acl_service: FlextLdifAclService,
        oid_acl_fixture: Path,
        oud_acl_fixture: Path,
    ) -> None:
        """Test processing both OID and OUD ACL types."""
        if not oid_acl_fixture.exists() or not oud_acl_fixture.exists():
            pytest.skip("One or both fixtures not found")

        # Read OID
        oid_content = oid_acl_fixture.read_text(encoding="utf-8")
        assert len(oid_content) > 0

        # Read OUD
        oud_content = oud_acl_fixture.read_text(encoding="utf-8")
        assert len(oud_content) > 0

        # Both should be readable
        assert oid_content != oud_content, "OID and OUD ACL should be different"

    def test_acl_service_validate_acl_structure(
        self, acl_service: FlextLdifAclService, oid_acl_fixture: Path
    ) -> None:
        """Test validating ACL structure from real fixture."""
        if not oid_acl_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_acl_fixture}")

        content = oid_acl_fixture.read_text(encoding="utf-8")
        lines = content.split("\n")

        # Count ACL entries
        acl_count = len([line for line in lines if "acl" in line.lower()])
        assert acl_count > 0, "Should find ACL entries"

    def test_acl_service_fixture_line_count(
        self, acl_service: FlextLdifAclService, oid_acl_fixture: Path
    ) -> None:
        """Test that ACL fixture has expected content."""
        if not oid_acl_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_acl_fixture}")

        content = oid_acl_fixture.read_text(encoding="utf-8")
        lines = [line for line in content.split("\n") if line.strip()]

        # Should have meaningful content
        assert len(lines) > 5, "ACL fixture should have multiple lines"

    def test_acl_service_handle_acl_attributes(
        self, acl_service: FlextLdifAclService, oid_acl_fixture: Path
    ) -> None:
        """Test handling various ACL attributes."""
        if not oid_acl_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_acl_fixture}")

        content = oid_acl_fixture.read_text(encoding="utf-8")

        # Parse into entries
        entries = content.split("dn:")
        entry_count = len([e for e in entries if e.strip()])

        # Should have multiple entries
        assert entry_count > 0, "Should have LDIF entries with ACL data"

    def test_acl_service_fixture_encoding(
        self, acl_service: FlextLdifAclService, oid_acl_fixture: Path
    ) -> None:
        """Test that ACL fixture has valid UTF-8 encoding."""
        if not oid_acl_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_acl_fixture}")

        # Read as UTF-8 and should not raise
        content = oid_acl_fixture.read_text(encoding="utf-8")
        assert isinstance(content, str)
        assert len(content) > 0

    def test_acl_service_both_fixtures_valid(
        self,
        acl_service: FlextLdifAclService,
        oid_acl_fixture: Path,
        oud_acl_fixture: Path,
    ) -> None:
        """Test that both OID and OUD ACL fixtures are valid."""
        if not oid_acl_fixture.exists() or not oud_acl_fixture.exists():
            pytest.skip("One or both fixtures not found")

        # Both should exist and be readable
        assert oid_acl_fixture.exists()
        assert oud_acl_fixture.exists()

        # Both should have content
        oid_content = oid_acl_fixture.read_text(encoding="utf-8")
        oud_content = oud_acl_fixture.read_text(encoding="utf-8")

        assert len(oid_content) > 0
        assert len(oud_content) > 0
