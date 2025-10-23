"""Comprehensive real tests for FlextLdifClient using actual LDIF fixtures.

Tests low-level client operations with real LDIF data from multiple server types.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif import FlextLdifClient


class TestFlextLdifClientWithRealFixtures:
    """Test FlextLdifClient operations with real LDIF fixture data."""

    @pytest.fixture
    def client(self) -> FlextLdifClient:
        """Create FlextLdifClient instance."""
        return FlextLdifClient()

    @pytest.fixture
    def oid_entries_fixture(self) -> Path:
        """Get path to OID entries fixture."""
        return (
            Path(__file__).parent.parent
            / "fixtures"
            / "oid"
            / "oid_entries_fixtures.ldif"
        )

    @pytest.fixture
    def oid_schema_fixture(self) -> Path:
        """Get path to OID schema fixture."""
        return (
            Path(__file__).parent.parent
            / "fixtures"
            / "oid"
            / "oid_schema_fixtures.ldif"
        )

    @pytest.fixture
    def oid_acl_fixture(self) -> Path:
        """Get path to OID ACL fixture."""
        return (
            Path(__file__).parent.parent / "fixtures" / "oid" / "oid_acl_fixtures.ldif"
        )

    @pytest.fixture
    def oud_entries_fixture(self) -> Path:
        """Get path to OUD entries fixture."""
        return (
            Path(__file__).parent.parent
            / "fixtures"
            / "oud"
            / "oud_entries_fixtures.ldif"
        )

    def test_client_parse_ldif_entries_oid(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test parsing real OID entries fixture."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        result = client.parse_ldif(oid_entries_fixture)
        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) > 0, "Should parse at least one entry"

    def test_client_parse_ldif_schema_oid(
        self, client: FlextLdifClient, oid_schema_fixture: Path
    ) -> None:
        """Test parsing real OID schema fixture."""
        if not oid_schema_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_schema_fixture}")

        result = client.parse_ldif(oid_schema_fixture)
        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) > 0, "Schema should have entries"

    def test_client_parse_ldif_acl_oid(
        self, client: FlextLdifClient, oid_acl_fixture: Path
    ) -> None:
        """Test parsing real OID ACL fixture."""
        if not oid_acl_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_acl_fixture}")

        result = client.parse_ldif(oid_acl_fixture)
        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) > 0, "ACL fixture should have entries"

    def test_client_parse_ldif_oud_entries(
        self, client: FlextLdifClient, oud_entries_fixture: Path
    ) -> None:
        """Test parsing real OUD entries fixture."""
        if not oud_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oud_entries_fixture}")

        result = client.parse_ldif(oud_entries_fixture)
        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) > 0

    def test_client_detect_encoding_from_fixture(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test detecting encoding from real fixture."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        content = oid_entries_fixture.read_bytes()
        result = client.detect_encoding(content)
        assert result.is_success, "Should detect encoding"
        encoding = result.unwrap()
        assert isinstance(encoding, str)
        assert len(encoding) > 0

    def test_client_validate_ldif_syntax_from_fixture(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test LDIF syntax validation on real fixture."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        content = oid_entries_fixture.read_text(encoding="utf-8")
        result = client.validate_ldif_syntax(content)
        assert result.is_success, "Should validate syntax"
        is_valid = result.unwrap()
        assert isinstance(is_valid, bool)

    def test_client_count_ldif_entries_from_fixture(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test counting entries in real fixture."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        content = oid_entries_fixture.read_text(encoding="utf-8")
        result = client.count_ldif_entries(content)
        assert result.is_success, "Should count entries"
        count = result.unwrap()
        assert count > 0, "Should have at least one entry"

    def test_client_write_ldif_to_string(
        self, client: FlextLdifClient, oid_entries_fixture: Path
    ) -> None:
        """Test writing parsed entries to LDIF string."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        parse_result = client.parse_ldif(oid_entries_fixture)
        assert parse_result.is_success

        entries = parse_result.unwrap()
        write_result = client.write_ldif(entries, output_path=None)
        assert write_result.is_success, f"Write failed: {write_result.error}"

        output = write_result.unwrap()
        assert isinstance(output, str)
        assert len(output) > 0
        assert "version: 1" in output, "Should have LDIF version header"
        assert "dn:" in output, "Should have DN entries"

    def test_client_write_ldif_to_file(
        self,
        client: FlextLdifClient,
        oid_entries_fixture: Path,
        tmp_path: Path,
    ) -> None:
        """Test writing parsed entries to LDIF file."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        parse_result = client.parse_ldif(oid_entries_fixture)
        assert parse_result.is_success

        entries = parse_result.unwrap()
        output_file = tmp_path / "output.ldif"
        write_result = client.write_ldif(entries, output_path=output_file)
        assert write_result.is_success

        assert output_file.exists(), "Output file should be created"
        content = output_file.read_text(encoding="utf-8")
        assert len(content) > 0
        assert "dn:" in content

    def test_client_roundtrip_parse_write_parse(
        self,
        client: FlextLdifClient,
        oid_entries_fixture: Path,
        tmp_path: Path,
    ) -> None:
        """Test roundtrip: parse → write → parse again."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        # Parse original
        parse1 = client.parse_ldif(oid_entries_fixture)
        assert parse1.is_success
        entries1 = parse1.unwrap()
        count1 = len(entries1)

        # Write to temp
        output_file = tmp_path / "roundtrip.ldif"
        write_result = client.write_ldif(entries1, output_path=output_file)
        assert write_result.is_success

        # Parse written file
        parse2 = client.parse_ldif(output_file)
        assert parse2.is_success
        entries2 = parse2.unwrap()
        count2 = len(entries2)

        # Verify counts preserved
        assert count1 == count2, "Roundtrip should preserve entry count"

    def test_client_parse_multiple_fixtures_sequential(
        self,
        client: FlextLdifClient,
        oid_entries_fixture: Path,
        oud_entries_fixture: Path,
    ) -> None:
        """Test parsing multiple fixtures in sequence."""
        if not oid_entries_fixture.exists() or not oud_entries_fixture.exists():
            pytest.skip("One or both fixtures not found")

        # Parse OID
        result1 = client.parse_ldif(oid_entries_fixture)
        assert result1.is_success
        entries1 = result1.unwrap()

        # Parse OUD
        result2 = client.parse_ldif(oud_entries_fixture)
        assert result2.is_success
        entries2 = result2.unwrap()

        # Both successful
        assert len(entries1) > 0
        assert len(entries2) > 0

    def test_client_handle_large_fixture(
        self, client: FlextLdifClient, oid_schema_fixture: Path
    ) -> None:
        """Test handling large LDIF schema fixture."""
        if not oid_schema_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_schema_fixture}")

        result = client.parse_ldif(oid_schema_fixture)
        assert result.is_success
        entries = result.unwrap()
        # Schema files should have at least one entry
        assert len(entries) > 0, "Schema should have at least one entry"
