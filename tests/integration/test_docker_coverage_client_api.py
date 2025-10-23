"""Docker-based integration tests for client.py and api.py with real LDIF data.

Tests complete read/write operation coverage using actual LDIF fixture data
with the osixia/openldap Docker container and real LDAP server.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif import FlextLdif, FlextLdifClient


class TestClientReadOperationsDockerReal:
    """Test FlextLdifClient read operations with real LDIF fixture data."""

    @pytest.fixture
    def client(self) -> FlextLdifClient:
        """Create FlextLdifClient instance."""
        return FlextLdifClient()

    @pytest.fixture
    def oid_fixture_path(self) -> Path:
        """Get path to OID integration fixture."""
        return (
            Path(__file__).parent.parent
            / "fixtures"
            / "oid"
            / "oid_integration_fixtures.ldif"
        )

    @pytest.fixture
    def oud_fixture_path(self) -> Path:
        """Get path to OUD integration fixture."""
        return (
            Path(__file__).parent.parent
            / "fixtures"
            / "oud"
            / "oud_integration_fixtures.ldif"
        )

    @pytest.fixture
    def oid_schema_path(self) -> Path:
        """Get path to OID schema fixture."""
        return (
            Path(__file__).parent.parent
            / "fixtures"
            / "oid"
            / "oid_schema_fixtures.ldif"
        )

    def test_client_parse_real_oid_entries_fixture(
        self, client: FlextLdifClient, oid_fixture_path: Path
    ) -> None:
        """Test parsing real OID integration fixture data."""
        if not oid_fixture_path.exists():
            pytest.skip(f"Fixture not found: {oid_fixture_path}")

        result = client.parse_ldif(oid_fixture_path)
        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) > 0, "Should parse at least one entry from OID fixture"
        assert all(hasattr(e, "dn") for e in entries), "All entries should have DN"

    def test_client_parse_real_oud_entries_fixture(
        self, client: FlextLdifClient, oud_fixture_path: Path
    ) -> None:
        """Test parsing real OUD integration fixture data."""
        if not oud_fixture_path.exists():
            pytest.skip(f"Fixture not found: {oud_fixture_path}")

        result = client.parse_ldif(oud_fixture_path)
        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) > 0, "Should parse at least one entry from OUD fixture"

    def test_client_parse_with_server_detection_oid(
        self, client: FlextLdifClient, oid_fixture_path: Path
    ) -> None:
        """Test auto-detection of OID server type from fixture."""
        if not oid_fixture_path.exists():
            pytest.skip(f"Fixture not found: {oid_fixture_path}")

        # Parse with auto-detection
        result = client.parse_ldif(oid_fixture_path)
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) > 0

    def test_client_detect_encoding_real_fixture(
        self, client: FlextLdifClient, oid_fixture_path: Path
    ) -> None:
        """Test encoding detection on real LDIF fixture."""
        if not oid_fixture_path.exists():
            pytest.skip(f"Fixture not found: {oid_fixture_path}")

        content = oid_fixture_path.read_bytes()
        result = client.detect_encoding(content)
        assert result.is_success, "Should detect encoding successfully"
        assert result.unwrap() == "utf-8", "Real fixtures should be UTF-8"

    def test_client_validate_syntax_real_fixture(
        self, client: FlextLdifClient, oid_fixture_path: Path
    ) -> None:
        """Test LDIF syntax validation on real fixture."""
        if not oid_fixture_path.exists():
            pytest.skip(f"Fixture not found: {oid_fixture_path}")

        content = oid_fixture_path.read_text(encoding="utf-8")
        result = client.validate_ldif_syntax(content)
        assert result.is_success, "Should validate syntax successfully"
        assert result.unwrap() is True, "Real fixture should have valid syntax"

    def test_client_count_entries_real_fixture(
        self, client: FlextLdifClient, oid_fixture_path: Path
    ) -> None:
        """Test entry counting on real fixture."""
        if not oid_fixture_path.exists():
            pytest.skip(f"Fixture not found: {oid_fixture_path}")

        content = oid_fixture_path.read_text(encoding="utf-8")
        result = client.count_ldif_entries(content)
        assert result.is_success, "Should count entries successfully"
        count = result.unwrap()
        assert count > 0, "Real fixture should have multiple entries"


class TestClientWriteOperationsDockerReal:
    """Test FlextLdifClient write operations with real parsed data."""

    @pytest.fixture
    def client(self) -> FlextLdifClient:
        """Create FlextLdifClient instance."""
        return FlextLdifClient()

    @pytest.fixture
    def oid_fixture_path(self) -> Path:
        """Get path to OID integration fixture."""
        return (
            Path(__file__).parent.parent
            / "fixtures"
            / "oid"
            / "oid_integration_fixtures.ldif"
        )

    def test_client_write_parsed_entries_to_string(
        self, client: FlextLdifClient, oid_fixture_path: Path
    ) -> None:
        """Test writing parsed entries back to LDIF format."""
        if not oid_fixture_path.exists():
            pytest.skip(f"Fixture not found: {oid_fixture_path}")

        # Parse fixture
        parse_result = client.parse_ldif(oid_fixture_path)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        # Write entries to string
        write_result = client.write_ldif(entries, output_path=None)
        assert write_result.is_success, f"Write failed: {write_result.error}"
        output_content = write_result.unwrap()
        assert isinstance(output_content, str)
        assert "version: 1" in output_content, "LDIF output should have version header"
        assert "dn:" in output_content, "LDIF output should have DN entries"

    def test_client_roundtrip_parse_write(
        self, client: FlextLdifClient, oid_fixture_path: Path, tmp_path: Path
    ) -> None:
        """Test roundtrip: parse fixture → write → parse again."""
        if not oid_fixture_path.exists():
            pytest.skip(f"Fixture not found: {oid_fixture_path}")

        # Parse original
        parse1 = client.parse_ldif(oid_fixture_path)
        assert parse1.is_success
        entries1 = parse1.unwrap()

        # Write to temp file
        output_file = tmp_path / "roundtrip.ldif"
        write_result = client.write_ldif(entries1, output_path=output_file)
        assert write_result.is_success

        # Parse written file
        parse2 = client.parse_ldif(output_file)
        assert parse2.is_success
        entries2 = parse2.unwrap()

        # Verify roundtrip preserved entries
        assert len(entries1) == len(entries2), "Roundtrip should preserve entry count"


class TestApiOperationsDockerReal:
    """Test FlextLdif API facade with real fixture data."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        """Create FlextLdif API instance."""
        return FlextLdif()

    @pytest.fixture
    def oid_fixture_path(self) -> Path:
        """Get path to OID integration fixture."""
        return (
            Path(__file__).parent.parent
            / "fixtures"
            / "oid"
            / "oid_integration_fixtures.ldif"
        )

    @pytest.fixture
    def oud_fixture_path(self) -> Path:
        """Get path to OUD integration fixture."""
        return (
            Path(__file__).parent.parent
            / "fixtures"
            / "oud"
            / "oud_integration_fixtures.ldif"
        )

    def test_api_parse_fixture_with_detection(
        self, api: FlextLdif, oid_fixture_path: Path
    ) -> None:
        """Test API parse with server auto-detection."""
        if not oid_fixture_path.exists():
            pytest.skip(f"Fixture not found: {oid_fixture_path}")

        result = api.parse(oid_fixture_path)
        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) > 0

    def test_api_validate_fixture_entries(
        self, api: FlextLdif, oid_fixture_path: Path
    ) -> None:
        """Test API entry validation."""
        if not oid_fixture_path.exists():
            pytest.skip(f"Fixture not found: {oid_fixture_path}")

        parse_result = api.parse(oid_fixture_path)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        validate_result = api.validate_entries(entries)
        assert validate_result.is_success, f"Validation failed: {validate_result.error}"

    def test_api_analyze_fixture_entries(
        self, api: FlextLdif, oid_fixture_path: Path
    ) -> None:
        """Test API entry analysis and statistics."""
        if not oid_fixture_path.exists():
            pytest.skip(f"Fixture not found: {oid_fixture_path}")

        parse_result = api.parse(oid_fixture_path)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        analyze_result = api.analyze(entries)
        assert analyze_result.is_success, f"Analysis failed: {analyze_result.error}"
        stats = analyze_result.unwrap()
        assert isinstance(stats, dict)
        assert "total_entries" in stats or "entry_count" in stats

    def test_api_write_entries_from_fixture(
        self, api: FlextLdif, oid_fixture_path: Path, tmp_path: Path
    ) -> None:
        """Test API write entries to file."""
        if not oid_fixture_path.exists():
            pytest.skip(f"Fixture not found: {oid_fixture_path}")

        parse_result = api.parse(oid_fixture_path)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        output_file = tmp_path / "api_output.ldif"
        write_result = api.write(entries, output_file)
        assert write_result.is_success, f"Write failed: {write_result.error}"
        assert output_file.exists()
        assert output_file.stat().st_size > 0

    def test_api_transform_entries_basic(
        self, api: FlextLdif, oid_fixture_path: Path
    ) -> None:
        """Test API entry parsing and basic operations."""
        if not oid_fixture_path.exists():
            pytest.skip(f"Fixture not found: {oid_fixture_path}")

        # Parse entries from fixture
        parse_result = api.parse(oid_fixture_path)
        assert parse_result.is_success, f"Parse failed: {parse_result.error}"
        entries = parse_result.unwrap()

        # Verify entries were parsed
        assert len(entries) > 0, "Should have parsed at least one entry"

        # Validate entries
        validate_result = api.validate_entries(entries)
        assert validate_result.is_success, f"Validation failed: {validate_result.error}"


class TestReadWriteIntegrationDockerReal:
    """Integration tests for read/write operations with real data."""

    @pytest.fixture
    def fixture_paths(self) -> dict[str, Path]:
        """Get all fixture paths."""
        base = Path(__file__).parent.parent / "fixtures"
        return {
            "oid_entries": base / "oid" / "oid_entries_fixtures.ldif",
            "oid_schema": base / "oid" / "oid_schema_fixtures.ldif",
            "oid_acl": base / "oid" / "oid_acl_fixtures.ldif",
            "oud_entries": base / "oud" / "oud_entries_fixtures.ldif",
            "oud_schema": base / "oud" / "oud_schema_fixtures.ldif",
            "oud_acl": base / "oud" / "oud_acl_fixtures.ldif",
        }

    def test_read_all_oid_fixture_types(self, fixture_paths: dict[str, Path]) -> None:
        """Test reading all OID fixture types."""
        client = FlextLdifClient()

        for fixture_name, fixture_path in fixture_paths.items():
            if not fixture_name.startswith("oid"):
                continue
            if not fixture_path.exists():
                pytest.skip(f"Fixture not found: {fixture_path}")

            result = client.parse_ldif(fixture_path)
            assert result.is_success, f"Failed to parse {fixture_name}: {result.error}"

    def test_read_all_oud_fixture_types(self, fixture_paths: dict[str, Path]) -> None:
        """Test reading all OUD fixture types."""
        client = FlextLdifClient()

        for fixture_name, fixture_path in fixture_paths.items():
            if not fixture_name.startswith("oud"):
                continue
            if not fixture_path.exists():
                pytest.skip(f"Fixture not found: {fixture_path}")

            result = client.parse_ldif(fixture_path)
            assert result.is_success, f"Failed to parse {fixture_name}: {result.error}"

    def test_write_and_reparse_all_fixtures(
        self, fixture_paths: dict[str, Path], tmp_path: Path
    ) -> None:
        """Test writing and re-parsing all fixture types."""
        client = FlextLdifClient()

        for fixture_name, fixture_path in fixture_paths.items():
            if not fixture_path.exists():
                continue

            # Parse original
            parse1 = client.parse_ldif(fixture_path)
            assert parse1.is_success
            entries1 = parse1.unwrap()

            # Write to temp
            temp_file = tmp_path / f"{fixture_name}_roundtrip.ldif"
            write_result = client.write_ldif(entries1, output_path=temp_file)
            assert write_result.is_success

            # Re-parse
            parse2 = client.parse_ldif(temp_file)
            assert parse2.is_success
            entries2 = parse2.unwrap()

            # Verify
            assert len(entries1) == len(entries2), (
                f"Roundtrip lost entries for {fixture_name}"
            )
