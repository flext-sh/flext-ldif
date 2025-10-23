"""Comprehensive real tests for FlextLdif API using actual LDIF fixtures.

Tests the complete FlextLdif API facade with real LDIF data from OID, OUD,
and other server types using actual fixture files.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif import FlextLdif


class TestFlextLdifApiWithRealFixtures:
    """Test FlextLdif API facade with real LDIF fixture data."""

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

    def test_api_parse_oid_fixture(
        self, api: FlextLdif, oid_fixture_path: Path
    ) -> None:
        """Test parsing real OID LDIF fixture."""
        if not oid_fixture_path.exists():
            pytest.skip(f"Fixture not found: {oid_fixture_path}")

        result = api.parse(oid_fixture_path)
        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) > 0, "Should parse at least one entry"
        assert all(hasattr(e, "dn") for e in entries), "All entries should have DN"

    def test_api_parse_oud_fixture(
        self, api: FlextLdif, oud_fixture_path: Path
    ) -> None:
        """Test parsing real OUD LDIF fixture."""
        if not oud_fixture_path.exists():
            pytest.skip(f"Fixture not found: {oud_fixture_path}")

        result = api.parse(oud_fixture_path)
        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) > 0, "Should parse at least one entry from OUD"

    def test_api_validate_entries_from_fixture(
        self, api: FlextLdif, oid_fixture_path: Path
    ) -> None:
        """Test validating entries parsed from real fixture."""
        if not oid_fixture_path.exists():
            pytest.skip(f"Fixture not found: {oid_fixture_path}")

        parse_result = api.parse(oid_fixture_path)
        assert parse_result.is_success

        entries = parse_result.unwrap()
        validate_result = api.validate_entries(entries)
        assert validate_result.is_success, f"Validation failed: {validate_result.error}"

    def test_api_analyze_entries_from_fixture(
        self, api: FlextLdif, oid_fixture_path: Path
    ) -> None:
        """Test analyzing entries from real fixture."""
        if not oid_fixture_path.exists():
            pytest.skip(f"Fixture not found: {oid_fixture_path}")

        parse_result = api.parse(oid_fixture_path)
        assert parse_result.is_success

        entries = parse_result.unwrap()
        analyze_result = api.analyze(entries)
        assert analyze_result.is_success, f"Analysis failed: {analyze_result.error}"

        stats = analyze_result.unwrap()
        assert isinstance(stats, dict), "Analysis should return a dictionary"
        # Check for expected stat keys
        assert any(
            key in stats for key in ["total_entries", "entry_count", "entries"]
        ), "Should have entry count statistics"

    def test_api_write_parsed_entries(
        self, api: FlextLdif, oid_fixture_path: Path, tmp_path: Path
    ) -> None:
        """Test writing parsed entries from real fixture."""
        if not oid_fixture_path.exists():
            pytest.skip(f"Fixture not found: {oid_fixture_path}")

        parse_result = api.parse(oid_fixture_path)
        assert parse_result.is_success

        entries = parse_result.unwrap()
        output_file = tmp_path / "output.ldif"

        write_result = api.write(entries, output_file)
        assert write_result.is_success, f"Write failed: {write_result.error}"
        assert output_file.exists(), "Output file should be created"
        assert output_file.stat().st_size > 0, "Output file should have content"

    def test_api_roundtrip_parse_write_parse(
        self, api: FlextLdif, oid_fixture_path: Path, tmp_path: Path
    ) -> None:
        """Test roundtrip: parse → write → parse again."""
        if not oid_fixture_path.exists():
            pytest.skip(f"Fixture not found: {oid_fixture_path}")

        # Parse original
        parse1 = api.parse(oid_fixture_path)
        assert parse1.is_success
        entries1 = parse1.unwrap()
        count1 = len(entries1)

        # Write to temp
        output_file = tmp_path / "roundtrip.ldif"
        write_result = api.write(entries1, output_file)
        assert write_result.is_success

        # Parse written file
        parse2 = api.parse(output_file)
        assert parse2.is_success
        entries2 = parse2.unwrap()
        count2 = len(entries2)

        # Verify counts preserved
        assert count1 == count2, "Roundtrip should preserve entry count"

    def test_api_detect_server_type_oid(
        self, api: FlextLdif, oid_fixture_path: Path
    ) -> None:
        """Test server type detection on OID fixture."""
        if not oid_fixture_path.exists():
            pytest.skip(f"Fixture not found: {oid_fixture_path}")

        result = api.detect_server_type(oid_fixture_path)
        assert result.is_success, f"Detection failed: {result.error}"

        detection = result.unwrap()
        assert isinstance(detection, dict)
        assert "detected_server_type" in detection

    def test_api_get_effective_server_type(
        self, api: FlextLdif, oid_fixture_path: Path
    ) -> None:
        """Test getting effective server type for parsing."""
        if not oid_fixture_path.exists():
            pytest.skip(f"Fixture not found: {oid_fixture_path}")

        result = api.get_effective_server_type(oid_fixture_path)
        assert result.is_success, f"Get server type failed: {result.error}"

        server_type = result.unwrap()
        assert isinstance(server_type, str)
        assert len(server_type) > 0

    def test_api_parse_with_manual_server_type(self, oid_fixture_path: Path) -> None:
        """Test parsing with manually specified server type."""
        if not oid_fixture_path.exists():
            pytest.skip(f"Fixture not found: {oid_fixture_path}")

        # Create new FlextLdif with manual quirks configuration
        from flext_ldif import FlextLdifConfig

        config = FlextLdifConfig(
            quirks_detection_mode="manual", quirks_server_type="oid"
        )
        api = FlextLdif(config=config)

        result = api.parse(oid_fixture_path)
        assert result.is_success, f"Parse failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) > 0

    def test_api_parse_with_relaxed_mode(self, oid_fixture_path: Path) -> None:
        """Test parsing with relaxed mode enabled."""
        if not oid_fixture_path.exists():
            pytest.skip(f"Fixture not found: {oid_fixture_path}")

        # Create new FlextLdif with relaxed parsing enabled
        from flext_ldif import FlextLdifConfig

        config = FlextLdifConfig(enable_relaxed_parsing=True)
        api = FlextLdif(config=config)

        result = api.parse(oid_fixture_path)
        assert result.is_success, f"Parse with relaxed failed: {result.error}"
        entries = result.unwrap()
        assert len(entries) > 0

    def test_api_parse_multiple_fixtures_sequence(
        self, api: FlextLdif, oid_fixture_path: Path, oud_fixture_path: Path
    ) -> None:
        """Test parsing multiple fixtures in sequence."""
        if not oid_fixture_path.exists() or not oud_fixture_path.exists():
            pytest.skip("One or both fixtures not found")

        # Parse OID first
        result1 = api.parse(oid_fixture_path)
        assert result1.is_success
        entries1 = result1.unwrap()

        # Then parse OUD
        result2 = api.parse(oud_fixture_path)
        assert result2.is_success
        entries2 = result2.unwrap()

        # Both should parse successfully
        assert len(entries1) > 0
        assert len(entries2) > 0
        # Totals should be reasonable
        assert len(entries1) + len(entries2) > 0
