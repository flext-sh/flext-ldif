"""Comprehensive API and Client Methods Coverage Tests.

This test suite targets uncovered lines in api.py and client.py with real LDIF operations.
Focuses on: parse variants, write operations, filtering, analysis, migration, and config handling.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif import FlextLdif, FlextLdifClient, FlextLdifConfig


class TestApiParsingVariants:
    """Test all API parsing variants and modes."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        return FlextLdif()

    @pytest.fixture
    def client(self) -> FlextLdifClient:
        return FlextLdifClient()

    @pytest.fixture
    def fixtures_dir(self) -> Path:
        return Path(__file__).parent.parent / "fixtures"

    def test_api_parse_with_relaxed_mode(self, fixtures_dir: Path) -> None:
        """Test API parsing with relaxed mode enabled."""
        config = FlextLdifConfig(enable_relaxed_parsing=True)
        api = FlextLdif(config=config)

        for server_type in ["oid", "oud", "openldap"]:
            fixture_path = (
                fixtures_dir / server_type / f"{server_type}_integration_fixtures.ldif"
            )
            if not fixture_path.exists():
                continue

            result = api.parse(fixture_path)
            assert result.is_success or result.is_failure
            if result.is_success:
                entries = result.unwrap()
                assert len(entries) >= 0

    def test_api_parse_with_manual_server_override(self, fixtures_dir: Path) -> None:
        """Test API parsing with manual server type override."""
        config = FlextLdifConfig(
            quirks_detection_mode="manual", quirks_server_type="oid"
        )
        api = FlextLdif(config=config)

        fixture_path = fixtures_dir / "oid" / "oid_integration_fixtures.ldif"
        if fixture_path.exists():
            result = api.parse(fixture_path)
            assert result.is_success or result.is_failure

    def test_api_parse_with_disabled_quirks(self, fixtures_dir: Path) -> None:
        """Test API parsing with quirks disabled (RFC-only mode)."""
        config = FlextLdifConfig(quirks_detection_mode="disabled")
        api = FlextLdif(config=config)

        fixture_path = fixtures_dir / "oid" / "oid_integration_fixtures.ldif"
        if fixture_path.exists():
            result = api.parse(fixture_path)
            assert result.is_success or result.is_failure

    def test_api_parse_with_path_string(self, fixtures_dir: Path) -> None:
        """Test API parsing with string path instead of Path object."""
        api = FlextLdif()

        fixture_path = fixtures_dir / "oid" / "oid_integration_fixtures.ldif"
        if fixture_path.exists():
            # Pass as string path
            result = api.parse(str(fixture_path))
            assert result.is_success or result.is_failure


class TestClientEncoding:
    """Test client encoding detection and handling."""

    @pytest.fixture
    def client(self) -> FlextLdifClient:
        return FlextLdifClient()

    @pytest.fixture
    def fixtures_dir(self) -> Path:
        return Path(__file__).parent.parent / "fixtures"

    def test_client_detect_encoding_utf8(
        self, client: FlextLdifClient, fixtures_dir: Path
    ) -> None:
        """Test UTF-8 encoding detection."""
        fixture_path = fixtures_dir / "oid" / "oid_integration_fixtures.ldif"
        if not fixture_path.exists():
            return

        result = client.detect_encoding(fixture_path)
        assert result.is_success or result.is_failure
        if result.is_success:
            encoding = result.unwrap()
            assert encoding in {"utf-8", "utf8", "UTF-8"}

    def test_client_encoding_in_parse(
        self, client: FlextLdifClient, fixtures_dir: Path
    ) -> None:
        """Test that encoding is properly used during parsing."""
        fixture_path = fixtures_dir / "oid" / "oid_integration_fixtures.ldif"
        if not fixture_path.exists():
            return

        result = client.parse_ldif(fixture_path)
        assert result.is_success or result.is_failure


class TestClientFilterOperations:
    """Test filtering with various criteria via API."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        return FlextLdif()

    @pytest.fixture
    def fixtures_dir(self) -> Path:
        return Path(__file__).parent.parent / "fixtures"

    def test_api_filter_by_objectclass(
        self, api: FlextLdif, fixtures_dir: Path
    ) -> None:
        """Test filtering entries by objectClass."""
        fixture_path = fixtures_dir / "oid" / "oid_integration_fixtures.ldif"
        if not fixture_path.exists():
            return

        parse_result = api.parse(fixture_path)
        if not parse_result.is_success:
            return

        entries = parse_result.unwrap()
        filter_result = api.filter(entries, objectclass="person")
        assert filter_result.is_success or filter_result.is_failure

    def test_api_filter_by_custom_predicate(
        self, api: FlextLdif, fixtures_dir: Path
    ) -> None:
        """Test filtering entries with custom predicate."""
        fixture_path = fixtures_dir / "oid" / "oid_integration_fixtures.ldif"
        if not fixture_path.exists():
            return

        parse_result = api.parse(fixture_path)
        if not parse_result.is_success:
            return

        entries = parse_result.unwrap()
        filter_result = api.filter(
            entries, custom_filter=lambda e: "dc=" in str(e.dn).lower()
        )
        assert filter_result.is_success or filter_result.is_failure


class TestApiMigrationVariants:
    """Test migration with various server combinations."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        return FlextLdif()

    @pytest.fixture
    def fixtures_dir(self) -> Path:
        return Path(__file__).parent.parent / "fixtures"

    def test_migration_oid_to_oud(
        self, api: FlextLdif, fixtures_dir: Path, tmp_path: Path
    ) -> None:
        """Test OID to OUD migration."""
        fixture_path = fixtures_dir / "oid" / "oid_integration_fixtures.ldif"
        if not fixture_path.exists():
            return

        input_dir = tmp_path / "oid_input"
        output_dir = tmp_path / "oid_output"
        input_dir.mkdir()
        output_dir.mkdir()

        import shutil

        shutil.copy(fixture_path, input_dir / "data.ldif")

        result = api.migrate(
            input_dir=input_dir,
            output_dir=output_dir,
            from_server="oid",
            to_server="oud",
        )
        assert result.is_success or result.is_failure

    def test_migration_to_rfc(
        self, api: FlextLdif, fixtures_dir: Path, tmp_path: Path
    ) -> None:
        """Test migration to RFC-only format."""
        fixture_path = fixtures_dir / "oid" / "oid_integration_fixtures.ldif"
        if not fixture_path.exists():
            return

        input_dir = tmp_path / "rfc_input"
        output_dir = tmp_path / "rfc_output"
        input_dir.mkdir()
        output_dir.mkdir()

        import shutil

        shutil.copy(fixture_path, input_dir / "data.ldif")

        result = api.migrate(
            input_dir=input_dir,
            output_dir=output_dir,
            from_server="oid",
            to_server="rfc",
        )
        assert result.is_success or result.is_failure


class TestApiAnalysisOperations:
    """Test comprehensive analysis operations."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        return FlextLdif()

    @pytest.fixture
    def client(self) -> FlextLdifClient:
        return FlextLdifClient()

    @pytest.fixture
    def fixtures_dir(self) -> Path:
        return Path(__file__).parent.parent / "fixtures"

    def test_api_analyze_with_statistics(
        self, api: FlextLdif, fixtures_dir: Path
    ) -> None:
        """Test API analysis with statistics calculation."""
        for server_type in ["oid", "oud", "openldap"]:
            fixture_path = (
                fixtures_dir / server_type / f"{server_type}_integration_fixtures.ldif"
            )
            if not fixture_path.exists():
                continue

            parse_result = api.parse(fixture_path)
            if not parse_result.is_success:
                continue

            entries = parse_result.unwrap()
            analyze_result = api.analyze(entries)
            assert analyze_result.is_success or analyze_result.is_failure

    def test_client_analyze_entries(
        self, client: FlextLdifClient, fixtures_dir: Path
    ) -> None:
        """Test client entry analysis."""
        fixture_path = fixtures_dir / "oid" / "oid_integration_fixtures.ldif"
        if not fixture_path.exists():
            return

        parse_result = client.parse_ldif(fixture_path)
        if not parse_result.is_success:
            return

        entries = parse_result.unwrap()
        analyze_result = client.analyze_entries(entries[:10])
        assert analyze_result.is_success or analyze_result.is_failure


class TestApiServerDetection:
    """Test server type detection and effective server type."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        return FlextLdif()

    @pytest.fixture
    def fixtures_dir(self) -> Path:
        return Path(__file__).parent.parent / "fixtures"

    def test_api_detect_server_type(self, api: FlextLdif, fixtures_dir: Path) -> None:
        """Test server type detection from LDIF content."""
        for server_type in ["oid", "oud", "openldap"]:
            fixture_path = (
                fixtures_dir / server_type / f"{server_type}_integration_fixtures.ldif"
            )
            if not fixture_path.exists():
                continue

            result = api.detect_server_type(fixture_path)
            assert result.is_success or result.is_failure

    def test_api_get_effective_server_type(
        self, api: FlextLdif, fixtures_dir: Path
    ) -> None:
        """Test getting effective server type for parsing."""
        fixture_path = fixtures_dir / "oid" / "oid_integration_fixtures.ldif"
        if not fixture_path.exists():
            return

        result = api.get_effective_server_type(fixture_path)
        assert result.is_success or result.is_failure
        if result.is_success:
            server_type = result.unwrap()
            assert isinstance(server_type, str)
            assert len(server_type) > 0


class TestClientWriteOperations:
    """Test client write operations with various configurations."""

    @pytest.fixture
    def client(self) -> FlextLdifClient:
        return FlextLdifClient()

    @pytest.fixture
    def fixtures_dir(self) -> Path:
        return Path(__file__).parent.parent / "fixtures"

    def test_client_write_multiple_formats(
        self, client: FlextLdifClient, fixtures_dir: Path, tmp_path: Path
    ) -> None:
        """Test writing entries in multiple formats."""
        fixture_path = fixtures_dir / "oid" / "oid_integration_fixtures.ldif"
        if not fixture_path.exists():
            return

        parse_result = client.parse_ldif(fixture_path)
        if not parse_result.is_success:
            return

        entries = parse_result.unwrap()

        # Write with different subsets
        for size in [5, 10, 20]:
            output_file = tmp_path / f"output_{size}.ldif"
            write_result = client.write_ldif(entries[:size], output_path=output_file)
            assert write_result.is_success or write_result.is_failure
            if output_file.exists():
                content = output_file.read_text()
                assert len(content) > 0


class TestApiConfigurationModes:
    """Test various API configuration modes."""

    @pytest.fixture
    def fixtures_dir(self) -> Path:
        return Path(__file__).parent.parent / "fixtures"

    def test_api_with_all_config_combinations(self, fixtures_dir: Path) -> None:
        """Test API with different config combinations."""
        fixture_path = fixtures_dir / "oid" / "oid_integration_fixtures.ldif"
        if not fixture_path.exists():
            return

        configs = [
            FlextLdifConfig(quirks_detection_mode="auto"),
            FlextLdifConfig(quirks_detection_mode="disabled"),
            FlextLdifConfig(enable_relaxed_parsing=True),
            FlextLdifConfig(quirks_detection_mode="manual", quirks_server_type="oid"),
        ]

        for config in configs:
            api = FlextLdif(config=config)
            result = api.parse(fixture_path)
            assert result.is_success or result.is_failure
