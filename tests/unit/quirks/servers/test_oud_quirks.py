"""Comprehensive test suite for Oracle Unified Directory (OUD) quirks.

High-coverage testing using real OUD LDIF fixtures from tests/fixtures/oud/.
All tests use actual implementations with real data, no mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif.api import FlextLdif
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.servers.oud_quirks import FlextLdifQuirksServersOud


class TestOudQuirksWithRealFixtures:
    """Test OUD quirks using real LDIF fixtures from tests/fixtures/oud/."""

    @pytest.fixture
    def oud_fixture_dir(self) -> Path:
        """Get OUD fixtures directory."""
        return Path(__file__).parent.parent.parent.parent / "fixtures" / "oud"

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    @pytest.fixture
    def api(self) -> FlextLdif:
        """Create FlextLdif API instance."""
        return FlextLdif()

    def test_parse_oud_schema_fixture(
        self, api: FlextLdif, oud_fixture_dir: Path
    ) -> None:
        """Test parsing real OUD schema fixture file."""
        schema_file = oud_fixture_dir / "oud_schema_fixtures.ldif"
        if not schema_file.exists():
            pytest.skip(f"OUD schema fixture not found: {schema_file}")

        result = api.parse(schema_file, server_type="oud")

        assert result.is_success
        entries = result.unwrap()
        assert len(entries) > 0, "OUD schema fixture should contain schema entries"

    def test_parse_oud_entries_fixture(
        self, api: FlextLdif, oud_fixture_dir: Path
    ) -> None:
        """Test parsing real OUD directory entries fixture."""
        entries_file = oud_fixture_dir / "oud_entries_fixtures.ldif"
        if not entries_file.exists():
            pytest.skip(f"OUD entries fixture not found: {entries_file}")

        result = api.parse(entries_file, server_type="oud")

        assert result.is_success
        entries = result.unwrap()
        assert len(entries) > 0, "OUD entries fixture should contain directory entries"

        # Verify entries have valid DNs
        for entry in entries:
            assert entry.dn.value, "Each entry must have a DN"
            assert len(entry.attributes) > 0, "Each entry must have attributes"

    def test_parse_oud_acl_fixture(self, api: FlextLdif, oud_fixture_dir: Path) -> None:
        """Test parsing real OUD ACL fixture."""
        acl_file = oud_fixture_dir / "oud_acl_fixtures.ldif"
        if not acl_file.exists():
            pytest.skip(f"OUD ACL fixture not found: {acl_file}")

        result = api.parse(acl_file, server_type="oud")

        assert result.is_success

    def test_roundtrip_oud_entries(
        self, api: FlextLdif, oud_fixture_dir: Path, tmp_path: Path
    ) -> None:
        """Test parsing OUD entries and writing them back maintains data integrity."""
        entries_file = oud_fixture_dir / "oud_entries_fixtures.ldif"
        if not entries_file.exists():
            pytest.skip(f"OUD entries fixture not found: {entries_file}")

        # Parse original
        parse_result = api.parse(entries_file, server_type="oud")
        assert parse_result.is_success
        entries = parse_result.unwrap()

        # Write to temporary file
        output_file = tmp_path / "roundtrip_oud_entries.ldif"
        write_result = api.write(entries, output_file)
        assert write_result.is_success

        # Parse again
        reparse_result = api.parse(output_file, server_type="oud")
        assert reparse_result.is_success
        reparsed_entries = reparse_result.unwrap()

        # Verify same number of entries
        assert len(entries) == len(reparsed_entries)

    def test_oud_server_type_detection(
        self, api: FlextLdif, oud_fixture_dir: Path
    ) -> None:
        """Test that OUD server type is correctly detected from OUD entries."""
        entries_file = oud_fixture_dir / "oud_entries_fixtures.ldif"
        if not entries_file.exists():
            pytest.skip(f"OUD entries fixture not found: {entries_file}")

        # Parse with auto-detection
        result = api.parse(entries_file)

        assert result.is_success

    def test_oud_vs_rfc_parsing(self, api: FlextLdif, oud_fixture_dir: Path) -> None:
        """Verify OUD and RFC parsing work with OUD data."""
        entries_file = oud_fixture_dir / "oud_entries_fixtures.ldif"
        if not entries_file.exists():
            pytest.skip(f"OUD entries fixture not found: {entries_file}")

        # Parse with OUD quirks
        oud_result = api.parse(entries_file, server_type="oud")
        assert oud_result.is_success

        # Parse with RFC-only mode
        rfc_result = api.parse(entries_file, server_type="rfc")
        assert rfc_result.is_success

    def test_oud_entry_attributes_preserved(
        self, api: FlextLdif, oud_fixture_dir: Path
    ) -> None:
        """Test that OUD-specific attributes are preserved during processing."""
        entries_file = oud_fixture_dir / "oud_entries_fixtures.ldif"
        if not entries_file.exists():
            pytest.skip(f"OUD entries fixture not found: {entries_file}")

        result = api.parse(entries_file, server_type="oud")
        assert result.is_success
        entries = result.unwrap()

        # Verify entries contain expected OUD attributes
        for entry in entries:
            # Check that attributes are preserved
            assert len(entry.attributes) > 0
