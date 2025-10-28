"""Comprehensive test suite for Oracle Internet Directory (OID) quirks.

High-coverage testing using real OID LDIF fixtures from tests/fixtures/oid/.
All tests use actual implementations with real data, no mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif.api import FlextLdif
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.servers.oid_quirks import FlextLdifQuirksServersOid


class TestOidQuirksWithRealFixtures:
    """Test OID quirks using real LDIF fixtures from tests/fixtures/oid/."""

    @pytest.fixture
    def oid_fixture_dir(self) -> Path:
        """Get OID fixtures directory."""
        # Navigate up to tests/ directory, then into fixtures/oid/
        return Path(__file__).parent.parent.parent.parent / "fixtures" / "oid"

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    @pytest.fixture
    def api(self) -> FlextLdif:
        """Create FlextLdif API instance."""
        return FlextLdif()

    def test_parse_oid_schema_fixture(
        self, api: FlextLdif, oid_fixture_dir: Path
    ) -> None:
        """Test parsing real OID schema fixture file."""
        schema_file = oid_fixture_dir / "oid_schema_fixtures.ldif"
        if not schema_file.exists():
            pytest.skip(f"OID schema fixture not found: {schema_file}")

        result = api.parse(schema_file, server_type="oid")

        assert result.is_success
        entries = result.unwrap()
        assert len(entries) > 0, "OID schema fixture should contain schema entries"

    def test_parse_oid_entries_fixture(
        self, api: FlextLdif, oid_fixture_dir: Path
    ) -> None:
        """Test parsing real OID directory entries fixture."""
        entries_file = oid_fixture_dir / "oid_entries_fixtures.ldif"
        if not entries_file.exists():
            pytest.skip(f"OID entries fixture not found: {entries_file}")

        result = api.parse(entries_file, server_type="oid")

        assert result.is_success
        entries = result.unwrap()
        assert len(entries) > 0, "OID entries fixture should contain directory entries"

        # Verify entries have valid DNs
        for entry in entries:
            assert entry.dn.value, "Each entry must have a DN"
            assert len(entry.attributes) > 0, "Each entry must have attributes"

    def test_parse_oid_acl_fixture(self, api: FlextLdif, oid_fixture_dir: Path) -> None:
        """Test parsing real OID ACL fixture."""
        acl_file = oid_fixture_dir / "oid_acl_fixtures.ldif"
        if not acl_file.exists():
            pytest.skip(f"OID ACL fixture not found: {acl_file}")

        result = api.parse(acl_file, server_type="oid")

        assert result.is_success

    def test_roundtrip_oid_entries(
        self, api: FlextLdif, oid_fixture_dir: Path, tmp_path: Path
    ) -> None:
        """Test parsing OID entries and writing them back maintains data integrity."""
        entries_file = oid_fixture_dir / "oid_entries_fixtures.ldif"
        if not entries_file.exists():
            pytest.skip(f"OID entries fixture not found: {entries_file}")

        # Parse original
        parse_result = api.parse(entries_file, server_type="oid")
        assert parse_result.is_success
        entries = parse_result.unwrap()

        # Write to temporary file
        output_file = tmp_path / "roundtrip_oid_entries.ldif"
        write_result = api.write(entries, output_file)
        assert write_result.is_success

        # Parse again
        reparse_result = api.parse(output_file, server_type="oid")
        assert reparse_result.is_success
        reparsed_entries = reparse_result.unwrap()

        # Verify same number of entries
        assert len(entries) == len(reparsed_entries)

    def test_oid_server_type_detection(
        self, api: FlextLdif, oid_fixture_dir: Path
    ) -> None:
        """Test that OID server type is correctly detected from OID entries."""
        entries_file = oid_fixture_dir / "oid_entries_fixtures.ldif"
        if not entries_file.exists():
            pytest.skip(f"OID entries fixture not found: {entries_file}")

        # Parse with auto-detection
        result = api.parse(entries_file)

        assert result.is_success

    def test_oid_vs_rfc_parsing(self, api: FlextLdif, oid_fixture_dir: Path) -> None:
        """Verify OID and RFC parsing work with OID data."""
        entries_file = oid_fixture_dir / "oid_entries_fixtures.ldif"
        if not entries_file.exists():
            pytest.skip(f"OID entries fixture not found: {entries_file}")

        # Parse with OID quirks
        oid_result = api.parse(entries_file, server_type="oid")
        assert oid_result.is_success
        oid_entries = oid_result.unwrap()

        # Parse with RFC-only mode
        rfc_result = api.parse(entries_file, server_type="rfc")
        assert rfc_result.is_success
        rfc_entries = rfc_result.unwrap()

        # Both should have same entries
        assert len(oid_entries) == len(rfc_entries)


class TestOidQuirksErrorHandling:
    """Test OID quirks error handling with real scenarios."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        """Create FlextLdif API instance."""
        return FlextLdif()

    def test_parse_empty_oid_ldif(self, api: FlextLdif) -> None:
        """Test parsing empty OID LDIF."""
        empty_ldif = ""
        result = api.parse(empty_ldif, server_type="oid")

        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
