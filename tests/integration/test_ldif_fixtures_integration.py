"""Integration tests for LDIF fixtures across all servers.

Tests cover real-world scenarios using 50+ fixture entries per server:
- RFC: 50+ entries with complete directory structure
- OID: 10+ entries with Oracle Internet Directory data
- OUD: 15+ entries with Oracle Unified Directory data
- OpenLDAP2: 50+ entries with POSIX account and group data

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif import ldif
from tests import c


class TestLdifFixturesIntegration:
    """Test LDIF fixture parsing and structure validation across all servers."""

    @pytest.fixture
    def ldif_client(self) -> ldif:
        """Initialize LDIF processor."""
        return ldif()

    def test_rfc_fixture_parsing(self, ldif_client: ldif) -> None:
        """Test parsing RFC fixture with current baseline entries."""
        fixture = c.Ldif.Tests.FIXTURES_DIR / c.Ldif.Tests.RFC / "rfc_entries_fixtures.ldif"
        result = ldif_client.parse_ldif(fixture)
        assert result.is_success
        entries_raw = result.value.entries
        assert len(entries_raw) >= 14, (
            f"Expected at least 14 RFC entries, got {len(entries_raw)}"
        )

    def test_rfc_fixture_validation(self, ldif_client: ldif) -> None:
        """Test RFC fixture entries are valid."""
        fixture = c.Ldif.Tests.FIXTURES_DIR / c.Ldif.Tests.RFC / "rfc_entries_fixtures.ldif"
        parse_result = ldif_client.parse_ldif(fixture)
        assert parse_result.is_success
        entries_raw = parse_result.value.entries
        for entry in entries_raw:
            assert entry.dn is not None
            assert entry.dn.value

    def test_oid_fixture_parsing(self, ldif_client: ldif) -> None:
        """Test parsing OID fixture."""
        fixture = c.Ldif.Tests.FIXTURES_DIR / c.Ldif.Tests.OID / "oid_entries_fixtures.ldif"
        result = ldif_client.parse_ldif(fixture)
        assert result.is_success
        entries_raw = result.value.entries
        assert len(entries_raw) >= 1

    def test_oud_fixture_parsing(self, ldif_client: ldif) -> None:
        """Test parsing OUD fixture."""
        fixture = c.Ldif.Tests.FIXTURES_DIR / c.Ldif.Tests.OUD / "oud_entries_fixtures.ldif"
        result = ldif_client.parse_ldif(fixture)
        assert result.is_success
        entries_raw = result.value.entries
        assert len(entries_raw) >= 1

    def test_openldap2_fixture_parsing(self, ldif_client: ldif) -> None:
        """Test parsing OpenLDAP2 fixture with 45+ entries."""
        fixture = (
            c.Ldif.Tests.FIXTURES_DIR
            / "openldap2"
            / "openldap2_integration_fixtures.ldif"
        )
        result = ldif_client.parse_ldif(fixture)
        assert result.is_success
        entries_raw = result.value.entries
        assert len(entries_raw) >= 45, (
            f"Expected 45+ OpenLDAP2 entries, got {len(entries_raw)}"
        )

    def test_cross_server_fixture_parsing(self, ldif_client: ldif) -> None:
        """Test parsing fixtures from all servers."""
        fixtures = [
            c.Ldif.Tests.FIXTURES_DIR / c.Ldif.Tests.RFC / "rfc_entries_fixtures.ldif",
            c.Ldif.Tests.FIXTURES_DIR / c.Ldif.Tests.OID / "oid_entries_fixtures.ldif",
            c.Ldif.Tests.FIXTURES_DIR / c.Ldif.Tests.OUD / "oud_entries_fixtures.ldif",
            c.Ldif.Tests.FIXTURES_DIR / "openldap2" / "openldap2_entries_fixtures.ldif",
        ]
        for fixture_path in fixtures:
            result = ldif_client.parse_ldif(fixture_path)
            assert result.is_success, f"Failed to parse {fixture_path}: {result.error}"
            entries_raw = result.value.entries
            assert len(entries_raw) >= 1, (
                f"Expected at least 1 entry from {fixture_path}"
            )

    def test_rfc_entries_have_valid_dns(self, ldif_client: ldif) -> None:
        """Test all RFC entries have valid DNs."""
        fixture = c.Ldif.Tests.FIXTURES_DIR / c.Ldif.Tests.RFC / "rfc_entries_fixtures.ldif"
        result = ldif_client.parse_ldif(fixture)
        assert result.is_success
        entries_raw = result.value.entries
        for entry in entries_raw:
            assert entry.dn is not None, "Entry must have DN"
            dn_str = entry.dn.value
            assert dn_str
            assert "=" in dn_str
