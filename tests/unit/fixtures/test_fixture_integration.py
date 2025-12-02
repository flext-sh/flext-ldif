"""Integration tests for LDIF fixtures across all servers.

Tests cover real-world scenarios using 50+ fixture entries per server:
- RFC: 50+ entries with complete directory structure
- OID: 10+ entries with Oracle Internet Directory data
- OUD: 15+ entries with Oracle Unified Directory data
- OpenLDAP2: 50+ entries with POSIX account and group data
"""

from pathlib import Path

import pytest

from flext_ldif import FlextLdif


class TestFixturesParsing:
    """Test LDIF fixture parsing across all servers."""

    @pytest.fixture
    def ldif(self) -> FlextLdif:
        """Initialize LDIF processor."""
        return FlextLdif()

    def test_rfc_fixture_parsing(self, ldif: FlextLdif) -> None:
        """Test parsing RFC fixture with 45+ entries."""
        fixture = Path("tests/fixtures/rfc/rfc_entries_fixtures.ldif")
        result = ldif.parse(fixture)
        assert result.is_success
        entries_raw = result.unwrap()
        assert isinstance(entries_raw, list)
        assert len(entries_raw) >= 45, (
            f"Expected 45+ RFC entries, got {len(entries_raw)}"
        )

    def test_rfc_fixture_validation(self, ldif: FlextLdif) -> None:
        """Test RFC fixture entries are valid."""
        fixture = Path("tests/fixtures/rfc/rfc_entries_fixtures.ldif")
        parse_result = ldif.parse(fixture)
        assert parse_result.is_success

        entries_raw = parse_result.unwrap()
        assert isinstance(entries_raw, list)
        for entry in entries_raw:
            assert entry.dn is not None
            assert len(entry.dn.value) > 0

    def test_oid_fixture_parsing(self, ldif: FlextLdif) -> None:
        """Test parsing OID fixture."""
        fixture = Path("tests/fixtures/oid/oid_entries_fixtures.ldif")
        result = ldif.parse(fixture)
        assert result.is_success
        entries_raw = result.unwrap()
        assert isinstance(entries_raw, list)
        assert len(entries_raw) >= 1

    def test_oud_fixture_parsing(self, ldif: FlextLdif) -> None:
        """Test parsing OUD fixture."""
        fixture = Path("tests/fixtures/oud/oud_entries_fixtures.ldif")
        result = ldif.parse(fixture)
        assert result.is_success
        entries_raw = result.unwrap()
        assert isinstance(entries_raw, list)
        assert len(entries_raw) >= 1

    def test_openldap2_fixture_parsing(self, ldif: FlextLdif) -> None:
        """Test parsing OpenLDAP2 fixture with 45+ entries."""
        fixture = Path("tests/fixtures/openldap2/openldap2_entries_fixtures.ldif")
        result = ldif.parse(fixture)
        assert result.is_success
        entries_raw = result.unwrap()
        assert isinstance(entries_raw, list)
        assert len(entries_raw) >= 45, (
            f"Expected 45+ OpenLDAP2 entries, got {len(entries_raw)}"
        )

    def test_cross_server_fixture_parsing(self, ldif: FlextLdif) -> None:
        """Test parsing fixtures from all servers."""
        fixtures = [
            "tests/fixtures/rfc/rfc_entries_fixtures.ldif",
            "tests/fixtures/oid/oid_entries_fixtures.ldif",
            "tests/fixtures/oud/oud_entries_fixtures.ldif",
            "tests/fixtures/openldap2/openldap2_entries_fixtures.ldif",
        ]

        for fixture_path in fixtures:
            result = ldif.parse(Path(fixture_path))
            assert result.is_success, f"Failed to parse {fixture_path}: {result.error}"
            entries_raw = result.unwrap()
            assert isinstance(entries_raw, list)
            assert len(entries_raw) >= 1, (
                f"Expected at least 1 entry from {fixture_path}"
            )


class TestFixturesStructure:
    """Test structure and consistency of fixtures."""

    @pytest.fixture
    def ldif(self) -> FlextLdif:
        """Initialize LDIF processor."""
        return FlextLdif()

    def test_rfc_entries_have_valid_dns(self, ldif: FlextLdif) -> None:
        """Test all RFC entries have valid DNs."""
        fixture = Path("tests/fixtures/rfc/rfc_entries_fixtures.ldif")
        result = ldif.parse(fixture)
        assert result.is_success

        entries_raw = result.unwrap()
        assert isinstance(entries_raw, list)
        for entry in entries_raw:
            # DN should follow RFC 4514 format
            assert entry.dn is not None, "Entry must have DN"
            dn_str = entry.dn.value
            assert len(dn_str) > 0
            # Should have at least one = for attribute=value
            assert "=" in dn_str

    def test_all_fixtures_have_objectclass(self, ldif: FlextLdif) -> None:
        """Test all entries in fixtures have objectClass."""
        fixtures = [
            "tests/fixtures/rfc/rfc_entries_fixtures.ldif",
            "tests/fixtures/oid/oid_entries_fixtures.ldif",
            "tests/fixtures/oud/oud_entries_fixtures.ldif",
            "tests/fixtures/openldap2/openldap2_entries_fixtures.ldif",
        ]

        for fixture_path in fixtures:
            result = ldif.parse(Path(fixture_path))
            assert result.is_success

            entries_raw = result.unwrap()
            assert isinstance(entries_raw, list)
            for entry in entries_raw:
                # Check for objectClass (case-insensitive)
                assert entry.attributes is not None, "Entry must have attributes"
                assert entry.dn is not None, "Entry must have DN"
                attrs = entry.attributes.attributes
                has_oc = any(attr.lower() == "objectclass" for attr in attrs)
                assert has_oc, f"Entry {entry.dn.value} missing objectClass"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
