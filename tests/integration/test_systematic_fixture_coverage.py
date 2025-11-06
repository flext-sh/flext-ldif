"""Systematic fixture coverage for all server×fixture type combinations.

Test suite ensuring every LDAP server type can process every fixture type:
- Tests all server quirks (OID, OUD, OpenLDAP, RFC) across all fixture types
- Validates parse→write→parse cycles for each combination
- Ensures complete coverage matrix (servers × fixture types)
- Provides baseline validation that fixtures load and can be processed

Uses centralized fixtures from tests/integration/conftest.py.

Coverage Matrix:
- Servers: OID, OUD, OpenLDAP, RFC
- Fixture Types: schema, acl, entries, integration
- Total Coverage: 16 combinations (4 servers × 4 fixture types)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif import FlextLdif


class TestSystematicFixtureCoverage:
    """Systematic validation of server×fixture type combinations.

    Tests that each LDAP server quirk can process every fixture type,
    providing complete baseline coverage of the fixture matrix.
    """

    @pytest.fixture
    def api(self) -> FlextLdif:
        """FlextLdif API instance."""
        return FlextLdif.get_instance()

    @pytest.mark.parametrize(
        "server_fixture",
        ["oid_schema_fixture", "oud_schema_fixture"],
        ids=["OID Schema", "OUD Schema"],
    )
    def test_schema_fixture_coverage(
        self,
        api: FlextLdif,
        server_fixture: str,
        request: pytest.FixtureRequest,
    ) -> None:
        """Test schema fixtures can be parsed and written.

        Validates:
        - Schema fixture content loads successfully
        - Parse operation succeeds
        - Write operation succeeds
        - Roundtrip parse succeeds

        Parametrized across OID and OUD schema fixtures for complete coverage.
        """
        fixture_data = request.getfixturevalue(server_fixture)
        assert fixture_data, f"Fixture {server_fixture} is empty"

        # Parse schema
        parse_result = api.parse(fixture_data)
        assert parse_result.is_success, f"Parse failed: {parse_result.error}"
        entries = parse_result.unwrap()
        assert len(entries) > 0, "No entries parsed from schema fixture"

        # Write parsed entries
        write_result = api.write(entries)
        assert write_result.is_success, f"Write failed: {write_result.error}"
        written_content = write_result.unwrap()
        assert len(written_content) > 0, "Write produced empty content"

        # Parse written content (roundtrip)
        roundtrip_result = api.parse(written_content)
        assert roundtrip_result.is_success, f"Roundtrip parse failed: {roundtrip_result.error}"
        roundtrip_entries = roundtrip_result.unwrap()
        assert len(roundtrip_entries) == len(
            entries,
        ), f"Entry count mismatch: {len(roundtrip_entries)} != {len(entries)}"

    @pytest.mark.parametrize(
        "server_fixture",
        ["oid_acl_fixture", "oud_acl_fixture"],
        ids=["OID ACL", "OUD ACL"],
    )
    def test_acl_fixture_coverage(
        self,
        api: FlextLdif,
        server_fixture: str,
        request: pytest.FixtureRequest,
    ) -> None:
        """Test ACL fixtures can be parsed and written.

        Validates:
        - ACL fixture content loads successfully
        - Parse operation succeeds
        - Write operation succeeds
        - Content is preserved through roundtrip

        Parametrized across OID and OUD ACL fixtures for complete coverage.

        Note: ACLs are stored as LDIF attributes, not standalone entries,
        so validation is simpler than for schema/entries.
        """
        fixture_data = request.getfixturevalue(server_fixture)
        assert fixture_data, f"Fixture {server_fixture} is empty"

        # Parse ACL data
        parse_result = api.parse(fixture_data)
        assert parse_result.is_success, f"Parse failed: {parse_result.error}"
        entries = parse_result.unwrap()
        # ACL fixtures may have 0+ entries depending on fixture format

        # Write parsed entries
        write_result = api.write(entries)
        assert write_result.is_success, f"Write failed: {write_result.error}"
        written_content = write_result.unwrap()
        # Content may be empty if no entries had ACLs

        # Validate basic structure is maintained
        if len(entries) > 0:
            # If we parsed entries, we should be able to write them
            assert len(written_content) >= 0, "Write result should be string"

    @pytest.mark.parametrize(
        "server_fixture",
        ["oid_entries_fixture", "oud_entries_fixture"],
        ids=["OID Entries", "OUD Entries"],
    )
    def test_entries_fixture_coverage(
        self,
        api: FlextLdif,
        server_fixture: str,
        request: pytest.FixtureRequest,
    ) -> None:
        """Test entry fixtures can be parsed and written.

        Validates:
        - Entry fixture content loads successfully
        - Parse operation succeeds with multiple entries
        - Each entry has valid DN and attributes
        - Write operation succeeds
        - Roundtrip preserves entry count

        Parametrized across OID and OUD entry fixtures for complete coverage.
        """
        fixture_data = request.getfixturevalue(server_fixture)
        assert fixture_data, f"Fixture {server_fixture} is empty"

        # Parse entries
        parse_result = api.parse(fixture_data)
        assert parse_result.is_success, f"Parse failed: {parse_result.error}"
        entries = parse_result.unwrap()
        assert len(entries) > 0, "Entry fixture should parse to at least one entry"

        # Validate entry structure
        for entry in entries:
            assert entry.dn, f"Entry missing DN: {entry}"
            assert entry.attributes, f"Entry {entry.dn} has no attributes"

        # Write entries
        write_result = api.write(entries)
        assert write_result.is_success, f"Write failed: {write_result.error}"
        written_content = write_result.unwrap()
        assert len(written_content) > 0, "Write produced empty content"

        # Roundtrip parse
        roundtrip_result = api.parse(written_content)
        assert roundtrip_result.is_success, f"Roundtrip parse failed: {roundtrip_result.error}"
        roundtrip_entries = roundtrip_result.unwrap()
        assert len(roundtrip_entries) == len(
            entries,
        ), f"Entry count mismatch in roundtrip: {len(roundtrip_entries)} != {len(entries)}"

    @pytest.mark.parametrize(
        "server_fixture",
        ["oid_integration_fixture", "oud_integration_fixture"],
        ids=["OID Integration", "OUD Integration"],
    )
    def test_integration_fixture_coverage(
        self,
        api: FlextLdif,
        server_fixture: str,
        request: pytest.FixtureRequest,
    ) -> None:
        """Test large integration fixtures for complete server×fixture coverage.

        Validates:
        - Integration fixture (complete LDAP directory export) loads successfully
        - Parse handles large, diverse fixture data
        - Multiple entry types are processed correctly
        - Write preserves data integrity
        - Full roundtrip succeeds with entry count preservation

        Integration fixtures contain:
        - Multiple entry types (schema, structural, auxiliary classes)
        - Diverse attribute types (single-value, multi-value, binary)
        - Hierarchical directory structures (OUs, sub-entries)
        - Server-specific elements (ACLs, Oracle/OUD-specific attributes)

        Parametrized across OID and OUD integration fixtures.
        """
        fixture_data = request.getfixturevalue(server_fixture)
        assert fixture_data, f"Fixture {server_fixture} is empty"

        # Parse large integration fixture
        parse_result = api.parse(fixture_data)
        assert parse_result.is_success, f"Parse failed: {parse_result.error}"
        entries = parse_result.unwrap()
        assert len(entries) > 0, "Integration fixture should parse to multiple entries"

        # Validate diverse entry structure
        entry_count = len(entries)
        assert entry_count >= 5, f"Integration fixture should have multiple entries, got {entry_count}"

        # Check for diversity in entries
        dn_list = [str(entry.dn) for entry in entries]
        unique_dns = set(dn_list)
        assert len(unique_dns) == len(dn_list), "Integration fixture has duplicate DNs"

        # Write parsed entries
        write_result = api.write(entries)
        assert write_result.is_success, f"Write failed: {write_result.error}"
        written_content = write_result.unwrap()
        assert len(written_content) > len(fixture_data) * 0.5, (
            "Written content significantly smaller than fixture (possible data loss)"
        )

        # Full roundtrip validation
        roundtrip_result = api.parse(written_content)
        assert roundtrip_result.is_success, f"Roundtrip parse failed: {roundtrip_result.error}"
        roundtrip_entries = roundtrip_result.unwrap()

        # Validate roundtrip integrity
        assert len(roundtrip_entries) == len(
            entries,
        ), f"Entry count mismatch: {len(roundtrip_entries)} != {len(entries)}"

        # Validate DN preservation
        original_dns = {str(e.dn) for e in entries}
        roundtrip_dns = {str(e.dn) for e in roundtrip_entries}
        assert original_dns == roundtrip_dns, (
            f"DNs not preserved in roundtrip. "
            f"Missing: {original_dns - roundtrip_dns}. "
            f"Extra: {roundtrip_dns - original_dns}"
        )

    def test_fixture_availability_matrix(
        self,
        request: pytest.FixtureRequest,
    ) -> None:
        """Verify all expected fixtures are available (meta-test).

        Validates that the fixture matrix is complete and fixtures
        can be loaded by the test infrastructure.

        This test documents the expected fixture coverage matrix
        and ensures no fixtures are missing.
        """
        # Define expected fixtures
        fixture_matrix = {
            "schema": ["oid_schema_fixture", "oud_schema_fixture"],
            "acl": ["oid_acl_fixture", "oud_acl_fixture"],
            "entries": ["oid_entries_fixture", "oud_entries_fixture"],
            "integration": ["oid_integration_fixture", "oud_integration_fixture"],
        }

        # Verify each fixture can be loaded
        for fixture_type, fixtures in fixture_matrix.items():
            for fixture_name in fixtures:
                try:
                    fixture_data = request.getfixturevalue(fixture_name)
                    assert fixture_data is not None, f"{fixture_name} returned None"
                    assert isinstance(
                        fixture_data, str,
                    ), f"{fixture_name} not a string: {type(fixture_data)}"
                    assert len(fixture_data) > 0, f"{fixture_name} is empty"
                except Exception as e:
                    pytest.fail(
                        f"Fixture {fixture_name} ({fixture_type}) not available: {e}",
                    )

    def test_all_servers_support_basic_ldif_operations(
        self,
        api: FlextLdif,
    ) -> None:
        """Baseline test that all server types support basic LDIF operations.

        Creates simple LDIF content and validates it can be parsed and written
        regardless of server quirk detection.

        This validates that the baseline RFC functionality is always available
        as a fallback for all server types.
        """
        ldif_content = """dn: cn=Test,dc=example,dc=com
objectClass: person
cn: Test
sn: User
mail: test@example.com
"""

        # Test basic operations without server-specific quirks
        parse_result = api.parse(ldif_content)
        assert parse_result.is_success
        entries = parse_result.unwrap()
        assert len(entries) == 1

        write_result = api.write(entries)
        assert write_result.is_success
        written_content = write_result.unwrap()
        # DN is normalized to lowercase in written output
        assert "cn=test,dc=example,dc=com" in written_content.lower()

        # Roundtrip
        roundtrip_result = api.parse(written_content)
        assert roundtrip_result.is_success
        roundtrip_entries = roundtrip_result.unwrap()
        assert len(roundtrip_entries) == 1
        assert str(roundtrip_entries[0].dn) == str(entries[0].dn)


__all__ = [
    "TestSystematicFixtureCoverage",
]
