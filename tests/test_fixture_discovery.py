"""Test fixture discovery and validation system.

Demonstrates the comprehensive fixture infrastructure working with
real LDIF fixtures and expected results.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextLogger

from flext_ldif import FlextLdif

from .fixtures.validator import FlextLdifFixtureDiscovery

logger = FlextLogger(__name__)


class TestFixtureDiscovery:
    """Test comprehensive fixture discovery system."""

    def test_discover_all_fixtures(self) -> None:
        """Test discovery of all fixtures in system."""
        discovery = FlextLdifFixtureDiscovery()
        fixtures = discovery.discover_all()

        assert len(fixtures) > 0, "Should discover at least one fixture"

        # Verify we have fixtures from all categories
        categories = {f.category for f in fixtures}
        assert "rfc" in categories, "Should have RFC fixtures"
        assert "servers" in categories, "Should have server-specific fixtures"

    def test_discover_rfc_fixtures(self) -> None:
        """Test discovery of RFC-compliant fixtures."""
        discovery = FlextLdifFixtureDiscovery()
        rfc_fixtures = discovery.discover_category("rfc")

        assert len(rfc_fixtures) > 0, "Should discover RFC fixtures"

        # Check for specific RFC fixtures
        fixture_names = {f.fixture_name for f in rfc_fixtures}
        assert "rfc2849_simple_entry" in fixture_names
        assert "rfc2849_multivalue_long" in fixture_names

    def test_discover_server_fixtures(self) -> None:
        """Test discovery of server-specific fixtures."""
        discovery = FlextLdifFixtureDiscovery()
        server_fixtures = discovery.discover_category("servers")

        assert len(server_fixtures) > 0, "Should discover server fixtures"

        # Check for all server types
        servers = {f.server_type for f in server_fixtures}
        assert "oid" in servers, "Should have OID fixtures"
        assert "oud" in servers, "Should have OUD fixtures"
        assert "openldap" in servers, "Should have OpenLDAP fixtures"

    def test_discover_edge_cases(self) -> None:
        """Test discovery of edge case fixtures."""
        discovery = FlextLdifFixtureDiscovery()
        edge_fixtures = discovery.discover_category("edge_cases")

        assert len(edge_fixtures) > 0, "Should discover edge case fixtures"

    def test_fixture_metadata(self) -> None:
        """Test fixture metadata extraction."""
        discovery = FlextLdifFixtureDiscovery()
        metadata = discovery.get_metadata("rfc2849_simple_entry")

        assert metadata is not None, "Should find rfc2849_simple_entry fixture"
        assert metadata.fixture_name == "rfc2849_simple_entry"
        assert metadata.category == "rfc"
        assert metadata.subcategory == "valid"
        assert metadata.has_expected, "Should have expected results"
        assert metadata.file_size > 0
        assert metadata.line_count > 0

    def test_load_expected_results(self) -> None:
        """Test loading expected results from JSON."""
        discovery = FlextLdifFixtureDiscovery()
        metadata = discovery.get_metadata("rfc2849_simple_entry")

        assert metadata is not None
        expected = discovery.load_expected_results(metadata)

        assert expected is not None, "Should load expected results"
        assert "entries" in expected
        assert expected["count"] == 1
        assert "valid" in expected

    def test_fixture_parsing_with_expected_comparison(self) -> None:
        """Test fixture parsing and comparison with expected results."""
        discovery = FlextLdifFixtureDiscovery()
        metadata = discovery.get_metadata("rfc2849_simple_entry")

        assert metadata is not None, "Should find fixture"

        # Load expected results
        expected = discovery.load_expected_results(metadata)
        assert expected is not None, "Should load expected results"

        # Parse LDIF fixture
        ldif = FlextLdif()
        content = metadata.fixture_path.read_text(encoding="utf-8")
        parse_result = ldif.parse(content)

        assert parse_result.is_success, f"Parse should succeed: {parse_result.error}"
        parsed_entries = parse_result.unwrap()

        # Verify entry count matches
        assert len(parsed_entries) == expected.get("count", 0), (
            "Entry count should match"
        )

        # Compare using validator's comparison method
        comparison = discovery.compare_results({"entries": parsed_entries}, expected)

        assert comparison is not None, "Comparison should return results"
        logger.info("Fixture parsing comparison result: %s", comparison)

    def test_multivalue_fixture(self) -> None:
        """Test multivalue attribute fixture."""
        discovery = FlextLdifFixtureDiscovery()
        metadata = discovery.get_metadata("rfc2849_multivalue_long")

        assert metadata is not None, "Should find multivalue fixture"
        assert metadata.has_expected

        # Load and verify expected results
        expected = discovery.load_expected_results(metadata)
        assert expected is not None
        assert expected["count"] == 1

        # Verify multivalue attributes
        entry = expected["entries"][0]
        assert len(entry["attributes"]["mail"]) > 1

    def test_changetype_fixtures(self) -> None:
        """Test LDIF changetype fixtures (modify, delete, modrdn)."""
        discovery = FlextLdifFixtureDiscovery()

        # Test modify changetype
        modify_metadata = discovery.get_metadata("rfc2849_changetype_modify")
        assert modify_metadata is not None
        assert modify_metadata.fixture_type == "modify"

        # Test delete changetype
        delete_metadata = discovery.get_metadata("rfc2849_changetype_delete")
        assert delete_metadata is not None
        assert delete_metadata.fixture_type == "delete"

        # Test modrdn changetype
        modrdn_metadata = discovery.get_metadata("rfc2849_changetype_modrdn")
        assert modrdn_metadata is not None
        assert modrdn_metadata.fixture_type == "modrdn"

    def test_server_specific_fixtures(self) -> None:
        """Test server-specific fixtures."""
        discovery = FlextLdifFixtureDiscovery()

        # Test OID fixture
        oid_metadata = discovery.get_metadata("oracle_oid_acl")
        assert oid_metadata is not None
        assert oid_metadata.server_type == "oid"
        oid_expected = discovery.load_expected_results(oid_metadata)
        assert oid_expected is not None
        assert oid_expected["server_type"] == "oid"

        # Test OUD fixture
        oud_metadata = discovery.get_metadata("oracle_oud_sync")
        assert oud_metadata is not None
        assert oud_metadata.server_type == "oud"
        oud_expected = discovery.load_expected_results(oud_metadata)
        assert oud_expected is not None
        assert oud_expected["server_type"] == "oud"

        # Test OpenLDAP fixture
        openldap_metadata = discovery.get_metadata("openldap2_config")
        assert openldap_metadata is not None
        assert openldap_metadata.server_type == "openldap"

    def test_edge_case_fixtures(self) -> None:
        """Test edge case fixtures."""
        discovery = FlextLdifFixtureDiscovery()

        # Test deep DN fixture
        deep_metadata = discovery.get_metadata("deep_dn")
        assert deep_metadata is not None
        deep_expected = discovery.load_expected_results(deep_metadata)
        assert deep_expected is not None
        assert deep_expected["entries"][0]["dn_depth"] == 12

        # Test large multivalue fixture
        large_metadata = discovery.get_metadata("large_multivalue")
        assert large_metadata is not None
        large_expected = discovery.load_expected_results(large_metadata)
        assert large_expected is not None

        # Test unicode fixture
        unicode_metadata = discovery.get_metadata("unicode_names")
        assert unicode_metadata is not None
        unicode_expected = discovery.load_expected_results(unicode_metadata)
        assert unicode_expected is not None
        assert unicode_expected["count"] == 3

    def test_broken_fixtures(self) -> None:
        """Test broken/error case fixtures."""
        discovery = FlextLdifFixtureDiscovery()

        incomplete_metadata = discovery.get_metadata("incomplete_entry")
        assert incomplete_metadata is not None
        incomplete_expected = discovery.load_expected_results(incomplete_metadata)
        assert incomplete_expected is not None
        assert not incomplete_expected["valid"], "Should be marked as invalid"
        assert "relaxed_mode" in incomplete_expected


if __name__ == "__main__":
    import sys

    test = TestFixtureDiscovery()

    tests = [
        ("discover_all_fixtures", test.test_discover_all_fixtures),
        ("discover_rfc_fixtures", test.test_discover_rfc_fixtures),
        ("discover_server_fixtures", test.test_discover_server_fixtures),
        ("discover_edge_cases", test.test_discover_edge_cases),
        ("fixture_metadata", test.test_fixture_metadata),
        ("load_expected_results", test.test_load_expected_results),
        (
            "fixture_parsing_with_expected_comparison",
            test.test_fixture_parsing_with_expected_comparison,
        ),
        ("multivalue_fixture", test.test_multivalue_fixture),
        ("changetype_fixtures", test.test_changetype_fixtures),
        ("server_specific_fixtures", test.test_server_specific_fixtures),
        ("edge_case_fixtures", test.test_edge_case_fixtures),
        ("broken_fixtures", test.test_broken_fixtures),
    ]

    passed = 0
    failed = 0

    for _test_name, test_func in tests:
        try:
            test_func()
            passed += 1
        except AssertionError:
            failed += 1
        except (ValueError, TypeError, AttributeError):
            failed += 1

    sys.exit(0 if failed == 0 else 1)
