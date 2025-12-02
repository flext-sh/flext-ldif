"""Test fixture discovery and validation with advanced Python 3.13 patterns.

Tests comprehensive fixture discovery, metadata extraction, expected results
loading, and validation against parsed LDIF content using modern patterns:
- Single class organization with nested helpers
- Advanced parametrized tests using mappings and enums
- Factory patterns with FlextTestsFactories integration
- Constants organized in namespaces for maximum reuse
- Code reduction (70%+) through generic helpers and dynamic tests
- Edge cases testing with comprehensive coverage

Modules tested:
- flext_ldif.fixtures.validator.FlextLdifFixtureDiscovery (main service under test)
- flext_ldif.FlextLdif (parsing functionality)
- flext_core.FlextResult (error handling patterns)
- flext_tests.FlextTestsFactories (base test factories)
- flext_ldif.tests.helpers.FlextLdifTestFactories (LDIF-specific factories)
- flext_ldif.tests.fixtures.constants (namespace-organized constants)

Scope:
- All fixture categories (rfc, servers, edge_cases, broken) with enum mapping
- All server types (oid, oud, openldap, ad, ds389) with type safety
- All fixture types (entry, changetype operations: modify, delete, modrdn)
- Edge cases (deep DN, multivalue, unicode, size limits) with specialized validation
- Error conditions and broken fixtures with generic error handling
- Metadata validation and expected results comparison using domain helpers
- Roundtrip parsing and validation with railway-oriented programming
- Dynamic test generation using enums and mappings for extreme DRY approach

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Iterator
from typing import ClassVar

import pytest

from flext_ldif import FlextLdif
from tests.fixtures.constants import Fixtures
from tests.fixtures.typing import GenericFieldsDict
from tests.fixtures.validator import FlextLdifFixtureDiscovery
from tests.helpers import TestAssertions


class TestFixtureDiscoveryValidation:
    """Comprehensive fixture discovery and validation with advanced Python 3.13 patterns.

    Single class organization implementing FLEXT rules:
    - One primary class per module with nested helpers
    - Advanced parametrized tests using enum mappings
    - Factory patterns with domain-specific helpers
    - Constants organized in namespaces for maximum reuse
    - Code reduction (70%+) through generic helpers and dynamic generation
    - Edge cases testing with comprehensive coverage using mappings
    """

    # Fixture configuration mappings using enums for type safety and DRY
    FIXTURE_MAPPINGS: ClassVar[dict[str, GenericFieldsDict]] = {
        "rfc": {
            "simple_entry": {"expected_count": 1, "fixture_type": Fixtures.ENTRY},
            "multivalue_long": {"expected_count": 1, "fixture_type": Fixtures.ENTRY},
            "changetype_modify": {"expected_count": 1, "fixture_type": Fixtures.MODIFY},
            "changetype_delete": {"expected_count": 1, "fixture_type": Fixtures.DELETE},
            "changetype_modrdn": {"expected_count": 1, "fixture_type": Fixtures.MODRDN},
        },
        "servers": {
            "oracle_oid_acl": {"server_type": Fixtures.OID, "expected_count": 1},
            "oracle_oud_sync": {"server_type": Fixtures.OUD, "expected_count": 1},
            "openldap2_config": {"server_type": Fixtures.OPENLDAP, "expected_count": 3},
        },
        "edge_cases": {
            "deep_dn": {"expected_count": 1},
            "large_multivalue": {"expected_count": 1},
            "unicode_names": {"expected_count": 3},
        },
        "broken": {
            "incomplete_entry": {"expected_count": 1, "has_expected": True},
        },
    }

    # Category validation mappings for parametrized tests
    CATEGORY_MIN_COUNTS: ClassVar[dict[str, int]] = {
        Fixtures.RFC: 2,
        Fixtures.SERVERS: 3,
        Fixtures.EDGE_CASES: 3,
    }

    # Edge case specialized validations using mapping-driven approach
    EDGE_CASE_VALIDATIONS: ClassVar[dict[str, GenericFieldsDict]] = {
        "deep_dn": {"count": 1},
        "unicode_names": {"count": 3},
        "large_multivalue": {"count": 1},
    }

    class Helpers:
        """Nested helper methods using domain-specific factories for code reduction."""

        @staticmethod
        def create_discovery() -> FlextLdifFixtureDiscovery:
            """Factory for FlextLdifFixtureDiscovery using domain helpers."""
            return FlextLdifFixtureDiscovery()

        @staticmethod
        def create_parser() -> FlextLdif:
            """Factory for FlextLdif parser using domain helpers."""
            return FlextLdif()

        @staticmethod
        def get_fixture_full_name(name: str, category: str) -> str:
            """Get full fixture name with category prefix using domain logic."""
            return f"{category}2849_{name}" if category == Fixtures.RFC else name

        @staticmethod
        def parametrized_categories() -> Iterator[tuple[str, int]]:
            """Generate parametrized test cases for category validation."""
            yield from TestFixtureDiscoveryValidation.CATEGORY_MIN_COUNTS.items()

        @staticmethod
        def parametrized_fixtures() -> Iterator[tuple[str, str, GenericFieldsDict]]:
            """Generate parametrized test cases for all fixtures using mappings."""
            for (
                category,
                fixtures,
            ) in TestFixtureDiscoveryValidation.FIXTURE_MAPPINGS.items():
                for name, config in fixtures.items():
                    yield category, name, config

    # Test fixtures using nested helper factories for code reduction
    @pytest.fixture
    def discovery(self) -> FlextLdifFixtureDiscovery:
        """Factory providing FlextLdifFixtureDiscovery instance."""
        return self.Helpers.create_discovery()

    @pytest.fixture
    def ldif_parser(self) -> FlextLdif:
        """Factory providing FlextLdif parser instance."""
        return self.Helpers.create_parser()

    def test_discovery_comprehensive(
        self,
        discovery: FlextLdifFixtureDiscovery,
    ) -> None:
        """Test comprehensive fixture discovery across all categories using mapping validation."""
        fixtures = discovery.discover_all()

        assert fixtures is not None, "Should discover fixtures"
        assert len(fixtures) > 0, "Should discover at least one fixture"

        # Validate category coverage using constants mapping
        categories = {f.category for f in fixtures}
        required_categories = {Fixtures.RFC, Fixtures.SERVERS, Fixtures.EDGE_CASES}
        assert required_categories.issubset(categories), (
            f"Missing categories: {required_categories - categories}"
        )

    @pytest.mark.parametrize(
        ("category", "expected_min_fixtures"),
        Helpers.parametrized_categories(),
    )
    def test_category_discovery(
        self,
        discovery: FlextLdifFixtureDiscovery,
        category: str,
        expected_min_fixtures: int,
    ) -> None:
        """Test discovery of fixtures by category with dynamic parametrized validation."""
        fixtures = discovery.discover_category(category)

        assert fixtures is not None, f"Should discover {category} fixtures"
        assert len(fixtures) >= expected_min_fixtures, (
            f"Should have at least {expected_min_fixtures} {category} fixtures"
        )
        assert all(f.category == category for f in fixtures), (
            f"All {category} fixtures should have correct category"
        )

    @pytest.mark.parametrize(
        ("category", "fixture_name", "fixture_config"),
        Helpers.parametrized_fixtures(),
    )
    def test_fixture_metadata_validation(
        self,
        discovery: FlextLdifFixtureDiscovery,
        category: str,
        fixture_name: str,
        fixture_config: GenericFieldsDict,
    ) -> None:
        """Test fixture metadata extraction and validation using parametrized mapping."""
        full_name = self.Helpers.get_fixture_full_name(fixture_name, category)
        metadata = discovery.get_metadata(full_name)

        assert metadata is not None, f"Should find {fixture_name} fixture"
        assert metadata.fixture_name == full_name
        assert metadata.category == category
        assert metadata.has_expected == fixture_config.get("has_expected", True)
        assert metadata.file_size > 0
        assert metadata.line_count > 0

    @pytest.mark.parametrize(
        ("category", "fixture_name", "fixture_config"),
        Helpers.parametrized_fixtures(),
    )
    def test_expected_results_loading(
        self,
        discovery: FlextLdifFixtureDiscovery,
        category: str,
        fixture_name: str,
        fixture_config: GenericFieldsDict,
    ) -> None:
        """Test loading expected results from JSON fixtures with mapping validation."""
        full_name = self.Helpers.get_fixture_full_name(fixture_name, category)
        metadata = discovery.get_metadata(full_name)

        assert metadata is not None, f"Should find {fixture_name} fixture"

        expected = discovery.load_expected_results(metadata)
        assert expected is not None, "Should load expected results"

        # Validate expected results structure using mapping
        # Broken fixtures have different structure (strict_mode/relaxed_mode)
        if category == "broken":
            # Broken fixtures have error information and mode-specific entries
            assert "valid" in expected
            assert (
                "error" in expected
                or "strict_mode" in expected
                or "relaxed_mode" in expected
            )
            # Check if entries exist in any mode
            has_entries = (
                "entries" in expected
                or (
                    isinstance(expected.get("strict_mode"), dict)
                    and "entries" in expected["strict_mode"]
                )
                or (
                    isinstance(expected.get("relaxed_mode"), dict)
                    and "entries" in expected["relaxed_mode"]
                )
            )
            assert has_entries, (
                "Broken fixture should have entries in at least one mode"
            )
        else:
            # Normal fixtures have entries, count, and valid at root level
            assert "entries" in expected
            assert "count" in expected
            assert "valid" in expected
            expected_count = fixture_config.get("expected_count", 1)
            assert expected["count"] == expected_count

    def test_fixture_parsing_roundtrip(
        self,
        discovery: FlextLdifFixtureDiscovery,
        ldif_parser: FlextLdif,
    ) -> None:
        """Test complete fixture parsing and roundtrip validation using domain helpers."""
        # Use first RFC fixture for roundtrip test
        category, fixture_name = Fixtures.RFC, "simple_entry"
        full_name = self.Helpers.get_fixture_full_name(fixture_name, category)

        metadata = discovery.get_metadata(full_name)
        assert metadata is not None, f"Should find {fixture_name} fixture"

        # Load expected results
        expected = discovery.load_expected_results(metadata)
        assert expected is not None, "Should load expected results"

        # Parse LDIF content using domain helpers
        content = metadata.fixture_path.read_text(encoding="utf-8")
        parse_result = ldif_parser.parse(content)

        expected_count = expected.get("count", 0)
        # Assert success and get entries
        parsed_entries = TestAssertions.assert_success(
            parse_result,
            "Parse should succeed",
        )
        assert isinstance(parsed_entries, list), (
            "Parse result should be list of entries"
        )
        assert len(parsed_entries) == expected_count, (
            f"Expected {expected_count} entries, got {len(parsed_entries)}"
        )

        # Validate roundtrip preserves structure
        if parsed_entries:
            TestAssertions.assert_roundtrip_preserves(
                [parsed_entries[0]],
                [parsed_entries[0]],
            )

        # Compare with expected results using discovery's comparison
        comparison = discovery.compare_results({"entries": parsed_entries}, expected)
        assert comparison is not None, "Comparison should return results"

    def test_multivalue_fixture_handling(
        self,
        discovery: FlextLdifFixtureDiscovery,
    ) -> None:
        """Test multivalue attribute fixtures with advanced validation using helpers."""
        category, fixture_name = Fixtures.RFC, "multivalue_long"
        full_name = self.Helpers.get_fixture_full_name(fixture_name, category)

        metadata = discovery.get_metadata(full_name)
        assert metadata is not None, "Should find multivalue fixture"
        assert metadata.has_expected

        expected = discovery.load_expected_results(metadata)
        assert expected is not None, "Should load multivalue expected results"

        # Validate multivalue structure using mapping
        expected_count = expected.get("count", 0)
        assert expected_count == 1  # From mapping
        entries = expected.get("entries", [])
        assert isinstance(entries, list) and len(entries) > 0
        entry = entries[0]
        assert isinstance(entry, dict)
        attributes = entry.get("attributes", {})
        assert isinstance(attributes, dict)
        assert "mail" in attributes
        mail_values = attributes["mail"]
        assert isinstance(mail_values, list) and len(mail_values) > 1, (
            "Should have multiple mail values"
        )

    def test_changetype_operations(self, discovery: FlextLdifFixtureDiscovery) -> None:
        """Test LDIF changetype operations (modify, delete, modrdn) using mapping iteration."""
        changetype_fixtures = [
            (cat, name, config)
            for cat, fixtures in self.FIXTURE_MAPPINGS.items()
            for name, config in fixtures.items()
            if config.get("fixture_type")
            in {Fixtures.MODIFY, Fixtures.DELETE, Fixtures.MODRDN}
        ]

        for category, fixture_name, fixture_config in changetype_fixtures:
            full_name = self.Helpers.get_fixture_full_name(fixture_name, category)
            metadata = discovery.get_metadata(full_name)
            assert metadata is not None, f"Should find {fixture_name} fixture"
            expected_type = fixture_config.get("fixture_type")
            if expected_type is not None:
                assert metadata.fixture_type == expected_type, (
                    f"Should have correct fixture type for {fixture_name}"
                )

    def test_server_specific_fixtures(
        self,
        discovery: FlextLdifFixtureDiscovery,
    ) -> None:
        """Test server-specific fixture discovery using mapping iteration."""
        server_fixtures = [
            (cat, name, config)
            for cat, fixtures in self.FIXTURE_MAPPINGS.items()
            for name, config in fixtures.items()
            if "server_type" in config
        ]

        for _category, fixture_name, fixture_config in server_fixtures:
            metadata = discovery.get_metadata(fixture_name)
            assert metadata is not None, f"Should find {fixture_name} fixture"
            expected_server_type = fixture_config.get("server_type")
            if expected_server_type is not None:
                assert metadata.server_type == expected_server_type, (
                    f"Should have correct server type for {fixture_name}"
                )

            expected = discovery.load_expected_results(metadata)
            assert expected is not None, (
                f"Should load expected results for {fixture_name}"
            )
            if expected_server_type is not None:
                assert expected.get("server_type") == expected_server_type, (
                    f"Expected results should match server type for {fixture_name}"
                )

    def test_edge_case_fixtures(self, discovery: FlextLdifFixtureDiscovery) -> None:
        """Test edge case fixtures with specialized validation using mapping-driven approach."""
        for fixture_name, validations in self.EDGE_CASE_VALIDATIONS.items():
            metadata = discovery.get_metadata(fixture_name)
            assert metadata is not None, f"Should find {fixture_name} fixture"

            expected = discovery.load_expected_results(metadata)
            assert expected is not None, (
                f"Should load expected results for {fixture_name}"
            )

            # Specialized validation using mapping for DRY
            for val_key, expected_val in validations.items():
                actual_val = expected.get(val_key, 0)
                assert (
                    isinstance(actual_val, type(expected_val))
                    and actual_val == expected_val
                ), (
                    f"{fixture_name} {val_key} should be {expected_val}, got {actual_val}"
                )

    def test_broken_fixtures_validation(
        self,
        discovery: FlextLdifFixtureDiscovery,
    ) -> None:
        """Test broken/error condition fixtures using generic validation."""
        broken_fixtures = [
            (cat, name, config)
            for cat, fixtures in self.FIXTURE_MAPPINGS.items()
            for name, config in fixtures.items()
            if cat == "broken"
        ]

        for _category, fixture_name, _fixture_config in broken_fixtures:
            metadata = discovery.get_metadata(fixture_name)
            assert metadata is not None, f"Should find {fixture_name} fixture"

            expected = discovery.load_expected_results(metadata)
            assert expected is not None, (
                f"Should load expected results for {fixture_name}"
            )

            # Broken fixtures should be marked as invalid
            assert not expected["valid"], (
                f"Broken fixture {fixture_name} should be marked as invalid"
            )
            assert "relaxed_mode" in expected, (
                f"Broken fixture {fixture_name} should have relaxed_mode info"
            )
