"""Fixture validation framework for LDIF schema and entry testing.

Provides validation utilities for LDIF fixture correctness and completeness.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, cast

from flext_core import FlextResult

from . import helpers


class FixtureValidator:
    """Validates LDIF fixture files for correctness and completeness."""

    @staticmethod
    def validate_schema_fixture(content: str) -> FlextResult[dict[str, object]]:
        """Validate schema fixture has proper LDIF format and structure.

        Args:
            content: LDIF formatted schema content

        Returns:
            FlextResult with validation statistics

        """
        if not content or not content.strip():
            return FlextResult.fail("Schema fixture is empty")

        try:
            attributes = helpers.extract_attributes(content)
            objectclasses = helpers.extract_objectclasses(content)

            if not attributes and not objectclasses:
                return FlextResult.fail("No schema definitions found in fixture")

            # Validate all OIDs are present
            invalid_attrs = []
            for attr in attributes:
                oid = helpers.extract_oid(attr)
                if not oid:
                    invalid_attrs.append(attr[:50])

            invalid_ocs = []
            for oc in objectclasses:
                oid = helpers.extract_oid(oc)
                if not oid:
                    invalid_ocs.append(oc[:50])

            stats: dict[str, object] = {
                "attribute_count": len(attributes),
                "objectclass_count": len(objectclasses),
                "total_definitions": len(attributes) + len(objectclasses),
                "invalid_attributes": len(invalid_attrs),
                "invalid_objectclasses": len(invalid_ocs),
                "is_valid": len(invalid_attrs) == 0 and len(invalid_ocs) == 0,
            }

            if not stats["is_valid"]:
                error = (
                    f"Invalid schema definitions found: "
                    f"{len(invalid_attrs)} attributes, {len(invalid_ocs)} objectclasses"
                )
                return FlextResult.fail(error)

            return FlextResult.ok(stats)

        except Exception as e:
            return FlextResult.fail(f"Schema validation error: {e!s}")

    @staticmethod
    def validate_entry_fixture(content: str) -> FlextResult[dict[str, object]]:
        """Validate entry fixture completeness and structure.

        Args:
            content: LDIF formatted entry content

        Returns:
            FlextResult with validation statistics

        """
        if not content or not content.strip():
            return FlextResult.fail("Entry fixture is empty")

        try:
            entries = helpers.extract_entries(content)

            if not entries:
                return FlextResult.fail("No entries found in fixture")

            # Validate all entries have DN
            invalid_entries = 0
            for entry in entries:
                if "dn" not in entry:
                    invalid_entries += 1

            # Validate DN hierarchy
            dns = [
                entry.get("dn", "")
                for entry in entries
                if isinstance(entry.get("dn"), str)
            ]
            invalid_dns = [dn for dn in dns if not dn or "=" not in cast("str", dn)]

            stats: dict[str, object] = {
                "entry_count": len(entries),
                "entries_with_dn": len(entries) - invalid_entries,
                "invalid_dns": len(invalid_dns),
                "is_valid": invalid_entries == 0 and len(invalid_dns) == 0,
            }

            if not stats["is_valid"]:
                error = (
                    f"Invalid entries found: "
                    f"{invalid_entries} without DN, {len(invalid_dns)} with invalid DN"
                )
                return FlextResult.fail(error)

            return FlextResult.ok(stats)

        except Exception as e:
            return FlextResult.fail(f"Entry validation error: {e!s}")

    @staticmethod
    def assert_semantic_equivalent(original: str, final: str) -> FlextResult[bool]:
        """Compare that essential schema elements are preserved between conversions.

        Args:
            original: Original schema definition
            final: Final schema definition after conversion

        Returns:
            FlextResult with True if semantically equivalent

        """
        try:
            orig_oid = helpers.extract_oid(original)
            final_oid = helpers.extract_oid(final)

            if orig_oid != final_oid:
                return FlextResult.fail(f"OID changed: {orig_oid} → {final_oid}")

            orig_name = helpers.extract_name(original)
            final_name = helpers.extract_name(final)

            if orig_name != final_name:
                return FlextResult.fail(f"NAME changed: {orig_name} → {final_name}")

            return FlextResult.ok(True)

        except Exception as e:
            return FlextResult.fail(f"Semantic comparison error: {e!s}")

    @staticmethod
    def validate_roundtrip(
        original: str, backward: str
    ) -> FlextResult[dict[str, object]]:
        """Validate roundtrip conversion preserves key information.

        Args:
            original: Original schema definition
            backward: Definition after backward conversion

        Returns:
            FlextResult with validation details

        """
        try:
            # Check OIDs preserved
            orig_oid = helpers.extract_oid(original)
            back_oid = helpers.extract_oid(backward)

            if orig_oid != back_oid:
                return FlextResult.fail(
                    f"OID not preserved in roundtrip: {orig_oid} → {back_oid}"
                )

            # Check NAMEs preserved
            orig_name = helpers.extract_name(original)
            back_name = helpers.extract_name(backward)

            if orig_name != back_name:
                return FlextResult.fail(
                    f"NAME not preserved in roundtrip: {orig_name} → {back_name}"
                )

            stats: dict[str, object] = {
                "oid_preserved": orig_oid == back_oid,
                "name_preserved": orig_name == back_name,
                "roundtrip_valid": orig_oid == back_oid and orig_name == back_name,
            }

            return FlextResult.ok(stats)

        except Exception as e:
            return FlextResult.fail(f"Roundtrip validation error: {e!s}")


class FixtureCoverageReport:
    """Generates coverage reports for LDIF fixtures."""

    @staticmethod
    def generate_summary(
        fixtures_by_server: dict[str, dict[object, str]],
    ) -> dict[str, object]:
        """Generate summary of fixture coverage across servers.

        Args:
            fixtures_by_server: Dict mapping server names to fixture content dicts
                (keys can be strings or FixtureType enums)

        Returns:
            Coverage summary statistics

        """
        coverage: dict[str, object] = {}

        for server_name, fixtures in fixtures_by_server.items():
            # Convert enum keys to strings for comparison
            str_fixtures = {str(k): v for k, v in fixtures.items()}

            server_stats = {
                "has_schema": False,
                "has_entries": False,
                "has_acl": False,
                "has_integration": False,
                "schema_attrs": 0,
                "schema_ocs": 0,
                "entries": 0,
            }

            # Check schema fixture
            if "schema" in str_fixtures:
                schema_content = str_fixtures["schema"]
                if schema_content and schema_content.strip():
                    server_stats["has_schema"] = True
                    attrs = helpers.extract_attributes(schema_content)
                    ocs = helpers.extract_objectclasses(schema_content)
                    server_stats["schema_attrs"] = len(attrs)
                    server_stats["schema_ocs"] = len(ocs)

            # Check entries fixture
            if "entries" in str_fixtures:
                entries_content = str_fixtures["entries"]
                if entries_content and entries_content.strip():
                    server_stats["has_entries"] = True
                    entry_count = helpers.count_entries(entries_content)
                    server_stats["entries"] = entry_count

            # Check ACL fixture
            if "acl" in str_fixtures:
                acl_content = str_fixtures["acl"]
                if acl_content and acl_content.strip():
                    server_stats["has_acl"] = True

            # Check integration fixture
            if "integration" in str_fixtures:
                integration_content = str_fixtures["integration"]
                if integration_content and integration_content.strip():
                    server_stats["has_integration"] = True

            coverage[server_name] = server_stats

        return coverage

    @staticmethod
    def print_coverage_report(coverage: dict[str, object]) -> None:
        """Print formatted coverage report.

        Args:
            coverage: Coverage report from generate_summary

        """
        for _server_name, stats in sorted(coverage.items()):
            if not isinstance(stats, dict):
                continue


@dataclass(frozen=True)
class FixtureMetadata:
    """Complete metadata about a fixture and its expected results."""

    fixture_path: Path
    expected_path: Path | None
    fixture_name: str
    category: str  # rfc, servers, broken, edge_cases
    subcategory: str | None  # valid, violations, oid, oud, etc.
    server_type: str | None
    file_size: int
    line_count: int
    has_expected: bool
    fixture_type: str  # Type of content: entries, modify, delete, modrdn, etc.


class FlextLdifFixtureDiscovery:
    """Enhanced fixture discovery and result comparison system.

    Supports comprehensive fixture discovery and validation across all
    fixture categories with expected result comparison.

    Usage:
        discovery = FlextLdifFixtureDiscovery()

        # Find all fixtures
        fixtures = discovery.discover_all()

        # Load fixture with expected results
        metadata = discovery.get_metadata("rfc2849_simple_entry")
        ldif_content = metadata.fixture_path.read_text()
        expected_results = discovery.load_expected_results(metadata)

        # Validate fixture-by-category
        rfc_fixtures = discovery.discover_category("rfc")
        server_fixtures = discovery.discover_category("servers")
        broken_fixtures = discovery.discover_category("broken")
        edge_fixtures = discovery.discover_category("edge_cases")
    """

    def __init__(self, fixtures_root: Path | None = None) -> None:
        """Initialize fixture discovery.

        Args:
            fixtures_root: Root directory for fixtures. Defaults to tests/fixtures/

        """
        if fixtures_root is None:
            fixtures_root = Path(__file__).parent
        self.fixtures_root: Final[Path] = fixtures_root

    def discover_all(self) -> list[FixtureMetadata]:
        """Discover all fixtures in the fixture directory.

        Returns:
            list[FixtureMetadata]: All discovered fixtures with metadata

        """
        fixtures: list[FixtureMetadata] = []

        # Recursively search for .ldif files
        for ldif_file in self.fixtures_root.rglob("*.ldif"):
            # Skip any in __pycache__ or other special directories
            if "__pycache__" in ldif_file.parts:
                continue

            metadata = self._create_metadata(ldif_file)
            fixtures.append(metadata)

        return sorted(fixtures, key=lambda m: str(m.fixture_path))

    def discover_category(self, category: str) -> list[FixtureMetadata]:
        """Discover fixtures in a specific category.

        Args:
            category: Category to discover (rfc, servers, broken, edge_cases)

        Returns:
            list[FixtureMetadata]: Fixtures in the specified category

        """
        category_path = self.fixtures_root / category
        if not category_path.exists():
            return []

        fixtures: list[FixtureMetadata] = []
        for ldif_file in category_path.rglob("*.ldif"):
            if "__pycache__" in ldif_file.parts:
                continue
            metadata = self._create_metadata(ldif_file)
            fixtures.append(metadata)

        return sorted(fixtures, key=lambda m: str(m.fixture_path))

    def get_metadata(self, fixture_name: str) -> FixtureMetadata | None:
        """Get metadata for a specific fixture by name.

        Args:
            fixture_name: Name of the fixture (without .ldif extension)

        Returns:
            FixtureMetadata: Fixture metadata, or None if not found

        """
        all_fixtures = self.discover_all()
        for fixture in all_fixtures:
            if fixture.fixture_name == fixture_name:
                return fixture
        return None

    def load_expected_results(self, metadata: FixtureMetadata) -> dict[str, Any] | None:
        """Load expected results for a fixture.

        Args:
            metadata: Fixture metadata

        Returns:
            Expected results dict or None if not found
            dict: Expected results as parsed JSON, or None if not available

        """
        if not metadata.has_expected:
            return None

        if metadata.expected_path is None:
            return None

        if not metadata.expected_path.exists():
            return None

        try:
            loaded_json = json.loads(metadata.expected_path.read_text(encoding="utf-8"))
            return cast("dict[str, Any]", loaded_json)
        except (OSError, json.JSONDecodeError):
            return None

    def compare_results(
        self,
        actual: dict[str, Any],
        expected: dict[str, Any],
    ) -> dict[str, Any]:
        """Compare actual parsing results with expected results.

        Args:
            actual: Actual parsed results
            expected: Expected results

        Returns:
            dict: Comparison results with matches, differences, etc.

        """
        result: dict[str, Any] = {
            "matches": True,
            "differences": [],
            "entry_count_matches": False,
            "entries_match": False,
        }

        # Compare entry counts
        actual_count = len(actual.get("entries", []))
        expected_count = len(expected.get("entries", []))

        if actual_count == expected_count:
            result["entry_count_matches"] = True
        else:
            cast("list[str]", result["differences"]).append(
                f"Entry count mismatch: actual={actual_count}, expected={expected_count}"
            )
            result["matches"] = False

        # Compare entries
        if result["entry_count_matches"]:
            entries_match = True
            for i, (actual_entry, expected_entry) in enumerate(
                zip(
                    actual.get("entries", []), expected.get("entries", []), strict=False
                )
            ):
                # Convert Pydantic Entry to dict if needed
                if hasattr(actual_entry, "model_dump"):
                    actual_entry_dict = actual_entry.model_dump(mode="python")
                else:
                    actual_entry_dict = actual_entry

                # Extract DN - handle both dict and string forms
                actual_dn = actual_entry_dict.get("dn")
                if isinstance(actual_dn, dict):
                    actual_dn = actual_dn.get("value")

                expected_dn = expected_entry.get("dn")
                if isinstance(expected_dn, dict):
                    expected_dn = expected_dn.get("value")

                if actual_dn != expected_dn:
                    cast("list[str]", result["differences"]).append(
                        f"Entry {i}: DN mismatch: {actual_dn} != {expected_dn}"
                    )
                    entries_match = False

                # Compare attributes - handle both dict and nested object forms
                actual_attrs = actual_entry_dict.get("attributes", {})
                if isinstance(actual_attrs, dict) and "attributes" in actual_attrs:
                    # Handle nested structure
                    actual_attrs = actual_attrs.get("attributes", {})

                expected_attrs = expected_entry.get("attributes", {})
                if isinstance(expected_attrs, dict) and "attributes" in expected_attrs:
                    # Handle nested structure
                    expected_attrs = expected_attrs.get("attributes", {})

                if actual_attrs != expected_attrs:
                    cast("list[str]", result["differences"]).append(
                        f"Entry {i}: Attributes mismatch for {actual_dn}"
                    )
                    entries_match = False

            result["entries_match"] = entries_match
            result["matches"] = result["matches"] and entries_match

        return result

    def _create_metadata(self, ldif_file: Path) -> FixtureMetadata:
        """Create metadata for a fixture file.

        Args:
            ldif_file: Path to LDIF file

        Returns:
            FixtureMetadata: Metadata for the fixture

        """
        # Extract fixture name and category
        fixture_name = ldif_file.stem
        relative_path = ldif_file.relative_to(self.fixtures_root)
        parts = relative_path.parts

        # Determine category and subcategory
        category = parts[0] if len(parts) > 1 else "unknown"
        subcategory = parts[1] if len(parts) > 2 else None

        # Try to determine server type from subcategory or fixture name
        server_type = None
        if category == "servers" and subcategory:
            server_type = subcategory
        elif "oid" in fixture_name.lower():
            server_type = "oid"
        elif "oud" in fixture_name.lower():
            server_type = "oud"
        elif "openldap" in fixture_name.lower():
            server_type = "openldap"
        elif (
            "active_directory" in fixture_name.lower() or "ad_" in fixture_name.lower()
        ):
            server_type = "active_directory"

        # Determine fixture type
        fixture_type = "entries"
        if "modify" in fixture_name:
            fixture_type = "modify"
        elif "delete" in fixture_name:
            fixture_type = "delete"
        elif "modrdn" in fixture_name:
            fixture_type = "modrdn"
        elif "schema" in fixture_name:
            fixture_type = "schema"
        elif "acl" in fixture_name:
            fixture_type = "acl"
        elif "config" in fixture_name:
            fixture_type = "config"

        # Check for expected results
        expected_path = ldif_file.with_suffix(".expected.json")
        has_expected = expected_path.exists()

        # Get file size and line count
        file_size = ldif_file.stat().st_size
        content = ldif_file.read_text(encoding="utf-8")
        line_count = len(content.splitlines())

        return FixtureMetadata(
            fixture_path=ldif_file,
            expected_path=expected_path if has_expected else None,
            fixture_name=fixture_name,
            category=category,
            subcategory=subcategory,
            server_type=server_type,
            file_size=file_size,
            line_count=line_count,
            has_expected=has_expected,
            fixture_type=fixture_type,
        )


__all__ = [
    "FixtureCoverageReport",
    "FixtureMetadata",
    "FixtureValidator",
    "FlextLdifFixtureDiscovery",
]
