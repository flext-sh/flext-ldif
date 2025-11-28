"""Fixture validation framework for LDIF schema and entry testing.

Provides validation utilities for LDIF fixture correctness and completeness.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from flext_core import FlextResult

from tests.fixtures.typing import GenericFieldsDict, GenericTestCaseDict

from . import helpers


class FixtureValidator:
    """Validates LDIF fixture files for correctness and completeness."""

    @staticmethod
    def validate_schema_fixture(content: str) -> FlextResult[GenericFieldsDict]:
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

            stats: GenericFieldsDict = {
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

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Schema validation error: {e!s}")

    @staticmethod
    def validate_entry_fixture(content: str) -> FlextResult[GenericFieldsDict]:
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
            invalid_dns = [
                dn for dn in dns if isinstance(dn, str) and (not dn or "=" not in dn)
            ]

            stats: GenericFieldsDict = {
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

        except (ValueError, TypeError, AttributeError) as e:
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

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Semantic comparison error: {e!s}")

    @staticmethod
    def validate_roundtrip(
        original: str,
        backward: str,
    ) -> FlextResult[GenericFieldsDict]:
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
                    f"OID not preserved in roundtrip: {orig_oid} → {back_oid}",
                )

            # Check NAMEs preserved
            orig_name = helpers.extract_name(original)
            back_name = helpers.extract_name(backward)

            if orig_name != back_name:
                return FlextResult.fail(
                    f"NAME not preserved in roundtrip: {orig_name} → {back_name}",
                )

            stats: GenericFieldsDict = {
                "oid_preserved": orig_oid == back_oid,
                "name_preserved": orig_name == back_name,
                "roundtrip_valid": orig_oid == back_oid and orig_name == back_name,
            }

            return FlextResult.ok(stats)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Roundtrip validation error: {e!s}")


class FixtureCoverageReport:
    """Generates coverage reports for LDIF fixtures."""

    @staticmethod
    def generate_summary(
        fixtures_by_server: dict[str, dict[object, str]],
    ) -> GenericFieldsDict:
        """Generate summary of fixture coverage across servers.

        Args:
            fixtures_by_server: Dict mapping server names to fixture content dicts
                (keys can be strings or FixtureType enums)

        Returns:
            Coverage summary statistics

        """
        coverage: GenericFieldsDict = {}

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
    def print_coverage_report(coverage: GenericFieldsDict) -> None:
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

    def load_expected_results(
        self,
        metadata: FixtureMetadata,
    ) -> GenericFieldsDict | None:
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
            result = json.loads(metadata.expected_path.read_text(encoding="utf-8"))
            if isinstance(result, dict):
                return result
            return None
        except (OSError, json.JSONDecodeError):
            return None

    def compare_results(
        self,
        actual: GenericFieldsDict,
        expected: GenericFieldsDict,
    ) -> GenericFieldsDict:
        """Compare actual parsing results with expected results.

        Args:
            actual: Actual parsed results
            expected: Expected results

        Returns:
            dict: Comparison results with matches, differences, etc.

        """
        result: GenericFieldsDict = {
            "matches": True,
            "differences": [],
            "entry_count_matches": False,
            "entries_match": False,
        }
        differences: list[str] = []

        # Compare entry counts
        actual_entries = actual.get("entries", [])
        expected_entries = expected.get("entries", [])
        if not isinstance(actual_entries, list):
            actual_entries = []
        if not isinstance(expected_entries, list):
            expected_entries = []
        actual_count = len(actual_entries)
        expected_count = len(expected_entries)

        if actual_count == expected_count:
            result["entry_count_matches"] = True
        else:
            differences.append(
                f"Entry count mismatch: actual={actual_count}, expected={expected_count}",
            )
            result["matches"] = False

        # Compare entries
        if result["entry_count_matches"]:
            entries_match = True
            for i, (actual_entry, expected_entry) in enumerate(
                zip(
                    actual_entries,
                    expected_entries,
                    strict=False,
                ),
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
                    differences.append(
                        f"Entry {i}: DN mismatch: {actual_dn} != {expected_dn}",
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
                    differences.append(
                        f"Entry {i}: Attributes mismatch for {actual_dn}",
                    )
                    entries_match = False

            result["entries_match"] = entries_match
            result["matches"] = result["matches"] and entries_match

        result["differences"] = differences
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


class RoundTripValidator:
    """Deep round-trip validation comparing content, not just counts.

    Provides comprehensive validation for parse → write → parse cycles
    to ensure data integrity across conversions.
    """

    @staticmethod
    def validate_entries_deep(
        original_entries: list[GenericTestCaseDict],
        roundtrip_entries: list[GenericTestCaseDict],
    ) -> FlextResult[GenericFieldsDict]:
        """Deeply validate entry preservation across round-trip.

        Args:
            original_entries: Original entries before round-trip
            roundtrip_entries: Entries after write and re-parse

        Returns:
            FlextResult with detailed comparison report

        """
        if len(original_entries) != len(roundtrip_entries):
            return FlextResult.fail(
                f"Entry count mismatch: {len(original_entries)} vs {len(roundtrip_entries)}",
            )

        total_matches = 0
        mismatches: list[GenericTestCaseDict] = []

        for i, (original, roundtrip) in enumerate(
            zip(original_entries, roundtrip_entries, strict=False),
        ):
            comparison = helpers.compare_entries_deep(original, roundtrip)

            if comparison.get("matches"):
                total_matches += 1
            else:
                mismatches.append(
                    {
                        "entry_index": i,
                        "dn": comparison.get("dn_original"),
                        "comparison": comparison,
                    },
                )

        report: GenericFieldsDict = {
            "total_entries": len(original_entries),
            "matching_entries": total_matches,
            "mismatched_entries": len(mismatches),
            "perfect_roundtrip": len(mismatches) == 0,
            "mismatches": mismatches,
        }

        if len(mismatches) > 0:
            error_msg = f"Round-trip validation failed: {len(mismatches)}/{len(original_entries)} entries mismatched"
            return FlextResult.fail(error_msg, error_data=report)

        return FlextResult.ok(report)

    @staticmethod
    def validate_attribute_values(
        original_entries: list[GenericTestCaseDict],
        roundtrip_entries: list[GenericTestCaseDict],
        attribute_names: list[str] | None = None,
    ) -> FlextResult[GenericFieldsDict]:
        """Validate specific attribute values across round-trip.

        Args:
            original_entries: Original entries
            roundtrip_entries: Entries after round-trip
            attribute_names: Specific attributes to validate (None for all)

        Returns:
            FlextResult with attribute-level validation

        """
        if len(original_entries) != len(roundtrip_entries):
            return FlextResult.fail("Entry count mismatch")

        attr_reports: dict[str, GenericFieldsDict] = {}

        for _i, (original, roundtrip) in enumerate(
            zip(original_entries, roundtrip_entries, strict=False),
        ):
            # Get all attributes to check
            original_attrs = {k.lower() for k in original if k.lower() != "dn"}
            {k.lower() for k in roundtrip if k.lower() != "dn"}

            # Filter if specific attributes requested
            attrs_to_check = attribute_names or original_attrs

            for attr_name in attrs_to_check:
                attr_lower = attr_name.lower()

                if attr_lower not in attr_reports:
                    attr_reports[attr_lower] = {
                        "matches": 0,
                        "mismatches": 0,
                        "missing_roundtrip": 0,
                        "extra_roundtrip": 0,
                    }

                orig_values = helpers.get_entry_attribute_values(original, attr_name)
                round_values = helpers.get_entry_attribute_values(roundtrip, attr_name)

                if (not orig_values and not round_values) or sorted(
                    orig_values,
                ) == sorted(round_values):
                    matches = attr_reports[attr_lower].get("matches", 0)
                    if isinstance(matches, int):
                        attr_reports[attr_lower]["matches"] = matches + 1
                else:
                    mismatches = attr_reports[attr_lower].get("mismatches", 0)
                    if isinstance(mismatches, int):
                        attr_reports[attr_lower]["mismatches"] = mismatches + 1
                    if not round_values:
                        missing = attr_reports[attr_lower].get("missing_roundtrip", 0)
                        if isinstance(missing, int):
                            attr_reports[attr_lower]["missing_roundtrip"] = missing + 1

        report: GenericFieldsDict = {
            "attribute_count": len(attr_reports),
            "perfectly_preserved": sum(
                1
                for attr in attr_reports.values()
                if attr.get("mismatches") == 0 and attr.get("missing_roundtrip") == 0
            ),
            "attribute_reports": attr_reports,
        }

        total_perfect_obj = report.get("perfectly_preserved", 0)
        total_attrs_obj = report.get("attribute_count", 0)
        total_perfect = (
            int(total_perfect_obj) if isinstance(total_perfect_obj, (int, str)) else 0
        )
        total_attrs = (
            int(total_attrs_obj) if isinstance(total_attrs_obj, (int, str)) else 0
        )

        if total_perfect < total_attrs:
            error_msg = f"Attribute preservation failed: {total_perfect}/{total_attrs} attributes perfectly preserved"
            return FlextResult.fail(error_msg, error_data=report)

        return FlextResult.ok(report)


class RfcComplianceValidator:
    """RFC compliance validation for LDIF format and schema.

    Validates conformance to RFC 2849 (LDIF) and RFC 4512 (Schema).
    """

    @staticmethod
    def validate_ldif_format(content: str) -> FlextResult[GenericFieldsDict]:
        """Validate LDIF conforms to RFC 2849 format.

        Args:
            content: LDIF formatted string

        Returns:
            FlextResult with RFC 2849 compliance report

        """
        validation = helpers.validate_ldif_rfc2849_format(content)

        if not validation.get("is_valid"):
            error_parts: list[str] = []
            line_length_issues = validation.get("line_length_issues")
            if line_length_issues and isinstance(line_length_issues, list):
                error_parts.append(
                    f"{len(line_length_issues)} lines exceed 76 chars",
                )
            missing_dn_entries = validation.get("missing_dn_entries")
            if missing_dn_entries:
                error_parts.append(
                    f"{missing_dn_entries} entries missing DN",
                )
            error_msg = f"RFC 2849 compliance failed: {'; '.join(error_parts)}"
            return FlextResult.fail(error_msg, error_data=validation)

        return FlextResult.ok(validation)

    @staticmethod
    def validate_schema_format(
        entry: GenericFieldsDict,
    ) -> FlextResult[GenericFieldsDict]:
        """Validate schema entry conforms to RFC 4512.

        Args:
            entry: Schema entry dictionary

        Returns:
            FlextResult with RFC 4512 compliance report

        """
        report: GenericFieldsDict = {
            "has_attributetypes": False,
            "has_objectclasses": False,
            "attribute_count": 0,
            "objectclass_count": 0,
            "is_valid": False,
        }

        # Check for schema attributes
        for key in entry:
            if isinstance(key, str):
                key_lower = key.lower()
                if key_lower == "attributetypes":
                    value = entry[key]
                    if isinstance(value, list):
                        report["attribute_count"] = len(value)
                    else:
                        report["attribute_count"] = 1
                    report["has_attributetypes"] = True
                elif key_lower == "objectclasses":
                    value = entry[key]
                    if isinstance(value, list):
                        report["objectclass_count"] = len(value)
                    else:
                        report["objectclass_count"] = 1
                    report["has_objectclasses"] = True

        # Valid schema has at least attributes or objectclasses
        is_valid = report.get("has_attributetypes", False) or report.get(
            "has_objectclasses",
            False,
        )
        report["is_valid"] = is_valid

        if not is_valid:
            return FlextResult.fail(
                "RFC 4512 compliance failed: No attributeTypes or objectClasses found",
                error_data=report,
            )

        return FlextResult.ok(report)

    @staticmethod
    def validate_dn_format(dn: str) -> FlextResult[GenericFieldsDict]:
        """Validate DN conforms to RFC 4514.

        Args:
            dn: DN string

        Returns:
            FlextResult with RFC 4514 compliance report

        """
        validation = helpers.validate_dn_rfc4514_format(dn)

        if not validation.get("is_valid"):
            errors_obj = validation.get("errors", [])
            errors = (
                [str(e) for e in errors_obj] if isinstance(errors_obj, list) else []
            )
            error_msg = f"RFC 4514 compliance failed: {'; '.join(errors)}"
            return FlextResult.fail(error_msg, error_data=validation)

        return FlextResult.ok(validation)


__all__ = [
    "FixtureCoverageReport",
    "FixtureMetadata",
    "FixtureValidator",
    "FlextLdifFixtureDiscovery",
    "RfcComplianceValidator",
    "RoundTripValidator",
]
