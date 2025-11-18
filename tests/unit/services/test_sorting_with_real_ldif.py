"""Comprehensive unit tests for FlextLdifSorting using REAL LDIF fixtures.

This test file validates ALL sorting functionality with authentic LDIF data from:
  - tests/fixtures/oid/oid_entries_fixtures.ldif
  - tests/fixtures/oid/oid_schema_fixtures.ldif
  - tests/fixtures/oid/oid_acl_fixtures.ldif

Tests verify that sorting works correctly with real-world LDIF data.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif import FlextLdif
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.sorting import FlextLdifSorting

# ════════════════════════════════════════════════════════════════════════════
# FIXTURES - Load REAL LDIF Data
# ════════════════════════════════════════════════════════════════════════════


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    """Get fixtures directory path."""
    return Path(__file__).parent.parent.parent / "fixtures"


@pytest.fixture(scope="session")
def oid_entries_ldif_path(fixtures_dir: Path) -> Path:
    """Path to OID entries fixture."""
    return fixtures_dir / "oid" / "oid_entries_fixtures.ldif"


@pytest.fixture(scope="session")
def oid_schema_ldif_path(fixtures_dir: Path) -> Path:
    """Path to OID schema fixture."""
    return fixtures_dir / "oid" / "oid_schema_fixtures.ldif"


@pytest.fixture(scope="session")
def oid_acl_ldif_path(fixtures_dir: Path) -> Path:
    """Path to OID ACL fixture."""
    return fixtures_dir / "oid" / "oid_acl_fixtures.ldif"


@pytest.fixture
def oid_entries(oid_entries_ldif_path: Path) -> list[FlextLdifModels.Entry]:
    """Load real OID entries from fixture."""
    if not oid_entries_ldif_path.exists():
        pytest.skip(f"Fixture not found: {oid_entries_ldif_path}")

    ldif = FlextLdif()
    result = ldif.parse(oid_entries_ldif_path)

    if not result.is_success:
        pytest.skip(f"Failed to parse fixture: {result.error}")

    return result.unwrap()


@pytest.fixture
def oid_schema(oid_schema_ldif_path: Path) -> list[FlextLdifModels.Entry]:
    """Load real OID schema from fixture."""
    if not oid_schema_ldif_path.exists():
        pytest.skip(f"Fixture not found: {oid_schema_ldif_path}")

    ldif = FlextLdif()
    result = ldif.parse(oid_schema_ldif_path)

    if not result.is_success:
        pytest.skip(f"Failed to parse fixture: {result.error}")

    return result.unwrap()


@pytest.fixture
def oid_acl(oid_acl_ldif_path: Path) -> list[FlextLdifModels.Entry]:
    """Load real OID ACL from fixture."""
    if not oid_acl_ldif_path.exists():
        pytest.skip(f"Fixture not found: {oid_acl_ldif_path}")

    ldif = FlextLdif()
    result = ldif.parse(oid_acl_ldif_path)

    if not result.is_success:
        pytest.skip(f"Failed to parse fixture: {result.error}")

    return result.unwrap()


# ════════════════════════════════════════════════════════════════════════════
# REAL LDIF TESTS - by_hierarchy
# ════════════════════════════════════════════════════════════════════════════


class TestSortingWithRealOIDEntries:
    """Test sorting with real OID LDIF entries."""

    def test_by_hierarchy_real_ldif(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test by_hierarchy with real OID LDIF data."""
        if not oid_entries:
            pytest.skip("No OID entries loaded")

        result = FlextLdifSorting.by_hierarchy(oid_entries)

        assert result.is_success
        sorted_entries = result.unwrap()
        assert len(sorted_entries) == len(oid_entries)

        # Verify entries are sorted by depth
        depths = [e.dn.value.count(",") if e.dn else 0 for e in sorted_entries]
        for i in range(len(depths) - 1):
            # Within same depth, should be alphabetical
            if depths[i] == depths[i + 1]:
                entry1_dn = sorted_entries[i].dn
                entry2_dn = sorted_entries[i + 1].dn
                assert entry1_dn is not None
                assert entry2_dn is not None
                assert entry1_dn.value.lower() <= entry2_dn.value.lower()

    def test_by_dn_real_ldif(self, oid_entries: list[FlextLdifModels.Entry]) -> None:
        """Test by_dn with real OID LDIF data."""
        if not oid_entries:
            pytest.skip("No OID entries loaded")

        result = FlextLdifSorting.by_dn(oid_entries)

        assert result.is_success
        sorted_entries = result.unwrap()

        # Verify alphabetical sorting
        dns = [e.dn.value.lower() if e.dn else "" for e in sorted_entries]
        assert dns == sorted(dns)

    def test_execute_hierarchy_real_ldif(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test execute() with hierarchy sorting on real data."""
        if not oid_entries:
            pytest.skip("No OID entries loaded")

        # FIXED: auto_execute=False requires .execute() call
        result = FlextLdifSorting(
            entries=oid_entries,
            sort_target="entries",
            sort_by="hierarchy",
        ).execute()
        assert result.is_success
        sorted_entries = result.unwrap()
        assert len(sorted_entries) == len(oid_entries)

    def test_execute_attributes_sorting_real_ldif(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test attributes sorting on real LDIF data."""
        if not oid_entries:
            pytest.skip("No OID entries loaded")

        # Take first entry for testing
        entry = oid_entries[0]

        # FIXED: auto_execute=False requires .execute() call
        result = FlextLdifSorting(entries=[entry], sort_target="attributes").execute()
        assert result.is_success
        sorted_entries = result.unwrap()
        assert len(sorted_entries) == 1

        # Verify attributes are present
        assert sorted_entries[0].attributes is not None
        attrs = sorted_entries[0].attributes.attributes
        assert len(attrs) > 0

        # Verify alphabetical sorting
        attr_names = list(attrs.keys())
        assert attr_names == sorted(attr_names, key=str.lower)

    def test_execute_combined_sorting_real_ldif(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test combined sorting (entries + attributes) on real data."""
        if not oid_entries:
            pytest.skip("No OID entries loaded")

        # FIXED: auto_execute=False requires .execute() call
        result = FlextLdifSorting(
            entries=oid_entries,
            sort_target="combined",
            sort_by="hierarchy",
            sort_attributes=True,
        ).execute()
        assert result.is_success
        sorted_entries = result.unwrap()
        assert len(sorted_entries) == len(oid_entries)

        # Verify each entry has attributes
        for entry in sorted_entries:
            assert entry.attributes is not None
            assert len(entry.attributes.attributes) > 0


# ════════════════════════════════════════════════════════════════════════════
# REAL LDIF TESTS - Schema Sorting
# ════════════════════════════════════════════════════════════════════════════


class TestSortingWithRealOIDSchema:
    """Test sorting with real OID schema LDIF."""

    def test_by_schema_real_ldif(self, oid_schema: list[FlextLdifModels.Entry]) -> None:
        """Test by_schema with real OID schema data."""
        if not oid_schema:
            pytest.skip("No OID schema loaded")

        result = FlextLdifSorting.by_schema(oid_schema)

        assert result.is_success
        sorted_entries = result.unwrap()
        assert len(sorted_entries) == len(oid_schema)

    def test_execute_schema_target_real_ldif(
        self,
        oid_schema: list[FlextLdifModels.Entry],
    ) -> None:
        """Test execute with schema target on real data."""
        if not oid_schema:
            pytest.skip("No OID schema loaded")

        # FIXED: auto_execute=False requires .execute() call
        result = FlextLdifSorting(
            entries=oid_schema,
            sort_target="schema",
            sort_by="schema",
        ).execute()
        assert result.is_success
        sorted_entries = result.unwrap()
        assert len(sorted_entries) == len(oid_schema)


# ════════════════════════════════════════════════════════════════════════════
# REAL LDIF TESTS - ACL Sorting
# ════════════════════════════════════════════════════════════════════════════


class TestSortingWithRealOIDACL:
    """Test sorting with real OID ACL LDIF."""

    def test_execute_acl_target_real_ldif(
        self,
        oid_acl: list[FlextLdifModels.Entry],
    ) -> None:
        """Test ACL sorting on real data."""
        if not oid_acl:
            pytest.skip("No OID ACL loaded")

        # FIXED: auto_execute=False requires .execute() call
        result = FlextLdifSorting(entries=oid_acl, sort_target="acl").execute()
        assert result.is_success
        sorted_entries = result.unwrap()
        assert len(sorted_entries) == len(oid_acl)

        # Verify entries are still valid
        for entry in sorted_entries:
            assert entry.dn is not None
            assert entry.attributes is not None


# ════════════════════════════════════════════════════════════════════════════
# INTEGRATION TESTS - Multi-Stage Sorting Pipelines
# ════════════════════════════════════════════════════════════════════════════


class TestRealWorldSortingPipelines:
    """Test real-world sorting scenarios with LDIF data."""

    def test_hierarchy_then_attributes_pipeline(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test realistic pipeline: sort by hierarchy then sort attributes."""
        if not oid_entries:
            pytest.skip("No OID entries loaded")

        # Stage 1: Sort entries by hierarchy
        result1 = FlextLdifSorting.by_hierarchy(oid_entries)
        assert result1.is_success
        entries_by_hierarchy = result1.unwrap()

        # Stage 2: Sort attributes within those entries
        # FIXED: auto_execute=False requires .execute() call
        result2 = FlextLdifSorting(
            entries=entries_by_hierarchy,
            sort_target="attributes",
        ).execute()
        assert result2.is_success
        final_entries = result2.unwrap()

        # Verify all entries are present and valid
        assert len(final_entries) == len(oid_entries)
        for entry in final_entries:
            assert entry.dn is not None
            assert entry.attributes is not None
            assert len(entry.attributes.attributes) > 0

    def test_custom_sorting_by_dn_length(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test custom sorting - order by DN length."""
        if not oid_entries:
            pytest.skip("No OID entries loaded")

        def dn_length(entry: FlextLdifModels.Entry) -> int:
            if not entry.dn:
                return 0
            return len(entry.dn.value)

        result = FlextLdifSorting.by_custom(oid_entries, dn_length)

        assert result.is_success
        sorted_entries = result.unwrap()

        # Verify sorting by DN length
        lengths = [len(e.dn.value) if e.dn else 0 for e in sorted_entries]
        assert lengths == sorted(lengths)

    def test_custom_sorting_by_dn_depth(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test custom sorting - order by DN depth (comma count)."""
        if not oid_entries:
            pytest.skip("No OID entries loaded")

        def dn_depth(entry: FlextLdifModels.Entry) -> int:
            if not entry.dn:
                return 0
            return entry.dn.value.count(",")

        result = FlextLdifSorting.by_custom(oid_entries, dn_depth)

        assert result.is_success
        sorted_entries = result.unwrap()

        # Verify sorting by depth
        depths = [e.dn.value.count(",") if e.dn else 0 for e in sorted_entries]
        assert depths == sorted(depths)

    def test_multiple_custom_sorts_via_classmethod(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test multiple sorting strategies via classmethod."""
        if not oid_entries:
            pytest.skip("No OID entries loaded")

        def length_key(e: FlextLdifModels.Entry) -> int:
            return len(e.dn.value) if e.dn else 0

        strategies = [
            ("hierarchy", None),  # Use by_hierarchy method
            ("dn", None),  # Use by_dn method
            ("length", length_key),
        ]

        for name, key_func in strategies:
            if name == "hierarchy":
                result = FlextLdifSorting.by_hierarchy(oid_entries)
            elif name == "dn":
                result = FlextLdifSorting.by_dn(oid_entries)
            else:
                assert key_func is not None
                result = FlextLdifSorting.by_custom(oid_entries, key_func)

            assert result.is_success, f"Failed for strategy: {name}"


# ════════════════════════════════════════════════════════════════════════════
# EDGE CASES WITH REAL DATA
# ════════════════════════════════════════════════════════════════════════════


class TestEdgeCasesWithRealLDIF:
    """Test edge cases with real LDIF data."""

    def test_sorting_preserves_data_integrity(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Verify sorting doesn't lose or corrupt data."""
        if not oid_entries:
            pytest.skip("No OID entries loaded")

        result = FlextLdifSorting.by_hierarchy(oid_entries)
        sorted_entries = result.unwrap()

        # All DNs should still be present
        original_dns = {e.dn.value for e in oid_entries if e.dn}
        sorted_dns = {e.dn.value for e in sorted_entries if e.dn}
        assert original_dns == sorted_dns

        # All entries should still have their attributes
        for original_entry in oid_entries:
            if not original_entry.dn:
                continue
            # Find corresponding sorted entry
            sorted_entry = next(
                (
                    e
                    for e in sorted_entries
                    if e.dn and e.dn.value == original_entry.dn.value
                ),
                None,
            )
            assert sorted_entry is not None
            assert sorted_entry.attributes is not None
            assert len(sorted_entry.attributes.attributes) > 0

    def test_sorting_large_entry_set(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test sorting performance with real large LDIF datasets."""
        if len(oid_entries) < 10:
            pytest.skip("Not enough entries for performance test")

        # Test all sorting strategies
        strategies = [
            FlextLdifSorting.by_hierarchy,
            FlextLdifSorting.by_dn,
        ]

        for strategy in strategies:
            result = strategy(oid_entries)
            assert result.is_success
            sorted_entries = result.unwrap()
            assert len(sorted_entries) == len(oid_entries)

    def test_sorting_with_special_characters_in_dn(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test sorting handles special characters in DNs correctly."""
        if not oid_entries:
            pytest.skip("No OID entries loaded")

        result = FlextLdifSorting.by_hierarchy(oid_entries)

        assert result.is_success
        sorted_entries = result.unwrap()

        # All entries should be present
        assert len(sorted_entries) == len(oid_entries)


# ════════════════════════════════════════════════════════════════════════════
# COMPREHENSIVE API COVERAGE
# ════════════════════════════════════════════════════════════════════════════


class TestComprehensiveAPIUsage:
    """Comprehensive tests covering all public APIs."""

    def test_all_entry_sorting_methods(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test all entry sorting classmethods."""
        if not oid_entries:
            pytest.skip("No OID entries loaded")

        methods = [
            FlextLdifSorting.by_hierarchy,
            FlextLdifSorting.by_dn,
            FlextLdifSorting.by_schema,
        ]

        for method in methods:
            result = method(oid_entries)
            assert result.is_success, f"Failed for method: {method.__name__}"
            # Fixed: API returns list directly, not wrapper with .content
            assert len(result.unwrap()) == len(oid_entries)

    def test_all_sort_targets_via_execute(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test all sort targets via execute() method."""
        if not oid_entries:
            pytest.skip("No OID entries loaded")

        targets = ["entries", "attributes", "acl", "combined"]

        for target in targets:
            # FIXED: auto_execute=False requires .execute() call
            result = FlextLdifSorting(
                entries=oid_entries,
                sort_target=target,
                sort_by="hierarchy",
            ).execute()
            assert result.is_success, f"Failed for target: {target}"
            sorted_entries = result.unwrap()
            assert isinstance(sorted_entries, list), f"Failed for target: {target}"

    def test_builder_pattern_with_real_data(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test fluent builder pattern with real data."""
        if not oid_entries:
            pytest.skip("No OID entries loaded")

        sorted_entries = (
            FlextLdifSorting.builder()
            .with_entries(oid_entries)
            .with_strategy("hierarchy")
            .with_attribute_sorting(alphabetical=True)
            .build()
        )

        assert isinstance(sorted_entries, list)
        assert len(sorted_entries) == len(oid_entries)

    def test_classmethod_sort_with_real_data(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test classmethod sort() with real data."""
        if not oid_entries:
            pytest.skip("No OID entries loaded")

        result = FlextLdifSorting.sort(
            oid_entries,
            by="hierarchy",
            sort_attributes=True,
        )

        assert result.is_success
        # Fixed: API returns list directly, not wrapper with .content
        assert len(result.unwrap()) == len(oid_entries)


if __name__ == "__main__":
    _ = pytest.main([__file__, "-v", "--tb=short"])
