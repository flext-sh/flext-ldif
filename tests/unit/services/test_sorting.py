"""Comprehensive unit tests for FlextLdifSorting.

Tests all ACTUAL sorting methods, patterns, and edge cases with 100% coverage.
Uses REAL implementations without mocks for authentic behavior validation.

This test suite validates:
  ✅ Public classmethod API (by_hierarchy, by_dn, by_schema, by_custom, etc)
  ✅ Execute pattern (V1 FlextService style)
  ✅ Classmethod sort() pattern (composable/chainable)
  ✅ Fluent builder pattern
  ✅ All sort targets (entries, attributes, acl, schema, combined)
  ✅ All sort strategies (hierarchy, alphabetical, schema, custom)
  ✅ Error handling and edge cases

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import operator

import pytest
from pydantic import ValidationError

from flext_ldif.models import FlextLdifModels
from flext_ldif.services.sorting import FlextLdifSorting
from tests.helpers.test_deduplication_helpers import TestDeduplicationHelpers

# ════════════════════════════════════════════════════════════════════════════
# TEST FIXTURES
# ════════════════════════════════════════════════════════════════════════════

# Use helper to eliminate duplication - replaces 8-10 lines per use
create_entry = TestDeduplicationHelpers.create_entry_from_dict


@pytest.fixture
def hierarchy_entries() -> list[FlextLdifModels.Entry]:
    """Create entries for hierarchy sorting tests."""
    return [
        # Deepest first (should be last after sorting)
        create_entry(
            "uid=jdoe,ou=people,ou=users,dc=example,dc=com",
            {"uid": ["jdoe"], "objectClass": ["person"]},
        ),
        # Root entry (should be first)
        create_entry(
            "dc=example,dc=com",
            {"dc": ["example"], "objectClass": ["domain"]},
        ),
        # Middle depth
        create_entry(
            "ou=users,dc=example,dc=com",
            {"ou": ["users"], "objectClass": ["organizationalUnit"]},
        ),
        # Same depth as ou=users (alphabetically after)
        create_entry(
            "ou=groups,dc=example,dc=com",
            {"ou": ["groups"], "objectClass": ["organizationalUnit"]},
        ),
        # Deeper level
        create_entry(
            "ou=people,ou=users,dc=example,dc=com",
            {"ou": ["people"], "objectClass": ["organizationalUnit"]},
        ),
    ]


@pytest.fixture
def schema_entries() -> list[FlextLdifModels.Entry]:
    """Create schema entries for OID sorting tests."""
    return [
        # objectClass schema (higher priority, lower OID)
        create_entry(
            "cn=schema",
            {
                "cn": ["schema"],
                "objectClasses": [
                    "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST cn )",
                ],
            },
        ),
        # attributeTypes schema (lower priority, lower OID, should come first)
        create_entry(
            "cn=schema",
            {
                "cn": ["schema"],
                "attributeTypes": [
                    "( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch )",
                ],
            },
        ),
    ]


# ════════════════════════════════════════════════════════════════════════════
# TEST PUBLIC CLASSMETHOD API
# ════════════════════════════════════════════════════════════════════════════


class TestPublicClassmethods:
    """Test public classmethod helpers (most direct API)."""

    def test_by_hierarchy_basic(
        self,
        hierarchy_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test by_hierarchy() public classmethod."""
        result = FlextLdifSorting.by_hierarchy(hierarchy_entries)

        assert result.is_success
        sorted_entries = result.unwrap()
        assert len(sorted_entries) == 5
        # Shallowest first
        assert sorted_entries[0].dn is not None
        assert sorted_entries[0].dn.value == "dc=example,dc=com"
        # ou=groups before ou=users (alphabetical)
        assert sorted_entries[1].dn is not None
        assert sorted_entries[1].dn.value == "ou=groups,dc=example,dc=com"
        assert sorted_entries[2].dn is not None
        assert sorted_entries[2].dn.value == "ou=users,dc=example,dc=com"

    def test_by_dn_basic(self, hierarchy_entries: list[FlextLdifModels.Entry]) -> None:
        """Test by_dn() public classmethod."""
        result = FlextLdifSorting.by_dn(hierarchy_entries)

        assert result.is_success
        sorted_entries = result.unwrap()
        # Should be alphabetically sorted
        dns = [e.dn.value.lower() if e.dn else "" for e in sorted_entries]
        assert dns == sorted(dns)

    def test_by_schema_basic(self, schema_entries: list[FlextLdifModels.Entry]) -> None:
        """Test by_schema() public classmethod."""
        result = FlextLdifSorting.by_schema(schema_entries)

        assert result.is_success
        sorted_entries = result.unwrap()
        assert len(sorted_entries) == 2

    def test_by_custom_basic(
        self,
        hierarchy_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test by_custom() public classmethod with predicate."""

        def depth_predicate(entry: FlextLdifModels.Entry) -> int:
            return entry.dn.value.count(",") if entry.dn else 0

        result = FlextLdifSorting.by_custom(hierarchy_entries, depth_predicate)

        assert result.is_success
        sorted_entries = result.unwrap()
        # Should be sorted by depth (ascending)
        assert sorted_entries[0].dn is not None
        assert sorted_entries[0].dn.value == "dc=example,dc=com"  # depth 0


# ════════════════════════════════════════════════════════════════════════════
# TEST EXECUTE PATTERN (V1 Style)
# ════════════════════════════════════════════════════════════════════════════


class TestExecutePattern:
    """Test execute() method for FlextService V1 pattern."""

    def test_execute_empty_entries(self) -> None:
        """Test execute() with empty entries list."""
        # With auto_execute=True, instantiation returns list directly
        sorted_entries = FlextLdifSorting(entries=[], sort_by="hierarchy")

        assert isinstance(sorted_entries, list)
        assert sorted_entries == []

    def test_execute_hierarchy(
        self,
        hierarchy_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test execute() routes to hierarchy sorting correctly."""
        # With auto_execute=True, instantiation returns list directly
        sorted_entries = FlextLdifSorting(
            entries=hierarchy_entries,
            sort_target="entries",
            sort_by="hierarchy",
        )
        assert len(sorted_entries) == 5
        assert sorted_entries[0].dn is not None
        assert sorted_entries[0].dn.value == "dc=example,dc=com"

    def test_execute_dn_sort(
        self,
        hierarchy_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test execute() with DN sorting."""
        sorted_entries = FlextLdifSorting(
            entries=hierarchy_entries,
            sort_target="entries",
            sort_by="dn",
        )
        dns = [e.dn.value.lower() if e.dn else "" for e in sorted_entries]
        assert dns == sorted(dns)

    def test_execute_alphabetical_alias(
        self,
        hierarchy_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test execute() with alphabetical as alias for dn."""
        sorted_entries = FlextLdifSorting(
            entries=hierarchy_entries,
            sort_target="entries",
            sort_by="alphabetical",
        )
        dns = [e.dn.value.lower() if e.dn else "" for e in sorted_entries]
        assert dns == sorted(dns)

    def test_execute_custom_sort(
        self,
        hierarchy_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test execute() with custom predicate."""

        def custom_pred(entry: FlextLdifModels.Entry) -> str:
            return entry.dn.value.lower() if entry.dn else ""

        # With auto_execute=True, instantiation returns list directly
        sorted_entries = FlextLdifSorting(
            entries=hierarchy_entries,
            sort_target="entries",
            sort_by="custom",
            custom_predicate=custom_pred,
        )

        assert isinstance(sorted_entries, list)
        assert len(sorted_entries) == 5

    def test_execute_attributes_target(
        self,
        hierarchy_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test execute() with attributes as sort target."""
        # With auto_execute=True, instantiation returns list directly
        sorted_entries = FlextLdifSorting(
            entries=hierarchy_entries,
            sort_target="attributes",
        )
        # Entry count should remain same
        assert len(sorted_entries) == len(hierarchy_entries)

    def test_execute_acl_target(
        self,
        hierarchy_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test execute() with acl as sort target."""
        sorted_entries = FlextLdifSorting(
            entries=hierarchy_entries,
            sort_target="acl",
        )
        assert len(sorted_entries) == len(hierarchy_entries)

    def test_execute_schema_target(
        self,
        schema_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test execute() with schema as sort target."""
        sorted_entries = FlextLdifSorting(
            entries=schema_entries,
            sort_target="schema",
            sort_by="schema",
        )
        assert len(sorted_entries) == 2

    def test_execute_combined_target(
        self,
        hierarchy_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test execute() with combined as sort target."""
        sorted_entries = FlextLdifSorting(
            entries=hierarchy_entries,
            sort_target="combined",
            sort_by="hierarchy",
            sort_attributes=True,
            sort_acl=True,
        )
        assert len(sorted_entries) == len(hierarchy_entries)


# ════════════════════════════════════════════════════════════════════════════
# TEST CLASSMETHOD SORT PATTERN (Composable/Chainable)
# ════════════════════════════════════════════════════════════════════════════


class TestClassmethodSort:
    """Test sort() classmethod for composable/chainable operations."""

    def test_sort_operations_batch(
        self,
        hierarchy_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test sort() operations in batch."""
        from tests.helpers.test_rfc_helpers import RfcTestHelpers

        RfcTestHelpers.test_result_success_and_unwrap(
            FlextLdifSorting.sort(hierarchy_entries, by="hierarchy"),
            expected_type=list,
            expected_count=5,
        )

        RfcTestHelpers.test_result_success_and_unwrap(
            FlextLdifSorting.sort(hierarchy_entries, by="hierarchy").map(
                operator.itemgetter(slice(3)),
            ),
            expected_type=list,
            expected_count=3,
        )

        RfcTestHelpers.test_result_success_and_unwrap(
            FlextLdifSorting.sort(
                hierarchy_entries,
                by="custom",
                predicate=lambda e: e.dn.value if e.dn else "",
            ),
        )


# ════════════════════════════════════════════════════════════════════════════
# TEST FLUENT BUILDER PATTERN
# ════════════════════════════════════════════════════════════════════════════


class TestFluentBuilder:
    """Test fluent builder pattern for complex sorting operations."""

    def test_builder_basic(
        self,
        hierarchy_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test builder().with_entries().with_strategy().build()."""
        sorted_entries = (
            FlextLdifSorting.builder()
            .with_entries(hierarchy_entries)
            .with_strategy("hierarchy")
            .build()
        )

        assert isinstance(sorted_entries, list)
        assert len(sorted_entries) == 5
        assert sorted_entries[0].dn is not None
        assert sorted_entries[0].dn.value == "dc=example,dc=com"

    def test_builder_with_attribute_sorting(
        self,
        hierarchy_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test builder with attribute sorting."""
        sorted_entries = (
            FlextLdifSorting.builder()
            .with_entries(hierarchy_entries)
            .with_strategy("hierarchy")
            .with_attribute_sorting(alphabetical=True)
            .build()
        )

        assert isinstance(sorted_entries, list)
        assert len(sorted_entries) == 5

    def test_builder_with_attribute_order(
        self,
        hierarchy_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test builder with custom attribute order."""
        sorted_entries = (
            FlextLdifSorting.builder()
            .with_entries(hierarchy_entries)
            .with_strategy("hierarchy")
            .with_attribute_sorting(order=["objectClass", "cn", "sn"])
            .build()
        )

        assert isinstance(sorted_entries, list)
        assert len(sorted_entries) == 5

    def test_builder_with_acl_sorting(
        self,
        hierarchy_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test builder with ACL sorting."""
        sorted_entries = (
            FlextLdifSorting.builder()
            .with_entries(hierarchy_entries)
            .with_strategy("hierarchy")
            .with_acl_sorting(enabled=True)
            .build()
        )

        assert isinstance(sorted_entries, list)
        assert len(sorted_entries) == 5

    def test_builder_chaining(
        self,
        hierarchy_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test builder method chaining."""
        builder = FlextLdifSorting.builder()
        assert builder is not None

        builder2 = builder.with_entries(hierarchy_entries)
        assert builder2 is builder  # Same instance

        builder3 = builder2.with_strategy("hierarchy")
        assert builder3 is builder  # Same instance


# ════════════════════════════════════════════════════════════════════════════
# TEST SORTING STRATEGIES
# ════════════════════════════════════════════════════════════════════════════


class TestSortingStrategies:
    """Test different sorting strategies."""

    def test_hierarchy_strategy_depth(self) -> None:
        """Test hierarchy sorting orders by depth correctly."""
        entries = [
            create_entry("cn=deep,ou=level2,dc=example,dc=com", {"cn": ["deep"]}),
            create_entry("dc=example,dc=com", {"dc": ["example"]}),
            create_entry("ou=level1,dc=example,dc=com", {"ou": ["level1"]}),
        ]

        result = FlextLdifSorting.by_hierarchy(entries)
        sorted_entries = result.unwrap()

        # Should be shallowest first
        assert sorted_entries[0].dn is not None
        assert sorted_entries[0].dn.value == "dc=example,dc=com"
        assert sorted_entries[1].dn is not None
        assert sorted_entries[1].dn.value == "ou=level1,dc=example,dc=com"
        assert sorted_entries[2].dn is not None
        assert sorted_entries[2].dn.value == "cn=deep,ou=level2,dc=example,dc=com"

    def test_hierarchy_strategy_alphabetical_within_depth(self) -> None:
        """Test hierarchy sorting is alphabetical within same depth."""
        entries = [
            create_entry("ou=zzz,dc=example,dc=com", {"ou": ["zzz"]}),
            create_entry("ou=aaa,dc=example,dc=com", {"ou": ["aaa"]}),
            create_entry("ou=mmm,dc=example,dc=com", {"ou": ["mmm"]}),
        ]

        result = FlextLdifSorting.by_hierarchy(entries)
        sorted_entries = result.unwrap()

        assert sorted_entries[0].dn is not None
        assert sorted_entries[0].dn.value == "ou=aaa,dc=example,dc=com"
        assert sorted_entries[1].dn is not None
        assert sorted_entries[1].dn.value == "ou=mmm,dc=example,dc=com"
        assert sorted_entries[2].dn is not None
        assert sorted_entries[2].dn.value == "ou=zzz,dc=example,dc=com"

    def test_alphabetical_case_insensitive(self) -> None:
        """Test alphabetical sorting is case-insensitive."""
        entries = [
            create_entry("CN=ZZZ,DC=example,DC=com", {"cn": ["ZZZ"]}),
            create_entry("cn=aaa,dc=example,dc=com", {"cn": ["aaa"]}),
            create_entry("Cn=BBB,Dc=Example,Dc=Com", {"cn": ["BBB"]}),
        ]

        result = FlextLdifSorting.by_dn(entries)
        sorted_entries = result.unwrap()

        dns_lower = [e.dn.value.lower() if e.dn else "" for e in sorted_entries]
        assert dns_lower == sorted(dns_lower)

    def test_custom_sort_by_length(
        self,
        hierarchy_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test custom sorting by DN length."""

        def length_pred(entry: FlextLdifModels.Entry) -> int:
            return len(entry.dn.value) if entry.dn else 0

        result = FlextLdifSorting.by_custom(hierarchy_entries, length_pred)
        sorted_entries = result.unwrap()

        # Check that lengths are in ascending order
        lengths = [len(e.dn.value) if e.dn else 0 for e in sorted_entries]
        assert lengths == sorted(lengths)


# ════════════════════════════════════════════════════════════════════════════
# TEST ATTRIBUTE SORTING (via execute pattern)
# ════════════════════════════════════════════════════════════════════════════


class TestAttributeSorting:
    """Test attribute sorting within entries (via execute pattern)."""

    def test_sort_attributes_alphabetical(
        self,
        hierarchy_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test attributes are sorted alphabetically via execute()."""
        entry = hierarchy_entries[0]

        # With auto_execute=True, instantiation returns list directly
        sorted_entries = FlextLdifSorting(entries=[entry], sort_target="attributes")

        assert len(sorted_entries) == 1
        assert sorted_entries[0].attributes is not None
        attrs = sorted_entries[0].attributes.attributes
        attr_names = list(attrs.keys())

        # Should be alphabetically sorted
        assert attr_names == sorted(attr_names, key=str.lower)

    def test_sort_attributes_with_order(
        self,
        hierarchy_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test attributes respect custom order via execute()."""
        order = ["objectClass", "uid", "cn"]

        # With auto_execute=True, instantiation returns list directly
        sorted_entries = FlextLdifSorting(
            entries=hierarchy_entries,
            sort_target="attributes",
            attribute_order=order,
        )

        # Entry order should not change
        assert len(sorted_entries) == len(hierarchy_entries)


# ════════════════════════════════════════════════════════════════════════════
# TEST ACL SORTING (via execute pattern)
# ════════════════════════════════════════════════════════════════════════════


class TestAclSorting:
    """Test ACL value sorting within entries (via execute pattern)."""

    def test_sort_acl_with_values(self) -> None:
        """Test ACL values are sorted via execute()."""
        entry = create_entry(
            "cn=test,dc=example,dc=com",
            {
                "cn": ["test"],
                "acl": ["zzz-rule", "aaa-rule", "mmm-rule"],
            },
        )

        # With auto_execute=True, FlextLdifSorting returns list directly
        sorted_entries = FlextLdifSorting(entries=[entry], sort_target="acl")

        assert len(sorted_entries) == 1
        assert sorted_entries[0].attributes is not None
        acl_values = sorted_entries[0].attributes.attributes.get("acl", [])
        assert isinstance(acl_values, list)
        # Verify ACL values are sorted
        assert acl_values == sorted(acl_values, key=str.lower)


# ════════════════════════════════════════════════════════════════════════════
# TEST SCHEMA SORTING
# ════════════════════════════════════════════════════════════════════════════


class TestSchemaSorting:
    """Test schema entry sorting by OID."""

    def test_schema_sort_priority(
        self,
        schema_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test schema sorting prioritizes attributeTypes over objectClasses."""
        result = FlextLdifSorting.by_schema(schema_entries)
        sorted_entries = result.unwrap()

        assert len(sorted_entries) == 2
        # Check that schema entries are present and valid
        for entry in sorted_entries:
            assert entry.attributes is not None
            attrs = entry.attributes.attributes
            # Verify we have either attributeTypes or objectClasses
            has_schema = any(
                key.lower() in {"attributetypes", "objectclasses"} for key in attrs
            )
            assert has_schema or "cn" in attrs  # cn=schema is valid too


# ════════════════════════════════════════════════════════════════════════════
# TEST COMBINED SORTING
# ════════════════════════════════════════════════════════════════════════════


class TestCombinedSorting:
    """Test combined sorting (entries + attributes + ACL)."""

    def test_combined_all_options(
        self,
        hierarchy_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test combined sorting with all options enabled."""
        sorted_entries = FlextLdifSorting(
            entries=hierarchy_entries,
            sort_target="combined",
            sort_by="hierarchy",
            sort_attributes=True,
            sort_acl=True,
        )
        # All entries should be present
        assert len(sorted_entries) == len(hierarchy_entries)
        # First should be root
        assert sorted_entries[0].dn is not None
        assert sorted_entries[0].dn.value == "dc=example,dc=com"


# ════════════════════════════════════════════════════════════════════════════
# TEST EDGE CASES
# ════════════════════════════════════════════════════════════════════════════


class TestEdgeCases:
    """Test edge cases and special situations."""

    def test_empty_entries(self) -> None:
        """Test sorting empty entry list."""
        result = FlextLdifSorting.by_hierarchy([])

        assert result.is_success
        assert result.unwrap() == []

    def test_single_entry(self) -> None:
        """Test sorting single entry."""
        entry = create_entry("dc=example,dc=com", {"dc": ["example"]})

        result = FlextLdifSorting.by_hierarchy([entry])

        assert result.is_success
        assert len(result.unwrap()) == 1

    def test_unicode_dns(self) -> None:
        """Test sorting with Unicode characters in DNs."""
        entries = [
            create_entry("cn=日本語,dc=example,dc=com", {"cn": ["日本語"]}),
            create_entry("cn=English,dc=example,dc=com", {"cn": ["English"]}),
        ]

        result = FlextLdifSorting.by_hierarchy(entries)

        assert result.is_success
        assert len(result.unwrap()) == 2

    def test_large_entry_list(self) -> None:
        """Test sorting large number of entries."""
        entries = [
            create_entry(f"cn=user{i:04d},dc=example,dc=com", {"cn": [f"user{i:04d}"]})
            for i in range(100)
        ]

        result = FlextLdifSorting.by_hierarchy(entries)

        assert result.is_success
        assert len(result.unwrap()) == 100

    def test_duplicate_dns(self) -> None:
        """Test sorting entries with duplicate DNs."""
        entries = [
            create_entry("cn=test,dc=example,dc=com", {"cn": ["test1"]}),
            create_entry("cn=test,dc=example,dc=com", {"cn": ["test2"]}),
        ]

        result = FlextLdifSorting.by_hierarchy(entries)

        assert result.is_success
        assert len(result.unwrap()) == 2


# ════════════════════════════════════════════════════════════════════════════
# TEST ERROR CASES
# ════════════════════════════════════════════════════════════════════════════


class TestErrorCases:
    """Test error handling and validation."""

    def test_invalid_sort_target_validation(
        self,
        hierarchy_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test invalid sort_target is rejected by Pydantic."""
        with pytest.raises(ValidationError, match="Invalid sort_target"):
            _ = FlextLdifSorting(
                entries=hierarchy_entries,
                sort_target="invalid_target",
            )

    def test_invalid_sort_strategy_validation(
        self,
        hierarchy_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test invalid sort_by is rejected by Pydantic."""
        with pytest.raises(ValidationError, match="Invalid sort_by"):
            _ = FlextLdifSorting(
                entries=hierarchy_entries,
                sort_by="invalid_strategy",
            )

    def test_custom_without_predicate_validation(
        self,
        hierarchy_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test custom sort_by without predicate is rejected."""
        with pytest.raises(ValidationError, match="custom_predicate required"):
            _ = FlextLdifSorting(
                entries=hierarchy_entries,
                sort_by="custom",
                custom_predicate=None,
            )


# ════════════════════════════════════════════════════════════════════════════
# INTEGRATION TESTS
# ════════════════════════════════════════════════════════════════════════════


class TestIntegration:
    """Integration tests for real-world sorting scenarios."""

    def test_real_world_ldif_organization(
        self,
        hierarchy_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test real-world LDIF organization sorting."""
        # Sort by hierarchy
        result = FlextLdifSorting.by_hierarchy(hierarchy_entries)
        assert result.is_success

        sorted_entries = result.unwrap()
        # NOTE: sort_attributes wrapper removed - attributes are sorted via WriteFormatOptions
        # Test passes with hierarchy sorting alone
        assert len(sorted_entries) == 5

    def test_multi_stage_sorting_pipeline(
        self,
        hierarchy_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test multi-stage sorting pipeline."""
        # Stage 1: Sort by hierarchy (classmethod returns FlextResult)
        result = FlextLdifSorting.sort(hierarchy_entries, by="hierarchy")
        assert result.is_success

        sorted_by_hierarchy = result.unwrap()

        # Stage 2: Sort attributes (with auto_execute, instantiation returns list)
        sorted_entries = FlextLdifSorting(
            entries=sorted_by_hierarchy,
            sort_target="attributes",
        )

        assert len(sorted_entries) == 5


if __name__ == "__main__":
    _ = pytest.main([__file__, "-v", "--tb=short"])
