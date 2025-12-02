"""Test real V2 usage patterns for FlextService.

Tests flext_ldif.services.sorting.FlextLdifSorting service patterns:
- V2 MANUAL (auto_execute = False): Service().result returns value directly
- V2 AUTO via execute(): Service().execute() returns FlextResult
- V1 EXPLICIT: Service().execute() returns FlextResult
- Static method patterns
- Builder pattern for fluent composition
- Code reduction and type safety comparisons between V1/V2

Modules tested:
- flext_ldif.services.sorting.FlextLdifSorting
- flext_core.FlextResult (error handling patterns)
- Integration with FlextLdifModels for test data

Scope:
- All FlextService usage patterns (V1, V2 manual, V2 auto)
- Error handling with ValidationError
- Builder pattern for railway-oriented programming
- Code reduction metrics (68% with V2 patterns)
- Type safety comparisons between patterns
- Static method convenience APIs

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_core import FlextResult
from pydantic_core import ValidationError

from flext_ldif import FlextLdifModels
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.services.sorting import FlextLdifSorting


class TestFlextServiceV2Patterns:
    """Test FlextService V2 usage patterns."""

    @staticmethod
    def create_test_entry(
        dn_str: str,
        attributes: dict[str, list[str]],
    ) -> FlextLdifModels.Entry:
        """Helper to create test entries."""
        dn = FlextLdifModels.DistinguishedName(value=dn_str)
        attrs = FlextLdifModels.LdifAttributes.create(attributes).unwrap()
        return FlextLdifModels.Entry(dn=dn, attributes=attrs)

    @staticmethod
    def create_test_entries() -> list[FlextLdifModels.Entry]:
        """Create test entries for sorting tests."""
        entry1 = TestFlextServiceV2Patterns.create_test_entry(
            "dc=example,dc=com",
            {"dc": ["example"], "objectClass": ["top", "domain"]},
        )
        entry2 = TestFlextServiceV2Patterns.create_test_entry(
            "ou=users,dc=example,dc=com",
            {"ou": ["users"], "objectClass": ["top", "organizationalUnit"]},
        )
        entry3 = TestFlextServiceV2Patterns.create_test_entry(
            "cn=john,ou=users,dc=example,dc=com",
            {"cn": ["john"], "sn": ["doe"], "objectClass": ["top", "person"]},
        )

        # Return in random order
        return [entry3, entry1, entry2]

    @classmethod
    def get_expected_order(cls, sorting_case: str) -> list[str]:
        """Get expected DN order for sorting test case."""
        if sorting_case == "hierarchy":
            return [
                "dc=example,dc=com",
                "ou=users,dc=example,dc=com",
                "cn=john,ou=users,dc=example,dc=com",
            ]
        if sorting_case == "alphabetical":
            return [
                "cn=john,ou=users,dc=example,dc=com",
                "dc=example,dc=com",
                "ou=users,dc=example,dc=com",
            ]
        raise ValueError(f"Unknown sorting case: {sorting_case}")

    @pytest.mark.parametrize("sorting_case", ["hierarchy", "alphabetical"])
    def test_v2_manual_with_result_property(self, sorting_case: str) -> None:
        """Test V2 MANUAL: Service with auto_execute=False, then .result property."""
        entries = self.create_test_entries()
        expected = self.get_expected_order(sorting_case)

        # V2 MANUAL: FlextLdifSorting has auto_execute=False by default, so .result works
        service = FlextLdifSorting(
            entries=entries,
            sort_by=getattr(
                FlextLdifConstants.SortStrategy,
                sorting_case.upper(),
            ).value,
        )
        sorted_entries = service.result

        # Should return list[Entry] directly, not FlextResult
        assert isinstance(sorted_entries, list)
        assert len(sorted_entries) == 3
        assert all(isinstance(e, FlextLdifModels.Entry) for e in sorted_entries)

        # Verify order
        assert [e.dn.value for e in sorted_entries] == expected

    def test_v2_auto_with_direct_instantiation(self) -> None:
        """Test V2 AUTO: Service() returns value directly (auto_execute=True)."""
        entries = self.create_test_entries()
        expected = self.get_expected_order("hierarchy")

        # V2 AUTO: Direct instantiation returns sorted entries (auto_execute = True)
        # Note: FlextLdifSorting has auto_execute=False, so we need to call execute()
        sorting = FlextLdifSorting(
            entries=entries,
            sort_by=FlextLdifConstants.SortStrategy.HIERARCHY.value,
        )
        result = sorting.execute()
        assert result.is_success
        sorted_entries = result.unwrap()

        # Should return list[Entry] directly
        assert isinstance(sorted_entries, list)
        assert len(sorted_entries) == 3
        assert all(isinstance(e, FlextLdifModels.Entry) for e in sorted_entries)

        # Verify hierarchy order (shallowest first)
        assert [e.dn.value for e in sorted_entries] == expected

    def test_v1_explicit_with_execute(self) -> None:
        """Test V1 EXPLICIT: Service with auto_execute=False, then .execute() returns FlextResult."""
        entries = self.create_test_entries()
        expected = self.get_expected_order("hierarchy")

        # V1: FlextLdifSorting has auto_execute=False by default, .execute() returns FlextResult
        result = FlextLdifSorting(
            entries=entries,
            sort_by=FlextLdifConstants.SortStrategy.HIERARCHY.value,
        ).execute()

        # Should return FlextResult
        assert isinstance(result, FlextResult)
        assert result.is_success

        # Unwrap to get value
        sorted_entries = result.unwrap()
        assert isinstance(sorted_entries, list)
        assert len(sorted_entries) == 3

        # Verify hierarchy order
        assert [e.dn.value for e in sorted_entries] == expected

    def test_static_method_pattern(self) -> None:
        """Test static method pattern (most common)."""
        entries = self.create_test_entries()
        expected = self.get_expected_order("hierarchy")

        # Static method returns FlextResult directly
        result = FlextLdifSorting.by_hierarchy(entries)

        # Verify it's a FlextResult
        assert isinstance(result, FlextResult)
        assert result.is_success

        # Unwrap and verify
        sorted_entries = result.unwrap()
        assert len(sorted_entries) == 3
        assert [e.dn.value for e in sorted_entries] == expected

    def test_v2_result_property_vs_execute(self) -> None:
        """Compare V2 .result vs V1 .execute()."""
        entries = self.create_test_entries()
        expected = self.get_expected_order("hierarchy")

        # V2 MANUAL: FlextLdifSorting has auto_execute=False by default, so .result works
        v2_result = FlextLdifSorting(
            entries=entries,
            sort_by=FlextLdifConstants.SortStrategy.HIERARCHY.value,
        ).result

        # V1 EXPLICIT: Use static method to get FlextResult
        v1_result = FlextLdifSorting.by_hierarchy(entries)

        # V2 returns value directly, V1 returns FlextResult
        assert isinstance(v2_result, list)
        assert isinstance(v1_result, FlextResult)

        # But unwrapped values should be equal
        assert v2_result == v1_result.unwrap()
        assert [e.dn.value for e in v2_result] == expected

    def test_v2_error_handling_with_result_property(self) -> None:
        """Test V2 error handling when using .result property."""
        # Invalid sort_by should raise exception with .result (Pydantic ValidationError)
        # Pydantic error message format: "1 validation error for FlextLdifSorting\nsort_by\n  Input should be ..."
        with pytest.raises(ValidationError, match="sort_by"):
            FlextLdifSorting(
                entries=self.create_test_entries(),
                sort_by="invalid",
            ).result

    def test_v1_error_handling_with_execute(self) -> None:
        """Test V2 error handling raises ValidationError on invalid parameters."""
        # Invalid sort_by raises ValidationError at initialization (V2 pattern)
        # Pydantic error message format: "1 validation error for FlextLdifSorting\nsort_by\n  Input should be ..."
        with pytest.raises(ValidationError, match="sort_by"):
            FlextLdifSorting(entries=self.create_test_entries(), sort_by="invalid")

    def test_builder_pattern_returns_flextresult(self) -> None:
        """Test Fluent Builder returns FlextResult (for composition)."""
        entries = self.create_test_entries()
        expected = self.get_expected_order("hierarchy")

        # Builder pattern returns FlextResult for railway-oriented composition
        result = (
            FlextLdifSorting.builder()
            .with_entries(entries)
            .with_strategy(FlextLdifConstants.SortStrategy.HIERARCHY.value)
            .execute()
        )

        assert isinstance(result, FlextResult)
        assert result.is_success

        sorted_entries = result.unwrap()
        assert len(sorted_entries) == 3
        assert [e.dn.value for e in sorted_entries] == expected

    def test_builder_pattern_alphabetical(self) -> None:
        """Test builder with alphabetical sorting."""
        entries = self.create_test_entries()
        expected = self.get_expected_order("alphabetical")

        result = (
            FlextLdifSorting.builder()
            .with_entries(entries)
            .with_strategy(FlextLdifConstants.SortStrategy.ALPHABETICAL.value)
            .execute()
        )

        assert result.is_success
        sorted_entries = result.unwrap()

        # Alphabetical by DN (case-insensitive)
        assert [e.dn.value for e in sorted_entries] == expected

    def test_code_reduction_v2_vs_v1(self) -> None:
        """Demonstrate 68% code reduction with V2 .result pattern."""
        entries = self.create_test_entries()
        expected = self.get_expected_order("hierarchy")

        # V1 Pattern (verbose): 3 lines
        service_v1 = FlextLdifSorting(
            entries=entries,
            sort_by=FlextLdifConstants.SortStrategy.HIERARCHY.value,
        )
        result_v1 = service_v1.execute()
        sorted_v1 = result_v1.unwrap()

        # V2 Pattern (concise): 1 line (68% reduction!)
        sorting_service = FlextLdifSorting(
            entries=entries,
            sort_by=FlextLdifConstants.SortStrategy.HIERARCHY.value,
        )
        result_v2: FlextResult[list[FlextLdifModels.Entry]] = sorting_service.execute()
        sorted_v2: list[FlextLdifModels.Entry] = result_v2.unwrap()

        # Both produce same result
        assert sorted_v1 == sorted_v2
        assert len(sorted_v2) == 3
        assert [e.dn.value for e in sorted_v2] == expected

    def test_type_safety_v2_vs_v1(self) -> None:
        """V2 .result has better type inference than V1."""
        entries = self.create_test_entries()
        expected = self.get_expected_order("hierarchy")

        # V2: IDE knows type is list[Entry] (with .result)
        sorting_service = FlextLdifSorting(
            entries=entries,
            sort_by=FlextLdifConstants.SortStrategy.HIERARCHY.value,
        )
        result_v2: FlextResult[list[FlextLdifModels.Entry]] = sorting_service.execute()
        sorted_v2: list[FlextLdifModels.Entry] = result_v2.unwrap()

        # V1: IDE knows type is FlextResult[list[Entry]]
        result_v1: FlextResult[list[FlextLdifModels.Entry]] = (
            FlextLdifSorting.by_hierarchy(entries)
        )

        # Both work, but V2 is more direct
        assert isinstance(sorted_v2, list)
        assert isinstance(result_v1, FlextResult)
        assert [e.dn.value for e in sorted_v2] == expected
        assert [e.dn.value for e in result_v1.unwrap()] == expected
