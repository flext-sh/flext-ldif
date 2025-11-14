"""Test real V2 usage patterns for FlextService.

Demonstrates the 3 usage patterns:
1. V2 AUTO (auto_execute = True): Service() returns value directly
2. V2 MANUAL (auto_execute = False): Service().result returns value
3. V1 EXPLICIT: Service().execute() returns FlextResult

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldif.models import FlextLdifModels
from flext_ldif.services.sorting import FlextLdifSorting


def create_test_entry(
    dn_str: str,
    attributes: dict[str, list[str]],
) -> FlextLdifModels.Entry:
    """Helper to create test entries."""
    dn = FlextLdifModels.DistinguishedName(value=dn_str)
    attrs = FlextLdifModels.LdifAttributes.create(attributes).unwrap()
    return FlextLdifModels.Entry(dn=dn, attributes=attrs)


def create_test_entries() -> list[FlextLdifModels.Entry]:
    """Create test entries for sorting tests."""
    entry1 = create_test_entry(
        "dc=example,dc=com",
        {"dc": ["example"], "objectClass": ["top", "domain"]},
    )
    entry2 = create_test_entry(
        "ou=users,dc=example,dc=com",
        {"ou": ["users"], "objectClass": ["top", "organizationalUnit"]},
    )
    entry3 = create_test_entry(
        "cn=john,ou=users,dc=example,dc=com",
        {"cn": ["john"], "sn": ["doe"], "objectClass": ["top", "person"]},
    )

    # Return in random order
    return [entry3, entry1, entry2]


class TestFlextServiceV2Patterns:
    """Test FlextService V2 usage patterns."""

    def test_v2_manual_with_result_property(self) -> None:
        """Test V2 MANUAL: Service.v1().result returns value directly."""
        entries = create_test_entries()

        # V2 MANUAL: Use .v1() to disable auto_execute, then .result property
        service = FlextLdifSorting.v1(entries=entries, sort_by="hierarchy")
        sorted_entries = service.result

        # Should return list[Entry] directly, not FlextResult
        assert isinstance(sorted_entries, list)
        assert len(sorted_entries) == 3
        assert all(isinstance(e, FlextLdifModels.Entry) for e in sorted_entries)

        # Verify hierarchy order (shallowest first)
        assert sorted_entries[0].dn.value == "dc=example,dc=com"
        assert sorted_entries[1].dn.value == "ou=users,dc=example,dc=com"
        assert sorted_entries[2].dn.value == "cn=john,ou=users,dc=example,dc=com"

    def test_v2_auto_with_direct_instantiation(self) -> None:
        """Test V2 AUTO: Service() returns value directly (auto_execute=True)."""
        entries = create_test_entries()

        # V2 AUTO: Direct instantiation returns sorted entries (auto_execute = True)
        sorted_entries = FlextLdifSorting(entries=entries, sort_by="hierarchy")

        # Should return list[Entry] directly, not FlextResult or service instance
        assert isinstance(sorted_entries, list)
        assert len(sorted_entries) == 3
        assert all(isinstance(e, FlextLdifModels.Entry) for e in sorted_entries)

        # Verify hierarchy order (shallowest first)
        assert sorted_entries[0].dn.value == "dc=example,dc=com"
        assert sorted_entries[1].dn.value == "ou=users,dc=example,dc=com"
        assert sorted_entries[2].dn.value == "cn=john,ou=users,dc=example,dc=com"

    def test_v1_explicit_with_execute(self) -> None:
        """Test V1 EXPLICIT: Service.v1().execute() returns FlextResult."""
        entries = create_test_entries()

        # V1: Use .v1() to disable auto_execute, then .execute() explicitly for FlextResult
        result = FlextLdifSorting.v1(entries=entries, sort_by="hierarchy").execute()

        # Should return FlextResult
        assert isinstance(result, FlextResult)
        assert result.is_success

        # Unwrap to get value
        sorted_entries = result.unwrap()
        assert isinstance(sorted_entries, list)
        assert len(sorted_entries) == 3

        # Verify hierarchy order
        assert sorted_entries[0].dn.value == "dc=example,dc=com"
        assert sorted_entries[1].dn.value == "ou=users,dc=example,dc=com"
        assert sorted_entries[2].dn.value == "cn=john,ou=users,dc=example,dc=com"

    def test_static_method_pattern(self) -> None:
        """Test static method pattern (most common)."""
        entries = create_test_entries()

        # Static method returns FlextResult directly
        result = FlextLdifSorting.by_hierarchy(entries)

        # Verify it's a FlextResult
        assert isinstance(result, FlextResult)
        assert result.is_success

        # Unwrap and verify
        sorted_entries = result.unwrap()
        assert len(sorted_entries) == 3
        assert sorted_entries[0].dn.value == "dc=example,dc=com"

    def test_v2_result_property_vs_execute(self) -> None:
        """Compare V2 .result vs V1 .execute()."""
        entries = create_test_entries()

        # V2 MANUAL: Use .v1() to get service instance, then .result
        v2_result = FlextLdifSorting.v1(entries=entries, sort_by="hierarchy").result

        # V1 EXPLICIT: Use .with_result() to get FlextResult
        v1_result = FlextLdifSorting.with_result(entries=entries, sort_by="hierarchy")

        # V2 returns value directly, V1 returns FlextResult
        assert isinstance(v2_result, list)
        assert isinstance(v1_result, FlextResult)

        # But unwrapped values should be equal
        assert v2_result == v1_result.unwrap()

    def test_v2_error_handling_with_result_property(self) -> None:
        """Test V2 error handling when using .result property."""
        # Invalid sort_by should raise exception with .result (Pydantic ValidationError)
        from pydantic_core import ValidationError

        with pytest.raises(ValidationError, match="Invalid sort_by"):
            FlextLdifSorting(entries=create_test_entries(), sort_by="invalid").result

    def test_v1_error_handling_with_execute(self) -> None:
        """Test V2 error handling raises ValidationError on invalid parameters."""
        # Invalid sort_by raises ValidationError at initialization (V2 pattern)
        from pydantic_core import ValidationError

        with pytest.raises(ValidationError, match="Invalid sort_by"):
            FlextLdifSorting(entries=create_test_entries(), sort_by="invalid")


class TestFlextServiceV2BuilderPattern:
    """Test FlextService V2 with Fluent Builder Pattern."""

    def test_builder_pattern_returns_flextresult(self) -> None:
        """Test Fluent Builder returns FlextResult (for composition)."""
        entries = create_test_entries()

        # Builder pattern returns FlextResult for railway-oriented composition
        result = (
            FlextLdifSorting.builder()
            .with_entries(entries)
            .with_strategy("hierarchy")
            .execute()
        )

        assert isinstance(result, FlextResult)
        assert result.is_success

        sorted_entries = result.unwrap()
        assert len(sorted_entries) == 3
        assert sorted_entries[0].dn.value == "dc=example,dc=com"

    def test_builder_pattern_alphabetical(self) -> None:
        """Test builder with alphabetical sorting."""
        entries = create_test_entries()

        result = (
            FlextLdifSorting.builder()
            .with_entries(entries)
            .with_strategy("alphabetical")
            .execute()
        )

        assert result.is_success
        sorted_entries = result.unwrap()

        # Alphabetical by DN (case-insensitive)
        assert sorted_entries[0].dn.value == "cn=john,ou=users,dc=example,dc=com"
        assert sorted_entries[1].dn.value == "dc=example,dc=com"
        assert sorted_entries[2].dn.value == "ou=users,dc=example,dc=com"


class TestFlextServiceV2Comparison:
    """Compare V1 vs V2 patterns - code reduction metrics."""

    def test_code_reduction_v2_vs_v1(self) -> None:
        """Demonstrate 68% code reduction with V2 .result pattern."""
        entries = create_test_entries()

        # V1 Pattern (verbose): 3 lines
        service_v1 = FlextLdifSorting.v1(
            entries=entries, sort_by="hierarchy"
        )  # Disable auto_execute
        result_v1 = service_v1.execute()
        sorted_v1 = result_v1.unwrap()

        # V2 Pattern (concise): 1 line (68% reduction!)
        sorted_v2 = FlextLdifSorting.v1(entries=entries, sort_by="hierarchy").result

        # Both produce same result
        assert sorted_v1 == sorted_v2
        assert len(sorted_v2) == 3

    def test_type_safety_v2_vs_v1(self) -> None:
        """V2 .result has better type inference than V1."""
        entries = create_test_entries()

        # V2: IDE knows type is list[Entry] (with .result)
        sorted_v2: list[FlextLdifModels.Entry] = FlextLdifSorting.v1(
            entries=entries,
            sort_by="hierarchy",
        ).result

        # V1: IDE knows type is FlextResult[list[Entry]]
        result_v1: FlextResult[list[FlextLdifModels.Entry]] = (
            FlextLdifSorting.with_result(
                entries=entries,
                sort_by="hierarchy",
            )
        )

        # Both work, but V2 is more direct
        assert isinstance(sorted_v2, list)
        assert isinstance(result_v1, FlextResult)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
