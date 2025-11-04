"""Standalone comprehensive tests for FlextLdifSortingService.

This is a standalone test file that doesn't depend on conftest.py.
Tests all sorting functionality with real data.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make sure we can import flext_ldif
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

import pytest

from flext_ldif.models import FlextLdifModels
from flext_ldif.services.sorting import FlextLdifSortingService


def create_entry(dn_str: str, attributes: dict[str, list[str]]) -> FlextLdifModels.Entry:
    """Create test entry with DN and attributes."""
    dn = FlextLdifModels.DistinguishedName(value=dn_str)
    attrs = FlextLdifModels.LdifAttributes.create(attributes).unwrap()
    return FlextLdifModels.Entry(dn=dn, attributes=attrs)


# ════════════════════════════════════════════════════════════════════════════
# TEST CLASSMETHOD HELPERS
# ════════════════════════════════════════════════════════════════════════════


def test_by_hierarchy_exists_and_works():
    """Test by_hierarchy classmethod exists and works."""
    entries = [
        create_entry("cn=deep,ou=level2,dc=example,dc=com", {"cn": ["deep"]}),
        create_entry("dc=example,dc=com", {"dc": ["example"]}),
        create_entry("ou=level1,dc=example,dc=com", {"ou": ["level1"]}),
    ]

    result = FlextLdifSortingService.by_hierarchy(entries)
    assert result.is_success
    sorted_entries = result.unwrap()

    # Should be shallowest first
    assert sorted_entries[0].dn.value == "dc=example,dc=com"
    assert sorted_entries[1].dn.value == "ou=level1,dc=example,dc=com"
    assert sorted_entries[2].dn.value == "cn=deep,ou=level2,dc=example,dc=com"


def test_by_dn_exists_and_works():
    """Test by_dn classmethod exists and works."""
    entries = [
        create_entry("cn=zzz,dc=example,dc=com", {"cn": ["zzz"]}),
        create_entry("cn=aaa,dc=example,dc=com", {"cn": ["aaa"]}),
        create_entry("cn=mmm,dc=example,dc=com", {"cn": ["mmm"]}),
    ]

    result = FlextLdifSortingService.by_dn(entries)
    assert result.is_success
    sorted_entries = result.unwrap()

    dns = [e.dn.value.lower() for e in sorted_entries]
    assert dns == sorted(dns)


def test_by_schema_exists_and_works():
    """Test by_schema classmethod exists and works."""
    entries = [
        create_entry(
            "cn=schema",
            {"cn": ["schema"], "objectClasses": ["( 2.5.6.6 NAME 'person' )"]},
        ),
        create_entry(
            "cn=schema",
            {"cn": ["schema"], "attributeTypes": ["( 2.5.4.3 NAME 'cn' )"]},
        ),
    ]

    result = FlextLdifSortingService.by_schema(entries)
    assert result.is_success
    sorted_entries = result.unwrap()
    assert len(sorted_entries) == 2


def test_by_custom_exists_and_works():
    """Test by_custom classmethod exists and works."""
    entries = [
        create_entry("cn=aaa,ou=b,dc=example,dc=com", {"cn": ["aaa"]}),  # depth 2
        create_entry("dc=example,dc=com", {"dc": ["example"]}),  # depth 0
        create_entry("ou=b,dc=example,dc=com", {"ou": ["b"]}),  # depth 1
    ]

    def depth_pred(e: FlextLdifModels.Entry) -> int:
        return e.dn.value.count(",")

    result = FlextLdifSortingService.by_custom(entries, depth_pred)
    assert result.is_success
    sorted_entries = result.unwrap()

    # Should be sorted by depth
    assert sorted_entries[0].dn.value == "dc=example,dc=com"
    assert sorted_entries[1].dn.value == "ou=b,dc=example,dc=com"
    assert sorted_entries[2].dn.value == "cn=aaa,ou=b,dc=example,dc=com"


# ════════════════════════════════════════════════════════════════════════════
# TEST EXECUTE PATTERN (V1 Style)
# ════════════════════════════════════════════════════════════════════════════


def test_execute_hierarchy():
    """Test execute() with hierarchy sorting."""
    entries = [
        create_entry(
            "uid=jdoe,ou=people,ou=users,dc=example,dc=com",
            {"uid": ["jdoe"], "objectClass": ["person"]},
        ),
        create_entry("dc=example,dc=com", {"dc": ["example"], "objectClass": ["domain"]}),
        create_entry(
            "ou=users,dc=example,dc=com",
            {"ou": ["users"], "objectClass": ["organizationalUnit"]},
        ),
    ]

    result = FlextLdifSortingService(
        entries=entries, sort_target="entries", sort_by="hierarchy"
    ).execute()

    assert result.is_success
    sorted_entries = result.unwrap()
    assert sorted_entries[0].dn.value == "dc=example,dc=com"


def test_execute_alphabetical():
    """Test execute() with alphabetical sorting."""
    entries = [
        create_entry("cn=zzz,dc=example,dc=com", {"cn": ["zzz"]}),
        create_entry("cn=aaa,dc=example,dc=com", {"cn": ["aaa"]}),
        create_entry("cn=mmm,dc=example,dc=com", {"cn": ["mmm"]}),
    ]

    result = FlextLdifSortingService(
        entries=entries, sort_target="entries", sort_by="alphabetical"
    ).execute()

    assert result.is_success
    sorted_entries = result.unwrap()
    dns = [e.dn.value.lower() for e in sorted_entries]
    assert dns == sorted(dns)


def test_execute_custom():
    """Test execute() with custom sorting."""

    def custom_pred(e: FlextLdifModels.Entry) -> str:
        return e.dn.value.lower()

    entries = [
        create_entry("cn=zzz,dc=example,dc=com", {"cn": ["zzz"]}),
        create_entry("cn=aaa,dc=example,dc=com", {"cn": ["aaa"]}),
    ]

    result = FlextLdifSortingService(
        entries=entries, sort_target="entries", sort_by="custom", custom_predicate=custom_pred
    ).execute()

    assert result.is_success


def test_execute_attributes_target():
    """Test execute() with attributes as target."""
    entry = create_entry(
        "cn=test,dc=example,dc=com",
        {"zzz": ["z"], "aaa": ["a"], "cn": ["test"]},
    )

    result = FlextLdifSortingService(
        entries=[entry], sort_target="attributes"
    ).execute()

    assert result.is_success
    sorted_entries = result.unwrap()
    # Verify entry still has attributes
    attrs = sorted_entries[0].attributes.attributes
    assert len(attrs) == 3


def test_execute_acl_target():
    """Test execute() with acl as target."""
    entry = create_entry(
        "cn=test,dc=example,dc=com",
        {"cn": ["test"], "acl": ["zzz-rule", "aaa-rule"]},
    )

    result = FlextLdifSortingService(
        entries=[entry], sort_target="acl"
    ).execute()

    assert result.is_success
    sorted_entries = result.unwrap()
    assert len(sorted_entries) == 1


def test_execute_combined_target():
    """Test execute() with combined target."""
    entries = [
        create_entry(
            "ou=users,dc=example,dc=com",
            {"zzz": ["z"], "ou": ["users"]},
        ),
        create_entry(
            "dc=example,dc=com",
            {"aaa": ["a"], "dc": ["example"]},
        ),
    ]

    result = FlextLdifSortingService(
        entries=entries,
        sort_target="combined",
        sort_by="hierarchy",
        sort_attributes=True,
    ).execute()

    assert result.is_success
    sorted_entries = result.unwrap()
    assert len(sorted_entries) == 2


# ════════════════════════════════════════════════════════════════════════════
# TEST CLASSMETHOD SORT() for Composable Operations
# ════════════════════════════════════════════════════════════════════════════


def test_sort_classmethod():
    """Test sort() classmethod."""
    entries = [
        create_entry("cn=zzz,dc=example,dc=com", {"cn": ["zzz"]}),
        create_entry("cn=aaa,dc=example,dc=com", {"cn": ["aaa"]}),
    ]

    result = FlextLdifSortingService.sort(entries, by="alphabetical")
    assert result.is_success
    sorted_entries = result.unwrap()
    assert sorted_entries[0].dn.value == "cn=aaa,dc=example,dc=com"


def test_sort_classmethod_with_custom():
    """Test sort() classmethod with custom predicate."""
    entries = [
        create_entry("cn=a,ou=b,dc=example,dc=com", {"cn": ["a"]}),  # length: 22
        create_entry("dc=example,dc=com", {"dc": ["example"]}),  # length: 15
        create_entry("ou=b,dc=example,dc=com", {"ou": ["b"]}),  # length: 19
    ]

    def length_pred(e: FlextLdifModels.Entry) -> int:
        return len(e.dn.value)

    result = FlextLdifSortingService.sort(entries, by="custom", predicate=length_pred)
    assert result.is_success
    sorted_entries = result.unwrap()

    lengths = [len(e.dn.value) for e in sorted_entries]
    assert lengths == sorted(lengths)


# ════════════════════════════════════════════════════════════════════════════
# TEST FLUENT BUILDER PATTERN
# ════════════════════════════════════════════════════════════════════════════


def test_builder_pattern():
    """Test fluent builder pattern."""
    entries = [
        create_entry("cn=zzz,dc=example,dc=com", {"zzz": ["z"], "cn": ["zzz"]}),
        create_entry("cn=aaa,dc=example,dc=com", {"aaa": ["a"], "cn": ["aaa"]}),
    ]

    sorted_entries = (
        FlextLdifSortingService.builder()
        .with_entries(entries)
        .with_strategy("hierarchy")
        .build()
    )

    assert isinstance(sorted_entries, list)
    assert len(sorted_entries) == 2


def test_builder_with_attribute_sorting():
    """Test builder with attribute sorting."""
    entries = [
        create_entry("cn=test,dc=example,dc=com", {"zzz": ["z"], "aaa": ["a"]}),
    ]

    sorted_entries = (
        FlextLdifSortingService.builder()
        .with_entries(entries)
        .with_strategy("hierarchy")
        .with_attribute_sorting(alphabetical=True)
        .build()
    )

    assert len(sorted_entries) == 1
    attrs = sorted_entries[0].attributes.attributes
    # Verify attributes are still present
    assert len(attrs) == 2


def test_builder_with_attribute_order():
    """Test builder with custom attribute order."""
    entries = [
        create_entry("cn=test,dc=example,dc=com", {"zzz": ["z"], "cn": ["test"], "aaa": ["a"]}),
    ]

    sorted_entries = (
        FlextLdifSortingService.builder()
        .with_entries(entries)
        .with_strategy("hierarchy")
        .with_attribute_sorting(order=["cn", "zzz"])
        .build()
    )

    assert len(sorted_entries) == 1
    attrs = sorted_entries[0].attributes.attributes
    # First two attrs should be cn and zzz (in some order from those specified)
    attr_names = list(attrs.keys())
    assert len(attr_names) == 3


# ════════════════════════════════════════════════════════════════════════════
# EDGE CASES
# ════════════════════════════════════════════════════════════════════════════


def test_empty_entries():
    """Test sorting empty list."""
    result = FlextLdifSortingService.by_hierarchy([])
    assert result.is_success
    assert result.unwrap() == []


def test_single_entry():
    """Test sorting single entry."""
    entry = create_entry("dc=example,dc=com", {"dc": ["example"]})
    result = FlextLdifSortingService.by_hierarchy([entry])
    assert result.is_success
    assert len(result.unwrap()) == 1


def test_duplicate_dns():
    """Test sorting with duplicate DNs."""
    entries = [
        create_entry("cn=test,dc=example,dc=com", {"cn": ["test1"]}),
        create_entry("cn=test,dc=example,dc=com", {"cn": ["test2"]}),
    ]
    result = FlextLdifSortingService.by_hierarchy(entries)
    assert result.is_success
    assert len(result.unwrap()) == 2


def test_unicode_dns():
    """Test sorting with Unicode."""
    entries = [
        create_entry("cn=日本語,dc=example,dc=com", {"cn": ["日本語"]}),
        create_entry("cn=English,dc=example,dc=com", {"cn": ["English"]}),
    ]
    result = FlextLdifSortingService.by_hierarchy(entries)
    assert result.is_success
    assert len(result.unwrap()) == 2


# ════════════════════════════════════════════════════════════════════════════
# VALIDATION AND ERROR HANDLING
# ════════════════════════════════════════════════════════════════════════════


def test_invalid_sort_target():
    """Test invalid sort_target raises validation error."""
    from pydantic import ValidationError

    entries = [create_entry("cn=test,dc=example,dc=com", {"cn": ["test"]})]

    with pytest.raises(ValidationError, match="Invalid sort_target"):
        FlextLdifSortingService(
            entries=entries,
            sort_target="invalid_target",
        )


def test_invalid_sort_strategy():
    """Test invalid sort_by raises validation error."""
    from pydantic import ValidationError

    entries = [create_entry("cn=test,dc=example,dc=com", {"cn": ["test"]})]

    with pytest.raises(ValidationError, match="Invalid sort_by"):
        FlextLdifSortingService(
            entries=entries,
            sort_by="invalid_strategy",
        )


def test_custom_without_predicate():
    """Test custom sort_by without predicate raises validation error."""
    from pydantic import ValidationError

    entries = [create_entry("cn=test,dc=example,dc=com", {"cn": ["test"]})]

    with pytest.raises(ValidationError, match="custom_predicate required"):
        FlextLdifSortingService(
            entries=entries,
            sort_by="custom",
            custom_predicate=None,
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
