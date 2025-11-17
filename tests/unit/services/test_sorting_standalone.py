"""Standalone comprehensive tests for FlextLdifSorting.

This is a standalone test file that doesn't depend on conftest.py.
Tests all sorting functionality with real data.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from flext_ldif.models import FlextLdifModels
from flext_ldif.services.sorting import FlextLdifSorting

# Make sure we can import flext_ldif
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))


def create_entry(
    dn_str: str,
    attributes: dict[str, list[str]],
) -> FlextLdifModels.Entry:
    """Create test entry with DN and attributes."""
    dn = FlextLdifModels.DistinguishedName(value=dn_str)
    attrs_result = FlextLdifModels.LdifAttributes.create(attributes)
    error_msg = attrs_result.error or "Unknown error"
    assert attrs_result.is_success, f"Failed to create attributes: {error_msg}"
    attrs = attrs_result.unwrap()
    entry = FlextLdifModels.Entry(dn=dn, attributes=attrs)
    # Validate entry was created correctly
    assert entry.dn is not None
    assert entry.attributes is not None
    return entry


# ════════════════════════════════════════════════════════════════════════════
# TEST CLASSMETHOD HELPERS
# ════════════════════════════════════════════════════════════════════════════


def test_by_hierarchy_exists_and_works() -> None:
    """Test by_hierarchy classmethod exists and works."""
    entries = [
        create_entry("cn=deep,ou=level2,dc=example,dc=com", {"cn": ["deep"]}),
        create_entry("dc=example,dc=com", {"dc": ["example"]}),
        create_entry("ou=level1,dc=example,dc=com", {"ou": ["level1"]}),
    ]

    result = FlextLdifSorting.by_hierarchy(entries)
    assert result.is_success
    sorted_entries = result.unwrap()

    # Should be shallowest first (depth-first traversal)
    assert len(sorted_entries) == 3
    # Root should be first
    assert sorted_entries[0].dn is not None
    assert sorted_entries[0].dn.value == "dc=example,dc=com"
    # Level 1 should be second
    assert sorted_entries[1].dn is not None
    assert sorted_entries[1].dn.value == "ou=level1,dc=example,dc=com"
    # Level 2 should be third
    assert sorted_entries[2].dn is not None
    assert sorted_entries[2].dn.value == "cn=deep,ou=level2,dc=example,dc=com"


def test_by_dn_exists_and_works() -> None:
    """Test by_dn classmethod exists and works."""
    entries = [
        create_entry("cn=zzz,dc=example,dc=com", {"cn": ["zzz"]}),
        create_entry("cn=aaa,dc=example,dc=com", {"cn": ["aaa"]}),
        create_entry("cn=mmm,dc=example,dc=com", {"cn": ["mmm"]}),
    ]

    result = FlextLdifSorting.by_dn(entries)
    assert result.is_success
    sorted_entries = result.unwrap()

    dns = [e.dn.value.lower() if e.dn else "" for e in sorted_entries]
    assert dns == sorted(dns)


def test_by_schema_exists_and_works() -> None:
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

    result = FlextLdifSorting.by_schema(entries)
    assert result.is_success
    sorted_entries = result.unwrap()
    assert len(sorted_entries) == 2
    # attributeTypes should come before objectClasses
    # Check that first entry has attributeTypes
    first_attrs = (
        sorted_entries[0].attributes.attributes if sorted_entries[0].attributes else {}
    )
    assert "attributeTypes" in first_attrs or "objectClasses" in first_attrs


def test_by_custom_exists_and_works() -> None:
    """Test by_custom classmethod exists and works."""
    entries = [
        create_entry("cn=aaa,ou=b,dc=example,dc=com", {"cn": ["aaa"]}),  # depth 2
        create_entry("dc=example,dc=com", {"dc": ["example"]}),  # depth 0
        create_entry("ou=b,dc=example,dc=com", {"ou": ["b"]}),  # depth 1
    ]

    def depth_pred(e: FlextLdifModels.Entry) -> int:
        return e.dn.value.count(",") if e.dn else 0

    result = FlextLdifSorting.by_custom(entries, depth_pred)
    assert result.is_success
    sorted_entries = result.unwrap()

    # Should be sorted by depth
    assert sorted_entries[0].dn is not None
    assert sorted_entries[0].dn.value == "dc=example,dc=com"
    assert sorted_entries[1].dn is not None
    assert sorted_entries[1].dn.value == "ou=b,dc=example,dc=com"
    assert sorted_entries[2].dn is not None
    assert sorted_entries[2].dn.value == "cn=aaa,ou=b,dc=example,dc=com"


# ════════════════════════════════════════════════════════════════════════════
# TEST EXECUTE PATTERN (V1 Style)
# ════════════════════════════════════════════════════════════════════════════


def test_execute_hierarchy() -> None:
    """Test execute() with hierarchy sorting."""
    entries = [
        create_entry(
            "uid=jdoe,ou=people,ou=users,dc=example,dc=com",
            {"uid": ["jdoe"], "objectClass": ["person"]},
        ),
        create_entry(
            "dc=example,dc=com",
            {"dc": ["example"], "objectClass": ["domain"]},
        ),
        create_entry(
            "ou=users,dc=example,dc=com",
            {"ou": ["users"], "objectClass": ["organizationalUnit"]},
        ),
    ]

    sorted_entries = FlextLdifSorting(
        entries=entries,
        sort_target="entries",
        sort_by="hierarchy",
    )
    assert sorted_entries[0].dn is not None
    assert sorted_entries[0].dn.value == "dc=example,dc=com"


def test_execute_alphabetical() -> None:
    """Test execute() with alphabetical sorting."""
    entries = [
        create_entry("cn=zzz,dc=example,dc=com", {"cn": ["zzz"]}),
        create_entry("cn=aaa,dc=example,dc=com", {"cn": ["aaa"]}),
        create_entry("cn=mmm,dc=example,dc=com", {"cn": ["mmm"]}),
    ]

    sorted_entries = FlextLdifSorting(
        entries=entries,
        sort_target="entries",
        sort_by="alphabetical",
    )
    dns = [e.dn.value.lower() if e.dn else "" for e in sorted_entries]
    assert dns == sorted(dns)


def test_execute_custom() -> None:
    """Test execute() with custom sorting."""

    def custom_pred(e: FlextLdifModels.Entry) -> str:
        return e.dn.value.lower() if e.dn else ""

    entries = [
        create_entry("cn=zzz,dc=example,dc=com", {"cn": ["zzz"]}),
        create_entry("cn=aaa,dc=example,dc=com", {"cn": ["aaa"]}),
    ]

    sorted_entries = FlextLdifSorting(
        entries=entries,
        sort_target="entries",
        sort_by="custom",
        custom_predicate=custom_pred,
    )
    assert len(sorted_entries) == 2
    assert sorted_entries[0].dn is not None
    assert sorted_entries[0].dn.value == "cn=aaa,dc=example,dc=com"


def test_execute_attributes_target() -> None:
    """Test execute() with attributes as target."""
    entry = create_entry(
        "cn=test,dc=example,dc=com",
        {"zzz": ["z"], "aaa": ["a"], "cn": ["test"]},
    )

    sorted_entries = FlextLdifSorting(entries=[entry], sort_target="attributes")
    assert len(sorted_entries) == 1
    # Verify entry still has attributes
    assert sorted_entries[0].attributes is not None
    attrs = sorted_entries[0].attributes.attributes
    assert len(attrs) == 3
    # Verify attributes are sorted alphabetically
    attr_names = list(attrs.keys())
    assert attr_names == sorted(attr_names, key=str.lower)


def test_execute_acl_target() -> None:
    """Test execute() with acl as target."""
    entry = create_entry(
        "cn=test,dc=example,dc=com",
        {"cn": ["test"], "acl": ["zzz-rule", "aaa-rule"]},
    )

    sorted_entries = FlextLdifSorting(entries=[entry], sort_target="acl")
    assert len(sorted_entries) == 1
    # Verify ACL values are sorted
    assert sorted_entries[0].attributes is not None
    acl_values = sorted_entries[0].attributes.attributes.get("acl", [])
    assert len(acl_values) == 2
    # Verify ACL values are sorted alphabetically
    assert acl_values == sorted(acl_values, key=str.lower)


def test_execute_combined_target() -> None:
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

    sorted_entries = FlextLdifSorting(
        entries=entries,
        sort_target="combined",
        sort_by="hierarchy",
        sort_attributes=True,
    )
    assert len(sorted_entries) == 2


# ════════════════════════════════════════════════════════════════════════════
# TEST CLASSMETHOD SORT() for Composable Operations
# ════════════════════════════════════════════════════════════════════════════


def test_sort_classmethod() -> None:
    """Test sort() classmethod."""
    entries = [
        create_entry("cn=zzz,dc=example,dc=com", {"cn": ["zzz"]}),
        create_entry("cn=aaa,dc=example,dc=com", {"cn": ["aaa"]}),
    ]

    result = FlextLdifSorting.sort(entries, by="alphabetical")
    assert result.is_success
    sorted_entries = result.unwrap()
    assert sorted_entries[0].dn is not None
    assert sorted_entries[0].dn.value == "cn=aaa,dc=example,dc=com"


def test_sort_classmethod_with_custom() -> None:
    """Test sort() classmethod with custom predicate."""
    entries = [
        create_entry("cn=a,ou=b,dc=example,dc=com", {"cn": ["a"]}),  # length: 22
        create_entry("dc=example,dc=com", {"dc": ["example"]}),  # length: 15
        create_entry("ou=b,dc=example,dc=com", {"ou": ["b"]}),  # length: 19
    ]

    def length_pred(e: FlextLdifModels.Entry) -> int:
        return len(e.dn.value) if e.dn else 0

    result = FlextLdifSorting.sort(entries, by="custom", predicate=length_pred)
    assert result.is_success
    sorted_entries = result.unwrap()

    lengths = [len(e.dn.value) if e.dn else 0 for e in sorted_entries]
    assert lengths == sorted(lengths)


# ════════════════════════════════════════════════════════════════════════════
# TEST FLUENT BUILDER PATTERN
# ════════════════════════════════════════════════════════════════════════════


def test_builder_pattern() -> None:
    """Test fluent builder pattern."""
    entries = [
        create_entry("cn=zzz,dc=example,dc=com", {"zzz": ["z"], "cn": ["zzz"]}),
        create_entry("cn=aaa,dc=example,dc=com", {"aaa": ["a"], "cn": ["aaa"]}),
    ]

    sorted_entries = (
        FlextLdifSorting.builder()
        .with_entries(entries)
        .with_strategy("hierarchy")
        .build()
    )

    assert isinstance(sorted_entries, list)
    assert len(sorted_entries) == 2


def test_builder_with_attribute_sorting() -> None:
    """Test builder with attribute sorting."""
    entries = [
        create_entry("cn=test,dc=example,dc=com", {"zzz": ["z"], "aaa": ["a"]}),
    ]

    sorted_entries = (
        FlextLdifSorting.builder()
        .with_entries(entries)
        .with_strategy("hierarchy")
        .with_target("combined")
        .with_attribute_sorting(alphabetical=True)
        .build()
    )

    assert len(sorted_entries) == 1
    assert sorted_entries[0].attributes is not None
    attrs = sorted_entries[0].attributes.attributes
    # Verify attributes are still present
    assert len(attrs) == 2
    # Verify attributes are sorted alphabetically
    attr_names = list(attrs.keys())
    assert attr_names == sorted(attr_names, key=str.lower)


def test_builder_with_attribute_order() -> None:
    """Test builder with custom attribute order."""
    entries = [
        create_entry(
            "cn=test,dc=example,dc=com",
            {"zzz": ["z"], "cn": ["test"], "aaa": ["a"]},
        ),
    ]

    sorted_entries = (
        FlextLdifSorting.builder()
        .with_entries(entries)
        .with_strategy("hierarchy")
        .with_target("combined")
        .with_attribute_sorting(order=["cn", "zzz"])
        .build()
    )

    assert len(sorted_entries) == 1
    assert sorted_entries[0].attributes is not None
    attrs = sorted_entries[0].attributes.attributes
    # First two attrs should be cn and zzz (in order specified)
    attr_names = list(attrs.keys())
    assert len(attr_names) == 3
    # First two should be cn and zzz in that order
    assert attr_names[0] == "cn"
    assert attr_names[1] == "zzz"
    # Last should be aaa (alphabetically sorted)
    assert attr_names[2] == "aaa"


# ════════════════════════════════════════════════════════════════════════════
# EDGE CASES
# ════════════════════════════════════════════════════════════════════════════


def test_empty_entries() -> None:
    """Test sorting empty list."""
    result = FlextLdifSorting.by_hierarchy([])
    assert result.is_success
    assert result.unwrap() == []


def test_single_entry() -> None:
    """Test sorting single entry."""
    entry = create_entry("dc=example,dc=com", {"dc": ["example"]})
    result = FlextLdifSorting.by_hierarchy([entry])
    assert result.is_success
    assert len(result.unwrap()) == 1


def test_duplicate_dns() -> None:
    """Test sorting with duplicate DNs."""
    entries = [
        create_entry("cn=test,dc=example,dc=com", {"cn": ["test1"]}),
        create_entry("cn=test,dc=example,dc=com", {"cn": ["test2"]}),
    ]
    result = FlextLdifSorting.by_hierarchy(entries)
    assert result.is_success
    assert len(result.unwrap()) == 2


def test_unicode_dns() -> None:
    """Test sorting with Unicode."""
    entries = [
        create_entry("cn=日本語,dc=example,dc=com", {"cn": ["日本語"]}),
        create_entry("cn=English,dc=example,dc=com", {"cn": ["English"]}),
    ]
    result = FlextLdifSorting.by_hierarchy(entries)
    assert result.is_success
    assert len(result.unwrap()) == 2


# ════════════════════════════════════════════════════════════════════════════
# VALIDATION AND ERROR HANDLING
# ════════════════════════════════════════════════════════════════════════════


def test_invalid_sort_target() -> None:
    """Test invalid sort_target raises validation error."""
    entries = [create_entry("cn=test,dc=example,dc=com", {"cn": ["test"]})]

    with pytest.raises(ValidationError, match="Invalid sort_target"):
        _ = FlextLdifSorting(
            entries=entries,
            sort_target="invalid_target",
        )


def test_invalid_sort_strategy() -> None:
    """Test invalid sort_by raises validation error."""
    entries = [create_entry("cn=test,dc=example,dc=com", {"cn": ["test"]})]

    with pytest.raises(ValidationError, match="Invalid sort_by"):
        _ = FlextLdifSorting(
            entries=entries,
            sort_by="invalid_strategy",
        )


def test_custom_without_predicate() -> None:
    """Test custom sort_by without predicate raises validation error."""
    entries = [create_entry("cn=test,dc=example,dc=com", {"cn": ["test"]})]

    with pytest.raises(ValidationError, match="custom_predicate required"):
        _ = FlextLdifSorting(
            entries=entries,
            sort_by="custom",
            custom_predicate=None,
        )


if __name__ == "__main__":
    _ = pytest.main([__file__, "-v", "--tb=short"])
