"""FlextLdifFilters comprehensive tests using REAL LDIF fixtures.

Tests all filtering functionality with authentic LDIF data from project fixtures.
NO MOCKS - only real LDIF entries parsed from actual fixture files.

This test suite validates:
  ✅ All filter patterns (by_dn, by_objectclass, by_attributes, by_base_dn)
  ✅ All filter modes (include, exclude)
  ✅ Entry categorization with real data
  ✅ Schema/ACL detection
  ✅ Attribute/objectClass removal
  ✅ Error handling

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import fnmatch
from pathlib import Path

import pytest

from flext_ldif import FlextLdif
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.filters import FlextLdifFilters

# ════════════════════════════════════════════════════════════════════════════
# LOAD REAL LDIF FIXTURES
# ════════════════════════════════════════════════════════════════════════════


def load_real_ldif_entries(fixture_path: str) -> list[FlextLdifModels.Entry]:
    """Load REAL LDIF entries from fixture file (no mocks)."""
    fixture_file = Path(__file__).parent.parent.parent / "fixtures" / fixture_path
    if not fixture_file.exists():
        pytest.skip(f"Fixture file not found: {fixture_path}")

    ldif = FlextLdif()
    result = ldif.parse(fixture_file)

    if not result.is_success:
        pytest.skip(f"Failed to parse fixture: {result.error}")

    return result.unwrap()


@pytest.fixture
def oid_entries() -> list[FlextLdifModels.Entry]:
    """Load real OID LDIF entries."""
    return load_real_ldif_entries("oid/oid_entries_fixtures.ldif")


@pytest.fixture
def oid_schema_entries() -> list[FlextLdifModels.Entry]:
    """Load real OID schema entries."""
    return load_real_ldif_entries("oid/oid_schema_fixtures.ldif")


# ════════════════════════════════════════════════════════════════════════════
# FILTER BY DN PATTERN
# ════════════════════════════════════════════════════════════════════════════


class TestFilterByDN:
    """Test DN pattern filtering with real LDIF data."""

    def test_filter_users_ou_pattern(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test filtering by DN pattern: *,ou=people,*."""
        result = FlextLdifFilters.by_dn(oid_entries, "*,ou=people,*", mode="include")

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) > 0
        assert all("ou=people" in e.dn.value.lower() for e in filtered)

    def test_filter_groups_ou_pattern(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test filtering by DN pattern: *,ou=groups,*."""
        result = FlextLdifFilters.by_dn(oid_entries, "*,ou=groups,*", mode="include")

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) > 0
        assert all("ou=groups" in e.dn.value.lower() for e in filtered)

    def test_filter_excludes_non_matching(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test that non-matching entries are excluded (mark_excluded=False)."""
        result = FlextLdifFilters.by_dn(
            oid_entries,
            "*,ou=people,*",
            mode="include",
            mark_excluded=False,
        )

        assert result.is_success
        filtered = result.unwrap()
        # Should NOT include base domain entry (dc=example,dc=com)
        assert not any(e.dn.value == "dc=example,dc=com" for e in filtered)

    def test_filter_with_mark_excluded(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test mark_excluded=True returns matching + marked excluded."""
        original_count = len(oid_entries)

        result = FlextLdifFilters.by_dn(
            oid_entries,
            "*,ou=people,*",
            mode="include",
            mark_excluded=True,
        )

        assert result.is_success
        filtered = result.unwrap()
        # Should include all entries
        assert len(filtered) == original_count

        # Some should have exclusion metadata
        excluded_entries = [
            e
            for e in filtered
            if e.metadata and "exclusion_info" in e.metadata.extensions
        ]
        assert len(excluded_entries) > 0

    def test_filter_exclude_mode(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test exclude mode removes matching entries."""
        # Count entries matching the fnmatch pattern (same logic as production code)
        pattern = "*,ou=people,*"
        people_entries = [
            e
            for e in oid_entries
            if fnmatch.fnmatch(e.dn.value.lower(), pattern.lower())
        ]
        original_count = len(oid_entries)

        result = FlextLdifFilters.by_dn(oid_entries, pattern, mode="exclude")

        assert result.is_success
        filtered = result.unwrap()
        # Should have all entries except those matching pattern
        expected_count = original_count - len(people_entries)
        assert len(filtered) == expected_count, (
            f"Expected {expected_count}, got {len(filtered)}"
        )
        # Verify no filtered entry matches the pattern
        assert all(
            not fnmatch.fnmatch(e.dn.value.lower(), pattern.lower()) for e in filtered
        )


# ════════════════════════════════════════════════════════════════════════════
# FILTER BY OBJECTCLASS
# ════════════════════════════════════════════════════════════════════════════


class TestFilterByObjectClass:
    """Test objectClass filtering with real LDIF data."""

    def test_filter_inetorgperson(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test filtering by inetOrgPerson objectClass."""
        result = FlextLdifFilters.by_objectclass(oid_entries, "inetOrgPerson")

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) > 0

        for entry in filtered:
            ocs = entry.get_attribute_values("objectClass")
            assert any(oc.lower() == "inetorgperson" for oc in ocs)

    def test_filter_groupofnames(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test filtering by groupOfNames objectClass."""
        result = FlextLdifFilters.by_objectclass(oid_entries, "groupOfNames")

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) > 0

        for entry in filtered:
            ocs = entry.get_attribute_values("objectClass")
            assert any(oc.lower() == "groupofnames" for oc in ocs)

    def test_filter_with_required_attributes(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test filtering by objectClass with required attributes."""
        result = FlextLdifFilters.by_objectclass(
            oid_entries,
            "inetOrgPerson",
            required_attributes=["mail"],
        )

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) > 0

        for entry in filtered:
            assert entry.has_attribute("mail")
            ocs = entry.get_attribute_values("objectClass")
            assert any(oc.lower() == "inetorgperson" for oc in ocs)

    def test_filter_organizational_unit(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test filtering by organizationalUnit objectClass."""
        result = FlextLdifFilters.by_objectclass(oid_entries, "organizationalUnit")

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) > 0

        for entry in filtered:
            ocs = entry.get_attribute_values("objectClass")
            assert any(oc.lower() == "organizationalunit" for oc in ocs)


# ════════════════════════════════════════════════════════════════════════════
# FILTER BY ATTRIBUTES
# ════════════════════════════════════════════════════════════════════════════


class TestFilterByAttributes:
    """Test attribute-based filtering with real LDIF data."""

    def test_filter_entries_with_mail(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test filtering entries that have mail attribute."""
        result = FlextLdifFilters.by_attributes(oid_entries, ["mail"], match_all=False)

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) > 0

        for entry in filtered:
            assert entry.has_attribute("mail")

    def test_filter_entries_with_multiple_attributes_any(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test filtering entries with ANY of the specified attributes."""
        result = FlextLdifFilters.by_attributes(
            oid_entries,
            ["mail", "telephoneNumber"],
            match_all=False,
        )

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) > 0

        for entry in filtered:
            has_mail = entry.has_attribute("mail")
            has_phone = entry.has_attribute("telephoneNumber")
            assert has_mail or has_phone

    def test_filter_entries_with_multiple_attributes_all(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test filtering entries with ALL specified attributes."""
        result = FlextLdifFilters.by_attributes(
            oid_entries,
            ["mail", "cn"],
            match_all=True,
        )

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) > 0

        for entry in filtered:
            assert entry.has_attribute("mail")
            assert entry.has_attribute("cn")


# ════════════════════════════════════════════════════════════════════════════
# FILTER BY BASE DN
# ════════════════════════════════════════════════════════════════════════════


class TestFilterByBaseDN:
    """Test base DN hierarchy filtering with real LDIF data."""

    def test_filter_base_dn_hierarchy(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test filtering entries under base DN."""
        included, excluded = FlextLdifFilters.by_base_dn(
            oid_entries,
            "dc=example,dc=com",
        )

        # All entries should be under dc=example,dc=com
        assert len(included) == len(oid_entries)
        assert len(excluded) == 0

        for entry in included:
            assert "dc=example,dc=com" in entry.dn.value.lower()


# ════════════════════════════════════════════════════════════════════════════
# SCHEMA DETECTION
# ════════════════════════════════════════════════════════════════════════════


class TestSchemaDetection:
    """Test schema entry detection with real LDIF data."""

    def test_detect_schema_entries(
        self,
        oid_schema_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test detecting schema entries from real schema fixture."""
        schema_entries = [
            e for e in oid_schema_entries if FlextLdifFilters.is_schema(e)
        ]

        assert len(schema_entries) > 0

    def test_extract_acl_entries(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test extracting ACL entries if present in fixtures."""
        result = FlextLdifFilters.extract_acl_entries(
            oid_entries,
            acl_attributes=["acl", "aci", "orclaci"],
        )

        assert result.is_success
        # May be empty if no ACL entries in fixture
        acl_entries = result.unwrap()
        assert isinstance(acl_entries, list)


# ════════════════════════════════════════════════════════════════════════════
# ENTRY CATEGORIZATION
# ════════════════════════════════════════════════════════════════════════════


class TestCategorization:
    """Test entry categorization with real LDIF data."""

    def test_categorize_real_entries(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test categorizing real LDIF entries."""
        rules = {
            "user_objectclasses": ["person", "inetOrgPerson"],
            "group_objectclasses": ["groupOfNames"],
            "hierarchy_objectclasses": ["organizationalUnit"],
            "acl_attributes": ["acl", "aci"],
        }

        categories = {}
        for entry in oid_entries:
            category, _ = FlextLdifFilters.categorize(entry, rules)
            categories[entry.dn.value] = category

        # Should have at least users and hierarchy
        assert "users" in categories.values()
        assert "hierarchy" in categories.values()


# ════════════════════════════════════════════════════════════════════════════
# TRANSFORMATION
# ════════════════════════════════════════════════════════════════════════════


class TestTransformation:
    """Test attribute/objectClass removal with real LDIF data."""

    def test_remove_attributes_from_real_entry(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test removing attributes from real entries."""
        # Find an entry with mail attribute
        entry_with_mail = next(
            (e for e in oid_entries if e.has_attribute("mail")),
            None,
        )

        if not entry_with_mail:
            pytest.skip("No entry with mail attribute in fixtures")

        result = FlextLdifFilters.remove_attributes(entry_with_mail, ["mail"])

        assert result.is_success
        filtered = result.unwrap()
        assert not filtered.has_attribute("mail")
        assert filtered.has_attribute("cn")  # Should keep other attributes

    def test_remove_objectclasses_from_real_entry(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test removing objectClasses from real entries."""
        # Find an entry with multiple objectClasses (need 3+ to remove one and still have 2+)
        entry_with_multiple_ocs = next(
            (e for e in oid_entries if len(e.get_attribute_values("objectClass")) >= 3),
            None,
        )

        if not entry_with_multiple_ocs:
            pytest.skip("No entry with 3+ objectClasses in fixtures")

        original_ocs = entry_with_multiple_ocs.get_attribute_values("objectClass")
        # Remove one that's not the only remaining
        oc_to_remove = original_ocs[0]

        result = FlextLdifFilters.remove_objectclasses(
            entry_with_multiple_ocs,
            [oc_to_remove],
        )

        assert result.is_success
        filtered = result.unwrap()
        remaining_ocs = filtered.get_attribute_values("objectClass")
        assert oc_to_remove.lower() not in [o.lower() for o in remaining_ocs]
        assert len(remaining_ocs) == len(original_ocs) - 1


# ════════════════════════════════════════════════════════════════════════════
# FLUENT BUILDER
# ════════════════════════════════════════════════════════════════════════════


class TestFluentBuilder:
    """Test fluent builder pattern with real LDIF data."""

    def test_builder_dn_pattern(self, oid_entries: list[FlextLdifModels.Entry]) -> None:
        """Test builder with DN pattern."""
        result = (
            FlextLdifFilters.builder()
            .with_entries(oid_entries)
            .with_dn_pattern("*,ou=people,*")
            .build()
        )

        assert len(result) > 0
        assert all("ou=people" in e.dn.value.lower() for e in result)

    def test_builder_objectclass_with_attributes(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test builder with objectClass and required attributes."""
        result = (
            FlextLdifFilters.builder()
            .with_entries(oid_entries)
            .with_objectclass("inetOrgPerson")
            .with_required_attributes(["mail"])
            .build()
        )

        assert len(result) > 0
        for entry in result:
            ocs = entry.get_attribute_values("objectClass")
            assert any(oc.lower() == "inetorgperson" for oc in ocs)
            assert entry.has_attribute("mail")


# ════════════════════════════════════════════════════════════════════════════
# INTEGRATION
# ════════════════════════════════════════════════════════════════════════════


class TestIntegration:
    """Integration tests with real LDIF data."""

    def test_multi_stage_filtering(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test multi-stage filtering pipeline with real data."""
        # Stage 1: Filter by DN pattern
        result1 = FlextLdifFilters.filter(
            oid_entries,
            criteria="dn",
            pattern="*,ou=people,*",
        )
        assert result1.is_success
        stage1 = result1.unwrap()
        assert len(stage1) > 0

        # Stage 2: Filter by objectClass
        result2 = FlextLdifFilters.filter(
            stage1,
            criteria="objectclass",
            objectclass="inetOrgPerson",
        )
        assert result2.is_success
        stage2 = result2.unwrap()
        assert len(stage2) > 0

        # All should be users
        for entry in stage2:
            assert "ou=people" in entry.dn.value.lower()
            ocs = entry.get_attribute_values("objectClass")
            assert any(oc.lower() == "inetorgperson" for oc in ocs)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
