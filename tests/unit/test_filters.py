"""Unit tests for FlextLdifFilters - Filtering and categorization utilities.

Tests all filtering functionality including:
- DN pattern matching
- OID pattern matching
- Entry exclusion marking
- ObjectClass filtering
- Attribute filtering
- Entry categorization

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif.filters import FlextLdifFilters
from flext_ldif.models import FlextLdifModels


def create_test_entry(
    dn_str: str, attributes: dict[str, list[str]]
) -> FlextLdifModels.Entry:
    """Helper function to create test entries with proper attribute wrapping.

    Args:
        dn_str: DN string for the entry
        attributes: Dictionary mapping attribute names to value lists

    Returns:
        Properly constructed Entry instance

    """
    dn_result = FlextLdifModels.DistinguishedName.create(dn_str)
    assert dn_result.is_success
    dn = dn_result.unwrap()

    # Wrap all attribute values in AttributeValues objects
    wrapped_attrs = {
        name: FlextLdifModels.AttributeValues(values=values)
        for name, values in attributes.items()
    }

    attrs_result = FlextLdifModels.LdifAttributes.create(wrapped_attrs)
    assert attrs_result.is_success
    attrs = attrs_result.unwrap()

    return FlextLdifModels.Entry(dn=dn, attributes=attrs)


class TestDnPatternMatching:
    """Test DN wildcard pattern matching."""

    def test_exact_match(self) -> None:
        """Test exact DN match."""
        dn = "cn=john,ou=users,dc=example,dc=com"
        pattern = "cn=john,ou=users,dc=example,dc=com"
        assert FlextLdifFilters.matches_dn_pattern(dn, pattern)

    def test_wildcard_start(self) -> None:
        """Test wildcard at start of pattern."""
        dn = "cn=john,ou=users,dc=example,dc=com"
        pattern = "*,ou=users,dc=example,dc=com"
        assert FlextLdifFilters.matches_dn_pattern(dn, pattern)

    def test_wildcard_middle(self) -> None:
        """Test wildcard in middle of pattern."""
        dn = "cn=john,ou=users,dc=example,dc=com"
        pattern = "cn=john,*,dc=com"
        assert FlextLdifFilters.matches_dn_pattern(dn, pattern)

    def test_wildcard_end(self) -> None:
        """Test wildcard at end of pattern."""
        dn = "cn=john,ou=users,dc=example,dc=com"
        pattern = "cn=john,ou=users,*"
        assert FlextLdifFilters.matches_dn_pattern(dn, pattern)

    def test_question_mark_wildcard(self) -> None:
        """Test single character wildcard."""
        dn = "cn=user1,dc=example,dc=com"
        pattern = "cn=user?,dc=example,dc=com"
        assert FlextLdifFilters.matches_dn_pattern(dn, pattern)

    def test_case_insensitive(self) -> None:
        """Test case-insensitive matching."""
        dn = "CN=John,OU=Users,DC=Example,DC=COM"
        pattern = "cn=john,ou=users,dc=example,dc=com"
        assert FlextLdifFilters.matches_dn_pattern(dn, pattern)

    def test_no_match(self) -> None:
        """Test pattern that doesn't match."""
        dn = "cn=john,ou=users,dc=example,dc=com"
        pattern = "*,ou=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        assert not FlextLdifFilters.matches_dn_pattern(dn, pattern)


class TestOidPatternMatching:
    """Test OID pattern matching."""

    def test_exact_match(self) -> None:
        """Test exact OID match."""
        oid = "1.3.6.1.4.1.111.2.3"
        patterns = ["1.3.6.1.4.1.111.2.3"]
        assert FlextLdifFilters.matches_oid_pattern(oid, patterns)

    def test_wildcard_match(self) -> None:
        """Test OID wildcard match."""
        oid = "1.3.6.1.4.1.111.2.3.4"
        patterns = ["1.3.6.1.4.1.111.*"]
        assert FlextLdifFilters.matches_oid_pattern(oid, patterns)

    def test_multiple_patterns(self) -> None:
        """Test matching against multiple patterns."""
        oid = "2.16.840.1.113894.1.2.3"
        patterns = ["1.3.6.1.4.1.111.*", "2.16.840.1.113894.*"]
        assert FlextLdifFilters.matches_oid_pattern(oid, patterns)

    def test_oracle_oid_pattern(self) -> None:
        """Test Oracle OID namespace pattern."""
        oid = "2.16.840.1.113894.5.12.3"
        patterns = ["2.16.840.1.113894.*"]
        assert FlextLdifFilters.matches_oid_pattern(oid, patterns)

    def test_no_match(self) -> None:
        """Test OID that doesn't match any pattern."""
        oid = "1.2.3.4.5.6.7"
        patterns = ["1.3.6.1.4.1.111.*", "2.16.840.1.113894.*"]
        assert not FlextLdifFilters.matches_oid_pattern(oid, patterns)

    def test_empty_patterns(self) -> None:
        """Test with empty pattern list."""
        oid = "1.3.6.1.4.1.111.2.3"
        patterns: list[str] = []
        assert not FlextLdifFilters.matches_oid_pattern(oid, patterns)


class TestEntryExclusionMarking:
    """Test entry exclusion metadata marking."""

    @pytest.fixture
    def sample_entry(self) -> FlextLdifModels.Entry:
        """Create sample entry for testing."""
        return create_test_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": ["person"]},
        )

    def test_mark_entry_excluded_basic(self, sample_entry: FlextLdifModels.Entry) -> None:
        """Test basic exclusion marking."""
        marked = FlextLdifFilters.mark_entry_excluded(
            sample_entry, "Test exclusion reason"
        )

        assert FlextLdifFilters.is_entry_excluded(marked)
        assert FlextLdifFilters.get_exclusion_reason(marked) == "Test exclusion reason"

    def test_mark_entry_excluded_with_criteria(
        self, sample_entry: FlextLdifModels.Entry
    ) -> None:
        """Test exclusion marking with filter criteria."""
        criteria = FlextLdifModels.FilterCriteria(
            filter_type="dn_pattern",
            pattern="*,dc=old,dc=com",
            mode="exclude",
        )

        marked = FlextLdifFilters.mark_entry_excluded(
            sample_entry, "DN outside base context", criteria
        )

        assert FlextLdifFilters.is_entry_excluded(marked)
        assert marked.metadata is not None
        assert "exclusion_info" in marked.metadata.extensions

    def test_mark_entry_preserves_existing_metadata(
        self, sample_entry: FlextLdifModels.Entry
    ) -> None:
        """Test that marking preserves existing metadata."""
        # Create entry with metadata
        existing_metadata = FlextLdifModels.QuirkMetadata(
            original_format="oid",
            quirk_type="schema",
            extensions={"custom": "data"},
        )
        entry_with_metadata = sample_entry.model_copy(update={"metadata": existing_metadata})

        marked = FlextLdifFilters.mark_entry_excluded(
            entry_with_metadata, "Test reason"
        )

        assert marked.metadata is not None
        assert marked.metadata.original_format == "oid"
        assert marked.metadata.quirk_type == "schema"
        assert "custom" in marked.metadata.extensions
        assert "exclusion_info" in marked.metadata.extensions

    def test_is_entry_excluded_false_no_metadata(
        self, sample_entry: FlextLdifModels.Entry
    ) -> None:
        """Test is_entry_excluded returns False for entry without metadata."""
        assert not FlextLdifFilters.is_entry_excluded(sample_entry)

    def test_get_exclusion_reason_none_not_excluded(
        self, sample_entry: FlextLdifModels.Entry
    ) -> None:
        """Test get_exclusion_reason returns None for non-excluded entry."""
        assert FlextLdifFilters.get_exclusion_reason(sample_entry) is None


class TestHasObjectClass:
    """Test objectClass checking."""

    @pytest.fixture
    def entry_with_objectclasses(self) -> FlextLdifModels.Entry:
        """Create entry with multiple objectClasses."""
        return create_test_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": ["person", "inetOrgPerson", "organizationalPerson"]},
        )

    def test_has_single_objectclass(
        self, entry_with_objectclasses: FlextLdifModels.Entry
    ) -> None:
        """Test checking for single objectClass."""
        assert FlextLdifFilters.has_objectclass(entry_with_objectclasses, ("person",))

    def test_has_multiple_objectclasses(
        self, entry_with_objectclasses: FlextLdifModels.Entry
    ) -> None:
        """Test checking for any of multiple objectClasses."""
        assert FlextLdifFilters.has_objectclass(
            entry_with_objectclasses, ("person", "groupOfNames")
        )

    def test_case_insensitive_objectclass(
        self, entry_with_objectclasses: FlextLdifModels.Entry
    ) -> None:
        """Test case-insensitive objectClass matching."""
        assert FlextLdifFilters.has_objectclass(entry_with_objectclasses, ("PERSON",))
        assert FlextLdifFilters.has_objectclass(
            entry_with_objectclasses, ("inetorgperson",)
        )

    def test_no_objectclass_match(
        self, entry_with_objectclasses: FlextLdifModels.Entry
    ) -> None:
        """Test when objectClass doesn't match."""
        assert not FlextLdifFilters.has_objectclass(
            entry_with_objectclasses, ("groupOfNames",)
        )


class TestHasRequiredAttributes:
    """Test required attribute checking."""

    @pytest.fixture
    def sample_entry(self) -> FlextLdifModels.Entry:
        """Create sample entry with various attributes."""
        return create_test_entry(
            "cn=test,dc=example,dc=com",
            {
                "cn": ["test"],
                "sn": ["User"],
                "mail": ["test@example.com"],
                "objectClass": ["person"],
            },
        )

    def test_has_all_required_attributes(
        self, sample_entry: FlextLdifModels.Entry
    ) -> None:
        """Test when entry has all required attributes."""
        assert FlextLdifFilters.has_required_attributes(sample_entry, ["cn", "sn", "mail"])

    def test_missing_required_attribute(
        self, sample_entry: FlextLdifModels.Entry
    ) -> None:
        """Test when entry is missing a required attribute."""
        assert not FlextLdifFilters.has_required_attributes(
            sample_entry, ["cn", "sn", "mail", "telephoneNumber"]
        )

    def test_empty_required_list(self, sample_entry: FlextLdifModels.Entry) -> None:
        """Test with empty required attributes list."""
        assert FlextLdifFilters.has_required_attributes(sample_entry, [])


class TestCategorizeEntry:
    """Test entry categorization logic."""

    def _create_entry(self, objectclasses: list[str]) -> FlextLdifModels.Entry:
        """Helper to create entry with specified objectClasses."""
        return create_test_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": objectclasses},
        )

    def test_categorize_as_user(self) -> None:
        """Test categorizing user entries."""
        entry = self._create_entry(["person", "inetOrgPerson"])
        category = FlextLdifFilters.categorize_entry(
            entry,
            user_objectclasses=("person", "inetOrgPerson"),
            group_objectclasses=("groupOfNames",),
            container_objectclasses=("organizationalUnit",),
        )
        assert category == "user"

    def test_categorize_as_group(self) -> None:
        """Test categorizing group entries."""
        entry = self._create_entry(["groupOfNames", "top"])
        category = FlextLdifFilters.categorize_entry(
            entry,
            user_objectclasses=("person", "inetOrgPerson"),
            group_objectclasses=("groupOfNames", "groupOfUniqueNames"),
            container_objectclasses=("organizationalUnit",),
        )
        assert category == "group"

    def test_categorize_as_container(self) -> None:
        """Test categorizing container entries."""
        entry = self._create_entry(["organizationalUnit", "top"])
        category = FlextLdifFilters.categorize_entry(
            entry,
            user_objectclasses=("person",),
            group_objectclasses=("groupOfNames",),
            container_objectclasses=("organizationalUnit", "organization"),
        )
        assert category == "container"

    def test_categorize_as_uncategorized(self) -> None:
        """Test categorizing entries that don't match any category."""
        entry = self._create_entry(["device", "top"])
        category = FlextLdifFilters.categorize_entry(
            entry,
            user_objectclasses=("person",),
            group_objectclasses=("groupOfNames",),
            container_objectclasses=("organizationalUnit",),
        )
        assert category == "uncategorized"

    def test_categorize_priority_user_over_group(self) -> None:
        """Test that user category takes priority over group."""
        entry = self._create_entry(["person", "groupOfNames"])
        category = FlextLdifFilters.categorize_entry(
            entry,
            user_objectclasses=("person",),
            group_objectclasses=("groupOfNames",),
            container_objectclasses=("organizationalUnit",),
        )
        assert category == "user"  # User has priority


class TestFilterEntriesByDn:
    """Test DN pattern filtering."""

    @pytest.fixture
    def sample_entries(self) -> list[FlextLdifModels.Entry]:
        """Create sample entries with different DNs."""
        dns = [
            "cn=user1,ou=users,dc=example,dc=com",
            "cn=user2,ou=users,dc=example,dc=com",
            "cn=REDACTED_LDAP_BIND_PASSWORD1,ou=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            "cn=group1,ou=groups,dc=example,dc=com",
        ]

        entries = []
        for dn_str in dns:
            cn_value = dn_str.split(",")[0].split("=")[1]
            entry = create_test_entry(
                dn_str,
                {"cn": [cn_value], "objectClass": ["person"]},
            )
            entries.append(entry)

        return entries

    def test_filter_include_mode(
        self, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test include mode filtering."""
        result = FlextLdifFilters.filter_entries_by_dn(
            sample_entries, pattern="*,ou=users,*", mode="include", mark_excluded=False
        )

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 2  # Only user1 and user2

    def test_filter_exclude_mode(
        self, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test exclude mode filtering."""
        result = FlextLdifFilters.filter_entries_by_dn(
            sample_entries, pattern="*,ou=users,*", mode="exclude", mark_excluded=False
        )

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 2  # REDACTED_LDAP_BIND_PASSWORD1 and group1

    def test_filter_with_exclusion_marking(
        self, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test filtering with exclusion metadata marking."""
        result = FlextLdifFilters.filter_entries_by_dn(
            sample_entries, pattern="*,ou=users,*", mode="include", mark_excluded=True
        )

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 4  # All entries returned

        # Check that excluded entries are marked
        excluded_count = sum(1 for e in filtered if FlextLdifFilters.is_entry_excluded(e))
        assert excluded_count == 2  # REDACTED_LDAP_BIND_PASSWORD1 and group1 are marked excluded


class TestFilterEntriesByObjectClass:
    """Test objectClass filtering."""

    @pytest.fixture
    def sample_entries(self) -> list[FlextLdifModels.Entry]:
        """Create sample entries with different objectClasses."""
        test_data = [
            (["person", "inetOrgPerson"], ["cn", "sn", "mail"]),
            (["person"], ["cn", "sn"]),
            (["groupOfNames"], ["cn", "member"]),
            (["organizationalUnit"], ["ou"]),
        ]

        entries = []
        for idx, (objectclasses, attrs) in enumerate(test_data):
            attr_dict = {attr: [f"value{idx}"] for attr in attrs}
            attr_dict["objectClass"] = objectclasses

            entry = create_test_entry(f"cn=test{idx},dc=example,dc=com", attr_dict)
            entries.append(entry)

        return entries

    def test_filter_single_objectclass(
        self, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test filtering by single objectClass."""
        result = FlextLdifFilters.filter_entries_by_objectclass(
            sample_entries, objectclass="person", mark_excluded=False
        )

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 2  # First two entries have "person"

    def test_filter_multiple_objectclasses(
        self, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test filtering by multiple objectClasses."""
        result = FlextLdifFilters.filter_entries_by_objectclass(
            sample_entries,
            objectclass=("person", "groupOfNames"),
            mark_excluded=False,
        )

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 3  # person and group entries

    def test_filter_with_required_attributes(
        self, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test filtering with required attribute validation."""
        result = FlextLdifFilters.filter_entries_by_objectclass(
            sample_entries,
            objectclass="person",
            required_attributes=["cn", "sn", "mail"],
            mark_excluded=False,
        )

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 1  # Only first entry has all three attrs

    def test_filter_exclude_mode(
        self, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test exclude mode filtering."""
        result = FlextLdifFilters.filter_entries_by_objectclass(
            sample_entries, objectclass="person", mode="exclude", mark_excluded=False
        )

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 2  # group and ou entries


class TestFilterEntriesByAttributes:
    """Test attribute presence filtering."""

    @pytest.fixture
    def sample_entries(self) -> list[FlextLdifModels.Entry]:
        """Create sample entries with different attributes."""
        test_data = [
            {"cn": ["user1"], "mail": ["user1@example.com"], "telephoneNumber": ["123"]},
            {"cn": ["user2"], "mail": ["user2@example.com"]},
            {"cn": ["user3"], "telephoneNumber": ["456"]},
            {"cn": ["user4"]},
        ]

        entries = []
        for idx, attrs in enumerate(test_data):
            attrs["objectClass"] = ["person"]
            entry = create_test_entry(f"cn=test{idx},dc=example,dc=com", attrs)
            entries.append(entry)

        return entries

    def test_filter_any_attribute(
        self, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test filtering with ANY attribute matching."""
        result = FlextLdifFilters.filter_entries_by_attributes(
            sample_entries,
            attributes=["mail", "telephoneNumber"],
            match_all=False,
            mark_excluded=False,
        )

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 3  # First three entries have either mail or phone

    def test_filter_all_attributes(
        self, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test filtering with ALL attributes required."""
        result = FlextLdifFilters.filter_entries_by_attributes(
            sample_entries,
            attributes=["mail", "telephoneNumber"],
            match_all=True,
            mark_excluded=False,
        )

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 1  # Only first entry has both

    def test_filter_exclude_mode(
        self, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test exclude mode filtering."""
        result = FlextLdifFilters.filter_entries_by_attributes(
            sample_entries,
            attributes=["mail"],
            mode="exclude",
            mark_excluded=False,
        )

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 2  # Last two entries don't have mail


__all__ = [
    "TestCategorizeEntry",
    "TestDnPatternMatching",
    "TestEntryExclusionMarking",
    "TestFilterEntriesByAttributes",
    "TestFilterEntriesByDn",
    "TestFilterEntriesByObjectClass",
    "TestHasObjectClass",
    "TestHasRequiredAttributes",
    "TestOidPatternMatching",
]
