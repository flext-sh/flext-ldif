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

from flext_ldif.constants import FlextLdifConstants
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
    # Direct instantiation pattern - Pydantic 2 validates via @field_validator
    dn = FlextLdifModels.DistinguishedName(value=dn_str)

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
        pattern = "*,ou=admin,dc=example,dc=com"
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
            {"cn": ["test"], "objectclass": ["person"]},
        )

    def test_mark_entry_excluded_basic(
        self, sample_entry: FlextLdifModels.Entry
    ) -> None:
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
        entry_with_metadata = sample_entry.model_copy(
            update={"metadata": existing_metadata}
        )

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
            {
                "cn": ["test"],
                "objectclass": ["person", "inetOrgPerson", "organizationalPerson"],
            },
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
                "objectclass": ["person"],
            },
        )

    def test_has_all_required_attributes(
        self, sample_entry: FlextLdifModels.Entry
    ) -> None:
        """Test when entry has all required attributes."""
        assert FlextLdifFilters.has_required_attributes(
            sample_entry, ["cn", "sn", "mail"]
        )

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
    """Test 6-category entry categorization logic."""

    def _create_dict_entry(
        self,
        dn: str,
        objectclasses: list[str],
        attributes: dict[str, list[str]] | None = None,
    ) -> dict[str, object]:
        """Helper to create dict entry with specified objectClasses."""
        entry: dict[str, object] = {
            FlextLdifConstants.DictKeys.DN: dn,
            FlextLdifConstants.DictKeys.OBJECTCLASS: objectclasses,
        }
        if attributes:
            entry[FlextLdifConstants.DictKeys.ATTRIBUTES] = attributes
        return entry

    def test_categorize_as_schema(self) -> None:
        """Test categorizing schema entries."""
        entry = self._create_dict_entry(
            "cn=schema",
            ["subschema"],
            {"attributeTypes": ["( 2.5.4.3 NAME 'cn' )"]},
        )
        category, reason = FlextLdifFilters.categorize_entry(
            entry,
            categorization_rules={
                "user_objectclasses": ["person"],
                "group_objectclasses": ["groupOfNames"],
                "hierarchy_objectclasses": ["organizationalUnit"],
                "acl_attributes": [],
            },
        )
        assert category == "schema"
        assert reason is None

    def test_categorize_as_hierarchy(self) -> None:
        """Test categorizing hierarchy entries."""
        entry = self._create_dict_entry(
            "ou=users,dc=example,dc=com",
            ["organizationalUnit", "top"],
        )
        category, reason = FlextLdifFilters.categorize_entry(
            entry,
            categorization_rules={
                "user_objectclasses": ["person"],
                "group_objectclasses": ["groupOfNames"],
                "hierarchy_objectclasses": ["organizationalUnit", "organization"],
                "acl_attributes": [],
            },
        )
        assert category == "hierarchy"
        assert reason is None

    def test_categorize_as_users(self) -> None:
        """Test categorizing user entries."""
        entry = self._create_dict_entry(
            "cn=jdoe,ou=users,dc=example,dc=com",
            ["person", "inetOrgPerson"],
        )
        category, reason = FlextLdifFilters.categorize_entry(
            entry,
            categorization_rules={
                "user_objectclasses": ["person", "inetOrgPerson"],
                "group_objectclasses": ["groupOfNames"],
                "hierarchy_objectclasses": ["organizationalUnit"],
                "acl_attributes": [],
            },
        )
        assert category == "users"
        assert reason is None

    def test_categorize_as_groups(self) -> None:
        """Test categorizing group entries."""
        entry = self._create_dict_entry(
            "cn=admins,ou=groups,dc=example,dc=com",
            ["groupOfNames", "top"],
        )
        category, reason = FlextLdifFilters.categorize_entry(
            entry,
            categorization_rules={
                "user_objectclasses": ["person"],
                "group_objectclasses": ["groupOfNames"],
                "hierarchy_objectclasses": ["organizationalUnit"],
                "acl_attributes": [],
            },
        )
        assert category == "groups"
        assert reason is None

    def test_categorize_as_acl(self) -> None:
        """Test categorizing ACL entries."""
        entry = self._create_dict_entry(
            "cn=acl_entry,dc=example,dc=com",
            ["top"],
            {"orclPrivilege": ["entry"]},
        )
        category, reason = FlextLdifFilters.categorize_entry(
            entry,
            categorization_rules={
                "user_objectclasses": ["person"],
                "group_objectclasses": ["groupOfNames"],
                "hierarchy_objectclasses": ["organizationalUnit"],
                "acl_attributes": ["orclPrivilege", "acl"],
            },
        )
        assert category == "acl"
        assert reason is None

    def test_categorize_as_rejected(self) -> None:
        """Test categorizing entries with no matching category."""
        entry = self._create_dict_entry(
            "cn=device1,dc=example,dc=com",
            ["device", "top"],
        )
        category, reason = FlextLdifFilters.categorize_entry(
            entry,
            categorization_rules={
                "user_objectclasses": ["person"],
                "group_objectclasses": ["groupOfNames"],
                "hierarchy_objectclasses": ["organizationalUnit"],
                "acl_attributes": [],
            },
        )
        assert category == "rejected"
        assert reason is not None
        assert "No category match" in reason

    def test_categorize_hierarchy_priority_over_acl(self) -> None:
        """Test that hierarchy has priority over ACL (critical for Oracle containers)."""
        entry = self._create_dict_entry(
            "cn=oraclcontainer,dc=example,dc=com",
            ["orclContainer"],
            {"orclPrivilege": ["entry"]},  # Has ACL attributes but is hierarchy
        )
        category, reason = FlextLdifFilters.categorize_entry(
            entry,
            categorization_rules={
                "user_objectclasses": ["person"],
                "group_objectclasses": ["groupOfNames"],
                "hierarchy_objectclasses": ["orclContainer"],
                "acl_attributes": ["orclPrivilege"],
            },
        )
        assert category == "hierarchy"  # Hierarchy takes priority over ACL
        assert reason is None

    def test_categorize_user_with_dn_pattern_match(self) -> None:
        """Test user categorization with DN pattern validation."""
        entry = self._create_dict_entry(
            "cn=jdoe,ou=users,dc=example,dc=com",
            ["person"],
        )
        category, reason = FlextLdifFilters.categorize_entry(
            entry,
            categorization_rules={
                "user_objectclasses": ["person"],
                "group_objectclasses": ["groupOfNames"],
                "hierarchy_objectclasses": ["organizationalUnit"],
                "user_dn_patterns": ["ou=users"],
                "acl_attributes": [],
            },
        )
        assert category == "users"
        assert reason is None

    def test_categorize_user_with_dn_pattern_mismatch(self) -> None:
        """Test user categorization rejected when DN pattern doesn't match."""
        entry = self._create_dict_entry(
            "cn=jdoe,ou=accounts,dc=example,dc=com",
            ["person"],
        )
        category, reason = FlextLdifFilters.categorize_entry(
            entry,
            categorization_rules={
                "user_objectclasses": ["person"],
                "group_objectclasses": ["groupOfNames"],
                "hierarchy_objectclasses": ["organizationalUnit"],
                "user_dn_patterns": ["ou=users"],
                "acl_attributes": [],
            },
        )
        assert category == "rejected"
        assert reason is not None
        assert "DN pattern mismatch" in reason

    def test_categorize_blocked_objectclass(self) -> None:
        """Test rejection of entries with blocked objectClasses (ALGAR rule)."""
        entry = self._create_dict_entry(
            "cn=oid_entry,dc=example,dc=com",
            ["orclOracleUser"],  # OID-specific class
        )
        category, reason = FlextLdifFilters.categorize_entry(
            entry,
            categorization_rules={
                "user_objectclasses": ["person"],
                "group_objectclasses": ["groupOfNames"],
                "hierarchy_objectclasses": ["organizationalUnit"],
                "acl_attributes": [],
            },
            schema_whitelist_rules={"blocked_objectclasses": ["orclOracleUser"]},
        )
        assert category == "rejected"
        assert reason is not None
        assert "Blocked objectClass" in reason


class TestFilterEntriesByDn:
    """Test DN pattern filtering."""

    @pytest.fixture
    def sample_entries(self) -> list[FlextLdifModels.Entry]:
        """Create sample entries with different DNs."""
        dns = [
            "cn=user1,ou=users,dc=example,dc=com",
            "cn=user2,ou=users,dc=example,dc=com",
            "cn=admin1,ou=admin,dc=example,dc=com",
            "cn=group1,ou=groups,dc=example,dc=com",
        ]

        entries = []
        for dn_str in dns:
            cn_value = dn_str.split(",")[0].split("=")[1]
            entry = create_test_entry(
                dn_str,
                {"cn": [cn_value], "objectclass": ["person"]},
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
        assert len(filtered) == 2  # admin1 and group1

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
        excluded_count = sum(
            1 for e in filtered if FlextLdifFilters.is_entry_excluded(e)
        )
        assert excluded_count == 2  # admin1 and group1 are marked excluded


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
            attr_dict["objectclass"] = objectclasses

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
            {
                "cn": ["user1"],
                "mail": ["user1@example.com"],
                "telephoneNumber": ["123"],
            },
            {"cn": ["user2"], "mail": ["user2@example.com"]},
            {"cn": ["user3"], "telephoneNumber": ["456"]},
            {"cn": ["user4"]},
        ]

        entries = []
        for idx, attrs in enumerate(test_data):
            attrs["objectclass"] = ["person"]
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
