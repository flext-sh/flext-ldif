"""Tests for EntryResult helper methods.

Phase 1 of EntryResult-centric refactoring: Test new helper methods.
"""

from tests import m, s

from flext_ldif.models import m


class TestsFlextLdifEntryResultHelpers(s):
    """Test EntryResult helper methods added in Phase 1."""

    def test_from_entries_creates_entry_result(self) -> None:
        """Test EntryResult.from_entries() factory method."""
        entry1 = RfcTestHelpers.test_entry_create_and_unwrap(
            "cn=user1,dc=example,dc=com",
            {"cn": ["user1"], "objectClass": ["person"]},
        )
        entry2 = RfcTestHelpers.test_entry_create_and_unwrap(
            "cn=user2,dc=example,dc=com",
            {"cn": ["user2"], "objectClass": ["person"]},
        )
        result = m.EntryResult.from_entries(
            [entry1, entry2],
            category="users",
        )
        # Verify entries_by_category using get() for type safety
        users_category = result.entries_by_category.get("users", [])
        assert users_category == [entry1, entry2]
        assert result.statistics.total_entries == 2
        assert len(result.get_all_entries()) == 2

    def test_empty_creates_empty_entry_result(self) -> None:
        """Test EntryResult.empty() factory method."""
        result = m.EntryResult.empty()

        # Verify empty categories
        assert len(result.entries_by_category) == 0
        assert result.statistics.total_entries == 0
        assert result.get_all_entries() == []

    def test_get_all_entries_flattens_categories(self) -> None:
        """Test get_all_entries() flattens all categories."""
        entry1 = m.Entry.create(
            dn="cn=user1,dc=example,dc=com",
            attributes={"cn": ["user1"]},
        ).unwrap()
        entry2 = m.Entry.create(
            dn="cn=group1,dc=example,dc=com",
            attributes={"cn": ["group1"]},
        ).unwrap()

        # Use _FlexibleCategories directly for type safety
        categories = m.FlexibleCategories()
        categories.add_entries("users", [entry1])
        categories.add_entries("groups", [entry2])
        result = m.EntryResult(
            entries_by_category=categories,
            statistics=m.Statistics(total_entries=2),
        )

        all_entries = result.get_all_entries()
        assert len(all_entries) == 2
        assert entry1 in all_entries
        assert entry2 in all_entries

    def test_get_category_returns_entries(self) -> None:
        """Test get_category() returns specific category."""
        entry1 = m.Entry.create(
            dn="cn=user1,dc=example,dc=com",
            attributes={"cn": ["user1"]},
        ).unwrap()
        entry2 = m.Entry.create(
            dn="cn=group1,dc=example,dc=com",
            attributes={"cn": ["group1"]},
        ).unwrap()

        # Use _FlexibleCategories directly for type safety
        categories = m.FlexibleCategories()
        categories.add_entries("users", [entry1])
        categories.add_entries("groups", [entry2])
        result = m.EntryResult(
            entries_by_category=categories,
            statistics=m.Statistics(total_entries=2),
        )

        users = result.get_category("users")
        assert users == [entry1]

        groups = result.get_category("groups")
        assert groups == [entry2]

    def test_get_category_with_default(self) -> None:
        """Test get_category() with default for missing category."""
        result = m.EntryResult.empty()

        # Missing category returns default
        entries = result.get_category("missing", default=[])
        assert entries == []

        # Missing category without default returns empty list
        entries2 = result.get_category("missing")
        assert entries2 == []

    def test_merge_combines_entry_results(self) -> None:
        """Test merge() combines two EntryResults."""
        entry1 = m.Entry.create(
            dn="cn=user1,dc=example,dc=com",
            attributes={"cn": ["user1"]},
        ).unwrap()
        entry2 = m.Entry.create(
            dn="cn=user2,dc=example,dc=com",
            attributes={"cn": ["user2"]},
        ).unwrap()

        # Use _FlexibleCategories directly for type safety
        categories1 = m.FlexibleCategories()
        categories1.add_entries("users", [entry1])
        result1 = m.EntryResult(
            entries_by_category=categories1,
            statistics=m.Statistics(total_entries=1),
        )

        categories2 = m.FlexibleCategories()
        categories2.add_entries("users", [entry2])
        result2 = m.EntryResult(
            entries_by_category=categories2,
            statistics=m.Statistics(total_entries=1),
        )

        merged = result1.merge(result2)

        # Verify merged categories
        users_category = merged.entries_by_category.get("users", [])
        assert len(users_category) == 2
        assert entry1 in users_category
        assert entry2 in users_category

        # Verify merged statistics
        assert merged.statistics.total_entries == 2

    def test_merge_handles_different_categories(self) -> None:
        """Test merge() with different categories."""
        entry1 = m.Entry.create(
            dn="cn=user1,dc=example,dc=com",
            attributes={"cn": ["user1"]},
        ).unwrap()
        entry2 = m.Entry.create(
            dn="cn=group1,dc=example,dc=com",
            attributes={"cn": ["group1"]},
        ).unwrap()

        # Use _FlexibleCategories directly for type safety
        categories1 = m.FlexibleCategories()
        categories1.add_entries("users", [entry1])
        result1 = m.EntryResult(
            entries_by_category=categories1,
            statistics=m.Statistics(total_entries=1),
        )

        categories2 = m.FlexibleCategories()
        categories2.add_entries("groups", [entry2])
        result2 = m.EntryResult(
            entries_by_category=categories2,
            statistics=m.Statistics(total_entries=1),
        )

        merged = result1.merge(result2)

        # Verify separate categories preserved
        assert merged.entries_by_category.get("users", []) == [entry1]
        assert merged.entries_by_category.get("groups", []) == [entry2]
        assert merged.statistics.total_entries == 2

    def test_merge_preserves_immutability(self) -> None:
        """Test merge() doesn't modify original EntryResults."""
        entry1 = m.Entry.create(
            dn="cn=user1,dc=example,dc=com",
            attributes={"cn": ["user1"]},
        ).unwrap()

        # Use _FlexibleCategories directly for type safety
        categories1 = m.FlexibleCategories()
        categories1.add_entries("users", [entry1])
        result1 = m.EntryResult(
            entries_by_category=categories1,
            statistics=m.Statistics(total_entries=1),
        )

        result2 = m.EntryResult.empty()

        # Merge should create new instance
        merged = result1.merge(result2)

        # Original should be unchanged
        assert result1.entries_by_category.get("users", []) == [entry1]
        assert result1.statistics.total_entries == 1

        # Merged should have same data
        assert merged.entries_by_category.get("users", []) == [entry1]
        assert merged.statistics.total_entries == 1
