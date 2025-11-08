"""Tests for EntryResult helper methods.

Phase 1 of EntryResult-centric refactoring: Test new helper methods.
"""

from flext_ldif.models import FlextLdifModels


class TestEntryResultHelpers:
    """Test EntryResult helper methods added in Phase 1."""

    def test_from_entries_creates_entry_result(self) -> None:
        """Test EntryResult.from_entries() factory method."""
        # Create sample entries using factory method
        entry1_result = FlextLdifModels.Entry.create(
            dn="cn=user1,dc=example,dc=com",
            attributes={"cn": ["user1"], "objectClass": ["person"]},
        )
        assert entry1_result.is_success
        entry1 = entry1_result.unwrap()

        entry2_result = FlextLdifModels.Entry.create(
            dn="cn=user2,dc=example,dc=com",
            attributes={"cn": ["user2"], "objectClass": ["person"]},
        )
        assert entry2_result.is_success
        entry2 = entry2_result.unwrap()

        entries = [entry1, entry2]

        # Create EntryResult using factory
        result = FlextLdifModels.EntryResult.from_entries(entries, category="users")

        # Verify structure
        assert result.entries_by_category == {"users": entries}
        assert result.statistics.total_entries == 2
        assert len(result.get_all_entries()) == 2

    def test_empty_creates_empty_entry_result(self) -> None:
        """Test EntryResult.empty() factory method."""
        result = FlextLdifModels.EntryResult.empty()

        assert result.entries_by_category == {}
        assert result.statistics.total_entries == 0
        assert result.get_all_entries() == []

    def test_get_all_entries_flattens_categories(self) -> None:
        """Test get_all_entries() flattens all categories."""
        entry1 = FlextLdifModels.Entry.create(
            dn="cn=user1,dc=example,dc=com",
            attributes={"cn": ["user1"]},
        ).unwrap()
        entry2 = FlextLdifModels.Entry.create(
            dn="cn=group1,dc=example,dc=com",
            attributes={"cn": ["group1"]},
        ).unwrap()

        result = FlextLdifModels.EntryResult(
            entries_by_category={
                "users": [entry1],
                "groups": [entry2],
            },
            statistics=FlextLdifModels.Statistics(total_entries=2),
        )

        all_entries = result.get_all_entries()
        assert len(all_entries) == 2
        assert entry1 in all_entries
        assert entry2 in all_entries

    def test_get_category_returns_entries(self) -> None:
        """Test get_category() returns specific category."""
        entry1 = FlextLdifModels.Entry.create(
            dn="cn=user1,dc=example,dc=com",
            attributes={"cn": ["user1"]},
        ).unwrap()
        entry2 = FlextLdifModels.Entry.create(
            dn="cn=group1,dc=example,dc=com",
            attributes={"cn": ["group1"]},
        ).unwrap()

        result = FlextLdifModels.EntryResult(
            entries_by_category={
                "users": [entry1],
                "groups": [entry2],
            },
            statistics=FlextLdifModels.Statistics(total_entries=2),
        )

        users = result.get_category("users")
        assert users == [entry1]

        groups = result.get_category("groups")
        assert groups == [entry2]

    def test_get_category_with_default(self) -> None:
        """Test get_category() with default for missing category."""
        result = FlextLdifModels.EntryResult.empty()

        # Missing category returns default
        entries = result.get_category("missing", default=[])
        assert entries == []

        # Missing category without default returns empty list
        entries2 = result.get_category("missing")
        assert entries2 == []

    def test_merge_combines_entry_results(self) -> None:
        """Test merge() combines two EntryResults."""
        entry1 = FlextLdifModels.Entry.create(
            dn="cn=user1,dc=example,dc=com",
            attributes={"cn": ["user1"]},
        ).unwrap()
        entry2 = FlextLdifModels.Entry.create(
            dn="cn=user2,dc=example,dc=com",
            attributes={"cn": ["user2"]},
        ).unwrap()

        result1 = FlextLdifModels.EntryResult(
            entries_by_category={"users": [entry1]},
            statistics=FlextLdifModels.Statistics(total_entries=1),
        )

        result2 = FlextLdifModels.EntryResult(
            entries_by_category={"users": [entry2]},
            statistics=FlextLdifModels.Statistics(total_entries=1),
        )

        merged = result1.merge(result2)

        # Verify merged categories
        assert len(merged.entries_by_category["users"]) == 2
        assert entry1 in merged.entries_by_category["users"]
        assert entry2 in merged.entries_by_category["users"]

        # Verify merged statistics
        assert merged.statistics.total_entries == 2

    def test_merge_handles_different_categories(self) -> None:
        """Test merge() with different categories."""
        entry1 = FlextLdifModels.Entry.create(
            dn="cn=user1,dc=example,dc=com",
            attributes={"cn": ["user1"]},
        ).unwrap()
        entry2 = FlextLdifModels.Entry.create(
            dn="cn=group1,dc=example,dc=com",
            attributes={"cn": ["group1"]},
        ).unwrap()

        result1 = FlextLdifModels.EntryResult(
            entries_by_category={"users": [entry1]},
            statistics=FlextLdifModels.Statistics(total_entries=1),
        )

        result2 = FlextLdifModels.EntryResult(
            entries_by_category={"groups": [entry2]},
            statistics=FlextLdifModels.Statistics(total_entries=1),
        )

        merged = result1.merge(result2)

        # Verify separate categories preserved
        assert merged.entries_by_category["users"] == [entry1]
        assert merged.entries_by_category["groups"] == [entry2]
        assert merged.statistics.total_entries == 2

    def test_merge_preserves_immutability(self) -> None:
        """Test merge() doesn't modify original EntryResults."""
        entry1 = FlextLdifModels.Entry.create(
            dn="cn=user1,dc=example,dc=com",
            attributes={"cn": ["user1"]},
        ).unwrap()

        result1 = FlextLdifModels.EntryResult(
            entries_by_category={"users": [entry1]},
            statistics=FlextLdifModels.Statistics(total_entries=1),
        )

        result2 = FlextLdifModels.EntryResult.empty()

        # Merge should create new instance
        merged = result1.merge(result2)

        # Original should be unchanged
        assert result1.entries_by_category == {"users": [entry1]}
        assert result1.statistics.total_entries == 1

        # Merged should have same data
        assert merged.entries_by_category == {"users": [entry1]}
        assert merged.statistics.total_entries == 1
