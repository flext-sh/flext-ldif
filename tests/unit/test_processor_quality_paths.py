"""Tests for processor quality assessment paths.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import FlextLdifModels, FlextLdifProcessor


class TestProcessorQualityPaths:
    """Tests for processor quality assessment code paths."""

    @staticmethod
    def test_validate_entries_with_duplicate_dns() -> None:
        """Test quality check for duplicate DNs."""
        processor = FlextLdifProcessor()

        # Create entries with duplicate DNs
        entries: list[FlextLdifModels.Entry] = []
        for _ in range(2):
            entry_result = FlextLdifModels.Entry.create({
                "dn": "cn=duplicate,dc=example,dc=com",
                "attributes": {
                    "cn": ["duplicate"],
                    "objectClass": ["person"],
                },
            })
            if entry_result.is_success:
                entries.append(entry_result.value)

        # Quality check should detect duplicates
        quality_data = processor._AnalyticsHelper.calculate_quality_metrics(entries)
        assert "issues" in quality_data
        issues_obj = quality_data.get("issues", [])
        assert isinstance(issues_obj, list)
        issues: list[str] = issues_obj
        assert any("Duplicate DNs" in str(issue) for issue in issues)

    @staticmethod
    def test_validate_entries_missing_object_class() -> None:
        """Test quality check for entries without objectClass."""
        processor = FlextLdifProcessor()

        # Create entries without objectClass
        entries: list[FlextLdifModels.Entry] = []
        for i in range(5):
            entry_result = FlextLdifModels.Entry.create({
                "dn": f"cn=user{i},dc=example,dc=com",
                "attributes": {
                    "cn": [f"user{i}"],
                },
            })
            if entry_result.is_success:
                entries.append(entry_result.value)

        # Quality check should detect missing objectClass
        quality_data = processor._AnalyticsHelper.calculate_quality_metrics(entries)
        assert "issues" in quality_data
        issues_obj = quality_data.get("issues", [])
        assert isinstance(issues_obj, list)
        issues: list[str] = issues_obj
        assert any("objectClass" in str(issue) for issue in issues)

    @staticmethod
    def test_validate_entries_with_few_attributes() -> None:
        """Test quality check for entries with minimal attributes."""
        processor = FlextLdifProcessor()

        # Create entries with only 1 attribute each
        entries: list[FlextLdifModels.Entry] = []
        for i in range(5):
            entry_result = FlextLdifModels.Entry.create({
                "dn": f"cn=minimal{i},dc=example,dc=com",
                "attributes": {
                    "cn": [f"minimal{i}"],
                },
            })
            if entry_result.is_success:
                entries.append(entry_result.value)

        # Quality check should detect minimal attributes
        quality_data = processor._AnalyticsHelper.calculate_quality_metrics(entries)
        assert "issues" in quality_data
        issues_obj = quality_data.get("issues", [])
        assert isinstance(issues_obj, list)
        issues: list[str] = issues_obj
        assert any("few attributes" in str(issue) for issue in issues)

    @staticmethod
    def test_merge_entries_without_duplicates() -> None:
        """Test merge when entries have no duplicates."""
        processor = FlextLdifProcessor()

        # Create first set of entries
        entries1: list[FlextLdifModels.Entry] = []
        for i in range(2):
            entry_result = FlextLdifModels.Entry.create({
                "dn": f"cn=user{i},dc=example,dc=com",
                "attributes": {
                    "cn": [f"user{i}"],
                    "objectClass": ["person"],
                },
            })
            if entry_result.is_success:
                entries1.append(entry_result.value)

        # Create second set with different DNs
        entries2: list[FlextLdifModels.Entry] = []
        for i in range(2, 4):
            entry_result = FlextLdifModels.Entry.create({
                "dn": f"cn=user{i},dc=example,dc=com",
                "attributes": {
                    "cn": [f"user{i}"],
                    "objectClass": ["person"],
                },
            })
            if entry_result.is_success:
                entries2.append(entry_result.value)

        # Merge should combine all entries
        result = processor.merge_entries(entries1, entries2)
        assert result.is_success
        merged = result.value
        assert len(merged) == 4
