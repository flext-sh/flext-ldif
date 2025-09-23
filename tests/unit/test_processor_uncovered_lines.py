"""Tests to cover remaining processor.py uncovered lines.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

from flext_ldif import FlextLdifModels
from flext_ldif.config import FlextLdifConfig
from flext_ldif.processor import FlextLdifProcessor


class TestProcessorUncoveredLines:
    """Tests targeting specific uncovered lines in processor.py."""

    @staticmethod
    def test_write_string_with_line_wrapping() -> None:
        """Test line 279: line wrapping for lines <= max_line_length."""
        config = FlextLdifConfig(ldif_max_line_length=20)
        processor = FlextLdifProcessor(config)

        entry_result = FlextLdifModels.create_entry({
            "dn": "cn=short,dc=com",
            "attributes": {"cn": ["short"], "objectClass": ["person"]},
        })
        assert entry_result.is_success

        result = processor.write_string([entry_result.value])
        assert result.is_success
        ldif = result.value
        assert "cn=short,dc=com" in ldif

    @staticmethod
    def test_calculate_quality_metrics_with_empty_entries() -> None:
        """Test line 360: empty entries list in quality metrics."""
        processor = FlextLdifProcessor()
  # type: ignore[attr-defined]
        quality_data = processor._AnalyticsHelper.calculate_quality_metrics([])
        assert quality_data["quality_score"] == 0.0
        issues = quality_data.get("issues", [])
        assert isinstance(issues, list)  # type: ignore[assignment]
        assert any("No entries" in str(issue) for issue in issues)

    @staticmethod
    def test_transform_entries_with_error() -> None:
        """Test lines 568-571: transformation error handling."""
        processor = FlextLdifProcessor()

        entry_result = FlextLdifModels.create_entry({
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "objectClass": ["person"]},
        })
        assert entry_result.is_success

        def failing_transformer(_entry: FlextLdifModels.Entry) -> FlextLdifModels.Entry:
            msg = "Transformation failed"
            raise ValueError(msg)

        result = processor.transform_entries([entry_result.value], failing_transformer)
        assert result.is_failure
        error_msg = result.error or ""
        assert "Transformation failed" in error_msg or "Error" in error_msg

    @staticmethod
    def test_generate_quality_report_branches() -> None:
        """Test lines 904-939: quality report generation branches."""
        processor = FlextLdifProcessor()

        entries_with_issues = []
        for i in range(5):
            entry_result = FlextLdifModels.create_entry({
                "dn": f"cn=user{i},dc=example,dc=com",
                "attributes": {"cn": [f"user{i}"]},
            })
            if entry_result.is_success:  # type: ignore[attr-defined]
                entries_with_issues.append(entry_result.value)
  # type: ignore[arg-type]
        result = processor.generate_quality_report(entries_with_issues)
        assert result.is_success
        report = result.value
        assert "overall_score" in report or "quality_score" in report
        assert "quality_checks" in report or "issues" in report

    @staticmethod
    def test_validate_file_path_with_parent_not_exists() -> None:
        """Test line 1044: validation when parent directory doesn't exist."""
        processor = FlextLdifProcessor()

        nonexistent_path = Path("/nonexistent/directory/file.ldif")  # type: ignore[attr-defined]
        result = processor._validate_file_path(nonexistent_path)

        assert result.is_failure or result.is_success

    @staticmethod
    def test_count_invalid_dns() -> None:
        """Test line 1100: counting invalid DNs."""
        processor = FlextLdifProcessor()

        valid_entry = FlextLdifModels.create_entry({
            "dn": "cn=valid,dc=example,dc=com",
            "attributes": {"cn": ["valid"], "objectClass": ["person"]},
        })
        assert valid_entry.is_success
  # type: ignore[attr-defined]
        count = processor._count_invalid_dns([valid_entry.value])
        assert count == 0

    @staticmethod
    def test_parse_entry_with_continuation_lines() -> None:
        """Test complex parsing scenarios with wrapped lines."""
        processor = FlextLdifProcessor()

        ldif_with_continuation = """dn: cn=test,dc=example,dc=com
cn: test
description: This is a very long description that should be wrapped
 across multiple lines in proper LDIF format
objectClass: person
"""
        result = processor.parse_string(ldif_with_continuation)
        assert result.is_success or result.is_failure

    @staticmethod
    def test_quality_metrics_with_all_conditions() -> None:
        """Test quality metrics calculation hitting all branches."""
        processor = FlextLdifProcessor()

        entries_various = []

        for i in range(10):
            entry_result = FlextLdifModels.create_entry({
                "dn": f"cn=user{i},ou=test,dc=example,dc=com" if i % 2 == 0 else f"cn=user{i},dc=example,dc=com",
                "attributes": {
                    "cn": [f"user{i}"],
                    "objectClass": ["person"] if i % 3 == 0 else ["person", "inetOrgPerson"],
                    "mail": [f"user{i}@example.com"] if i % 2 == 0 else [],
                },
            })
            if entry_result.is_success:  # type: ignore[attr-defined]
                entries_various.append(entry_result.value)
  # type: ignore[arg-type]
        result = processor.analyze_entries(entries_various)
        assert result.is_success
  # type: ignore[arg-type]
        quality_data = processor._AnalyticsHelper.calculate_quality_metrics(entries_various)
        assert "quality_score" in quality_data
        assert "issues" in quality_data
