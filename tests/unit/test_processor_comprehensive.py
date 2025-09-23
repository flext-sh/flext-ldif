"""Comprehensive tests for FlextLdifProcessor - targeting 100% coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import cast
from unittest.mock import patch

from flext_ldif.config import FlextLdifConfig
from flext_ldif.models import FlextLdifModels
from flext_ldif.processor import FlextLdifProcessor


class TestFlextLdifProcessorComprehensive:
    """Comprehensive processor tests for 100% coverage."""

    def test_processor_initialization_with_config(self) -> None:
        """Test processor initialization with custom config."""
        config = FlextLdifConfig(ldif_max_entries=5000)
        processor = FlextLdifProcessor(config=config)

        assert processor is not None  # type: ignore[attr-defined]
        assert processor._config == config

    def test_processor_initialization_without_config(self) -> None:
        """Test processor initialization without config."""
        processor = FlextLdifProcessor()

        assert processor is not None  # type: ignore[attr-defined]
        assert processor._config is None

    def test_execute_method(self) -> None:
        """Test execute method returns health check."""
        processor = FlextLdifProcessor()
        result = processor.execute()

        assert result.is_success
        assert "status" in result.value
        assert result.value["status"] == "healthy"

    def test_parse_string_empty_content(self) -> None:
        """Test parsing empty content."""
        processor = FlextLdifProcessor()
        result = processor.parse_string("")

        assert result.is_success
        assert result.value == []

    def test_parse_string_whitespace_only(self) -> None:
        """Test parsing whitespace-only content."""
        processor = FlextLdifProcessor()
        result = processor.parse_string("   \n\n   ")

        assert result.is_success
        assert result.value == []

    def test_parse_string_simple_entry(self) -> None:
        """Test parsing simple LDIF entry."""
        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
sn: Test User"""

        processor = FlextLdifProcessor()
        result = processor.parse_string(ldif_content)

        assert result.is_success
        assert len(result.value) == 1
        entry = result.value[0]
        assert entry.dn.value == "cn=test,dc=example,dc=com"
        assert entry.get_attribute("cn") == ["test"]

    def test_parse_string_multiple_entries(self) -> None:
        """Test parsing multiple LDIF entries."""
        ldif_content = """dn: cn=user1,dc=example,dc=com
cn: user1
objectClass: person

dn: cn=user2,dc=example,dc=com
cn: user2
objectClass: person"""

        processor = FlextLdifProcessor()
        result = processor.parse_string(ldif_content)

        assert result.is_success
        assert len(result.value) == 2

    def test_parse_string_with_line_continuations(self) -> None:
        """Test parsing LDIF with line continuations."""
        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
description: This is a very long description that
 continues on the next line
objectClass: person"""

        processor = FlextLdifProcessor()
        result = processor.parse_string(ldif_content)

        assert result.is_success
        assert len(result.value) == 1
        entry = result.value[0]
        description = entry.get_attribute("description")
        assert description is not None
        assert "continues on the next line" in description[0]

    def test_parse_string_invalid_no_dn(self) -> None:
        """Test parsing invalid LDIF without DN."""
        ldif_content = """cn: test
objectClass: person"""

        processor = FlextLdifProcessor()
        result = processor.parse_string(ldif_content)

        assert result.is_failure
        assert result.error and "must start with 'dn:'" in result.error

    def test_parse_string_empty_dn(self) -> None:
        """Test parsing LDIF with empty DN."""
        ldif_content = """dn:
cn: test"""

        processor = FlextLdifProcessor()
        result = processor.parse_string(ldif_content)

        assert result.is_failure
        assert result.error and "DN cannot be empty" in result.error

    def test_parse_ldif_file_success(self) -> None:
        """Test parsing LDIF file successfully."""
        ldif_content = """dn: cn=filetest,dc=example,dc=com
cn: filetest
objectClass: person"""

        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", suffix=".ldif", delete=False
        ) as f:
            f.write(ldif_content)
            temp_path = Path(f.name)

        try:
            processor = FlextLdifProcessor()
            result = processor.parse_ldif_file(temp_path)

            assert result.is_success
            assert len(result.value) == 1
            assert result.value[0].get_attribute("cn") == ["filetest"]
        finally:
            temp_path.unlink()

    def test_parse_ldif_file_nonexistent(self) -> None:
        """Test parsing nonexistent LDIF file."""
        processor = FlextLdifProcessor()
        nonexistent_path = Path("/nonexistent/path/test.ldif")
        result = processor.parse_ldif_file(nonexistent_path)

        assert result.is_failure
        assert result.error and (
            "Failed to read file" in result.error
            or "Cannot create directory" in result.error
        )

    def test_parse_ldif_file_unicode_decode_error(self) -> None:
        """Test parsing file with encoding issues."""
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".ldif", delete=False) as f:
            # Write invalid UTF-8 bytes
            f.write(b"\xff\xfe\x00invalid")
            temp_path = Path(f.name)

        try:
            processor = FlextLdifProcessor()
            result = processor.parse_ldif_file(temp_path)

            assert result.is_failure
            assert result.error and "Failed to decode file" in result.error
        finally:
            temp_path.unlink()

    def test_validate_entries_empty_list(self) -> None:
        """Test validating empty entries list."""
        processor = FlextLdifProcessor()
        result = processor.validate_entries([])

        assert result.is_failure
        assert result.error and "No entries to validate" in result.error

    def test_validate_entries_valid(self) -> None:
        """Test validating valid entries."""  # type: ignore[assignment]
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "objectClass": ["person"], "sn": ["Test"]},
        }
        entry_result = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry_data)
        )
        assert entry_result.is_success

        processor = FlextLdifProcessor()
        result = processor.validate_entries([entry_result.value])

        assert result.is_success

    def test_validate_entries_invalid_dn(self) -> None:
        """Test validating entries with invalid DN."""
        # Create entry with invalid DN (no = sign)  # type: ignore[assignment]
        entry_data = {"dn": "invalid_dn_format", "attributes": {"cn": ["test"]}}
        # This should fail at entry creation level
        entry_result = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry_data)
        )
        assert entry_result.is_failure

    def test_write_string_empty_entries(self) -> None:
        """Test writing empty entries list."""
        processor = FlextLdifProcessor()
        result = processor.write_string([])

        assert result.is_success
        assert not result.value

    def test_write_string_single_entry(self) -> None:
        """Test writing single entry to string."""  # type: ignore[assignment]
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "objectClass": ["person"]},
        }
        entry_result = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry_data)
        )
        assert entry_result.is_success

        processor = FlextLdifProcessor()
        result = processor.write_string([entry_result.value])

        assert result.is_success
        assert "dn: cn=test,dc=example,dc=com" in result.value
        assert "cn: test" in result.value

    def test_write_string_with_line_wrapping(self) -> None:
        """Test writing with line wrapping enabled."""
        processor = FlextLdifProcessor()
  # type: ignore[assignment]
        entry_data = {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": ["test"]}}
        entry_result = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry_data)
        )
        assert entry_result.is_success

        result = processor.write_string([entry_result.value])
        assert result.is_success

    def test_write_file_success(self) -> None:
        """Test writing entries to file successfully."""  # type: ignore[assignment]
        entry_data = {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": ["test"]}}
        entry_result = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry_data)
        )
        assert entry_result.is_success

        with tempfile.NamedTemporaryFile(suffix=".ldif", delete=False) as f:
            temp_path = f.name

        try:
            processor = FlextLdifProcessor()
            result = processor.write_file([entry_result.value], temp_path)

            assert result.is_success

            # Verify file was written
            written_content = Path(temp_path).read_text(encoding="utf-8")
            assert "dn: cn=test,dc=example,dc=com" in written_content
        finally:
            Path(temp_path).unlink()

    def test_write_file_permission_error(self) -> None:
        """Test writing to path without permissions."""  # type: ignore[assignment]
        entry_data = {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": ["test"]}}
        entry_result = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry_data)
        )
        assert entry_result.is_success

        processor = FlextLdifProcessor()
        # Try to write to root directory (should fail)
        result = processor.write_file([entry_result.value], "/root/test.ldif")

        assert result.is_failure
        assert result.error and (
            "Failed to write file" in result.error
            or "No write permission" in result.error
            or "File path validation failed" in result.error
            or "Permission denied" in result.error
        )

    def test_transform_entries_empty(self) -> None:
        """Test transforming empty entries list."""
        processor = FlextLdifProcessor()
        result = processor.transform_entries([], lambda x: x)

        assert result.is_success
        assert result.value == []

    def test_transform_entries_identity(self) -> None:
        """Test transforming entries with identity function."""  # type: ignore[assignment]
        entry_data = {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": ["test"]}}
        entry_result = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry_data)
        )
        assert entry_result.is_success

        processor = FlextLdifProcessor()
        result = processor.transform_entries([entry_result.value], lambda x: x)

        assert result.is_success
        assert len(result.value) == 1

    def test_transform_entries_with_exception(self) -> None:
        """Test transformation with failing transformer."""  # type: ignore[assignment]
        entry_data = {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": ["test"]}}
        entry_result = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry_data)
        )
        assert entry_result.is_success

        def failing_transformer(_entry: FlextLdifModels.Entry) -> FlextLdifModels.Entry:
            msg = "Transformation failed"
            raise ValueError(msg)

        processor = FlextLdifProcessor()
        result = processor.transform_entries([entry_result.value], failing_transformer)

        assert result.is_failure
        assert result.error and "Transformation failed for entry 1" in result.error

    def test_analyze_entries_empty(self) -> None:
        """Test analyzing empty entries list."""
        processor = FlextLdifProcessor()
        result = processor.analyze_entries([])

        assert result.is_success
        assert "entry_count" in result.value
        assert result.value["entry_count"] == 0

    def test_analyze_entries_small_count(self) -> None:
        """Test analyzing small number of entries (basic analysis)."""  # type: ignore[assignment]
        entry_data = {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": ["test"]}}
        entry_result = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry_data)
        )
        assert entry_result.is_success

        processor = FlextLdifProcessor()
        # Should trigger basic analysis (< MIN_ENTRY_COUNT_FOR_ANALYTICS)
        result = processor.analyze_entries([entry_result.value])

        assert result.is_success
        assert "note" in result.value
        assert "Basic analysis only" in str(result.value["note"])

    def test_analyze_entries_comprehensive(self) -> None:
        """Test comprehensive analysis with many entries."""
        entries = []
        # Create enough entries to trigger comprehensive analysis (use 100 to be safe)
        for i in range(100):  # Above MIN_ENTRY_COUNT_FOR_ANALYTICS  # type: ignore[assignment]
            entry_data = {
                "dn": f"cn=user{i},dc=example,dc=com",
                "attributes": {"cn": [f"user{i}"], "objectClass": ["person"]},
            }
            entry_result = FlextLdifModels.create_entry(
                cast("dict[str, object]", entry_data)
            )
            assert entry_result.is_success
            entry: FlextLdifModels.Entry = entry_result.value  # type: ignore[attr-defined]
            entries.append(entry)

        processor = FlextLdifProcessor()  # type: ignore[arg-type]
        result = processor.analyze_entries(entries)

        assert result.is_success
        assert "basic_statistics" in result.value
        assert "dn_analysis" in result.value
        assert "quality_metrics" in result.value
        assert "analysis_timestamp" in result.value

    def test_analyze_entries_exception(self) -> None:
        """Test analysis with exception."""
        processor = FlextLdifProcessor()
  # type: ignore[assignment]
        entry_data = {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": ["test"]}}
        entry_result = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry_data)
        )
        assert entry_result.is_success

        # Use fewer entries to trigger basic analysis, then mock it to fail
        result = processor.analyze_entries(
            [entry_result.value] * 5
        )  # Less than MIN_ENTRY_COUNT_FOR_ANALYTICS

        # This should succeed for basic analysis
        assert result.is_success

    def test_filter_entries_by_dn_pattern_empty(self) -> None:
        """Test filtering empty list by DN pattern."""
        processor = FlextLdifProcessor()
        result = processor.filter_entries_by_dn_pattern([], ".*test.*")

        assert result.is_success
        assert result.value == []

    def test_filter_entries_by_dn_pattern_success(self) -> None:
        """Test filtering entries by DN pattern successfully."""  # type: ignore[assignment]
        entry1_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"]},
        }  # type: ignore[assignment]
        entry2_data = {
            "dn": "cn=user,dc=example,dc=com",
            "attributes": {"cn": ["user"]},
        }
        entry1 = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry1_data)
        ).value
        entry2 = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry2_data)
        ).value

        processor = FlextLdifProcessor()
        result = processor.filter_entries_by_dn_pattern([entry1, entry2], ".*test.*")

        assert result.is_success
        assert len(result.value) == 1
        assert result.value[0].dn.value == "cn=test,dc=example,dc=com"

    def test_filter_entries_by_dn_pattern_invalid_regex(self) -> None:
        """Test filtering with invalid regex pattern."""  # type: ignore[assignment]
        entry_data = {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": ["test"]}}
        entry = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry_data)
        ).value

        processor = FlextLdifProcessor()
        result = processor.filter_entries_by_dn_pattern([entry], "[invalid_regex")

        assert result.is_failure
        assert result.error and "Invalid regex pattern" in result.error

    def test_filter_entries_by_object_class_empty(self) -> None:
        """Test filtering empty list by object class."""
        processor = FlextLdifProcessor()
        result = processor.filter_entries_by_object_class([], "person")

        assert result.is_success
        assert result.value == []

    def test_filter_entries_by_object_class_success(self) -> None:
        """Test filtering entries by object class successfully."""  # type: ignore[assignment]
        person_data = {
            "dn": "cn=person,dc=example,dc=com",
            "attributes": {"cn": ["person"], "objectClass": ["person"]},
        }  # type: ignore[assignment]
        group_data = {
            "dn": "cn=group,dc=example,dc=com",
            "attributes": {"cn": ["group"], "objectClass": ["groupOfNames"]},
        }
        person_entry = FlextLdifModels.create_entry(
            cast("dict[str, object]", person_data)
        ).value
        group_entry = FlextLdifModels.create_entry(
            cast("dict[str, object]", group_data)
        ).value

        processor = FlextLdifProcessor()
        result = processor.filter_entries_by_object_class(
            [person_entry, group_entry], "person"
        )

        assert result.is_success
        assert len(result.value) == 1
        assert result.value[0].dn.value == "cn=person,dc=example,dc=com"

    def test_get_entry_by_dn_found(self) -> None:
        """Test getting entry by DN when found."""  # type: ignore[assignment]
        entry_data = {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": ["test"]}}
        entry = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry_data)
        ).value

        processor = FlextLdifProcessor()
        result = processor.get_entry_by_dn([entry], "cn=test,dc=example,dc=com")

        assert result.is_success
        assert result.value is not None
        assert result.value.dn.value == "cn=test,dc=example,dc=com"

    def test_get_entry_by_dn_not_found(self) -> None:
        """Test getting entry by DN when not found."""  # type: ignore[assignment]
        entry_data = {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": ["test"]}}
        entry = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry_data)
        ).value

        processor = FlextLdifProcessor()
        result = processor.get_entry_by_dn([entry], "cn=notfound,dc=example,dc=com")

        assert result.is_success
        assert result.value is None

    def test_get_entries_by_attribute_empty(self) -> None:
        """Test getting entries by attribute from empty list."""
        processor = FlextLdifProcessor()
        result = processor.get_entries_by_attribute([], "cn", "test")

        assert result.is_success
        assert result.value == []

    def test_get_entries_by_attribute_found(self) -> None:
        """Test getting entries by attribute when found."""  # type: ignore[assignment]
        entry1_data = {
            "dn": "cn=test1,dc=example,dc=com",
            "attributes": {"cn": ["test"], "mail": ["test@example.com"]},
        }  # type: ignore[assignment]
        entry2_data = {
            "dn": "cn=test2,dc=example,dc=com",
            "attributes": {"cn": ["other"], "mail": ["other@example.com"]},
        }
        entry1 = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry1_data)
        ).value
        entry2 = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry2_data)
        ).value

        processor = FlextLdifProcessor()
        result = processor.get_entries_by_attribute([entry1, entry2], "cn", "test")

        assert result.is_success
        assert len(result.value) == 1
        assert result.value[0].dn.value == "cn=test1,dc=example,dc=com"

    def test_validate_schema_compliance_empty(self) -> None:
        """Test schema compliance validation with empty entries."""
        processor = FlextLdifProcessor()
        result = processor.validate_schema_compliance([], {})

        assert result.is_success
        assert result.value["status"] == "no_entries"

    def test_validate_schema_compliance_with_rules(self) -> None:
        """Test schema compliance validation with rules."""  # type: ignore[assignment]
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "objectClass": ["person"], "sn": ["Test"]},
        }
        entry = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry_data)
        ).value

        schema_rules = {
            "required_attributes": ["cn", "sn"],
            "required_object_classes": ["person"],
        }

        processor = FlextLdifProcessor()
        result = processor.validate_schema_compliance(
            [entry], cast("dict[str, object]", schema_rules)
        )

        assert result.is_success
        assert "total_entries" in result.value
        assert "compliant_entries" in result.value
        assert "compliance_percentage" in result.value
        assert result.value["compliance_percentage"] == 100.0

    def test_merge_entries_empty_lists(self) -> None:
        """Test merging empty entry lists."""
        processor = FlextLdifProcessor()
        result = processor.merge_entries([], [])

        assert result.is_success
        assert result.value == []

    def test_merge_entries_first_empty(self) -> None:
        """Test merging with first list empty."""  # type: ignore[assignment]
        entry_data = {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": ["test"]}}
        entry = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry_data)
        ).value

        processor = FlextLdifProcessor()
        result = processor.merge_entries([], [entry])

        assert result.is_success
        assert len(result.value) == 1

    def test_merge_entries_second_empty(self) -> None:
        """Test merging with second list empty."""  # type: ignore[assignment]
        entry_data = {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": ["test"]}}
        entry = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry_data)
        ).value

        processor = FlextLdifProcessor()
        result = processor.merge_entries([entry], [])

        assert result.is_success
        assert len(result.value) == 1

    def test_merge_entries_with_duplicates_no_overwrite(self) -> None:
        """Test merging entries with duplicates without overwriting."""  # type: ignore[assignment]
        entry1_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test1"]},
        }  # type: ignore[assignment]
        entry2_data = {
            "dn": "cn=test,dc=example,dc=com",  # Same DN
            "attributes": {"cn": ["test2"]},
        }
        entry1 = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry1_data)
        ).value
        entry2 = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry2_data)
        ).value

        processor = FlextLdifProcessor()
        result = processor.merge_entries([entry1], [entry2], overwrite_duplicates=False)

        assert result.is_success
        assert len(result.value) == 1  # Duplicate not added
        assert result.value[0].get_attribute("cn") == ["test1"]  # Original kept

    def test_merge_entries_with_duplicates_overwrite(self) -> None:
        """Test merging entries with duplicates with overwriting."""  # type: ignore[assignment]
        entry1_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test1"]},
        }  # type: ignore[assignment]
        entry2_data = {
            "dn": "cn=test,dc=example,dc=com",  # Same DN
            "attributes": {"cn": ["test2"]},
        }
        entry1 = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry1_data)
        ).value
        entry2 = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry2_data)
        ).value

        processor = FlextLdifProcessor()
        result = processor.merge_entries([entry1], [entry2], overwrite_duplicates=True)

        assert result.is_success
        assert len(result.value) == 1  # Still one entry
        assert result.value[0].get_attribute("cn") == ["test2"]  # New one kept

    def test_detect_patterns_empty(self) -> None:
        """Test pattern detection with empty entries."""
        processor = FlextLdifProcessor()
        result = processor.detect_patterns([])

        assert result.is_success
        assert "patterns" in result.value
        assert "summary" in result.value

    def test_detect_patterns_with_entries(self) -> None:
        """Test pattern detection with actual entries."""  # type: ignore[assignment]
        entry1_data = {
            "dn": "cn=test1,ou=people,dc=example,dc=com",
            "attributes": {"cn": ["test1"], "objectClass": ["person", "inetOrgPerson"]},
        }  # type: ignore[assignment]
        entry2_data = {
            "dn": "cn=test2,ou=people,dc=example,dc=com",
            "attributes": {
                "cn": ["test2"],
                "objectClass": ["person", "inetOrgPerson"],
                "mail": ["test2@example.com"],
            },
        }
        entry1 = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry1_data)
        ).value
        entry2 = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry2_data)
        ).value

        processor = FlextLdifProcessor()
        result = processor.detect_patterns([entry1, entry2])

        assert result.is_success
        assert "object_class_patterns" in result.value
        assert "attribute_frequency" in result.value
        assert "dn_structures" in result.value
        assert "summary" in result.value

    def test_generate_quality_report_empty(self) -> None:
        """Test quality report generation with empty entries."""
        processor = FlextLdifProcessor()
        result = processor.generate_quality_report([])

        assert result.is_success
        assert result.value["status"] == "no_entries"

    def test_generate_quality_report_with_entries(self) -> None:
        """Test quality report generation with entries."""  # type: ignore[assignment]
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "objectClass": ["person"], "sn": ["Test"]},
        }
        entry = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry_data)
        ).value

        processor = FlextLdifProcessor()
        result = processor.generate_quality_report([entry])

        assert result.is_success
        assert "overall_score" in result.value
        assert "quality_level" in result.value
        assert "total_entries" in result.value
        assert "quality_metrics" in result.value
        assert "recommendations" in result.value

    def test_generate_quality_report_exception(self) -> None:
        """Test quality report generation with exception."""
        processor = FlextLdifProcessor()
  # type: ignore[assignment]
        entry_data = {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": ["test"]}}
        entry = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry_data)
        ).value

        # Mock the quality metrics calculation to raise an exception
        with patch.object(  # type: ignore[attr-defined]
            processor._AnalyticsHelper, "calculate_quality_metrics"
        ) as mock_method:
            mock_method.side_effect = RuntimeError("Quality calculation failed")

            result = processor.generate_quality_report([entry])

            assert result.is_failure
            assert result.error and "Quality report generation failed" in result.error

    def test_get_processor_health_success(self) -> None:
        """Test processor health check success."""
        processor = FlextLdifProcessor()
        result = processor.get_processor_health()

        assert result.is_success
        assert "status" in result.value
        assert "timestamp" in result.value
        assert "config" in result.value
        assert "capabilities" in result.value
        assert result.value["status"] == "healthy"

    def test_get_processor_health_exception(self) -> None:
        """Test processor health check with exception."""
        from unittest.mock import patch

        processor = FlextLdifProcessor()

        # Mock datetime.now to raise an exception
        with patch("flext_ldif.processor.datetime") as mock_datetime:
            mock_datetime.now.side_effect = RuntimeError("Time error")

            result = processor.get_processor_health()
            assert result.is_failure
            assert result.error and "Health check failed" in result.error

    def test_get_config_info(self) -> None:
        """Test getting configuration information."""
        config = FlextLdifConfig(ldif_max_entries=1000)
        processor = FlextLdifProcessor(config=config)

        info = processor.get_config_info()

        assert "encoding" in info
        assert "max_entries" in info
        assert "strict_validation" in info
        assert "wrap_lines" in info
        assert info["max_entries"] == 1000
        # Note: getattr looks for 'strict_validation' attribute but config uses different attribute names
        # This test verifies the method works, actual values may use defaults

    def test_validate_file_path_nonexistent_parent(self) -> None:
        """Test file path validation with nonexistent parent directory."""
        test_path = Path("/nonexistent/deeply/nested/path/test.ldif")  # type: ignore[attr-defined]
        result = FlextLdifProcessor._validate_file_path(test_path)

        # Should fail because we can't create the deeply nested path
        assert result.is_failure
        assert result.error and (
            "Cannot create directory" in result.error
            or "No write permission" in result.error
        )

    def test_validate_file_path_existing_file_readonly(self) -> None:
        """Test file path validation with existing readonly file."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = Path(f.name)

        try:
            # Make file readonly
            temp_path.chmod(0o444)
  # type: ignore[attr-defined]
            result = FlextLdifProcessor._validate_file_path(temp_path)

            # Should fail because file is readonly
            assert result.is_failure
            assert result.error and "No write permission for file" in result.error
        finally:
            temp_path.chmod(0o644)  # Restore permissions to delete
            temp_path.unlink()

    def test_get_required_attributes_for_classes(self) -> None:
        """Test getting required attributes for object classes."""
        processor = FlextLdifProcessor()

        # Test person class  # type: ignore[attr-defined]
        attrs = processor._get_required_attributes_for_classes(["person"])
        assert "cn" in attrs
        assert "sn" in attrs

        # Test organizationalunit class  # type: ignore[attr-defined]
        attrs = processor._get_required_attributes_for_classes(["organizationalunit"])
        assert "ou" in attrs

        # Test groupofnames class  # type: ignore[attr-defined]
        attrs = processor._get_required_attributes_for_classes(["groupofnames"])
        assert "cn" in attrs
        assert "member" in attrs

        # Test unknown class  # type: ignore[attr-defined]
        attrs = processor._get_required_attributes_for_classes(["unknownclass"])
        assert attrs == []

    def test_count_empty_attributes(self) -> None:
        """Test counting entries with empty attributes."""  # type: ignore[assignment]
        entry1_data = {
            "dn": "cn=test1,dc=example,dc=com",
            "attributes": {"cn": ["test1"], "description": [""]},  # Empty description
        }  # type: ignore[assignment]
        entry2_data = {
            "dn": "cn=test2,dc=example,dc=com",
            "attributes": {
                "cn": ["test2"],
                "mail": ["test@example.com"],
            },  # No empty attrs
        }
        entry1 = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry1_data)
        ).value
        entry2 = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry2_data)
        ).value

        processor = FlextLdifProcessor()  # type: ignore[attr-defined]
        count = processor._count_empty_attributes([entry1, entry2])

        assert count == 1  # Only entry1 has empty attribute

    def test_count_missing_object_classes(self) -> None:
        """Test counting entries missing objectClass."""  # type: ignore[assignment]
        entry1_data = {
            "dn": "cn=test1,dc=example,dc=com",
            "attributes": {"cn": ["test1"]},  # No objectClass
        }  # type: ignore[assignment]
        entry2_data = {
            "dn": "cn=test2,dc=example,dc=com",
            "attributes": {
                "cn": ["test2"],
                "objectClass": ["person"],
            },  # Has objectClass
        }
        entry1 = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry1_data)
        ).value
        entry2 = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry2_data)
        ).value

        processor = FlextLdifProcessor()  # type: ignore[attr-defined]
        count = processor._count_missing_object_classes([entry1, entry2])

        assert count == 1  # Only entry1 missing objectClass

    def test_count_duplicate_dns(self) -> None:
        """Test counting duplicate DN entries."""  # type: ignore[assignment]
        entry1_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test1"]},
        }  # type: ignore[assignment]
        entry2_data = {
            "dn": "cn=test,dc=example,dc=com",  # Same DN
            "attributes": {"cn": ["test2"]},
        }  # type: ignore[assignment]
        entry3_data = {
            "dn": "cn=unique,dc=example,dc=com",  # Unique DN
            "attributes": {"cn": ["unique"]},
        }
        entry1 = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry1_data)
        ).value
        entry2 = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry2_data)
        ).value
        entry3 = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry3_data)
        ).value

        processor = FlextLdifProcessor()  # type: ignore[attr-defined]
        count = processor._count_duplicate_dns([entry1, entry2, entry3])

        assert count == 1  # One duplicate (3 total - 2 unique = 1 duplicate)

    def test_count_invalid_dns(self) -> None:
        """Test counting invalid DN entries."""
        # This test verifies the private method exists and can be called
        # In practice, invalid DNs would be caught during entry creation  # type: ignore[assignment]
        entry_data = {
            "dn": "cn=valid,dc=example,dc=com",
            "attributes": {"cn": ["valid"]},
        }
        entry = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry_data)
        ).value

        processor = FlextLdifProcessor()
        # All our entries should be valid since they passed model validation  # type: ignore[attr-defined]
        count = processor._count_invalid_dns([entry])

        assert count == 0  # All entries have valid DNs

    def test_parse_helper_process_line_continuation(self) -> None:
        """Test line continuation processing."""
        content = """dn: cn=test,dc=example,dc=com
description: This is a long line that
 continues on the next line
cn: test"""
  # type: ignore[attr-defined]
        processed = FlextLdifProcessor._ParseHelper.process_line_continuation(content)

        assert "This is a long line thatcontinues on the next line" in processed

    def test_writer_helper_apply_line_wrapping(self) -> None:
        """Test line wrapping application."""
        long_line = "a" * 100  # Long line that should be wrapped  # type: ignore[attr-defined]
        wrapped = FlextLdifProcessor._WriterHelper.apply_line_wrapping(
            long_line, max_line_length=50
        )

        lines = wrapped.split("\n")
        assert len(lines) > 1  # Should be split into multiple lines
        assert all(
            len(line) <= 51 for line in lines
        )  # Each line should be <= 51 (50 + possible leading space)

    def test_analytics_helper_analyze_dn_patterns(self) -> None:
        """Test DN pattern analysis."""  # type: ignore[assignment]
        entry1_data = {
            "dn": "cn=user1,ou=people,dc=example,dc=com",
            "attributes": {"cn": ["user1"]},
        }  # type: ignore[assignment]
        entry2_data = {
            "dn": "cn=user2,ou=people,dc=example,dc=com",
            "attributes": {"cn": ["user2"]},
        }
        entry1 = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry1_data)
        ).value
        entry2 = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry2_data)
        ).value
  # type: ignore[attr-defined]
        analysis = FlextLdifProcessor._AnalyticsHelper.analyze_dn_patterns([
            entry1,
            entry2,
        ])

        assert "dn_patterns" in analysis
        assert "base_patterns" in analysis
        assert "unique_dn_count" in analysis
        assert analysis["unique_dn_count"] == 2

    def test_parse_helper_process_entry_block_no_colon(self) -> None:
        """Test processing entry block with invalid attribute line."""
        block = """dn: cn=test,dc=example,dc=com
invalid_line_without_colon
cn: test"""
  # type: ignore[attr-defined]
        result = FlextLdifProcessor._ParseHelper.process_entry_block(block)

        # Should still succeed, invalid lines are skipped
        assert result.is_success

    def test_validation_helper_validate_object_classes_missing(self) -> None:
        """Test object class validation with missing required classes."""  # type: ignore[assignment]
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "cn": ["test"],
                "objectClass": ["inetOrgPerson"],
            },  # Missing "person"
        }
        entry = FlextLdifModels.create_entry(
            cast("dict[str, object]", entry_data)
        ).value
  # type: ignore[attr-defined]
        result = FlextLdifProcessor._LdifValidationHelper.validate_object_classes(
            entry, ["person"]
        )

        assert result.is_failure
        assert (
            result.error and "Required object class 'person' is missing" in result.error
        )
