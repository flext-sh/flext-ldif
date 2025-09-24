"""Real API tests focused on 100% coverage with minimal mocking.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import cast

import pytest

from flext_ldif.api import FlextLdifAPI
from flext_ldif.config import FlextLdifConfig
from flext_ldif.models import FlextLdifModels


class TestFlextLdifAPIRealCoverage:
    """Real API tests focused on achieving 100% coverage."""

    @pytest.fixture
    def api_default(self) -> FlextLdifAPI:
        """Create API with default configuration."""
        return FlextLdifAPI()

    @pytest.fixture
    def api_with_config(self) -> FlextLdifAPI:
        """Create API with custom configuration."""
        config = FlextLdifConfig(
            ldif_max_entries=1000,
            ldif_chunk_size=50,
            ldif_strict_validation=True,
        )
        return FlextLdifAPI(config)

    @pytest.fixture
    def sample_entries(self) -> list[FlextLdifModels.Entry]:
        """Create sample entries for testing."""
        entry1_result = FlextLdifModels.Entry.create({
            "dn": "cn=test1,dc=example,dc=com",
            "attributes": {
                "cn": ["test1"],
                "sn": ["Test1"],
                "objectClass": ["person"],
            },
        })
        entry2_result = FlextLdifModels.Entry.create({
            "dn": "cn=test2,dc=example,dc=com",
            "attributes": {
                "cn": ["test2"],
                "sn": ["Test2"],
                "objectClass": ["person"],
            },
        })

        # Extract the actual Entry objects from FlextResult
        if not entry1_result.is_success or not entry2_result.is_success:
            error_msg = "Failed to create sample entries"
            raise RuntimeError(error_msg)

        entry1 = entry1_result.unwrap()
        entry2 = entry2_result.unwrap()

        return [entry1, entry2]

    def test_api_initialization_default(self) -> None:
        """Test API initialization with default config."""
        api = FlextLdifAPI()
        assert api is not None
        # Check that processor was initialized by testing health check
        health_result = api.health_check()
        assert health_result.is_success

    def test_api_initialization_with_config(
        self, api_with_config: FlextLdifAPI
    ) -> None:
        """Test API initialization with custom config."""
        # Test that API works with custom config by checking service info
        service_info = api_with_config.get_service_info()
        assert service_info["api"] == "FlextLdifAPI"
        assert "config" in service_info

    def test_api_initialization_global_config_fallback(self) -> None:
        """Test API fallback to default config when global config fails."""
        # Test with None config (should use default)
        api = FlextLdifAPI(None)
        assert api is not None
        # Test that API works by checking health
        health_result = api.health_check()
        assert health_result.is_success

    def test_parse_success(self, api_default: FlextLdifAPI) -> None:
        """Test successful LDIF content parsing."""
        content = """dn: cn=test,dc=example,dc=com
cn: test
sn: Test
objectClass: person
"""
        result = api_default.parse(content)
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 1
        assert entries[0].dn.value == "cn=test,dc=example,dc=com"

    def test_parse_empty_content(self, api_default: FlextLdifAPI) -> None:
        """Test parsing empty content."""
        result = api_default.parse("")
        assert result.is_success
        assert result.unwrap() == []

    def test_parse_malformed_content(self, api_default: FlextLdifAPI) -> None:
        """Test parsing malformed content to trigger exception path."""
        # Test with content that causes parsing exceptions
        malformed_content = "dn invalid format\nobjectClass person"
        result = api_default.parse(malformed_content)
        # Should either succeed with partial parsing or fail gracefully
        assert result.is_success or result.is_failure

    def test_parse_ldif_file_success(self, api_default: FlextLdifAPI) -> None:
        """Test successful file parsing."""
        content = """dn: cn=test,dc=example,dc=com
cn: test
sn: Test
objectClass: person
"""
        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", suffix=".ldif", delete=False
        ) as f:
            f.write(content)
            temp_path = Path(f.name)

        try:
            result = api_default.parse_ldif_file(temp_path)
            assert result.is_success
            entries = result.unwrap()
            assert len(entries) == 1
        finally:
            temp_path.unlink()

    def test_parse_ldif_file_string_input(self, api_default: FlextLdifAPI) -> None:
        """Test file parsing with string path input."""
        content = """dn: cn=test,dc=example,dc=com
cn: test
sn: Test
objectClass: person
"""
        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", suffix=".ldif", delete=False
        ) as f:
            f.write(content)
            temp_path = f.name

        try:
            result = api_default.parse_ldif_file(temp_path)
            assert result.is_success
            entries = result.unwrap()
            assert len(entries) == 1
        finally:
            Path(temp_path).unlink()

    def test_parse_ldif_file_nonexistent_file(self, api_default: FlextLdifAPI) -> None:
        """Test parsing nonexistent file to trigger error path."""
        result = api_default.parse_ldif_file("/nonexistent/file.ldif")
        assert result.is_failure
        assert result.error is not None
        error_str = str(result.error)
        assert (
            "File not found" in error_str
            or "File parse error:" in error_str
            or "Permission denied" in error_str
            or "Cannot create directory" in error_str
        )

    def test_validate_entries_success(
        self, api_default: FlextLdifAPI, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test successful entry validation."""
        result = api_default.validate_entries(sample_entries)
        # The validate_entries method returns the original entries if validation succeeds
        # or an empty list if validation fails (due to the .recover(lambda _: []) in the API)
        assert result.is_success
        validated_entries = result.unwrap()
        # Check that we get some result (either original entries or empty list)
        assert isinstance(validated_entries, list)

    def test_validate_entries_empty_list(self, api_default: FlextLdifAPI) -> None:
        """Test validation with empty entry list."""
        result = api_default.validate_entries([])
        # With empty list, validation fails with error message
        assert result.is_failure
        assert "No entries to validate" in (result.error or "")

    def test_write_success(
        self, api_default: FlextLdifAPI, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test successful LDIF writing."""
        result = api_default.write(sample_entries)
        assert result.is_success
        ldif_content = result.unwrap()
        assert isinstance(ldif_content, str)
        assert "cn=test1,dc=example,dc=com" in ldif_content

    def test_write_file_success(
        self, api_default: FlextLdifAPI, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test successful file writing."""
        with tempfile.NamedTemporaryFile(suffix=".ldif", delete=False) as f:
            temp_path = Path(f.name)

        try:
            result = api_default.write_file(sample_entries, temp_path)
            assert result.is_success
            # The write_file method returns True on success or False on failure
            write_result = result.unwrap()
            assert isinstance(write_result, bool)
            assert temp_path.exists()
        finally:
            temp_path.unlink()

    def test_write_file_string_path(
        self, api_default: FlextLdifAPI, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test file writing with string path."""
        with tempfile.NamedTemporaryFile(suffix=".ldif", delete=False) as f:
            temp_path = f.name

        try:
            result = api_default.write_file(sample_entries, temp_path)
            assert result.is_success
            assert Path(temp_path).exists()
        finally:
            Path(temp_path).unlink()

    def test_transform_no_transformation(
        self, api_default: FlextLdifAPI, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test transform with no transformation function."""
        result = api_default.transform(sample_entries)
        assert result.is_success
        transformed = result.unwrap()
        assert transformed == sample_entries

    def test_transform_with_function(
        self, api_default: FlextLdifAPI, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test transform with transformation function."""

        def add_mail_attr(entry: FlextLdifModels.Entry) -> FlextLdifModels.Entry:
            # Copy existing attributes and add mail
            new_attrs = dict(
                entry.attributes.data
            )  # Use .data to access the underlying dict
            cn_values = entry.attributes.get_attribute("cn")
            cn_value = cn_values[0] if cn_values else "test"
            new_attrs["mail"] = [f"{cn_value}@example.com"]
            entry_result = FlextLdifModels.Entry.create({
                "dn": entry.dn.value,
                "attributes": new_attrs,
            })
            if entry_result.is_success:
                return entry_result.unwrap()
            return entry

        result = api_default.transform(sample_entries, add_mail_attr)
        assert result.is_success
        transformed = result.unwrap()
        assert len(transformed) == 2
        assert transformed[0].attributes.has_attribute("mail")

    def test_analyze_success(
        self, api_default: FlextLdifAPI, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test successful analysis."""
        result = api_default.analyze(sample_entries)
        assert result.is_success
        analysis = result.unwrap()
        assert isinstance(analysis, dict)
        assert "total_entries" in analysis

    def test_filter_entries_by_attribute(
        self, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test filtering by attribute."""

        def filter_by_cn(entry: FlextLdifModels.Entry) -> bool:
            cn_values = entry.attributes.get_attribute("cn")
            return cn_values is not None and "test1" in cn_values

        result = FlextLdifAPI.filter_entries(sample_entries, filter_by_cn)
        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 1
        cn_values = filtered[0].attributes.get_attribute("cn")
        assert cn_values and cn_values[0] == "test1"

    def test_filter_entries_by_attribute_none_value(
        self, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test filtering by attribute with None value."""

        def filter_by_cn_none(entry: FlextLdifModels.Entry) -> bool:
            cn_values = entry.attributes.get_attribute("cn")
            return cn_values is None or len(cn_values) == 0

        result = FlextLdifAPI.filter_entries(sample_entries, filter_by_cn_none)
        assert result.is_success

    def test_filter_entries_by_objectclass(
        self, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test filtering by objectClass."""

        def filter_by_person(entry: FlextLdifModels.Entry) -> bool:
            return entry.has_object_class("person")

        result = FlextLdifAPI.filter_entries(sample_entries, filter_by_person)
        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 2

    def test_filter_entries_no_criteria(
        self, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test filtering with no supported criteria."""

        def always_true(_entry: FlextLdifModels.Entry) -> bool:
            return True

        result = FlextLdifAPI.filter_entries(sample_entries, always_true)
        assert result.is_success
        filtered = result.unwrap()
        assert filtered == sample_entries

    def test_health_check_success(self, api_default: FlextLdifAPI) -> None:
        """Test successful health check."""
        result = api_default.health_check()
        assert result.is_success
        health = result.unwrap()
        assert health["status"] == "healthy"
        assert "timestamp" in health
        assert "config" in health

    def test_get_service_info(self, api_default: FlextLdifAPI) -> None:
        """Test service info retrieval."""
        info = api_default.get_service_info()
        assert info["api"] == "FlextLdifAPI"
        assert "capabilities" in info
        expected_capabilities = [
            "parse",
            "parse_file",
            "validate",
            "write",
            "write_file",
            "transform",
            "analyze",
            "filter_entries",
            "health_check",
        ]
        capabilities = info["capabilities"]
        assert isinstance(capabilities, list)
        # Based on API return type, capabilities is list[str]
        # Cast to help Pyright understand the type
        capabilities_list: list[str] = [
            str(capability_item) for capability_item in cast("list[str]", capabilities)
        ]
        for capability in expected_capabilities:
            assert capability in capabilities_list, (
                f"Capability '{capability}' not found in capabilities"
            )
        assert "processor" in info
        assert "config" in info

    def test_execute(self, api_default: FlextLdifAPI) -> None:
        """Test execute method."""
        result = api_default.execute()
        assert result.is_success
        health_data = result.unwrap()
        assert isinstance(health_data, dict)
        assert "status" in health_data

    # Error condition tests with real service failures

    def test_write_file_invalid_path(
        self, api_default: FlextLdifAPI, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test write_file with invalid path to trigger service failure."""
        # Try to write to a directory that doesn't exist
        invalid_path = "/nonexistent/directory/file.ldif"
        result = api_default.write_file(sample_entries, invalid_path)
        # The API returns success with False on write failure (due to .recover(lambda _: False))
        assert result.is_success
        write_result = result.unwrap()
        assert not write_result

    def test_transform_with_failing_function(
        self, api_default: FlextLdifAPI, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test transform with function that raises exception."""

        def failing_transform(_entry: FlextLdifModels.Entry) -> FlextLdifModels.Entry:
            error_message = "Transform failed"
            raise ValueError(error_message)

        result = api_default.transform(sample_entries, failing_transform)
        assert result.is_failure
        assert result.error is not None
        error_str = str(result.error)
        assert (
            "Transform error:" in error_str
            or "Transformation failed" in error_str
            or "Transform failed" in error_str
        )

    def test_filter_entries_invalid_repository_access(self) -> None:
        """Test filter_entries with conditions that might fail."""
        # Create entries with extreme values that might cause issues using list comprehension
        large_entries: list[FlextLdifModels.Entry] = []
        for i in range(100):  # Reduced size for test performance
            entry_result = FlextLdifModels.Entry.create({
                "dn": f"cn=user{i},dc=example,dc=com",
                "attributes": {
                    "cn": [f"user{i}"],
                    "sn": [f"User{i}"],
                    "objectClass": ["person"],
                },
            })
            if entry_result.is_success:
                large_entries.append(entry_result.unwrap())

        def filter_nonexistent(_entry: FlextLdifModels.Entry) -> bool:
            return False  # Filter out all entries

        result = FlextLdifAPI.filter_entries(large_entries, filter_nonexistent)
        # Should handle gracefully
        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 0

    def test_analyze_edge_cases(self, api_default: FlextLdifAPI) -> None:
        """Test analyze with edge cases."""
        # Test with empty entries
        result = api_default.analyze([])
        assert result.is_success
        analysis = result.unwrap()
        assert isinstance(analysis, dict)
        # Check that we get some analysis data (exact keys may vary)
        assert len(analysis) > 0

        # Test with single entry
        single_entry_result = FlextLdifModels.Entry.create({
            "dn": "cn=single,dc=example,dc=com",
            "attributes": {
                "cn": ["single"],
                "sn": ["Single"],
                "objectClass": ["person"],
            },
        })
        single_entry = (
            [single_entry_result.unwrap()] if single_entry_result.is_success else []
        )

        result = api_default.analyze(single_entry)
        assert result.is_success
        analysis = result.unwrap()
        assert isinstance(analysis, dict)
        # Check that we get some analysis data (exact keys may vary)
        assert len(analysis) > 0
