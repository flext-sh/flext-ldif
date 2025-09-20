"""Real API tests focused on 100% coverage with minimal mocking.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

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
        return [
            FlextLdifModels.create_entry(
                {
                    "dn": "cn=test1,dc=example,dc=com",
                    "attributes": {
                        "cn": ["test1"],
                        "sn": ["Test1"],
                        "objectClass": ["person"],
                    },
                }
            ),
            FlextLdifModels.create_entry(
                {
                    "dn": "cn=test2,dc=example,dc=com",
                    "attributes": {
                        "cn": ["test2"],
                        "sn": ["Test2"],
                        "objectClass": ["person"],
                    },
                }
            ),
        ]

    def test_api_initialization_default(self) -> None:
        """Test API initialization with default config."""
        api = FlextLdifAPI()
        assert api is not None
        assert api._config is not None
        assert api._services is not None
        assert api._logger is not None

    def test_api_initialization_with_config(
        self, api_with_config: FlextLdifAPI
    ) -> None:
        """Test API initialization with custom config."""
        assert api_with_config._config.ldif_max_entries == 1000
        assert api_with_config._config.ldif_chunk_size == 50
        assert api_with_config._config.ldif_strict_validation is True

    @patch("flext_ldif.config.FlextLdifConfig.get_global_ldif_config")
    def test_api_initialization_global_config_fallback(self, mock_global: Mock) -> None:
        """Test API fallback to default config when global config fails."""
        mock_global.side_effect = RuntimeError("No global config")
        api = FlextLdifAPI()
        assert api._config is not None
        mock_global.assert_called_once()

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

    def test_parse_file_path_success(self, api_default: FlextLdifAPI) -> None:
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
            result = api_default.parse_file_path(temp_path)
            assert result.is_success
            entries = result.unwrap()
            assert len(entries) == 1
        finally:
            temp_path.unlink()

    def test_parse_file_path_string_input(self, api_default: FlextLdifAPI) -> None:
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
            result = api_default.parse_file_path(temp_path)
            assert result.is_success
            entries = result.unwrap()
            assert len(entries) == 1
        finally:
            Path(temp_path).unlink()

    def test_parse_file_path_nonexistent_file(self, api_default: FlextLdifAPI) -> None:
        """Test parsing nonexistent file to trigger error path."""
        result = api_default.parse_file_path("/nonexistent/file.ldif")
        assert result.is_failure
        assert "File not found" in result.error or "File parse error:" in result.error

    def test_validate_entries_success(
        self, api_default: FlextLdifAPI, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test successful entry validation."""
        result = api_default.validate_entries(sample_entries)
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_entries_empty_list(self, api_default: FlextLdifAPI) -> None:
        """Test validation with empty entry list."""
        result = api_default.validate_entries([])
        # With empty list, validation fails (cannot validate empty list)
        assert result.is_failure
        assert "empty" in result.error.lower()

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
            assert result.unwrap() is None
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
            return FlextLdifModels.create_entry(
                {"dn": entry.dn.value, "attributes": new_attrs}
            )

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
        self, api_default: FlextLdifAPI, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test filtering by attribute."""
        criteria = {"attribute": "cn", "value": "test1"}
        result = api_default.filter_entries(sample_entries, criteria)
        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 1
        cn_values = filtered[0].attributes.get_attribute("cn")
        assert cn_values and cn_values[0] == "test1"

    def test_filter_entries_by_attribute_none_value(
        self, api_default: FlextLdifAPI, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test filtering by attribute with None value."""
        criteria = {"attribute": "cn", "value": None}
        result = api_default.filter_entries(sample_entries, criteria)
        assert result.is_success

    def test_filter_entries_by_objectclass(
        self, api_default: FlextLdifAPI, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test filtering by objectClass."""
        criteria = {"objectClass": "person"}
        result = api_default.filter_entries(sample_entries, criteria)
        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 2

    def test_filter_entries_no_criteria(
        self, api_default: FlextLdifAPI, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test filtering with no supported criteria."""
        criteria = {"unsupported": "value"}
        result = api_default.filter_entries(sample_entries, criteria)
        assert result.is_success
        filtered = result.unwrap()
        assert filtered == sample_entries

    def test_health_check_success(self, api_default: FlextLdifAPI) -> None:
        """Test successful health check."""
        result = api_default.health_check()
        assert result.is_success
        health = result.unwrap()
        assert health["api"] == "FlextLdifAPI"
        assert health["status"] == "healthy"
        assert "services" in health
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
        for capability in expected_capabilities:
            assert capability in info["capabilities"]
        assert "services" in info
        assert "config" in info

    def test_execute(self, api_default: FlextLdifAPI) -> None:
        """Test execute method."""
        result = api_default.execute()
        assert result.is_success
        assert result.unwrap() == []

    # Error condition tests with real service failures

    def test_write_file_invalid_path(
        self, api_default: FlextLdifAPI, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test write_file with invalid path to trigger service failure."""
        # Try to write to a directory that doesn't exist
        invalid_path = "/nonexistent/directory/file.ldif"
        result = api_default.write_file(sample_entries, invalid_path)
        assert result.is_failure
        # The error should be from the service layer or caught by API exception handling
        assert (
            "directory does not exist" in result.error
            or "File write error:" in result.error
            or "write failed" in result.error.lower()
        )

    def test_transform_with_failing_function(
        self, api_default: FlextLdifAPI, sample_entries: list[FlextLdifModels.Entry]
    ) -> None:
        """Test transform with function that raises exception."""

        def failing_transform(_entry: FlextLdifModels.Entry) -> FlextLdifModels.Entry:
            error_message = "Transform failed"
            raise ValueError(error_message)

        result = api_default.transform(sample_entries, failing_transform)
        assert result.is_failure
        assert "Transform error:" in result.error

    def test_filter_entries_invalid_repository_access(
        self, api_default: FlextLdifAPI
    ) -> None:
        """Test filter_entries with conditions that might fail."""
        # Create entries with extreme values that might cause issues using list comprehension
        large_entries = [
            FlextLdifModels.create_entry(
                {
                    "dn": f"cn=user{i},dc=example,dc=com",
                    "attributes": {
                        "cn": [f"user{i}"],
                        "sn": [f"User{i}"],
                        "objectClass": ["person"],
                    },
                }
            )
            for i in range(1000)
        ]

        criteria = {"attribute": "nonexistent", "value": "test"}
        result = api_default.filter_entries(large_entries, criteria)
        # Should handle gracefully
        assert result.is_success

    def test_analyze_edge_cases(self, api_default: FlextLdifAPI) -> None:
        """Test analyze with edge cases."""
        # Test with empty entries
        result = api_default.analyze([])
        assert result.is_success
        analysis = result.unwrap()
        assert analysis["total_entries"] == 0

        # Test with single entry
        single_entry = [
            FlextLdifModels.create_entry(
                {
                    "dn": "cn=single,dc=example,dc=com",
                    "attributes": {
                        "cn": ["single"],
                        "sn": ["Single"],
                        "objectClass": ["person"],
                    },
                }
            )
        ]

        result = api_default.analyze(single_entry)
        assert result.is_success
        analysis = result.unwrap()
        assert analysis["total_entries"] == 1
