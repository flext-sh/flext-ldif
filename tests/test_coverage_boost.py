"""Additional tests to boost coverage to 90%+.

This module contains targeted tests for uncovered code paths
identified in the coverage analysis to reach the 90%+ target.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from flext_ldif import FlextLdifAPI, FlextLdifConfig
from flext_ldif.cli import cli
from flext_ldif.models import (
    FlextLdifAttributes,
    FlextLdifDistinguishedName,
    FlextLdifEntry,
)


class TestAPICoverageBoost:
    """Tests to boost API coverage from 72% to 90%+."""

    def test_api_parse_with_none_result_data(self) -> None:
        """Test API parse when result data is None."""
        api = FlextLdifAPI()

        # Mock the TLdif.parse to return success but with None data
        with patch("flext_ldif.api.TLdif.parse") as mock_parse:
            mock_result = Mock()
            mock_result.is_success = True
            mock_result.data = None
            mock_parse.return_value = mock_result

            result = api.parse("test content")
            assert not result.is_success
            assert "No entries parsed" in result.error

    def test_api_parse_file_with_none_result_data(self) -> None:
        """Test API parse_file when result data is None."""
        api = FlextLdifAPI()

        # Create temp file
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write("dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test")
            temp_path = f.name

        try:
            # Mock the TLdif.read_file to return success but with None data
            with patch("flext_ldif.api.TLdif.read_file") as mock_read:
                mock_result = Mock()
                mock_result.is_success = True
                mock_result.data = None
                mock_read.return_value = mock_result

                result = api.parse_file(temp_path)
                assert not result.is_success
                assert "No entries parsed from file" in result.error
        finally:
            Path(temp_path).unlink()

    def test_api_validate_empty_attributes_not_allowed(self) -> None:
        """Test validate method when empty attributes are not allowed."""
        config = FlextLdifConfig()
        config.allow_empty_attributes = False
        api = FlextLdifAPI(config)

        # Create entry with empty attribute
        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifAttributes(
                attributes={"cn": [""], "objectClass": ["person"]},
            ),
        )

        result = api.validate([entry])
        assert not result.is_success
        assert "Empty attribute value not allowed" in result.error

    def test_api_validate_entry_size_exceeds_limit(self) -> None:
        """Test validate method when entry size exceeds limit."""
        config = FlextLdifConfig()
        config.max_entry_size = 50  # Very small limit
        api = FlextLdifAPI(config)

        # Create entry with large attribute values
        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifAttributes(
                attributes={
                    "cn": ["test"],
                    "objectClass": ["person"],
                    "description": [
                        "This is a very long description that exceeds the size limit set in the configuration for testing purposes",
                    ],
                },
            ),
        )

        result = api.validate([entry])
        assert not result.is_success
        assert "Entry size" in result.error
        assert "exceeds limit" in result.error

    def test_api_write_file_create_directory_permission_error(self) -> None:
        """Test write method when directory creation fails due to permissions."""
        config = FlextLdifConfig()
        config.create_output_dir = True
        config.output_directory = Path("/")  # Root directory - permission denied
        api = FlextLdifAPI(config)

        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifAttributes(
                attributes={"cn": ["test"], "objectClass": ["person"]},
            ),
        )

        # Should attempt to create directory but fail gracefully
        result = api.write([entry], "test.ldif")
        # Write should still proceed and fail naturally
        assert not result.is_success

    def test_api_entries_to_ldif_write_failure(self) -> None:
        """Test entries_to_ldif when write operation fails."""
        api = FlextLdifAPI()

        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifAttributes(
                attributes={"cn": ["test"], "objectClass": ["person"]},
            ),
        )

        # Mock TLdif.write to fail
        with patch("flext_ldif.api.TLdif.write") as mock_write:
            mock_result = Mock()
            mock_result.is_success = False
            mock_result.error = "Write error"
            mock_write.return_value = mock_result

            with pytest.raises(ValueError, match="Failed to convert entries to LDIF"):
                api.entries_to_ldif([entry])

    def test_api_get_entry_statistics_error_handling(self) -> None:
        """Test get_entry_statistics error handling."""
        api = FlextLdifAPI()

        # Create invalid entry that will cause errors
        with patch.object(api, "_observability_monitor") as mock_monitor:
            mock_monitor.flext_record_metric.side_effect = Exception("Metrics error")

            # Should still return error statistics
            result = api.get_entry_statistics([])
            assert "error" in result
            assert "Statistics calculation failed" in result["error"]

    def test_api_observability_initialization_failure(self) -> None:
        """Test API initialization when observability fails."""
        with patch("flext_ldif.api.FlextObservabilityMonitor") as mock_monitor_class:
            mock_monitor = Mock()
            mock_result = Mock()
            mock_result.is_success = False
            mock_result.error = "Initialization failed"
            mock_monitor.flext_initialize_observability.return_value = mock_result
            mock_monitor_class.return_value = mock_monitor

            api = FlextLdifAPI()
            # Should create API even if observability fails
            assert api is not None

    def test_api_get_observability_metrics_failures(self) -> None:
        """Test get_observability_metrics failure scenarios."""
        api = FlextLdifAPI()

        # Test when monitor is not available
        api._observability_monitor = None
        result = api.get_observability_metrics()
        assert not result.is_success
        assert "not available" in result.error

        # Test when metrics summary fails
        api._observability_monitor = Mock()
        mock_metrics_result = Mock()
        mock_metrics_result.is_failure = True
        mock_metrics_result.error = "Metrics error"
        api._observability_monitor.flext_get_metrics_summary.return_value = (
            mock_metrics_result
        )

        result = api.get_observability_metrics()
        assert not result.is_success
        assert "Failed to get metrics" in result.error

    def test_api_reset_observability_metrics_failures(self) -> None:
        """Test reset_observability_metrics failure scenarios."""
        api = FlextLdifAPI()

        # Test when monitor is not available
        api._observability_monitor = None
        result = api.reset_observability_metrics()
        assert not result.is_success
        assert "not available" in result.error


class TestCLICoverageBoost:
    """Tests to boost CLI coverage from 75% to 90%+."""

    def test_cli_parse_validation_errors(self) -> None:
        """Test parse command with validation errors."""
        runner = CliRunner()

        # Create invalid LDIF file (missing objectClass)
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write("dn: cn=test,dc=example,dc=com\ncn: test\n")
            temp_path = f.name

        try:
            result = runner.invoke(cli, ["parse", temp_path, "--validate"])
            # Should still show successful parse but with validation warnings
            assert result.exit_code == 0
        finally:
            Path(temp_path).unlink()

    def test_cli_parse_max_entries_limit_exceeded(self) -> None:
        """Test parse command when max entries limit is exceeded."""
        runner = CliRunner()

        # Create LDIF with multiple entries
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write("""dn: cn=test1,dc=example,dc=com
objectClass: person
cn: test1

dn: cn=test2,dc=example,dc=com
objectClass: person
cn: test2
""")
            temp_path = f.name

        try:
            # Set max entries to 1
            result = runner.invoke(cli, ["parse", temp_path, "--max-entries", "1"])
            assert result.exit_code == 1
            assert "Too many entries" in result.output
        finally:
            Path(temp_path).unlink()

    def test_cli_validate_strict_mode_failures(self) -> None:
        """Test validate command in strict mode with failures."""
        runner = CliRunner()

        # Create invalid LDIF file
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write("dn: cn=test,dc=example,dc=com\ncn: test\n")  # Missing objectClass
            temp_path = f.name

        try:
            result = runner.invoke(cli, ["validate", temp_path, "--strict"])
            assert result.exit_code == 1
            assert (
                "Validation failed" in result.output
                or "Failed to parse file for validation" in result.output
            )
        finally:
            Path(temp_path).unlink()

    def test_cli_transform_filter_error_handling(self) -> None:
        """Test transform command filter error handling."""
        runner = CliRunner()

        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write("dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test")
            input_path = f.name

        with tempfile.NamedTemporaryFile(suffix=".ldif", delete=False) as f:
            output_path = f.name

        try:
            # Use invalid filter type (Click validates before our code runs)
            result = runner.invoke(
                cli,
                [
                    "transform",
                    input_path,
                    output_path,
                    "--filter-type",
                    "invalid_filter",
                ],
            )
            assert (
                result.exit_code == 2
            )  # Click validation error (not graceful handling)
            assert (
                "Invalid value" in result.output
                or "invalid choice" in result.output.lower()
            )
        finally:
            Path(input_path).unlink()
            Path(output_path).unlink(missing_ok=True)

    def test_cli_convert_format_error_handling(self) -> None:
        """Test convert command format error handling."""
        runner = CliRunner()

        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write("dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test")
            input_path = f.name

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            output_path = f.name

        try:
            # Use unsupported input format (Click validates choices before our code runs)
            result = runner.invoke(
                cli,
                [
                    "convert",
                    "--input-format",
                    "xml",  # Invalid choice - Click will catch this
                    "--output-format",
                    "json",
                    input_path,
                    output_path,
                ],
            )
            assert result.exit_code == 2  # Click validation error
            assert (
                "Invalid value" in result.output
                or "invalid choice" in result.output.lower()
                or "Choose from" in result.output
            )
        finally:
            Path(input_path).unlink()
            Path(output_path).unlink(missing_ok=True)

    def test_cli_main_function_keyboard_interrupt(self) -> None:
        """Test main function keyboard interrupt handling."""
        from flext_ldif.cli import main

        with patch("flext_ldif.cli.setup_cli") as mock_setup:
            mock_setup.side_effect = KeyboardInterrupt()

            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

    def test_cli_main_function_setup_failure(self) -> None:
        """Test main function when CLI setup fails."""
        from flext_ldif.cli import main

        with patch("flext_ldif.cli.setup_cli") as mock_setup:
            mock_result = Mock()
            mock_result.is_success = False
            mock_result.error = "Setup failed"
            mock_setup.return_value = mock_result

            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1


class TestModelsCoverageBoost:
    """Tests to boost models coverage from 84% to 90%+."""

    def test_ldif_entry_validation_edge_cases(self) -> None:
        """Test FlextLdifEntry validation edge cases."""
        # Test empty DN
        with pytest.raises(ValueError, match="DN must be a non-empty string"):
            FlextLdifDistinguishedName(value="")

    def test_ldif_attributes_edge_cases(self) -> None:
        """Test FlextLdifAttributes edge cases."""
        attrs = FlextLdifAttributes(attributes={})

        # Test get_single_value with empty list
        attrs.attributes["test"] = []
        result = attrs.get_single_value("test")
        assert result is None

        # Test get_values with non-existent attribute
        assert attrs.get_values("nonexistent") == []

    def test_ldif_entry_specification_methods_edge_cases(self) -> None:
        """Test FlextLdifEntry specification methods edge cases."""
        # Test entry without objectClass
        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifAttributes(attributes={"cn": ["test"]}),
        )

        # Should return False for all type checks without objectClass
        assert not entry.is_person_entry()
        assert not entry.is_group_entry()
        assert not entry.is_organizational_unit()
        assert not entry.is_change_record()

    def test_ldif_entry_from_ldif_dict_error_handling(self) -> None:
        """Test FlextLdifEntry.from_ldif_dict error handling."""
        # Test with truly invalid DN that causes real exception
        with pytest.raises(ValueError, match="DN must be a non-empty string"):
            FlextLdifEntry.from_ldif_dict("", {"cn": ["test"]})

    def test_ldif_distinguished_name_edge_cases(self) -> None:
        """Test FlextLdifDistinguishedName edge cases."""
        # Test various DN formats
        dn1 = FlextLdifDistinguishedName(value="cn=test,dc=example,dc=com")
        dn2 = FlextLdifDistinguishedName(value="cn=test,dc=example,dc=com")
        dn3 = FlextLdifDistinguishedName(value="cn=other,dc=example,dc=com")

        # Test equality
        assert dn1 == dn2
        assert dn1 != dn3

        # Test hash
        assert hash(dn1) == hash(dn2)
        assert hash(dn1) != hash(dn3)

    def test_ldif_entry_model_dump_edge_cases(self) -> None:
        """Test FlextLdifEntry model_dump edge cases."""
        entry = FlextLdifEntry(
            dn=FlextLdifDistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifAttributes(
                attributes={"cn": ["test"], "objectClass": ["person"]},
            ),
        )

        # Test model_dump with different options
        dump_data = entry.model_dump(exclude_none=True)
        assert "dn" in dump_data
        assert "attributes" in dump_data

        # Test model_dump_json
        json_data = entry.model_dump_json()
        parsed_data = json.loads(json_data)
        assert "dn" in parsed_data
