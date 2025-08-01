"""Tests for CLI functionality.

Comprehensive test suite for the flext-ldif CLI implementation
using flext-cli foundation patterns.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from click.testing import CliRunner

from flext_ldif.cli import cli


class TestFlextLdifCLI:
    """Test suite for FLEXT LDIF CLI."""

    def test_cli_help(self) -> None:
        """Test CLI help command."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])

        assert result.exit_code == 0
        assert "FLEXT LDIF" in result.output
        assert "Enterprise LDIF Processing CLI" in result.output

    def test_cli_parse_command_help(self) -> None:
        """Test parse command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["parse", "--help"])

        assert result.exit_code == 0
        assert "Parse LDIF file" in result.output

    def test_cli_validate_command_help(self) -> None:
        """Test validate command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", "--help"])

        assert result.exit_code == 0
        assert "Validate LDIF file" in result.output

    def test_cli_transform_command_help(self) -> None:
        """Test transform command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["transform", "--help"])

        assert result.exit_code == 0
        assert "Transform LDIF file" in result.output

    def test_cli_stats_command_help(self) -> None:
        """Test stats command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["stats", "--help"])

        assert result.exit_code == 0
        assert "Display comprehensive statistics" in result.output

    def test_cli_find_command_help(self) -> None:
        """Test find command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["find", "--help"])

        assert result.exit_code == 0
        assert "Find specific entry" in result.output

    def test_cli_filter_by_class_command_help(self) -> None:
        """Test filter-by-class command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["filter-by-class", "--help"])

        assert result.exit_code == 0
        assert "Filter entries by objectClass" in result.output

    def test_cli_convert_command_help(self) -> None:
        """Test convert command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["convert", "--help"])

        assert result.exit_code == 0
        assert "Convert between different file formats" in result.output

    def test_cli_config_check_command_help(self) -> None:
        """Test config-check command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["config-check", "--help"])

        assert result.exit_code == 0
        assert "Validate CLI configuration" in result.output

    def test_cli_parse_nonexistent_file(self) -> None:
        """Test parse command with nonexistent file."""
        runner = CliRunner()
        result = runner.invoke(cli, ["parse", "/nonexistent/file.ldif"])

        # Click returns exit code 2 for invalid arguments (file doesn't exist)
        assert result.exit_code == 2
        assert "does not exist" in result.output

    def test_cli_parse_valid_file(self) -> None:
        """Test parse command with valid LDIF file."""
        runner = CliRunner()

        # Create a temporary LDIF file
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write("""dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
""")
            temp_path = f.name

        try:
            result = runner.invoke(cli, ["parse", temp_path])

            assert result.exit_code == 0
            assert "Successfully parsed" in result.output
            assert "entries from" in result.output
        finally:
            Path(temp_path).unlink()

    def test_cli_parse_with_output_file(self) -> None:
        """Test parse command with output file."""
        runner = CliRunner()

        # Create input file
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write("""dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
""")
            input_path = f.name

        # Create output file path
        with tempfile.NamedTemporaryFile(suffix=".ldif", delete=False) as f:
            output_path = f.name

        try:
            result = runner.invoke(cli, ["parse", input_path, "--output", output_path])

            assert result.exit_code == 0
            assert "Successfully parsed" in result.output
            assert f"written to {output_path}" in result.output
        finally:
            Path(input_path).unlink()
            Path(output_path).unlink(missing_ok=True)

    def test_cli_parse_with_validation(self) -> None:
        """Test parse command with validation."""
        runner = CliRunner()

        # Create a temporary LDIF file
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write("""dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
""")
            temp_path = f.name

        try:
            result = runner.invoke(cli, ["parse", temp_path, "--validate"])

            assert result.exit_code == 0
            assert "Successfully parsed" in result.output
        finally:
            Path(temp_path).unlink()

    def test_cli_validate_valid_file(self) -> None:
        """Test validate command with valid file."""
        runner = CliRunner()

        # Create a temporary LDIF file
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write("""dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
""")
            temp_path = f.name

        try:
            result = runner.invoke(cli, ["validate", temp_path])

            assert result.exit_code == 0
            assert "All" in result.output
            assert "entries are valid" in result.output
        finally:
            Path(temp_path).unlink()

    def test_cli_stats_valid_file(self) -> None:
        """Test stats command with valid file."""
        runner = CliRunner()

        # Create a temporary LDIF file
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write("""dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
""")
            temp_path = f.name

        try:
            result = runner.invoke(cli, ["stats", temp_path])

            assert result.exit_code == 0
            assert f"Statistics for {temp_path}" in result.output
        finally:
            Path(temp_path).unlink()

    def test_cli_find_existing_entry(self) -> None:
        """Test find command with existing entry."""
        runner = CliRunner()

        # Create a temporary LDIF file
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write("""dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
""")
            temp_path = f.name

        try:
            result = runner.invoke(
                cli,
                ["find", temp_path, "cn=test,dc=example,dc=com"],
            )

            assert result.exit_code == 0
            assert "Found entry" in result.output
        finally:
            Path(temp_path).unlink()

    def test_cli_find_nonexistent_entry(self) -> None:
        """Test find command with nonexistent entry."""
        runner = CliRunner()

        # Create a temporary LDIF file
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write("""dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
""")
            temp_path = f.name

        try:
            result = runner.invoke(
                cli,
                ["find", temp_path, "cn=nonexistent,dc=example,dc=com"],
            )

            assert result.exit_code == 1
            assert "not found" in result.output
        finally:
            Path(temp_path).unlink()

    def test_cli_filter_by_class(self) -> None:
        """Test filter-by-class command."""
        runner = CliRunner()

        # Create a temporary LDIF file
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write("""dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
""")
            temp_path = f.name

        try:
            result = runner.invoke(cli, ["filter-by-class", temp_path, "person"])

            assert result.exit_code == 0
            assert "Found" in result.output
            assert "entries with objectClass 'person'" in result.output
        finally:
            Path(temp_path).unlink()

    def test_cli_transform_with_filter(self) -> None:
        """Test transform command with filtering."""
        runner = CliRunner()

        # Create input file
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write("""dn: cn=person,dc=example,dc=com
objectClass: person
cn: person

dn: cn=group,dc=example,dc=com
objectClass: groupOfNames
cn: group
""")
            input_path = f.name

        # Create output file path
        with tempfile.NamedTemporaryFile(suffix=".ldif", delete=False) as f:
            output_path = f.name

        try:
            result = runner.invoke(
                cli,
                [
                    "transform",
                    input_path,
                    output_path,
                    "--filter-type",
                    "persons",
                ],
            )

            assert result.exit_code == 0
            assert "Loaded" in result.output
            assert "Filtered to" in result.output
        finally:
            Path(input_path).unlink()
            Path(output_path).unlink(missing_ok=True)

    def test_cli_transform_with_sort(self) -> None:
        """Test transform command with sorting."""
        runner = CliRunner()

        # Create input file
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write("""dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
""")
            input_path = f.name

        # Create output file path
        with tempfile.NamedTemporaryFile(suffix=".ldif", delete=False) as f:
            output_path = f.name

        try:
            result = runner.invoke(
                cli,
                [
                    "transform",
                    input_path,
                    output_path,
                    "--sort",
                ],
            )

            assert result.exit_code == 0
            assert "Loaded" in result.output
            assert "sorted hierarchically" in result.output
        finally:
            Path(input_path).unlink()
            Path(output_path).unlink(missing_ok=True)

    def test_cli_convert_to_json(self) -> None:
        """Test convert command to JSON format."""
        runner = CliRunner()

        # Create input file
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write("""dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
""")
            input_path = f.name

        # Create output file path
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            output_path = f.name

        try:
            result = runner.invoke(
                cli,
                [
                    "convert",
                    "--output-format",
                    "json",
                    input_path,
                    output_path,
                ],
            )

            assert result.exit_code == 0
            assert "Converted" in result.output
            assert "to json" in result.output
        finally:
            Path(input_path).unlink()
            Path(output_path).unlink(missing_ok=True)

    def test_cli_config_check(self) -> None:
        """Test config-check command."""
        runner = CliRunner()

        # Use input() to automatically confirm the action
        result = runner.invoke(cli, ["config-check"], input="y\n")

        assert result.exit_code == 0
        assert "CLI Configuration" in result.output

    @patch("flext_ldif.cli.create_api_with_config")
    def test_cli_with_exception_handling(self, mock_create_api: Mock) -> None:
        """Test CLI exception handling."""
        runner = CliRunner()

        # Mock API to raise exception
        mock_api = Mock()
        mock_api.parse_file.side_effect = Exception("Test exception")
        mock_create_api.return_value = mock_api

        # Create a temporary test file for error testing
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write("test")
            temp_path = f.name

        try:
            result = runner.invoke(cli, ["parse", temp_path])
        finally:
            Path(temp_path).unlink()

        assert result.exit_code == 1
        assert "Parse operation failed" in result.output

    def test_cli_global_options(self) -> None:
        """Test CLI global options."""
        runner = CliRunner()

        # Test verbose option
        result = runner.invoke(cli, ["--verbose", "--help"])
        assert result.exit_code == 0

        # Test format option
        result = runner.invoke(cli, ["--format", "json", "--help"])
        assert result.exit_code == 0

    def test_cli_keyboard_interrupt(self) -> None:
        """Test CLI keyboard interrupt handling."""
        runner = CliRunner()

        with patch("flext_ldif.cli.create_api_with_config") as mock_create_api:
            mock_api = Mock()
            mock_api.parse_file.side_effect = KeyboardInterrupt()
            mock_create_api.return_value = mock_api

            # Create a temporary test file for interrupt testing
            with tempfile.NamedTemporaryFile(
                encoding="utf-8",
                mode="w",
                suffix=".ldif",
                delete=False,
            ) as f:
                f.write("test")
                temp_path = f.name

            try:
                result = runner.invoke(cli, ["parse", temp_path])
            finally:
                Path(temp_path).unlink()

            assert result.exit_code == 1
            assert "Aborted!" in result.output
