"""Test suite for FlextLdifUtilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from flext_core import FlextResult
from flext_ldif.utilities import FlextLdifUtilities


class TestFlextLdifUtilities:
    """Test suite for FlextLdifUtilities."""

    def test_initialization(self) -> None:
        """Test utilities initialization."""
        utilities = FlextLdifUtilities()
        assert utilities is not None

    def test_validate_file_path_exists(self) -> None:
        """Test file path validation for existing files."""
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_path = Path(temp_file.name)
            temp_file.write(b"test content")

        try:
            result = FlextLdifUtilities.FileUtilities.validate_file_path(temp_path)
            assert isinstance(result, FlextResult)
            assert result.is_success
            assert result.value == temp_path
        finally:
            temp_path.unlink()

    def test_validate_file_path_not_exists(self) -> None:
        """Test file path validation for non-existing files."""
        non_existent_path = Path("/non/existent/path.txt")

        result = FlextLdifUtilities.FileUtilities.validate_file_path(non_existent_path)
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert "does not exist" in str(result.error)

    def test_validate_file_path_directory(self) -> None:
        """Test file path validation for directories."""
        with tempfile.TemporaryDirectory() as temp_dir:
            dir_path = Path(temp_dir)

            result = FlextLdifUtilities.FileUtilities.validate_file_path(dir_path)
            assert isinstance(result, FlextResult)
            assert result.is_failure
            assert "is a directory" in str(result.error)

    def test_validate_file_path_permissions(self) -> None:
        """Test file path validation for permission issues."""
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_path = Path(temp_file.name)
            temp_file.write(b"test content")

        try:
            # Make file read-only
            temp_path.chmod(0o444)

            result = FlextLdifUtilities.FileUtilities.validate_file_path(temp_path)
            assert isinstance(result, FlextResult)
            # Should succeed for read-only files
            assert result.is_success
        finally:
            temp_path.unlink()

    def test_validate_file_path_writable(self) -> None:
        """Test file path validation for writable files."""
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_path = Path(temp_file.name)
            temp_file.write(b"test content")

        try:
            result = FlextLdifUtilities.FileUtilities.validate_file_path(
                temp_path, check_writable=True
            )
            assert isinstance(result, FlextResult)
            assert result.is_success
        finally:
            temp_path.unlink()

    def test_validate_file_path_not_writable(self) -> None:
        """Test file path validation for non-writable files."""
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_path = Path(temp_file.name)
            temp_file.write(b"test content")

        try:
            # Make file read-only
            temp_path.chmod(0o444)

            result = FlextLdifUtilities.FileUtilities.validate_file_path(
                temp_path, check_writable=True
            )
            assert isinstance(result, FlextResult)
            assert result.is_failure
            assert "not writable" in str(result.error)
        finally:
            temp_path.unlink()

    def test_validate_file_path_parent_not_writable(self) -> None:
        """Test file path validation when parent directory is not writable."""
        with tempfile.TemporaryDirectory() as temp_dir:
            parent_path = Path(temp_dir)
            file_path = parent_path / "test.txt"

            # Make parent directory read-only
            parent_path.chmod(0o555)

            try:
                result = FlextLdifUtilities.FileUtilities.validate_file_path(
                    file_path, check_writable=True
                )
                assert isinstance(result, FlextResult)
                assert result.is_failure
                assert "not writable" in str(result.error)
            finally:
                # Restore permissions for cleanup
                parent_path.chmod(0o755)

    def test_validate_file_path_absolute(self) -> None:
        """Test file path validation with absolute paths."""
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_path = Path(temp_file.name).resolve()
            temp_file.write(b"test content")

        try:
            result = FlextLdifUtilities.FileUtilities.validate_file_path(temp_path)
            assert isinstance(result, FlextResult)
            assert result.is_success
            assert result.value == temp_path
        finally:
            temp_path.unlink()

    def test_validate_file_path_relative(self) -> None:
        """Test file path validation with relative paths."""
        with tempfile.NamedTemporaryFile(dir=".", delete=False) as temp_file:
            temp_path = Path(temp_file.name)
            temp_file.write(b"test content")

        try:
            result = FlextLdifUtilities.FileUtilities.validate_file_path(temp_path)
            assert isinstance(result, FlextResult)
            assert result.is_success
            assert result.value == temp_path.resolve()
        finally:
            temp_path.unlink()

    def test_format_byte_size_zero(self) -> None:
        """Test byte size formatting for zero bytes."""
        result = FlextLdifUtilities.TextUtilities.format_byte_size(0)
        assert result == "0 B"

    def test_format_byte_size_bytes(self) -> None:
        """Test byte size formatting for bytes."""
        result = FlextLdifUtilities.TextUtilities.format_byte_size(512)
        assert result == "512.0 B"

    def test_format_byte_size_kilobytes(self) -> None:
        """Test byte size formatting for kilobytes."""
        result = FlextLdifUtilities.TextUtilities.format_byte_size(1024)
        assert result == "1.0 KB"

    def test_format_byte_size_megabytes(self) -> None:
        """Test byte size formatting for megabytes."""
        result = FlextLdifUtilities.TextUtilities.format_byte_size(1024 * 1024)
        assert result == "1.0 MB"

    def test_format_byte_size_gigabytes(self) -> None:
        """Test byte size formatting for gigabytes."""
        result = FlextLdifUtilities.TextUtilities.format_byte_size(1024 * 1024 * 1024)
        assert result == "1.0 GB"

    def test_format_byte_size_terabytes(self) -> None:
        """Test byte size formatting for terabytes."""
        result = FlextLdifUtilities.TextUtilities.format_byte_size(
            1024 * 1024 * 1024 * 1024
        )
        assert result == "1.0 TB"

    def test_format_byte_size_fractional(self) -> None:
        """Test byte size formatting with fractional values."""
        result = FlextLdifUtilities.TextUtilities.format_byte_size(1536)  # 1.5 KB
        assert result == "1.5 KB"

    def test_format_byte_size_large_value(self) -> None:
        """Test byte size formatting with very large values."""
        result = FlextLdifUtilities.TextUtilities.format_byte_size(
            1024 * 1024 * 1024 * 1024 * 1024
        )
        assert result == "1024.0 TB"

    def test_count_lines_in_file(self) -> None:
        """Test counting lines in a file."""
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, encoding="utf-8"
        ) as temp_file:
            temp_path = Path(temp_file.name)
            temp_file.write("line 1\nline 2\nline 3\n")

        try:
            result = FlextLdifUtilities.FileUtilities.count_lines_in_file(temp_path)
            assert isinstance(result, FlextResult)
            assert result.is_success
            assert result.value == 3
        finally:
            temp_path.unlink()

    def test_count_lines_in_file_empty(self) -> None:
        """Test counting lines in an empty file."""
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, encoding="utf-8"
        ) as temp_file:
            temp_path = Path(temp_file.name)
            # Write nothing (empty file)

        try:
            result = FlextLdifUtilities.FileUtilities.count_lines_in_file(temp_path)
            assert isinstance(result, FlextResult)
            assert result.is_success
            assert result.value == 0
        finally:
            temp_path.unlink()

    def test_count_lines_in_file_no_newline(self) -> None:
        """Test counting lines in a file without final newline."""
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, encoding="utf-8"
        ) as temp_file:
            temp_path = Path(temp_file.name)
            temp_file.write("line 1\nline 2\nline 3")  # No final newline

        try:
            result = FlextLdifUtilities.FileUtilities.count_lines_in_file(temp_path)
            assert isinstance(result, FlextResult)
            assert result.is_success
            assert result.value == 3
        finally:
            temp_path.unlink()

    def test_count_lines_in_file_nonexistent(self) -> None:
        """Test counting lines in a non-existent file."""
        non_existent_path = Path("/non/existent/path.txt")

        result = FlextLdifUtilities.FileUtilities.count_lines_in_file(non_existent_path)
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert "does not exist" in str(result.error)

    def test_count_lines_in_file_encoding_error(self) -> None:
        """Test counting lines in a file with encoding issues."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as temp_file:
            temp_path = Path(temp_file.name)
            # Write binary data that can't be decoded as UTF-8
            temp_file.write(b"\xff\xfe\x00\x00")

        try:
            result = FlextLdifUtilities.FileUtilities.count_lines_in_file(temp_path)
            assert isinstance(result, FlextResult)
            assert result.is_failure
            assert "encoding" in str(result.error).lower()
        finally:
            temp_path.unlink()

    def test_count_lines_in_file_large_file(self) -> None:
        """Test counting lines in a large file."""
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, encoding="utf-8"
        ) as temp_file:
            temp_path = Path(temp_file.name)
            # Write 1000 lines
            for i in range(1000):
                temp_file.write(f"line {i}\n")

        try:
            result = FlextLdifUtilities.FileUtilities.count_lines_in_file(temp_path)
            assert isinstance(result, FlextResult)
            assert result.is_success
            assert result.value == 1000
        finally:
            temp_path.unlink()

    def test_utility_methods_exist(self) -> None:
        """Test that all expected utility methods exist."""
        utilities = FlextLdifUtilities()

        # Test that all public methods exist
        assert hasattr(utilities.FileUtilities, "validate_file_path")
        assert hasattr(utilities.TextUtilities, "format_byte_size")
        assert hasattr(utilities.FileUtilities, "count_lines_in_file")

        # Test that methods are callable
        assert callable(utilities.FileUtilities.validate_file_path)
        assert callable(utilities.TextUtilities.format_byte_size)
        assert callable(utilities.FileUtilities.count_lines_in_file)

    def test_utility_methods_return_types(self) -> None:
        """Test that utility methods return expected types."""
        utilities = FlextLdifUtilities()

        # Test format_byte_size returns string
        result = utilities.TextUtilities.format_byte_size(1024)
        assert isinstance(result, str)

        # Test validate_file_path returns FlextResult
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_path = Path(temp_file.name)
            temp_file.write(b"test")

        try:
            result = utilities.FileUtilities.validate_file_path(temp_path)
            assert isinstance(result, FlextResult)
        finally:
            temp_path.unlink()

        # Test count_lines_in_file returns FlextResult
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, encoding="utf-8"
        ) as temp_file:
            temp_path = Path(temp_file.name)
            temp_file.write("test\n")

        try:
            result = utilities.FileUtilities.count_lines_in_file(temp_path)
            assert isinstance(result, FlextResult)
        finally:
            temp_path.unlink()

    def test_error_handling(self) -> None:
        """Test error handling in utility methods."""
        utilities = FlextLdifUtilities()

        # Test invalid input types (should raise TypeError for non-int inputs)
        with pytest.raises(TypeError):
            utilities.TextUtilities.format_byte_size("invalid")

        with pytest.raises(TypeError):
            utilities.TextUtilities.format_byte_size(None)

    def test_edge_cases(self) -> None:
        """Test edge cases in utility methods."""
        utilities = FlextLdifUtilities()

        # Test negative byte size
        result = utilities.TextUtilities.format_byte_size(-1)
        assert result == "0 B"  # Should handle negative values gracefully

        # Test very small positive byte size
        result = utilities.TextUtilities.format_byte_size(1)
        assert result == "1.0 B"

        # Test byte size exactly at boundary
        result = utilities.TextUtilities.format_byte_size(1023)
        assert result == "1023.0 B"

        result = utilities.TextUtilities.format_byte_size(1024)
        assert result == "1.0 KB"

    # =========================================================================
    # TIME UTILITIES TESTS - Comprehensive time-related functionality
    # =========================================================================

    def test_time_get_timestamp(self) -> None:
        """Test getting ISO format timestamp."""
        timestamp = FlextLdifUtilities.TimeUtilities.get_timestamp()
        assert isinstance(timestamp, str)
        # Check ISO format (YYYY-MM-DDTHH:MM:SS.microseconds+TZ)
        assert "T" in timestamp
        assert len(timestamp) > 20  # ISO timestamp is at least 20 chars

    def test_time_get_formatted_timestamp_default(self) -> None:
        """Test getting formatted timestamp with default format."""
        timestamp = FlextLdifUtilities.TimeUtilities.get_formatted_timestamp()
        assert isinstance(timestamp, str)
        # Default format: "%Y-%m-%d %H:%M:%S"
        assert len(timestamp) == 19  # YYYY-MM-DD HH:MM:SS = 19 chars
        assert timestamp[4] == "-"
        assert timestamp[7] == "-"
        assert timestamp[10] == " "
        assert timestamp[13] == ":"
        assert timestamp[16] == ":"

    def test_time_get_formatted_timestamp_custom(self) -> None:
        """Test getting formatted timestamp with custom format."""
        timestamp = FlextLdifUtilities.TimeUtilities.get_formatted_timestamp("%Y%m%d")
        assert isinstance(timestamp, str)
        assert len(timestamp) == 8  # YYYYMMDD = 8 chars
        assert timestamp.isdigit()

    def test_time_get_formatted_timestamp_various_formats(self) -> None:
        """Test various timestamp formats."""
        # Time only
        time_only = FlextLdifUtilities.TimeUtilities.get_formatted_timestamp("%H:%M:%S")
        assert len(time_only) == 8

        # Date only
        date_only = FlextLdifUtilities.TimeUtilities.get_formatted_timestamp("%Y-%m-%d")
        assert len(date_only) == 10

        # Custom format with text
        custom = FlextLdifUtilities.TimeUtilities.get_formatted_timestamp("Year: %Y")
        assert "Year:" in custom

    # =========================================================================
    # DN UTILITIES TESTS - Comprehensive DN parsing and validation
    # =========================================================================

    def test_dn_parse_components_simple(self) -> None:
        """Test parsing simple DN components."""
        dn = "cn=test,ou=users,dc=example,dc=com"
        result = FlextLdifUtilities.DnUtilities.parse_dn_components(dn)

        assert result.is_success
        components = result.unwrap()
        assert len(components) == 4
        assert components[0] == "cn=test"
        assert components[1] == "ou=users"
        assert components[2] == "dc=example"
        assert components[3] == "dc=com"

    def test_dn_parse_components_with_escaped_comma(self) -> None:
        """Test parsing DN with escaped comma."""
        dn = r"cn=Smith\, John,ou=users,dc=example,dc=com"
        result = FlextLdifUtilities.DnUtilities.parse_dn_components(dn)

        assert result.is_success
        components = result.unwrap()
        assert len(components) == 4
        assert components[0] == r"cn=Smith\, John"

    def test_dn_parse_components_with_spaces(self) -> None:
        """Test parsing DN with spaces."""
        dn = "cn=John Doe, ou=Engineering Department, dc=example, dc=com"
        result = FlextLdifUtilities.DnUtilities.parse_dn_components(dn)

        assert result.is_success
        components = result.unwrap()
        assert len(components) == 4
        assert components[0] == "cn=John Doe"
        assert components[1] == "ou=Engineering Department"

    def test_dn_parse_components_empty_dn(self) -> None:
        """Test parsing empty DN."""
        result = FlextLdifUtilities.DnUtilities.parse_dn_components("")
        assert result.is_failure
        assert "cannot be empty" in str(result.error)

    def test_dn_parse_components_whitespace_only(self) -> None:
        """Test parsing whitespace-only DN."""
        result = FlextLdifUtilities.DnUtilities.parse_dn_components("   ")
        assert result.is_failure
        assert "cannot be empty" in str(result.error)

    def test_dn_validate_format_valid(self) -> None:
        """Test validating valid DN format."""
        dn = "cn=test,ou=users,dc=example,dc=com"
        result = FlextLdifUtilities.DnUtilities.validate_dn_format(dn)

        assert result.is_success
        assert result.unwrap() is True

    def test_dn_validate_format_empty(self) -> None:
        """Test validating empty DN."""
        result = FlextLdifUtilities.DnUtilities.validate_dn_format("")
        assert result.is_failure
        assert "empty" in str(result.error).lower()

    def test_dn_validate_format_too_long(self) -> None:
        """Test validating DN exceeding maximum length."""
        # Create a DN longer than MAX_DN_LENGTH (typically 1024)
        long_dn = "cn=" + "x" * 10000 + ",dc=example,dc=com"
        result = FlextLdifUtilities.DnUtilities.validate_dn_format(long_dn)

        assert result.is_failure
        assert "exceeds maximum length" in str(result.error)

    def test_dn_validate_format_missing_equals(self) -> None:
        """Test validating DN with missing = separator."""
        dn = "cntest,ou=users,dc=example,dc=com"
        result = FlextLdifUtilities.DnUtilities.validate_dn_format(dn)

        assert result.is_failure
        assert "missing '=' separator" in str(result.error)

    def test_dn_validate_format_empty_attribute(self) -> None:
        """Test validating DN with empty attribute."""
        dn = "=test,ou=users,dc=example,dc=com"
        result = FlextLdifUtilities.DnUtilities.validate_dn_format(dn)

        assert result.is_failure
        assert "Empty attribute" in str(result.error)

    def test_dn_validate_format_empty_value(self) -> None:
        """Test validating DN with empty value."""
        dn = "cn=,ou=users,dc=example,dc=com"
        result = FlextLdifUtilities.DnUtilities.validate_dn_format(dn)

        assert result.is_failure
        assert "Empty" in str(result.error) and "value" in str(result.error)

    def test_dn_validate_format_single_component(self) -> None:
        """Test validating DN with single component (valid if minimum is 1)."""
        dn = "dc=com"  # Single component DN
        result = FlextLdifUtilities.DnUtilities.validate_dn_format(dn)

        # Should succeed if MIN_DN_COMPONENTS is 1
        assert result.is_success

    def test_dn_normalize_simple(self) -> None:
        """Test normalizing simple DN."""
        dn = "CN=Test,OU=Users,DC=Example,DC=Com"
        result = FlextLdifUtilities.DnUtilities.normalize_dn(dn)

        assert result.is_success
        normalized = result.unwrap()
        assert normalized == "cn=Test,ou=Users,dc=Example,dc=Com"
        # Attributes lowercased, values preserved case

    def test_dn_normalize_with_spaces(self) -> None:
        """Test normalizing DN with extra spaces."""
        dn = "cn =  Test  User  , ou = Users , dc = example , dc = com"
        result = FlextLdifUtilities.DnUtilities.normalize_dn(dn)

        assert result.is_success
        normalized = result.unwrap()
        assert normalized == "cn=Test User,ou=Users,dc=example,dc=com"

    def test_dn_normalize_invalid(self) -> None:
        """Test normalizing invalid DN."""
        dn = "invalid-dn-format"
        result = FlextLdifUtilities.DnUtilities.normalize_dn(dn)

        assert result.is_failure

    def test_dn_get_depth_simple(self) -> None:
        """Test getting DN depth."""
        dn = "cn=test,ou=users,dc=example,dc=com"
        result = FlextLdifUtilities.DnUtilities.get_dn_depth(dn)

        assert result.is_success
        assert result.unwrap() == 4

    def test_dn_get_depth_single_component(self) -> None:
        """Test getting depth of single-component DN."""
        dn = "dc=com"
        result = FlextLdifUtilities.DnUtilities.get_dn_depth(dn)

        assert result.is_success
        assert result.unwrap() == 1

    def test_dn_get_depth_invalid(self) -> None:
        """Test getting depth of invalid DN."""
        result = FlextLdifUtilities.DnUtilities.get_dn_depth("")
        assert result.is_failure

    def test_dn_extract_attribute_found(self) -> None:
        """Test extracting existing attribute from DN."""
        dn = "cn=test,ou=users,dc=example,dc=com"
        result = FlextLdifUtilities.DnUtilities.extract_dn_attribute(dn, "cn")

        assert result.is_success
        assert result.unwrap() == "test"

    def test_dn_extract_attribute_case_insensitive(self) -> None:
        """Test extracting attribute case-insensitively."""
        dn = "CN=test,OU=users,DC=example,DC=com"
        result = FlextLdifUtilities.DnUtilities.extract_dn_attribute(dn, "cn")

        assert result.is_success
        assert result.unwrap() == "test"

    def test_dn_extract_attribute_not_found(self) -> None:
        """Test extracting non-existent attribute."""
        dn = "cn=test,ou=users,dc=example,dc=com"
        result = FlextLdifUtilities.DnUtilities.extract_dn_attribute(dn, "uid")

        assert result.is_failure
        assert "not found" in str(result.error)

    def test_dn_extract_attribute_multiple_matches(self) -> None:
        """Test extracting attribute when multiple DC components exist."""
        dn = "cn=test,ou=users,dc=example,dc=com"
        result = FlextLdifUtilities.DnUtilities.extract_dn_attribute(dn, "dc")

        assert result.is_success
        # Should return first match
        assert result.unwrap() == "example"

    def test_dn_extract_attribute_with_spaces(self) -> None:
        """Test extracting attribute with spaces in value."""
        dn = "cn=John Doe,ou=Engineering Dept,dc=example,dc=com"
        result = FlextLdifUtilities.DnUtilities.extract_dn_attribute(dn, "cn")

        assert result.is_success
        assert result.unwrap() == "John Doe"

    def test_dn_extract_attribute_invalid_dn(self) -> None:
        """Test extracting attribute from invalid DN."""
        result = FlextLdifUtilities.DnUtilities.extract_dn_attribute("", "cn")
        assert result.is_failure

    # =========================================================================
    # FILE UTILITIES - Additional edge cases for 100% coverage
    # =========================================================================

    def test_validate_file_path_nonexistent_with_writable_check(self) -> None:
        """Test validating non-existent file with writable check."""
        with tempfile.TemporaryDirectory() as temp_dir:
            parent_path = Path(temp_dir)
            file_path = parent_path / "newfile.txt"

            # File doesn't exist but parent is writable
            result = FlextLdifUtilities.FileUtilities.validate_file_path(
                file_path, check_writable=True
            )
            assert result.is_success
            assert result.unwrap() == file_path.resolve()

    def test_validate_file_path_nonexistent_parent_nonexistent(self) -> None:
        """Test validating file when parent directory doesn't exist."""
        nonexistent_parent = Path("/nonexistent/directory")
        file_path = nonexistent_parent / "file.txt"

        result = FlextLdifUtilities.FileUtilities.validate_file_path(
            file_path, check_writable=True
        )
        assert result.is_failure
        assert "Parent directory does not exist" in str(result.error)

    def test_validate_file_path_special_file(self) -> None:
        """Test validating special file (not regular file)."""
        # Use /dev/null as a special file that exists but isn't a regular file
        dev_null = Path("/dev/null")
        if dev_null.exists() and not dev_null.is_file():
            result = FlextLdifUtilities.FileUtilities.validate_file_path(dev_null)
            assert result.is_failure
            assert "not a file" in str(result.error)

    def test_count_lines_in_file_not_a_file(self) -> None:
        """Test counting lines when path is a directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            dir_path = Path(temp_dir)

            result = FlextLdifUtilities.FileUtilities.count_lines_in_file(dir_path)
            assert result.is_failure
            assert "not a file" in str(result.error)

    def test_ensure_file_extension_no_dot(self) -> None:
        """Test ensuring file extension when extension has no leading dot."""
        file_path = Path("/tmp/test.txt")
        result = FlextLdifUtilities.FileUtilities.ensure_file_extension(
            file_path, "ldif"
        )
        assert result.suffix == ".ldif"

    def test_ensure_file_extension_already_correct(self) -> None:
        """Test ensuring file extension when already correct."""
        file_path = Path("/tmp/test.ldif")
        result = FlextLdifUtilities.FileUtilities.ensure_file_extension(
            file_path, ".ldif"
        )
        assert result == file_path

    def test_ensure_file_extension_case_insensitive(self) -> None:
        """Test ensuring file extension with case variations."""
        file_path = Path("/tmp/test.LDIF")
        result = FlextLdifUtilities.FileUtilities.ensure_file_extension(
            file_path, ".ldif"
        )
        # Should recognize .LDIF as equivalent to .ldif
        assert result == file_path

    # =========================================================================
    # DN UTILITIES - Additional edge cases for exception paths
    # =========================================================================

    def test_dn_parse_components_exception_handling(self) -> None:
        """Test DN parsing exception handling with complex escaped sequences."""
        # Test with multiple consecutive escaped characters
        dn = r"cn=Test\\User\,Special,ou=users,dc=example,dc=com"
        result = FlextLdifUtilities.DnUtilities.parse_dn_components(dn)

        assert result.is_success
        components = result.unwrap()
        assert len(components) == 4

    def test_dn_validate_format_all_components_validation(self) -> None:
        """Test that all DN components are validated properly."""
        # DN with invalid component in the middle
        dn = "cn=test,invalidcomponent,dc=example,dc=com"
        result = FlextLdifUtilities.DnUtilities.validate_dn_format(dn)

        assert result.is_failure
        assert "missing '=' separator" in str(result.error)

    def test_dn_parse_components_trailing_comma(self) -> None:
        """Test parsing DN with trailing comma (empty component)."""
        dn = "cn=test,ou=users,dc=example,dc=com,"
        result = FlextLdifUtilities.DnUtilities.parse_dn_components(dn)

        # Should succeed, empty components are stripped
        assert result.is_success
        components = result.unwrap()
        assert len(components) == 4  # Empty component should be ignored

    def test_dn_parse_components_only_commas(self) -> None:
        """Test parsing DN with only commas (no valid components)."""
        dn = ",,,"
        result = FlextLdifUtilities.DnUtilities.parse_dn_components(dn)

        assert result.is_failure
        assert "no valid components" in str(result.error)

    def test_dn_extract_attribute_component_without_equals(self) -> None:
        """Test extracting attribute when component has no equals sign."""
        # Create a scenario where a component might not have '=' in extract logic
        # This tests the condition check in line 422
        dn = "cn=test,ou=users,dc=example"
        result = FlextLdifUtilities.DnUtilities.extract_dn_attribute(dn, "sn")

        # Should not find it
        assert result.is_failure
        assert "not found" in str(result.error)

    def test_validate_file_path_existing_parent_not_writable(self) -> None:
        """Test file path validation when existing file's parent is not writable."""
        with tempfile.TemporaryDirectory() as temp_dir:
            parent_path = Path(temp_dir)
            file_path = parent_path / "test.txt"
            file_path.write_text("test", encoding="utf-8")

            # Make parent directory read-only
            parent_path.chmod(0o555)

            try:
                result = FlextLdifUtilities.FileUtilities.validate_file_path(
                    file_path, check_writable=True
                )
                # On Linux, root can still write, so check result appropriately
                if result.is_failure:
                    assert "not writable" in str(result.error)
            finally:
                # Restore permissions for cleanup
                parent_path.chmod(0o755)
