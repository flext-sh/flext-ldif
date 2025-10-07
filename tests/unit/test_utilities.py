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
            assert (
                "encoding" in str(result.error).lower()
                or "codec" in str(result.error).lower()
            )
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
            validation_result = utilities.FileUtilities.validate_file_path(temp_path)
            assert isinstance(validation_result, FlextResult)
        finally:
            temp_path.unlink()

        # Test count_lines_in_file returns FlextResult
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, encoding="utf-8"
        ) as temp_file:
            temp_path = Path(temp_file.name)
            temp_file.write("test\n")

        try:
            count_result = utilities.FileUtilities.count_lines_in_file(temp_path)
            assert isinstance(count_result, FlextResult)
        finally:
            temp_path.unlink()

    def test_error_handling(self) -> None:
        """Test error handling in utility methods."""
        utilities = FlextLdifUtilities()

        # Test invalid input types
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
        assert "Empty" in str(result.error)
        assert "value" in str(result.error)

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
        assert result == Path("/tmp/test.ldif")

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
                result = FlextLdifUtilities.FileUtilities.validate_file_path(file_path)
                # validate_file_path checks existence and is_file, not writability
                # The file still exists and is a file, so this should pass
                assert result.is_success
            finally:
                # Restore permissions for cleanup
                parent_path.chmod(0o755)


class TestFlextLdifUtilitiesDnUtilities:
    """Test suite for DN utilities."""

    def test_parse_dn_components_valid(self) -> None:
        """Test parsing valid DN components."""
        dn = "cn=test,ou=users,dc=example,dc=com"

        result = FlextLdifUtilities.DnUtilities.parse_dn_components(dn)

        assert result.is_success
        components = result.unwrap()
        assert isinstance(components, list)
        assert len(components) > 0

    def test_parse_dn_components_invalid(self) -> None:
        """Test parsing invalid DN components."""
        invalid_dn = "invalid-dn-format"

        result = FlextLdifUtilities.DnUtilities.parse_dn_components(invalid_dn)

        # Should handle gracefully
        assert isinstance(result, FlextResult)

    def test_normalize_dn_components(self) -> None:
        """Test normalizing DN components."""
        dn = "CN=test,OU=users,DC=example,DC=com"

        result = FlextLdifUtilities.DnUtilities.normalize_dn(dn)

        assert result.is_success
        normalized = result.unwrap()
        assert isinstance(normalized, str)
        # Should be lowercase
        assert normalized == dn.lower()

    def test_extract_dn_components(self) -> None:
        """Test parsing DN components."""
        dn = "cn=test,ou=users,dc=example,dc=com"

        result = FlextLdifUtilities.DnUtilities.parse_dn_components(dn)

        assert result.is_success
        components = result.unwrap()
        assert isinstance(components, list)
        assert len(components) > 0
        # Each component should be a tuple of (attribute, value)
        for comp in components:
            assert isinstance(comp, tuple)
            assert len(comp) == 2


class TestFlextLdifUtilitiesEncodingUtilities:
    """Test suite for encoding utilities."""

    def test_detect_encoding_utf8(self) -> None:
        """Test detecting UTF-8 encoding."""
        content = "dn: cn=test,dc=example,dc=com\ncn: test"

        result = FlextLdifUtilities.EncodingUtilities.detect_encoding(
            content.encode("utf-8")
        )

        assert result.is_success
        encoding = result.unwrap()
        assert encoding == "utf-8"

    def test_detect_encoding_latin1(self) -> None:
        """Test detecting Latin-1 encoding."""
        content = "dn: cn=test,dc=example,dc=com\ncn: test"
        latin1_content = content.encode("latin-1")

        result = FlextLdifUtilities.EncodingUtilities.detect_encoding(latin1_content)

        assert result.is_success
        encoding = result.unwrap()
        assert encoding in {"latin-1", "utf-8"}  # May detect as either

    def test_validate_encoding_supported(self) -> None:
        """Test validating supported encoding."""
        result = FlextLdifUtilities.FileUtilities.validate_encoding("utf-8")

        assert result.is_success
        valid_encoding = result.unwrap()
        assert valid_encoding == "utf-8"

    def test_validate_encoding_unsupported(self) -> None:
        """Test validating unsupported encoding."""
        result = FlextLdifUtilities.FileUtilities.validate_encoding(
            "unsupported-encoding"
        )

        assert result.is_failure


class TestFlextLdifUtilitiesTextUtilities:
    """Test suite for text utilities."""

    def test_format_byte_size_bytes(self) -> None:
        """Test formatting bytes."""
        result = FlextLdifUtilities.TextUtilities.format_byte_size(512)

        assert result == "512 B"

    def test_format_byte_size_kilobytes(self) -> None:
        """Test formatting kilobytes."""
        result = FlextLdifUtilities.TextUtilities.format_byte_size(1536)

        assert "1.5 KB" in result

    def test_format_byte_size_megabytes(self) -> None:
        """Test formatting megabytes."""
        result = FlextLdifUtilities.TextUtilities.format_byte_size(1048576)

        assert "1.0 MB" in result

    def test_format_byte_size_zero(self) -> None:
        """Test formatting zero bytes."""
        result = FlextLdifUtilities.TextUtilities.format_byte_size(0)

        assert result == "0 B"

    def test_format_byte_size_negative(self) -> None:
        """Test formatting negative bytes."""
        result = FlextLdifUtilities.TextUtilities.format_byte_size(-100)

        assert result == "0 B"


class TestFlextLdifUtilitiesTimeUtilities:
    """Test suite for time utilities."""

    def test_get_timestamp(self) -> None:
        """Test getting current timestamp."""
        timestamp = FlextLdifUtilities.TimeUtilities.get_timestamp()

        assert isinstance(timestamp, str)
        assert len(timestamp) > 0
        # Should be ISO format
        assert "T" in timestamp

    def test_get_formatted_timestamp(self) -> None:
        """Test getting formatted timestamp."""
        format_string = "%Y-%m-%d %H:%M:%S"
        timestamp = FlextLdifUtilities.TimeUtilities.get_formatted_timestamp(
            format_string
        )

        assert isinstance(timestamp, str)
        assert len(timestamp) > 0
        # Should match format
        assert len(timestamp.split("-")) == 3  # YYYY-MM-DD
        assert len(timestamp.split(":")) == 3  # HH:MM:SS


class TestFlextLdifUtilitiesFileUtilities:
    """Test suite for file utilities."""

    def test_get_file_info_existing_file(self, tmp_path: Path) -> None:
        """Test getting info for existing file."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content", encoding="utf-8")

        result = FlextLdifUtilities.FileUtilities.get_file_info(test_file)

        assert result.is_success
        info = result.unwrap()
        assert isinstance(info, dict)
        assert "size" in info
        assert "modified" in info
        assert "encoding" in info

    def test_get_file_info_nonexistent_file(self) -> None:
        """Test getting info for non-existent file."""
        nonexistent_file = Path("/non/existent/file.txt")

        result = FlextLdifUtilities.FileUtilities.get_file_info(nonexistent_file)

        assert result.is_failure

    def test_validate_directory_path_existing(self, tmp_path: Path) -> None:
        """Test validating existing directory path."""
        result = FlextLdifUtilities.FileUtilities.validate_directory_path(tmp_path)

        assert result.is_success
        validated_path = result.unwrap()
        assert validated_path == tmp_path

    def test_validate_directory_path_nonexistent(self) -> None:
        """Test validating non-existent directory path."""
        nonexistent_dir = Path("/non/existent/directory")

        result = FlextLdifUtilities.FileUtilities.validate_directory_path(
            nonexistent_dir
        )

        assert result.is_failure


class TestFlextLdifUtilitiesValidationUtilities:
    """Test suite for validation utilities."""

    def test_validate_object_class_name_valid(self) -> None:
        """Test validating valid object class name."""
        result = FlextLdifUtilities.ValidationUtilities.validate_object_class_name(
            "inetOrgPerson"
        )

        assert result.is_success
        valid_name = result.unwrap()
        assert valid_name == "inetOrgPerson"

    def test_validate_object_class_name_invalid(self) -> None:
        """Test validating invalid object class name."""
        result = FlextLdifUtilities.ValidationUtilities.validate_object_class_name(
            "invalid-class-name!"
        )

        assert result.is_failure

    def test_validate_attribute_name_valid(self) -> None:
        """Test validating valid attribute name."""
        result = FlextLdifUtilities.ValidationUtilities.validate_attribute_name("cn")

        assert result.is_success
        valid_name = result.unwrap()
        assert valid_name == "cn"

    def test_validate_attribute_name_invalid(self) -> None:
        """Test validating invalid attribute name."""
        result = FlextLdifUtilities.ValidationUtilities.validate_attribute_name(
            "invalid-attr!"
        )

        assert result.is_failure


class TestFlextLdifUtilitiesLdifUtilities:
    """Test suite for LDIF-specific utilities."""

    def test_count_ldif_entries(self) -> None:
        """Test counting LDIF entries."""
        ldif_content = """dn: cn=test1,dc=example,dc=com
cn: test1

dn: cn=test2,dc=example,dc=com
cn: test2
"""

        result = FlextLdifUtilities.LdifUtilities.count_ldif_entries(ldif_content)

        assert result.is_success
        count = result.unwrap()
        assert count == 2

    def test_count_ldif_entries_empty(self) -> None:
        """Test counting entries in empty LDIF."""
        result = FlextLdifUtilities.LdifUtilities.count_ldif_entries("")

        assert result.is_success
        count = result.unwrap()
        assert count == 0

    def test_validate_ldif_syntax_valid(self) -> None:
        """Test validating valid LDIF syntax."""
        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
"""

        result = FlextLdifUtilities.LdifUtilities.validate_ldif_syntax(ldif_content)

        assert result.is_success
        validation = result.unwrap()
        assert isinstance(validation, dict)

    def test_validate_ldif_syntax_invalid(self) -> None:
        """Test validating invalid LDIF syntax."""
        invalid_content = "invalid ldif content without proper format"

        result = FlextLdifUtilities.LdifUtilities.validate_ldif_syntax(invalid_content)

        assert result.is_failure


class TestFlextLdifUtilitiesNamespace:
    """Test suite for the FlextLdifUtilities namespace class."""

    def test_utilities_namespace_access(self) -> None:
        """Test accessing utilities through namespace."""
        # Test that all expected utility classes are available
        assert hasattr(FlextLdifUtilities, "DnUtilities")
        assert hasattr(FlextLdifUtilities, "EncodingUtilities")
        assert hasattr(FlextLdifUtilities, "TextUtilities")
        assert hasattr(FlextLdifUtilities, "TimeUtilities")
        assert hasattr(FlextLdifUtilities, "FileUtilities")
        assert hasattr(FlextLdifUtilities, "ValidationUtilities")
        assert hasattr(FlextLdifUtilities, "LdifUtilities")

    def test_utilities_are_classes(self) -> None:
        """Test that utility groups are classes."""
        assert isinstance(FlextLdifUtilities.DnUtilities, type)
        assert isinstance(FlextLdifUtilities.EncodingUtilities, type)
        assert isinstance(FlextLdifUtilities.TextUtilities, type)
        assert isinstance(FlextLdifUtilities.TimeUtilities, type)
        assert isinstance(FlextLdifUtilities.FileUtilities, type)
        assert isinstance(FlextLdifUtilities.ValidationUtilities, type)
        assert isinstance(FlextLdifUtilities.LdifUtilities, type)

    def test_utility_methods_exist(self) -> None:
        """Test that key utility methods exist."""
        # DnUtilities
        assert hasattr(FlextLdifUtilities.DnUtilities, "parse_dn_components")
        assert hasattr(FlextLdifUtilities.DnUtilities, "validate_dn_format")

        # TextUtilities
        assert hasattr(FlextLdifUtilities.TextUtilities, "format_byte_size")

        # TimeUtilities
        assert hasattr(FlextLdifUtilities.TimeUtilities, "get_timestamp")

        # FileUtilities
        assert hasattr(FlextLdifUtilities.FileUtilities, "validate_file_path")

        # EncodingUtilities
        assert hasattr(FlextLdifUtilities.EncodingUtilities, "detect_encoding")

        # ValidationUtilities
        assert hasattr(
            FlextLdifUtilities.ValidationUtilities, "validate_attribute_name"
        )

        # LdifUtilities
        assert hasattr(FlextLdifUtilities.LdifUtilities, "count_ldif_entries")
