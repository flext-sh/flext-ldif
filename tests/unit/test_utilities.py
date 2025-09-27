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
            result = FlextLdifUtilities.validate_file_path(temp_path)
            assert isinstance(result, FlextResult)
            assert result.is_success
            assert result.value == temp_path
        finally:
            temp_path.unlink()

    def test_validate_file_path_not_exists(self) -> None:
        """Test file path validation for non-existing files."""
        non_existent_path = Path("/non/existent/path.txt")

        result = FlextLdifUtilities.validate_file_path(non_existent_path)
        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert "does not exist" in str(result.error)

    def test_validate_file_path_directory(self) -> None:
        """Test file path validation for directories."""
        with tempfile.TemporaryDirectory() as temp_dir:
            dir_path = Path(temp_dir)

            result = FlextLdifUtilities.validate_file_path(dir_path)
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

            result = FlextLdifUtilities.validate_file_path(temp_path)
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
            result = FlextLdifUtilities.validate_file_path(
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

            result = FlextLdifUtilities.validate_file_path(
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
                result = FlextLdifUtilities.validate_file_path(
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
            result = FlextLdifUtilities.validate_file_path(temp_path)
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
            result = FlextLdifUtilities.validate_file_path(temp_path)
            assert isinstance(result, FlextResult)
            assert result.is_success
            assert result.value == temp_path.resolve()
        finally:
            temp_path.unlink()

    def test_format_byte_size_zero(self) -> None:
        """Test byte size formatting for zero bytes."""
        result = FlextLdifUtilities.format_byte_size(0)
        assert result == "0 B"

    def test_format_byte_size_bytes(self) -> None:
        """Test byte size formatting for bytes."""
        result = FlextLdifUtilities.format_byte_size(512)
        assert result == "512.0 B"

    def test_format_byte_size_kilobytes(self) -> None:
        """Test byte size formatting for kilobytes."""
        result = FlextLdifUtilities.format_byte_size(1024)
        assert result == "1.0 KB"

    def test_format_byte_size_megabytes(self) -> None:
        """Test byte size formatting for megabytes."""
        result = FlextLdifUtilities.format_byte_size(1024 * 1024)
        assert result == "1.0 MB"

    def test_format_byte_size_gigabytes(self) -> None:
        """Test byte size formatting for gigabytes."""
        result = FlextLdifUtilities.format_byte_size(1024 * 1024 * 1024)
        assert result == "1.0 GB"

    def test_format_byte_size_terabytes(self) -> None:
        """Test byte size formatting for terabytes."""
        result = FlextLdifUtilities.format_byte_size(1024 * 1024 * 1024 * 1024)
        assert result == "1.0 TB"

    def test_format_byte_size_fractional(self) -> None:
        """Test byte size formatting with fractional values."""
        result = FlextLdifUtilities.format_byte_size(1536)  # 1.5 KB
        assert result == "1.5 KB"

    def test_format_byte_size_large_value(self) -> None:
        """Test byte size formatting with very large values."""
        result = FlextLdifUtilities.format_byte_size(1024 * 1024 * 1024 * 1024 * 1024)
        assert result == "1024.0 TB"

    def test_count_lines_in_file(self) -> None:
        """Test counting lines in a file."""
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, encoding="utf-8"
        ) as temp_file:
            temp_path = Path(temp_file.name)
            temp_file.write("line 1\nline 2\nline 3\n")

        try:
            result = FlextLdifUtilities.count_lines_in_file(temp_path)
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
            result = FlextLdifUtilities.count_lines_in_file(temp_path)
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
            result = FlextLdifUtilities.count_lines_in_file(temp_path)
            assert isinstance(result, FlextResult)
            assert result.is_success
            assert result.value == 3
        finally:
            temp_path.unlink()

    def test_count_lines_in_file_nonexistent(self) -> None:
        """Test counting lines in a non-existent file."""
        non_existent_path = Path("/non/existent/path.txt")

        result = FlextLdifUtilities.count_lines_in_file(non_existent_path)
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
            result = FlextLdifUtilities.count_lines_in_file(temp_path)
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
            result = FlextLdifUtilities.count_lines_in_file(temp_path)
            assert isinstance(result, FlextResult)
            assert result.is_success
            assert result.value == 1000
        finally:
            temp_path.unlink()

    def test_utility_methods_exist(self) -> None:
        """Test that all expected utility methods exist."""
        utilities = FlextLdifUtilities()

        # Test that all public methods exist
        assert hasattr(utilities, "validate_file_path")
        assert hasattr(utilities, "format_byte_size")
        assert hasattr(utilities, "count_lines_in_file")

        # Test that methods are callable
        assert callable(utilities.validate_file_path)
        assert callable(utilities.format_byte_size)
        assert callable(utilities.count_lines_in_file)

    def test_utility_methods_return_types(self) -> None:
        """Test that utility methods return expected types."""
        utilities = FlextLdifUtilities()

        # Test format_byte_size returns string
        result = utilities.format_byte_size(1024)
        assert isinstance(result, str)

        # Test validate_file_path returns FlextResult
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_path = Path(temp_file.name)
            temp_file.write(b"test")

        try:
            result = utilities.validate_file_path(temp_path)
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
            result = utilities.count_lines_in_file(temp_path)
            assert isinstance(result, FlextResult)
        finally:
            temp_path.unlink()

    def test_error_handling(self) -> None:
        """Test error handling in utility methods."""
        utilities = FlextLdifUtilities()

        # Test invalid input types
        with pytest.raises(TypeError):
            utilities.format_byte_size("invalid")  # type: ignore[arg-type]

        with pytest.raises(TypeError):
            utilities.format_byte_size(None)  # type: ignore[arg-type]

    def test_edge_cases(self) -> None:
        """Test edge cases in utility methods."""
        utilities = FlextLdifUtilities()

        # Test negative byte size
        result = utilities.format_byte_size(-1)
        assert result == "0 B"  # Should handle negative values gracefully

        # Test very small positive byte size
        result = utilities.format_byte_size(1)
        assert result == "1.0 B"

        # Test byte size exactly at boundary
        result = utilities.format_byte_size(1023)
        assert result == "1023.0 B"

        result = utilities.format_byte_size(1024)
        assert result == "1.0 KB"
