"""Comprehensive tests for FlextLdifUtilities to achieve 100% coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from flext_ldif import FlextLdifProtocols, FlextLdifUtilities


class TestTimeUtilities:
    """Tests for TimeUtilities nested class."""

    def test_get_timestamp_returns_iso_format(self) -> None:
        timestamp = FlextLdifUtilities.TimeUtilities.get_timestamp()
        assert isinstance(timestamp, str)
        assert "T" in timestamp
        assert timestamp.endswith(("Z", "+00:00"))

    def test_get_formatted_timestamp_default_format(self) -> None:
        timestamp = FlextLdifUtilities.TimeUtilities.get_formatted_timestamp()
        assert isinstance(timestamp, str)
        assert len(timestamp) == 19
        assert timestamp.count(":") == 2

    def test_get_formatted_timestamp_custom_format(self) -> None:
        custom_format = "%Y-%m-%d"
        timestamp = FlextLdifUtilities.TimeUtilities.get_formatted_timestamp(
            custom_format
        )
        assert isinstance(timestamp, str)
        assert len(timestamp) == 10
        assert timestamp.count("-") == 2


class TestFileUtilities:
    """Tests for FileUtilities nested class."""

    def test_validate_file_path_success_existing_directory(
        self, tmp_path: Path
    ) -> None:
        file_path = tmp_path / "test.txt"
        result = FlextLdifUtilities.FileUtilities.validate_file_path(file_path)
        assert result.is_success

    def test_validate_file_path_creates_parent_directory(self, tmp_path: Path) -> None:
        file_path = tmp_path / "new_dir" / "sub_dir" / "test.txt"
        result = FlextLdifUtilities.FileUtilities.validate_file_path(file_path)
        assert result.is_success
        assert file_path.parent.exists()

    def test_validate_file_path_permission_error_on_mkdir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        file_path = tmp_path / "protected" / "test.txt"

        original_mkdir = Path.mkdir

        def mock_mkdir(
            self: Path,
            mode: int = 0o777,
            *,
            parents: bool = False,
            exist_ok: bool = False,
        ) -> None:
            if "protected" in str(self):
                msg = "Permission denied"
                raise PermissionError(msg)
            original_mkdir(self, mode, parents, exist_ok)

        monkeypatch.setattr(Path, "mkdir", mock_mkdir)

        result = FlextLdifUtilities.FileUtilities.validate_file_path(file_path)
        assert result.is_failure
        assert result.error is not None
        assert "Permission denied" in result.error

    def test_validate_file_path_oserror_on_mkdir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        file_path = tmp_path / "bad_dir" / "test.txt"

        original_mkdir = Path.mkdir

        def mock_mkdir(
            self: Path,
            mode: int = 0o777,
            *,
            parents: bool = False,
            exist_ok: bool = False,
        ) -> None:
            if "bad_dir" in str(self):
                msg = "OS error occurred"
                raise OSError(msg)
            original_mkdir(self, mode, parents, exist_ok)

        monkeypatch.setattr(Path, "mkdir", mock_mkdir)

        result = FlextLdifUtilities.FileUtilities.validate_file_path(file_path)
        assert result.is_failure
        assert result.error is not None
        assert "Failed to create directory" in result.error
        assert "OS error occurred" in result.error

    def test_validate_file_path_existing_non_file(self, tmp_path: Path) -> None:
        dir_path = tmp_path / "existing_dir"
        dir_path.mkdir()

        result = FlextLdifUtilities.FileUtilities.validate_file_path(dir_path)
        assert result.is_failure
        assert result.error is not None
        assert "not a file" in result.error

    def test_validate_file_path_non_writable_file(self, tmp_path: Path) -> None:
        file_path = tmp_path / "readonly.txt"
        file_path.write_text("test")
        file_path.chmod(0o444)

        result = FlextLdifUtilities.FileUtilities.validate_file_path(file_path)

        file_path.chmod(0o644)

        assert result.is_failure
        assert result.error is not None
        assert "not writable" in result.error

    def test_validate_file_path_non_writable_parent_directory(
        self, tmp_path: Path
    ) -> None:
        parent_dir = tmp_path / "readonly_dir"
        parent_dir.mkdir()
        parent_dir.chmod(0o555)

        file_path = parent_dir / "test.txt"

        result = FlextLdifUtilities.FileUtilities.validate_file_path(file_path)

        parent_dir.chmod(0o755)

        assert result.is_failure
        assert result.error is not None
        assert "not writable" in result.error

    def test_ensure_file_extension_adds_extension(self) -> None:
        file_path = Path("test")
        result = FlextLdifUtilities.FileUtilities.ensure_file_extension(
            file_path, ".ldif"
        )
        assert result == Path("test.ldif")

    def test_ensure_file_extension_without_dot(self) -> None:
        file_path = Path("test")
        result = FlextLdifUtilities.FileUtilities.ensure_file_extension(
            file_path, "ldif"
        )
        assert result == Path("test.ldif")

    def test_ensure_file_extension_changes_wrong_extension(self) -> None:
        file_path = Path("test.txt")
        result = FlextLdifUtilities.FileUtilities.ensure_file_extension(
            file_path, ".ldif"
        )
        assert result == Path("test.ldif")

    def test_ensure_file_extension_keeps_correct_extension(self) -> None:
        file_path = Path("test.ldif")
        result = FlextLdifUtilities.FileUtilities.ensure_file_extension(
            file_path, ".ldif"
        )
        assert result == Path("test.ldif")

    def test_ensure_file_extension_case_insensitive(self) -> None:
        file_path = Path("test.LDIF")
        result = FlextLdifUtilities.FileUtilities.ensure_file_extension(
            file_path, ".ldif"
        )
        assert result == Path("test.LDIF")


class TestTextUtilities:
    """Tests for TextUtilities nested class."""

    def test_format_bytes_zero(self) -> None:
        result = FlextLdifUtilities.TextUtilities.format_bytes(0)
        assert result == "0 B"

    def test_format_bytes_bytes(self) -> None:
        result = FlextLdifUtilities.TextUtilities.format_bytes(500)
        assert result == "500 B"

    def test_format_bytes_kilobytes(self) -> None:
        result = FlextLdifUtilities.TextUtilities.format_bytes(1536)
        assert result == "1.5 KB"

    def test_format_bytes_megabytes(self) -> None:
        result = FlextLdifUtilities.TextUtilities.format_bytes(1048576)
        assert result == "1.0 MB"

    def test_format_bytes_gigabytes(self) -> None:
        result = FlextLdifUtilities.TextUtilities.format_bytes(1073741824)
        assert result == "1.0 GB"

    def test_format_bytes_terabytes(self) -> None:
        result = FlextLdifUtilities.TextUtilities.format_bytes(1099511627776)
        assert result == "1.0 TB"

    def test_format_bytes_max_unit(self) -> None:
        result = FlextLdifUtilities.TextUtilities.format_bytes(10 * 1099511627776)
        assert "TB" in result

    def test_truncate_string_no_truncation_needed(self) -> None:
        text = "short"
        result = FlextLdifUtilities.TextUtilities.truncate_string(text, 10)
        assert result == "short"

    def test_truncate_string_truncates_long_text(self) -> None:
        text = "This is a very long string"
        result = FlextLdifUtilities.TextUtilities.truncate_string(text, 15)
        assert result == "This is a ve..."
        assert len(result) == 15

    def test_truncate_string_custom_suffix(self) -> None:
        text = "Long text here"
        result = FlextLdifUtilities.TextUtilities.truncate_string(text, 10, " [...]")
        assert result.endswith(" [...]")
        assert len(result) == 10

    def test_truncate_string_suffix_longer_than_max(self) -> None:
        text = "Text"
        result = FlextLdifUtilities.TextUtilities.truncate_string(text, 2, "...")
        assert result == ".."
        assert len(result) == 2

    def test_truncate_string_exact_max_length(self) -> None:
        text = "Exactly"
        result = FlextLdifUtilities.TextUtilities.truncate_string(text, 7)
        assert result == "Exactly"


class TestLdifUtilities:
    """Tests for LdifUtilities nested class."""

    def test_count_entries_with_attribute_using_has_attribute(self) -> None:
        entry1 = MagicMock(spec=FlextLdifProtocols.LdifEntryProtocol)
        entry1.has_attribute = MagicMock(return_value=True)
        entry2 = MagicMock(spec=FlextLdifProtocols.LdifEntryProtocol)
        entry2.has_attribute = MagicMock(return_value=False)
        entry3 = MagicMock(spec=FlextLdifProtocols.LdifEntryProtocol)
        entry3.has_attribute = MagicMock(return_value=True)

        entries: list[FlextLdifProtocols.LdifEntryProtocol] = [entry1, entry2, entry3]
        count = FlextLdifUtilities.LdifUtilities.count_entries_with_attribute(
            entries, "cn"
        )

        assert count == 2

    def test_count_entries_with_attribute_using_attributes_dict(self) -> None:
        entry1 = MagicMock(spec=FlextLdifProtocols.LdifEntryProtocol)
        entry1.attributes = {"cn": ["test"], "sn": ["user"]}
        delattr(entry1, "has_attribute")

        entry2 = MagicMock(spec=FlextLdifProtocols.LdifEntryProtocol)
        entry2.attributes = {"sn": ["user"]}
        delattr(entry2, "has_attribute")

        entries: list[FlextLdifProtocols.LdifEntryProtocol] = [entry1, entry2]
        count = FlextLdifUtilities.LdifUtilities.count_entries_with_attribute(
            entries, "cn"
        )

        assert count == 1

    def test_count_entries_with_attribute_no_entries(self) -> None:
        count = FlextLdifUtilities.LdifUtilities.count_entries_with_attribute([], "cn")
        assert count == 0

    def test_extract_dns_from_entries(self) -> None:
        entry1 = MagicMock(spec=FlextLdifProtocols.LdifEntryProtocol)
        entry1.dn = "cn=test1,dc=example,dc=com"

        entry2 = MagicMock(spec=FlextLdifProtocols.LdifEntryProtocol)
        entry2.dn = "cn=test2,dc=example,dc=com"

        entries: list[FlextLdifProtocols.LdifEntryProtocol] = [entry1, entry2]
        dns = FlextLdifUtilities.LdifUtilities.extract_dns_from_entries(entries)

        assert dns == ["cn=test1,dc=example,dc=com", "cn=test2,dc=example,dc=com"]

    def test_extract_dns_from_entries_empty(self) -> None:
        dns = FlextLdifUtilities.LdifUtilities.extract_dns_from_entries([])
        assert dns == []

    def test_extract_dns_from_entries_missing_dn(self) -> None:
        entry1 = MagicMock(spec=FlextLdifProtocols.LdifEntryProtocol)
        entry1.dn = "cn=test,dc=example,dc=com"

        entry2 = MagicMock(spec=[])

        entries: list[FlextLdifProtocols.LdifEntryProtocol] = [entry1, entry2]
        dns = FlextLdifUtilities.LdifUtilities.extract_dns_from_entries(entries)

        assert dns == ["cn=test,dc=example,dc=com"]

    def test_get_unique_attribute_names(self) -> None:
        entry1 = MagicMock(spec=FlextLdifProtocols.LdifEntryProtocol)
        entry1.attributes = {"cn": ["test"], "sn": ["user"]}

        entry2 = MagicMock(spec=FlextLdifProtocols.LdifEntryProtocol)
        entry2.attributes = {"cn": ["test2"], "mail": ["test@example.com"]}

        entries: list[FlextLdifProtocols.LdifEntryProtocol] = [entry1, entry2]
        attrs = FlextLdifUtilities.LdifUtilities.get_unique_attribute_names(entries)

        assert attrs == {"cn", "sn", "mail"}

    def test_get_unique_attribute_names_empty(self) -> None:
        attrs = FlextLdifUtilities.LdifUtilities.get_unique_attribute_names([])
        assert attrs == set()

    def test_get_unique_attribute_names_no_attributes(self) -> None:
        entry1 = MagicMock(spec=[])
        entry2 = MagicMock(spec=[])

        entries: list[FlextLdifProtocols.LdifEntryProtocol] = [entry1, entry2]
        attrs = FlextLdifUtilities.LdifUtilities.get_unique_attribute_names(entries)

        assert attrs == set()
