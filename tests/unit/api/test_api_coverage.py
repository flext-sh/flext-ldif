"""Coverage tests for FlextLdif API.

Tests core API functionality including parsing, writing, filtering, and error handling.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar, cast

import pytest

from flext_ldif import FlextLdif
from tests import m, s


class TestsFlextLdifApiCoverage(s):
    """Test coverage for FlextLdif API operations."""

    api: ClassVar[FlextLdif]  # pytest fixture

    @pytest.fixture
    def api(self) -> FlextLdif:
        """Create API instance."""
        return FlextLdif()

    def test_get_effective_server_type(self, api: FlextLdif) -> None:
        """Test get_effective_server_type."""
        result = api.get_effective_server_type()
        assert result.is_success
        assert result.unwrap() == "rfc"

    def test_parse_file_os_error(self, api: FlextLdif, tmp_path: Path) -> None:
        """Test _parse_file with OSError (directory)."""
        directory = tmp_path / "test_dir"
        directory.mkdir()
        result = api.parse(directory)
        assert result.is_failure
        assert "Failed to read file" in str(result.error)

    def test_write_file_os_error(self, api: FlextLdif, tmp_path: Path) -> None:
        """Test write_file with OSError (directory as file)."""
        directory = tmp_path / "test_dir_write"
        directory.mkdir()
        entries = [m.Entry(dn="cn=test", attributes={"cn": ["test"]})]
        result = api.write_file(entries, directory)
        assert result.is_failure
        assert "Failed to write file" in str(result.error)

    def test_filter_entries_exception(self, api: FlextLdif) -> None:
        """Test filter_entries with exception raising function."""
        entries = [m.Entry(dn="cn=test", attributes={"cn": ["test"]})]

        def failing_filter(_entry: m.Entry) -> bool:
            msg = "Filter failed"
            raise ValueError(msg)

        result = api.filter_entries(entries, failing_filter)
        assert result.is_failure
        assert "Filter error" in str(result.error)

    def test_get_entry_statistics_exception(self, api: FlextLdif) -> None:
        """Test get_entry_statistics exception handling."""
        result = api.get_entry_statistics(cast("list[m.Entry]", None))
        assert result.is_success
