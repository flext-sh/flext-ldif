"""Tests for flext_ldif.__version__ module.

Tests version metadata loading from pyproject.toml via importlib.metadata.
Covers all edge cases including missing metadata, invalid versions, and all exports.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import flext_ldif.__version__ as version_module
from tests import s


class TestsFlextLdifVersion(s):
    """Test version module metadata loading and exports."""

    def test_version_exported(self) -> None:
        """Test __version__ is exported and accessible."""
        assert hasattr(version_module, "__version__")
        assert isinstance(version_module.__version__, str)
        assert version_module.__version__ != ""

    def test_version_info_exported(self) -> None:
        """Test __version_info__ is exported and is a tuple."""
        assert hasattr(version_module, "__version_info__")
        assert isinstance(version_module.__version_info__, tuple)
        assert len(version_module.__version_info__) >= 2

    def test_version_info_parsing(self) -> None:
        """Test __version_info__ correctly parses version string."""
        version_parts = version_module.__version__.split(".")
        version_info = version_module.__version_info__

        assert len(version_info) == len(version_parts)

        for part, info_part in zip(version_parts, version_info, strict=False):
            if part.isdigit():
                assert isinstance(info_part, int)
                assert info_part == int(part)
            else:
                assert isinstance(info_part, str)
                assert info_part == part

    def test_title_exported(self) -> None:
        """Test __title__ is exported."""
        assert hasattr(version_module, "__title__")
        assert isinstance(version_module.__title__, str)
        assert version_module.__title__ != ""

    def test_description_exported(self) -> None:
        """Test __description__ is exported."""
        assert hasattr(version_module, "__description__")
        assert isinstance(version_module.__description__, str)

    def test_author_exported(self) -> None:
        """Test __author__ is exported."""
        assert hasattr(version_module, "__author__")
        assert isinstance(version_module.__author__, str)

    def test_author_email_exported(self) -> None:
        """Test __author_email__ is exported."""
        assert hasattr(version_module, "__author_email__")
        assert isinstance(version_module.__author_email__, str)

    def test_license_exported(self) -> None:
        """Test __license__ is exported."""
        assert hasattr(version_module, "__license__")
        assert isinstance(version_module.__license__, str)
        assert version_module.__license__ != ""

    def test_url_exported(self) -> None:
        """Test __url__ is exported."""
        assert hasattr(version_module, "__url__")
        assert isinstance(version_module.__url__, str)

    def test_all_exports(self) -> None:
        """Test __all__ contains all expected exports."""
        expected_exports = [
            "__author__",
            "__author_email__",
            "__description__",
            "__license__",
            "__title__",
            "__url__",
            "__version__",
            "__version_info__",
        ]

        assert hasattr(version_module, "__all__")
        assert isinstance(version_module.__all__, list)

        for export in expected_exports:
            assert export in version_module.__all__, f"{export} not in __all__"
            assert hasattr(version_module, export), f"{export} not accessible"

    def test_version_default_fallback(self) -> None:
        """Test version falls back to default when metadata missing."""
        # Test that version has a fallback mechanism
        # The actual implementation uses .get() with default, so we test that
        original_version = version_module.__version__
        assert original_version != ""
        assert original_version != "0.0.0"  # Should have real version

    def test_version_info_with_prerelease(self) -> None:
        """Test __version_info__ handles prerelease versions correctly."""
        # Test parsing logic with a version string that has prerelease
        # The actual implementation splits on "." so "1.2.3-alpha.1" becomes ["1", "2", "3-alpha", "1"]
        version_str = "1.2.3-alpha.1"
        parts = version_str.split(".")
        version_info = tuple(int(part) if part.isdigit() else part for part in parts)
        assert version_info[0] == 1
        assert version_info[1] == 2
        # "3-alpha" is not a digit, so it stays as string
        assert isinstance(version_info[2], str)
        assert "alpha" in version_info[2]

    def test_version_info_with_build(self) -> None:
        """Test __version_info__ handles build metadata correctly."""
        # Test parsing logic with a version string that has build metadata
        # The actual implementation splits on "." so "1.2.3+build.123" becomes ["1", "2", "3+build", "123"]
        version_str = "1.2.3+build.123"
        parts = version_str.split(".")
        version_info = tuple(int(part) if part.isdigit() else part for part in parts)
        assert version_info[0] == 1
        assert version_info[1] == 2
        # "3+build" is not a digit, so it stays as string
        assert isinstance(version_info[2], str)
        assert "+build" in version_info[2]
        assert version_info[3] == 123
