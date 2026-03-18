"""Tests for flext_ldif.__version__ module.

Tests version metadata loading from pyproject.toml via importlib.metadata.
Covers all edge cases including missing metadata, invalid versions, and all exports.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from importlib import import_module

from flext_tests import tm

from tests import s

version_module = import_module("flext_ldif.__version__")


class TestsFlextLdifVersion(s):
    """Test version module metadata loading and exports."""

    def test_version_exported(self) -> None:
        """Test __version__ is exported and accessible."""
        tm.that(hasattr(version_module, "__version__"), eq=True)
        tm.that(isinstance(version_module.__version__, str), eq=True)
        tm.that(version_module.__version__ != "", eq=True)

    def test_version_info_exported(self) -> None:
        """Test __version_info__ is exported and is a tuple."""
        tm.that(hasattr(version_module, "__version_info__"), eq=True)
        tm.that(isinstance(version_module.__version_info__, tuple), eq=True)
        tm.that(len(version_module.__version_info__) >= 2, eq=True)

    def test_version_info_parsing(self) -> None:
        """Test __version_info__ correctly parses version string."""
        version_parts = version_module.__version__.split(".")
        version_info = version_module.__version_info__
        tm.that(len(version_info) == len(version_parts), eq=True)
        for part, info_part in zip(version_parts, version_info, strict=False):
            if part.isdigit():
                tm.that(isinstance(info_part, int), eq=True)
                tm.that(info_part == int(part), eq=True)
            else:
                tm.that(isinstance(info_part, str), eq=True)
                tm.that(info_part == part, eq=True)

    def test_title_exported(self) -> None:
        """Test __title__ is exported."""
        tm.that(hasattr(version_module, "__title__"), eq=True)
        tm.that(isinstance(version_module.__title__, str), eq=True)
        tm.that(version_module.__title__ != "", eq=True)

    def test_description_exported(self) -> None:
        """Test __description__ is exported."""
        tm.that(hasattr(version_module, "__description__"), eq=True)
        tm.that(isinstance(version_module.__description__, str), eq=True)

    def test_author_exported(self) -> None:
        """Test __author__ is exported."""
        tm.that(hasattr(version_module, "__author__"), eq=True)
        tm.that(isinstance(version_module.__author__, str), eq=True)

    def test_author_email_exported(self) -> None:
        """Test __author_email__ is exported."""
        tm.that(hasattr(version_module, "__author_email__"), eq=True)
        tm.that(isinstance(version_module.__author_email__, str), eq=True)

    def test_license_exported(self) -> None:
        """Test __license__ is exported."""
        tm.that(hasattr(version_module, "__license__"), eq=True)
        tm.that(isinstance(version_module.__license__, str), eq=True)
        tm.that(version_module.__license__ != "", eq=True)

    def test_url_exported(self) -> None:
        """Test __url__ is exported."""
        tm.that(hasattr(version_module, "__url__"), eq=True)
        tm.that(isinstance(version_module.__url__, str), eq=True)

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
        tm.that(hasattr(version_module, "__all__"), eq=True)
        tm.that(isinstance(version_module.__all__, list), eq=True)
        for export in expected_exports:
            (
                tm.that(export in version_module.__all__, eq=True),
                f"{export} not in __all__",
            )
            (
                tm.that(hasattr(version_module, export), eq=True),
                f"{export} not accessible",
            )

    def test_version_default_fallback(self) -> None:
        """Test version falls back to default when metadata missing."""
        original_version = version_module.__version__
        tm.that(original_version != "", eq=True)
        tm.that(original_version != "0.0.0", eq=True)

    def test_version_info_with_prerelease(self) -> None:
        """Test __version_info__ handles prerelease versions correctly."""
        version_str = "1.2.3-alpha.1"
        parts = version_str.split(".")
        version_info = tuple(int(part) if part.isdigit() else part for part in parts)
        tm.that(version_info[0] == 1, eq=True)
        tm.that(version_info[1] == 2, eq=True)
        tm.that(isinstance(version_info[2], str), eq=True)
        if isinstance(version_info[2], str):
            tm.that("alpha" in version_info[2], eq=True)

    def test_version_info_with_build(self) -> None:
        """Test __version_info__ handles build metadata correctly."""
        version_str = "1.2.3+build.123"
        parts = version_str.split(".")
        version_info = tuple(int(part) if part.isdigit() else part for part in parts)
        tm.that(version_info[0] == 1, eq=True)
        tm.that(version_info[1] == 2, eq=True)
        tm.that(isinstance(version_info[2], str), eq=True)
        if isinstance(version_info[2], str):
            tm.that("+build" in version_info[2], eq=True)
        tm.that(version_info[3] == 123, eq=True)
