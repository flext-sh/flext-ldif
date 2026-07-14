"""Behavioral tests for the public flext_ldif.__version__ contract."""

from __future__ import annotations

import importlib

import pytest
from flext_tests import tm

from tests import c

version_module = importlib.import_module("flext_ldif.__version__")
FlextLdifVersion = version_module.FlextLdifVersion


class TestsFlextLdifVersion:
    """Validate the observable public version metadata and API."""

    def test_version_exports_are_present_and_non_empty(self) -> None:
        """Required public metadata strings are present and non-empty."""
        tm.that(version_module.__version__, is_=str)
        tm.that(version_module.__title__, is_=str)
        tm.that(version_module.__license__, is_=str)
        tm.that(version_module.__all__, is_=list)
        tm.that(version_module.__version__ != "", eq=True)
        tm.that(version_module.__title__ != "", eq=True)
        tm.that(version_module.__license__ != "", eq=True)

    def test_all_expected_symbols_are_exported(self) -> None:
        """Every documented symbol is exported through __all__ and importable."""
        for export in c.Tests.VERSION_EXPECTED_EXPORTS:
            tm.that(version_module.__all__, has=export)
            tm.that(hasattr(version_module, export), eq=True)

    def test_version_info_shape_matches_version_string(self) -> None:
        """__version_info__ token count equals the dotted __version__ token count."""
        version_parts = version_module.__version__.split(".")
        tm.that(version_module.__version_info__, is_=tuple)
        tm.that(len(version_module.__version_info__), eq=len(version_parts))

    def test_version_info_parses_numeric_tokens_as_int(self) -> None:
        """Numeric version tokens are exposed as ints for comparison semantics."""
        for token, part in zip(
            version_module.__version_info__,
            version_module.__version__.split("."),
            strict=True,
        ):
            expected: int | str = int(part) if part.isdigit() else part
            tm.that(token, eq=expected)

    def test_resolve_version_string_returns_public_version(self) -> None:
        """resolve_version_string() returns the exported version string."""
        tm.that(
            FlextLdifVersion.resolve_version_string(),
            eq=version_module.__version__,
        )

    def test_resolve_version_info_returns_public_version_info(self) -> None:
        """resolve_version_info() returns the exported version-info tuple."""
        tm.that(
            FlextLdifVersion.resolve_version_info(),
            eq=version_module.__version_info__,
        )

    def test_resolve_package_info_reports_public_metadata(self) -> None:
        """resolve_package_info() mirrors the exported metadata fields."""
        info = FlextLdifVersion.resolve_package_info()
        tm.that(info["name"], eq=version_module.__title__)
        tm.that(info["version"], eq=version_module.__version__)
        tm.that(info["description"], eq=version_module.__description__)
        tm.that(info["author"], eq=version_module.__author__)
        tm.that(info["author_email"], eq=version_module.__author_email__)
        tm.that(info["license"], eq=version_module.__license__)
        tm.that(info["url"], eq=version_module.__url__)

    @pytest.mark.parametrize(
        ("major", "minor", "patch", "expected"),
        [
            (0, 0, 0, True),
            (999, 0, 0, False),
            (0, 999, 0, False),
        ],
    )
    def test_version_at_least_enforces_ordering(
        self,
        major: int,
        minor: int,
        patch: int,
        *,
        expected: bool,
    ) -> None:
        """version_at_least() answers the ordering query against the real version."""
        tm.that(
            FlextLdifVersion.version_at_least(major, minor, patch),
            eq=expected,
        )

    def test_version_at_least_is_satisfied_by_own_numeric_version(self) -> None:
        """The package always satisfies a bound equal to its own numeric prefix."""
        numeric = [
            int(part)
            for part in version_module.__version__.split(".")
            if part.isdigit()
        ]
        major = numeric[0] if numeric else 0
        minor = numeric[1] if len(numeric) > 1 else 0
        patch = numeric[2] if len(numeric) > 2 else 0
        tm.that(FlextLdifVersion.version_at_least(major, minor, patch), eq=True)
