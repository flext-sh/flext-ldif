"""Behavioral tests for the public flext_ldif.__version__ contract."""

from __future__ import annotations

import importlib

from flext_tests import tm
from packaging.version import Version

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
        """__version_info__ is an exact three-integer release tuple."""
        tm.that(version_module.__version_info__, is_=tuple)
        tm.that(len(version_module.__version_info__), eq=3)
        assert all(
            isinstance(component, int) for component in version_module.__version_info__
        )

    def test_version_info_parses_numeric_tokens_as_int(self) -> None:
        """Version info matches the release tuple parsed from the public version."""
        expected = Version(version_module.__version__).release
        tm.that(version_module.__version_info__, eq=expected)

    def test_version_attribute_returns_public_version(self) -> None:
        """FlextLdifVersion.__version__ equals the exported version string."""
        tm.that(
            FlextLdifVersion.__version__,
            eq=version_module.__version__,
        )

    def test_version_info_attribute_returns_public_version_info(self) -> None:
        """FlextLdifVersion.__version_info__ equals the exported version-info tuple."""
        tm.that(
            FlextLdifVersion.__version_info__,
            eq=version_module.__version_info__,
        )

    def test_metadata_attributes_mirror_module_exports(self) -> None:
        """The metadata facade attributes mirror the exported module metadata."""
        tm.that(FlextLdifVersion.__title__, eq=version_module.__title__)
        tm.that(FlextLdifVersion.__version__, eq=version_module.__version__)
        tm.that(FlextLdifVersion.__description__, eq=version_module.__description__)
        tm.that(FlextLdifVersion.__author__, eq=version_module.__author__)
        tm.that(FlextLdifVersion.__license__, eq=version_module.__license__)
        tm.that(FlextLdifVersion.__url__, eq=version_module.__url__)
