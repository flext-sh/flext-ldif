"""Behavior tests for the public flext_ldif.__version__ module."""

from __future__ import annotations

import importlib

from flext_tests import tm

from tests.constants import c

version_module = importlib.import_module("flext_ldif.__version__")


class TestsFlextLdifVersion:
    """Validate exported public version metadata."""

    def test_version_exports_are_present(self) -> None:
        """Public metadata exports are available and non-empty where required."""
        tm.that(version_module.__version__, is_=str)
        tm.that(version_module.__title__, is_=str)
        tm.that(version_module.__license__, is_=str)
        tm.that(version_module.__all__, is_=list)
        tm.that(version_module.__version__ != "", eq=True)
        tm.that(version_module.__title__ != "", eq=True)
        tm.that(version_module.__license__ != "", eq=True)

    def test_version_info_matches_version_shape(self) -> None:
        """__version_info__ aligns with the split version token count."""
        version_parts = version_module.__version__.split(".")
        tm.that(version_module.__version_info__, is_=tuple)
        tm.that(len(version_module.__version_info__), eq=len(version_parts))

    def test_all_public_symbols_are_exported(self) -> None:
        """All documented symbols are exported through __all__."""
        for export in c.Tests.VERSION_EXPECTED_EXPORTS:
            tm.that(version_module.__all__, has=export)
            tm.that(hasattr(version_module, export), eq=True)

    def test_exports_reference_flextldifversion_class(self) -> None:
        """Module-level exports are derived from FlextLdifVersion fields."""
        tm.that(
            version_module.__version__, eq=version_module.FlextLdifVersion.__version__
        )
        tm.that(
            version_module.__version_info__,
            eq=version_module.FlextLdifVersion.__version_info__,
        )
        tm.that(version_module.__title__, eq=version_module.FlextLdifVersion.__title__)
        tm.that(
            version_module.__description__,
            eq=version_module.FlextLdifVersion.__description__,
        )
        tm.that(
            version_module.__author__, eq=version_module.FlextLdifVersion.__author__
        )
        tm.that(
            version_module.__author_email__,
            eq=version_module.FlextLdifVersion.__author_email__,
        )
        tm.that(
            version_module.__license__, eq=version_module.FlextLdifVersion.__license__
        )
        tm.that(version_module.__url__, eq=version_module.FlextLdifVersion.__url__)
