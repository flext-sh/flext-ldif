"""Behavioral tests for the public flext_ldif.__version__ contract.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import sys

from packaging.version import Version

from flext_ldif import FlextLdifVersion
from tests import c, tm

# The package root shadows `__version__` with the exported version string, so
# the submodule object is reached through sys.modules; the module-level import
# above guarantees the submodule is loaded and present in sys.modules.
version_module = sys.modules["flext_ldif.__version__"]


class TestsFlextLdifVersion:
    """Validate the observable public version metadata and API."""

    @staticmethod
    def test_version_exports_are_present_and_non_empty() -> None:
        """Required public metadata strings are present and non-empty."""
        tm.that(version_module.__version__, is_=str)
        tm.that(version_module.__title__, is_=str)
        tm.that(version_module.__license__, is_=str)
        tm.that(version_module.__all__, is_=list)
        for metadata in (
            version_module.__version__,
            version_module.__title__,
            version_module.__license__,
        ):
            tm.ok(len(metadata) > 0)

    @staticmethod
    def test_all_expected_symbols_are_exported() -> None:
        """Every documented symbol is exported through __all__ and importable."""
        for export in c.Tests.VERSION_EXPECTED_EXPORTS:
            tm.that(version_module.__all__, has=export)
            tm.ok(hasattr(version_module, export))

    @staticmethod
    def test_version_info_shape_matches_version_string() -> None:
        """__version_info__ is an exact three-integer release tuple."""
        tm.that(version_module.__version_info__, is_=tuple)
        tm.that(len(version_module.__version_info__), eq=3)
        assert all(
            isinstance(component, int) for component in version_module.__version_info__
        )

    @staticmethod
    def test_version_info_parses_numeric_tokens_as_int() -> None:
        """Version info matches the release tuple parsed from the public version."""
        expected = Version(version_module.__version__).release
        tm.that(version_module.__version_info__, eq=expected)

    @staticmethod
    def test_version_attribute_returns_public_version() -> None:
        """FlextLdifVersion.__version__ equals the exported version string."""
        tm.that(FlextLdifVersion.__version__, eq=version_module.__version__)

    @staticmethod
    def test_version_info_attribute_returns_public_version_info() -> None:
        """FlextLdifVersion.__version_info__ equals the exported version-info tuple."""
        tm.that(FlextLdifVersion.__version_info__, eq=version_module.__version_info__)

    @staticmethod
    def test_metadata_attributes_mirror_module_exports() -> None:
        """The metadata facade attributes mirror the exported module metadata."""
        tm.that(FlextLdifVersion.__title__, eq=version_module.__title__)
        tm.that(FlextLdifVersion.__version__, eq=version_module.__version__)
        tm.that(FlextLdifVersion.__description__, eq=version_module.__description__)
        tm.that(FlextLdifVersion.__author__, eq=version_module.__author__)
        tm.that(FlextLdifVersion.__license__, eq=version_module.__license__)
        tm.that(FlextLdifVersion.__url__, eq=version_module.__url__)
