# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)

if _t.TYPE_CHECKING:
    from flext_ldap import d, e, h, r, s, x
    from flext_tests import td, tf, tk, tm, tv

    from tests.constants import TestsFlextLdifConstants, c
    from tests.models import TestsFlextLdifModels, m
    from tests.protocols import TestsFlextLdifProtocols, p
    from tests.typings import TestsFlextLdifTypes, t
    from tests.unit.services.test_migration_pipeline import (
        TestsTestFlextLdifMigrationPipeline,
    )
    from tests.unit.services.test_quirks_standardization import (
        TestAliasDiscovery,
        TestQuirksAutoInterchange,
        TestQuirksWithRealLdifFixtures,
        TestsFlextLdifServersStandardizedConstants,
    )
    from tests.utilities import TestsFlextLdifUtilities, u
_LAZY_IMPORTS = merge_lazy_imports(
    (
        ".integration",
        ".unit",
    ),
    build_lazy_import_map(
        {
            ".constants": (
                "TestsFlextLdifConstants",
                "c",
            ),
            ".models": (
                "TestsFlextLdifModels",
                "m",
            ),
            ".protocols": (
                "TestsFlextLdifProtocols",
                "p",
            ),
            ".typings": (
                "TestsFlextLdifTypes",
                "t",
            ),
            ".unit.services.test_migration_pipeline": (
                "TestsTestFlextLdifMigrationPipeline",
            ),
            ".unit.services.test_quirks_standardization": (
                "TestAliasDiscovery",
                "TestQuirksAutoInterchange",
                "TestQuirksWithRealLdifFixtures",
                "TestsFlextLdifServersStandardizedConstants",
            ),
            ".utilities": (
                "TestsFlextLdifUtilities",
                "u",
            ),
            "flext_ldap": (
                "d",
                "e",
                "h",
                "r",
                "s",
                "x",
            ),
            "flext_tests": (
                "td",
                "tf",
                "tk",
                "tm",
                "tv",
            ),
        },
    ),
    exclude_names=(
        "cleanup_submodule_namespace",
        "install_lazy_exports",
        "lazy_getattr",
        "logger",
        "merge_lazy_imports",
        "output",
        "output_reporting",
    ),
    module_name=__name__,
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)

__all__: list[str] = [
    "TestAliasDiscovery",
    "TestQuirksAutoInterchange",
    "TestQuirksWithRealLdifFixtures",
    "TestsFlextLdifConstants",
    "TestsFlextLdifModels",
    "TestsFlextLdifProtocols",
    "TestsFlextLdifServersStandardizedConstants",
    "TestsFlextLdifTypes",
    "TestsFlextLdifUtilities",
    "TestsTestFlextLdifMigrationPipeline",
    "c",
    "d",
    "e",
    "h",
    "m",
    "p",
    "r",
    "s",
    "t",
    "td",
    "tf",
    "tk",
    "tm",
    "tv",
    "u",
    "x",
]
