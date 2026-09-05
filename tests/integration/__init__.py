# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests.integration package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_tests import c, d, e, h, m, p, r, s, t, td, tf, tk, tm, tv, u, x

    from .test_cross_direction_conversion import TestsFlextLdifCrossDirectionConversion
    from .test_cross_server_conversion import TestsFlextLdifCrossServerConversion
    from .test_dn_case_handling import TestsFlextLdifDnCaseHandling
    from .test_edge_cases import TestsFlextLdifEdgeCases
    from .test_error_recovery import TestsFlextLdifErrorRecovery
    from .test_minimal_differences_metadata import (
        TestsFlextLdifMinimalDifferencesMetadata,
    )
    from .test_oid_integration import TestsFlextLdifOidIntegration
    from .test_oud_integration import TestsFlextLdifOudIntegration
    from .test_oud_to_oid_migration import TestsFlextLdifOudToOidMigration
    from .test_real_ldap_config import TestsFlextLdifRealLdapConfig
    from .test_real_ldap_export import TestsFlextLdifRealLdapExport
    from .test_real_ldap_import import TestsFlextLdifRealLdapImport
    from .test_real_ldap_roundtrip import TestsFlextLdifRealLdapRoundtrip
    from .test_systematic_fixture_coverage import (
        TestsFlextLdifSystematicFixtureCoverage,
    )
__all__: tuple[str, ...] = (
    "TestsFlextLdifCrossDirectionConversion",
    "TestsFlextLdifCrossServerConversion",
    "TestsFlextLdifDnCaseHandling",
    "TestsFlextLdifEdgeCases",
    "TestsFlextLdifErrorRecovery",
    "TestsFlextLdifMinimalDifferencesMetadata",
    "TestsFlextLdifOidIntegration",
    "TestsFlextLdifOudIntegration",
    "TestsFlextLdifOudToOidMigration",
    "TestsFlextLdifRealLdapConfig",
    "TestsFlextLdifRealLdapExport",
    "TestsFlextLdifRealLdapImport",
    "TestsFlextLdifRealLdapRoundtrip",
    "TestsFlextLdifSystematicFixtureCoverage",
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
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".test_cross_direction_conversion": (
                "TestsFlextLdifCrossDirectionConversion",
            ),
            ".test_cross_server_conversion": ("TestsFlextLdifCrossServerConversion",),
            ".test_dn_case_handling": ("TestsFlextLdifDnCaseHandling",),
            ".test_edge_cases": ("TestsFlextLdifEdgeCases",),
            ".test_error_recovery": ("TestsFlextLdifErrorRecovery",),
            ".test_minimal_differences_metadata": (
                "TestsFlextLdifMinimalDifferencesMetadata",
            ),
            ".test_oid_integration": ("TestsFlextLdifOidIntegration",),
            ".test_oud_integration": ("TestsFlextLdifOudIntegration",),
            ".test_oud_to_oid_migration": ("TestsFlextLdifOudToOidMigration",),
            ".test_real_ldap_config": ("TestsFlextLdifRealLdapConfig",),
            ".test_real_ldap_export": ("TestsFlextLdifRealLdapExport",),
            ".test_real_ldap_import": ("TestsFlextLdifRealLdapImport",),
            ".test_real_ldap_roundtrip": ("TestsFlextLdifRealLdapRoundtrip",),
            ".test_systematic_fixture_coverage": (
                "TestsFlextLdifSystematicFixtureCoverage",
            ),
            "flext_tests": (
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
            ),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
