# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests.integration package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from types import MappingProxyType

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_tests import c, d, e, h, m, p, r, s, t, td, tf, tk, tm, tv, u, x

    from .fixtures import (
        clean_test_ou,
        ldap_connection,
        ldap_container,
        make_test_base_dn,
        make_test_username,
        unique_dn_suffix,
    )
    from .test_acl_metadata_preservation import TestsFlextLdifAclMetadataPreservation
    from .test_api_integration import TestsFlextLdifApiIntegration
    from .test_categorization_real_data import TestsFlextLdifCategorizationRealData
    from .test_config_integration import TestsFlextLdifConfigIntegration
    from .test_cross_direction_conversion import TestsFlextLdifCrossDirectionConversion
    from .test_cross_server_conversion import TestsFlextLdifCrossServerConversion
    from .test_dn_case_handling import TestsFlextLdifDnCaseHandling
    from .test_edge_cases import TestsFlextLdifEdgeCases
    from .test_error_recovery import TestsFlextLdifErrorRecovery
    from .test_ldif_fixtures_integration import TestsFlextLdifLdifFixturesIntegration
    from .test_minimal_differences_metadata import (
        TestsFlextLdifMinimalDifferencesMetadata,
    )
    from .test_oid_integration import TestsFlextLdifOidIntegration
    from .test_oud_integration import TestsFlextLdifOudIntegration
    from .test_oud_to_oid_migration import TestsFlextLdifOudToOidMigration
    from .test_pipeline_integration import (
        GROUP_ENTRY,
        SINGLE_ENTRY,
        THREE_ENTRIES,
        TestsFlextLdifPipelineIntegration,
        WITH_HEADER,
    )
    from .test_real_ldap_config import TestsFlextLdifRealLdapConfig
    from .test_real_ldap_export import TestsFlextLdifRealLdapExport
    from .test_real_ldap_import import TestsFlextLdifRealLdapImport
    from .test_real_ldap_roundtrip import TestsFlextLdifRealLdapRoundtrip
    from .test_rfc_docker_real import TestsFlextLdifRfcDockerReal
    from .test_rfc_docker_real_integration import TestsFlextLdifRfcDockerRealIntegration
    from .test_simple_ldap import TestsFlextLdifSimpleLdap
    from .test_systematic_fixture_coverage import (
        TestsFlextLdifSystematicFixtureCoverage,
    )
    from .test_zero_data_loss_oid_oud import TestsFlextLdifZeroDataLossOidOud
__all__: tuple[str, ...] = (
    "GROUP_ENTRY",
    "SINGLE_ENTRY",
    "THREE_ENTRIES",
    "WITH_HEADER",
    "TestsFlextLdifAclMetadataPreservation",
    "TestsFlextLdifApiIntegration",
    "TestsFlextLdifCategorizationRealData",
    "TestsFlextLdifConfigIntegration",
    "TestsFlextLdifCrossDirectionConversion",
    "TestsFlextLdifCrossServerConversion",
    "TestsFlextLdifDnCaseHandling",
    "TestsFlextLdifEdgeCases",
    "TestsFlextLdifErrorRecovery",
    "TestsFlextLdifLdifFixturesIntegration",
    "TestsFlextLdifMinimalDifferencesMetadata",
    "TestsFlextLdifOidIntegration",
    "TestsFlextLdifOudIntegration",
    "TestsFlextLdifOudToOidMigration",
    "TestsFlextLdifPipelineIntegration",
    "TestsFlextLdifRealLdapConfig",
    "TestsFlextLdifRealLdapExport",
    "TestsFlextLdifRealLdapImport",
    "TestsFlextLdifRealLdapRoundtrip",
    "TestsFlextLdifRfcDockerReal",
    "TestsFlextLdifRfcDockerRealIntegration",
    "TestsFlextLdifSimpleLdap",
    "TestsFlextLdifSystematicFixtureCoverage",
    "TestsFlextLdifZeroDataLossOidOud",
    "c",
    "clean_test_ou",
    "d",
    "e",
    "h",
    "ldap_connection",
    "ldap_container",
    "m",
    "make_test_base_dn",
    "make_test_username",
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
    "unique_dn_suffix",
    "x",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".fixtures": (
                "clean_test_ou",
                "ldap_connection",
                "ldap_container",
                "make_test_base_dn",
                "make_test_username",
                "unique_dn_suffix",
            ),
            ".test_acl_metadata_preservation": (
                "TestsFlextLdifAclMetadataPreservation",
            ),
            ".test_api_integration": ("TestsFlextLdifApiIntegration",),
            ".test_categorization_real_data": ("TestsFlextLdifCategorizationRealData",),
            ".test_config_integration": ("TestsFlextLdifConfigIntegration",),
            ".test_cross_direction_conversion": (
                "TestsFlextLdifCrossDirectionConversion",
            ),
            ".test_cross_server_conversion": ("TestsFlextLdifCrossServerConversion",),
            ".test_dn_case_handling": ("TestsFlextLdifDnCaseHandling",),
            ".test_edge_cases": ("TestsFlextLdifEdgeCases",),
            ".test_error_recovery": ("TestsFlextLdifErrorRecovery",),
            ".test_ldif_fixtures_integration": (
                "TestsFlextLdifLdifFixturesIntegration",
            ),
            ".test_minimal_differences_metadata": (
                "TestsFlextLdifMinimalDifferencesMetadata",
            ),
            ".test_oid_integration": ("TestsFlextLdifOidIntegration",),
            ".test_oud_integration": ("TestsFlextLdifOudIntegration",),
            ".test_oud_to_oid_migration": ("TestsFlextLdifOudToOidMigration",),
            ".test_pipeline_integration": (
                "GROUP_ENTRY",
                "SINGLE_ENTRY",
                "THREE_ENTRIES",
                "TestsFlextLdifPipelineIntegration",
                "WITH_HEADER",
            ),
            ".test_real_ldap_config": ("TestsFlextLdifRealLdapConfig",),
            ".test_real_ldap_export": ("TestsFlextLdifRealLdapExport",),
            ".test_real_ldap_import": ("TestsFlextLdifRealLdapImport",),
            ".test_real_ldap_roundtrip": ("TestsFlextLdifRealLdapRoundtrip",),
            ".test_rfc_docker_real": ("TestsFlextLdifRfcDockerReal",),
            ".test_rfc_docker_real_integration": (
                "TestsFlextLdifRfcDockerRealIntegration",
            ),
            ".test_simple_ldap": ("TestsFlextLdifSimpleLdap",),
            ".test_systematic_fixture_coverage": (
                "TestsFlextLdifSystematicFixtureCoverage",
            ),
            ".test_zero_data_loss_oid_oud": ("TestsFlextLdifZeroDataLossOidOud",),
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
