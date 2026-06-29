# AUTO-GENERATED FILE — Regenerate with: make gen
"""Integration package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".fixtures": ("fixtures",),
        ".test_acl_metadata_preservation": ("TestsFlextLdifAclMetadataPreservation",),
        ".test_api_integration": ("TestsFlextLdifApiIntegration",),
        ".test_categorization_real_data": ("TestsFlextLdifCategorizationRealData",),
        ".test_config_integration": ("TestsFlextLdifConfigIntegration",),
        ".test_cross_direction_conversion": (
            "TestsTestFlextLdifCrossDirectionConversion",
        ),
        ".test_cross_server_conversion": ("TestsFlextLdifCrossServerConversion",),
        ".test_dn_case_handling": ("TestsFlextLdifDnCaseHandling",),
        ".test_edge_cases": ("TestsFlextLdifEdgeCasesInt",),
        ".test_error_recovery": ("TestsFlextLdifErrorRecovery",),
        ".test_ldif_fixtures_integration": ("TestsFlextLdifLdifFixturesIntegration",),
        ".test_minimal_differences_metadata": (
            "TestsFlextLdifMinimalDifferencesMetadata",
        ),
        ".test_oid_integration": ("TestsFlextLdifOidIntegration",),
        ".test_oud_integration": ("TestsFlextLdifOudIntegration",),
        ".test_oud_to_oid_migration": ("TestsFlextLdifOudToOidMigration",),
        ".test_pipeline_integration": ("TestsFlextLdifPipelineIntegration",),
        ".test_real_ldap_config": ("TestsFlextLdifRealLdapConfig",),
        ".test_real_ldap_crud": ("test_real_ldap_crud",),
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
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
