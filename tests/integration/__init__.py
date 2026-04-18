# AUTO-GENERATED FILE — Regenerate with: make gen
"""Integration package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".test_acl_metadata_preservation": (
            "TestAclRoundTripPreservation",
            "TestOidAclMetadataPreservation",
            "TestOudAciMetadataPreservation",
        ),
        ".test_api_integration": ("TestFlextLdifAPIIntegration",),
        ".test_categorization_real_data": ("TestCategorizationRealData",),
        ".test_config_integration": ("TestFlextLdifSettingsIntegration",),
        ".test_cross_direction_conversion": (
            "TestsTestFlextLdifCrossDirectionConversion",
        ),
        ".test_cross_quirk_conversion": (
            "TestOidToOudAclConversion",
            "TestOidToOudIntegrationConversion",
            "TestOidToOudSchemaConversion",
            "TestQuirksConversionMatrixFacade",
        ),
        ".test_dn_case_handling": (
            "TestDnCaseNormalizationScenarios",
            "TestDnCaseRegistry",
        ),
        ".test_edge_cases": (
            "TestBoundaryValues",
            "TestEmptyAndMinimalCases",
            "TestLargeAndComplexCases",
            "TestRoundtripEdgeCases",
            "TestUnicodeBoundaries",
        ),
        ".test_error_recovery": (
            "TestEncodingErrors",
            "TestIncompleteEntries",
            "TestInvalidSchemaDefinitions",
            "TestMalformedLdifHandling",
        ),
        ".test_ldif_fixtures_integration": ("TestLdifFixturesIntegration",),
        ".test_minimal_differences_metadata": ("TestMinimalDifferencesOidOud",),
        ".test_oid_integration": (
            "TestOidEntryIntegration",
            "TestOidRoundTripIntegration",
            "TestOidSchemaIntegration",
        ),
        ".test_oud_integration": (
            "TestOudAclIntegration",
            "TestOudEntryIntegration",
            "TestOudMetadataPreservation",
            "TestOudRoundTripIntegration",
            "TestOudSchemaIntegration",
        ),
        ".test_oud_to_oid_migration": (
            "TestOudToOidAclMigration",
            "TestOudToOidEntryMigration",
            "TestOudToOidFullMigration",
            "TestOudToOidSchemaMigration",
        ),
        ".test_pipeline_integration": ("TestFlextLdifFacadeWorkflows",),
        ".test_quirks_transformations": (
            "TestOidQuirksTransformations",
            "TestOudQuirksTransformations",
            "TestQuirksPropertyValidation",
        ),
        ".test_real_ldap_config": (
            "TestRealLdapConfigurationFromEnv",
            "TestRealLdapRailwayComposition",
        ),
        ".test_real_ldap_crud": (
            "TestRealLdapBatchOperations",
            "TestRealLdapCRUD",
        ),
        ".test_real_ldap_export": ("TestRealLdapExport",),
        ".test_real_ldap_import": ("TestRealLdapImport",),
        ".test_real_ldap_roundtrip": ("TestRealLdapRoundtrip",),
        ".test_rfc_docker_real": (
            "TestRfcDockerRealData",
            "TestRfcIntegrationRealWorld",
        ),
        ".test_rfc_docker_real_integration": (
            "TestRfcExceptionHandlingRealScenarios",
            "TestRfcParserRealFixtures",
            "TestRfcSchemaParserRealFixtures",
            "TestRfcWriterRealFixtures",
        ),
        ".test_simple_ldap": ("test_simple_ldap",),
        ".test_systematic_fixture_coverage": ("TestSystematicFixtureCoverage",),
        ".test_zero_data_loss_oid_oud": ("TestZeroDataLossOidOud",),
        ".test_zero_data_loss_schema": (
            "TestSchemaDeviationsAttributeKeyCasing",
            "TestSchemaDeviationsComplete",
            "TestSchemaDeviationsMissingSpaces",
            "TestSchemaDeviationsNameAliases",
            "TestSchemaDeviationsObsolete",
            "TestSchemaDeviationsOriginalString",
            "TestSchemaDeviationsRoundTrip",
            "TestSchemaDeviationsSpacing",
            "TestSchemaDeviationsSyntaxQuotes",
            "TestSchemaDeviationsUtilities",
            "TestSchemaDeviationsXOrigin",
        ),
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
