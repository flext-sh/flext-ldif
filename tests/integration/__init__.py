# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if _t.TYPE_CHECKING:
    from flext_ldif.test_acl_metadata_preservation import (
        TestAclRoundTripPreservation,
        TestOidAclMetadataPreservation,
        TestOudAciMetadataPreservation,
    )
    from flext_ldif.test_api_integration import TestFlextLdifAPIIntegration
    from flext_ldif.test_categorization_real_data import TestCategorizationRealData
    from flext_ldif.test_config_integration import TestFlextLdifSettingsIntegration
    from flext_ldif.test_cross_direction_conversion import (
        TestsTestFlextLdifCrossDirectionConversion,
    )
    from flext_ldif.test_cross_quirk_conversion import (
        TestOidToOudAclConversion,
        TestOidToOudIntegrationConversion,
        TestOidToOudSchemaConversion,
        TestQuirksConversionMatrixFacade,
    )
    from flext_ldif.test_dn_case_handling import (
        TestDnCaseNormalizationScenarios,
        TestDnCaseRegistry,
    )
    from flext_ldif.test_edge_cases import (
        TestBoundaryValues,
        TestEmptyAndMinimalCases,
        TestLargeAndComplexCases,
        TestRoundtripEdgeCases,
        TestUnicodeBoundaries,
    )
    from flext_ldif.test_error_recovery import (
        TestEncodingErrors,
        TestIncompleteEntries,
        TestInvalidSchemaDefinitions,
        TestMalformedLdifHandling,
    )
    from flext_ldif.test_ldif_fixtures_integration import TestLdifFixturesIntegration
    from flext_ldif.test_minimal_differences_metadata import (
        TestMinimalDifferencesOidOud,
    )
    from flext_ldif.test_oid_integration import (
        TestOidEntryIntegration,
        TestOidRoundTripIntegration,
        TestOidSchemaIntegration,
    )
    from flext_ldif.test_oud_integration import (
        TestOudAclIntegration,
        TestOudEntryIntegration,
        TestOudMetadataPreservation,
        TestOudRoundTripIntegration,
        TestOudSchemaIntegration,
    )
    from flext_ldif.test_oud_to_oid_migration import (
        TestOudToOidAclMigration,
        TestOudToOidEntryMigration,
        TestOudToOidFullMigration,
        TestOudToOidSchemaMigration,
    )
    from flext_ldif.test_pipeline_integration import TestFlextLdifFacadeWorkflows
    from flext_ldif.test_quirks_transformations import (
        TestOidQuirksTransformations,
        TestOudQuirksTransformations,
        TestQuirksPropertyValidation,
        fixtures_dir,
        migration_inputs,
    )
    from flext_ldif.test_real_ldap_config import (
        TestRealLdapConfigurationFromEnv,
        TestRealLdapRailwayComposition,
    )
    from flext_ldif.test_real_ldap_crud import (
        TestRealLdapBatchOperations,
        TestRealLdapCRUD,
    )
    from flext_ldif.test_real_ldap_export import TestRealLdapExport
    from flext_ldif.test_real_ldap_import import TestRealLdapImport
    from flext_ldif.test_real_ldap_roundtrip import TestRealLdapRoundtrip
    from flext_ldif.test_rfc_docker_real import (
        TestRfcDockerRealData,
        TestRfcIntegrationRealWorld,
    )
    from flext_ldif.test_rfc_docker_real_integration import (
        TestRfcExceptionHandlingRealScenarios,
        TestRfcParserRealFixtures,
        TestRfcSchemaParserRealFixtures,
        TestRfcWriterRealFixtures,
    )
    from flext_ldif.test_simple_ldap import (
        test_create_and_export_entry,
        test_ldap_connection,
        test_simple_ldap_search,
    )
    from flext_ldif.test_systematic_fixture_coverage import (
        TestSystematicFixtureCoverage,
    )
    from flext_ldif.test_zero_data_loss_oid_oud import TestZeroDataLossOidOud
    from flext_ldif.test_zero_data_loss_schema import (
        TestSchemaDeviationsAttributeKeyCasing,
        TestSchemaDeviationsComplete,
        TestSchemaDeviationsMissingSpaces,
        TestSchemaDeviationsNameAliases,
        TestSchemaDeviationsObsolete,
        TestSchemaDeviationsOriginalString,
        TestSchemaDeviationsRoundTrip,
        TestSchemaDeviationsSpacing,
        TestSchemaDeviationsSyntaxQuotes,
        TestSchemaDeviationsUtilities,
        TestSchemaDeviationsXOrigin,
    )
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
            "fixtures_dir",
            "migration_inputs",
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
        ".test_simple_ldap": (
            "test_create_and_export_entry",
            "test_ldap_connection",
            "test_simple_ldap_search",
        ),
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


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)

__all__ = [
    "TestAclRoundTripPreservation",
    "TestBoundaryValues",
    "TestCategorizationRealData",
    "TestDnCaseNormalizationScenarios",
    "TestDnCaseRegistry",
    "TestEmptyAndMinimalCases",
    "TestEncodingErrors",
    "TestFlextLdifAPIIntegration",
    "TestFlextLdifFacadeWorkflows",
    "TestFlextLdifSettingsIntegration",
    "TestIncompleteEntries",
    "TestInvalidSchemaDefinitions",
    "TestLargeAndComplexCases",
    "TestLdifFixturesIntegration",
    "TestMalformedLdifHandling",
    "TestMinimalDifferencesOidOud",
    "TestOidAclMetadataPreservation",
    "TestOidEntryIntegration",
    "TestOidQuirksTransformations",
    "TestOidRoundTripIntegration",
    "TestOidSchemaIntegration",
    "TestOidToOudAclConversion",
    "TestOidToOudIntegrationConversion",
    "TestOidToOudSchemaConversion",
    "TestOudAciMetadataPreservation",
    "TestOudAclIntegration",
    "TestOudEntryIntegration",
    "TestOudMetadataPreservation",
    "TestOudQuirksTransformations",
    "TestOudRoundTripIntegration",
    "TestOudSchemaIntegration",
    "TestOudToOidAclMigration",
    "TestOudToOidEntryMigration",
    "TestOudToOidFullMigration",
    "TestOudToOidSchemaMigration",
    "TestQuirksConversionMatrixFacade",
    "TestQuirksPropertyValidation",
    "TestRealLdapBatchOperations",
    "TestRealLdapCRUD",
    "TestRealLdapConfigurationFromEnv",
    "TestRealLdapExport",
    "TestRealLdapImport",
    "TestRealLdapRailwayComposition",
    "TestRealLdapRoundtrip",
    "TestRfcDockerRealData",
    "TestRfcExceptionHandlingRealScenarios",
    "TestRfcIntegrationRealWorld",
    "TestRfcParserRealFixtures",
    "TestRfcSchemaParserRealFixtures",
    "TestRfcWriterRealFixtures",
    "TestRoundtripEdgeCases",
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
    "TestSystematicFixtureCoverage",
    "TestUnicodeBoundaries",
    "TestZeroDataLossOidOud",
    "TestsTestFlextLdifCrossDirectionConversion",
    "fixtures_dir",
    "migration_inputs",
    "test_create_and_export_entry",
    "test_ldap_connection",
    "test_simple_ldap_search",
]
