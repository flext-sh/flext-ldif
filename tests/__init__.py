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
    from tests.integration.test_acl_metadata_preservation import (
        TestAclRoundTripPreservation,
        TestOidAclMetadataPreservation,
        TestOudAciMetadataPreservation,
    )
    from tests.integration.test_api_integration import TestFlextLdifAPIIntegration
    from tests.integration.test_categorization_real_data import (
        TestCategorizationRealData,
    )
    from tests.integration.test_config_integration import (
        TestFlextLdifSettingsIntegration,
    )
    from tests.integration.test_cross_direction_conversion import (
        TestsTestFlextLdifCrossDirectionConversion,
    )
    from tests.integration.test_cross_quirk_conversion import (
        TestOidToOudAclConversion,
        TestOidToOudIntegrationConversion,
        TestOidToOudSchemaConversion,
        TestQuirksConversionMatrixFacade,
    )
    from tests.integration.test_dn_case_handling import (
        TestDnCaseNormalizationScenarios,
        TestDnCaseRegistry,
    )
    from tests.integration.test_edge_cases import (
        TestBoundaryValues,
        TestEmptyAndMinimalCases,
        TestLargeAndComplexCases,
        TestRoundtripEdgeCases,
        TestUnicodeBoundaries,
    )
    from tests.integration.test_error_recovery import (
        TestEncodingErrors,
        TestIncompleteEntries,
        TestInvalidSchemaDefinitions,
        TestMalformedLdifHandling,
    )
    from tests.integration.test_ldif_fixtures_integration import (
        TestLdifFixturesIntegration,
    )
    from tests.integration.test_minimal_differences_metadata import (
        TestMinimalDifferencesOidOud,
    )
    from tests.integration.test_oid_integration import (
        TestOidEntryIntegration,
        TestOidRoundTripIntegration,
        TestOidSchemaIntegration,
    )
    from tests.integration.test_oud_integration import (
        TestOudAclIntegration,
        TestOudEntryIntegration,
        TestOudMetadataPreservation,
        TestOudRoundTripIntegration,
        TestOudSchemaIntegration,
    )
    from tests.integration.test_oud_to_oid_migration import (
        TestOudToOidAclMigration,
        TestOudToOidEntryMigration,
        TestOudToOidFullMigration,
        TestOudToOidSchemaMigration,
    )
    from tests.integration.test_pipeline_integration import TestFlextLdifFacadeWorkflows
    from tests.integration.test_quirks_transformations import (
        TestOidQuirksTransformations,
        TestOudQuirksTransformations,
        TestQuirksPropertyValidation,
    )
    from tests.integration.test_real_ldap_config import (
        TestRealLdapConfigurationFromEnv,
        TestRealLdapRailwayComposition,
    )
    from tests.integration.test_real_ldap_crud import (
        TestRealLdapBatchOperations,
        TestRealLdapCRUD,
    )
    from tests.integration.test_real_ldap_export import TestRealLdapExport
    from tests.integration.test_real_ldap_import import TestRealLdapImport
    from tests.integration.test_real_ldap_roundtrip import TestRealLdapRoundtrip
    from tests.integration.test_rfc_docker_real import (
        TestRfcDockerRealData,
        TestRfcIntegrationRealWorld,
    )
    from tests.integration.test_rfc_docker_real_integration import (
        TestRfcExceptionHandlingRealScenarios,
        TestRfcParserRealFixtures,
        TestRfcSchemaParserRealFixtures,
        TestRfcWriterRealFixtures,
    )
    from tests.integration.test_systematic_fixture_coverage import (
        TestSystematicFixtureCoverage,
    )
    from tests.integration.test_zero_data_loss_oid_oud import TestZeroDataLossOidOud
    from tests.integration.test_zero_data_loss_schema import (
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
    from tests.models import TestsFlextLdifModels, m
    from tests.protocols import TestsFlextLdifProtocols, p
    from tests.typings import TestsFlextLdifTypes, t
    from tests.unit.servers.test_apache_quirks import TestsTestFlextLdifApacheQuirks
    from tests.unit.servers.test_ds389_quirks import TestsTestFlextLdifDs389Quirks
    from tests.unit.servers.test_edge_cases import TestsFlextLdifEdgeCases
    from tests.unit.servers.test_novell_quirks import (
        TestNovellAcls,
        TestNovellEntryDetection,
        TestNovellSchemaAttributeDetection,
        TestNovellSchemaAttributeParsing,
        TestNovellSchemaObjectClassDetection,
        TestNovellSchemaObjectClassParsing,
        TestsFlextLdifNovellInitialization,
    )
    from tests.unit.servers.test_oid_quirks import TestsTestFlextLdifOidQuirks
    from tests.unit.servers.test_relaxed_quirks import TestsTestFlextLdifRelaxedQuirks
    from tests.unit.servers.test_schema_transformer import (
        TestSchemaTransformerNormalizeMatchingRule,
        TestSchemaTransformerNormalizeSyntaxOid,
        TestsFlextLdifSchemaTransformerNormalizeAttributeName,
    )
    from tests.unit.services.test_api_server_registry import (
        TestsTestFlextLdifApiServerRegistry,
    )
    from tests.unit.services.test_migration_pipeline import (
        TestsTestFlextLdifMigrationPipeline,
    )
    from tests.unit.services.test_quirks_standardization import (
        TestAliasDiscovery,
        TestQuirksAutoInterchange,
        TestQuirksWithRealLdifFixtures,
        TestsFlextLdifServersStandardizedConstants,
    )
    from tests.unit.test_acl_registry import TestsTestFlextLdifAclAttributeRegistry
    from tests.unit.test_migration_pipeline import TestsFlextLdifMigrationPipeline
    from tests.unit.test_migration_pipeline_quirks import (
        TestsFlextLdifMigrationPipelineQuirks,
    )
    from tests.unit.test_oid_utilities import TestFlextLdifUtilitiesOID
    from tests.unit.test_parser_utilities import TestFlextLdifUtilitiesParser
    from tests.unit.test_protocols import TestsTestFlextLdifProtocols
    from tests.unit.test_server_utilities import TestFlextLdifUtilitiesServer
    from tests.unit.test_typings import (
        TestFlextLdifTypesStructure,
        TestIntegrationWithLdifFixtures,
        TestModelsNamespace,
        TestPhase1StandardizationResults,
        TestRemovalOfOverEngineering,
        TestsFlextLdifCommonDictionaryTypes,
    )
    from tests.unit.test_version import TestsFlextLdifVersion
    from tests.unit.utilities.test_utilities_comprehensive import (
        TestFlextLdifUtilitiesComprehensive,
    )
    from tests.unit.utilities.test_utilities_core import (
        TestAttributeFixer,
        TestDnObjectClassMethods,
        TestLdifParser,
        TestObjectClassUtilities,
        TestServerTypes,
        TestsFlextLdifDnOperationsPure,
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
            ".integration.test_acl_metadata_preservation": (
                "TestAclRoundTripPreservation",
                "TestOidAclMetadataPreservation",
                "TestOudAciMetadataPreservation",
            ),
            ".integration.test_api_integration": ("TestFlextLdifAPIIntegration",),
            ".integration.test_categorization_real_data": (
                "TestCategorizationRealData",
            ),
            ".integration.test_config_integration": (
                "TestFlextLdifSettingsIntegration",
            ),
            ".integration.test_cross_direction_conversion": (
                "TestsTestFlextLdifCrossDirectionConversion",
            ),
            ".integration.test_cross_quirk_conversion": (
                "TestOidToOudAclConversion",
                "TestOidToOudIntegrationConversion",
                "TestOidToOudSchemaConversion",
                "TestQuirksConversionMatrixFacade",
            ),
            ".integration.test_dn_case_handling": (
                "TestDnCaseNormalizationScenarios",
                "TestDnCaseRegistry",
            ),
            ".integration.test_edge_cases": (
                "TestBoundaryValues",
                "TestEmptyAndMinimalCases",
                "TestLargeAndComplexCases",
                "TestRoundtripEdgeCases",
                "TestUnicodeBoundaries",
            ),
            ".integration.test_error_recovery": (
                "TestEncodingErrors",
                "TestIncompleteEntries",
                "TestInvalidSchemaDefinitions",
                "TestMalformedLdifHandling",
            ),
            ".integration.test_ldif_fixtures_integration": (
                "TestLdifFixturesIntegration",
            ),
            ".integration.test_minimal_differences_metadata": (
                "TestMinimalDifferencesOidOud",
            ),
            ".integration.test_oid_integration": (
                "TestOidEntryIntegration",
                "TestOidRoundTripIntegration",
                "TestOidSchemaIntegration",
            ),
            ".integration.test_oud_integration": (
                "TestOudAclIntegration",
                "TestOudEntryIntegration",
                "TestOudMetadataPreservation",
                "TestOudRoundTripIntegration",
                "TestOudSchemaIntegration",
            ),
            ".integration.test_oud_to_oid_migration": (
                "TestOudToOidAclMigration",
                "TestOudToOidEntryMigration",
                "TestOudToOidFullMigration",
                "TestOudToOidSchemaMigration",
            ),
            ".integration.test_pipeline_integration": ("TestFlextLdifFacadeWorkflows",),
            ".integration.test_quirks_transformations": (
                "TestOidQuirksTransformations",
                "TestOudQuirksTransformations",
                "TestQuirksPropertyValidation",
            ),
            ".integration.test_real_ldap_config": (
                "TestRealLdapConfigurationFromEnv",
                "TestRealLdapRailwayComposition",
            ),
            ".integration.test_real_ldap_crud": (
                "TestRealLdapBatchOperations",
                "TestRealLdapCRUD",
            ),
            ".integration.test_real_ldap_export": ("TestRealLdapExport",),
            ".integration.test_real_ldap_import": ("TestRealLdapImport",),
            ".integration.test_real_ldap_roundtrip": ("TestRealLdapRoundtrip",),
            ".integration.test_rfc_docker_real": (
                "TestRfcDockerRealData",
                "TestRfcIntegrationRealWorld",
            ),
            ".integration.test_rfc_docker_real_integration": (
                "TestRfcExceptionHandlingRealScenarios",
                "TestRfcParserRealFixtures",
                "TestRfcSchemaParserRealFixtures",
                "TestRfcWriterRealFixtures",
            ),
            ".integration.test_systematic_fixture_coverage": (
                "TestSystematicFixtureCoverage",
            ),
            ".integration.test_zero_data_loss_oid_oud": ("TestZeroDataLossOidOud",),
            ".integration.test_zero_data_loss_schema": (
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
            ".unit.servers.test_apache_quirks": ("TestsTestFlextLdifApacheQuirks",),
            ".unit.servers.test_ds389_quirks": ("TestsTestFlextLdifDs389Quirks",),
            ".unit.servers.test_edge_cases": ("TestsFlextLdifEdgeCases",),
            ".unit.servers.test_novell_quirks": (
                "TestNovellAcls",
                "TestNovellEntryDetection",
                "TestNovellSchemaAttributeDetection",
                "TestNovellSchemaAttributeParsing",
                "TestNovellSchemaObjectClassDetection",
                "TestNovellSchemaObjectClassParsing",
                "TestsFlextLdifNovellInitialization",
            ),
            ".unit.servers.test_oid_quirks": ("TestsTestFlextLdifOidQuirks",),
            ".unit.servers.test_relaxed_quirks": ("TestsTestFlextLdifRelaxedQuirks",),
            ".unit.servers.test_schema_transformer": (
                "TestSchemaTransformerNormalizeMatchingRule",
                "TestSchemaTransformerNormalizeSyntaxOid",
                "TestsFlextLdifSchemaTransformerNormalizeAttributeName",
            ),
            ".unit.services.test_api_server_registry": (
                "TestsTestFlextLdifApiServerRegistry",
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
            ".unit.test_acl_registry": ("TestsTestFlextLdifAclAttributeRegistry",),
            ".unit.test_migration_pipeline": ("TestsFlextLdifMigrationPipeline",),
            ".unit.test_migration_pipeline_quirks": (
                "TestsFlextLdifMigrationPipelineQuirks",
            ),
            ".unit.test_oid_utilities": ("TestFlextLdifUtilitiesOID",),
            ".unit.test_parser_utilities": ("TestFlextLdifUtilitiesParser",),
            ".unit.test_protocols": ("TestsTestFlextLdifProtocols",),
            ".unit.test_server_utilities": ("TestFlextLdifUtilitiesServer",),
            ".unit.test_typings": (
                "TestFlextLdifTypesStructure",
                "TestIntegrationWithLdifFixtures",
                "TestModelsNamespace",
                "TestPhase1StandardizationResults",
                "TestRemovalOfOverEngineering",
                "TestsFlextLdifCommonDictionaryTypes",
            ),
            ".unit.test_version": ("TestsFlextLdifVersion",),
            ".unit.utilities.test_utilities_comprehensive": (
                "TestFlextLdifUtilitiesComprehensive",
            ),
            ".unit.utilities.test_utilities_core": (
                "TestAttributeFixer",
                "TestDnObjectClassMethods",
                "TestLdifParser",
                "TestObjectClassUtilities",
                "TestServerTypes",
                "TestsFlextLdifDnOperationsPure",
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
    "TestAclRoundTripPreservation",
    "TestAliasDiscovery",
    "TestAttributeFixer",
    "TestBoundaryValues",
    "TestCategorizationRealData",
    "TestDnCaseNormalizationScenarios",
    "TestDnCaseRegistry",
    "TestDnObjectClassMethods",
    "TestEmptyAndMinimalCases",
    "TestEncodingErrors",
    "TestFlextLdifAPIIntegration",
    "TestFlextLdifFacadeWorkflows",
    "TestFlextLdifSettingsIntegration",
    "TestFlextLdifTypesStructure",
    "TestFlextLdifUtilitiesComprehensive",
    "TestFlextLdifUtilitiesOID",
    "TestFlextLdifUtilitiesParser",
    "TestFlextLdifUtilitiesServer",
    "TestIncompleteEntries",
    "TestIntegrationWithLdifFixtures",
    "TestInvalidSchemaDefinitions",
    "TestLargeAndComplexCases",
    "TestLdifFixturesIntegration",
    "TestLdifParser",
    "TestMalformedLdifHandling",
    "TestMinimalDifferencesOidOud",
    "TestModelsNamespace",
    "TestNovellAcls",
    "TestNovellEntryDetection",
    "TestNovellSchemaAttributeDetection",
    "TestNovellSchemaAttributeParsing",
    "TestNovellSchemaObjectClassDetection",
    "TestNovellSchemaObjectClassParsing",
    "TestObjectClassUtilities",
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
    "TestPhase1StandardizationResults",
    "TestQuirksAutoInterchange",
    "TestQuirksConversionMatrixFacade",
    "TestQuirksPropertyValidation",
    "TestQuirksWithRealLdifFixtures",
    "TestRealLdapBatchOperations",
    "TestRealLdapCRUD",
    "TestRealLdapConfigurationFromEnv",
    "TestRealLdapExport",
    "TestRealLdapImport",
    "TestRealLdapRailwayComposition",
    "TestRealLdapRoundtrip",
    "TestRemovalOfOverEngineering",
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
    "TestSchemaTransformerNormalizeMatchingRule",
    "TestSchemaTransformerNormalizeSyntaxOid",
    "TestServerTypes",
    "TestSystematicFixtureCoverage",
    "TestUnicodeBoundaries",
    "TestZeroDataLossOidOud",
    "TestsFlextLdifCommonDictionaryTypes",
    "TestsFlextLdifConstants",
    "TestsFlextLdifDnOperationsPure",
    "TestsFlextLdifEdgeCases",
    "TestsFlextLdifMigrationPipeline",
    "TestsFlextLdifMigrationPipelineQuirks",
    "TestsFlextLdifModels",
    "TestsFlextLdifNovellInitialization",
    "TestsFlextLdifProtocols",
    "TestsFlextLdifSchemaTransformerNormalizeAttributeName",
    "TestsFlextLdifServersStandardizedConstants",
    "TestsFlextLdifTypes",
    "TestsFlextLdifUtilities",
    "TestsFlextLdifVersion",
    "TestsTestFlextLdifAclAttributeRegistry",
    "TestsTestFlextLdifApacheQuirks",
    "TestsTestFlextLdifApiServerRegistry",
    "TestsTestFlextLdifCrossDirectionConversion",
    "TestsTestFlextLdifDs389Quirks",
    "TestsTestFlextLdifMigrationPipeline",
    "TestsTestFlextLdifOidQuirks",
    "TestsTestFlextLdifProtocols",
    "TestsTestFlextLdifRelaxedQuirks",
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
