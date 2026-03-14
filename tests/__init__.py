# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Tests package for flext-ldif.

Unified test infrastructure providing:
- t: TestsFlextLdifTypes (type definitions and TypeVars)
- c: TestsFlextLdifConstants (test constants organized by domain)
- p: TestsFlextLdifProtocols (test protocol definitions)
- m: TestsFlextLdifModels (test model definitions)
- u: TestsFlextLdifUtilities (test utility functions)
- s: FlextLdifTestsServiceBase (base class for test services with factories)
- tv: FlextTestsValidator (validation helpers)
- tf: FlextTestsFactories (factory helpers)

All test files should import these unified infrastructure components:
    from tests import t, c, p, m, u, s, tv, tf

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from tests.base import FlextLdifTestsServiceBase, s
    from tests.conftest import (
        FIXTURES_DIR,
        OID_FIXTURES_DIR,
        FlextLdifFixtures,
        flext_ldif,
        ldif_parser,
        ldif_writer,
        pytest_configure,
        real_ldif_group_entry,
        real_ldif_multiple_entries,
        real_ldif_user_entry,
        sample_ldif_entries,
        temp_file,
    )
    from tests.conftest_shared import (
        large_test_dataset,
        parametrized_real_data,
        real_entry,
        real_ldif_content,
    )
    from tests.constants import (
        RfcTestHelpers,
        TestDeduplicationHelpers,
        TestsFlextLdifConstants,
        c,
    )
    from tests.integration.conftest import (
        all_acl_fixtures,
        all_entries_fixtures,
        all_integration_fixtures,
        all_schema_fixtures,
        api,
        clean_test_ou,
        conversion_matrix,
        ldap_connection,
        ldap_container,
        ldap_container_shared,
        make_test_base_dn,
        make_test_username,
        oid_acl_fixture,
        oid_acl_quirk,
        oid_entries,
        oid_entries_fixture,
        oid_integration_fixture,
        oid_quirk,
        oid_schema_entries,
        oid_schema_fixture,
        oid_schema_quirk,
        openldap_acl_fixture,
        openldap_entries,
        openldap_entries_fixture,
        openldap_integration_fixture,
        openldap_schema_entries,
        openldap_schema_fixture,
        oud_acl_fixture,
        oud_acl_quirk,
        oud_entries,
        oud_entries_fixture,
        oud_integration_fixture,
        oud_quirk,
        oud_schema_entries,
        oud_schema_fixture,
        oud_schema_quirk,
        parser,
        rfc_schema_entries,
        rfc_schema_fixture,
        server,
        tmp_ldif_path,
        unique_dn_suffix,
        writer,
    )
    from tests.integration.test_acl_metadata_preservation import (
        TestAclRoundTripPreservation,
        TestOidAclMetadataPreservation,
        TestOudAciMetadataPreservation,
    )
    from tests.integration.test_api_integration import (
        APIScenarios,
        TestData,
        TestFlextLdifAPIIntegration,
    )
    from tests.integration.test_categorization_real_data import (
        TestCategorizationRealData,
    )
    from tests.integration.test_config_integration import (
        ConfigTestData,
        TestFlextLdifSettingsIntegration,
        logger,
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
        fixtures_dir,
        migration_inputs,
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
    from tests.integration.test_simple_ldap import (
        test_create_and_export_entry,
        test_ldap_connection,
        test_simple_ldap_search,
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
    from tests.support.conftest_factory import FlextLdifTestConftest, FlextTestsDocker
    from tests.support.ldif_data import LdifSample, LdifTestData
    from tests.support.test_files import FileManager
    from tests.support.validators import MockMatchers, MockResultHelpers, TestValidators
    from tests.test_factory import FlextLdifTestFactory
    from tests.test_helpers import (
        TestsFlextLdifFixtures,
        TestsFlextLdifMatchers,
        TestsFlextLdifValidators,
    )
    from tests.typings import GenericFieldsDict, TestsFlextLdifTypes, t
    from tests.unit.__init__.test_version import TestsFlextLdifVersion
    from tests.unit.constants.test_acl_registry import (
        GetAclAttributesServerType,
        IsAclAttributeType,
        TestsTestFlextLdifAclAttributeRegistry,
    )
    from tests.unit.models.test_models import TestFlextLdifModels
    from tests.unit.protocols.test_protocols import TestsTestFlextLdifProtocols
    from tests.unit.services.test_migration_pipeline import (
        TestsTestFlextLdifMigrationPipeline,
    )
    from tests.unit.services.test_quirks_standardization import (
        TestAliasDiscovery,
        TestQuirksAutoInterchange,
        TestQuirksWithRealLdifFixtures,
        TestsFlextLdifQuirksStandardizedConstants,
    )
    from tests.unit.services.test_schema_service import (
        TestSchemaServiceBuilder,
        TestSchemaServiceCanHandleAttribute,
        TestSchemaServiceIntegration,
        TestSchemaServiceParseAttribute,
        TestSchemaServiceParseObjectClass,
        TestSchemaServiceRepr,
        TestSchemaServiceValidateAttribute,
        TestSchemaServiceValidateObjectClass,
        TestSchemaServiceWriteAttribute,
        TestSchemaServiceWriteObjectClass,
        TestsFlextLdifSchemaServiceExecute,
        complex_attribute_definition,
        complex_objectclass_definition,
        schema_service,
        schema_service_oud,
        simple_attribute_definition,
        simple_objectclass_definition,
    )
    from tests.unit.services.test_writer_dn_normalization import (
        TestsFlextLdifsFlextLdifWriterDnNormalization,
    )
    from tests.unit.test_filters import TestAclAttributes
    from tests.unit.test_helpers import TestFlextLdifDeduplicationHelpers
    from tests.unit.test_migration_pipeline import TestsFlextLdifMigrationPipeline
    from tests.unit.test_migration_pipeline_quirks import (
        OidTestConstants,
        TestsFlextLdifMigrationPipelineQuirks,
    )
    from tests.unit.test_typings import (
        TestFlextLdifTypesStructure,
        TestIntegrationWithLdifFixtures,
        TestModelsNamespace,
        TestPhase1StandardizationResults,
        TestRemovalOfOverEngineering,
        TestsFlextLdifCommonDictionaryTypes,
    )
    from tests.unit.utilities.test_utilities import TestsTestFlextLdifServiceAPIs
    from tests.unit.utilities.test_utilities_comprehensive import (
        TestFlextLdifUtilitiesComprehensive,
    )
    from tests.unit.utilities.test_utilities_constants import (
        GetValidValuesType,
        IsValidTestType,
        TestsTestFlextLdifConstants,
        ValidateManyType,
    )
    from tests.unit.utilities.test_utilities_core import (
        TestAclParser,
        TestAttributeFixer,
        TestDnObjectClassMethods,
        TestLdifParser,
        TestObjectClassUtilities,
        TestServerTypes,
        TestsFlextLdifDnOperationsPure,
    )
    from tests.utilities import TestsFlextLdifUtilities, u

# Lazy import mapping: export_name -> (module_path, attr_name)
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "APIScenarios": ("tests.integration.test_api_integration", "APIScenarios"),
    "ConfigTestData": ("tests.integration.test_config_integration", "ConfigTestData"),
    "FIXTURES_DIR": ("tests.conftest", "FIXTURES_DIR"),
    "FileManager": ("tests.support.test_files", "FileManager"),
    "FlextLdifFixtures": ("tests.conftest", "FlextLdifFixtures"),
    "FlextLdifTestConftest": (
        "tests.support.conftest_factory",
        "FlextLdifTestConftest",
    ),
    "FlextLdifTestFactory": ("tests.test_factory", "FlextLdifTestFactory"),
    "FlextLdifTestsServiceBase": ("tests.base", "FlextLdifTestsServiceBase"),
    "FlextTestsDocker": ("tests.support.conftest_factory", "FlextTestsDocker"),
    "GenericFieldsDict": ("tests.typings", "GenericFieldsDict"),
    "GetAclAttributesServerType": (
        "tests.unit.constants.test_acl_registry",
        "GetAclAttributesServerType",
    ),
    "GetValidValuesType": (
        "tests.unit.utilities.test_utilities_constants",
        "GetValidValuesType",
    ),
    "IsAclAttributeType": (
        "tests.unit.constants.test_acl_registry",
        "IsAclAttributeType",
    ),
    "IsValidTestType": (
        "tests.unit.utilities.test_utilities_constants",
        "IsValidTestType",
    ),
    "LdifSample": ("tests.support.ldif_data", "LdifSample"),
    "LdifTestData": ("tests.support.ldif_data", "LdifTestData"),
    "MockMatchers": ("tests.support.validators", "MockMatchers"),
    "MockResultHelpers": ("tests.support.validators", "MockResultHelpers"),
    "OID_FIXTURES_DIR": ("tests.conftest", "OID_FIXTURES_DIR"),
    "OidTestConstants": (
        "tests.unit.test_migration_pipeline_quirks",
        "OidTestConstants",
    ),
    "RfcTestHelpers": ("tests.constants", "RfcTestHelpers"),
    "TestAclAttributes": ("tests.unit.test_filters", "TestAclAttributes"),
    "TestAclParser": ("tests.unit.utilities.test_utilities_core", "TestAclParser"),
    "TestAclRoundTripPreservation": (
        "tests.integration.test_acl_metadata_preservation",
        "TestAclRoundTripPreservation",
    ),
    "TestAliasDiscovery": (
        "tests.unit.services.test_quirks_standardization",
        "TestAliasDiscovery",
    ),
    "TestAttributeFixer": (
        "tests.unit.utilities.test_utilities_core",
        "TestAttributeFixer",
    ),
    "TestBoundaryValues": ("tests.integration.test_edge_cases", "TestBoundaryValues"),
    "TestCategorizationRealData": (
        "tests.integration.test_categorization_real_data",
        "TestCategorizationRealData",
    ),
    "TestData": ("tests.integration.test_api_integration", "TestData"),
    "TestDeduplicationHelpers": ("tests.constants", "TestDeduplicationHelpers"),
    "TestDnCaseNormalizationScenarios": (
        "tests.integration.test_dn_case_handling",
        "TestDnCaseNormalizationScenarios",
    ),
    "TestDnCaseRegistry": (
        "tests.integration.test_dn_case_handling",
        "TestDnCaseRegistry",
    ),
    "TestDnObjectClassMethods": (
        "tests.unit.utilities.test_utilities_core",
        "TestDnObjectClassMethods",
    ),
    "TestEmptyAndMinimalCases": (
        "tests.integration.test_edge_cases",
        "TestEmptyAndMinimalCases",
    ),
    "TestEncodingErrors": (
        "tests.integration.test_error_recovery",
        "TestEncodingErrors",
    ),
    "TestFlextLdifAPIIntegration": (
        "tests.integration.test_api_integration",
        "TestFlextLdifAPIIntegration",
    ),
    "TestFlextLdifDeduplicationHelpers": (
        "tests.unit.test_helpers",
        "TestFlextLdifDeduplicationHelpers",
    ),
    "TestFlextLdifFacadeWorkflows": (
        "tests.integration.test_pipeline_integration",
        "TestFlextLdifFacadeWorkflows",
    ),
    "TestFlextLdifModels": ("tests.unit.models.test_models", "TestFlextLdifModels"),
    "TestFlextLdifSettingsIntegration": (
        "tests.integration.test_config_integration",
        "TestFlextLdifSettingsIntegration",
    ),
    "TestFlextLdifTypesStructure": (
        "tests.unit.test_typings",
        "TestFlextLdifTypesStructure",
    ),
    "TestFlextLdifUtilitiesComprehensive": (
        "tests.unit.utilities.test_utilities_comprehensive",
        "TestFlextLdifUtilitiesComprehensive",
    ),
    "TestIncompleteEntries": (
        "tests.integration.test_error_recovery",
        "TestIncompleteEntries",
    ),
    "TestIntegrationWithLdifFixtures": (
        "tests.unit.test_typings",
        "TestIntegrationWithLdifFixtures",
    ),
    "TestInvalidSchemaDefinitions": (
        "tests.integration.test_error_recovery",
        "TestInvalidSchemaDefinitions",
    ),
    "TestLargeAndComplexCases": (
        "tests.integration.test_edge_cases",
        "TestLargeAndComplexCases",
    ),
    "TestLdifParser": ("tests.unit.utilities.test_utilities_core", "TestLdifParser"),
    "TestMalformedLdifHandling": (
        "tests.integration.test_error_recovery",
        "TestMalformedLdifHandling",
    ),
    "TestMinimalDifferencesOidOud": (
        "tests.integration.test_minimal_differences_metadata",
        "TestMinimalDifferencesOidOud",
    ),
    "TestModelsNamespace": ("tests.unit.test_typings", "TestModelsNamespace"),
    "TestObjectClassUtilities": (
        "tests.unit.utilities.test_utilities_core",
        "TestObjectClassUtilities",
    ),
    "TestOidAclMetadataPreservation": (
        "tests.integration.test_acl_metadata_preservation",
        "TestOidAclMetadataPreservation",
    ),
    "TestOidEntryIntegration": (
        "tests.integration.test_oid_integration",
        "TestOidEntryIntegration",
    ),
    "TestOidQuirksTransformations": (
        "tests.integration.test_quirks_transformations",
        "TestOidQuirksTransformations",
    ),
    "TestOidRoundTripIntegration": (
        "tests.integration.test_oid_integration",
        "TestOidRoundTripIntegration",
    ),
    "TestOidSchemaIntegration": (
        "tests.integration.test_oid_integration",
        "TestOidSchemaIntegration",
    ),
    "TestOidToOudAclConversion": (
        "tests.integration.test_cross_quirk_conversion",
        "TestOidToOudAclConversion",
    ),
    "TestOidToOudIntegrationConversion": (
        "tests.integration.test_cross_quirk_conversion",
        "TestOidToOudIntegrationConversion",
    ),
    "TestOidToOudSchemaConversion": (
        "tests.integration.test_cross_quirk_conversion",
        "TestOidToOudSchemaConversion",
    ),
    "TestOudAciMetadataPreservation": (
        "tests.integration.test_acl_metadata_preservation",
        "TestOudAciMetadataPreservation",
    ),
    "TestOudAclIntegration": (
        "tests.integration.test_oud_integration",
        "TestOudAclIntegration",
    ),
    "TestOudEntryIntegration": (
        "tests.integration.test_oud_integration",
        "TestOudEntryIntegration",
    ),
    "TestOudMetadataPreservation": (
        "tests.integration.test_oud_integration",
        "TestOudMetadataPreservation",
    ),
    "TestOudQuirksTransformations": (
        "tests.integration.test_quirks_transformations",
        "TestOudQuirksTransformations",
    ),
    "TestOudRoundTripIntegration": (
        "tests.integration.test_oud_integration",
        "TestOudRoundTripIntegration",
    ),
    "TestOudSchemaIntegration": (
        "tests.integration.test_oud_integration",
        "TestOudSchemaIntegration",
    ),
    "TestOudToOidAclMigration": (
        "tests.integration.test_oud_to_oid_migration",
        "TestOudToOidAclMigration",
    ),
    "TestOudToOidEntryMigration": (
        "tests.integration.test_oud_to_oid_migration",
        "TestOudToOidEntryMigration",
    ),
    "TestOudToOidFullMigration": (
        "tests.integration.test_oud_to_oid_migration",
        "TestOudToOidFullMigration",
    ),
    "TestOudToOidSchemaMigration": (
        "tests.integration.test_oud_to_oid_migration",
        "TestOudToOidSchemaMigration",
    ),
    "TestPhase1StandardizationResults": (
        "tests.unit.test_typings",
        "TestPhase1StandardizationResults",
    ),
    "TestQuirksAutoInterchange": (
        "tests.unit.services.test_quirks_standardization",
        "TestQuirksAutoInterchange",
    ),
    "TestQuirksConversionMatrixFacade": (
        "tests.integration.test_cross_quirk_conversion",
        "TestQuirksConversionMatrixFacade",
    ),
    "TestQuirksPropertyValidation": (
        "tests.integration.test_quirks_transformations",
        "TestQuirksPropertyValidation",
    ),
    "TestQuirksWithRealLdifFixtures": (
        "tests.unit.services.test_quirks_standardization",
        "TestQuirksWithRealLdifFixtures",
    ),
    "TestRealLdapBatchOperations": (
        "tests.integration.test_real_ldap_crud",
        "TestRealLdapBatchOperations",
    ),
    "TestRealLdapCRUD": ("tests.integration.test_real_ldap_crud", "TestRealLdapCRUD"),
    "TestRealLdapConfigurationFromEnv": (
        "tests.integration.test_real_ldap_config",
        "TestRealLdapConfigurationFromEnv",
    ),
    "TestRealLdapExport": (
        "tests.integration.test_real_ldap_export",
        "TestRealLdapExport",
    ),
    "TestRealLdapImport": (
        "tests.integration.test_real_ldap_import",
        "TestRealLdapImport",
    ),
    "TestRealLdapRailwayComposition": (
        "tests.integration.test_real_ldap_config",
        "TestRealLdapRailwayComposition",
    ),
    "TestRealLdapRoundtrip": (
        "tests.integration.test_real_ldap_roundtrip",
        "TestRealLdapRoundtrip",
    ),
    "TestRemovalOfOverEngineering": (
        "tests.unit.test_typings",
        "TestRemovalOfOverEngineering",
    ),
    "TestRfcDockerRealData": (
        "tests.integration.test_rfc_docker_real",
        "TestRfcDockerRealData",
    ),
    "TestRfcExceptionHandlingRealScenarios": (
        "tests.integration.test_rfc_docker_real_integration",
        "TestRfcExceptionHandlingRealScenarios",
    ),
    "TestRfcIntegrationRealWorld": (
        "tests.integration.test_rfc_docker_real",
        "TestRfcIntegrationRealWorld",
    ),
    "TestRfcParserRealFixtures": (
        "tests.integration.test_rfc_docker_real_integration",
        "TestRfcParserRealFixtures",
    ),
    "TestRfcSchemaParserRealFixtures": (
        "tests.integration.test_rfc_docker_real_integration",
        "TestRfcSchemaParserRealFixtures",
    ),
    "TestRfcWriterRealFixtures": (
        "tests.integration.test_rfc_docker_real_integration",
        "TestRfcWriterRealFixtures",
    ),
    "TestRoundtripEdgeCases": (
        "tests.integration.test_edge_cases",
        "TestRoundtripEdgeCases",
    ),
    "TestSchemaDeviationsAttributeKeyCasing": (
        "tests.integration.test_zero_data_loss_schema",
        "TestSchemaDeviationsAttributeKeyCasing",
    ),
    "TestSchemaDeviationsComplete": (
        "tests.integration.test_zero_data_loss_schema",
        "TestSchemaDeviationsComplete",
    ),
    "TestSchemaDeviationsMissingSpaces": (
        "tests.integration.test_zero_data_loss_schema",
        "TestSchemaDeviationsMissingSpaces",
    ),
    "TestSchemaDeviationsNameAliases": (
        "tests.integration.test_zero_data_loss_schema",
        "TestSchemaDeviationsNameAliases",
    ),
    "TestSchemaDeviationsObsolete": (
        "tests.integration.test_zero_data_loss_schema",
        "TestSchemaDeviationsObsolete",
    ),
    "TestSchemaDeviationsOriginalString": (
        "tests.integration.test_zero_data_loss_schema",
        "TestSchemaDeviationsOriginalString",
    ),
    "TestSchemaDeviationsRoundTrip": (
        "tests.integration.test_zero_data_loss_schema",
        "TestSchemaDeviationsRoundTrip",
    ),
    "TestSchemaDeviationsSpacing": (
        "tests.integration.test_zero_data_loss_schema",
        "TestSchemaDeviationsSpacing",
    ),
    "TestSchemaDeviationsSyntaxQuotes": (
        "tests.integration.test_zero_data_loss_schema",
        "TestSchemaDeviationsSyntaxQuotes",
    ),
    "TestSchemaDeviationsUtilities": (
        "tests.integration.test_zero_data_loss_schema",
        "TestSchemaDeviationsUtilities",
    ),
    "TestSchemaDeviationsXOrigin": (
        "tests.integration.test_zero_data_loss_schema",
        "TestSchemaDeviationsXOrigin",
    ),
    "TestSchemaServiceBuilder": (
        "tests.unit.services.test_schema_service",
        "TestSchemaServiceBuilder",
    ),
    "TestSchemaServiceCanHandleAttribute": (
        "tests.unit.services.test_schema_service",
        "TestSchemaServiceCanHandleAttribute",
    ),
    "TestSchemaServiceIntegration": (
        "tests.unit.services.test_schema_service",
        "TestSchemaServiceIntegration",
    ),
    "TestSchemaServiceParseAttribute": (
        "tests.unit.services.test_schema_service",
        "TestSchemaServiceParseAttribute",
    ),
    "TestSchemaServiceParseObjectClass": (
        "tests.unit.services.test_schema_service",
        "TestSchemaServiceParseObjectClass",
    ),
    "TestSchemaServiceRepr": (
        "tests.unit.services.test_schema_service",
        "TestSchemaServiceRepr",
    ),
    "TestSchemaServiceValidateAttribute": (
        "tests.unit.services.test_schema_service",
        "TestSchemaServiceValidateAttribute",
    ),
    "TestSchemaServiceValidateObjectClass": (
        "tests.unit.services.test_schema_service",
        "TestSchemaServiceValidateObjectClass",
    ),
    "TestSchemaServiceWriteAttribute": (
        "tests.unit.services.test_schema_service",
        "TestSchemaServiceWriteAttribute",
    ),
    "TestSchemaServiceWriteObjectClass": (
        "tests.unit.services.test_schema_service",
        "TestSchemaServiceWriteObjectClass",
    ),
    "TestServerTypes": ("tests.unit.utilities.test_utilities_core", "TestServerTypes"),
    "TestSystematicFixtureCoverage": (
        "tests.integration.test_systematic_fixture_coverage",
        "TestSystematicFixtureCoverage",
    ),
    "TestUnicodeBoundaries": (
        "tests.integration.test_edge_cases",
        "TestUnicodeBoundaries",
    ),
    "TestValidators": ("tests.support.validators", "TestValidators"),
    "TestZeroDataLossOidOud": (
        "tests.integration.test_zero_data_loss_oid_oud",
        "TestZeroDataLossOidOud",
    ),
    "TestsFlextLdifCommonDictionaryTypes": (
        "tests.unit.test_typings",
        "TestsFlextLdifCommonDictionaryTypes",
    ),
    "TestsFlextLdifConstants": ("tests.constants", "TestsFlextLdifConstants"),
    "TestsFlextLdifDnOperationsPure": (
        "tests.unit.utilities.test_utilities_core",
        "TestsFlextLdifDnOperationsPure",
    ),
    "TestsFlextLdifFixtures": ("tests.test_helpers", "TestsFlextLdifFixtures"),
    "TestsFlextLdifMatchers": ("tests.test_helpers", "TestsFlextLdifMatchers"),
    "TestsFlextLdifMigrationPipeline": (
        "tests.unit.test_migration_pipeline",
        "TestsFlextLdifMigrationPipeline",
    ),
    "TestsFlextLdifMigrationPipelineQuirks": (
        "tests.unit.test_migration_pipeline_quirks",
        "TestsFlextLdifMigrationPipelineQuirks",
    ),
    "TestsFlextLdifModels": ("tests.models", "TestsFlextLdifModels"),
    "TestsFlextLdifProtocols": ("tests.protocols", "TestsFlextLdifProtocols"),
    "TestsFlextLdifQuirksStandardizedConstants": (
        "tests.unit.services.test_quirks_standardization",
        "TestsFlextLdifQuirksStandardizedConstants",
    ),
    "TestsFlextLdifSchemaServiceExecute": (
        "tests.unit.services.test_schema_service",
        "TestsFlextLdifSchemaServiceExecute",
    ),
    "TestsFlextLdifTypes": ("tests.typings", "TestsFlextLdifTypes"),
    "TestsFlextLdifUtilities": ("tests.utilities", "TestsFlextLdifUtilities"),
    "TestsFlextLdifValidators": ("tests.test_helpers", "TestsFlextLdifValidators"),
    "TestsFlextLdifVersion": (
        "tests.unit.__init__.test_version",
        "TestsFlextLdifVersion",
    ),
    "TestsFlextLdifsFlextLdifWriterDnNormalization": (
        "tests.unit.services.test_writer_dn_normalization",
        "TestsFlextLdifsFlextLdifWriterDnNormalization",
    ),
    "TestsTestFlextLdifAclAttributeRegistry": (
        "tests.unit.constants.test_acl_registry",
        "TestsTestFlextLdifAclAttributeRegistry",
    ),
    "TestsTestFlextLdifConstants": (
        "tests.unit.utilities.test_utilities_constants",
        "TestsTestFlextLdifConstants",
    ),
    "TestsTestFlextLdifMigrationPipeline": (
        "tests.unit.services.test_migration_pipeline",
        "TestsTestFlextLdifMigrationPipeline",
    ),
    "TestsTestFlextLdifProtocols": (
        "tests.unit.protocols.test_protocols",
        "TestsTestFlextLdifProtocols",
    ),
    "TestsTestFlextLdifServiceAPIs": (
        "tests.unit.utilities.test_utilities",
        "TestsTestFlextLdifServiceAPIs",
    ),
    "ValidateManyType": (
        "tests.unit.utilities.test_utilities_constants",
        "ValidateManyType",
    ),
    "all_acl_fixtures": ("tests.integration.conftest", "all_acl_fixtures"),
    "all_entries_fixtures": ("tests.integration.conftest", "all_entries_fixtures"),
    "all_integration_fixtures": (
        "tests.integration.conftest",
        "all_integration_fixtures",
    ),
    "all_schema_fixtures": ("tests.integration.conftest", "all_schema_fixtures"),
    "api": ("tests.integration.conftest", "api"),
    "c": ("tests.constants", "c"),
    "clean_test_ou": ("tests.integration.conftest", "clean_test_ou"),
    "complex_attribute_definition": (
        "tests.unit.services.test_schema_service",
        "complex_attribute_definition",
    ),
    "complex_objectclass_definition": (
        "tests.unit.services.test_schema_service",
        "complex_objectclass_definition",
    ),
    "conversion_matrix": ("tests.integration.conftest", "conversion_matrix"),
    "fixtures_dir": ("tests.integration.test_quirks_transformations", "fixtures_dir"),
    "flext_ldif": ("tests.conftest", "flext_ldif"),
    "large_test_dataset": ("tests.conftest_shared", "large_test_dataset"),
    "ldap_connection": ("tests.integration.conftest", "ldap_connection"),
    "ldap_container": ("tests.integration.conftest", "ldap_container"),
    "ldap_container_shared": ("tests.integration.conftest", "ldap_container_shared"),
    "ldif_parser": ("tests.conftest", "ldif_parser"),
    "ldif_writer": ("tests.conftest", "ldif_writer"),
    "logger": ("tests.integration.test_config_integration", "logger"),
    "m": ("tests.models", "m"),
    "make_test_base_dn": ("tests.integration.conftest", "make_test_base_dn"),
    "make_test_username": ("tests.integration.conftest", "make_test_username"),
    "migration_inputs": (
        "tests.integration.test_quirks_transformations",
        "migration_inputs",
    ),
    "oid_acl_fixture": ("tests.integration.conftest", "oid_acl_fixture"),
    "oid_acl_quirk": ("tests.integration.conftest", "oid_acl_quirk"),
    "oid_entries": ("tests.integration.conftest", "oid_entries"),
    "oid_entries_fixture": ("tests.integration.conftest", "oid_entries_fixture"),
    "oid_integration_fixture": (
        "tests.integration.conftest",
        "oid_integration_fixture",
    ),
    "oid_quirk": ("tests.integration.conftest", "oid_quirk"),
    "oid_schema_entries": ("tests.integration.conftest", "oid_schema_entries"),
    "oid_schema_fixture": ("tests.integration.conftest", "oid_schema_fixture"),
    "oid_schema_quirk": ("tests.integration.conftest", "oid_schema_quirk"),
    "openldap_acl_fixture": ("tests.integration.conftest", "openldap_acl_fixture"),
    "openldap_entries": ("tests.integration.conftest", "openldap_entries"),
    "openldap_entries_fixture": (
        "tests.integration.conftest",
        "openldap_entries_fixture",
    ),
    "openldap_integration_fixture": (
        "tests.integration.conftest",
        "openldap_integration_fixture",
    ),
    "openldap_schema_entries": (
        "tests.integration.conftest",
        "openldap_schema_entries",
    ),
    "openldap_schema_fixture": (
        "tests.integration.conftest",
        "openldap_schema_fixture",
    ),
    "oud_acl_fixture": ("tests.integration.conftest", "oud_acl_fixture"),
    "oud_acl_quirk": ("tests.integration.conftest", "oud_acl_quirk"),
    "oud_entries": ("tests.integration.conftest", "oud_entries"),
    "oud_entries_fixture": ("tests.integration.conftest", "oud_entries_fixture"),
    "oud_integration_fixture": (
        "tests.integration.conftest",
        "oud_integration_fixture",
    ),
    "oud_quirk": ("tests.integration.conftest", "oud_quirk"),
    "oud_schema_entries": ("tests.integration.conftest", "oud_schema_entries"),
    "oud_schema_fixture": ("tests.integration.conftest", "oud_schema_fixture"),
    "oud_schema_quirk": ("tests.integration.conftest", "oud_schema_quirk"),
    "p": ("tests.protocols", "p"),
    "parametrized_real_data": ("tests.conftest_shared", "parametrized_real_data"),
    "parser": ("tests.integration.conftest", "parser"),
    "pytest_configure": ("tests.conftest", "pytest_configure"),
    "real_entry": ("tests.conftest_shared", "real_entry"),
    "real_ldif_content": ("tests.conftest_shared", "real_ldif_content"),
    "real_ldif_group_entry": ("tests.conftest", "real_ldif_group_entry"),
    "real_ldif_multiple_entries": ("tests.conftest", "real_ldif_multiple_entries"),
    "real_ldif_user_entry": ("tests.conftest", "real_ldif_user_entry"),
    "rfc_schema_entries": ("tests.integration.conftest", "rfc_schema_entries"),
    "rfc_schema_fixture": ("tests.integration.conftest", "rfc_schema_fixture"),
    "s": ("tests.base", "s"),
    "sample_ldif_entries": ("tests.conftest", "sample_ldif_entries"),
    "schema_service": ("tests.unit.services.test_schema_service", "schema_service"),
    "schema_service_oud": (
        "tests.unit.services.test_schema_service",
        "schema_service_oud",
    ),
    "server": ("tests.integration.conftest", "server"),
    "simple_attribute_definition": (
        "tests.unit.services.test_schema_service",
        "simple_attribute_definition",
    ),
    "simple_objectclass_definition": (
        "tests.unit.services.test_schema_service",
        "simple_objectclass_definition",
    ),
    "t": ("tests.typings", "t"),
    "temp_file": ("tests.conftest", "temp_file"),
    "test_create_and_export_entry": (
        "tests.integration.test_simple_ldap",
        "test_create_and_export_entry",
    ),
    "test_ldap_connection": (
        "tests.integration.test_simple_ldap",
        "test_ldap_connection",
    ),
    "test_simple_ldap_search": (
        "tests.integration.test_simple_ldap",
        "test_simple_ldap_search",
    ),
    "tmp_ldif_path": ("tests.integration.conftest", "tmp_ldif_path"),
    "u": ("tests.utilities", "u"),
    "unique_dn_suffix": ("tests.integration.conftest", "unique_dn_suffix"),
    "writer": ("tests.integration.conftest", "writer"),
}

__all__ = [
    "FIXTURES_DIR",
    "OID_FIXTURES_DIR",
    "APIScenarios",
    "ConfigTestData",
    "FileManager",
    "FlextLdifFixtures",
    "FlextLdifTestConftest",
    "FlextLdifTestFactory",
    "FlextLdifTestsServiceBase",
    "FlextTestsDocker",
    "GenericFieldsDict",
    "GetAclAttributesServerType",
    "GetValidValuesType",
    "IsAclAttributeType",
    "IsValidTestType",
    "LdifSample",
    "LdifTestData",
    "MockMatchers",
    "MockResultHelpers",
    "OidTestConstants",
    "RfcTestHelpers",
    "TestAclAttributes",
    "TestAclParser",
    "TestAclRoundTripPreservation",
    "TestAliasDiscovery",
    "TestAttributeFixer",
    "TestBoundaryValues",
    "TestCategorizationRealData",
    "TestData",
    "TestDeduplicationHelpers",
    "TestDnCaseNormalizationScenarios",
    "TestDnCaseRegistry",
    "TestDnObjectClassMethods",
    "TestEmptyAndMinimalCases",
    "TestEncodingErrors",
    "TestFlextLdifAPIIntegration",
    "TestFlextLdifDeduplicationHelpers",
    "TestFlextLdifFacadeWorkflows",
    "TestFlextLdifModels",
    "TestFlextLdifSettingsIntegration",
    "TestFlextLdifTypesStructure",
    "TestFlextLdifUtilitiesComprehensive",
    "TestIncompleteEntries",
    "TestIntegrationWithLdifFixtures",
    "TestInvalidSchemaDefinitions",
    "TestLargeAndComplexCases",
    "TestLdifParser",
    "TestMalformedLdifHandling",
    "TestMinimalDifferencesOidOud",
    "TestModelsNamespace",
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
    "TestSchemaServiceBuilder",
    "TestSchemaServiceCanHandleAttribute",
    "TestSchemaServiceIntegration",
    "TestSchemaServiceParseAttribute",
    "TestSchemaServiceParseObjectClass",
    "TestSchemaServiceRepr",
    "TestSchemaServiceValidateAttribute",
    "TestSchemaServiceValidateObjectClass",
    "TestSchemaServiceWriteAttribute",
    "TestSchemaServiceWriteObjectClass",
    "TestServerTypes",
    "TestSystematicFixtureCoverage",
    "TestUnicodeBoundaries",
    "TestValidators",
    "TestZeroDataLossOidOud",
    "TestsFlextLdifCommonDictionaryTypes",
    "TestsFlextLdifConstants",
    "TestsFlextLdifDnOperationsPure",
    "TestsFlextLdifFixtures",
    "TestsFlextLdifMatchers",
    "TestsFlextLdifMigrationPipeline",
    "TestsFlextLdifMigrationPipelineQuirks",
    "TestsFlextLdifModels",
    "TestsFlextLdifProtocols",
    "TestsFlextLdifQuirksStandardizedConstants",
    "TestsFlextLdifSchemaServiceExecute",
    "TestsFlextLdifTypes",
    "TestsFlextLdifUtilities",
    "TestsFlextLdifValidators",
    "TestsFlextLdifVersion",
    "TestsFlextLdifsFlextLdifWriterDnNormalization",
    "TestsTestFlextLdifAclAttributeRegistry",
    "TestsTestFlextLdifConstants",
    "TestsTestFlextLdifMigrationPipeline",
    "TestsTestFlextLdifProtocols",
    "TestsTestFlextLdifServiceAPIs",
    "ValidateManyType",
    "all_acl_fixtures",
    "all_entries_fixtures",
    "all_integration_fixtures",
    "all_schema_fixtures",
    "api",
    "c",
    "clean_test_ou",
    "complex_attribute_definition",
    "complex_objectclass_definition",
    "conversion_matrix",
    "fixtures_dir",
    "flext_ldif",
    "large_test_dataset",
    "ldap_connection",
    "ldap_container",
    "ldap_container_shared",
    "ldif_parser",
    "ldif_writer",
    "logger",
    "m",
    "make_test_base_dn",
    "make_test_username",
    "migration_inputs",
    "oid_acl_fixture",
    "oid_acl_quirk",
    "oid_entries",
    "oid_entries_fixture",
    "oid_integration_fixture",
    "oid_quirk",
    "oid_schema_entries",
    "oid_schema_fixture",
    "oid_schema_quirk",
    "openldap_acl_fixture",
    "openldap_entries",
    "openldap_entries_fixture",
    "openldap_integration_fixture",
    "openldap_schema_entries",
    "openldap_schema_fixture",
    "oud_acl_fixture",
    "oud_acl_quirk",
    "oud_entries",
    "oud_entries_fixture",
    "oud_integration_fixture",
    "oud_quirk",
    "oud_schema_entries",
    "oud_schema_fixture",
    "oud_schema_quirk",
    "p",
    "parametrized_real_data",
    "parser",
    "pytest_configure",
    "real_entry",
    "real_ldif_content",
    "real_ldif_group_entry",
    "real_ldif_multiple_entries",
    "real_ldif_user_entry",
    "rfc_schema_entries",
    "rfc_schema_fixture",
    "s",
    "sample_ldif_entries",
    "schema_service",
    "schema_service_oud",
    "server",
    "simple_attribute_definition",
    "simple_objectclass_definition",
    "t",
    "temp_file",
    "test_create_and_export_entry",
    "test_ldap_connection",
    "test_simple_ldap_search",
    "tmp_ldif_path",
    "u",
    "unique_dn_suffix",
    "writer",
]


def __getattr__(name: str) -> t.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
