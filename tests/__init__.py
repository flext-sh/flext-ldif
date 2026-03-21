# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Tests package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes

    from flext_ldif import d, e, h, r, s, t, x

    from . import integration as integration, support as support, unit as unit
    from .base import FlextLdifTestsServiceBase
    from .conftest import (
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
    from .conftest_shared import (
        large_test_dataset,
        parametrized_real_data,
        real_entry,
        real_ldif_content,
    )
    from .constants import TestsFlextLdifConstants, TestsFlextLdifConstants as c
    from .integration.conftest import (
        LDAP_ADMIN_DN,
        LDAP_ADMIN_PASSWORD,
        LDAP_BASE_DN,
        LDAP_COMPOSE_FILE,
        LDAP_CONTAINER_NAME,
        LDAP_PORT,
        LDAP_SERVICE_NAME,
        WORKSPACE_ROOT,
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
    from .integration.test_acl_metadata_preservation import (
        TestAclRoundTripPreservation,
        TestOidAclMetadataPreservation,
        TestOudAciMetadataPreservation,
    )
    from .integration.test_api_integration import (
        APIScenarios,
        TestData,
        TestFlextLdifAPIIntegration,
    )
    from .integration.test_categorization_real_data import TestCategorizationRealData
    from .integration.test_config_integration import (
        ConfigTestData,
        TestFlextLdifSettingsIntegration,
        logger,
    )
    from .integration.test_cross_quirk_conversion import (
        TestOidToOudAclConversion,
        TestOidToOudIntegrationConversion,
        TestOidToOudSchemaConversion,
        TestQuirksConversionMatrixFacade,
    )
    from .integration.test_dn_case_handling import (
        TestDnCaseNormalizationScenarios,
        TestDnCaseRegistry,
    )
    from .integration.test_edge_cases import (
        TestBoundaryValues,
        TestEmptyAndMinimalCases,
        TestLargeAndComplexCases,
        TestRoundtripEdgeCases,
        TestUnicodeBoundaries,
    )
    from .integration.test_error_recovery import (
        TestEncodingErrors,
        TestIncompleteEntries,
        TestInvalidSchemaDefinitions,
        TestMalformedLdifHandling,
    )
    from .integration.test_ldif_fixtures_integration import TestsFlextLdifFixtures
    from .integration.test_minimal_differences_metadata import (
        TestMinimalDifferencesOidOud,
    )
    from .integration.test_oid_integration import (
        TestOidEntryIntegration,
        TestOidRoundTripIntegration,
        TestOidSchemaIntegration,
    )
    from .integration.test_oud_integration import (
        TestOudAclIntegration,
        TestOudEntryIntegration,
        TestOudMetadataPreservation,
        TestOudRoundTripIntegration,
        TestOudSchemaIntegration,
    )
    from .integration.test_oud_to_oid_migration import (
        TestOudToOidAclMigration,
        TestOudToOidEntryMigration,
        TestOudToOidFullMigration,
        TestOudToOidSchemaMigration,
    )
    from .integration.test_pipeline_integration import TestFlextLdifFacadeWorkflows
    from .integration.test_quirks_transformations import (
        TestOidQuirksTransformations,
        TestOudQuirksTransformations,
        TestQuirksPropertyValidation,
        fixtures_dir,
        migration_inputs,
    )
    from .integration.test_real_ldap_config import (
        TestRealLdapConfigurationFromEnv,
        TestRealLdapRailwayComposition,
    )
    from .integration.test_real_ldap_crud import (
        TestRealLdapBatchOperations,
        TestRealLdapCRUD,
    )
    from .integration.test_real_ldap_export import TestRealLdapExport
    from .integration.test_real_ldap_import import TestRealLdapImport
    from .integration.test_real_ldap_roundtrip import TestRealLdapRoundtrip
    from .integration.test_rfc_docker_real import (
        TestRfcDockerRealData,
        TestRfcIntegrationRealWorld,
    )
    from .integration.test_rfc_docker_real_integration import (
        TestRfcExceptionHandlingRealScenarios,
        TestRfcParserRealFixtures,
        TestRfcSchemaParserRealFixtures,
        TestRfcWriterRealFixtures,
    )
    from .integration.test_simple_ldap import (
        test_create_and_export_entry,
        test_ldap_connection,
        test_simple_ldap_search,
    )
    from .integration.test_systematic_fixture_coverage import (
        TestSystematicFixtureCoverage,
    )
    from .integration.test_zero_data_loss_oid_oud import TestZeroDataLossOidOud
    from .integration.test_zero_data_loss_schema import (
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
    from .models import TestsFlextLdifModels, TestsFlextLdifModels as m
    from .protocols import TestsFlextLdifProtocols, TestsFlextLdifProtocols as p
    from .support.conftest_factory import FlextLdifTestConftest, tk
    from .support.ldif_data import LdifSample, LdifTestData
    from .support.real_services import FlextLdifTestFactory
    from .support.test_files import FileManager
    from .support.validators import (
        MockFlextUtilitiesResultHelpers,
        MockMatchers,
        TestValidators,
    )
    from .test_helpers import (
        TestsFlextLdifMatchers,
        TestsFlextLdifTypes,
        TestsFlextLdifValidators,
        tf,
        tm,
        tt,
        tv,
    )
    from .typings import GenericFieldsDict
    from .unit import (
        constants as constants,
        models as models,
        protocols as protocols,
        services as services,
        utilities as utilities,
    )
    from .unit.__init__.test_version import TestsFlextLdifVersion, version_module
    from .unit._utilities.oid.test_oid_utilities import TestFlextLdifUtilitiesOID
    from .unit._utilities.parser.test_parser_utilities import (
        TestFlextLdifUtilitiesParser,
    )
    from .unit._utilities.server.test_server_utilities import (
        OidServer,
        OudServer,
        TestFlextLdifUtilitiesServer,
    )
    from .unit.constants.test_acl_registry import (
        GetAclAttributesServerType,
        IsAclAttributeType,
        TestsTestFlextLdifAclAttributeRegistry,
    )
    from .unit.models.test_models import TestFlextLdifModels
    from .unit.protocols.test_protocols import TestsTestFlextLdifProtocols
    from .unit.quirks.servers.test_apache_quirks import TestsTestFlextLdifApacheQuirks
    from .unit.quirks.servers.test_ds389_quirks import (
        ACL_TEST_CASES,
        AclScenario,
        AclTestCase,
        TestsTestFlextLdifDs389Quirks,
    )
    from .unit.quirks.servers.test_edge_cases import (
        TestsFlextLdifEdgeCases,
        cleanup_state,
        ldif_api,
    )
    from .unit.quirks.servers.test_novell_quirks import (
        ATTRIBUTE_TEST_CASES,
        ENTRY_TEST_CASES,
        OBJECTCLASS_TEST_CASES,
        AttributeScenario,
        AttributeTestCase,
        EntryScenario,
        EntryTestCase,
        ObjectClassScenario,
        ObjectClassTestCase,
        RfcTestHelpers,
        TestDeduplicationHelpers,
        TestNovellAcls,
        TestNovellEntryDetection,
        TestNovellSchemaAttributeDetection,
        TestNovellSchemaAttributeParsing,
        TestNovellSchemaObjectClassDetection,
        TestNovellSchemaObjectClassParsing,
        TestsFlextLdifNovellInitialization,
        entry_quirk,
        novell_server,
        schema_quirk,
    )
    from .unit.quirks.servers.test_oid_quirks import TestsTestFlextLdifOidQuirks
    from .unit.quirks.servers.test_relaxed_quirks import (
        ParseScenario,
        TestsTestFlextLdifRelaxedQuirks,
        WriteScenario,
        meta_keys,
    )
    from .unit.quirks.servers.test_schema_transformer import (
        TestSchemaTransformerApplyAttributeTransformations,
        TestSchemaTransformerApplyObjectClassTransformations,
        TestSchemaTransformerNormalizeMatchingRule,
        TestSchemaTransformerNormalizeSyntaxOid,
        TestsFlextLdifSchemaTransformerNormalizeAttributeName,
    )
    from .unit.services.test_migration_pipeline import (
        TestsTestFlextLdifMigrationPipeline,
    )
    from .unit.services.test_quirks_standardization import (
        TestAliasDiscovery,
        TestQuirksAutoInterchange,
        TestQuirksWithRealLdifFixtures,
        TestsFlextLdifQuirksStandardizedConstants,
    )
    from .unit.services.test_schema_service import (
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
    from .unit.services.test_writer_dn_normalization import (
        TestsFlextLdifsFlextLdifWriterDnNormalization,
    )
    from .unit.test_filters import TestAclAttributes
    from .unit.test_helpers import TestFlextLdifDeduplicationHelpers
    from .unit.test_migration_pipeline import TestsFlextLdifMigrationPipeline
    from .unit.test_migration_pipeline_quirks import (
        OidTestConstants,
        TestsFlextLdifMigrationPipelineQuirks,
    )
    from .unit.test_typings import (
        TestFlextLdifTypesStructure,
        TestIntegrationWithLdifFixtures,
        TestModelsNamespace,
        TestPhase1StandardizationResults,
        TestRemovalOfOverEngineering,
        TestsFlextLdifCommonDictionaryTypes,
    )
    from .unit.utilities.test_utilities import TestsTestFlextLdifServiceAPIs
    from .unit.utilities.test_utilities_comprehensive import (
        TestFlextLdifUtilitiesComprehensive,
    )
    from .unit.utilities.test_utilities_constants import (
        GetValidValuesType,
        IsValidTestType,
        TestsTestFlextLdifConstants,
        ValidateManyType,
    )
    from .unit.utilities.test_utilities_core import (
        TestAclParser,
        TestAttributeFixer,
        TestDnObjectClassMethods,
        TestLdifParser,
        TestObjectClassUtilities,
        TestServerTypes,
        TestsFlextLdifDnOperationsPure,
    )
    from .utilities import TestsFlextLdifUtilities, TestsFlextLdifUtilities as u

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "ACL_TEST_CASES": ("tests.unit.quirks.servers.test_ds389_quirks", "ACL_TEST_CASES"),
    "APIScenarios": ("tests.integration.test_api_integration", "APIScenarios"),
    "ATTRIBUTE_TEST_CASES": (
        "tests.unit.quirks.servers.test_novell_quirks",
        "ATTRIBUTE_TEST_CASES",
    ),
    "AclScenario": ("tests.unit.quirks.servers.test_ds389_quirks", "AclScenario"),
    "AclTestCase": ("tests.unit.quirks.servers.test_ds389_quirks", "AclTestCase"),
    "AttributeScenario": (
        "tests.unit.quirks.servers.test_novell_quirks",
        "AttributeScenario",
    ),
    "AttributeTestCase": (
        "tests.unit.quirks.servers.test_novell_quirks",
        "AttributeTestCase",
    ),
    "ConfigTestData": ("tests.integration.test_config_integration", "ConfigTestData"),
    "ENTRY_TEST_CASES": (
        "tests.unit.quirks.servers.test_novell_quirks",
        "ENTRY_TEST_CASES",
    ),
    "EntryScenario": ("tests.unit.quirks.servers.test_novell_quirks", "EntryScenario"),
    "EntryTestCase": ("tests.unit.quirks.servers.test_novell_quirks", "EntryTestCase"),
    "FIXTURES_DIR": ("tests.conftest", "FIXTURES_DIR"),
    "FileManager": ("tests.support.test_files", "FileManager"),
    "FlextLdifFixtures": ("tests.conftest", "FlextLdifFixtures"),
    "FlextLdifTestConftest": (
        "tests.support.conftest_factory",
        "FlextLdifTestConftest",
    ),
    "FlextLdifTestFactory": ("tests.support.real_services", "FlextLdifTestFactory"),
    "FlextLdifTestsServiceBase": ("tests.base", "FlextLdifTestsServiceBase"),
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
    "LDAP_ADMIN_DN": ("tests.integration.conftest", "LDAP_ADMIN_DN"),
    "LDAP_ADMIN_PASSWORD": ("tests.integration.conftest", "LDAP_ADMIN_PASSWORD"),
    "LDAP_BASE_DN": ("tests.integration.conftest", "LDAP_BASE_DN"),
    "LDAP_COMPOSE_FILE": ("tests.integration.conftest", "LDAP_COMPOSE_FILE"),
    "LDAP_CONTAINER_NAME": ("tests.integration.conftest", "LDAP_CONTAINER_NAME"),
    "LDAP_PORT": ("tests.integration.conftest", "LDAP_PORT"),
    "LDAP_SERVICE_NAME": ("tests.integration.conftest", "LDAP_SERVICE_NAME"),
    "LdifSample": ("tests.support.ldif_data", "LdifSample"),
    "LdifTestData": ("tests.support.ldif_data", "LdifTestData"),
    "MockFlextUtilitiesResultHelpers": (
        "tests.support.validators",
        "MockFlextUtilitiesResultHelpers",
    ),
    "MockMatchers": ("tests.support.validators", "MockMatchers"),
    "OBJECTCLASS_TEST_CASES": (
        "tests.unit.quirks.servers.test_novell_quirks",
        "OBJECTCLASS_TEST_CASES",
    ),
    "OID_FIXTURES_DIR": ("tests.conftest", "OID_FIXTURES_DIR"),
    "ObjectClassScenario": (
        "tests.unit.quirks.servers.test_novell_quirks",
        "ObjectClassScenario",
    ),
    "ObjectClassTestCase": (
        "tests.unit.quirks.servers.test_novell_quirks",
        "ObjectClassTestCase",
    ),
    "OidServer": ("tests.unit._utilities.server.test_server_utilities", "OidServer"),
    "OidTestConstants": (
        "tests.unit.test_migration_pipeline_quirks",
        "OidTestConstants",
    ),
    "OudServer": ("tests.unit._utilities.server.test_server_utilities", "OudServer"),
    "ParseScenario": ("tests.unit.quirks.servers.test_relaxed_quirks", "ParseScenario"),
    "RfcTestHelpers": (
        "tests.unit.quirks.servers.test_novell_quirks",
        "RfcTestHelpers",
    ),
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
    "TestDeduplicationHelpers": (
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestDeduplicationHelpers",
    ),
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
    "TestFlextLdifUtilitiesOID": (
        "tests.unit._utilities.oid.test_oid_utilities",
        "TestFlextLdifUtilitiesOID",
    ),
    "TestFlextLdifUtilitiesParser": (
        "tests.unit._utilities.parser.test_parser_utilities",
        "TestFlextLdifUtilitiesParser",
    ),
    "TestFlextLdifUtilitiesServer": (
        "tests.unit._utilities.server.test_server_utilities",
        "TestFlextLdifUtilitiesServer",
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
    "TestNovellAcls": (
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellAcls",
    ),
    "TestNovellEntryDetection": (
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellEntryDetection",
    ),
    "TestNovellSchemaAttributeDetection": (
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellSchemaAttributeDetection",
    ),
    "TestNovellSchemaAttributeParsing": (
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellSchemaAttributeParsing",
    ),
    "TestNovellSchemaObjectClassDetection": (
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellSchemaObjectClassDetection",
    ),
    "TestNovellSchemaObjectClassParsing": (
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellSchemaObjectClassParsing",
    ),
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
    "TestSchemaTransformerApplyAttributeTransformations": (
        "tests.unit.quirks.servers.test_schema_transformer",
        "TestSchemaTransformerApplyAttributeTransformations",
    ),
    "TestSchemaTransformerApplyObjectClassTransformations": (
        "tests.unit.quirks.servers.test_schema_transformer",
        "TestSchemaTransformerApplyObjectClassTransformations",
    ),
    "TestSchemaTransformerNormalizeMatchingRule": (
        "tests.unit.quirks.servers.test_schema_transformer",
        "TestSchemaTransformerNormalizeMatchingRule",
    ),
    "TestSchemaTransformerNormalizeSyntaxOid": (
        "tests.unit.quirks.servers.test_schema_transformer",
        "TestSchemaTransformerNormalizeSyntaxOid",
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
    "TestsFlextLdifEdgeCases": (
        "tests.unit.quirks.servers.test_edge_cases",
        "TestsFlextLdifEdgeCases",
    ),
    "TestsFlextLdifFixtures": (
        "tests.integration.test_ldif_fixtures_integration",
        "TestsFlextLdifFixtures",
    ),
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
    "TestsFlextLdifNovellInitialization": (
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestsFlextLdifNovellInitialization",
    ),
    "TestsFlextLdifProtocols": ("tests.protocols", "TestsFlextLdifProtocols"),
    "TestsFlextLdifQuirksStandardizedConstants": (
        "tests.unit.services.test_quirks_standardization",
        "TestsFlextLdifQuirksStandardizedConstants",
    ),
    "TestsFlextLdifSchemaServiceExecute": (
        "tests.unit.services.test_schema_service",
        "TestsFlextLdifSchemaServiceExecute",
    ),
    "TestsFlextLdifSchemaTransformerNormalizeAttributeName": (
        "tests.unit.quirks.servers.test_schema_transformer",
        "TestsFlextLdifSchemaTransformerNormalizeAttributeName",
    ),
    "TestsFlextLdifTypes": ("tests.test_helpers", "TestsFlextLdifTypes"),
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
    "TestsTestFlextLdifApacheQuirks": (
        "tests.unit.quirks.servers.test_apache_quirks",
        "TestsTestFlextLdifApacheQuirks",
    ),
    "TestsTestFlextLdifConstants": (
        "tests.unit.utilities.test_utilities_constants",
        "TestsTestFlextLdifConstants",
    ),
    "TestsTestFlextLdifDs389Quirks": (
        "tests.unit.quirks.servers.test_ds389_quirks",
        "TestsTestFlextLdifDs389Quirks",
    ),
    "TestsTestFlextLdifMigrationPipeline": (
        "tests.unit.services.test_migration_pipeline",
        "TestsTestFlextLdifMigrationPipeline",
    ),
    "TestsTestFlextLdifOidQuirks": (
        "tests.unit.quirks.servers.test_oid_quirks",
        "TestsTestFlextLdifOidQuirks",
    ),
    "TestsTestFlextLdifProtocols": (
        "tests.unit.protocols.test_protocols",
        "TestsTestFlextLdifProtocols",
    ),
    "TestsTestFlextLdifRelaxedQuirks": (
        "tests.unit.quirks.servers.test_relaxed_quirks",
        "TestsTestFlextLdifRelaxedQuirks",
    ),
    "TestsTestFlextLdifServiceAPIs": (
        "tests.unit.utilities.test_utilities",
        "TestsTestFlextLdifServiceAPIs",
    ),
    "ValidateManyType": (
        "tests.unit.utilities.test_utilities_constants",
        "ValidateManyType",
    ),
    "WORKSPACE_ROOT": ("tests.integration.conftest", "WORKSPACE_ROOT"),
    "WriteScenario": ("tests.unit.quirks.servers.test_relaxed_quirks", "WriteScenario"),
    "all_acl_fixtures": ("tests.integration.conftest", "all_acl_fixtures"),
    "all_entries_fixtures": ("tests.integration.conftest", "all_entries_fixtures"),
    "all_integration_fixtures": (
        "tests.integration.conftest",
        "all_integration_fixtures",
    ),
    "all_schema_fixtures": ("tests.integration.conftest", "all_schema_fixtures"),
    "api": ("tests.integration.conftest", "api"),
    "c": ("tests.constants", "TestsFlextLdifConstants"),
    "clean_test_ou": ("tests.integration.conftest", "clean_test_ou"),
    "cleanup_state": ("tests.unit.quirks.servers.test_edge_cases", "cleanup_state"),
    "complex_attribute_definition": (
        "tests.unit.services.test_schema_service",
        "complex_attribute_definition",
    ),
    "complex_objectclass_definition": (
        "tests.unit.services.test_schema_service",
        "complex_objectclass_definition",
    ),
    "constants": ("tests.unit.constants", ""),
    "conversion_matrix": ("tests.integration.conftest", "conversion_matrix"),
    "d": ("flext_ldif", "d"),
    "e": ("flext_ldif", "e"),
    "entry_quirk": ("tests.unit.quirks.servers.test_novell_quirks", "entry_quirk"),
    "fixtures_dir": ("tests.integration.test_quirks_transformations", "fixtures_dir"),
    "flext_ldif": ("tests.conftest", "flext_ldif"),
    "h": ("flext_ldif", "h"),
    "integration": ("tests.integration", ""),
    "large_test_dataset": ("tests.conftest_shared", "large_test_dataset"),
    "ldap_connection": ("tests.integration.conftest", "ldap_connection"),
    "ldap_container": ("tests.integration.conftest", "ldap_container"),
    "ldap_container_shared": ("tests.integration.conftest", "ldap_container_shared"),
    "ldif_api": ("tests.unit.quirks.servers.test_edge_cases", "ldif_api"),
    "ldif_parser": ("tests.conftest", "ldif_parser"),
    "ldif_writer": ("tests.conftest", "ldif_writer"),
    "logger": ("tests.integration.test_config_integration", "logger"),
    "m": ("tests.models", "TestsFlextLdifModels"),
    "make_test_base_dn": ("tests.integration.conftest", "make_test_base_dn"),
    "make_test_username": ("tests.integration.conftest", "make_test_username"),
    "meta_keys": ("tests.unit.quirks.servers.test_relaxed_quirks", "meta_keys"),
    "migration_inputs": (
        "tests.integration.test_quirks_transformations",
        "migration_inputs",
    ),
    "models": ("tests.unit.models", ""),
    "novell_server": ("tests.unit.quirks.servers.test_novell_quirks", "novell_server"),
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
    "p": ("tests.protocols", "TestsFlextLdifProtocols"),
    "parametrized_real_data": ("tests.conftest_shared", "parametrized_real_data"),
    "parser": ("tests.integration.conftest", "parser"),
    "protocols": ("tests.unit.protocols", ""),
    "pytest_configure": ("tests.conftest", "pytest_configure"),
    "r": ("flext_ldif", "r"),
    "real_entry": ("tests.conftest_shared", "real_entry"),
    "real_ldif_content": ("tests.conftest_shared", "real_ldif_content"),
    "real_ldif_group_entry": ("tests.conftest", "real_ldif_group_entry"),
    "real_ldif_multiple_entries": ("tests.conftest", "real_ldif_multiple_entries"),
    "real_ldif_user_entry": ("tests.conftest", "real_ldif_user_entry"),
    "rfc_schema_entries": ("tests.integration.conftest", "rfc_schema_entries"),
    "rfc_schema_fixture": ("tests.integration.conftest", "rfc_schema_fixture"),
    "s": ("flext_ldif", "s"),
    "sample_ldif_entries": ("tests.conftest", "sample_ldif_entries"),
    "schema_quirk": ("tests.unit.quirks.servers.test_novell_quirks", "schema_quirk"),
    "schema_service": ("tests.unit.services.test_schema_service", "schema_service"),
    "schema_service_oud": (
        "tests.unit.services.test_schema_service",
        "schema_service_oud",
    ),
    "server": ("tests.integration.conftest", "server"),
    "services": ("tests.unit.services", ""),
    "simple_attribute_definition": (
        "tests.unit.services.test_schema_service",
        "simple_attribute_definition",
    ),
    "simple_objectclass_definition": (
        "tests.unit.services.test_schema_service",
        "simple_objectclass_definition",
    ),
    "support": ("tests.support", ""),
    "t": ("flext_ldif", "t"),
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
    "tf": ("tests.test_helpers", "tf"),
    "tk": ("tests.support.conftest_factory", "tk"),
    "tm": ("tests.test_helpers", "tm"),
    "tmp_ldif_path": ("tests.integration.conftest", "tmp_ldif_path"),
    "tt": ("tests.test_helpers", "tt"),
    "tv": ("tests.test_helpers", "tv"),
    "u": ("tests.utilities", "TestsFlextLdifUtilities"),
    "unique_dn_suffix": ("tests.integration.conftest", "unique_dn_suffix"),
    "unit": ("tests.unit", ""),
    "utilities": ("tests.unit.utilities", ""),
    "version_module": ("tests.unit.__init__.test_version", "version_module"),
    "writer": ("tests.integration.conftest", "writer"),
    "x": ("flext_ldif", "x"),
}

__all__ = [
    "ACL_TEST_CASES",
    "ATTRIBUTE_TEST_CASES",
    "ENTRY_TEST_CASES",
    "FIXTURES_DIR",
    "LDAP_ADMIN_DN",
    "LDAP_ADMIN_PASSWORD",
    "LDAP_BASE_DN",
    "LDAP_COMPOSE_FILE",
    "LDAP_CONTAINER_NAME",
    "LDAP_PORT",
    "LDAP_SERVICE_NAME",
    "OBJECTCLASS_TEST_CASES",
    "OID_FIXTURES_DIR",
    "WORKSPACE_ROOT",
    "APIScenarios",
    "AclScenario",
    "AclTestCase",
    "AttributeScenario",
    "AttributeTestCase",
    "ConfigTestData",
    "EntryScenario",
    "EntryTestCase",
    "FileManager",
    "FlextLdifFixtures",
    "FlextLdifTestConftest",
    "FlextLdifTestFactory",
    "FlextLdifTestsServiceBase",
    "GenericFieldsDict",
    "GetAclAttributesServerType",
    "GetValidValuesType",
    "IsAclAttributeType",
    "IsValidTestType",
    "LdifSample",
    "LdifTestData",
    "MockFlextUtilitiesResultHelpers",
    "MockMatchers",
    "ObjectClassScenario",
    "ObjectClassTestCase",
    "OidServer",
    "OidTestConstants",
    "OudServer",
    "ParseScenario",
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
    "TestFlextLdifUtilitiesOID",
    "TestFlextLdifUtilitiesParser",
    "TestFlextLdifUtilitiesServer",
    "TestIncompleteEntries",
    "TestIntegrationWithLdifFixtures",
    "TestInvalidSchemaDefinitions",
    "TestLargeAndComplexCases",
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
    "TestSchemaTransformerApplyAttributeTransformations",
    "TestSchemaTransformerApplyObjectClassTransformations",
    "TestSchemaTransformerNormalizeMatchingRule",
    "TestSchemaTransformerNormalizeSyntaxOid",
    "TestServerTypes",
    "TestSystematicFixtureCoverage",
    "TestUnicodeBoundaries",
    "TestValidators",
    "TestZeroDataLossOidOud",
    "TestsFlextLdifCommonDictionaryTypes",
    "TestsFlextLdifConstants",
    "TestsFlextLdifDnOperationsPure",
    "TestsFlextLdifEdgeCases",
    "TestsFlextLdifFixtures",
    "TestsFlextLdifMatchers",
    "TestsFlextLdifMigrationPipeline",
    "TestsFlextLdifMigrationPipelineQuirks",
    "TestsFlextLdifModels",
    "TestsFlextLdifNovellInitialization",
    "TestsFlextLdifProtocols",
    "TestsFlextLdifQuirksStandardizedConstants",
    "TestsFlextLdifSchemaServiceExecute",
    "TestsFlextLdifSchemaTransformerNormalizeAttributeName",
    "TestsFlextLdifTypes",
    "TestsFlextLdifUtilities",
    "TestsFlextLdifValidators",
    "TestsFlextLdifVersion",
    "TestsFlextLdifsFlextLdifWriterDnNormalization",
    "TestsTestFlextLdifAclAttributeRegistry",
    "TestsTestFlextLdifApacheQuirks",
    "TestsTestFlextLdifConstants",
    "TestsTestFlextLdifDs389Quirks",
    "TestsTestFlextLdifMigrationPipeline",
    "TestsTestFlextLdifOidQuirks",
    "TestsTestFlextLdifProtocols",
    "TestsTestFlextLdifRelaxedQuirks",
    "TestsTestFlextLdifServiceAPIs",
    "ValidateManyType",
    "WriteScenario",
    "all_acl_fixtures",
    "all_entries_fixtures",
    "all_integration_fixtures",
    "all_schema_fixtures",
    "api",
    "c",
    "clean_test_ou",
    "cleanup_state",
    "complex_attribute_definition",
    "complex_objectclass_definition",
    "constants",
    "conversion_matrix",
    "d",
    "e",
    "entry_quirk",
    "fixtures_dir",
    "flext_ldif",
    "h",
    "integration",
    "large_test_dataset",
    "ldap_connection",
    "ldap_container",
    "ldap_container_shared",
    "ldif_api",
    "ldif_parser",
    "ldif_writer",
    "logger",
    "m",
    "make_test_base_dn",
    "make_test_username",
    "meta_keys",
    "migration_inputs",
    "models",
    "novell_server",
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
    "protocols",
    "pytest_configure",
    "r",
    "real_entry",
    "real_ldif_content",
    "real_ldif_group_entry",
    "real_ldif_multiple_entries",
    "real_ldif_user_entry",
    "rfc_schema_entries",
    "rfc_schema_fixture",
    "s",
    "sample_ldif_entries",
    "schema_quirk",
    "schema_service",
    "schema_service_oud",
    "server",
    "services",
    "simple_attribute_definition",
    "simple_objectclass_definition",
    "support",
    "t",
    "temp_file",
    "test_create_and_export_entry",
    "test_ldap_connection",
    "test_simple_ldap_search",
    "tf",
    "tk",
    "tm",
    "tmp_ldif_path",
    "tt",
    "tv",
    "u",
    "unique_dn_suffix",
    "unit",
    "utilities",
    "version_module",
    "writer",
    "x",
]


_LAZY_CACHE: dict[str, FlextTypes.ModuleExport] = {}


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562).

    A local cache ``_LAZY_CACHE`` persists resolved objects across repeated
    accesses during process lifetime.

    Args:
        name: Attribute name requested by dir()/import.

    Returns:
        Lazy-loaded module export type.

    Raises:
        AttributeError: If attribute not registered.

    """
    if name in _LAZY_CACHE:
        return _LAZY_CACHE[name]

    value = lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)
    _LAZY_CACHE[name] = value
    return value


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete.

    Returns:
        List of public names from module exports.

    """
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
