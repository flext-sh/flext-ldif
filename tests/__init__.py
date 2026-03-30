# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from tests import (
        base as base,
        conftest as conftest,
        conftest_shared as conftest_shared,
        constants as constants,
        e2e as e2e,
        helpers as helpers,
        integration as integration,
        models as models,
        protocols as protocols,
        support as support,
        test_factory as test_factory,
        test_helpers as test_helpers,
        typings as typings,
        unit as unit,
        utilities as utilities,
    )
    from tests.base import (
        FlextLdifTestsServiceBase as FlextLdifTestsServiceBase,
        s as s,
    )
    from tests.conftest import (
        FIXTURES_DIR as FIXTURES_DIR,
        OID_FIXTURES_DIR as OID_FIXTURES_DIR,
        FlextLdifFixtures as FlextLdifFixtures,
        flext_ldif as flext_ldif,
        ldif_parser as ldif_parser,
        ldif_writer as ldif_writer,
        pytest_configure as pytest_configure,
        real_ldif_group_entry as real_ldif_group_entry,
        real_ldif_multiple_entries as real_ldif_multiple_entries,
        real_ldif_user_entry as real_ldif_user_entry,
        sample_ldif_entries as sample_ldif_entries,
        temp_file as temp_file,
    )
    from tests.conftest_shared import (
        large_test_dataset as large_test_dataset,
        parametrized_real_data as parametrized_real_data,
        real_entry as real_entry,
        real_ldif_content as real_ldif_content,
    )
    from tests.constants import (
        FlextLdifTestConstants as FlextLdifTestConstants,
        FlextLdifTestConstants as c,
    )
    from tests.e2e import test_enterprise as test_enterprise
    from tests.helpers import example_refactoring as example_refactoring
    from tests.integration import (
        test_acl_metadata_preservation as test_acl_metadata_preservation,
        test_api_integration as test_api_integration,
        test_categorization_real_data as test_categorization_real_data,
        test_config_integration as test_config_integration,
        test_cross_quirk_conversion as test_cross_quirk_conversion,
        test_dn_case_handling as test_dn_case_handling,
        test_edge_cases as test_edge_cases,
        test_error_recovery as test_error_recovery,
        test_ldif_fixtures_integration as test_ldif_fixtures_integration,
        test_minimal_differences_metadata as test_minimal_differences_metadata,
        test_oid_integration as test_oid_integration,
        test_oud_integration as test_oud_integration,
        test_oud_to_oid_migration as test_oud_to_oid_migration,
        test_pipeline_integration as test_pipeline_integration,
        test_quirks_transformations as test_quirks_transformations,
        test_real_ldap_config as test_real_ldap_config,
        test_real_ldap_crud as test_real_ldap_crud,
        test_real_ldap_export as test_real_ldap_export,
        test_real_ldap_import as test_real_ldap_import,
        test_real_ldap_roundtrip as test_real_ldap_roundtrip,
        test_rfc_docker_real as test_rfc_docker_real,
        test_rfc_docker_real_integration as test_rfc_docker_real_integration,
        test_simple_ldap as test_simple_ldap,
        test_systematic_fixture_coverage as test_systematic_fixture_coverage,
        test_zero_data_loss_oid_oud as test_zero_data_loss_oid_oud,
        test_zero_data_loss_schema as test_zero_data_loss_schema,
    )
    from tests.integration.conftest import (
        WORKSPACE_ROOT as WORKSPACE_ROOT,
        all_acl_fixtures as all_acl_fixtures,
        all_entries_fixtures as all_entries_fixtures,
        all_integration_fixtures as all_integration_fixtures,
        all_schema_fixtures as all_schema_fixtures,
        api as api,
        clean_test_ou as clean_test_ou,
        conversion_matrix as conversion_matrix,
        ldap_connection as ldap_connection,
        ldap_container as ldap_container,
        ldap_container_shared as ldap_container_shared,
        make_test_base_dn as make_test_base_dn,
        make_test_username as make_test_username,
        oid_acl_fixture as oid_acl_fixture,
        oid_acl_quirk as oid_acl_quirk,
        oid_entries as oid_entries,
        oid_entries_fixture as oid_entries_fixture,
        oid_integration_fixture as oid_integration_fixture,
        oid_quirk as oid_quirk,
        oid_schema_entries as oid_schema_entries,
        oid_schema_fixture as oid_schema_fixture,
        oid_schema_quirk as oid_schema_quirk,
        openldap_acl_fixture as openldap_acl_fixture,
        openldap_entries as openldap_entries,
        openldap_entries_fixture as openldap_entries_fixture,
        openldap_integration_fixture as openldap_integration_fixture,
        openldap_schema_entries as openldap_schema_entries,
        openldap_schema_fixture as openldap_schema_fixture,
        oud_acl_fixture as oud_acl_fixture,
        oud_acl_quirk as oud_acl_quirk,
        oud_entries as oud_entries,
        oud_entries_fixture as oud_entries_fixture,
        oud_integration_fixture as oud_integration_fixture,
        oud_quirk as oud_quirk,
        oud_schema_entries as oud_schema_entries,
        oud_schema_fixture as oud_schema_fixture,
        oud_schema_quirk as oud_schema_quirk,
        parser as parser,
        rfc_schema_entries as rfc_schema_entries,
        rfc_schema_fixture as rfc_schema_fixture,
        server as server,
        tmp_ldif_path as tmp_ldif_path,
        unique_dn_suffix as unique_dn_suffix,
        writer as writer,
    )
    from tests.integration.test_acl_metadata_preservation import (
        TestAclRoundTripPreservation as TestAclRoundTripPreservation,
        TestOidAclMetadataPreservation as TestOidAclMetadataPreservation,
        TestOudAciMetadataPreservation as TestOudAciMetadataPreservation,
    )
    from tests.integration.test_api_integration import (
        APIScenarios as APIScenarios,
        TestData as TestData,
        TestFlextLdifAPIIntegration as TestFlextLdifAPIIntegration,
    )
    from tests.integration.test_categorization_real_data import (
        TestCategorizationRealData as TestCategorizationRealData,
    )
    from tests.integration.test_config_integration import (
        ConfigTestData as ConfigTestData,
        TestFlextLdifSettingsIntegration as TestFlextLdifSettingsIntegration,
        logger as logger,
    )
    from tests.integration.test_cross_quirk_conversion import (
        TestOidToOudAclConversion as TestOidToOudAclConversion,
        TestOidToOudIntegrationConversion as TestOidToOudIntegrationConversion,
        TestOidToOudSchemaConversion as TestOidToOudSchemaConversion,
        TestQuirksConversionMatrixFacade as TestQuirksConversionMatrixFacade,
    )
    from tests.integration.test_dn_case_handling import (
        TestDnCaseNormalizationScenarios as TestDnCaseNormalizationScenarios,
        TestDnCaseRegistry as TestDnCaseRegistry,
    )
    from tests.integration.test_edge_cases import (
        TestBoundaryValues as TestBoundaryValues,
        TestEmptyAndMinimalCases as TestEmptyAndMinimalCases,
        TestLargeAndComplexCases as TestLargeAndComplexCases,
        TestRoundtripEdgeCases as TestRoundtripEdgeCases,
        TestUnicodeBoundaries as TestUnicodeBoundaries,
    )
    from tests.integration.test_error_recovery import (
        TestEncodingErrors as TestEncodingErrors,
        TestIncompleteEntries as TestIncompleteEntries,
        TestInvalidSchemaDefinitions as TestInvalidSchemaDefinitions,
        TestMalformedLdifHandling as TestMalformedLdifHandling,
    )
    from tests.integration.test_ldif_fixtures_integration import (
        TestsFlextLdifFixtures as TestsFlextLdifFixtures,
    )
    from tests.integration.test_minimal_differences_metadata import (
        TestMinimalDifferencesOidOud as TestMinimalDifferencesOidOud,
    )
    from tests.integration.test_oid_integration import (
        TestOidEntryIntegration as TestOidEntryIntegration,
        TestOidRoundTripIntegration as TestOidRoundTripIntegration,
        TestOidSchemaIntegration as TestOidSchemaIntegration,
    )
    from tests.integration.test_oud_integration import (
        TestOudAclIntegration as TestOudAclIntegration,
        TestOudEntryIntegration as TestOudEntryIntegration,
        TestOudMetadataPreservation as TestOudMetadataPreservation,
        TestOudRoundTripIntegration as TestOudRoundTripIntegration,
        TestOudSchemaIntegration as TestOudSchemaIntegration,
    )
    from tests.integration.test_oud_to_oid_migration import (
        TestOudToOidAclMigration as TestOudToOidAclMigration,
        TestOudToOidEntryMigration as TestOudToOidEntryMigration,
        TestOudToOidFullMigration as TestOudToOidFullMigration,
        TestOudToOidSchemaMigration as TestOudToOidSchemaMigration,
    )
    from tests.integration.test_pipeline_integration import (
        TestFlextLdifFacadeWorkflows as TestFlextLdifFacadeWorkflows,
    )
    from tests.integration.test_quirks_transformations import (
        TestOidQuirksTransformations as TestOidQuirksTransformations,
        TestOudQuirksTransformations as TestOudQuirksTransformations,
        TestQuirksPropertyValidation as TestQuirksPropertyValidation,
        fixtures_dir as fixtures_dir,
        migration_inputs as migration_inputs,
    )
    from tests.integration.test_real_ldap_config import (
        TestRealLdapConfigurationFromEnv as TestRealLdapConfigurationFromEnv,
        TestRealLdapRailwayComposition as TestRealLdapRailwayComposition,
    )
    from tests.integration.test_real_ldap_crud import (
        TestRealLdapBatchOperations as TestRealLdapBatchOperations,
        TestRealLdapCRUD as TestRealLdapCRUD,
    )
    from tests.integration.test_real_ldap_export import (
        TestRealLdapExport as TestRealLdapExport,
    )
    from tests.integration.test_real_ldap_import import (
        TestRealLdapImport as TestRealLdapImport,
    )
    from tests.integration.test_real_ldap_roundtrip import (
        TestRealLdapRoundtrip as TestRealLdapRoundtrip,
    )
    from tests.integration.test_rfc_docker_real import (
        TestRfcDockerRealData as TestRfcDockerRealData,
        TestRfcIntegrationRealWorld as TestRfcIntegrationRealWorld,
    )
    from tests.integration.test_rfc_docker_real_integration import (
        TestRfcExceptionHandlingRealScenarios as TestRfcExceptionHandlingRealScenarios,
        TestRfcParserRealFixtures as TestRfcParserRealFixtures,
        TestRfcSchemaParserRealFixtures as TestRfcSchemaParserRealFixtures,
        TestRfcWriterRealFixtures as TestRfcWriterRealFixtures,
    )
    from tests.integration.test_simple_ldap import (
        test_create_and_export_entry as test_create_and_export_entry,
        test_ldap_connection as test_ldap_connection,
        test_simple_ldap_search as test_simple_ldap_search,
    )
    from tests.integration.test_systematic_fixture_coverage import (
        TestSystematicFixtureCoverage as TestSystematicFixtureCoverage,
    )
    from tests.integration.test_zero_data_loss_oid_oud import (
        TestZeroDataLossOidOud as TestZeroDataLossOidOud,
    )
    from tests.integration.test_zero_data_loss_schema import (
        TestSchemaDeviationsAttributeKeyCasing as TestSchemaDeviationsAttributeKeyCasing,
        TestSchemaDeviationsComplete as TestSchemaDeviationsComplete,
        TestSchemaDeviationsMissingSpaces as TestSchemaDeviationsMissingSpaces,
        TestSchemaDeviationsNameAliases as TestSchemaDeviationsNameAliases,
        TestSchemaDeviationsObsolete as TestSchemaDeviationsObsolete,
        TestSchemaDeviationsOriginalString as TestSchemaDeviationsOriginalString,
        TestSchemaDeviationsRoundTrip as TestSchemaDeviationsRoundTrip,
        TestSchemaDeviationsSpacing as TestSchemaDeviationsSpacing,
        TestSchemaDeviationsSyntaxQuotes as TestSchemaDeviationsSyntaxQuotes,
        TestSchemaDeviationsUtilities as TestSchemaDeviationsUtilities,
        TestSchemaDeviationsXOrigin as TestSchemaDeviationsXOrigin,
    )
    from tests.models import (
        FlextLdifTestModels as FlextLdifTestModels,
        FlextLdifTestModels as m,
    )
    from tests.protocols import (
        FlextLdifTestProtocols as FlextLdifTestProtocols,
        FlextLdifTestProtocols as p,
    )
    from tests.support import (
        conftest_factory as conftest_factory,
        ldif_data as ldif_data,
        real_services as real_services,
        test_files as test_files,
        validators as validators,
    )
    from tests.support.conftest_factory import (
        FlextLdifTestConftest as FlextLdifTestConftest,
        tk as tk,
    )
    from tests.support.ldif_data import (
        LdifSample as LdifSample,
        LdifTestData as LdifTestData,
    )
    from tests.support.real_services import (
        FlextLdifTestServiceFactory as FlextLdifTestServiceFactory,
    )
    from tests.support.test_files import FileManager as FileManager
    from tests.support.validators import (
        MockFlextUtilitiesResultHelpers as MockFlextUtilitiesResultHelpers,
        MockMatchers as MockMatchers,
        TestValidators as TestValidators,
    )
    from tests.test_factory import FlextLdifTestFactory as FlextLdifTestFactory
    from tests.test_helpers import (
        TestsFlextLdifMatchers as TestsFlextLdifMatchers,
        TestsFlextLdifTypes as TestsFlextLdifTypes,
        TestsFlextLdifValidators as TestsFlextLdifValidators,
        tf as tf,
        tm as tm,
        tt as tt,
        tv as tv,
    )
    from tests.typings import (
        FlextLdifTestTypes as FlextLdifTestTypes,
        FlextLdifTestTypes as t,
        GenericFieldsDict as GenericFieldsDict,
    )
    from tests.unit import (
        services as services,
        test_migration_pipeline as test_migration_pipeline,
        test_migration_pipeline_quirks as test_migration_pipeline_quirks,
        test_typings as test_typings,
    )
    from tests.unit.__init__ import test_version as test_version
    from tests.unit.__init__.test_version import (
        TestsFlextLdifVersion as TestsFlextLdifVersion,
        version_module as version_module,
    )
    from tests.unit._utilities.oid.test_oid_utilities import (
        TestFlextLdifUtilitiesOID as TestFlextLdifUtilitiesOID,
    )
    from tests.unit._utilities.parser.test_parser_utilities import (
        TestFlextLdifUtilitiesParser as TestFlextLdifUtilitiesParser,
    )
    from tests.unit._utilities.server.test_server_utilities import (
        OidServer as OidServer,
        OudServer as OudServer,
        TestFlextLdifUtilitiesServer as TestFlextLdifUtilitiesServer,
    )
    from tests.unit.constants import test_acl_registry as test_acl_registry
    from tests.unit.constants.test_acl_registry import (
        GetAclAttributesServerType as GetAclAttributesServerType,
        IsAclAttributeType as IsAclAttributeType,
        TestsTestFlextLdifAclAttributeRegistry as TestsTestFlextLdifAclAttributeRegistry,
    )
    from tests.unit.protocols import test_protocols as test_protocols
    from tests.unit.protocols.test_protocols import (
        TestsTestFlextLdifProtocols as TestsTestFlextLdifProtocols,
    )
    from tests.unit.quirks.servers.test_apache_quirks import (
        TestsTestFlextLdifApacheQuirks as TestsTestFlextLdifApacheQuirks,
    )
    from tests.unit.quirks.servers.test_ds389_quirks import (
        ACL_TEST_CASES as ACL_TEST_CASES,
        AclScenario as AclScenario,
        AclTestCase as AclTestCase,
        TestsTestFlextLdifDs389Quirks as TestsTestFlextLdifDs389Quirks,
    )
    from tests.unit.quirks.servers.test_edge_cases import (
        TestsFlextLdifEdgeCases as TestsFlextLdifEdgeCases,
        cleanup_state as cleanup_state,
        ldif_api as ldif_api,
    )
    from tests.unit.quirks.servers.test_novell_quirks import (
        ATTRIBUTE_TEST_CASES as ATTRIBUTE_TEST_CASES,
        ENTRY_TEST_CASES as ENTRY_TEST_CASES,
        OBJECTCLASS_TEST_CASES as OBJECTCLASS_TEST_CASES,
        AttributeScenario as AttributeScenario,
        AttributeTestCase as AttributeTestCase,
        EntryScenario as EntryScenario,
        EntryTestCase as EntryTestCase,
        ObjectClassScenario as ObjectClassScenario,
        ObjectClassTestCase as ObjectClassTestCase,
        RfcTestHelpers as RfcTestHelpers,
        TestDeduplicationHelpers as TestDeduplicationHelpers,
        TestNovellAcls as TestNovellAcls,
        TestNovellEntryDetection as TestNovellEntryDetection,
        TestNovellSchemaAttributeDetection as TestNovellSchemaAttributeDetection,
        TestNovellSchemaAttributeParsing as TestNovellSchemaAttributeParsing,
        TestNovellSchemaObjectClassDetection as TestNovellSchemaObjectClassDetection,
        TestNovellSchemaObjectClassParsing as TestNovellSchemaObjectClassParsing,
        TestsFlextLdifNovellInitialization as TestsFlextLdifNovellInitialization,
        entry_quirk as entry_quirk,
        novell_server as novell_server,
        schema_quirk as schema_quirk,
    )
    from tests.unit.quirks.servers.test_oid_quirks import (
        TestsTestFlextLdifOidQuirks as TestsTestFlextLdifOidQuirks,
    )
    from tests.unit.quirks.servers.test_relaxed_quirks import (
        ParseScenario as ParseScenario,
        TestsTestFlextLdifRelaxedQuirks as TestsTestFlextLdifRelaxedQuirks,
        WriteScenario as WriteScenario,
        meta_keys as meta_keys,
    )
    from tests.unit.quirks.servers.test_schema_transformer import (
        TestSchemaTransformerNormalizeMatchingRule as TestSchemaTransformerNormalizeMatchingRule,
        TestSchemaTransformerNormalizeSyntaxOid as TestSchemaTransformerNormalizeSyntaxOid,
        TestsFlextLdifSchemaTransformerNormalizeAttributeName as TestsFlextLdifSchemaTransformerNormalizeAttributeName,
    )
    from tests.unit.services import (
        test_quirks_standardization as test_quirks_standardization,
    )
    from tests.unit.services.test_migration_pipeline import (
        TestsTestFlextLdifMigrationPipeline as TestsTestFlextLdifMigrationPipeline,
    )
    from tests.unit.services.test_quirks_standardization import (
        TestAliasDiscovery as TestAliasDiscovery,
        TestQuirksAutoInterchange as TestQuirksAutoInterchange,
        TestQuirksWithRealLdifFixtures as TestQuirksWithRealLdifFixtures,
        TestsFlextLdifQuirksStandardizedConstants as TestsFlextLdifQuirksStandardizedConstants,
    )
    from tests.unit.test_migration_pipeline import (
        TestsFlextLdifMigrationPipeline as TestsFlextLdifMigrationPipeline,
    )
    from tests.unit.test_migration_pipeline_quirks import (
        OidTestConstants as OidTestConstants,
        TestsFlextLdifMigrationPipelineQuirks as TestsFlextLdifMigrationPipelineQuirks,
    )
    from tests.unit.test_typings import (
        TestFlextLdifTypesStructure as TestFlextLdifTypesStructure,
        TestIntegrationWithLdifFixtures as TestIntegrationWithLdifFixtures,
        TestModelsNamespace as TestModelsNamespace,
        TestPhase1StandardizationResults as TestPhase1StandardizationResults,
        TestRemovalOfOverEngineering as TestRemovalOfOverEngineering,
        TestsFlextLdifCommonDictionaryTypes as TestsFlextLdifCommonDictionaryTypes,
    )
    from tests.unit.utilities import (
        test_utilities_comprehensive as test_utilities_comprehensive,
        test_utilities_core as test_utilities_core,
    )
    from tests.unit.utilities.test_utilities_comprehensive import (
        TestFlextLdifUtilitiesComprehensive as TestFlextLdifUtilitiesComprehensive,
    )
    from tests.unit.utilities.test_utilities_core import (
        TestAttributeFixer as TestAttributeFixer,
        TestDnObjectClassMethods as TestDnObjectClassMethods,
        TestLdifParser as TestLdifParser,
        TestObjectClassUtilities as TestObjectClassUtilities,
        TestServerTypes as TestServerTypes,
        TestsFlextLdifDnOperationsPure as TestsFlextLdifDnOperationsPure,
    )
    from tests.utilities import (
        FlextLdifTestUtilities as FlextLdifTestUtilities,
        FlextLdifTestUtilities as u,
    )

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "ACL_TEST_CASES": ["tests.unit.quirks.servers.test_ds389_quirks", "ACL_TEST_CASES"],
    "APIScenarios": ["tests.integration.test_api_integration", "APIScenarios"],
    "ATTRIBUTE_TEST_CASES": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "ATTRIBUTE_TEST_CASES",
    ],
    "AclScenario": ["tests.unit.quirks.servers.test_ds389_quirks", "AclScenario"],
    "AclTestCase": ["tests.unit.quirks.servers.test_ds389_quirks", "AclTestCase"],
    "AttributeScenario": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "AttributeScenario",
    ],
    "AttributeTestCase": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "AttributeTestCase",
    ],
    "ConfigTestData": ["tests.integration.test_config_integration", "ConfigTestData"],
    "ENTRY_TEST_CASES": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "ENTRY_TEST_CASES",
    ],
    "EntryScenario": ["tests.unit.quirks.servers.test_novell_quirks", "EntryScenario"],
    "EntryTestCase": ["tests.unit.quirks.servers.test_novell_quirks", "EntryTestCase"],
    "FIXTURES_DIR": ["tests.conftest", "FIXTURES_DIR"],
    "FileManager": ["tests.support.test_files", "FileManager"],
    "FlextLdifFixtures": ["tests.conftest", "FlextLdifFixtures"],
    "FlextLdifTestConftest": [
        "tests.support.conftest_factory",
        "FlextLdifTestConftest",
    ],
    "FlextLdifTestConstants": ["tests.constants", "FlextLdifTestConstants"],
    "FlextLdifTestFactory": ["tests.test_factory", "FlextLdifTestFactory"],
    "FlextLdifTestModels": ["tests.models", "FlextLdifTestModels"],
    "FlextLdifTestProtocols": ["tests.protocols", "FlextLdifTestProtocols"],
    "FlextLdifTestServiceFactory": [
        "tests.support.real_services",
        "FlextLdifTestServiceFactory",
    ],
    "FlextLdifTestTypes": ["tests.typings", "FlextLdifTestTypes"],
    "FlextLdifTestUtilities": ["tests.utilities", "FlextLdifTestUtilities"],
    "FlextLdifTestsServiceBase": ["tests.base", "FlextLdifTestsServiceBase"],
    "GenericFieldsDict": ["tests.typings", "GenericFieldsDict"],
    "GetAclAttributesServerType": [
        "tests.unit.constants.test_acl_registry",
        "GetAclAttributesServerType",
    ],
    "IsAclAttributeType": [
        "tests.unit.constants.test_acl_registry",
        "IsAclAttributeType",
    ],
    "LdifSample": ["tests.support.ldif_data", "LdifSample"],
    "LdifTestData": ["tests.support.ldif_data", "LdifTestData"],
    "MockFlextUtilitiesResultHelpers": [
        "tests.support.validators",
        "MockFlextUtilitiesResultHelpers",
    ],
    "MockMatchers": ["tests.support.validators", "MockMatchers"],
    "OBJECTCLASS_TEST_CASES": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "OBJECTCLASS_TEST_CASES",
    ],
    "OID_FIXTURES_DIR": ["tests.conftest", "OID_FIXTURES_DIR"],
    "ObjectClassScenario": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "ObjectClassScenario",
    ],
    "ObjectClassTestCase": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "ObjectClassTestCase",
    ],
    "OidServer": ["tests.unit._utilities.server.test_server_utilities", "OidServer"],
    "OidTestConstants": [
        "tests.unit.test_migration_pipeline_quirks",
        "OidTestConstants",
    ],
    "OudServer": ["tests.unit._utilities.server.test_server_utilities", "OudServer"],
    "ParseScenario": ["tests.unit.quirks.servers.test_relaxed_quirks", "ParseScenario"],
    "RfcTestHelpers": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "RfcTestHelpers",
    ],
    "TestAclRoundTripPreservation": [
        "tests.integration.test_acl_metadata_preservation",
        "TestAclRoundTripPreservation",
    ],
    "TestAliasDiscovery": [
        "tests.unit.services.test_quirks_standardization",
        "TestAliasDiscovery",
    ],
    "TestAttributeFixer": [
        "tests.unit.utilities.test_utilities_core",
        "TestAttributeFixer",
    ],
    "TestBoundaryValues": ["tests.integration.test_edge_cases", "TestBoundaryValues"],
    "TestCategorizationRealData": [
        "tests.integration.test_categorization_real_data",
        "TestCategorizationRealData",
    ],
    "TestData": ["tests.integration.test_api_integration", "TestData"],
    "TestDeduplicationHelpers": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestDeduplicationHelpers",
    ],
    "TestDnCaseNormalizationScenarios": [
        "tests.integration.test_dn_case_handling",
        "TestDnCaseNormalizationScenarios",
    ],
    "TestDnCaseRegistry": [
        "tests.integration.test_dn_case_handling",
        "TestDnCaseRegistry",
    ],
    "TestDnObjectClassMethods": [
        "tests.unit.utilities.test_utilities_core",
        "TestDnObjectClassMethods",
    ],
    "TestEmptyAndMinimalCases": [
        "tests.integration.test_edge_cases",
        "TestEmptyAndMinimalCases",
    ],
    "TestEncodingErrors": [
        "tests.integration.test_error_recovery",
        "TestEncodingErrors",
    ],
    "TestFlextLdifAPIIntegration": [
        "tests.integration.test_api_integration",
        "TestFlextLdifAPIIntegration",
    ],
    "TestFlextLdifFacadeWorkflows": [
        "tests.integration.test_pipeline_integration",
        "TestFlextLdifFacadeWorkflows",
    ],
    "TestFlextLdifSettingsIntegration": [
        "tests.integration.test_config_integration",
        "TestFlextLdifSettingsIntegration",
    ],
    "TestFlextLdifTypesStructure": [
        "tests.unit.test_typings",
        "TestFlextLdifTypesStructure",
    ],
    "TestFlextLdifUtilitiesComprehensive": [
        "tests.unit.utilities.test_utilities_comprehensive",
        "TestFlextLdifUtilitiesComprehensive",
    ],
    "TestFlextLdifUtilitiesOID": [
        "tests.unit._utilities.oid.test_oid_utilities",
        "TestFlextLdifUtilitiesOID",
    ],
    "TestFlextLdifUtilitiesParser": [
        "tests.unit._utilities.parser.test_parser_utilities",
        "TestFlextLdifUtilitiesParser",
    ],
    "TestFlextLdifUtilitiesServer": [
        "tests.unit._utilities.server.test_server_utilities",
        "TestFlextLdifUtilitiesServer",
    ],
    "TestIncompleteEntries": [
        "tests.integration.test_error_recovery",
        "TestIncompleteEntries",
    ],
    "TestIntegrationWithLdifFixtures": [
        "tests.unit.test_typings",
        "TestIntegrationWithLdifFixtures",
    ],
    "TestInvalidSchemaDefinitions": [
        "tests.integration.test_error_recovery",
        "TestInvalidSchemaDefinitions",
    ],
    "TestLargeAndComplexCases": [
        "tests.integration.test_edge_cases",
        "TestLargeAndComplexCases",
    ],
    "TestLdifParser": ["tests.unit.utilities.test_utilities_core", "TestLdifParser"],
    "TestMalformedLdifHandling": [
        "tests.integration.test_error_recovery",
        "TestMalformedLdifHandling",
    ],
    "TestMinimalDifferencesOidOud": [
        "tests.integration.test_minimal_differences_metadata",
        "TestMinimalDifferencesOidOud",
    ],
    "TestModelsNamespace": ["tests.unit.test_typings", "TestModelsNamespace"],
    "TestNovellAcls": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellAcls",
    ],
    "TestNovellEntryDetection": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellEntryDetection",
    ],
    "TestNovellSchemaAttributeDetection": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellSchemaAttributeDetection",
    ],
    "TestNovellSchemaAttributeParsing": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellSchemaAttributeParsing",
    ],
    "TestNovellSchemaObjectClassDetection": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellSchemaObjectClassDetection",
    ],
    "TestNovellSchemaObjectClassParsing": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellSchemaObjectClassParsing",
    ],
    "TestObjectClassUtilities": [
        "tests.unit.utilities.test_utilities_core",
        "TestObjectClassUtilities",
    ],
    "TestOidAclMetadataPreservation": [
        "tests.integration.test_acl_metadata_preservation",
        "TestOidAclMetadataPreservation",
    ],
    "TestOidEntryIntegration": [
        "tests.integration.test_oid_integration",
        "TestOidEntryIntegration",
    ],
    "TestOidQuirksTransformations": [
        "tests.integration.test_quirks_transformations",
        "TestOidQuirksTransformations",
    ],
    "TestOidRoundTripIntegration": [
        "tests.integration.test_oid_integration",
        "TestOidRoundTripIntegration",
    ],
    "TestOidSchemaIntegration": [
        "tests.integration.test_oid_integration",
        "TestOidSchemaIntegration",
    ],
    "TestOidToOudAclConversion": [
        "tests.integration.test_cross_quirk_conversion",
        "TestOidToOudAclConversion",
    ],
    "TestOidToOudIntegrationConversion": [
        "tests.integration.test_cross_quirk_conversion",
        "TestOidToOudIntegrationConversion",
    ],
    "TestOidToOudSchemaConversion": [
        "tests.integration.test_cross_quirk_conversion",
        "TestOidToOudSchemaConversion",
    ],
    "TestOudAciMetadataPreservation": [
        "tests.integration.test_acl_metadata_preservation",
        "TestOudAciMetadataPreservation",
    ],
    "TestOudAclIntegration": [
        "tests.integration.test_oud_integration",
        "TestOudAclIntegration",
    ],
    "TestOudEntryIntegration": [
        "tests.integration.test_oud_integration",
        "TestOudEntryIntegration",
    ],
    "TestOudMetadataPreservation": [
        "tests.integration.test_oud_integration",
        "TestOudMetadataPreservation",
    ],
    "TestOudQuirksTransformations": [
        "tests.integration.test_quirks_transformations",
        "TestOudQuirksTransformations",
    ],
    "TestOudRoundTripIntegration": [
        "tests.integration.test_oud_integration",
        "TestOudRoundTripIntegration",
    ],
    "TestOudSchemaIntegration": [
        "tests.integration.test_oud_integration",
        "TestOudSchemaIntegration",
    ],
    "TestOudToOidAclMigration": [
        "tests.integration.test_oud_to_oid_migration",
        "TestOudToOidAclMigration",
    ],
    "TestOudToOidEntryMigration": [
        "tests.integration.test_oud_to_oid_migration",
        "TestOudToOidEntryMigration",
    ],
    "TestOudToOidFullMigration": [
        "tests.integration.test_oud_to_oid_migration",
        "TestOudToOidFullMigration",
    ],
    "TestOudToOidSchemaMigration": [
        "tests.integration.test_oud_to_oid_migration",
        "TestOudToOidSchemaMigration",
    ],
    "TestPhase1StandardizationResults": [
        "tests.unit.test_typings",
        "TestPhase1StandardizationResults",
    ],
    "TestQuirksAutoInterchange": [
        "tests.unit.services.test_quirks_standardization",
        "TestQuirksAutoInterchange",
    ],
    "TestQuirksConversionMatrixFacade": [
        "tests.integration.test_cross_quirk_conversion",
        "TestQuirksConversionMatrixFacade",
    ],
    "TestQuirksPropertyValidation": [
        "tests.integration.test_quirks_transformations",
        "TestQuirksPropertyValidation",
    ],
    "TestQuirksWithRealLdifFixtures": [
        "tests.unit.services.test_quirks_standardization",
        "TestQuirksWithRealLdifFixtures",
    ],
    "TestRealLdapBatchOperations": [
        "tests.integration.test_real_ldap_crud",
        "TestRealLdapBatchOperations",
    ],
    "TestRealLdapCRUD": ["tests.integration.test_real_ldap_crud", "TestRealLdapCRUD"],
    "TestRealLdapConfigurationFromEnv": [
        "tests.integration.test_real_ldap_config",
        "TestRealLdapConfigurationFromEnv",
    ],
    "TestRealLdapExport": [
        "tests.integration.test_real_ldap_export",
        "TestRealLdapExport",
    ],
    "TestRealLdapImport": [
        "tests.integration.test_real_ldap_import",
        "TestRealLdapImport",
    ],
    "TestRealLdapRailwayComposition": [
        "tests.integration.test_real_ldap_config",
        "TestRealLdapRailwayComposition",
    ],
    "TestRealLdapRoundtrip": [
        "tests.integration.test_real_ldap_roundtrip",
        "TestRealLdapRoundtrip",
    ],
    "TestRemovalOfOverEngineering": [
        "tests.unit.test_typings",
        "TestRemovalOfOverEngineering",
    ],
    "TestRfcDockerRealData": [
        "tests.integration.test_rfc_docker_real",
        "TestRfcDockerRealData",
    ],
    "TestRfcExceptionHandlingRealScenarios": [
        "tests.integration.test_rfc_docker_real_integration",
        "TestRfcExceptionHandlingRealScenarios",
    ],
    "TestRfcIntegrationRealWorld": [
        "tests.integration.test_rfc_docker_real",
        "TestRfcIntegrationRealWorld",
    ],
    "TestRfcParserRealFixtures": [
        "tests.integration.test_rfc_docker_real_integration",
        "TestRfcParserRealFixtures",
    ],
    "TestRfcSchemaParserRealFixtures": [
        "tests.integration.test_rfc_docker_real_integration",
        "TestRfcSchemaParserRealFixtures",
    ],
    "TestRfcWriterRealFixtures": [
        "tests.integration.test_rfc_docker_real_integration",
        "TestRfcWriterRealFixtures",
    ],
    "TestRoundtripEdgeCases": [
        "tests.integration.test_edge_cases",
        "TestRoundtripEdgeCases",
    ],
    "TestSchemaDeviationsAttributeKeyCasing": [
        "tests.integration.test_zero_data_loss_schema",
        "TestSchemaDeviationsAttributeKeyCasing",
    ],
    "TestSchemaDeviationsComplete": [
        "tests.integration.test_zero_data_loss_schema",
        "TestSchemaDeviationsComplete",
    ],
    "TestSchemaDeviationsMissingSpaces": [
        "tests.integration.test_zero_data_loss_schema",
        "TestSchemaDeviationsMissingSpaces",
    ],
    "TestSchemaDeviationsNameAliases": [
        "tests.integration.test_zero_data_loss_schema",
        "TestSchemaDeviationsNameAliases",
    ],
    "TestSchemaDeviationsObsolete": [
        "tests.integration.test_zero_data_loss_schema",
        "TestSchemaDeviationsObsolete",
    ],
    "TestSchemaDeviationsOriginalString": [
        "tests.integration.test_zero_data_loss_schema",
        "TestSchemaDeviationsOriginalString",
    ],
    "TestSchemaDeviationsRoundTrip": [
        "tests.integration.test_zero_data_loss_schema",
        "TestSchemaDeviationsRoundTrip",
    ],
    "TestSchemaDeviationsSpacing": [
        "tests.integration.test_zero_data_loss_schema",
        "TestSchemaDeviationsSpacing",
    ],
    "TestSchemaDeviationsSyntaxQuotes": [
        "tests.integration.test_zero_data_loss_schema",
        "TestSchemaDeviationsSyntaxQuotes",
    ],
    "TestSchemaDeviationsUtilities": [
        "tests.integration.test_zero_data_loss_schema",
        "TestSchemaDeviationsUtilities",
    ],
    "TestSchemaDeviationsXOrigin": [
        "tests.integration.test_zero_data_loss_schema",
        "TestSchemaDeviationsXOrigin",
    ],
    "TestSchemaTransformerNormalizeMatchingRule": [
        "tests.unit.quirks.servers.test_schema_transformer",
        "TestSchemaTransformerNormalizeMatchingRule",
    ],
    "TestSchemaTransformerNormalizeSyntaxOid": [
        "tests.unit.quirks.servers.test_schema_transformer",
        "TestSchemaTransformerNormalizeSyntaxOid",
    ],
    "TestServerTypes": ["tests.unit.utilities.test_utilities_core", "TestServerTypes"],
    "TestSystematicFixtureCoverage": [
        "tests.integration.test_systematic_fixture_coverage",
        "TestSystematicFixtureCoverage",
    ],
    "TestUnicodeBoundaries": [
        "tests.integration.test_edge_cases",
        "TestUnicodeBoundaries",
    ],
    "TestValidators": ["tests.support.validators", "TestValidators"],
    "TestZeroDataLossOidOud": [
        "tests.integration.test_zero_data_loss_oid_oud",
        "TestZeroDataLossOidOud",
    ],
    "TestsFlextLdifCommonDictionaryTypes": [
        "tests.unit.test_typings",
        "TestsFlextLdifCommonDictionaryTypes",
    ],
    "TestsFlextLdifDnOperationsPure": [
        "tests.unit.utilities.test_utilities_core",
        "TestsFlextLdifDnOperationsPure",
    ],
    "TestsFlextLdifEdgeCases": [
        "tests.unit.quirks.servers.test_edge_cases",
        "TestsFlextLdifEdgeCases",
    ],
    "TestsFlextLdifFixtures": [
        "tests.integration.test_ldif_fixtures_integration",
        "TestsFlextLdifFixtures",
    ],
    "TestsFlextLdifMatchers": ["tests.test_helpers", "TestsFlextLdifMatchers"],
    "TestsFlextLdifMigrationPipeline": [
        "tests.unit.test_migration_pipeline",
        "TestsFlextLdifMigrationPipeline",
    ],
    "TestsFlextLdifMigrationPipelineQuirks": [
        "tests.unit.test_migration_pipeline_quirks",
        "TestsFlextLdifMigrationPipelineQuirks",
    ],
    "TestsFlextLdifNovellInitialization": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestsFlextLdifNovellInitialization",
    ],
    "TestsFlextLdifQuirksStandardizedConstants": [
        "tests.unit.services.test_quirks_standardization",
        "TestsFlextLdifQuirksStandardizedConstants",
    ],
    "TestsFlextLdifSchemaTransformerNormalizeAttributeName": [
        "tests.unit.quirks.servers.test_schema_transformer",
        "TestsFlextLdifSchemaTransformerNormalizeAttributeName",
    ],
    "TestsFlextLdifTypes": ["tests.test_helpers", "TestsFlextLdifTypes"],
    "TestsFlextLdifValidators": ["tests.test_helpers", "TestsFlextLdifValidators"],
    "TestsFlextLdifVersion": [
        "tests.unit.__init__.test_version",
        "TestsFlextLdifVersion",
    ],
    "TestsTestFlextLdifAclAttributeRegistry": [
        "tests.unit.constants.test_acl_registry",
        "TestsTestFlextLdifAclAttributeRegistry",
    ],
    "TestsTestFlextLdifApacheQuirks": [
        "tests.unit.quirks.servers.test_apache_quirks",
        "TestsTestFlextLdifApacheQuirks",
    ],
    "TestsTestFlextLdifDs389Quirks": [
        "tests.unit.quirks.servers.test_ds389_quirks",
        "TestsTestFlextLdifDs389Quirks",
    ],
    "TestsTestFlextLdifMigrationPipeline": [
        "tests.unit.services.test_migration_pipeline",
        "TestsTestFlextLdifMigrationPipeline",
    ],
    "TestsTestFlextLdifOidQuirks": [
        "tests.unit.quirks.servers.test_oid_quirks",
        "TestsTestFlextLdifOidQuirks",
    ],
    "TestsTestFlextLdifProtocols": [
        "tests.unit.protocols.test_protocols",
        "TestsTestFlextLdifProtocols",
    ],
    "TestsTestFlextLdifRelaxedQuirks": [
        "tests.unit.quirks.servers.test_relaxed_quirks",
        "TestsTestFlextLdifRelaxedQuirks",
    ],
    "WORKSPACE_ROOT": ["tests.integration.conftest", "WORKSPACE_ROOT"],
    "WriteScenario": ["tests.unit.quirks.servers.test_relaxed_quirks", "WriteScenario"],
    "all_acl_fixtures": ["tests.integration.conftest", "all_acl_fixtures"],
    "all_entries_fixtures": ["tests.integration.conftest", "all_entries_fixtures"],
    "all_integration_fixtures": [
        "tests.integration.conftest",
        "all_integration_fixtures",
    ],
    "all_schema_fixtures": ["tests.integration.conftest", "all_schema_fixtures"],
    "api": ["tests.integration.conftest", "api"],
    "base": ["tests.base", ""],
    "c": ["tests.constants", "FlextLdifTestConstants"],
    "clean_test_ou": ["tests.integration.conftest", "clean_test_ou"],
    "cleanup_state": ["tests.unit.quirks.servers.test_edge_cases", "cleanup_state"],
    "conftest": ["tests.conftest", ""],
    "conftest_factory": ["tests.support.conftest_factory", ""],
    "conftest_shared": ["tests.conftest_shared", ""],
    "constants": ["tests.constants", ""],
    "conversion_matrix": ["tests.integration.conftest", "conversion_matrix"],
    "d": ["flext_tests", "d"],
    "e": ["flext_tests", "e"],
    "e2e": ["tests.e2e", ""],
    "entry_quirk": ["tests.unit.quirks.servers.test_novell_quirks", "entry_quirk"],
    "example_refactoring": ["tests.helpers.example_refactoring", ""],
    "fixtures_dir": ["tests.integration.test_quirks_transformations", "fixtures_dir"],
    "flext_ldif": ["tests.conftest", "flext_ldif"],
    "h": ["flext_tests", "h"],
    "helpers": ["tests.helpers", ""],
    "integration": ["tests.integration", ""],
    "large_test_dataset": ["tests.conftest_shared", "large_test_dataset"],
    "ldap_connection": ["tests.integration.conftest", "ldap_connection"],
    "ldap_container": ["tests.integration.conftest", "ldap_container"],
    "ldap_container_shared": ["tests.integration.conftest", "ldap_container_shared"],
    "ldif_api": ["tests.unit.quirks.servers.test_edge_cases", "ldif_api"],
    "ldif_data": ["tests.support.ldif_data", ""],
    "ldif_parser": ["tests.conftest", "ldif_parser"],
    "ldif_writer": ["tests.conftest", "ldif_writer"],
    "logger": ["tests.integration.test_config_integration", "logger"],
    "m": ["tests.models", "FlextLdifTestModels"],
    "make_test_base_dn": ["tests.integration.conftest", "make_test_base_dn"],
    "make_test_username": ["tests.integration.conftest", "make_test_username"],
    "meta_keys": ["tests.unit.quirks.servers.test_relaxed_quirks", "meta_keys"],
    "migration_inputs": [
        "tests.integration.test_quirks_transformations",
        "migration_inputs",
    ],
    "models": ["tests.models", ""],
    "novell_server": ["tests.unit.quirks.servers.test_novell_quirks", "novell_server"],
    "oid_acl_fixture": ["tests.integration.conftest", "oid_acl_fixture"],
    "oid_acl_quirk": ["tests.integration.conftest", "oid_acl_quirk"],
    "oid_entries": ["tests.integration.conftest", "oid_entries"],
    "oid_entries_fixture": ["tests.integration.conftest", "oid_entries_fixture"],
    "oid_integration_fixture": [
        "tests.integration.conftest",
        "oid_integration_fixture",
    ],
    "oid_quirk": ["tests.integration.conftest", "oid_quirk"],
    "oid_schema_entries": ["tests.integration.conftest", "oid_schema_entries"],
    "oid_schema_fixture": ["tests.integration.conftest", "oid_schema_fixture"],
    "oid_schema_quirk": ["tests.integration.conftest", "oid_schema_quirk"],
    "openldap_acl_fixture": ["tests.integration.conftest", "openldap_acl_fixture"],
    "openldap_entries": ["tests.integration.conftest", "openldap_entries"],
    "openldap_entries_fixture": [
        "tests.integration.conftest",
        "openldap_entries_fixture",
    ],
    "openldap_integration_fixture": [
        "tests.integration.conftest",
        "openldap_integration_fixture",
    ],
    "openldap_schema_entries": [
        "tests.integration.conftest",
        "openldap_schema_entries",
    ],
    "openldap_schema_fixture": [
        "tests.integration.conftest",
        "openldap_schema_fixture",
    ],
    "oud_acl_fixture": ["tests.integration.conftest", "oud_acl_fixture"],
    "oud_acl_quirk": ["tests.integration.conftest", "oud_acl_quirk"],
    "oud_entries": ["tests.integration.conftest", "oud_entries"],
    "oud_entries_fixture": ["tests.integration.conftest", "oud_entries_fixture"],
    "oud_integration_fixture": [
        "tests.integration.conftest",
        "oud_integration_fixture",
    ],
    "oud_quirk": ["tests.integration.conftest", "oud_quirk"],
    "oud_schema_entries": ["tests.integration.conftest", "oud_schema_entries"],
    "oud_schema_fixture": ["tests.integration.conftest", "oud_schema_fixture"],
    "oud_schema_quirk": ["tests.integration.conftest", "oud_schema_quirk"],
    "p": ["tests.protocols", "FlextLdifTestProtocols"],
    "parametrized_real_data": ["tests.conftest_shared", "parametrized_real_data"],
    "parser": ["tests.integration.conftest", "parser"],
    "protocols": ["tests.protocols", ""],
    "pytest_configure": ["tests.conftest", "pytest_configure"],
    "r": ["flext_tests", "r"],
    "real_entry": ["tests.conftest_shared", "real_entry"],
    "real_ldif_content": ["tests.conftest_shared", "real_ldif_content"],
    "real_ldif_group_entry": ["tests.conftest", "real_ldif_group_entry"],
    "real_ldif_multiple_entries": ["tests.conftest", "real_ldif_multiple_entries"],
    "real_ldif_user_entry": ["tests.conftest", "real_ldif_user_entry"],
    "real_services": ["tests.support.real_services", ""],
    "rfc_schema_entries": ["tests.integration.conftest", "rfc_schema_entries"],
    "rfc_schema_fixture": ["tests.integration.conftest", "rfc_schema_fixture"],
    "s": ["tests.base", "s"],
    "sample_ldif_entries": ["tests.conftest", "sample_ldif_entries"],
    "schema_quirk": ["tests.unit.quirks.servers.test_novell_quirks", "schema_quirk"],
    "server": ["tests.integration.conftest", "server"],
    "services": ["tests.unit.services", ""],
    "support": ["tests.support", ""],
    "t": ["tests.typings", "FlextLdifTestTypes"],
    "temp_file": ["tests.conftest", "temp_file"],
    "test_acl_metadata_preservation": [
        "tests.integration.test_acl_metadata_preservation",
        "",
    ],
    "test_acl_registry": ["tests.unit.constants.test_acl_registry", ""],
    "test_api_integration": ["tests.integration.test_api_integration", ""],
    "test_categorization_real_data": [
        "tests.integration.test_categorization_real_data",
        "",
    ],
    "test_config_integration": ["tests.integration.test_config_integration", ""],
    "test_create_and_export_entry": [
        "tests.integration.test_simple_ldap",
        "test_create_and_export_entry",
    ],
    "test_cross_quirk_conversion": [
        "tests.integration.test_cross_quirk_conversion",
        "",
    ],
    "test_dn_case_handling": ["tests.integration.test_dn_case_handling", ""],
    "test_edge_cases": ["tests.integration.test_edge_cases", ""],
    "test_enterprise": ["tests.e2e.test_enterprise", ""],
    "test_error_recovery": ["tests.integration.test_error_recovery", ""],
    "test_factory": ["tests.test_factory", ""],
    "test_files": ["tests.support.test_files", ""],
    "test_helpers": ["tests.test_helpers", ""],
    "test_ldap_connection": [
        "tests.integration.test_simple_ldap",
        "test_ldap_connection",
    ],
    "test_ldif_fixtures_integration": [
        "tests.integration.test_ldif_fixtures_integration",
        "",
    ],
    "test_migration_pipeline": ["tests.unit.test_migration_pipeline", ""],
    "test_migration_pipeline_quirks": ["tests.unit.test_migration_pipeline_quirks", ""],
    "test_minimal_differences_metadata": [
        "tests.integration.test_minimal_differences_metadata",
        "",
    ],
    "test_oid_integration": ["tests.integration.test_oid_integration", ""],
    "test_oud_integration": ["tests.integration.test_oud_integration", ""],
    "test_oud_to_oid_migration": ["tests.integration.test_oud_to_oid_migration", ""],
    "test_pipeline_integration": ["tests.integration.test_pipeline_integration", ""],
    "test_protocols": ["tests.unit.protocols.test_protocols", ""],
    "test_quirks_standardization": [
        "tests.unit.services.test_quirks_standardization",
        "",
    ],
    "test_quirks_transformations": [
        "tests.integration.test_quirks_transformations",
        "",
    ],
    "test_real_ldap_config": ["tests.integration.test_real_ldap_config", ""],
    "test_real_ldap_crud": ["tests.integration.test_real_ldap_crud", ""],
    "test_real_ldap_export": ["tests.integration.test_real_ldap_export", ""],
    "test_real_ldap_import": ["tests.integration.test_real_ldap_import", ""],
    "test_real_ldap_roundtrip": ["tests.integration.test_real_ldap_roundtrip", ""],
    "test_rfc_docker_real": ["tests.integration.test_rfc_docker_real", ""],
    "test_rfc_docker_real_integration": [
        "tests.integration.test_rfc_docker_real_integration",
        "",
    ],
    "test_simple_ldap": ["tests.integration.test_simple_ldap", ""],
    "test_simple_ldap_search": [
        "tests.integration.test_simple_ldap",
        "test_simple_ldap_search",
    ],
    "test_systematic_fixture_coverage": [
        "tests.integration.test_systematic_fixture_coverage",
        "",
    ],
    "test_typings": ["tests.unit.test_typings", ""],
    "test_utilities_comprehensive": [
        "tests.unit.utilities.test_utilities_comprehensive",
        "",
    ],
    "test_utilities_core": ["tests.unit.utilities.test_utilities_core", ""],
    "test_version": ["tests.unit.__init__.test_version", ""],
    "test_zero_data_loss_oid_oud": [
        "tests.integration.test_zero_data_loss_oid_oud",
        "",
    ],
    "test_zero_data_loss_schema": ["tests.integration.test_zero_data_loss_schema", ""],
    "tf": ["tests.test_helpers", "tf"],
    "tk": ["tests.support.conftest_factory", "tk"],
    "tm": ["tests.test_helpers", "tm"],
    "tmp_ldif_path": ["tests.integration.conftest", "tmp_ldif_path"],
    "tt": ["tests.test_helpers", "tt"],
    "tv": ["tests.test_helpers", "tv"],
    "typings": ["tests.typings", ""],
    "u": ["tests.utilities", "FlextLdifTestUtilities"],
    "unique_dn_suffix": ["tests.integration.conftest", "unique_dn_suffix"],
    "unit": ["tests.unit", ""],
    "utilities": ["tests.utilities", ""],
    "validators": ["tests.support.validators", ""],
    "version_module": ["tests.unit.__init__.test_version", "version_module"],
    "writer": ["tests.integration.conftest", "writer"],
    "x": ["flext_tests", "x"],
}

_EXPORTS: Sequence[str] = [
    "ACL_TEST_CASES",
    "APIScenarios",
    "ATTRIBUTE_TEST_CASES",
    "AclScenario",
    "AclTestCase",
    "AttributeScenario",
    "AttributeTestCase",
    "ConfigTestData",
    "ENTRY_TEST_CASES",
    "EntryScenario",
    "EntryTestCase",
    "FIXTURES_DIR",
    "FileManager",
    "FlextLdifFixtures",
    "FlextLdifTestConftest",
    "FlextLdifTestConstants",
    "FlextLdifTestFactory",
    "FlextLdifTestModels",
    "FlextLdifTestProtocols",
    "FlextLdifTestServiceFactory",
    "FlextLdifTestTypes",
    "FlextLdifTestUtilities",
    "FlextLdifTestsServiceBase",
    "GenericFieldsDict",
    "GetAclAttributesServerType",
    "IsAclAttributeType",
    "LdifSample",
    "LdifTestData",
    "MockFlextUtilitiesResultHelpers",
    "MockMatchers",
    "OBJECTCLASS_TEST_CASES",
    "OID_FIXTURES_DIR",
    "ObjectClassScenario",
    "ObjectClassTestCase",
    "OidServer",
    "OidTestConstants",
    "OudServer",
    "ParseScenario",
    "RfcTestHelpers",
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
    "TestValidators",
    "TestZeroDataLossOidOud",
    "TestsFlextLdifCommonDictionaryTypes",
    "TestsFlextLdifDnOperationsPure",
    "TestsFlextLdifEdgeCases",
    "TestsFlextLdifFixtures",
    "TestsFlextLdifMatchers",
    "TestsFlextLdifMigrationPipeline",
    "TestsFlextLdifMigrationPipelineQuirks",
    "TestsFlextLdifNovellInitialization",
    "TestsFlextLdifQuirksStandardizedConstants",
    "TestsFlextLdifSchemaTransformerNormalizeAttributeName",
    "TestsFlextLdifTypes",
    "TestsFlextLdifValidators",
    "TestsFlextLdifVersion",
    "TestsTestFlextLdifAclAttributeRegistry",
    "TestsTestFlextLdifApacheQuirks",
    "TestsTestFlextLdifDs389Quirks",
    "TestsTestFlextLdifMigrationPipeline",
    "TestsTestFlextLdifOidQuirks",
    "TestsTestFlextLdifProtocols",
    "TestsTestFlextLdifRelaxedQuirks",
    "WORKSPACE_ROOT",
    "WriteScenario",
    "all_acl_fixtures",
    "all_entries_fixtures",
    "all_integration_fixtures",
    "all_schema_fixtures",
    "api",
    "base",
    "c",
    "clean_test_ou",
    "cleanup_state",
    "conftest",
    "conftest_factory",
    "conftest_shared",
    "constants",
    "conversion_matrix",
    "d",
    "e",
    "e2e",
    "entry_quirk",
    "example_refactoring",
    "fixtures_dir",
    "flext_ldif",
    "h",
    "helpers",
    "integration",
    "large_test_dataset",
    "ldap_connection",
    "ldap_container",
    "ldap_container_shared",
    "ldif_api",
    "ldif_data",
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
    "real_services",
    "rfc_schema_entries",
    "rfc_schema_fixture",
    "s",
    "sample_ldif_entries",
    "schema_quirk",
    "server",
    "services",
    "support",
    "t",
    "temp_file",
    "test_acl_metadata_preservation",
    "test_acl_registry",
    "test_api_integration",
    "test_categorization_real_data",
    "test_config_integration",
    "test_create_and_export_entry",
    "test_cross_quirk_conversion",
    "test_dn_case_handling",
    "test_edge_cases",
    "test_enterprise",
    "test_error_recovery",
    "test_factory",
    "test_files",
    "test_helpers",
    "test_ldap_connection",
    "test_ldif_fixtures_integration",
    "test_migration_pipeline",
    "test_migration_pipeline_quirks",
    "test_minimal_differences_metadata",
    "test_oid_integration",
    "test_oud_integration",
    "test_oud_to_oid_migration",
    "test_pipeline_integration",
    "test_protocols",
    "test_quirks_standardization",
    "test_quirks_transformations",
    "test_real_ldap_config",
    "test_real_ldap_crud",
    "test_real_ldap_export",
    "test_real_ldap_import",
    "test_real_ldap_roundtrip",
    "test_rfc_docker_real",
    "test_rfc_docker_real_integration",
    "test_simple_ldap",
    "test_simple_ldap_search",
    "test_systematic_fixture_coverage",
    "test_typings",
    "test_utilities_comprehensive",
    "test_utilities_core",
    "test_version",
    "test_zero_data_loss_oid_oud",
    "test_zero_data_loss_schema",
    "tf",
    "tk",
    "tm",
    "tmp_ldif_path",
    "tt",
    "tv",
    "typings",
    "u",
    "unique_dn_suffix",
    "unit",
    "utilities",
    "validators",
    "version_module",
    "writer",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
