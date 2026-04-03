# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests package."""

from __future__ import annotations

import typing as _t

from flext_core.decorators import FlextDecorators as d
from flext_core.exceptions import FlextExceptions as e
from flext_core.handlers import FlextHandlers as h
from flext_core.lazy import install_lazy_exports, merge_lazy_imports
from flext_core.mixins import FlextMixins as x
from flext_core.result import FlextResult as r
from tests.base import FlextLdifTestsServiceBase, FlextLdifTestsServiceBase as s
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
from tests.constants import FlextLdifTestConstants, FlextLdifTestConstants as c
from tests.integration.conftest import (
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
from tests.integration.test_ldif_fixtures_integration import TestsFlextLdifFixtures
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
from tests.models import FlextLdifTestModels, FlextLdifTestModels as m
from tests.protocols import FlextLdifTestProtocols, FlextLdifTestProtocols as p
from tests.support.conftest_factory import FlextLdifTestConftest, tk
from tests.support.ldif_data import LdifSample, LdifTestData
from tests.support.real_services import FlextLdifTestServiceFactory
from tests.support.test_files import FileManager
from tests.support.validators import (
    MockFlextUtilitiesResultHelpers,
    MockMatchers,
    TestValidators,
)
from tests.test_factory import FlextLdifTestFactory
from tests.test_helpers import (
    TestsFlextLdifMatchers,
    TestsFlextLdifTypes,
    TestsFlextLdifValidators,
    tf,
    tm,
    tt,
    tv,
)
from tests.typings import (
    FlextLdifTestTypes,
    FlextLdifTestTypes as t,
    GenericFieldsDict,
)
from tests.unit.__init__.test_version import TestsFlextLdifVersion
from tests.unit._utilities.oid.test_oid_utilities import TestFlextLdifUtilitiesOID
from tests.unit._utilities.parser.test_parser_utilities import (
    TestFlextLdifUtilitiesParser,
)
from tests.unit._utilities.server.test_server_utilities import (
    OidServer,
    OudServer,
    TestFlextLdifUtilitiesServer,
)
from tests.unit.constants.test_acl_registry import (
    GetAclAttributesServerType,
    IsAclAttributeType,
    TestsTestFlextLdifAclAttributeRegistry,
)
from tests.unit.protocols.test_protocols import TestsTestFlextLdifProtocols
from tests.unit.quirks.servers.test_apache_quirks import (
    TestsTestFlextLdifApacheQuirks,
)
from tests.unit.quirks.servers.test_ds389_quirks import (
    ACL_TEST_CASES,
    AclScenario,
    AclTestCase,
    TestsTestFlextLdifDs389Quirks,
)
from tests.unit.quirks.servers.test_edge_cases import (
    TestsFlextLdifEdgeCases,
    cleanup_state,
    ldif_api,
)
from tests.unit.quirks.servers.test_novell_quirks import (
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
from tests.unit.quirks.servers.test_oid_quirks import TestsTestFlextLdifOidQuirks
from tests.unit.quirks.servers.test_relaxed_quirks import (
    ParseScenario,
    TestsTestFlextLdifRelaxedQuirks,
    WriteScenario,
    meta_keys,
)
from tests.unit.quirks.servers.test_schema_transformer import (
    TestSchemaTransformerNormalizeMatchingRule,
    TestSchemaTransformerNormalizeSyntaxOid,
    TestsFlextLdifSchemaTransformerNormalizeAttributeName,
)
from tests.unit.services.test_migration_pipeline import (
    TestsTestFlextLdifMigrationPipeline,
)
from tests.unit.services.test_quirks_standardization import (
    TestAliasDiscovery,
    TestQuirksAutoInterchange,
    TestQuirksWithRealLdifFixtures,
    TestsFlextLdifQuirksStandardizedConstants,
)
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
from tests.utilities import FlextLdifTestUtilities, FlextLdifTestUtilities as u

if _t.TYPE_CHECKING:
    import tests.base as _tests_base

    base = _tests_base
    import tests.conftest as _tests_conftest

    conftest = _tests_conftest
    import tests.conftest_shared as _tests_conftest_shared

    conftest_shared = _tests_conftest_shared
    import tests.constants as _tests_constants

    constants = _tests_constants
    import tests.e2e as _tests_e2e

    e2e = _tests_e2e
    import tests.e2e.test_enterprise as _tests_e2e_test_enterprise

    test_enterprise = _tests_e2e_test_enterprise
    import tests.helpers as _tests_helpers

    helpers = _tests_helpers
    import tests.helpers.example_refactoring as _tests_helpers_example_refactoring

    example_refactoring = _tests_helpers_example_refactoring
    import tests.integration as _tests_integration

    integration = _tests_integration
    import tests.integration.test_acl_metadata_preservation as _tests_integration_test_acl_metadata_preservation

    test_acl_metadata_preservation = _tests_integration_test_acl_metadata_preservation
    import tests.integration.test_api_integration as _tests_integration_test_api_integration

    test_api_integration = _tests_integration_test_api_integration
    import tests.integration.test_categorization_real_data as _tests_integration_test_categorization_real_data

    test_categorization_real_data = _tests_integration_test_categorization_real_data
    import tests.integration.test_config_integration as _tests_integration_test_config_integration

    test_config_integration = _tests_integration_test_config_integration
    import tests.integration.test_cross_quirk_conversion as _tests_integration_test_cross_quirk_conversion

    test_cross_quirk_conversion = _tests_integration_test_cross_quirk_conversion
    import tests.integration.test_dn_case_handling as _tests_integration_test_dn_case_handling

    test_dn_case_handling = _tests_integration_test_dn_case_handling
    import tests.integration.test_edge_cases as _tests_integration_test_edge_cases

    test_edge_cases = _tests_integration_test_edge_cases
    import tests.integration.test_error_recovery as _tests_integration_test_error_recovery

    test_error_recovery = _tests_integration_test_error_recovery
    import tests.integration.test_ldif_fixtures_integration as _tests_integration_test_ldif_fixtures_integration

    test_ldif_fixtures_integration = _tests_integration_test_ldif_fixtures_integration
    import tests.integration.test_minimal_differences_metadata as _tests_integration_test_minimal_differences_metadata

    test_minimal_differences_metadata = (
        _tests_integration_test_minimal_differences_metadata
    )
    import tests.integration.test_oid_integration as _tests_integration_test_oid_integration

    test_oid_integration = _tests_integration_test_oid_integration
    import tests.integration.test_oud_integration as _tests_integration_test_oud_integration

    test_oud_integration = _tests_integration_test_oud_integration
    import tests.integration.test_oud_to_oid_migration as _tests_integration_test_oud_to_oid_migration

    test_oud_to_oid_migration = _tests_integration_test_oud_to_oid_migration
    import tests.integration.test_pipeline_integration as _tests_integration_test_pipeline_integration

    test_pipeline_integration = _tests_integration_test_pipeline_integration
    import tests.integration.test_quirks_transformations as _tests_integration_test_quirks_transformations

    test_quirks_transformations = _tests_integration_test_quirks_transformations
    import tests.integration.test_real_ldap_config as _tests_integration_test_real_ldap_config

    test_real_ldap_config = _tests_integration_test_real_ldap_config
    import tests.integration.test_real_ldap_crud as _tests_integration_test_real_ldap_crud

    test_real_ldap_crud = _tests_integration_test_real_ldap_crud
    import tests.integration.test_real_ldap_export as _tests_integration_test_real_ldap_export

    test_real_ldap_export = _tests_integration_test_real_ldap_export
    import tests.integration.test_real_ldap_import as _tests_integration_test_real_ldap_import

    test_real_ldap_import = _tests_integration_test_real_ldap_import
    import tests.integration.test_real_ldap_roundtrip as _tests_integration_test_real_ldap_roundtrip

    test_real_ldap_roundtrip = _tests_integration_test_real_ldap_roundtrip
    import tests.integration.test_rfc_docker_real as _tests_integration_test_rfc_docker_real

    test_rfc_docker_real = _tests_integration_test_rfc_docker_real
    import tests.integration.test_rfc_docker_real_integration as _tests_integration_test_rfc_docker_real_integration

    test_rfc_docker_real_integration = (
        _tests_integration_test_rfc_docker_real_integration
    )
    import tests.integration.test_simple_ldap as _tests_integration_test_simple_ldap

    test_simple_ldap = _tests_integration_test_simple_ldap
    import tests.integration.test_systematic_fixture_coverage as _tests_integration_test_systematic_fixture_coverage

    test_systematic_fixture_coverage = (
        _tests_integration_test_systematic_fixture_coverage
    )
    import tests.integration.test_zero_data_loss_oid_oud as _tests_integration_test_zero_data_loss_oid_oud

    test_zero_data_loss_oid_oud = _tests_integration_test_zero_data_loss_oid_oud
    import tests.integration.test_zero_data_loss_schema as _tests_integration_test_zero_data_loss_schema

    test_zero_data_loss_schema = _tests_integration_test_zero_data_loss_schema
    import tests.models as _tests_models

    models = _tests_models
    import tests.protocols as _tests_protocols

    protocols = _tests_protocols
    import tests.support as _tests_support

    support = _tests_support
    import tests.support.conftest_factory as _tests_support_conftest_factory

    conftest_factory = _tests_support_conftest_factory
    import tests.support.ldif_data as _tests_support_ldif_data

    ldif_data = _tests_support_ldif_data
    import tests.support.real_services as _tests_support_real_services

    real_services = _tests_support_real_services
    import tests.support.test_files as _tests_support_test_files

    test_files = _tests_support_test_files
    import tests.support.validators as _tests_support_validators

    validators = _tests_support_validators
    import tests.test_factory as _tests_test_factory

    test_factory = _tests_test_factory
    import tests.test_helpers as _tests_test_helpers

    test_helpers = _tests_test_helpers
    import tests.typings as _tests_typings

    typings = _tests_typings
    import tests.unit as _tests_unit

    unit = _tests_unit
    import tests.unit.__init__.test_version as _tests_unit___init___test_version

    test_version = _tests_unit___init___test_version
    import tests.unit.constants.test_acl_registry as _tests_unit_constants_test_acl_registry

    test_acl_registry = _tests_unit_constants_test_acl_registry
    import tests.unit.protocols.test_protocols as _tests_unit_protocols_test_protocols

    test_protocols = _tests_unit_protocols_test_protocols
    import tests.unit.services as _tests_unit_services

    services = _tests_unit_services
    import tests.unit.services.test_quirks_standardization as _tests_unit_services_test_quirks_standardization

    test_quirks_standardization = _tests_unit_services_test_quirks_standardization
    import tests.unit.test_migration_pipeline as _tests_unit_test_migration_pipeline

    test_migration_pipeline = _tests_unit_test_migration_pipeline
    import tests.unit.test_migration_pipeline_quirks as _tests_unit_test_migration_pipeline_quirks

    test_migration_pipeline_quirks = _tests_unit_test_migration_pipeline_quirks
    import tests.unit.test_typings as _tests_unit_test_typings

    test_typings = _tests_unit_test_typings
    import tests.unit.utilities.test_utilities_comprehensive as _tests_unit_utilities_test_utilities_comprehensive

    test_utilities_comprehensive = _tests_unit_utilities_test_utilities_comprehensive
    import tests.unit.utilities.test_utilities_core as _tests_unit_utilities_test_utilities_core

    test_utilities_core = _tests_unit_utilities_test_utilities_core
    import tests.utilities as _tests_utilities

    utilities = _tests_utilities

    _ = (
        ACL_TEST_CASES,
        APIScenarios,
        ATTRIBUTE_TEST_CASES,
        AclScenario,
        AclTestCase,
        AttributeScenario,
        AttributeTestCase,
        ConfigTestData,
        ENTRY_TEST_CASES,
        EntryScenario,
        EntryTestCase,
        FIXTURES_DIR,
        FileManager,
        FlextLdifFixtures,
        FlextLdifTestConftest,
        FlextLdifTestConstants,
        FlextLdifTestFactory,
        FlextLdifTestModels,
        FlextLdifTestProtocols,
        FlextLdifTestServiceFactory,
        FlextLdifTestTypes,
        FlextLdifTestUtilities,
        FlextLdifTestsServiceBase,
        GenericFieldsDict,
        GetAclAttributesServerType,
        IsAclAttributeType,
        LdifSample,
        LdifTestData,
        MockFlextUtilitiesResultHelpers,
        MockMatchers,
        OBJECTCLASS_TEST_CASES,
        OID_FIXTURES_DIR,
        ObjectClassScenario,
        ObjectClassTestCase,
        OidServer,
        OidTestConstants,
        OudServer,
        ParseScenario,
        RfcTestHelpers,
        TestAclRoundTripPreservation,
        TestAliasDiscovery,
        TestAttributeFixer,
        TestBoundaryValues,
        TestCategorizationRealData,
        TestData,
        TestDeduplicationHelpers,
        TestDnCaseNormalizationScenarios,
        TestDnCaseRegistry,
        TestDnObjectClassMethods,
        TestEmptyAndMinimalCases,
        TestEncodingErrors,
        TestFlextLdifAPIIntegration,
        TestFlextLdifFacadeWorkflows,
        TestFlextLdifSettingsIntegration,
        TestFlextLdifTypesStructure,
        TestFlextLdifUtilitiesComprehensive,
        TestFlextLdifUtilitiesOID,
        TestFlextLdifUtilitiesParser,
        TestFlextLdifUtilitiesServer,
        TestIncompleteEntries,
        TestIntegrationWithLdifFixtures,
        TestInvalidSchemaDefinitions,
        TestLargeAndComplexCases,
        TestLdifParser,
        TestMalformedLdifHandling,
        TestMinimalDifferencesOidOud,
        TestModelsNamespace,
        TestNovellAcls,
        TestNovellEntryDetection,
        TestNovellSchemaAttributeDetection,
        TestNovellSchemaAttributeParsing,
        TestNovellSchemaObjectClassDetection,
        TestNovellSchemaObjectClassParsing,
        TestObjectClassUtilities,
        TestOidAclMetadataPreservation,
        TestOidEntryIntegration,
        TestOidQuirksTransformations,
        TestOidRoundTripIntegration,
        TestOidSchemaIntegration,
        TestOidToOudAclConversion,
        TestOidToOudIntegrationConversion,
        TestOidToOudSchemaConversion,
        TestOudAciMetadataPreservation,
        TestOudAclIntegration,
        TestOudEntryIntegration,
        TestOudMetadataPreservation,
        TestOudQuirksTransformations,
        TestOudRoundTripIntegration,
        TestOudSchemaIntegration,
        TestOudToOidAclMigration,
        TestOudToOidEntryMigration,
        TestOudToOidFullMigration,
        TestOudToOidSchemaMigration,
        TestPhase1StandardizationResults,
        TestQuirksAutoInterchange,
        TestQuirksConversionMatrixFacade,
        TestQuirksPropertyValidation,
        TestQuirksWithRealLdifFixtures,
        TestRealLdapBatchOperations,
        TestRealLdapCRUD,
        TestRealLdapConfigurationFromEnv,
        TestRealLdapExport,
        TestRealLdapImport,
        TestRealLdapRailwayComposition,
        TestRealLdapRoundtrip,
        TestRemovalOfOverEngineering,
        TestRfcDockerRealData,
        TestRfcExceptionHandlingRealScenarios,
        TestRfcIntegrationRealWorld,
        TestRfcParserRealFixtures,
        TestRfcSchemaParserRealFixtures,
        TestRfcWriterRealFixtures,
        TestRoundtripEdgeCases,
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
        TestSchemaTransformerNormalizeMatchingRule,
        TestSchemaTransformerNormalizeSyntaxOid,
        TestServerTypes,
        TestSystematicFixtureCoverage,
        TestUnicodeBoundaries,
        TestValidators,
        TestZeroDataLossOidOud,
        TestsFlextLdifCommonDictionaryTypes,
        TestsFlextLdifDnOperationsPure,
        TestsFlextLdifEdgeCases,
        TestsFlextLdifFixtures,
        TestsFlextLdifMatchers,
        TestsFlextLdifMigrationPipeline,
        TestsFlextLdifMigrationPipelineQuirks,
        TestsFlextLdifNovellInitialization,
        TestsFlextLdifQuirksStandardizedConstants,
        TestsFlextLdifSchemaTransformerNormalizeAttributeName,
        TestsFlextLdifTypes,
        TestsFlextLdifValidators,
        TestsFlextLdifVersion,
        TestsTestFlextLdifAclAttributeRegistry,
        TestsTestFlextLdifApacheQuirks,
        TestsTestFlextLdifDs389Quirks,
        TestsTestFlextLdifMigrationPipeline,
        TestsTestFlextLdifOidQuirks,
        TestsTestFlextLdifProtocols,
        TestsTestFlextLdifRelaxedQuirks,
        WORKSPACE_ROOT,
        WriteScenario,
        all_acl_fixtures,
        all_entries_fixtures,
        all_integration_fixtures,
        all_schema_fixtures,
        api,
        base,
        c,
        clean_test_ou,
        cleanup_state,
        conftest,
        conftest_factory,
        conftest_shared,
        constants,
        conversion_matrix,
        d,
        e,
        e2e,
        entry_quirk,
        example_refactoring,
        fixtures_dir,
        flext_ldif,
        h,
        helpers,
        integration,
        large_test_dataset,
        ldap_connection,
        ldap_container,
        ldap_container_shared,
        ldif_api,
        ldif_data,
        ldif_parser,
        ldif_writer,
        logger,
        m,
        make_test_base_dn,
        make_test_username,
        meta_keys,
        migration_inputs,
        models,
        novell_server,
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
        p,
        parametrized_real_data,
        parser,
        protocols,
        pytest_configure,
        r,
        real_entry,
        real_ldif_content,
        real_ldif_group_entry,
        real_ldif_multiple_entries,
        real_ldif_user_entry,
        real_services,
        rfc_schema_entries,
        rfc_schema_fixture,
        s,
        sample_ldif_entries,
        schema_quirk,
        server,
        services,
        support,
        t,
        temp_file,
        test_acl_metadata_preservation,
        test_acl_registry,
        test_api_integration,
        test_categorization_real_data,
        test_config_integration,
        test_create_and_export_entry,
        test_cross_quirk_conversion,
        test_dn_case_handling,
        test_edge_cases,
        test_enterprise,
        test_error_recovery,
        test_factory,
        test_files,
        test_helpers,
        test_ldap_connection,
        test_ldif_fixtures_integration,
        test_migration_pipeline,
        test_migration_pipeline_quirks,
        test_minimal_differences_metadata,
        test_oid_integration,
        test_oud_integration,
        test_oud_to_oid_migration,
        test_pipeline_integration,
        test_protocols,
        test_quirks_standardization,
        test_quirks_transformations,
        test_real_ldap_config,
        test_real_ldap_crud,
        test_real_ldap_export,
        test_real_ldap_import,
        test_real_ldap_roundtrip,
        test_rfc_docker_real,
        test_rfc_docker_real_integration,
        test_simple_ldap,
        test_simple_ldap_search,
        test_systematic_fixture_coverage,
        test_typings,
        test_utilities_comprehensive,
        test_utilities_core,
        test_version,
        test_zero_data_loss_oid_oud,
        test_zero_data_loss_schema,
        tf,
        tk,
        tm,
        tmp_ldif_path,
        tt,
        tv,
        typings,
        u,
        unique_dn_suffix,
        unit,
        utilities,
        validators,
        writer,
        x,
    )
_LAZY_IMPORTS = merge_lazy_imports(
    (
        "tests.e2e",
        "tests.helpers",
        "tests.integration",
        "tests.support",
        "tests.unit",
    ),
    {
        "FIXTURES_DIR": "tests.conftest",
        "FlextLdifFixtures": "tests.conftest",
        "FlextLdifTestConstants": "tests.constants",
        "FlextLdifTestFactory": "tests.test_factory",
        "FlextLdifTestModels": "tests.models",
        "FlextLdifTestProtocols": "tests.protocols",
        "FlextLdifTestTypes": "tests.typings",
        "FlextLdifTestUtilities": "tests.utilities",
        "FlextLdifTestsServiceBase": "tests.base",
        "GenericFieldsDict": "tests.typings",
        "OID_FIXTURES_DIR": "tests.conftest",
        "TestsFlextLdifMatchers": "tests.test_helpers",
        "TestsFlextLdifTypes": "tests.test_helpers",
        "TestsFlextLdifValidators": "tests.test_helpers",
        "base": "tests.base",
        "c": ("tests.constants", "FlextLdifTestConstants"),
        "conftest": "tests.conftest",
        "conftest_shared": "tests.conftest_shared",
        "constants": "tests.constants",
        "d": ("flext_core.decorators", "FlextDecorators"),
        "e": ("flext_core.exceptions", "FlextExceptions"),
        "e2e": "tests.e2e",
        "flext_ldif": "tests.conftest",
        "h": ("flext_core.handlers", "FlextHandlers"),
        "helpers": "tests.helpers",
        "integration": "tests.integration",
        "large_test_dataset": "tests.conftest_shared",
        "ldif_parser": "tests.conftest",
        "ldif_writer": "tests.conftest",
        "m": ("tests.models", "FlextLdifTestModels"),
        "models": "tests.models",
        "p": ("tests.protocols", "FlextLdifTestProtocols"),
        "parametrized_real_data": "tests.conftest_shared",
        "protocols": "tests.protocols",
        "pytest_configure": "tests.conftest",
        "r": ("flext_core.result", "FlextResult"),
        "real_entry": "tests.conftest_shared",
        "real_ldif_content": "tests.conftest_shared",
        "real_ldif_group_entry": "tests.conftest",
        "real_ldif_multiple_entries": "tests.conftest",
        "real_ldif_user_entry": "tests.conftest",
        "s": ("tests.base", "FlextLdifTestsServiceBase"),
        "sample_ldif_entries": "tests.conftest",
        "support": "tests.support",
        "t": ("tests.typings", "FlextLdifTestTypes"),
        "temp_file": "tests.conftest",
        "test_factory": "tests.test_factory",
        "test_helpers": "tests.test_helpers",
        "tf": "tests.test_helpers",
        "tm": "tests.test_helpers",
        "tt": "tests.test_helpers",
        "tv": "tests.test_helpers",
        "typings": "tests.typings",
        "u": ("tests.utilities", "FlextLdifTestUtilities"),
        "unit": "tests.unit",
        "utilities": "tests.utilities",
        "x": ("flext_core.mixins", "FlextMixins"),
    },
)

__all__ = [
    "ACL_TEST_CASES",
    "ATTRIBUTE_TEST_CASES",
    "ENTRY_TEST_CASES",
    "FIXTURES_DIR",
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
    "writer",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
