# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_tests import *

    from tests import (
        base,
        conftest,
        conftest_shared,
        constants,
        e2e,
        helpers,
        integration,
        models,
        protocols,
        support,
        test_factory,
        test_helpers,
        typings,
        unit,
        utilities,
    )
    from tests.base import *
    from tests.conftest import *
    from tests.conftest_shared import *
    from tests.constants import *
    from tests.e2e import test_enterprise
    from tests.helpers import example_refactoring
    from tests.integration import (
        test_acl_metadata_preservation,
        test_api_integration,
        test_categorization_real_data,
        test_config_integration,
        test_cross_quirk_conversion,
        test_dn_case_handling,
        test_edge_cases,
        test_error_recovery,
        test_ldif_fixtures_integration,
        test_minimal_differences_metadata,
        test_oid_integration,
        test_oud_integration,
        test_oud_to_oid_migration,
        test_pipeline_integration,
        test_quirks_transformations,
        test_real_ldap_config,
        test_real_ldap_crud,
        test_real_ldap_export,
        test_real_ldap_import,
        test_real_ldap_roundtrip,
        test_rfc_docker_real,
        test_rfc_docker_real_integration,
        test_simple_ldap,
        test_systematic_fixture_coverage,
        test_zero_data_loss_oid_oud,
        test_zero_data_loss_schema,
    )
    from tests.integration.conftest import *
    from tests.integration.test_acl_metadata_preservation import *
    from tests.integration.test_api_integration import *
    from tests.integration.test_categorization_real_data import *
    from tests.integration.test_config_integration import *
    from tests.integration.test_cross_quirk_conversion import *
    from tests.integration.test_dn_case_handling import *
    from tests.integration.test_edge_cases import *
    from tests.integration.test_error_recovery import *
    from tests.integration.test_ldif_fixtures_integration import *
    from tests.integration.test_minimal_differences_metadata import *
    from tests.integration.test_oid_integration import *
    from tests.integration.test_oud_integration import *
    from tests.integration.test_oud_to_oid_migration import *
    from tests.integration.test_pipeline_integration import *
    from tests.integration.test_quirks_transformations import *
    from tests.integration.test_real_ldap_config import *
    from tests.integration.test_real_ldap_crud import *
    from tests.integration.test_real_ldap_export import *
    from tests.integration.test_real_ldap_import import *
    from tests.integration.test_real_ldap_roundtrip import *
    from tests.integration.test_rfc_docker_real import *
    from tests.integration.test_rfc_docker_real_integration import *
    from tests.integration.test_simple_ldap import *
    from tests.integration.test_systematic_fixture_coverage import *
    from tests.integration.test_zero_data_loss_oid_oud import *
    from tests.integration.test_zero_data_loss_schema import *
    from tests.models import *
    from tests.protocols import *
    from tests.support import (
        conftest_factory,
        ldif_data,
        real_services,
        test_files,
        validators,
    )
    from tests.support.conftest_factory import *
    from tests.support.ldif_data import *
    from tests.support.real_services import *
    from tests.support.test_files import *
    from tests.support.validators import *
    from tests.test_factory import *
    from tests.test_helpers import *
    from tests.typings import *
    from tests.unit import (
        services,
        test_migration_pipeline,
        test_migration_pipeline_quirks,
        test_typings,
    )
    from tests.unit.__init__ import test_version
    from tests.unit.__init__.test_version import *
    from tests.unit._utilities.oid.test_oid_utilities import *
    from tests.unit._utilities.parser.test_parser_utilities import *
    from tests.unit._utilities.server.test_server_utilities import *
    from tests.unit.constants import test_acl_registry
    from tests.unit.constants.test_acl_registry import *
    from tests.unit.protocols import test_protocols
    from tests.unit.protocols.test_protocols import *
    from tests.unit.quirks.servers.test_apache_quirks import *
    from tests.unit.quirks.servers.test_ds389_quirks import *
    from tests.unit.quirks.servers.test_edge_cases import *
    from tests.unit.quirks.servers.test_novell_quirks import *
    from tests.unit.quirks.servers.test_oid_quirks import *
    from tests.unit.quirks.servers.test_relaxed_quirks import *
    from tests.unit.quirks.servers.test_schema_transformer import *
    from tests.unit.services import test_quirks_standardization
    from tests.unit.services.test_migration_pipeline import *
    from tests.unit.services.test_quirks_standardization import *
    from tests.unit.test_migration_pipeline import *
    from tests.unit.test_migration_pipeline_quirks import *
    from tests.unit.test_typings import *
    from tests.unit.utilities import test_utilities_comprehensive, test_utilities_core
    from tests.unit.utilities.test_utilities_comprehensive import *
    from tests.unit.utilities.test_utilities_core import *
    from tests.utilities import *

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    "ACL_TEST_CASES": "tests.unit.quirks.servers.test_ds389_quirks",
    "APIScenarios": "tests.integration.test_api_integration",
    "ATTRIBUTE_TEST_CASES": "tests.unit.quirks.servers.test_novell_quirks",
    "AclScenario": "tests.unit.quirks.servers.test_ds389_quirks",
    "AclTestCase": "tests.unit.quirks.servers.test_ds389_quirks",
    "AttributeScenario": "tests.unit.quirks.servers.test_novell_quirks",
    "AttributeTestCase": "tests.unit.quirks.servers.test_novell_quirks",
    "ConfigTestData": "tests.integration.test_config_integration",
    "ENTRY_TEST_CASES": "tests.unit.quirks.servers.test_novell_quirks",
    "EntryScenario": "tests.unit.quirks.servers.test_novell_quirks",
    "EntryTestCase": "tests.unit.quirks.servers.test_novell_quirks",
    "FIXTURES_DIR": "tests.conftest",
    "FileManager": "tests.support.test_files",
    "FlextLdifFixtures": "tests.conftest",
    "FlextLdifTestConftest": "tests.support.conftest_factory",
    "FlextLdifTestConstants": "tests.constants",
    "FlextLdifTestFactory": "tests.test_factory",
    "FlextLdifTestModels": "tests.models",
    "FlextLdifTestProtocols": "tests.protocols",
    "FlextLdifTestServiceFactory": "tests.support.real_services",
    "FlextLdifTestTypes": "tests.typings",
    "FlextLdifTestUtilities": "tests.utilities",
    "FlextLdifTestsServiceBase": "tests.base",
    "GenericFieldsDict": "tests.typings",
    "GetAclAttributesServerType": "tests.unit.constants.test_acl_registry",
    "IsAclAttributeType": "tests.unit.constants.test_acl_registry",
    "LdifSample": "tests.support.ldif_data",
    "LdifTestData": "tests.support.ldif_data",
    "MockFlextUtilitiesResultHelpers": "tests.support.validators",
    "MockMatchers": "tests.support.validators",
    "OBJECTCLASS_TEST_CASES": "tests.unit.quirks.servers.test_novell_quirks",
    "OID_FIXTURES_DIR": "tests.conftest",
    "ObjectClassScenario": "tests.unit.quirks.servers.test_novell_quirks",
    "ObjectClassTestCase": "tests.unit.quirks.servers.test_novell_quirks",
    "OidServer": "tests.unit._utilities.server.test_server_utilities",
    "OidTestConstants": "tests.unit.test_migration_pipeline_quirks",
    "OudServer": "tests.unit._utilities.server.test_server_utilities",
    "ParseScenario": "tests.unit.quirks.servers.test_relaxed_quirks",
    "RfcTestHelpers": "tests.unit.quirks.servers.test_novell_quirks",
    "TestAclRoundTripPreservation": "tests.integration.test_acl_metadata_preservation",
    "TestAliasDiscovery": "tests.unit.services.test_quirks_standardization",
    "TestAttributeFixer": "tests.unit.utilities.test_utilities_core",
    "TestBoundaryValues": "tests.integration.test_edge_cases",
    "TestCategorizationRealData": "tests.integration.test_categorization_real_data",
    "TestData": "tests.integration.test_api_integration",
    "TestDeduplicationHelpers": "tests.unit.quirks.servers.test_novell_quirks",
    "TestDnCaseNormalizationScenarios": "tests.integration.test_dn_case_handling",
    "TestDnCaseRegistry": "tests.integration.test_dn_case_handling",
    "TestDnObjectClassMethods": "tests.unit.utilities.test_utilities_core",
    "TestEmptyAndMinimalCases": "tests.integration.test_edge_cases",
    "TestEncodingErrors": "tests.integration.test_error_recovery",
    "TestFlextLdifAPIIntegration": "tests.integration.test_api_integration",
    "TestFlextLdifFacadeWorkflows": "tests.integration.test_pipeline_integration",
    "TestFlextLdifSettingsIntegration": "tests.integration.test_config_integration",
    "TestFlextLdifTypesStructure": "tests.unit.test_typings",
    "TestFlextLdifUtilitiesComprehensive": "tests.unit.utilities.test_utilities_comprehensive",
    "TestFlextLdifUtilitiesOID": "tests.unit._utilities.oid.test_oid_utilities",
    "TestFlextLdifUtilitiesParser": "tests.unit._utilities.parser.test_parser_utilities",
    "TestFlextLdifUtilitiesServer": "tests.unit._utilities.server.test_server_utilities",
    "TestIncompleteEntries": "tests.integration.test_error_recovery",
    "TestIntegrationWithLdifFixtures": "tests.unit.test_typings",
    "TestInvalidSchemaDefinitions": "tests.integration.test_error_recovery",
    "TestLargeAndComplexCases": "tests.integration.test_edge_cases",
    "TestLdifParser": "tests.unit.utilities.test_utilities_core",
    "TestMalformedLdifHandling": "tests.integration.test_error_recovery",
    "TestMinimalDifferencesOidOud": "tests.integration.test_minimal_differences_metadata",
    "TestModelsNamespace": "tests.unit.test_typings",
    "TestNovellAcls": "tests.unit.quirks.servers.test_novell_quirks",
    "TestNovellEntryDetection": "tests.unit.quirks.servers.test_novell_quirks",
    "TestNovellSchemaAttributeDetection": "tests.unit.quirks.servers.test_novell_quirks",
    "TestNovellSchemaAttributeParsing": "tests.unit.quirks.servers.test_novell_quirks",
    "TestNovellSchemaObjectClassDetection": "tests.unit.quirks.servers.test_novell_quirks",
    "TestNovellSchemaObjectClassParsing": "tests.unit.quirks.servers.test_novell_quirks",
    "TestObjectClassUtilities": "tests.unit.utilities.test_utilities_core",
    "TestOidAclMetadataPreservation": "tests.integration.test_acl_metadata_preservation",
    "TestOidEntryIntegration": "tests.integration.test_oid_integration",
    "TestOidQuirksTransformations": "tests.integration.test_quirks_transformations",
    "TestOidRoundTripIntegration": "tests.integration.test_oid_integration",
    "TestOidSchemaIntegration": "tests.integration.test_oid_integration",
    "TestOidToOudAclConversion": "tests.integration.test_cross_quirk_conversion",
    "TestOidToOudIntegrationConversion": "tests.integration.test_cross_quirk_conversion",
    "TestOidToOudSchemaConversion": "tests.integration.test_cross_quirk_conversion",
    "TestOudAciMetadataPreservation": "tests.integration.test_acl_metadata_preservation",
    "TestOudAclIntegration": "tests.integration.test_oud_integration",
    "TestOudEntryIntegration": "tests.integration.test_oud_integration",
    "TestOudMetadataPreservation": "tests.integration.test_oud_integration",
    "TestOudQuirksTransformations": "tests.integration.test_quirks_transformations",
    "TestOudRoundTripIntegration": "tests.integration.test_oud_integration",
    "TestOudSchemaIntegration": "tests.integration.test_oud_integration",
    "TestOudToOidAclMigration": "tests.integration.test_oud_to_oid_migration",
    "TestOudToOidEntryMigration": "tests.integration.test_oud_to_oid_migration",
    "TestOudToOidFullMigration": "tests.integration.test_oud_to_oid_migration",
    "TestOudToOidSchemaMigration": "tests.integration.test_oud_to_oid_migration",
    "TestPhase1StandardizationResults": "tests.unit.test_typings",
    "TestQuirksAutoInterchange": "tests.unit.services.test_quirks_standardization",
    "TestQuirksConversionMatrixFacade": "tests.integration.test_cross_quirk_conversion",
    "TestQuirksPropertyValidation": "tests.integration.test_quirks_transformations",
    "TestQuirksWithRealLdifFixtures": "tests.unit.services.test_quirks_standardization",
    "TestRealLdapBatchOperations": "tests.integration.test_real_ldap_crud",
    "TestRealLdapCRUD": "tests.integration.test_real_ldap_crud",
    "TestRealLdapConfigurationFromEnv": "tests.integration.test_real_ldap_config",
    "TestRealLdapExport": "tests.integration.test_real_ldap_export",
    "TestRealLdapImport": "tests.integration.test_real_ldap_import",
    "TestRealLdapRailwayComposition": "tests.integration.test_real_ldap_config",
    "TestRealLdapRoundtrip": "tests.integration.test_real_ldap_roundtrip",
    "TestRemovalOfOverEngineering": "tests.unit.test_typings",
    "TestRfcDockerRealData": "tests.integration.test_rfc_docker_real",
    "TestRfcExceptionHandlingRealScenarios": "tests.integration.test_rfc_docker_real_integration",
    "TestRfcIntegrationRealWorld": "tests.integration.test_rfc_docker_real",
    "TestRfcParserRealFixtures": "tests.integration.test_rfc_docker_real_integration",
    "TestRfcSchemaParserRealFixtures": "tests.integration.test_rfc_docker_real_integration",
    "TestRfcWriterRealFixtures": "tests.integration.test_rfc_docker_real_integration",
    "TestRoundtripEdgeCases": "tests.integration.test_edge_cases",
    "TestSchemaDeviationsAttributeKeyCasing": "tests.integration.test_zero_data_loss_schema",
    "TestSchemaDeviationsComplete": "tests.integration.test_zero_data_loss_schema",
    "TestSchemaDeviationsMissingSpaces": "tests.integration.test_zero_data_loss_schema",
    "TestSchemaDeviationsNameAliases": "tests.integration.test_zero_data_loss_schema",
    "TestSchemaDeviationsObsolete": "tests.integration.test_zero_data_loss_schema",
    "TestSchemaDeviationsOriginalString": "tests.integration.test_zero_data_loss_schema",
    "TestSchemaDeviationsRoundTrip": "tests.integration.test_zero_data_loss_schema",
    "TestSchemaDeviationsSpacing": "tests.integration.test_zero_data_loss_schema",
    "TestSchemaDeviationsSyntaxQuotes": "tests.integration.test_zero_data_loss_schema",
    "TestSchemaDeviationsUtilities": "tests.integration.test_zero_data_loss_schema",
    "TestSchemaDeviationsXOrigin": "tests.integration.test_zero_data_loss_schema",
    "TestSchemaTransformerNormalizeMatchingRule": "tests.unit.quirks.servers.test_schema_transformer",
    "TestSchemaTransformerNormalizeSyntaxOid": "tests.unit.quirks.servers.test_schema_transformer",
    "TestServerTypes": "tests.unit.utilities.test_utilities_core",
    "TestSystematicFixtureCoverage": "tests.integration.test_systematic_fixture_coverage",
    "TestUnicodeBoundaries": "tests.integration.test_edge_cases",
    "TestValidators": "tests.support.validators",
    "TestZeroDataLossOidOud": "tests.integration.test_zero_data_loss_oid_oud",
    "TestsFlextLdifCommonDictionaryTypes": "tests.unit.test_typings",
    "TestsFlextLdifDnOperationsPure": "tests.unit.utilities.test_utilities_core",
    "TestsFlextLdifEdgeCases": "tests.unit.quirks.servers.test_edge_cases",
    "TestsFlextLdifFixtures": "tests.integration.test_ldif_fixtures_integration",
    "TestsFlextLdifMatchers": "tests.test_helpers",
    "TestsFlextLdifMigrationPipeline": "tests.unit.test_migration_pipeline",
    "TestsFlextLdifMigrationPipelineQuirks": "tests.unit.test_migration_pipeline_quirks",
    "TestsFlextLdifNovellInitialization": "tests.unit.quirks.servers.test_novell_quirks",
    "TestsFlextLdifQuirksStandardizedConstants": "tests.unit.services.test_quirks_standardization",
    "TestsFlextLdifSchemaTransformerNormalizeAttributeName": "tests.unit.quirks.servers.test_schema_transformer",
    "TestsFlextLdifTypes": "tests.test_helpers",
    "TestsFlextLdifValidators": "tests.test_helpers",
    "TestsFlextLdifVersion": "tests.unit.__init__.test_version",
    "TestsTestFlextLdifAclAttributeRegistry": "tests.unit.constants.test_acl_registry",
    "TestsTestFlextLdifApacheQuirks": "tests.unit.quirks.servers.test_apache_quirks",
    "TestsTestFlextLdifDs389Quirks": "tests.unit.quirks.servers.test_ds389_quirks",
    "TestsTestFlextLdifMigrationPipeline": "tests.unit.services.test_migration_pipeline",
    "TestsTestFlextLdifOidQuirks": "tests.unit.quirks.servers.test_oid_quirks",
    "TestsTestFlextLdifProtocols": "tests.unit.protocols.test_protocols",
    "TestsTestFlextLdifRelaxedQuirks": "tests.unit.quirks.servers.test_relaxed_quirks",
    "WORKSPACE_ROOT": "tests.integration.conftest",
    "WriteScenario": "tests.unit.quirks.servers.test_relaxed_quirks",
    "all_acl_fixtures": "tests.integration.conftest",
    "all_entries_fixtures": "tests.integration.conftest",
    "all_integration_fixtures": "tests.integration.conftest",
    "all_schema_fixtures": "tests.integration.conftest",
    "api": "tests.integration.conftest",
    "base": "tests.base",
    "c": ["tests.constants", "FlextLdifTestConstants"],
    "clean_test_ou": "tests.integration.conftest",
    "cleanup_state": "tests.unit.quirks.servers.test_edge_cases",
    "conftest": "tests.conftest",
    "conftest_factory": "tests.support.conftest_factory",
    "conftest_shared": "tests.conftest_shared",
    "constants": "tests.constants",
    "conversion_matrix": "tests.integration.conftest",
    "d": "flext_tests",
    "e": "flext_tests",
    "e2e": "tests.e2e",
    "entry_quirk": "tests.unit.quirks.servers.test_novell_quirks",
    "example_refactoring": "tests.helpers.example_refactoring",
    "fixtures_dir": "tests.integration.test_quirks_transformations",
    "flext_ldif": "tests.conftest",
    "h": "flext_tests",
    "helpers": "tests.helpers",
    "integration": "tests.integration",
    "large_test_dataset": "tests.conftest_shared",
    "ldap_connection": "tests.integration.conftest",
    "ldap_container": "tests.integration.conftest",
    "ldap_container_shared": "tests.integration.conftest",
    "ldif_api": "tests.unit.quirks.servers.test_edge_cases",
    "ldif_data": "tests.support.ldif_data",
    "ldif_parser": "tests.conftest",
    "ldif_writer": "tests.conftest",
    "logger": "tests.integration.test_config_integration",
    "m": ["tests.models", "FlextLdifTestModels"],
    "make_test_base_dn": "tests.integration.conftest",
    "make_test_username": "tests.integration.conftest",
    "meta_keys": "tests.unit.quirks.servers.test_relaxed_quirks",
    "migration_inputs": "tests.integration.test_quirks_transformations",
    "models": "tests.models",
    "novell_server": "tests.unit.quirks.servers.test_novell_quirks",
    "oid_acl_fixture": "tests.integration.conftest",
    "oid_acl_quirk": "tests.integration.conftest",
    "oid_entries": "tests.integration.conftest",
    "oid_entries_fixture": "tests.integration.conftest",
    "oid_integration_fixture": "tests.integration.conftest",
    "oid_quirk": "tests.integration.conftest",
    "oid_schema_entries": "tests.integration.conftest",
    "oid_schema_fixture": "tests.integration.conftest",
    "oid_schema_quirk": "tests.integration.conftest",
    "openldap_acl_fixture": "tests.integration.conftest",
    "openldap_entries": "tests.integration.conftest",
    "openldap_entries_fixture": "tests.integration.conftest",
    "openldap_integration_fixture": "tests.integration.conftest",
    "openldap_schema_entries": "tests.integration.conftest",
    "openldap_schema_fixture": "tests.integration.conftest",
    "oud_acl_fixture": "tests.integration.conftest",
    "oud_acl_quirk": "tests.integration.conftest",
    "oud_entries": "tests.integration.conftest",
    "oud_entries_fixture": "tests.integration.conftest",
    "oud_integration_fixture": "tests.integration.conftest",
    "oud_quirk": "tests.integration.conftest",
    "oud_schema_entries": "tests.integration.conftest",
    "oud_schema_fixture": "tests.integration.conftest",
    "oud_schema_quirk": "tests.integration.conftest",
    "p": ["tests.protocols", "FlextLdifTestProtocols"],
    "parametrized_real_data": "tests.conftest_shared",
    "parser": "tests.integration.conftest",
    "protocols": "tests.protocols",
    "pytest_configure": "tests.conftest",
    "r": "flext_tests",
    "real_entry": "tests.conftest_shared",
    "real_ldif_content": "tests.conftest_shared",
    "real_ldif_group_entry": "tests.conftest",
    "real_ldif_multiple_entries": "tests.conftest",
    "real_ldif_user_entry": "tests.conftest",
    "real_services": "tests.support.real_services",
    "rfc_schema_entries": "tests.integration.conftest",
    "rfc_schema_fixture": "tests.integration.conftest",
    "s": "tests.base",
    "sample_ldif_entries": "tests.conftest",
    "schema_quirk": "tests.unit.quirks.servers.test_novell_quirks",
    "server": "tests.integration.conftest",
    "services": "tests.unit.services",
    "support": "tests.support",
    "t": ["tests.typings", "FlextLdifTestTypes"],
    "temp_file": "tests.conftest",
    "test_acl_metadata_preservation": "tests.integration.test_acl_metadata_preservation",
    "test_acl_registry": "tests.unit.constants.test_acl_registry",
    "test_api_integration": "tests.integration.test_api_integration",
    "test_categorization_real_data": "tests.integration.test_categorization_real_data",
    "test_config_integration": "tests.integration.test_config_integration",
    "test_create_and_export_entry": "tests.integration.test_simple_ldap",
    "test_cross_quirk_conversion": "tests.integration.test_cross_quirk_conversion",
    "test_dn_case_handling": "tests.integration.test_dn_case_handling",
    "test_edge_cases": "tests.integration.test_edge_cases",
    "test_enterprise": "tests.e2e.test_enterprise",
    "test_error_recovery": "tests.integration.test_error_recovery",
    "test_factory": "tests.test_factory",
    "test_files": "tests.support.test_files",
    "test_helpers": "tests.test_helpers",
    "test_ldap_connection": "tests.integration.test_simple_ldap",
    "test_ldif_fixtures_integration": "tests.integration.test_ldif_fixtures_integration",
    "test_migration_pipeline": "tests.unit.test_migration_pipeline",
    "test_migration_pipeline_quirks": "tests.unit.test_migration_pipeline_quirks",
    "test_minimal_differences_metadata": "tests.integration.test_minimal_differences_metadata",
    "test_oid_integration": "tests.integration.test_oid_integration",
    "test_oud_integration": "tests.integration.test_oud_integration",
    "test_oud_to_oid_migration": "tests.integration.test_oud_to_oid_migration",
    "test_pipeline_integration": "tests.integration.test_pipeline_integration",
    "test_protocols": "tests.unit.protocols.test_protocols",
    "test_quirks_standardization": "tests.unit.services.test_quirks_standardization",
    "test_quirks_transformations": "tests.integration.test_quirks_transformations",
    "test_real_ldap_config": "tests.integration.test_real_ldap_config",
    "test_real_ldap_crud": "tests.integration.test_real_ldap_crud",
    "test_real_ldap_export": "tests.integration.test_real_ldap_export",
    "test_real_ldap_import": "tests.integration.test_real_ldap_import",
    "test_real_ldap_roundtrip": "tests.integration.test_real_ldap_roundtrip",
    "test_rfc_docker_real": "tests.integration.test_rfc_docker_real",
    "test_rfc_docker_real_integration": "tests.integration.test_rfc_docker_real_integration",
    "test_simple_ldap": "tests.integration.test_simple_ldap",
    "test_simple_ldap_search": "tests.integration.test_simple_ldap",
    "test_systematic_fixture_coverage": "tests.integration.test_systematic_fixture_coverage",
    "test_typings": "tests.unit.test_typings",
    "test_utilities_comprehensive": "tests.unit.utilities.test_utilities_comprehensive",
    "test_utilities_core": "tests.unit.utilities.test_utilities_core",
    "test_version": "tests.unit.__init__.test_version",
    "test_zero_data_loss_oid_oud": "tests.integration.test_zero_data_loss_oid_oud",
    "test_zero_data_loss_schema": "tests.integration.test_zero_data_loss_schema",
    "tf": "tests.test_helpers",
    "tk": "tests.support.conftest_factory",
    "tm": "tests.test_helpers",
    "tmp_ldif_path": "tests.integration.conftest",
    "tt": "tests.test_helpers",
    "tv": "tests.test_helpers",
    "typings": "tests.typings",
    "u": ["tests.utilities", "FlextLdifTestUtilities"],
    "unique_dn_suffix": "tests.integration.conftest",
    "unit": "tests.unit",
    "utilities": "tests.utilities",
    "validators": "tests.support.validators",
    "version_module": "tests.unit.__init__.test_version",
    "writer": "tests.integration.conftest",
    "x": "flext_tests",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, sorted(_LAZY_IMPORTS))
