# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Integration tests for FLEXT-LDIF service interactions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from tests.integration import (
        conftest as conftest,
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
        typings as typings,
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

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "APIScenarios": ["tests.integration.test_api_integration", "APIScenarios"],
    "ConfigTestData": ["tests.integration.test_config_integration", "ConfigTestData"],
    "TestAclRoundTripPreservation": [
        "tests.integration.test_acl_metadata_preservation",
        "TestAclRoundTripPreservation",
    ],
    "TestBoundaryValues": ["tests.integration.test_edge_cases", "TestBoundaryValues"],
    "TestCategorizationRealData": [
        "tests.integration.test_categorization_real_data",
        "TestCategorizationRealData",
    ],
    "TestData": ["tests.integration.test_api_integration", "TestData"],
    "TestDnCaseNormalizationScenarios": [
        "tests.integration.test_dn_case_handling",
        "TestDnCaseNormalizationScenarios",
    ],
    "TestDnCaseRegistry": [
        "tests.integration.test_dn_case_handling",
        "TestDnCaseRegistry",
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
    "TestIncompleteEntries": [
        "tests.integration.test_error_recovery",
        "TestIncompleteEntries",
    ],
    "TestInvalidSchemaDefinitions": [
        "tests.integration.test_error_recovery",
        "TestInvalidSchemaDefinitions",
    ],
    "TestLargeAndComplexCases": [
        "tests.integration.test_edge_cases",
        "TestLargeAndComplexCases",
    ],
    "TestMalformedLdifHandling": [
        "tests.integration.test_error_recovery",
        "TestMalformedLdifHandling",
    ],
    "TestMinimalDifferencesOidOud": [
        "tests.integration.test_minimal_differences_metadata",
        "TestMinimalDifferencesOidOud",
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
    "TestQuirksConversionMatrixFacade": [
        "tests.integration.test_cross_quirk_conversion",
        "TestQuirksConversionMatrixFacade",
    ],
    "TestQuirksPropertyValidation": [
        "tests.integration.test_quirks_transformations",
        "TestQuirksPropertyValidation",
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
    "TestSystematicFixtureCoverage": [
        "tests.integration.test_systematic_fixture_coverage",
        "TestSystematicFixtureCoverage",
    ],
    "TestUnicodeBoundaries": [
        "tests.integration.test_edge_cases",
        "TestUnicodeBoundaries",
    ],
    "TestZeroDataLossOidOud": [
        "tests.integration.test_zero_data_loss_oid_oud",
        "TestZeroDataLossOidOud",
    ],
    "TestsFlextLdifFixtures": [
        "tests.integration.test_ldif_fixtures_integration",
        "TestsFlextLdifFixtures",
    ],
    "WORKSPACE_ROOT": ["tests.integration.conftest", "WORKSPACE_ROOT"],
    "all_acl_fixtures": ["tests.integration.conftest", "all_acl_fixtures"],
    "all_entries_fixtures": ["tests.integration.conftest", "all_entries_fixtures"],
    "all_integration_fixtures": [
        "tests.integration.conftest",
        "all_integration_fixtures",
    ],
    "all_schema_fixtures": ["tests.integration.conftest", "all_schema_fixtures"],
    "api": ["tests.integration.conftest", "api"],
    "clean_test_ou": ["tests.integration.conftest", "clean_test_ou"],
    "conftest": ["tests.integration.conftest", ""],
    "conversion_matrix": ["tests.integration.conftest", "conversion_matrix"],
    "fixtures_dir": ["tests.integration.test_quirks_transformations", "fixtures_dir"],
    "ldap_connection": ["tests.integration.conftest", "ldap_connection"],
    "ldap_container": ["tests.integration.conftest", "ldap_container"],
    "ldap_container_shared": ["tests.integration.conftest", "ldap_container_shared"],
    "logger": ["tests.integration.test_config_integration", "logger"],
    "make_test_base_dn": ["tests.integration.conftest", "make_test_base_dn"],
    "make_test_username": ["tests.integration.conftest", "make_test_username"],
    "migration_inputs": [
        "tests.integration.test_quirks_transformations",
        "migration_inputs",
    ],
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
    "parser": ["tests.integration.conftest", "parser"],
    "rfc_schema_entries": ["tests.integration.conftest", "rfc_schema_entries"],
    "rfc_schema_fixture": ["tests.integration.conftest", "rfc_schema_fixture"],
    "server": ["tests.integration.conftest", "server"],
    "test_acl_metadata_preservation": [
        "tests.integration.test_acl_metadata_preservation",
        "",
    ],
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
    "test_error_recovery": ["tests.integration.test_error_recovery", ""],
    "test_ldap_connection": [
        "tests.integration.test_simple_ldap",
        "test_ldap_connection",
    ],
    "test_ldif_fixtures_integration": [
        "tests.integration.test_ldif_fixtures_integration",
        "",
    ],
    "test_minimal_differences_metadata": [
        "tests.integration.test_minimal_differences_metadata",
        "",
    ],
    "test_oid_integration": ["tests.integration.test_oid_integration", ""],
    "test_oud_integration": ["tests.integration.test_oud_integration", ""],
    "test_oud_to_oid_migration": ["tests.integration.test_oud_to_oid_migration", ""],
    "test_pipeline_integration": ["tests.integration.test_pipeline_integration", ""],
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
    "test_zero_data_loss_oid_oud": [
        "tests.integration.test_zero_data_loss_oid_oud",
        "",
    ],
    "test_zero_data_loss_schema": ["tests.integration.test_zero_data_loss_schema", ""],
    "tmp_ldif_path": ["tests.integration.conftest", "tmp_ldif_path"],
    "typings": ["tests.integration.typings", ""],
    "unique_dn_suffix": ["tests.integration.conftest", "unique_dn_suffix"],
    "writer": ["tests.integration.conftest", "writer"],
}

_EXPORTS: Sequence[str] = [
    "APIScenarios",
    "ConfigTestData",
    "TestAclRoundTripPreservation",
    "TestBoundaryValues",
    "TestCategorizationRealData",
    "TestData",
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
    "TestsFlextLdifFixtures",
    "WORKSPACE_ROOT",
    "all_acl_fixtures",
    "all_entries_fixtures",
    "all_integration_fixtures",
    "all_schema_fixtures",
    "api",
    "clean_test_ou",
    "conftest",
    "conversion_matrix",
    "fixtures_dir",
    "ldap_connection",
    "ldap_container",
    "ldap_container_shared",
    "logger",
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
    "parser",
    "rfc_schema_entries",
    "rfc_schema_fixture",
    "server",
    "test_acl_metadata_preservation",
    "test_api_integration",
    "test_categorization_real_data",
    "test_config_integration",
    "test_create_and_export_entry",
    "test_cross_quirk_conversion",
    "test_dn_case_handling",
    "test_edge_cases",
    "test_error_recovery",
    "test_ldap_connection",
    "test_ldif_fixtures_integration",
    "test_minimal_differences_metadata",
    "test_oid_integration",
    "test_oud_integration",
    "test_oud_to_oid_migration",
    "test_pipeline_integration",
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
    "test_zero_data_loss_oid_oud",
    "test_zero_data_loss_schema",
    "tmp_ldif_path",
    "typings",
    "unique_dn_suffix",
    "writer",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
