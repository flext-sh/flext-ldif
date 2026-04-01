# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Integration tests for FLEXT-LDIF service interactions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes

    from tests.integration import (
        conftest,
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
        typings,
    )
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

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    "APIScenarios": "tests.integration.test_api_integration",
    "ConfigTestData": "tests.integration.test_config_integration",
    "TestAclRoundTripPreservation": "tests.integration.test_acl_metadata_preservation",
    "TestBoundaryValues": "tests.integration.test_edge_cases",
    "TestCategorizationRealData": "tests.integration.test_categorization_real_data",
    "TestData": "tests.integration.test_api_integration",
    "TestDnCaseNormalizationScenarios": "tests.integration.test_dn_case_handling",
    "TestDnCaseRegistry": "tests.integration.test_dn_case_handling",
    "TestEmptyAndMinimalCases": "tests.integration.test_edge_cases",
    "TestEncodingErrors": "tests.integration.test_error_recovery",
    "TestFlextLdifAPIIntegration": "tests.integration.test_api_integration",
    "TestFlextLdifFacadeWorkflows": "tests.integration.test_pipeline_integration",
    "TestFlextLdifSettingsIntegration": "tests.integration.test_config_integration",
    "TestIncompleteEntries": "tests.integration.test_error_recovery",
    "TestInvalidSchemaDefinitions": "tests.integration.test_error_recovery",
    "TestLargeAndComplexCases": "tests.integration.test_edge_cases",
    "TestMalformedLdifHandling": "tests.integration.test_error_recovery",
    "TestMinimalDifferencesOidOud": "tests.integration.test_minimal_differences_metadata",
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
    "TestQuirksConversionMatrixFacade": "tests.integration.test_cross_quirk_conversion",
    "TestQuirksPropertyValidation": "tests.integration.test_quirks_transformations",
    "TestRealLdapBatchOperations": "tests.integration.test_real_ldap_crud",
    "TestRealLdapCRUD": "tests.integration.test_real_ldap_crud",
    "TestRealLdapConfigurationFromEnv": "tests.integration.test_real_ldap_config",
    "TestRealLdapExport": "tests.integration.test_real_ldap_export",
    "TestRealLdapImport": "tests.integration.test_real_ldap_import",
    "TestRealLdapRailwayComposition": "tests.integration.test_real_ldap_config",
    "TestRealLdapRoundtrip": "tests.integration.test_real_ldap_roundtrip",
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
    "TestSystematicFixtureCoverage": "tests.integration.test_systematic_fixture_coverage",
    "TestUnicodeBoundaries": "tests.integration.test_edge_cases",
    "TestZeroDataLossOidOud": "tests.integration.test_zero_data_loss_oid_oud",
    "TestsFlextLdifFixtures": "tests.integration.test_ldif_fixtures_integration",
    "WORKSPACE_ROOT": "tests.integration.conftest",
    "all_acl_fixtures": "tests.integration.conftest",
    "all_entries_fixtures": "tests.integration.conftest",
    "all_integration_fixtures": "tests.integration.conftest",
    "all_schema_fixtures": "tests.integration.conftest",
    "api": "tests.integration.conftest",
    "clean_test_ou": "tests.integration.conftest",
    "conftest": "tests.integration.conftest",
    "conversion_matrix": "tests.integration.conftest",
    "fixtures_dir": "tests.integration.test_quirks_transformations",
    "ldap_connection": "tests.integration.conftest",
    "ldap_container": "tests.integration.conftest",
    "ldap_container_shared": "tests.integration.conftest",
    "logger": "tests.integration.test_config_integration",
    "make_test_base_dn": "tests.integration.conftest",
    "make_test_username": "tests.integration.conftest",
    "migration_inputs": "tests.integration.test_quirks_transformations",
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
    "parser": "tests.integration.conftest",
    "rfc_schema_entries": "tests.integration.conftest",
    "rfc_schema_fixture": "tests.integration.conftest",
    "server": "tests.integration.conftest",
    "test_acl_metadata_preservation": "tests.integration.test_acl_metadata_preservation",
    "test_api_integration": "tests.integration.test_api_integration",
    "test_categorization_real_data": "tests.integration.test_categorization_real_data",
    "test_config_integration": "tests.integration.test_config_integration",
    "test_create_and_export_entry": "tests.integration.test_simple_ldap",
    "test_cross_quirk_conversion": "tests.integration.test_cross_quirk_conversion",
    "test_dn_case_handling": "tests.integration.test_dn_case_handling",
    "test_edge_cases": "tests.integration.test_edge_cases",
    "test_error_recovery": "tests.integration.test_error_recovery",
    "test_ldap_connection": "tests.integration.test_simple_ldap",
    "test_ldif_fixtures_integration": "tests.integration.test_ldif_fixtures_integration",
    "test_minimal_differences_metadata": "tests.integration.test_minimal_differences_metadata",
    "test_oid_integration": "tests.integration.test_oid_integration",
    "test_oud_integration": "tests.integration.test_oud_integration",
    "test_oud_to_oid_migration": "tests.integration.test_oud_to_oid_migration",
    "test_pipeline_integration": "tests.integration.test_pipeline_integration",
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
    "test_zero_data_loss_oid_oud": "tests.integration.test_zero_data_loss_oid_oud",
    "test_zero_data_loss_schema": "tests.integration.test_zero_data_loss_schema",
    "tmp_ldif_path": "tests.integration.conftest",
    "typings": "tests.integration.typings",
    "unique_dn_suffix": "tests.integration.conftest",
    "writer": "tests.integration.conftest",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
