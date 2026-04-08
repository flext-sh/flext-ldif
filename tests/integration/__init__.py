# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Integration package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports

if _t.TYPE_CHECKING:
    import tests.integration.conftest as _tests_integration_conftest

    conftest = _tests_integration_conftest
    import tests.integration.test_acl_metadata_preservation as _tests_integration_test_acl_metadata_preservation
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

    test_acl_metadata_preservation = _tests_integration_test_acl_metadata_preservation
    import tests.integration.test_api_integration as _tests_integration_test_api_integration
    from tests.integration.test_acl_metadata_preservation import (
        TestAclRoundTripPreservation,
        TestOidAclMetadataPreservation,
        TestOudAciMetadataPreservation,
    )

    test_api_integration = _tests_integration_test_api_integration
    import tests.integration.test_categorization_real_data as _tests_integration_test_categorization_real_data
    from tests.integration.test_api_integration import TestFlextLdifAPIIntegration

    test_categorization_real_data = _tests_integration_test_categorization_real_data
    import tests.integration.test_config_integration as _tests_integration_test_config_integration
    from tests.integration.test_categorization_real_data import (
        TestCategorizationRealData,
    )

    test_config_integration = _tests_integration_test_config_integration
    import tests.integration.test_cross_direction_conversion as _tests_integration_test_cross_direction_conversion
    from tests.integration.test_config_integration import (
        ConfigTestData,
        TestFlextLdifSettingsIntegration,
        logger,
    )

    test_cross_direction_conversion = _tests_integration_test_cross_direction_conversion
    import tests.integration.test_cross_quirk_conversion as _tests_integration_test_cross_quirk_conversion
    from tests.integration.test_cross_direction_conversion import (
        TestsTestFlextLdifCrossDirectionConversion,
    )

    test_cross_quirk_conversion = _tests_integration_test_cross_quirk_conversion
    import tests.integration.test_dn_case_handling as _tests_integration_test_dn_case_handling
    from tests.integration.test_cross_quirk_conversion import (
        TestOidToOudAclConversion,
        TestOidToOudIntegrationConversion,
        TestOidToOudSchemaConversion,
        TestQuirksConversionMatrixFacade,
    )

    test_dn_case_handling = _tests_integration_test_dn_case_handling
    import tests.integration.test_edge_cases as _tests_integration_test_edge_cases
    from tests.integration.test_dn_case_handling import (
        TestDnCaseNormalizationScenarios,
        TestDnCaseRegistry,
    )

    test_edge_cases = _tests_integration_test_edge_cases
    import tests.integration.test_error_recovery as _tests_integration_test_error_recovery
    from tests.integration.test_edge_cases import (
        TestBoundaryValues,
        TestEmptyAndMinimalCases,
        TestLargeAndComplexCases,
        TestRoundtripEdgeCases,
        TestUnicodeBoundaries,
    )

    test_error_recovery = _tests_integration_test_error_recovery
    import tests.integration.test_ldif_fixtures_integration as _tests_integration_test_ldif_fixtures_integration
    from tests.integration.test_error_recovery import (
        TestEncodingErrors,
        TestIncompleteEntries,
        TestInvalidSchemaDefinitions,
        TestMalformedLdifHandling,
    )

    test_ldif_fixtures_integration = _tests_integration_test_ldif_fixtures_integration
    import tests.integration.test_minimal_differences_metadata as _tests_integration_test_minimal_differences_metadata
    from tests.integration.test_ldif_fixtures_integration import TestsFlextLdifFixtures

    test_minimal_differences_metadata = (
        _tests_integration_test_minimal_differences_metadata
    )
    import tests.integration.test_oid_integration as _tests_integration_test_oid_integration
    from tests.integration.test_minimal_differences_metadata import (
        TestMinimalDifferencesOidOud,
    )

    test_oid_integration = _tests_integration_test_oid_integration
    import tests.integration.test_oud_integration as _tests_integration_test_oud_integration
    from tests.integration.test_oid_integration import (
        TestOidEntryIntegration,
        TestOidRoundTripIntegration,
        TestOidSchemaIntegration,
    )

    test_oud_integration = _tests_integration_test_oud_integration
    import tests.integration.test_oud_to_oid_migration as _tests_integration_test_oud_to_oid_migration
    from tests.integration.test_oud_integration import (
        TestOudAclIntegration,
        TestOudEntryIntegration,
        TestOudMetadataPreservation,
        TestOudRoundTripIntegration,
        TestOudSchemaIntegration,
    )

    test_oud_to_oid_migration = _tests_integration_test_oud_to_oid_migration
    import tests.integration.test_pipeline_integration as _tests_integration_test_pipeline_integration
    from tests.integration.test_oud_to_oid_migration import (
        TestOudToOidAclMigration,
        TestOudToOidEntryMigration,
        TestOudToOidFullMigration,
        TestOudToOidSchemaMigration,
    )

    test_pipeline_integration = _tests_integration_test_pipeline_integration
    import tests.integration.test_quirks_transformations as _tests_integration_test_quirks_transformations
    from tests.integration.test_pipeline_integration import TestFlextLdifFacadeWorkflows

    test_quirks_transformations = _tests_integration_test_quirks_transformations
    import tests.integration.test_real_ldap_config as _tests_integration_test_real_ldap_config
    from tests.integration.test_quirks_transformations import (
        TestOidQuirksTransformations,
        TestOudQuirksTransformations,
        TestQuirksPropertyValidation,
        fixtures_dir,
        migration_inputs,
    )

    test_real_ldap_config = _tests_integration_test_real_ldap_config
    import tests.integration.test_real_ldap_crud as _tests_integration_test_real_ldap_crud
    from tests.integration.test_real_ldap_config import (
        TestRealLdapConfigurationFromEnv,
        TestRealLdapRailwayComposition,
    )

    test_real_ldap_crud = _tests_integration_test_real_ldap_crud
    import tests.integration.test_real_ldap_export as _tests_integration_test_real_ldap_export
    from tests.integration.test_real_ldap_crud import (
        TestRealLdapBatchOperations,
        TestRealLdapCRUD,
    )

    test_real_ldap_export = _tests_integration_test_real_ldap_export
    import tests.integration.test_real_ldap_import as _tests_integration_test_real_ldap_import
    from tests.integration.test_real_ldap_export import TestRealLdapExport

    test_real_ldap_import = _tests_integration_test_real_ldap_import
    import tests.integration.test_real_ldap_roundtrip as _tests_integration_test_real_ldap_roundtrip
    from tests.integration.test_real_ldap_import import TestRealLdapImport

    test_real_ldap_roundtrip = _tests_integration_test_real_ldap_roundtrip
    import tests.integration.test_rfc_docker_real as _tests_integration_test_rfc_docker_real
    from tests.integration.test_real_ldap_roundtrip import TestRealLdapRoundtrip

    test_rfc_docker_real = _tests_integration_test_rfc_docker_real
    import tests.integration.test_rfc_docker_real_integration as _tests_integration_test_rfc_docker_real_integration
    from tests.integration.test_rfc_docker_real import (
        TestRfcDockerRealData,
        TestRfcIntegrationRealWorld,
    )

    test_rfc_docker_real_integration = (
        _tests_integration_test_rfc_docker_real_integration
    )
    import tests.integration.test_simple_ldap as _tests_integration_test_simple_ldap
    from tests.integration.test_rfc_docker_real_integration import (
        TestRfcExceptionHandlingRealScenarios,
        TestRfcParserRealFixtures,
        TestRfcSchemaParserRealFixtures,
        TestRfcWriterRealFixtures,
    )

    test_simple_ldap = _tests_integration_test_simple_ldap
    import tests.integration.test_systematic_fixture_coverage as _tests_integration_test_systematic_fixture_coverage
    from tests.integration.test_simple_ldap import (
        test_create_and_export_entry,
        test_ldap_connection,
        test_simple_ldap_search,
    )

    test_systematic_fixture_coverage = (
        _tests_integration_test_systematic_fixture_coverage
    )
    import tests.integration.test_zero_data_loss_oid_oud as _tests_integration_test_zero_data_loss_oid_oud
    from tests.integration.test_systematic_fixture_coverage import (
        TestSystematicFixtureCoverage,
    )

    test_zero_data_loss_oid_oud = _tests_integration_test_zero_data_loss_oid_oud
    import tests.integration.test_zero_data_loss_schema as _tests_integration_test_zero_data_loss_schema
    from tests.integration.test_zero_data_loss_oid_oud import TestZeroDataLossOidOud

    test_zero_data_loss_schema = _tests_integration_test_zero_data_loss_schema
    import tests.integration.typings as _tests_integration_typings
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

    typings = _tests_integration_typings
    from flext_core.constants import FlextConstants as c
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.models import FlextModels as m
    from flext_core.protocols import FlextProtocols as p
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
    from flext_core.typings import FlextTypes as t
    from flext_core.utilities import FlextUtilities as u
_LAZY_IMPORTS = {
    "ConfigTestData": ("tests.integration.test_config_integration", "ConfigTestData"),
    "TestAclRoundTripPreservation": (
        "tests.integration.test_acl_metadata_preservation",
        "TestAclRoundTripPreservation",
    ),
    "TestBoundaryValues": ("tests.integration.test_edge_cases", "TestBoundaryValues"),
    "TestCategorizationRealData": (
        "tests.integration.test_categorization_real_data",
        "TestCategorizationRealData",
    ),
    "TestDnCaseNormalizationScenarios": (
        "tests.integration.test_dn_case_handling",
        "TestDnCaseNormalizationScenarios",
    ),
    "TestDnCaseRegistry": (
        "tests.integration.test_dn_case_handling",
        "TestDnCaseRegistry",
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
    "TestFlextLdifFacadeWorkflows": (
        "tests.integration.test_pipeline_integration",
        "TestFlextLdifFacadeWorkflows",
    ),
    "TestFlextLdifSettingsIntegration": (
        "tests.integration.test_config_integration",
        "TestFlextLdifSettingsIntegration",
    ),
    "TestIncompleteEntries": (
        "tests.integration.test_error_recovery",
        "TestIncompleteEntries",
    ),
    "TestInvalidSchemaDefinitions": (
        "tests.integration.test_error_recovery",
        "TestInvalidSchemaDefinitions",
    ),
    "TestLargeAndComplexCases": (
        "tests.integration.test_edge_cases",
        "TestLargeAndComplexCases",
    ),
    "TestMalformedLdifHandling": (
        "tests.integration.test_error_recovery",
        "TestMalformedLdifHandling",
    ),
    "TestMinimalDifferencesOidOud": (
        "tests.integration.test_minimal_differences_metadata",
        "TestMinimalDifferencesOidOud",
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
    "TestQuirksConversionMatrixFacade": (
        "tests.integration.test_cross_quirk_conversion",
        "TestQuirksConversionMatrixFacade",
    ),
    "TestQuirksPropertyValidation": (
        "tests.integration.test_quirks_transformations",
        "TestQuirksPropertyValidation",
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
    "TestSystematicFixtureCoverage": (
        "tests.integration.test_systematic_fixture_coverage",
        "TestSystematicFixtureCoverage",
    ),
    "TestUnicodeBoundaries": (
        "tests.integration.test_edge_cases",
        "TestUnicodeBoundaries",
    ),
    "TestZeroDataLossOidOud": (
        "tests.integration.test_zero_data_loss_oid_oud",
        "TestZeroDataLossOidOud",
    ),
    "TestsFlextLdifFixtures": (
        "tests.integration.test_ldif_fixtures_integration",
        "TestsFlextLdifFixtures",
    ),
    "TestsTestFlextLdifCrossDirectionConversion": (
        "tests.integration.test_cross_direction_conversion",
        "TestsTestFlextLdifCrossDirectionConversion",
    ),
    "all_acl_fixtures": ("tests.integration.conftest", "all_acl_fixtures"),
    "all_entries_fixtures": ("tests.integration.conftest", "all_entries_fixtures"),
    "all_integration_fixtures": (
        "tests.integration.conftest",
        "all_integration_fixtures",
    ),
    "all_schema_fixtures": ("tests.integration.conftest", "all_schema_fixtures"),
    "api": ("tests.integration.conftest", "api"),
    "c": ("flext_core.constants", "FlextConstants"),
    "clean_test_ou": ("tests.integration.conftest", "clean_test_ou"),
    "conftest": "tests.integration.conftest",
    "conversion_matrix": ("tests.integration.conftest", "conversion_matrix"),
    "d": ("flext_core.decorators", "FlextDecorators"),
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "fixtures_dir": ("tests.integration.test_quirks_transformations", "fixtures_dir"),
    "h": ("flext_core.handlers", "FlextHandlers"),
    "ldap_connection": ("tests.integration.conftest", "ldap_connection"),
    "ldap_container": ("tests.integration.conftest", "ldap_container"),
    "ldap_container_shared": ("tests.integration.conftest", "ldap_container_shared"),
    "logger": ("tests.integration.test_config_integration", "logger"),
    "m": ("flext_core.models", "FlextModels"),
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
    "p": ("flext_core.protocols", "FlextProtocols"),
    "parser": ("tests.integration.conftest", "parser"),
    "r": ("flext_core.result", "FlextResult"),
    "rfc_schema_entries": ("tests.integration.conftest", "rfc_schema_entries"),
    "rfc_schema_fixture": ("tests.integration.conftest", "rfc_schema_fixture"),
    "s": ("flext_core.service", "FlextService"),
    "server": ("tests.integration.conftest", "server"),
    "t": ("flext_core.typings", "FlextTypes"),
    "test_acl_metadata_preservation": "tests.integration.test_acl_metadata_preservation",
    "test_api_integration": "tests.integration.test_api_integration",
    "test_categorization_real_data": "tests.integration.test_categorization_real_data",
    "test_config_integration": "tests.integration.test_config_integration",
    "test_create_and_export_entry": (
        "tests.integration.test_simple_ldap",
        "test_create_and_export_entry",
    ),
    "test_cross_direction_conversion": "tests.integration.test_cross_direction_conversion",
    "test_cross_quirk_conversion": "tests.integration.test_cross_quirk_conversion",
    "test_dn_case_handling": "tests.integration.test_dn_case_handling",
    "test_edge_cases": "tests.integration.test_edge_cases",
    "test_error_recovery": "tests.integration.test_error_recovery",
    "test_ldap_connection": (
        "tests.integration.test_simple_ldap",
        "test_ldap_connection",
    ),
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
    "test_simple_ldap_search": (
        "tests.integration.test_simple_ldap",
        "test_simple_ldap_search",
    ),
    "test_systematic_fixture_coverage": "tests.integration.test_systematic_fixture_coverage",
    "test_zero_data_loss_oid_oud": "tests.integration.test_zero_data_loss_oid_oud",
    "test_zero_data_loss_schema": "tests.integration.test_zero_data_loss_schema",
    "tmp_ldif_path": ("tests.integration.conftest", "tmp_ldif_path"),
    "typings": "tests.integration.typings",
    "u": ("flext_core.utilities", "FlextUtilities"),
    "unique_dn_suffix": ("tests.integration.conftest", "unique_dn_suffix"),
    "writer": ("tests.integration.conftest", "writer"),
    "x": ("flext_core.mixins", "FlextMixins"),
}

__all__ = [
    "ConfigTestData",
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
    "TestsTestFlextLdifCrossDirectionConversion",
    "all_acl_fixtures",
    "all_entries_fixtures",
    "all_integration_fixtures",
    "all_schema_fixtures",
    "api",
    "c",
    "clean_test_ou",
    "conftest",
    "conversion_matrix",
    "d",
    "e",
    "fixtures_dir",
    "h",
    "ldap_connection",
    "ldap_container",
    "ldap_container_shared",
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
    "parser",
    "r",
    "rfc_schema_entries",
    "rfc_schema_fixture",
    "s",
    "server",
    "t",
    "test_acl_metadata_preservation",
    "test_api_integration",
    "test_categorization_real_data",
    "test_config_integration",
    "test_create_and_export_entry",
    "test_cross_direction_conversion",
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
    "u",
    "unique_dn_suffix",
    "writer",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
