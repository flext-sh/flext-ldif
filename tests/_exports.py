# AUTO-GENERATED FILE — Regenerate with: make gen
"""Lazy export registry."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, merge_lazy_imports

_LOCAL_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".base": (
            "TestsFlextLdifServiceBase",
            "s",
        ),
        ".conftest": ("conftest",),
        ".constants": (
            "TestsFlextLdifConstants",
            "c",
        ),
        ".integration": ("integration",),
        ".integration.test_acl_metadata_preservation": (
            "TestsFlextLdifAclMetadataPreservation",
        ),
        ".integration.test_api_integration": ("TestsFlextLdifApiIntegration",),
        ".integration.test_categorization_real_data": (
            "TestsFlextLdifCategorizationRealData",
        ),
        ".integration.test_config_integration": ("TestsFlextLdifConfigIntegration",),
        ".integration.test_cross_direction_conversion": (
            "TestsFlextLdifCrossDirectionConversion",
        ),
        ".integration.test_cross_server_conversion": (
            "TestsFlextLdifCrossServerConversion",
        ),
        ".integration.test_dn_case_handling": ("TestsFlextLdifDnCaseHandling",),
        ".integration.test_edge_cases": ("TestsFlextLdifEdgeCases",),
        ".integration.test_error_recovery": ("TestsFlextLdifErrorRecovery",),
        ".integration.test_ldif_fixtures_integration": (
            "TestsFlextLdifLdifFixturesIntegration",
        ),
        ".integration.test_minimal_differences_metadata": (
            "TestsFlextLdifMinimalDifferencesMetadata",
        ),
        ".integration.test_oid_integration": ("TestsFlextLdifOidIntegration",),
        ".integration.test_oud_integration": ("TestsFlextLdifOudIntegration",),
        ".integration.test_oud_to_oid_migration": ("TestsFlextLdifOudToOidMigration",),
        ".integration.test_pipeline_integration": (
            "TestsFlextLdifPipelineIntegration",
        ),
        ".integration.test_real_ldap_config": ("TestsFlextLdifRealLdapConfig",),
        ".integration.test_real_ldap_export": ("TestsFlextLdifRealLdapExport",),
        ".integration.test_real_ldap_import": ("TestsFlextLdifRealLdapImport",),
        ".integration.test_real_ldap_roundtrip": ("TestsFlextLdifRealLdapRoundtrip",),
        ".integration.test_rfc_docker_real": ("TestsFlextLdifRfcDockerReal",),
        ".integration.test_rfc_docker_real_integration": (
            "TestsFlextLdifRfcDockerRealIntegration",
        ),
        ".integration.test_simple_ldap": ("TestsFlextLdifSimpleLdap",),
        ".integration.test_systematic_fixture_coverage": (
            "TestsFlextLdifSystematicFixtureCoverage",
        ),
        ".integration.test_zero_data_loss_oid_oud": (
            "TestsFlextLdifZeroDataLossOidOud",
        ),
        ".models": (
            "TestsFlextLdifModels",
            "m",
        ),
        ".protocols": (
            "TestsFlextLdifProtocols",
            "p",
        ),
        ".settings": ("TestsFlextLdifSettings",),
        ".typings": (
            "TestsFlextLdifTypes",
            "t",
        ),
        ".unit": ("unit",),
        ".unit.servers.test_apache_servers": ("TestsFlextLdifApacheServers",),
        ".unit.servers.test_ds389_servers": ("TestsFlextLdifDs389Servers",),
        ".unit.servers.test_novell_servers": ("TestsFlextLdifNovellServers",),
        ".unit.servers.test_oid_acl_assemble": ("TestsFlextLdifOidAclAssemble",),
        ".unit.servers.test_oid_acl_convert": ("TestsFlextLdifOidAclConvert",),
        ".unit.servers.test_oid_acl_convert_oud": ("TestsFlextLdifOidAclConvertOud",),
        ".unit.servers.test_oid_acl_endtoend": ("TestsFlextLdifOidAclEndToEnd",),
        ".unit.servers.test_oid_servers": ("TestsFlextLdifOidServers",),
        ".unit.servers.test_relaxed_servers": ("TestsFlextLdifRelaxed",),
        ".unit.servers.test_schema_transformer": ("TestsFlextLdifSchemaTransformer",),
        ".unit.services.test_acl_service": ("TestsFlextLdifAclService",),
        ".unit.services.test_analysis_service": ("TestsFlextLdifAnalysisService",),
        ".unit.services.test_api_server_registry": ("TestsFlextLdifApiServerRegistry",),
        ".unit.services.test_detector_service": ("TestsFlextLdifDetectorService",),
        ".unit.services.test_entries_service": ("TestsFlextLdifEntries",),
        ".unit.services.test_filters_service": ("TestsFlextLdifFiltersService",),
        ".unit.services.test_migration_pipeline": ("TestsFlextLdifMigrationPipeline",),
        ".unit.services.test_parser_service": ("TestsFlextLdifParserService",),
        ".unit.services.test_processing_service": ("TestsFlextLdifProcessingService",),
        ".unit.services.test_servers_standardization": (
            "TestsFlextLdifServersStandardization",
        ),
        ".unit.services.test_statistics_service": ("TestsFlextLdifStatisticsService",),
        ".unit.services.test_transformers_service": (
            "TestsFlextLdifTransformersService",
        ),
        ".unit.services.test_validation_service": ("TestsFlextLdifValidationService",),
        ".unit.services.test_writer_service": ("TestsFlextLdifWriterService",),
        ".unit.test_acl_registry": ("TestsFlextLdifAclRegistry",),
        ".unit.test_api_freeze": ("TestsFlextLdifApiFreeze",),
        ".unit.test_collections_models": ("TestsFlextLdifCollectionsModels",),
        ".unit.test_constants_data_driven": ("TestsFlextLdifConstantsDataDriven",),
        ".unit.test_migration_pipeline_servers": (
            "TestsFlextLdifMigrationPipelineServers",
        ),
        ".unit.test_oid_utilities": ("TestsFlextLdifOidUtilities",),
        ".unit.test_parser_utilities": ("TestsFlextLdifParserUtilities",),
        ".unit.test_version": ("TestsFlextLdifVersion",),
        ".unit.utilities.test_utilities_comprehensive": (
            "TestsFlextLdifUtilitiesComprehensive",
        ),
        ".unit.utilities.test_utilities_core": ("TestsFlextLdifUtilitiesCore",),
        ".utilities": (
            "TestsFlextLdifUtilities",
            "u",
        ),
        "flext_tests": (
            "d",
            "e",
            "h",
            "r",
            "td",
            "tf",
            "tk",
            "tm",
            "tv",
            "x",
        ),
    },
)

TESTS_FLEXT_LDIF_LAZY_IMPORTS = merge_lazy_imports(
    (
        ".integration",
        ".unit",
    ),
    _LOCAL_LAZY_IMPORTS,
    exclude_names=(
        "cleanup_submodule_namespace",
        "install_lazy_exports",
        "lazy_getattr",
        "logger",
        "merge_lazy_imports",
        "output",
        "output_reporting",
        "pytest_addoption",
        "pytest_collect_file",
        "pytest_collection_modifyitems",
        "pytest_configure",
        "pytest_runtest_setup",
        "pytest_runtest_teardown",
        "pytest_sessionfinish",
        "pytest_sessionstart",
        "pytest_terminal_summary",
        "pytest_warning_recorded",
    ),
    module_name="tests",
)

__all__: list[str] = ["TESTS_FLEXT_LDIF_LAZY_IMPORTS"]
