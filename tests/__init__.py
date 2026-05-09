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
    from flext_ldap import d, e, h, r, x
    from flext_tests import td, tf, tk, tm, tv

    from tests.base import TestsFlextLdifServiceBase, s
    from tests.constants import TestsFlextLdifConstants, c
    from tests.integration.test_acl_metadata_preservation import (
        TestsFlextLdifAclMetadataPreservation,
    )
    from tests.integration.test_api_integration import TestsFlextLdifApiIntegration
    from tests.integration.test_categorization_real_data import (
        TestsFlextLdifCategorizationRealData,
    )
    from tests.integration.test_config_integration import (
        TestsFlextLdifConfigIntegration,
    )
    from tests.integration.test_cross_direction_conversion import (
        TestsTestFlextLdifCrossDirectionConversion,
    )
    from tests.integration.test_cross_server_conversion import (
        TestsFlextLdifCrossServerConversion,
    )
    from tests.integration.test_dn_case_handling import TestsFlextLdifDnCaseHandling
    from tests.integration.test_edge_cases import TestsFlextLdifEdgeCasesInt
    from tests.integration.test_error_recovery import TestsFlextLdifErrorRecovery
    from tests.integration.test_ldif_fixtures_integration import (
        TestsFlextLdifLdifFixturesIntegration,
    )
    from tests.integration.test_minimal_differences_metadata import (
        TestsFlextLdifMinimalDifferencesMetadata,
    )
    from tests.integration.test_oid_integration import TestsFlextLdifOidIntegration
    from tests.integration.test_oud_integration import TestsFlextLdifOudIntegration
    from tests.integration.test_oud_to_oid_migration import (
        TestsFlextLdifOudToOidMigration,
    )
    from tests.integration.test_pipeline_integration import (
        TestsFlextLdifPipelineIntegration,
    )
    from tests.integration.test_real_ldap_config import TestsFlextLdifRealLdapConfig
    from tests.integration.test_real_ldap_export import TestsFlextLdifRealLdapExport
    from tests.integration.test_real_ldap_import import TestsFlextLdifRealLdapImport
    from tests.integration.test_real_ldap_roundtrip import (
        TestsFlextLdifRealLdapRoundtrip,
    )
    from tests.integration.test_rfc_docker_real import TestsFlextLdifRfcDockerReal
    from tests.integration.test_rfc_docker_real_integration import (
        TestsFlextLdifRfcDockerRealIntegration,
    )
    from tests.integration.test_simple_ldap import TestsFlextLdifSimpleLdap
    from tests.integration.test_systematic_fixture_coverage import (
        TestsFlextLdifSystematicFixtureCoverage,
    )
    from tests.integration.test_zero_data_loss_oid_oud import (
        TestsFlextLdifZeroDataLossOidOud,
    )
    from tests.models import TestsFlextLdifModels, m
    from tests.protocols import TestsFlextLdifProtocols, p
    from tests.settings import TestsFlextLdifSettings
    from tests.typings import TestsFlextLdifTypes, t
    from tests.unit.servers.test_apache_servers import TestsTestFlextLdifApacheServers
    from tests.unit.servers.test_ds389_servers import TestsTestFlextLdifDs389Servers
    from tests.unit.servers.test_edge_cases import TestsFlextLdifEdgeCases
    from tests.unit.servers.test_novell_servers import TestsFlextLdifNovellServers
    from tests.unit.servers.test_oid_servers import TestsTestFlextLdifOidServers
    from tests.unit.servers.test_relaxed_servers import TestsTestFlextLdifRelaxedServers
    from tests.unit.servers.test_schema_transformer import (
        TestsFlextLdifSchemaTransformer,
    )
    from tests.unit.services.test_acl_service import TestsFlextLdifAclService
    from tests.unit.services.test_analysis_service import TestsFlextLdifAnalysisService
    from tests.unit.services.test_api_server_registry import (
        TestsTestFlextLdifApiServerRegistry,
    )
    from tests.unit.services.test_detector_service import TestsFlextLdifDetectorService
    from tests.unit.services.test_entries_service import TestsFlextLdifEntriesService
    from tests.unit.services.test_filters_service import TestsFlextLdifFiltersService
    from tests.unit.services.test_migration_pipeline import (
        TestsFlextLdifProcessingPipeline,
        TestsTestFlextLdifMigrationPipeline,
    )
    from tests.unit.services.test_parser_service import TestsFlextLdifParserService
    from tests.unit.services.test_processing_service import (
        TestsFlextLdifProcessingService,
    )
    from tests.unit.services.test_servers_standardization import (
        TestsFlextLdifServersStandardization,
    )
    from tests.unit.services.test_statistics_service import (
        TestsFlextLdifStatisticsService,
    )
    from tests.unit.services.test_transformers_service import (
        TestsFlextLdifTransformerService,
    )
    from tests.unit.services.test_validation_service import (
        TestsFlextLdifValidationService,
    )
    from tests.unit.services.test_writer_service import TestsFlextLdifWriterService
    from tests.unit.test_acl_registry import TestsFlextLdifAclRegistry
    from tests.unit.test_collections_models import TestsFlextLdifCollectionsModels
    from tests.unit.test_constants_data_driven import TestsFlextLdifConstantsDataDriven
    from tests.unit.test_migration_pipeline_servers import (
        TestsFlextLdifMigrationPipelineServers,
    )
    from tests.unit.test_oid_utilities import TestsFlextLdifOidUtilities
    from tests.unit.test_parser_utilities import TestsFlextLdifParserUtilities
    from tests.unit.test_version import TestsFlextLdifVersion
    from tests.unit.utilities.test_utilities_comprehensive import (
        TestsFlextLdifUtilitiesComprehensive,
    )
    from tests.unit.utilities.test_utilities_core import TestsFlextLdifUtilitiesCore
    from tests.utilities import TestsFlextLdifUtilities, u
_LAZY_IMPORTS = merge_lazy_imports(
    (
        ".integration",
        ".unit",
    ),
    build_lazy_import_map(
        {
            ".base": (
                "TestsFlextLdifServiceBase",
                "s",
            ),
            ".constants": (
                "TestsFlextLdifConstants",
                "c",
            ),
            ".integration.test_acl_metadata_preservation": (
                "TestsFlextLdifAclMetadataPreservation",
            ),
            ".integration.test_api_integration": ("TestsFlextLdifApiIntegration",),
            ".integration.test_categorization_real_data": (
                "TestsFlextLdifCategorizationRealData",
            ),
            ".integration.test_config_integration": (
                "TestsFlextLdifConfigIntegration",
            ),
            ".integration.test_cross_direction_conversion": (
                "TestsTestFlextLdifCrossDirectionConversion",
            ),
            ".integration.test_cross_server_conversion": (
                "TestsFlextLdifCrossServerConversion",
            ),
            ".integration.test_dn_case_handling": ("TestsFlextLdifDnCaseHandling",),
            ".integration.test_edge_cases": ("TestsFlextLdifEdgeCasesInt",),
            ".integration.test_error_recovery": ("TestsFlextLdifErrorRecovery",),
            ".integration.test_ldif_fixtures_integration": (
                "TestsFlextLdifLdifFixturesIntegration",
            ),
            ".integration.test_minimal_differences_metadata": (
                "TestsFlextLdifMinimalDifferencesMetadata",
            ),
            ".integration.test_oid_integration": ("TestsFlextLdifOidIntegration",),
            ".integration.test_oud_integration": ("TestsFlextLdifOudIntegration",),
            ".integration.test_oud_to_oid_migration": (
                "TestsFlextLdifOudToOidMigration",
            ),
            ".integration.test_pipeline_integration": (
                "TestsFlextLdifPipelineIntegration",
            ),
            ".integration.test_real_ldap_config": ("TestsFlextLdifRealLdapConfig",),
            ".integration.test_real_ldap_export": ("TestsFlextLdifRealLdapExport",),
            ".integration.test_real_ldap_import": ("TestsFlextLdifRealLdapImport",),
            ".integration.test_real_ldap_roundtrip": (
                "TestsFlextLdifRealLdapRoundtrip",
            ),
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
            ".unit.servers.test_apache_servers": ("TestsTestFlextLdifApacheServers",),
            ".unit.servers.test_ds389_servers": ("TestsTestFlextLdifDs389Servers",),
            ".unit.servers.test_edge_cases": ("TestsFlextLdifEdgeCases",),
            ".unit.servers.test_novell_servers": ("TestsFlextLdifNovellServers",),
            ".unit.servers.test_oid_servers": ("TestsTestFlextLdifOidServers",),
            ".unit.servers.test_relaxed_servers": ("TestsTestFlextLdifRelaxedServers",),
            ".unit.servers.test_schema_transformer": (
                "TestsFlextLdifSchemaTransformer",
            ),
            ".unit.services.test_acl_service": ("TestsFlextLdifAclService",),
            ".unit.services.test_analysis_service": ("TestsFlextLdifAnalysisService",),
            ".unit.services.test_api_server_registry": (
                "TestsTestFlextLdifApiServerRegistry",
            ),
            ".unit.services.test_detector_service": ("TestsFlextLdifDetectorService",),
            ".unit.services.test_entries_service": ("TestsFlextLdifEntriesService",),
            ".unit.services.test_filters_service": ("TestsFlextLdifFiltersService",),
            ".unit.services.test_migration_pipeline": (
                "TestsFlextLdifProcessingPipeline",
                "TestsTestFlextLdifMigrationPipeline",
            ),
            ".unit.services.test_parser_service": ("TestsFlextLdifParserService",),
            ".unit.services.test_processing_service": (
                "TestsFlextLdifProcessingService",
            ),
            ".unit.services.test_servers_standardization": (
                "TestsFlextLdifServersStandardization",
            ),
            ".unit.services.test_statistics_service": (
                "TestsFlextLdifStatisticsService",
            ),
            ".unit.services.test_transformers_service": (
                "TestsFlextLdifTransformerService",
            ),
            ".unit.services.test_validation_service": (
                "TestsFlextLdifValidationService",
            ),
            ".unit.services.test_writer_service": ("TestsFlextLdifWriterService",),
            ".unit.test_acl_registry": ("TestsFlextLdifAclRegistry",),
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
            "flext_ldap": (
                "d",
                "e",
                "h",
                "r",
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
    module_name=__name__,
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)

__all__: list[str] = [
    "TestsFlextLdifAclMetadataPreservation",
    "TestsFlextLdifAclRegistry",
    "TestsFlextLdifAclService",
    "TestsFlextLdifAnalysisService",
    "TestsFlextLdifApiIntegration",
    "TestsFlextLdifCategorizationRealData",
    "TestsFlextLdifCollectionsModels",
    "TestsFlextLdifConfigIntegration",
    "TestsFlextLdifConstants",
    "TestsFlextLdifConstantsDataDriven",
    "TestsFlextLdifCrossServerConversion",
    "TestsFlextLdifDetectorService",
    "TestsFlextLdifDnCaseHandling",
    "TestsFlextLdifEdgeCases",
    "TestsFlextLdifEdgeCasesInt",
    "TestsFlextLdifEntriesService",
    "TestsFlextLdifErrorRecovery",
    "TestsFlextLdifFiltersService",
    "TestsFlextLdifLdifFixturesIntegration",
    "TestsFlextLdifMigrationPipelineServers",
    "TestsFlextLdifMinimalDifferencesMetadata",
    "TestsFlextLdifModels",
    "TestsFlextLdifNovellServers",
    "TestsFlextLdifOidIntegration",
    "TestsFlextLdifOidUtilities",
    "TestsFlextLdifOudIntegration",
    "TestsFlextLdifOudToOidMigration",
    "TestsFlextLdifParserService",
    "TestsFlextLdifParserUtilities",
    "TestsFlextLdifPipelineIntegration",
    "TestsFlextLdifProcessingPipeline",
    "TestsFlextLdifProcessingService",
    "TestsFlextLdifProtocols",
    "TestsFlextLdifRealLdapConfig",
    "TestsFlextLdifRealLdapExport",
    "TestsFlextLdifRealLdapImport",
    "TestsFlextLdifRealLdapRoundtrip",
    "TestsFlextLdifRfcDockerReal",
    "TestsFlextLdifRfcDockerRealIntegration",
    "TestsFlextLdifSchemaTransformer",
    "TestsFlextLdifServersStandardization",
    "TestsFlextLdifServiceBase",
    "TestsFlextLdifSettings",
    "TestsFlextLdifSimpleLdap",
    "TestsFlextLdifStatisticsService",
    "TestsFlextLdifSystematicFixtureCoverage",
    "TestsFlextLdifTransformerService",
    "TestsFlextLdifTypes",
    "TestsFlextLdifUtilities",
    "TestsFlextLdifUtilitiesComprehensive",
    "TestsFlextLdifUtilitiesCore",
    "TestsFlextLdifValidationService",
    "TestsFlextLdifVersion",
    "TestsFlextLdifWriterService",
    "TestsFlextLdifZeroDataLossOidOud",
    "TestsTestFlextLdifApacheServers",
    "TestsTestFlextLdifApiServerRegistry",
    "TestsTestFlextLdifCrossDirectionConversion",
    "TestsTestFlextLdifDs389Servers",
    "TestsTestFlextLdifMigrationPipeline",
    "TestsTestFlextLdifOidServers",
    "TestsTestFlextLdifRelaxedServers",
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
