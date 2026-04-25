# AUTO-GENERATED FILE — Regenerate with: make gen
"""Unit package."""

from __future__ import annotations

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)

_LAZY_IMPORTS = merge_lazy_imports(
    (
        ".servers",
        ".services",
        ".utilities",
    ),
    build_lazy_import_map(
        {
            ".servers.test_apache_quirks": ("TestsTestFlextLdifApacheQuirks",),
            ".servers.test_ds389_quirks": ("TestsTestFlextLdifDs389Quirks",),
            ".servers.test_edge_cases": ("TestsFlextLdifEdgeCases",),
            ".servers.test_novell_quirks": (
                "TestNovellAcls",
                "TestNovellEntryDetection",
                "TestNovellSchemaAttributeDetection",
                "TestNovellSchemaAttributeParsing",
                "TestNovellSchemaObjectClassDetection",
                "TestNovellSchemaObjectClassParsing",
                "TestsFlextLdifNovellInitialization",
            ),
            ".servers.test_oid_quirks": ("TestsTestFlextLdifOidQuirks",),
            ".servers.test_relaxed_quirks": ("TestsTestFlextLdifRelaxedQuirks",),
            ".servers.test_schema_transformer": (
                "TestSchemaTransformerNormalizeMatchingRule",
                "TestSchemaTransformerNormalizeSyntaxOid",
                "TestsFlextLdifSchemaTransformerNormalizeAttributeName",
            ),
            ".services.test_api_server_registry": (
                "TestsTestFlextLdifApiServerRegistry",
            ),
            ".services.test_migration_pipeline": (
                "TestsTestFlextLdifMigrationPipeline",
            ),
            ".services.test_quirks_standardization": (
                "TestAliasDiscovery",
                "TestQuirksAutoInterchange",
                "TestQuirksWithRealLdifFixtures",
                "TestsFlextLdifServersStandardizedConstants",
            ),
            ".test_acl_registry": ("TestsFlextLdifAclRegistry",),
            ".test_migration_pipeline": ("TestsFlextLdifMigrationPipeline",),
            ".test_migration_pipeline_quirks": (
                "TestsFlextLdifMigrationPipelineQuirks",
            ),
            ".test_oid_utilities": ("TestsFlextLdifOidUtilities",),
            ".test_parser_utilities": ("TestsFlextLdifParserUtilities",),
            ".test_protocols": ("TestsFlextLdifProtocolsUnit",),
            ".test_server_utilities": ("TestsFlextLdifServerUtilities",),
            ".test_typings": ("TestsFlextLdifTypingsUnit",),
            ".test_version": ("TestsFlextLdifVersion",),
            ".utilities.test_utilities_comprehensive": (
                "TestFlextLdifUtilitiesComprehensive",
            ),
            ".utilities.test_utilities_core": (
                "TestAttributeFixer",
                "TestDnObjectClassMethods",
                "TestLdifParser",
                "TestObjectClassUtilities",
                "TestServerTypes",
                "TestsFlextLdifDnOperationsPure",
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


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
