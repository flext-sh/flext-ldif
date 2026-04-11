# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)

if _t.TYPE_CHECKING:
    from flext_ldif.test_acl_registry import TestsTestFlextLdifAclAttributeRegistry
    from flext_ldif.test_apache_quirks import TestsTestFlextLdifApacheQuirks
    from flext_ldif.test_ds389_quirks import TestsTestFlextLdifDs389Quirks
    from flext_ldif.test_edge_cases import (
        TestsFlextLdifEdgeCases,
        cleanup_state,
        ldif_api,
    )
    from flext_ldif.test_migration_pipeline import (
        TestsFlextLdifMigrationPipeline,
        TestsTestFlextLdifMigrationPipeline,
    )
    from flext_ldif.test_migration_pipeline_quirks import (
        TestsFlextLdifMigrationPipelineQuirks,
    )
    from flext_ldif.test_novell_quirks import (
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
    from flext_ldif.test_oid_quirks import TestsTestFlextLdifOidQuirks
    from flext_ldif.test_oid_utilities import TestFlextLdifUtilitiesOID
    from flext_ldif.test_parser_utilities import TestFlextLdifUtilitiesParser
    from flext_ldif.test_protocols import TestsTestFlextLdifProtocols
    from flext_ldif.test_quirks_standardization import (
        TestAliasDiscovery,
        TestQuirksAutoInterchange,
        TestQuirksWithRealLdifFixtures,
        TestsFlextLdifQuirksStandardizedConstants,
    )
    from flext_ldif.test_relaxed_quirks import TestsTestFlextLdifRelaxedQuirks
    from flext_ldif.test_schema_transformer import (
        TestSchemaTransformerNormalizeMatchingRule,
        TestSchemaTransformerNormalizeSyntaxOid,
        TestsFlextLdifSchemaTransformerNormalizeAttributeName,
    )
    from flext_ldif.test_server_utilities import TestFlextLdifUtilitiesServer
    from flext_ldif.test_typings import (
        TestFlextLdifTypesStructure,
        TestIntegrationWithLdifFixtures,
        TestModelsNamespace,
        TestPhase1StandardizationResults,
        TestRemovalOfOverEngineering,
        TestsFlextLdifCommonDictionaryTypes,
    )
    from flext_ldif.test_utilities_comprehensive import (
        TestFlextLdifUtilitiesComprehensive,
    )
    from flext_ldif.test_utilities_core import (
        TestAttributeFixer,
        TestDnObjectClassMethods,
        TestLdifParser,
        TestObjectClassUtilities,
        TestServerTypes,
        TestsFlextLdifDnOperationsPure,
    )
    from flext_ldif.test_version import TestsFlextLdifVersion, version_module
_LAZY_IMPORTS = merge_lazy_imports(
    (
        ".servers",
        ".services",
        ".utilities",
    ),
    build_lazy_import_map(
        {
            ".test_acl_registry": ("TestsTestFlextLdifAclAttributeRegistry",),
            ".test_apache_quirks": ("TestsTestFlextLdifApacheQuirks",),
            ".test_ds389_quirks": ("TestsTestFlextLdifDs389Quirks",),
            ".test_edge_cases": (
                "TestsFlextLdifEdgeCases",
                "cleanup_state",
                "ldif_api",
            ),
            ".test_migration_pipeline": (
                "TestsFlextLdifMigrationPipeline",
                "TestsTestFlextLdifMigrationPipeline",
            ),
            ".test_migration_pipeline_quirks": (
                "TestsFlextLdifMigrationPipelineQuirks",
            ),
            ".test_novell_quirks": (
                "TestNovellAcls",
                "TestNovellEntryDetection",
                "TestNovellSchemaAttributeDetection",
                "TestNovellSchemaAttributeParsing",
                "TestNovellSchemaObjectClassDetection",
                "TestNovellSchemaObjectClassParsing",
                "TestsFlextLdifNovellInitialization",
                "entry_quirk",
                "novell_server",
                "schema_quirk",
            ),
            ".test_oid_quirks": ("TestsTestFlextLdifOidQuirks",),
            ".test_oid_utilities": ("TestFlextLdifUtilitiesOID",),
            ".test_parser_utilities": ("TestFlextLdifUtilitiesParser",),
            ".test_protocols": ("TestsTestFlextLdifProtocols",),
            ".test_quirks_standardization": (
                "TestAliasDiscovery",
                "TestQuirksAutoInterchange",
                "TestQuirksWithRealLdifFixtures",
                "TestsFlextLdifQuirksStandardizedConstants",
            ),
            ".test_relaxed_quirks": ("TestsTestFlextLdifRelaxedQuirks",),
            ".test_schema_transformer": (
                "TestSchemaTransformerNormalizeMatchingRule",
                "TestSchemaTransformerNormalizeSyntaxOid",
                "TestsFlextLdifSchemaTransformerNormalizeAttributeName",
            ),
            ".test_server_utilities": ("TestFlextLdifUtilitiesServer",),
            ".test_typings": (
                "TestFlextLdifTypesStructure",
                "TestIntegrationWithLdifFixtures",
                "TestModelsNamespace",
                "TestPhase1StandardizationResults",
                "TestRemovalOfOverEngineering",
                "TestsFlextLdifCommonDictionaryTypes",
            ),
            ".test_utilities_comprehensive": ("TestFlextLdifUtilitiesComprehensive",),
            ".test_utilities_core": (
                "TestAttributeFixer",
                "TestDnObjectClassMethods",
                "TestLdifParser",
                "TestObjectClassUtilities",
                "TestServerTypes",
                "TestsFlextLdifDnOperationsPure",
            ),
            ".test_version": (
                "TestsFlextLdifVersion",
                "version_module",
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
    ),
    module_name=__name__,
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)

__all__ = [
    "TestAliasDiscovery",
    "TestAttributeFixer",
    "TestDnObjectClassMethods",
    "TestFlextLdifTypesStructure",
    "TestFlextLdifUtilitiesComprehensive",
    "TestFlextLdifUtilitiesOID",
    "TestFlextLdifUtilitiesParser",
    "TestFlextLdifUtilitiesServer",
    "TestIntegrationWithLdifFixtures",
    "TestLdifParser",
    "TestModelsNamespace",
    "TestNovellAcls",
    "TestNovellEntryDetection",
    "TestNovellSchemaAttributeDetection",
    "TestNovellSchemaAttributeParsing",
    "TestNovellSchemaObjectClassDetection",
    "TestNovellSchemaObjectClassParsing",
    "TestObjectClassUtilities",
    "TestPhase1StandardizationResults",
    "TestQuirksAutoInterchange",
    "TestQuirksWithRealLdifFixtures",
    "TestRemovalOfOverEngineering",
    "TestSchemaTransformerNormalizeMatchingRule",
    "TestSchemaTransformerNormalizeSyntaxOid",
    "TestServerTypes",
    "TestsFlextLdifCommonDictionaryTypes",
    "TestsFlextLdifDnOperationsPure",
    "TestsFlextLdifEdgeCases",
    "TestsFlextLdifMigrationPipeline",
    "TestsFlextLdifMigrationPipelineQuirks",
    "TestsFlextLdifNovellInitialization",
    "TestsFlextLdifQuirksStandardizedConstants",
    "TestsFlextLdifSchemaTransformerNormalizeAttributeName",
    "TestsFlextLdifVersion",
    "TestsTestFlextLdifAclAttributeRegistry",
    "TestsTestFlextLdifApacheQuirks",
    "TestsTestFlextLdifDs389Quirks",
    "TestsTestFlextLdifMigrationPipeline",
    "TestsTestFlextLdifOidQuirks",
    "TestsTestFlextLdifProtocols",
    "TestsTestFlextLdifRelaxedQuirks",
    "cleanup_state",
    "entry_quirk",
    "ldif_api",
    "novell_server",
    "schema_quirk",
    "version_module",
]
