# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Unit package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports, merge_lazy_imports

if _t.TYPE_CHECKING:
    import tests.unit.constants as _tests_unit_constants
    from tests.unit.__init__ import TestsFlextLdifVersion, test_version, version_module
    from tests.unit._utilities.oid import TestFlextLdifUtilitiesOID
    from tests.unit._utilities.parser import TestFlextLdifUtilitiesParser
    from tests.unit._utilities.server import TestFlextLdifUtilitiesServer

    constants = _tests_unit_constants
    import tests.unit.protocols as _tests_unit_protocols
    from tests.unit.constants import (
        TestsTestFlextLdifAclAttributeRegistry,
        test_acl_registry,
    )

    protocols = _tests_unit_protocols
    import tests.unit.services as _tests_unit_services
    from tests.unit.protocols import TestsTestFlextLdifProtocols, test_protocols
    from tests.unit.quirks.servers import (
        TestNovellAcls,
        TestNovellEntryDetection,
        TestNovellSchemaAttributeDetection,
        TestNovellSchemaAttributeParsing,
        TestNovellSchemaObjectClassDetection,
        TestNovellSchemaObjectClassParsing,
        TestSchemaTransformerNormalizeMatchingRule,
        TestSchemaTransformerNormalizeSyntaxOid,
        TestsFlextLdifEdgeCases,
        TestsFlextLdifNovellInitialization,
        TestsFlextLdifSchemaTransformerNormalizeAttributeName,
        TestsTestFlextLdifApacheQuirks,
        TestsTestFlextLdifDs389Quirks,
        TestsTestFlextLdifOidQuirks,
        TestsTestFlextLdifRelaxedQuirks,
        cleanup_state,
        entry_quirk,
        ldif_api,
        novell_server,
        schema_quirk,
    )

    services = _tests_unit_services
    import tests.unit.test_migration_pipeline as _tests_unit_test_migration_pipeline
    from tests.unit.services import (
        TestAliasDiscovery,
        TestQuirksAutoInterchange,
        TestQuirksWithRealLdifFixtures,
        TestsFlextLdifQuirksStandardizedConstants,
        TestsTestFlextLdifMigrationPipeline,
        test_quirks_standardization,
    )

    test_migration_pipeline = _tests_unit_test_migration_pipeline
    import tests.unit.test_migration_pipeline_quirks as _tests_unit_test_migration_pipeline_quirks
    from tests.unit.test_migration_pipeline import TestsFlextLdifMigrationPipeline

    test_migration_pipeline_quirks = _tests_unit_test_migration_pipeline_quirks
    import tests.unit.test_typings as _tests_unit_test_typings
    from tests.unit.test_migration_pipeline_quirks import (
        TestsFlextLdifMigrationPipelineQuirks,
    )

    test_typings = _tests_unit_test_typings
    import tests.unit.utilities as _tests_unit_utilities
    from tests.unit.test_typings import (
        TestFlextLdifTypesStructure,
        TestIntegrationWithLdifFixtures,
        TestModelsNamespace,
        TestPhase1StandardizationResults,
        TestRemovalOfOverEngineering,
        TestsFlextLdifCommonDictionaryTypes,
    )

    utilities = _tests_unit_utilities
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
    from tests.unit.utilities import (
        TestAttributeFixer,
        TestDnObjectClassMethods,
        TestFlextLdifUtilitiesComprehensive,
        TestLdifParser,
        TestObjectClassUtilities,
        TestServerTypes,
        TestsFlextLdifDnOperationsPure,
        test_utilities_comprehensive,
        test_utilities_core,
    )
_LAZY_IMPORTS = merge_lazy_imports(
    (
        "tests.unit.__init__",
        "tests.unit.constants",
        "tests.unit.protocols",
        "tests.unit.services",
        "tests.unit.utilities",
    ),
    {
        "TestFlextLdifTypesStructure": "tests.unit.test_typings",
        "TestFlextLdifUtilitiesOID": "tests.unit._utilities.oid.test_oid_utilities",
        "TestFlextLdifUtilitiesParser": "tests.unit._utilities.parser.test_parser_utilities",
        "TestFlextLdifUtilitiesServer": "tests.unit._utilities.server.test_server_utilities",
        "TestIntegrationWithLdifFixtures": "tests.unit.test_typings",
        "TestModelsNamespace": "tests.unit.test_typings",
        "TestNovellAcls": "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellEntryDetection": "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellSchemaAttributeDetection": "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellSchemaAttributeParsing": "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellSchemaObjectClassDetection": "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellSchemaObjectClassParsing": "tests.unit.quirks.servers.test_novell_quirks",
        "TestPhase1StandardizationResults": "tests.unit.test_typings",
        "TestRemovalOfOverEngineering": "tests.unit.test_typings",
        "TestSchemaTransformerNormalizeMatchingRule": "tests.unit.quirks.servers.test_schema_transformer",
        "TestSchemaTransformerNormalizeSyntaxOid": "tests.unit.quirks.servers.test_schema_transformer",
        "TestsFlextLdifCommonDictionaryTypes": "tests.unit.test_typings",
        "TestsFlextLdifEdgeCases": "tests.unit.quirks.servers.test_edge_cases",
        "TestsFlextLdifMigrationPipeline": "tests.unit.test_migration_pipeline",
        "TestsFlextLdifMigrationPipelineQuirks": "tests.unit.test_migration_pipeline_quirks",
        "TestsFlextLdifNovellInitialization": "tests.unit.quirks.servers.test_novell_quirks",
        "TestsFlextLdifSchemaTransformerNormalizeAttributeName": "tests.unit.quirks.servers.test_schema_transformer",
        "TestsTestFlextLdifApacheQuirks": "tests.unit.quirks.servers.test_apache_quirks",
        "TestsTestFlextLdifDs389Quirks": "tests.unit.quirks.servers.test_ds389_quirks",
        "TestsTestFlextLdifOidQuirks": "tests.unit.quirks.servers.test_oid_quirks",
        "TestsTestFlextLdifRelaxedQuirks": "tests.unit.quirks.servers.test_relaxed_quirks",
        "c": ("flext_core.constants", "FlextConstants"),
        "cleanup_state": "tests.unit.quirks.servers.test_edge_cases",
        "constants": "tests.unit.constants",
        "d": ("flext_core.decorators", "FlextDecorators"),
        "e": ("flext_core.exceptions", "FlextExceptions"),
        "entry_quirk": "tests.unit.quirks.servers.test_novell_quirks",
        "h": ("flext_core.handlers", "FlextHandlers"),
        "ldif_api": "tests.unit.quirks.servers.test_edge_cases",
        "m": ("flext_core.models", "FlextModels"),
        "novell_server": "tests.unit.quirks.servers.test_novell_quirks",
        "p": ("flext_core.protocols", "FlextProtocols"),
        "protocols": "tests.unit.protocols",
        "r": ("flext_core.result", "FlextResult"),
        "s": ("flext_core.service", "FlextService"),
        "schema_quirk": "tests.unit.quirks.servers.test_novell_quirks",
        "services": "tests.unit.services",
        "t": ("flext_core.typings", "FlextTypes"),
        "test_migration_pipeline": "tests.unit.test_migration_pipeline",
        "test_migration_pipeline_quirks": "tests.unit.test_migration_pipeline_quirks",
        "test_typings": "tests.unit.test_typings",
        "u": ("flext_core.utilities", "FlextUtilities"),
        "utilities": "tests.unit.utilities",
        "x": ("flext_core.mixins", "FlextMixins"),
    },
)
_ = _LAZY_IMPORTS.pop("cleanup_submodule_namespace", None)
_ = _LAZY_IMPORTS.pop("install_lazy_exports", None)
_ = _LAZY_IMPORTS.pop("lazy_getattr", None)
_ = _LAZY_IMPORTS.pop("merge_lazy_imports", None)
_ = _LAZY_IMPORTS.pop("output", None)
_ = _LAZY_IMPORTS.pop("output_reporting", None)

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
    "c",
    "cleanup_state",
    "constants",
    "d",
    "e",
    "entry_quirk",
    "h",
    "ldif_api",
    "m",
    "novell_server",
    "p",
    "protocols",
    "r",
    "s",
    "schema_quirk",
    "services",
    "t",
    "test_acl_registry",
    "test_migration_pipeline",
    "test_migration_pipeline_quirks",
    "test_protocols",
    "test_quirks_standardization",
    "test_typings",
    "test_utilities_comprehensive",
    "test_utilities_core",
    "test_version",
    "u",
    "utilities",
    "version_module",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
