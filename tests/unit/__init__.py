# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Unit package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports, merge_lazy_imports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
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
    from tests.unit import (
        constants,
        protocols,
        services,
        test_migration_pipeline,
        test_migration_pipeline_quirks,
        test_typings,
        utilities,
    )
    from tests.unit.__init__ import TestsFlextLdifVersion, test_version
    from tests.unit._utilities.oid import TestFlextLdifUtilitiesOID
    from tests.unit._utilities.parser import TestFlextLdifUtilitiesParser
    from tests.unit._utilities.server import (
        OidServer,
        OudServer,
        TestFlextLdifUtilitiesServer,
    )
    from tests.unit.constants import (
        GetAclAttributesServerType,
        IsAclAttributeType,
        TestsTestFlextLdifAclAttributeRegistry,
        test_acl_registry,
    )
    from tests.unit.protocols import TestsTestFlextLdifProtocols, test_protocols
    from tests.unit.quirks.servers import (
        ACL_TEST_CASES,
        ATTRIBUTE_TEST_CASES,
        ENTRY_TEST_CASES,
        OBJECTCLASS_TEST_CASES,
        AclScenario,
        AclTestCase,
        AttributeScenario,
        AttributeTestCase,
        EntryScenario,
        EntryTestCase,
        ObjectClassScenario,
        ObjectClassTestCase,
        ParseScenario,
        RfcTestHelpers,
        TestDeduplicationHelpers,
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
        WriteScenario,
        cleanup_state,
        entry_quirk,
        ldif_api,
        meta_keys,
        novell_server,
        schema_quirk,
    )
    from tests.unit.services import (
        TestAliasDiscovery,
        TestQuirksAutoInterchange,
        TestQuirksWithRealLdifFixtures,
        TestsFlextLdifQuirksStandardizedConstants,
        TestsTestFlextLdifMigrationPipeline,
        test_quirks_standardization,
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

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = merge_lazy_imports(
    (
        "tests.unit.__init__",
        "tests.unit.constants",
        "tests.unit.protocols",
        "tests.unit.services",
        "tests.unit.utilities",
    ),
    {
        "ACL_TEST_CASES": "tests.unit.quirks.servers.test_ds389_quirks",
        "ATTRIBUTE_TEST_CASES": "tests.unit.quirks.servers.test_novell_quirks",
        "AclScenario": "tests.unit.quirks.servers.test_ds389_quirks",
        "AclTestCase": "tests.unit.quirks.servers.test_ds389_quirks",
        "AttributeScenario": "tests.unit.quirks.servers.test_novell_quirks",
        "AttributeTestCase": "tests.unit.quirks.servers.test_novell_quirks",
        "ENTRY_TEST_CASES": "tests.unit.quirks.servers.test_novell_quirks",
        "EntryScenario": "tests.unit.quirks.servers.test_novell_quirks",
        "EntryTestCase": "tests.unit.quirks.servers.test_novell_quirks",
        "OBJECTCLASS_TEST_CASES": "tests.unit.quirks.servers.test_novell_quirks",
        "ObjectClassScenario": "tests.unit.quirks.servers.test_novell_quirks",
        "ObjectClassTestCase": "tests.unit.quirks.servers.test_novell_quirks",
        "OidServer": "tests.unit._utilities.server.test_server_utilities",
        "OidTestConstants": "tests.unit.test_migration_pipeline_quirks",
        "OudServer": "tests.unit._utilities.server.test_server_utilities",
        "ParseScenario": "tests.unit.quirks.servers.test_relaxed_quirks",
        "RfcTestHelpers": "tests.unit.quirks.servers.test_novell_quirks",
        "TestDeduplicationHelpers": "tests.unit.quirks.servers.test_novell_quirks",
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
        "WriteScenario": "tests.unit.quirks.servers.test_relaxed_quirks",
        "c": ("flext_core.constants", "FlextConstants"),
        "cleanup_state": "tests.unit.quirks.servers.test_edge_cases",
        "constants": "tests.unit.constants",
        "d": ("flext_core.decorators", "FlextDecorators"),
        "e": ("flext_core.exceptions", "FlextExceptions"),
        "entry_quirk": "tests.unit.quirks.servers.test_novell_quirks",
        "h": ("flext_core.handlers", "FlextHandlers"),
        "ldif_api": "tests.unit.quirks.servers.test_edge_cases",
        "m": ("flext_core.models", "FlextModels"),
        "meta_keys": "tests.unit.quirks.servers.test_relaxed_quirks",
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


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
