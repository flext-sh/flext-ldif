# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Unit package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports, merge_lazy_imports

if _TYPE_CHECKING:
    from tests.unit.__init__ import *
    from tests.unit._utilities.oid import *
    from tests.unit._utilities.parser import *
    from tests.unit._utilities.server import *
    from tests.unit.constants import *
    from tests.unit.protocols import *
    from tests.unit.quirks.servers import *
    from tests.unit.services import *
    from tests.unit.test_migration_pipeline import *
    from tests.unit.test_migration_pipeline_quirks import *
    from tests.unit.test_typings import *
    from tests.unit.utilities import *

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = merge_lazy_imports(
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
        "cleanup_state": "tests.unit.quirks.servers.test_edge_cases",
        "constants": "tests.unit.constants",
        "entry_quirk": "tests.unit.quirks.servers.test_novell_quirks",
        "ldif_api": "tests.unit.quirks.servers.test_edge_cases",
        "meta_keys": "tests.unit.quirks.servers.test_relaxed_quirks",
        "novell_server": "tests.unit.quirks.servers.test_novell_quirks",
        "protocols": "tests.unit.protocols",
        "schema_quirk": "tests.unit.quirks.servers.test_novell_quirks",
        "services": "tests.unit.services",
        "test_migration_pipeline": "tests.unit.test_migration_pipeline",
        "test_migration_pipeline_quirks": "tests.unit.test_migration_pipeline_quirks",
        "test_typings": "tests.unit.test_typings",
        "utilities": "tests.unit.utilities",
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
