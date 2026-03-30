# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Unit package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from tests.unit import (
        constants as constants,
        protocols as protocols,
        services as services,
        test_migration_pipeline as test_migration_pipeline,
        test_migration_pipeline_quirks as test_migration_pipeline_quirks,
        test_typings as test_typings,
        utilities as utilities,
    )
    from tests.unit.__init__ import test_version as test_version
    from tests.unit.__init__.test_version import (
        TestsFlextLdifVersion as TestsFlextLdifVersion,
        version_module as version_module,
    )
    from tests.unit._utilities.oid.test_oid_utilities import (
        TestFlextLdifUtilitiesOID as TestFlextLdifUtilitiesOID,
    )
    from tests.unit._utilities.parser.test_parser_utilities import (
        TestFlextLdifUtilitiesParser as TestFlextLdifUtilitiesParser,
    )
    from tests.unit._utilities.server.test_server_utilities import (
        OidServer as OidServer,
        OudServer as OudServer,
        TestFlextLdifUtilitiesServer as TestFlextLdifUtilitiesServer,
    )
    from tests.unit.constants import test_acl_registry as test_acl_registry
    from tests.unit.constants.test_acl_registry import (
        GetAclAttributesServerType as GetAclAttributesServerType,
        IsAclAttributeType as IsAclAttributeType,
        TestsTestFlextLdifAclAttributeRegistry as TestsTestFlextLdifAclAttributeRegistry,
    )
    from tests.unit.protocols import test_protocols as test_protocols
    from tests.unit.protocols.test_protocols import (
        TestsTestFlextLdifProtocols as TestsTestFlextLdifProtocols,
    )
    from tests.unit.quirks.servers.test_apache_quirks import (
        TestsTestFlextLdifApacheQuirks as TestsTestFlextLdifApacheQuirks,
    )
    from tests.unit.quirks.servers.test_ds389_quirks import (
        ACL_TEST_CASES as ACL_TEST_CASES,
        AclScenario as AclScenario,
        AclTestCase as AclTestCase,
        TestsTestFlextLdifDs389Quirks as TestsTestFlextLdifDs389Quirks,
    )
    from tests.unit.quirks.servers.test_edge_cases import (
        TestsFlextLdifEdgeCases as TestsFlextLdifEdgeCases,
        cleanup_state as cleanup_state,
        ldif_api as ldif_api,
    )
    from tests.unit.quirks.servers.test_novell_quirks import (
        ATTRIBUTE_TEST_CASES as ATTRIBUTE_TEST_CASES,
        ENTRY_TEST_CASES as ENTRY_TEST_CASES,
        OBJECTCLASS_TEST_CASES as OBJECTCLASS_TEST_CASES,
        AttributeScenario as AttributeScenario,
        AttributeTestCase as AttributeTestCase,
        EntryScenario as EntryScenario,
        EntryTestCase as EntryTestCase,
        ObjectClassScenario as ObjectClassScenario,
        ObjectClassTestCase as ObjectClassTestCase,
        RfcTestHelpers as RfcTestHelpers,
        TestDeduplicationHelpers as TestDeduplicationHelpers,
        TestNovellAcls as TestNovellAcls,
        TestNovellEntryDetection as TestNovellEntryDetection,
        TestNovellSchemaAttributeDetection as TestNovellSchemaAttributeDetection,
        TestNovellSchemaAttributeParsing as TestNovellSchemaAttributeParsing,
        TestNovellSchemaObjectClassDetection as TestNovellSchemaObjectClassDetection,
        TestNovellSchemaObjectClassParsing as TestNovellSchemaObjectClassParsing,
        TestsFlextLdifNovellInitialization as TestsFlextLdifNovellInitialization,
        entry_quirk as entry_quirk,
        novell_server as novell_server,
        schema_quirk as schema_quirk,
    )
    from tests.unit.quirks.servers.test_oid_quirks import (
        TestsTestFlextLdifOidQuirks as TestsTestFlextLdifOidQuirks,
    )
    from tests.unit.quirks.servers.test_relaxed_quirks import (
        ParseScenario as ParseScenario,
        TestsTestFlextLdifRelaxedQuirks as TestsTestFlextLdifRelaxedQuirks,
        WriteScenario as WriteScenario,
        meta_keys as meta_keys,
    )
    from tests.unit.quirks.servers.test_schema_transformer import (
        TestSchemaTransformerNormalizeMatchingRule as TestSchemaTransformerNormalizeMatchingRule,
        TestSchemaTransformerNormalizeSyntaxOid as TestSchemaTransformerNormalizeSyntaxOid,
        TestsFlextLdifSchemaTransformerNormalizeAttributeName as TestsFlextLdifSchemaTransformerNormalizeAttributeName,
    )
    from tests.unit.services import (
        test_quirks_standardization as test_quirks_standardization,
    )
    from tests.unit.services.test_migration_pipeline import (
        TestsTestFlextLdifMigrationPipeline as TestsTestFlextLdifMigrationPipeline,
    )
    from tests.unit.services.test_quirks_standardization import (
        TestAliasDiscovery as TestAliasDiscovery,
        TestQuirksAutoInterchange as TestQuirksAutoInterchange,
        TestQuirksWithRealLdifFixtures as TestQuirksWithRealLdifFixtures,
        TestsFlextLdifQuirksStandardizedConstants as TestsFlextLdifQuirksStandardizedConstants,
    )
    from tests.unit.test_migration_pipeline import (
        TestsFlextLdifMigrationPipeline as TestsFlextLdifMigrationPipeline,
    )
    from tests.unit.test_migration_pipeline_quirks import (
        OidTestConstants as OidTestConstants,
        TestsFlextLdifMigrationPipelineQuirks as TestsFlextLdifMigrationPipelineQuirks,
    )
    from tests.unit.test_typings import (
        TestFlextLdifTypesStructure as TestFlextLdifTypesStructure,
        TestIntegrationWithLdifFixtures as TestIntegrationWithLdifFixtures,
        TestModelsNamespace as TestModelsNamespace,
        TestPhase1StandardizationResults as TestPhase1StandardizationResults,
        TestRemovalOfOverEngineering as TestRemovalOfOverEngineering,
        TestsFlextLdifCommonDictionaryTypes as TestsFlextLdifCommonDictionaryTypes,
    )
    from tests.unit.utilities import (
        test_utilities_comprehensive as test_utilities_comprehensive,
        test_utilities_core as test_utilities_core,
    )
    from tests.unit.utilities.test_utilities_comprehensive import (
        TestFlextLdifUtilitiesComprehensive as TestFlextLdifUtilitiesComprehensive,
    )
    from tests.unit.utilities.test_utilities_core import (
        TestAttributeFixer as TestAttributeFixer,
        TestDnObjectClassMethods as TestDnObjectClassMethods,
        TestLdifParser as TestLdifParser,
        TestObjectClassUtilities as TestObjectClassUtilities,
        TestServerTypes as TestServerTypes,
        TestsFlextLdifDnOperationsPure as TestsFlextLdifDnOperationsPure,
    )

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "ACL_TEST_CASES": ["tests.unit.quirks.servers.test_ds389_quirks", "ACL_TEST_CASES"],
    "ATTRIBUTE_TEST_CASES": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "ATTRIBUTE_TEST_CASES",
    ],
    "AclScenario": ["tests.unit.quirks.servers.test_ds389_quirks", "AclScenario"],
    "AclTestCase": ["tests.unit.quirks.servers.test_ds389_quirks", "AclTestCase"],
    "AttributeScenario": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "AttributeScenario",
    ],
    "AttributeTestCase": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "AttributeTestCase",
    ],
    "ENTRY_TEST_CASES": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "ENTRY_TEST_CASES",
    ],
    "EntryScenario": ["tests.unit.quirks.servers.test_novell_quirks", "EntryScenario"],
    "EntryTestCase": ["tests.unit.quirks.servers.test_novell_quirks", "EntryTestCase"],
    "GetAclAttributesServerType": [
        "tests.unit.constants.test_acl_registry",
        "GetAclAttributesServerType",
    ],
    "IsAclAttributeType": [
        "tests.unit.constants.test_acl_registry",
        "IsAclAttributeType",
    ],
    "OBJECTCLASS_TEST_CASES": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "OBJECTCLASS_TEST_CASES",
    ],
    "ObjectClassScenario": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "ObjectClassScenario",
    ],
    "ObjectClassTestCase": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "ObjectClassTestCase",
    ],
    "OidServer": ["tests.unit._utilities.server.test_server_utilities", "OidServer"],
    "OidTestConstants": [
        "tests.unit.test_migration_pipeline_quirks",
        "OidTestConstants",
    ],
    "OudServer": ["tests.unit._utilities.server.test_server_utilities", "OudServer"],
    "ParseScenario": ["tests.unit.quirks.servers.test_relaxed_quirks", "ParseScenario"],
    "RfcTestHelpers": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "RfcTestHelpers",
    ],
    "TestAliasDiscovery": [
        "tests.unit.services.test_quirks_standardization",
        "TestAliasDiscovery",
    ],
    "TestAttributeFixer": [
        "tests.unit.utilities.test_utilities_core",
        "TestAttributeFixer",
    ],
    "TestDeduplicationHelpers": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestDeduplicationHelpers",
    ],
    "TestDnObjectClassMethods": [
        "tests.unit.utilities.test_utilities_core",
        "TestDnObjectClassMethods",
    ],
    "TestFlextLdifTypesStructure": [
        "tests.unit.test_typings",
        "TestFlextLdifTypesStructure",
    ],
    "TestFlextLdifUtilitiesComprehensive": [
        "tests.unit.utilities.test_utilities_comprehensive",
        "TestFlextLdifUtilitiesComprehensive",
    ],
    "TestFlextLdifUtilitiesOID": [
        "tests.unit._utilities.oid.test_oid_utilities",
        "TestFlextLdifUtilitiesOID",
    ],
    "TestFlextLdifUtilitiesParser": [
        "tests.unit._utilities.parser.test_parser_utilities",
        "TestFlextLdifUtilitiesParser",
    ],
    "TestFlextLdifUtilitiesServer": [
        "tests.unit._utilities.server.test_server_utilities",
        "TestFlextLdifUtilitiesServer",
    ],
    "TestIntegrationWithLdifFixtures": [
        "tests.unit.test_typings",
        "TestIntegrationWithLdifFixtures",
    ],
    "TestLdifParser": ["tests.unit.utilities.test_utilities_core", "TestLdifParser"],
    "TestModelsNamespace": ["tests.unit.test_typings", "TestModelsNamespace"],
    "TestNovellAcls": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellAcls",
    ],
    "TestNovellEntryDetection": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellEntryDetection",
    ],
    "TestNovellSchemaAttributeDetection": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellSchemaAttributeDetection",
    ],
    "TestNovellSchemaAttributeParsing": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellSchemaAttributeParsing",
    ],
    "TestNovellSchemaObjectClassDetection": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellSchemaObjectClassDetection",
    ],
    "TestNovellSchemaObjectClassParsing": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestNovellSchemaObjectClassParsing",
    ],
    "TestObjectClassUtilities": [
        "tests.unit.utilities.test_utilities_core",
        "TestObjectClassUtilities",
    ],
    "TestPhase1StandardizationResults": [
        "tests.unit.test_typings",
        "TestPhase1StandardizationResults",
    ],
    "TestQuirksAutoInterchange": [
        "tests.unit.services.test_quirks_standardization",
        "TestQuirksAutoInterchange",
    ],
    "TestQuirksWithRealLdifFixtures": [
        "tests.unit.services.test_quirks_standardization",
        "TestQuirksWithRealLdifFixtures",
    ],
    "TestRemovalOfOverEngineering": [
        "tests.unit.test_typings",
        "TestRemovalOfOverEngineering",
    ],
    "TestSchemaTransformerNormalizeMatchingRule": [
        "tests.unit.quirks.servers.test_schema_transformer",
        "TestSchemaTransformerNormalizeMatchingRule",
    ],
    "TestSchemaTransformerNormalizeSyntaxOid": [
        "tests.unit.quirks.servers.test_schema_transformer",
        "TestSchemaTransformerNormalizeSyntaxOid",
    ],
    "TestServerTypes": ["tests.unit.utilities.test_utilities_core", "TestServerTypes"],
    "TestsFlextLdifCommonDictionaryTypes": [
        "tests.unit.test_typings",
        "TestsFlextLdifCommonDictionaryTypes",
    ],
    "TestsFlextLdifDnOperationsPure": [
        "tests.unit.utilities.test_utilities_core",
        "TestsFlextLdifDnOperationsPure",
    ],
    "TestsFlextLdifEdgeCases": [
        "tests.unit.quirks.servers.test_edge_cases",
        "TestsFlextLdifEdgeCases",
    ],
    "TestsFlextLdifMigrationPipeline": [
        "tests.unit.test_migration_pipeline",
        "TestsFlextLdifMigrationPipeline",
    ],
    "TestsFlextLdifMigrationPipelineQuirks": [
        "tests.unit.test_migration_pipeline_quirks",
        "TestsFlextLdifMigrationPipelineQuirks",
    ],
    "TestsFlextLdifNovellInitialization": [
        "tests.unit.quirks.servers.test_novell_quirks",
        "TestsFlextLdifNovellInitialization",
    ],
    "TestsFlextLdifQuirksStandardizedConstants": [
        "tests.unit.services.test_quirks_standardization",
        "TestsFlextLdifQuirksStandardizedConstants",
    ],
    "TestsFlextLdifSchemaTransformerNormalizeAttributeName": [
        "tests.unit.quirks.servers.test_schema_transformer",
        "TestsFlextLdifSchemaTransformerNormalizeAttributeName",
    ],
    "TestsFlextLdifVersion": [
        "tests.unit.__init__.test_version",
        "TestsFlextLdifVersion",
    ],
    "TestsTestFlextLdifAclAttributeRegistry": [
        "tests.unit.constants.test_acl_registry",
        "TestsTestFlextLdifAclAttributeRegistry",
    ],
    "TestsTestFlextLdifApacheQuirks": [
        "tests.unit.quirks.servers.test_apache_quirks",
        "TestsTestFlextLdifApacheQuirks",
    ],
    "TestsTestFlextLdifDs389Quirks": [
        "tests.unit.quirks.servers.test_ds389_quirks",
        "TestsTestFlextLdifDs389Quirks",
    ],
    "TestsTestFlextLdifMigrationPipeline": [
        "tests.unit.services.test_migration_pipeline",
        "TestsTestFlextLdifMigrationPipeline",
    ],
    "TestsTestFlextLdifOidQuirks": [
        "tests.unit.quirks.servers.test_oid_quirks",
        "TestsTestFlextLdifOidQuirks",
    ],
    "TestsTestFlextLdifProtocols": [
        "tests.unit.protocols.test_protocols",
        "TestsTestFlextLdifProtocols",
    ],
    "TestsTestFlextLdifRelaxedQuirks": [
        "tests.unit.quirks.servers.test_relaxed_quirks",
        "TestsTestFlextLdifRelaxedQuirks",
    ],
    "WriteScenario": ["tests.unit.quirks.servers.test_relaxed_quirks", "WriteScenario"],
    "cleanup_state": ["tests.unit.quirks.servers.test_edge_cases", "cleanup_state"],
    "constants": ["tests.unit.constants", ""],
    "entry_quirk": ["tests.unit.quirks.servers.test_novell_quirks", "entry_quirk"],
    "ldif_api": ["tests.unit.quirks.servers.test_edge_cases", "ldif_api"],
    "meta_keys": ["tests.unit.quirks.servers.test_relaxed_quirks", "meta_keys"],
    "novell_server": ["tests.unit.quirks.servers.test_novell_quirks", "novell_server"],
    "protocols": ["tests.unit.protocols", ""],
    "schema_quirk": ["tests.unit.quirks.servers.test_novell_quirks", "schema_quirk"],
    "services": ["tests.unit.services", ""],
    "test_acl_registry": ["tests.unit.constants.test_acl_registry", ""],
    "test_migration_pipeline": ["tests.unit.test_migration_pipeline", ""],
    "test_migration_pipeline_quirks": ["tests.unit.test_migration_pipeline_quirks", ""],
    "test_protocols": ["tests.unit.protocols.test_protocols", ""],
    "test_quirks_standardization": [
        "tests.unit.services.test_quirks_standardization",
        "",
    ],
    "test_typings": ["tests.unit.test_typings", ""],
    "test_utilities_comprehensive": [
        "tests.unit.utilities.test_utilities_comprehensive",
        "",
    ],
    "test_utilities_core": ["tests.unit.utilities.test_utilities_core", ""],
    "test_version": ["tests.unit.__init__.test_version", ""],
    "utilities": ["tests.unit.utilities", ""],
    "version_module": ["tests.unit.__init__.test_version", "version_module"],
}

_EXPORTS: Sequence[str] = [
    "ACL_TEST_CASES",
    "ATTRIBUTE_TEST_CASES",
    "AclScenario",
    "AclTestCase",
    "AttributeScenario",
    "AttributeTestCase",
    "ENTRY_TEST_CASES",
    "EntryScenario",
    "EntryTestCase",
    "GetAclAttributesServerType",
    "IsAclAttributeType",
    "OBJECTCLASS_TEST_CASES",
    "ObjectClassScenario",
    "ObjectClassTestCase",
    "OidServer",
    "OidTestConstants",
    "OudServer",
    "ParseScenario",
    "RfcTestHelpers",
    "TestAliasDiscovery",
    "TestAttributeFixer",
    "TestDeduplicationHelpers",
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
    "WriteScenario",
    "cleanup_state",
    "constants",
    "entry_quirk",
    "ldif_api",
    "meta_keys",
    "novell_server",
    "protocols",
    "schema_quirk",
    "services",
    "test_acl_registry",
    "test_migration_pipeline",
    "test_migration_pipeline_quirks",
    "test_protocols",
    "test_quirks_standardization",
    "test_typings",
    "test_utilities_comprehensive",
    "test_utilities_core",
    "test_version",
    "utilities",
    "version_module",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
