# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Unit package."""

from __future__ import annotations

import typing as _t

from flext_core.constants import FlextConstants as c
from flext_core.decorators import FlextDecorators as d
from flext_core.exceptions import FlextExceptions as e
from flext_core.handlers import FlextHandlers as h
from flext_core.lazy import install_lazy_exports, merge_lazy_imports
from flext_core.mixins import FlextMixins as x
from flext_core.models import FlextModels as m
from flext_core.protocols import FlextProtocols as p
from flext_core.result import FlextResult as r
from flext_core.service import FlextService as s
from flext_core.typings import FlextTypes as t
from flext_core.utilities import FlextUtilities as u
from tests.unit.__init__.test_version import TestsFlextLdifVersion
from tests.unit._utilities.oid.test_oid_utilities import TestFlextLdifUtilitiesOID
from tests.unit._utilities.parser.test_parser_utilities import (
    TestFlextLdifUtilitiesParser,
)
from tests.unit._utilities.server.test_server_utilities import (
    OidServer,
    OudServer,
    TestFlextLdifUtilitiesServer,
)
from tests.unit.constants.test_acl_registry import (
    GetAclAttributesServerType,
    IsAclAttributeType,
    TestsTestFlextLdifAclAttributeRegistry,
)
from tests.unit.protocols.test_protocols import TestsTestFlextLdifProtocols
from tests.unit.quirks.servers.test_apache_quirks import (
    TestsTestFlextLdifApacheQuirks,
)
from tests.unit.quirks.servers.test_ds389_quirks import (
    ACL_TEST_CASES,
    AclScenario,
    AclTestCase,
    TestsTestFlextLdifDs389Quirks,
)
from tests.unit.quirks.servers.test_edge_cases import (
    TestsFlextLdifEdgeCases,
    cleanup_state,
    ldif_api,
)
from tests.unit.quirks.servers.test_novell_quirks import (
    ATTRIBUTE_TEST_CASES,
    ENTRY_TEST_CASES,
    OBJECTCLASS_TEST_CASES,
    AttributeScenario,
    AttributeTestCase,
    EntryScenario,
    EntryTestCase,
    ObjectClassScenario,
    ObjectClassTestCase,
    RfcTestHelpers,
    TestDeduplicationHelpers,
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
from tests.unit.quirks.servers.test_oid_quirks import TestsTestFlextLdifOidQuirks
from tests.unit.quirks.servers.test_relaxed_quirks import (
    ParseScenario,
    TestsTestFlextLdifRelaxedQuirks,
    WriteScenario,
    meta_keys,
)
from tests.unit.quirks.servers.test_schema_transformer import (
    TestSchemaTransformerNormalizeMatchingRule,
    TestSchemaTransformerNormalizeSyntaxOid,
    TestsFlextLdifSchemaTransformerNormalizeAttributeName,
)
from tests.unit.services.test_migration_pipeline import (
    TestsTestFlextLdifMigrationPipeline,
)
from tests.unit.services.test_quirks_standardization import (
    TestAliasDiscovery,
    TestQuirksAutoInterchange,
    TestQuirksWithRealLdifFixtures,
    TestsFlextLdifQuirksStandardizedConstants,
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
from tests.unit.utilities.test_utilities_comprehensive import (
    TestFlextLdifUtilitiesComprehensive,
)
from tests.unit.utilities.test_utilities_core import (
    TestAttributeFixer,
    TestDnObjectClassMethods,
    TestLdifParser,
    TestObjectClassUtilities,
    TestServerTypes,
    TestsFlextLdifDnOperationsPure,
)

if _t.TYPE_CHECKING:
    import tests.unit.__init__.test_version as _tests_unit___init___test_version

    test_version = _tests_unit___init___test_version
    import tests.unit.constants as _tests_unit_constants

    constants = _tests_unit_constants
    import tests.unit.constants.test_acl_registry as _tests_unit_constants_test_acl_registry

    test_acl_registry = _tests_unit_constants_test_acl_registry
    import tests.unit.protocols as _tests_unit_protocols

    protocols = _tests_unit_protocols
    import tests.unit.protocols.test_protocols as _tests_unit_protocols_test_protocols

    test_protocols = _tests_unit_protocols_test_protocols
    import tests.unit.services as _tests_unit_services

    services = _tests_unit_services
    import tests.unit.services.test_quirks_standardization as _tests_unit_services_test_quirks_standardization

    test_quirks_standardization = _tests_unit_services_test_quirks_standardization
    import tests.unit.test_migration_pipeline as _tests_unit_test_migration_pipeline

    test_migration_pipeline = _tests_unit_test_migration_pipeline
    import tests.unit.test_migration_pipeline_quirks as _tests_unit_test_migration_pipeline_quirks

    test_migration_pipeline_quirks = _tests_unit_test_migration_pipeline_quirks
    import tests.unit.test_typings as _tests_unit_test_typings

    test_typings = _tests_unit_test_typings
    import tests.unit.utilities as _tests_unit_utilities

    utilities = _tests_unit_utilities
    import tests.unit.utilities.test_utilities_comprehensive as _tests_unit_utilities_test_utilities_comprehensive

    test_utilities_comprehensive = _tests_unit_utilities_test_utilities_comprehensive
    import tests.unit.utilities.test_utilities_core as _tests_unit_utilities_test_utilities_core

    test_utilities_core = _tests_unit_utilities_test_utilities_core

    _ = (
        ACL_TEST_CASES,
        ATTRIBUTE_TEST_CASES,
        AclScenario,
        AclTestCase,
        AttributeScenario,
        AttributeTestCase,
        ENTRY_TEST_CASES,
        EntryScenario,
        EntryTestCase,
        GetAclAttributesServerType,
        IsAclAttributeType,
        OBJECTCLASS_TEST_CASES,
        ObjectClassScenario,
        ObjectClassTestCase,
        OidServer,
        OidTestConstants,
        OudServer,
        ParseScenario,
        RfcTestHelpers,
        TestAliasDiscovery,
        TestAttributeFixer,
        TestDeduplicationHelpers,
        TestDnObjectClassMethods,
        TestFlextLdifTypesStructure,
        TestFlextLdifUtilitiesComprehensive,
        TestFlextLdifUtilitiesOID,
        TestFlextLdifUtilitiesParser,
        TestFlextLdifUtilitiesServer,
        TestIntegrationWithLdifFixtures,
        TestLdifParser,
        TestModelsNamespace,
        TestNovellAcls,
        TestNovellEntryDetection,
        TestNovellSchemaAttributeDetection,
        TestNovellSchemaAttributeParsing,
        TestNovellSchemaObjectClassDetection,
        TestNovellSchemaObjectClassParsing,
        TestObjectClassUtilities,
        TestPhase1StandardizationResults,
        TestQuirksAutoInterchange,
        TestQuirksWithRealLdifFixtures,
        TestRemovalOfOverEngineering,
        TestSchemaTransformerNormalizeMatchingRule,
        TestSchemaTransformerNormalizeSyntaxOid,
        TestServerTypes,
        TestsFlextLdifCommonDictionaryTypes,
        TestsFlextLdifDnOperationsPure,
        TestsFlextLdifEdgeCases,
        TestsFlextLdifMigrationPipeline,
        TestsFlextLdifMigrationPipelineQuirks,
        TestsFlextLdifNovellInitialization,
        TestsFlextLdifQuirksStandardizedConstants,
        TestsFlextLdifSchemaTransformerNormalizeAttributeName,
        TestsFlextLdifVersion,
        TestsTestFlextLdifAclAttributeRegistry,
        TestsTestFlextLdifApacheQuirks,
        TestsTestFlextLdifDs389Quirks,
        TestsTestFlextLdifMigrationPipeline,
        TestsTestFlextLdifOidQuirks,
        TestsTestFlextLdifProtocols,
        TestsTestFlextLdifRelaxedQuirks,
        WriteScenario,
        c,
        cleanup_state,
        constants,
        d,
        e,
        entry_quirk,
        h,
        ldif_api,
        m,
        meta_keys,
        novell_server,
        p,
        protocols,
        r,
        s,
        schema_quirk,
        services,
        t,
        test_acl_registry,
        test_migration_pipeline,
        test_migration_pipeline_quirks,
        test_protocols,
        test_quirks_standardization,
        test_typings,
        test_utilities_comprehensive,
        test_utilities_core,
        test_version,
        u,
        utilities,
        x,
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

__all__ = [
    "ACL_TEST_CASES",
    "ATTRIBUTE_TEST_CASES",
    "ENTRY_TEST_CASES",
    "OBJECTCLASS_TEST_CASES",
    "AclScenario",
    "AclTestCase",
    "AttributeScenario",
    "AttributeTestCase",
    "EntryScenario",
    "EntryTestCase",
    "GetAclAttributesServerType",
    "IsAclAttributeType",
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
    "c",
    "cleanup_state",
    "constants",
    "d",
    "e",
    "entry_quirk",
    "h",
    "ldif_api",
    "m",
    "meta_keys",
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
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
