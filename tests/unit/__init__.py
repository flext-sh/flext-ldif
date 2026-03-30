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
        test_migration_pipeline,
        test_migration_pipeline_quirks,
        test_typings,
    )
    from tests.unit.__init__ import *
    from tests.unit._utilities.oid.test_oid_utilities import *
    from tests.unit._utilities.parser.test_parser_utilities import *
    from tests.unit._utilities.server.test_server_utilities import *
    from tests.unit.constants import *
    from tests.unit.protocols import *
    from tests.unit.quirks.servers.test_apache_quirks import *
    from tests.unit.quirks.servers.test_ds389_quirks import *
    from tests.unit.quirks.servers.test_edge_cases import *
    from tests.unit.quirks.servers.test_novell_quirks import *
    from tests.unit.quirks.servers.test_oid_quirks import *
    from tests.unit.quirks.servers.test_relaxed_quirks import *
    from tests.unit.quirks.servers.test_schema_transformer import *
    from tests.unit.services import *
    from tests.unit.test_migration_pipeline import *
    from tests.unit.test_migration_pipeline_quirks import *
    from tests.unit.test_typings import *
    from tests.unit.utilities import *

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    "ACL_TEST_CASES": "tests.unit.quirks.servers.test_ds389_quirks",
    "ATTRIBUTE_TEST_CASES": "tests.unit.quirks.servers.test_novell_quirks",
    "AclScenario": "tests.unit.quirks.servers.test_ds389_quirks",
    "AclTestCase": "tests.unit.quirks.servers.test_ds389_quirks",
    "AttributeScenario": "tests.unit.quirks.servers.test_novell_quirks",
    "AttributeTestCase": "tests.unit.quirks.servers.test_novell_quirks",
    "ENTRY_TEST_CASES": "tests.unit.quirks.servers.test_novell_quirks",
    "EntryScenario": "tests.unit.quirks.servers.test_novell_quirks",
    "EntryTestCase": "tests.unit.quirks.servers.test_novell_quirks",
    "GetAclAttributesServerType": "tests.unit.constants.test_acl_registry",
    "IsAclAttributeType": "tests.unit.constants.test_acl_registry",
    "OBJECTCLASS_TEST_CASES": "tests.unit.quirks.servers.test_novell_quirks",
    "ObjectClassScenario": "tests.unit.quirks.servers.test_novell_quirks",
    "ObjectClassTestCase": "tests.unit.quirks.servers.test_novell_quirks",
    "OidServer": "tests.unit._utilities.server.test_server_utilities",
    "OidTestConstants": "tests.unit.test_migration_pipeline_quirks",
    "OudServer": "tests.unit._utilities.server.test_server_utilities",
    "ParseScenario": "tests.unit.quirks.servers.test_relaxed_quirks",
    "RfcTestHelpers": "tests.unit.quirks.servers.test_novell_quirks",
    "TestAliasDiscovery": "tests.unit.services.test_quirks_standardization",
    "TestAttributeFixer": "tests.unit.utilities.test_utilities_core",
    "TestDeduplicationHelpers": "tests.unit.quirks.servers.test_novell_quirks",
    "TestDnObjectClassMethods": "tests.unit.utilities.test_utilities_core",
    "TestFlextLdifTypesStructure": "tests.unit.test_typings",
    "TestFlextLdifUtilitiesComprehensive": "tests.unit.utilities.test_utilities_comprehensive",
    "TestFlextLdifUtilitiesOID": "tests.unit._utilities.oid.test_oid_utilities",
    "TestFlextLdifUtilitiesParser": "tests.unit._utilities.parser.test_parser_utilities",
    "TestFlextLdifUtilitiesServer": "tests.unit._utilities.server.test_server_utilities",
    "TestIntegrationWithLdifFixtures": "tests.unit.test_typings",
    "TestLdifParser": "tests.unit.utilities.test_utilities_core",
    "TestModelsNamespace": "tests.unit.test_typings",
    "TestNovellAcls": "tests.unit.quirks.servers.test_novell_quirks",
    "TestNovellEntryDetection": "tests.unit.quirks.servers.test_novell_quirks",
    "TestNovellSchemaAttributeDetection": "tests.unit.quirks.servers.test_novell_quirks",
    "TestNovellSchemaAttributeParsing": "tests.unit.quirks.servers.test_novell_quirks",
    "TestNovellSchemaObjectClassDetection": "tests.unit.quirks.servers.test_novell_quirks",
    "TestNovellSchemaObjectClassParsing": "tests.unit.quirks.servers.test_novell_quirks",
    "TestObjectClassUtilities": "tests.unit.utilities.test_utilities_core",
    "TestPhase1StandardizationResults": "tests.unit.test_typings",
    "TestQuirksAutoInterchange": "tests.unit.services.test_quirks_standardization",
    "TestQuirksWithRealLdifFixtures": "tests.unit.services.test_quirks_standardization",
    "TestRemovalOfOverEngineering": "tests.unit.test_typings",
    "TestSchemaTransformerNormalizeMatchingRule": "tests.unit.quirks.servers.test_schema_transformer",
    "TestSchemaTransformerNormalizeSyntaxOid": "tests.unit.quirks.servers.test_schema_transformer",
    "TestServerTypes": "tests.unit.utilities.test_utilities_core",
    "TestsFlextLdifCommonDictionaryTypes": "tests.unit.test_typings",
    "TestsFlextLdifDnOperationsPure": "tests.unit.utilities.test_utilities_core",
    "TestsFlextLdifEdgeCases": "tests.unit.quirks.servers.test_edge_cases",
    "TestsFlextLdifMigrationPipeline": "tests.unit.test_migration_pipeline",
    "TestsFlextLdifMigrationPipelineQuirks": "tests.unit.test_migration_pipeline_quirks",
    "TestsFlextLdifNovellInitialization": "tests.unit.quirks.servers.test_novell_quirks",
    "TestsFlextLdifQuirksStandardizedConstants": "tests.unit.services.test_quirks_standardization",
    "TestsFlextLdifSchemaTransformerNormalizeAttributeName": "tests.unit.quirks.servers.test_schema_transformer",
    "TestsFlextLdifVersion": "tests.unit.__init__.test_version",
    "TestsTestFlextLdifAclAttributeRegistry": "tests.unit.constants.test_acl_registry",
    "TestsTestFlextLdifApacheQuirks": "tests.unit.quirks.servers.test_apache_quirks",
    "TestsTestFlextLdifDs389Quirks": "tests.unit.quirks.servers.test_ds389_quirks",
    "TestsTestFlextLdifMigrationPipeline": "tests.unit.services.test_migration_pipeline",
    "TestsTestFlextLdifOidQuirks": "tests.unit.quirks.servers.test_oid_quirks",
    "TestsTestFlextLdifProtocols": "tests.unit.protocols.test_protocols",
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
    "test_acl_registry": "tests.unit.constants.test_acl_registry",
    "test_migration_pipeline": "tests.unit.test_migration_pipeline",
    "test_migration_pipeline_quirks": "tests.unit.test_migration_pipeline_quirks",
    "test_protocols": "tests.unit.protocols.test_protocols",
    "test_quirks_standardization": "tests.unit.services.test_quirks_standardization",
    "test_typings": "tests.unit.test_typings",
    "test_utilities_comprehensive": "tests.unit.utilities.test_utilities_comprehensive",
    "test_utilities_core": "tests.unit.utilities.test_utilities_core",
    "test_version": "tests.unit.__init__.test_version",
    "utilities": "tests.unit.utilities",
    "version_module": "tests.unit.__init__.test_version",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, sorted(_LAZY_IMPORTS))
