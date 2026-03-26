# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Unit package."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core import FlextTypes

    from tests.unit import constants, models, protocols, services, utilities
    from tests.unit.__init__.test_version import TestsFlextLdifVersion, version_module
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
    from tests.unit.models.test_models import TestFlextLdifModels
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
        TestSchemaTransformerApplyAttributeTransformations,
        TestSchemaTransformerApplyObjectClassTransformations,
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
    from tests.unit.services.test_schema_service import (
        TestSchemaServiceBuilder,
        TestSchemaServiceCanHandleAttribute,
        TestSchemaServiceIntegration,
        TestSchemaServiceParseAttribute,
        TestSchemaServiceParseObjectClass,
        TestSchemaServiceRepr,
        TestSchemaServiceValidateAttribute,
        TestSchemaServiceValidateObjectClass,
        TestSchemaServiceWriteAttribute,
        TestSchemaServiceWriteObjectClass,
        TestsFlextLdifSchemaServiceExecute,
        complex_attribute_definition,
        complex_objectclass_definition,
        schema_service,
        schema_service_oud,
        simple_attribute_definition,
        simple_objectclass_definition,
    )
    from tests.unit.services.test_writer_dn_normalization import (
        TestsFlextLdifsFlextLdifWriterDnNormalization,
    )
    from tests.unit.test_filters import TestAclAttributes
    from tests.unit.test_helpers import TestFlextLdifDeduplicationHelpers
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
    from tests.unit.utilities.test_utilities import TestsTestFlextLdifServiceAPIs
    from tests.unit.utilities.test_utilities_comprehensive import (
        TestFlextLdifUtilitiesComprehensive,
    )
    from tests.unit.utilities.test_utilities_constants import (
        GetValidValuesType,
        IsValidTestType,
        TestsTestFlextLdifConstants,
        ValidateManyType,
    )
    from tests.unit.utilities.test_utilities_core import (
        TestAclParser,
        TestAttributeFixer,
        TestDnObjectClassMethods,
        TestLdifParser,
        TestObjectClassUtilities,
        TestServerTypes,
        TestsFlextLdifDnOperationsPure,
    )

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "ACL_TEST_CASES": ["tests.unit.quirks.servers.test_ds389_quirks", "ACL_TEST_CASES"],
    "ATTRIBUTE_TEST_CASES": ["tests.unit.quirks.servers.test_novell_quirks", "ATTRIBUTE_TEST_CASES"],
    "AclScenario": ["tests.unit.quirks.servers.test_ds389_quirks", "AclScenario"],
    "AclTestCase": ["tests.unit.quirks.servers.test_ds389_quirks", "AclTestCase"],
    "AttributeScenario": ["tests.unit.quirks.servers.test_novell_quirks", "AttributeScenario"],
    "AttributeTestCase": ["tests.unit.quirks.servers.test_novell_quirks", "AttributeTestCase"],
    "ENTRY_TEST_CASES": ["tests.unit.quirks.servers.test_novell_quirks", "ENTRY_TEST_CASES"],
    "EntryScenario": ["tests.unit.quirks.servers.test_novell_quirks", "EntryScenario"],
    "EntryTestCase": ["tests.unit.quirks.servers.test_novell_quirks", "EntryTestCase"],
    "GetAclAttributesServerType": ["tests.unit.constants.test_acl_registry", "GetAclAttributesServerType"],
    "GetValidValuesType": ["tests.unit.utilities.test_utilities_constants", "GetValidValuesType"],
    "IsAclAttributeType": ["tests.unit.constants.test_acl_registry", "IsAclAttributeType"],
    "IsValidTestType": ["tests.unit.utilities.test_utilities_constants", "IsValidTestType"],
    "OBJECTCLASS_TEST_CASES": ["tests.unit.quirks.servers.test_novell_quirks", "OBJECTCLASS_TEST_CASES"],
    "ObjectClassScenario": ["tests.unit.quirks.servers.test_novell_quirks", "ObjectClassScenario"],
    "ObjectClassTestCase": ["tests.unit.quirks.servers.test_novell_quirks", "ObjectClassTestCase"],
    "OidServer": ["tests.unit._utilities.server.test_server_utilities", "OidServer"],
    "OidTestConstants": ["tests.unit.test_migration_pipeline_quirks", "OidTestConstants"],
    "OudServer": ["tests.unit._utilities.server.test_server_utilities", "OudServer"],
    "ParseScenario": ["tests.unit.quirks.servers.test_relaxed_quirks", "ParseScenario"],
    "RfcTestHelpers": ["tests.unit.quirks.servers.test_novell_quirks", "RfcTestHelpers"],
    "TestAclAttributes": ["tests.unit.test_filters", "TestAclAttributes"],
    "TestAclParser": ["tests.unit.utilities.test_utilities_core", "TestAclParser"],
    "TestAliasDiscovery": ["tests.unit.services.test_quirks_standardization", "TestAliasDiscovery"],
    "TestAttributeFixer": ["tests.unit.utilities.test_utilities_core", "TestAttributeFixer"],
    "TestDeduplicationHelpers": ["tests.unit.quirks.servers.test_novell_quirks", "TestDeduplicationHelpers"],
    "TestDnObjectClassMethods": ["tests.unit.utilities.test_utilities_core", "TestDnObjectClassMethods"],
    "TestFlextLdifDeduplicationHelpers": ["tests.unit.test_helpers", "TestFlextLdifDeduplicationHelpers"],
    "TestFlextLdifModels": ["tests.unit.models.test_models", "TestFlextLdifModels"],
    "TestFlextLdifTypesStructure": ["tests.unit.test_typings", "TestFlextLdifTypesStructure"],
    "TestFlextLdifUtilitiesComprehensive": ["tests.unit.utilities.test_utilities_comprehensive", "TestFlextLdifUtilitiesComprehensive"],
    "TestFlextLdifUtilitiesOID": ["tests.unit._utilities.oid.test_oid_utilities", "TestFlextLdifUtilitiesOID"],
    "TestFlextLdifUtilitiesParser": ["tests.unit._utilities.parser.test_parser_utilities", "TestFlextLdifUtilitiesParser"],
    "TestFlextLdifUtilitiesServer": ["tests.unit._utilities.server.test_server_utilities", "TestFlextLdifUtilitiesServer"],
    "TestIntegrationWithLdifFixtures": ["tests.unit.test_typings", "TestIntegrationWithLdifFixtures"],
    "TestLdifParser": ["tests.unit.utilities.test_utilities_core", "TestLdifParser"],
    "TestModelsNamespace": ["tests.unit.test_typings", "TestModelsNamespace"],
    "TestNovellAcls": ["tests.unit.quirks.servers.test_novell_quirks", "TestNovellAcls"],
    "TestNovellEntryDetection": ["tests.unit.quirks.servers.test_novell_quirks", "TestNovellEntryDetection"],
    "TestNovellSchemaAttributeDetection": ["tests.unit.quirks.servers.test_novell_quirks", "TestNovellSchemaAttributeDetection"],
    "TestNovellSchemaAttributeParsing": ["tests.unit.quirks.servers.test_novell_quirks", "TestNovellSchemaAttributeParsing"],
    "TestNovellSchemaObjectClassDetection": ["tests.unit.quirks.servers.test_novell_quirks", "TestNovellSchemaObjectClassDetection"],
    "TestNovellSchemaObjectClassParsing": ["tests.unit.quirks.servers.test_novell_quirks", "TestNovellSchemaObjectClassParsing"],
    "TestObjectClassUtilities": ["tests.unit.utilities.test_utilities_core", "TestObjectClassUtilities"],
    "TestPhase1StandardizationResults": ["tests.unit.test_typings", "TestPhase1StandardizationResults"],
    "TestQuirksAutoInterchange": ["tests.unit.services.test_quirks_standardization", "TestQuirksAutoInterchange"],
    "TestQuirksWithRealLdifFixtures": ["tests.unit.services.test_quirks_standardization", "TestQuirksWithRealLdifFixtures"],
    "TestRemovalOfOverEngineering": ["tests.unit.test_typings", "TestRemovalOfOverEngineering"],
    "TestSchemaServiceBuilder": ["tests.unit.services.test_schema_service", "TestSchemaServiceBuilder"],
    "TestSchemaServiceCanHandleAttribute": ["tests.unit.services.test_schema_service", "TestSchemaServiceCanHandleAttribute"],
    "TestSchemaServiceIntegration": ["tests.unit.services.test_schema_service", "TestSchemaServiceIntegration"],
    "TestSchemaServiceParseAttribute": ["tests.unit.services.test_schema_service", "TestSchemaServiceParseAttribute"],
    "TestSchemaServiceParseObjectClass": ["tests.unit.services.test_schema_service", "TestSchemaServiceParseObjectClass"],
    "TestSchemaServiceRepr": ["tests.unit.services.test_schema_service", "TestSchemaServiceRepr"],
    "TestSchemaServiceValidateAttribute": ["tests.unit.services.test_schema_service", "TestSchemaServiceValidateAttribute"],
    "TestSchemaServiceValidateObjectClass": ["tests.unit.services.test_schema_service", "TestSchemaServiceValidateObjectClass"],
    "TestSchemaServiceWriteAttribute": ["tests.unit.services.test_schema_service", "TestSchemaServiceWriteAttribute"],
    "TestSchemaServiceWriteObjectClass": ["tests.unit.services.test_schema_service", "TestSchemaServiceWriteObjectClass"],
    "TestSchemaTransformerApplyAttributeTransformations": ["tests.unit.quirks.servers.test_schema_transformer", "TestSchemaTransformerApplyAttributeTransformations"],
    "TestSchemaTransformerApplyObjectClassTransformations": ["tests.unit.quirks.servers.test_schema_transformer", "TestSchemaTransformerApplyObjectClassTransformations"],
    "TestSchemaTransformerNormalizeMatchingRule": ["tests.unit.quirks.servers.test_schema_transformer", "TestSchemaTransformerNormalizeMatchingRule"],
    "TestSchemaTransformerNormalizeSyntaxOid": ["tests.unit.quirks.servers.test_schema_transformer", "TestSchemaTransformerNormalizeSyntaxOid"],
    "TestServerTypes": ["tests.unit.utilities.test_utilities_core", "TestServerTypes"],
    "TestsFlextLdifCommonDictionaryTypes": ["tests.unit.test_typings", "TestsFlextLdifCommonDictionaryTypes"],
    "TestsFlextLdifDnOperationsPure": ["tests.unit.utilities.test_utilities_core", "TestsFlextLdifDnOperationsPure"],
    "TestsFlextLdifEdgeCases": ["tests.unit.quirks.servers.test_edge_cases", "TestsFlextLdifEdgeCases"],
    "TestsFlextLdifMigrationPipeline": ["tests.unit.test_migration_pipeline", "TestsFlextLdifMigrationPipeline"],
    "TestsFlextLdifMigrationPipelineQuirks": ["tests.unit.test_migration_pipeline_quirks", "TestsFlextLdifMigrationPipelineQuirks"],
    "TestsFlextLdifNovellInitialization": ["tests.unit.quirks.servers.test_novell_quirks", "TestsFlextLdifNovellInitialization"],
    "TestsFlextLdifQuirksStandardizedConstants": ["tests.unit.services.test_quirks_standardization", "TestsFlextLdifQuirksStandardizedConstants"],
    "TestsFlextLdifSchemaServiceExecute": ["tests.unit.services.test_schema_service", "TestsFlextLdifSchemaServiceExecute"],
    "TestsFlextLdifSchemaTransformerNormalizeAttributeName": ["tests.unit.quirks.servers.test_schema_transformer", "TestsFlextLdifSchemaTransformerNormalizeAttributeName"],
    "TestsFlextLdifVersion": ["tests.unit.__init__.test_version", "TestsFlextLdifVersion"],
    "TestsFlextLdifsFlextLdifWriterDnNormalization": ["tests.unit.services.test_writer_dn_normalization", "TestsFlextLdifsFlextLdifWriterDnNormalization"],
    "TestsTestFlextLdifAclAttributeRegistry": ["tests.unit.constants.test_acl_registry", "TestsTestFlextLdifAclAttributeRegistry"],
    "TestsTestFlextLdifApacheQuirks": ["tests.unit.quirks.servers.test_apache_quirks", "TestsTestFlextLdifApacheQuirks"],
    "TestsTestFlextLdifConstants": ["tests.unit.utilities.test_utilities_constants", "TestsTestFlextLdifConstants"],
    "TestsTestFlextLdifDs389Quirks": ["tests.unit.quirks.servers.test_ds389_quirks", "TestsTestFlextLdifDs389Quirks"],
    "TestsTestFlextLdifMigrationPipeline": ["tests.unit.services.test_migration_pipeline", "TestsTestFlextLdifMigrationPipeline"],
    "TestsTestFlextLdifOidQuirks": ["tests.unit.quirks.servers.test_oid_quirks", "TestsTestFlextLdifOidQuirks"],
    "TestsTestFlextLdifProtocols": ["tests.unit.protocols.test_protocols", "TestsTestFlextLdifProtocols"],
    "TestsTestFlextLdifRelaxedQuirks": ["tests.unit.quirks.servers.test_relaxed_quirks", "TestsTestFlextLdifRelaxedQuirks"],
    "TestsTestFlextLdifServiceAPIs": ["tests.unit.utilities.test_utilities", "TestsTestFlextLdifServiceAPIs"],
    "ValidateManyType": ["tests.unit.utilities.test_utilities_constants", "ValidateManyType"],
    "WriteScenario": ["tests.unit.quirks.servers.test_relaxed_quirks", "WriteScenario"],
    "cleanup_state": ["tests.unit.quirks.servers.test_edge_cases", "cleanup_state"],
    "complex_attribute_definition": ["tests.unit.services.test_schema_service", "complex_attribute_definition"],
    "complex_objectclass_definition": ["tests.unit.services.test_schema_service", "complex_objectclass_definition"],
    "constants": ["tests.unit.constants", ""],
    "entry_quirk": ["tests.unit.quirks.servers.test_novell_quirks", "entry_quirk"],
    "ldif_api": ["tests.unit.quirks.servers.test_edge_cases", "ldif_api"],
    "meta_keys": ["tests.unit.quirks.servers.test_relaxed_quirks", "meta_keys"],
    "models": ["tests.unit.models", ""],
    "novell_server": ["tests.unit.quirks.servers.test_novell_quirks", "novell_server"],
    "protocols": ["tests.unit.protocols", ""],
    "schema_quirk": ["tests.unit.quirks.servers.test_novell_quirks", "schema_quirk"],
    "schema_service": ["tests.unit.services.test_schema_service", "schema_service"],
    "schema_service_oud": ["tests.unit.services.test_schema_service", "schema_service_oud"],
    "services": ["tests.unit.services", ""],
    "simple_attribute_definition": ["tests.unit.services.test_schema_service", "simple_attribute_definition"],
    "simple_objectclass_definition": ["tests.unit.services.test_schema_service", "simple_objectclass_definition"],
    "utilities": ["tests.unit.utilities", ""],
    "version_module": ["tests.unit.__init__.test_version", "version_module"],
}

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
    "GetValidValuesType",
    "IsAclAttributeType",
    "IsValidTestType",
    "ObjectClassScenario",
    "ObjectClassTestCase",
    "OidServer",
    "OidTestConstants",
    "OudServer",
    "ParseScenario",
    "RfcTestHelpers",
    "TestAclAttributes",
    "TestAclParser",
    "TestAliasDiscovery",
    "TestAttributeFixer",
    "TestDeduplicationHelpers",
    "TestDnObjectClassMethods",
    "TestFlextLdifDeduplicationHelpers",
    "TestFlextLdifModels",
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
    "TestSchemaServiceBuilder",
    "TestSchemaServiceCanHandleAttribute",
    "TestSchemaServiceIntegration",
    "TestSchemaServiceParseAttribute",
    "TestSchemaServiceParseObjectClass",
    "TestSchemaServiceRepr",
    "TestSchemaServiceValidateAttribute",
    "TestSchemaServiceValidateObjectClass",
    "TestSchemaServiceWriteAttribute",
    "TestSchemaServiceWriteObjectClass",
    "TestSchemaTransformerApplyAttributeTransformations",
    "TestSchemaTransformerApplyObjectClassTransformations",
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
    "TestsFlextLdifSchemaServiceExecute",
    "TestsFlextLdifSchemaTransformerNormalizeAttributeName",
    "TestsFlextLdifVersion",
    "TestsFlextLdifsFlextLdifWriterDnNormalization",
    "TestsTestFlextLdifAclAttributeRegistry",
    "TestsTestFlextLdifApacheQuirks",
    "TestsTestFlextLdifConstants",
    "TestsTestFlextLdifDs389Quirks",
    "TestsTestFlextLdifMigrationPipeline",
    "TestsTestFlextLdifOidQuirks",
    "TestsTestFlextLdifProtocols",
    "TestsTestFlextLdifRelaxedQuirks",
    "TestsTestFlextLdifServiceAPIs",
    "ValidateManyType",
    "WriteScenario",
    "cleanup_state",
    "complex_attribute_definition",
    "complex_objectclass_definition",
    "constants",
    "entry_quirk",
    "ldif_api",
    "meta_keys",
    "models",
    "novell_server",
    "protocols",
    "schema_quirk",
    "schema_service",
    "schema_service_oud",
    "services",
    "simple_attribute_definition",
    "simple_objectclass_definition",
    "utilities",
    "version_module",
]


_LAZY_CACHE: MutableMapping[str, FlextTypes.ModuleExport] = {}


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562).

    A local cache ``_LAZY_CACHE`` persists resolved objects across repeated
    accesses during process lifetime.

    Args:
        name: Attribute name requested by dir()/import.

    Returns:
        Lazy-loaded module export type.

    Raises:
        AttributeError: If attribute not registered.

    """
    if name in _LAZY_CACHE:
        return _LAZY_CACHE[name]

    value = lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)
    _LAZY_CACHE[name] = value
    return value


def __dir__() -> Sequence[str]:
    """Return list of available attributes for dir() and autocomplete.

    Returns:
        List of public names from module exports.

    """
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
