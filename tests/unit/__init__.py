# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Unit package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes

    from . import (
        __init__ as __init__,
        constants as constants,
        models as models,
        protocols as protocols,
        services as services,
        utilities as utilities,
    )
    from .__init__ import TestsFlextLdifVersion, version_module
    from .constants import (
        GetAclAttributesServerType,
        IsAclAttributeType,
        TestsTestFlextLdifAclAttributeRegistry,
    )
    from .models import TestFlextLdifModels
    from .protocols import TestsTestFlextLdifProtocols
    from .services import (
        TestAliasDiscovery,
        TestQuirksAutoInterchange,
        TestQuirksWithRealLdifFixtures,
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
        TestsFlextLdifQuirksStandardizedConstants,
        TestsFlextLdifSchemaServiceExecute,
        TestsFlextLdifsFlextLdifWriterDnNormalization,
        TestsTestFlextLdifMigrationPipeline,
        complex_attribute_definition,
        complex_objectclass_definition,
        schema_service,
        schema_service_oud,
        simple_attribute_definition,
        simple_objectclass_definition,
    )
    from .test_filters import TestAclAttributes
    from .test_helpers import TestFlextLdifDeduplicationHelpers
    from .test_migration_pipeline import TestsFlextLdifMigrationPipeline
    from .test_migration_pipeline_quirks import (
        OidTestConstants,
        TestsFlextLdifMigrationPipelineQuirks,
    )
    from .test_typings import (
        TestFlextLdifTypesStructure,
        TestIntegrationWithLdifFixtures,
        TestModelsNamespace,
        TestPhase1StandardizationResults,
        TestRemovalOfOverEngineering,
        TestsFlextLdifCommonDictionaryTypes,
    )
    from .utilities import (
        GetValidValuesType,
        IsValidTestType,
        TestAclParser,
        TestAttributeFixer,
        TestDnObjectClassMethods,
        TestFlextLdifUtilitiesComprehensive,
        TestLdifParser,
        TestObjectClassUtilities,
        TestServerTypes,
        TestsFlextLdifDnOperationsPure,
        TestsTestFlextLdifConstants,
        TestsTestFlextLdifServiceAPIs,
        ValidateManyType,
    )

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "GetAclAttributesServerType": (
        "tests.unit.constants",
        "GetAclAttributesServerType",
    ),
    "GetValidValuesType": ("tests.unit.utilities", "GetValidValuesType"),
    "IsAclAttributeType": ("tests.unit.constants", "IsAclAttributeType"),
    "IsValidTestType": ("tests.unit.utilities", "IsValidTestType"),
    "OidTestConstants": (
        "tests.unit.test_migration_pipeline_quirks",
        "OidTestConstants",
    ),
    "TestAclAttributes": ("tests.unit.test_filters", "TestAclAttributes"),
    "TestAclParser": ("tests.unit.utilities", "TestAclParser"),
    "TestAliasDiscovery": ("tests.unit.services", "TestAliasDiscovery"),
    "TestAttributeFixer": ("tests.unit.utilities", "TestAttributeFixer"),
    "TestDnObjectClassMethods": ("tests.unit.utilities", "TestDnObjectClassMethods"),
    "TestFlextLdifDeduplicationHelpers": (
        "tests.unit.test_helpers",
        "TestFlextLdifDeduplicationHelpers",
    ),
    "TestFlextLdifModels": ("tests.unit.models", "TestFlextLdifModels"),
    "TestFlextLdifTypesStructure": (
        "tests.unit.test_typings",
        "TestFlextLdifTypesStructure",
    ),
    "TestFlextLdifUtilitiesComprehensive": (
        "tests.unit.utilities",
        "TestFlextLdifUtilitiesComprehensive",
    ),
    "TestIntegrationWithLdifFixtures": (
        "tests.unit.test_typings",
        "TestIntegrationWithLdifFixtures",
    ),
    "TestLdifParser": ("tests.unit.utilities", "TestLdifParser"),
    "TestModelsNamespace": ("tests.unit.test_typings", "TestModelsNamespace"),
    "TestObjectClassUtilities": ("tests.unit.utilities", "TestObjectClassUtilities"),
    "TestPhase1StandardizationResults": (
        "tests.unit.test_typings",
        "TestPhase1StandardizationResults",
    ),
    "TestQuirksAutoInterchange": ("tests.unit.services", "TestQuirksAutoInterchange"),
    "TestQuirksWithRealLdifFixtures": (
        "tests.unit.services",
        "TestQuirksWithRealLdifFixtures",
    ),
    "TestRemovalOfOverEngineering": (
        "tests.unit.test_typings",
        "TestRemovalOfOverEngineering",
    ),
    "TestSchemaServiceBuilder": ("tests.unit.services", "TestSchemaServiceBuilder"),
    "TestSchemaServiceCanHandleAttribute": (
        "tests.unit.services",
        "TestSchemaServiceCanHandleAttribute",
    ),
    "TestSchemaServiceIntegration": (
        "tests.unit.services",
        "TestSchemaServiceIntegration",
    ),
    "TestSchemaServiceParseAttribute": (
        "tests.unit.services",
        "TestSchemaServiceParseAttribute",
    ),
    "TestSchemaServiceParseObjectClass": (
        "tests.unit.services",
        "TestSchemaServiceParseObjectClass",
    ),
    "TestSchemaServiceRepr": ("tests.unit.services", "TestSchemaServiceRepr"),
    "TestSchemaServiceValidateAttribute": (
        "tests.unit.services",
        "TestSchemaServiceValidateAttribute",
    ),
    "TestSchemaServiceValidateObjectClass": (
        "tests.unit.services",
        "TestSchemaServiceValidateObjectClass",
    ),
    "TestSchemaServiceWriteAttribute": (
        "tests.unit.services",
        "TestSchemaServiceWriteAttribute",
    ),
    "TestSchemaServiceWriteObjectClass": (
        "tests.unit.services",
        "TestSchemaServiceWriteObjectClass",
    ),
    "TestServerTypes": ("tests.unit.utilities", "TestServerTypes"),
    "TestsFlextLdifCommonDictionaryTypes": (
        "tests.unit.test_typings",
        "TestsFlextLdifCommonDictionaryTypes",
    ),
    "TestsFlextLdifDnOperationsPure": (
        "tests.unit.utilities",
        "TestsFlextLdifDnOperationsPure",
    ),
    "TestsFlextLdifMigrationPipeline": (
        "tests.unit.test_migration_pipeline",
        "TestsFlextLdifMigrationPipeline",
    ),
    "TestsFlextLdifMigrationPipelineQuirks": (
        "tests.unit.test_migration_pipeline_quirks",
        "TestsFlextLdifMigrationPipelineQuirks",
    ),
    "TestsFlextLdifQuirksStandardizedConstants": (
        "tests.unit.services",
        "TestsFlextLdifQuirksStandardizedConstants",
    ),
    "TestsFlextLdifSchemaServiceExecute": (
        "tests.unit.services",
        "TestsFlextLdifSchemaServiceExecute",
    ),
    "TestsFlextLdifVersion": ("tests.unit.__init__", "TestsFlextLdifVersion"),
    "TestsFlextLdifsFlextLdifWriterDnNormalization": (
        "tests.unit.services",
        "TestsFlextLdifsFlextLdifWriterDnNormalization",
    ),
    "TestsTestFlextLdifAclAttributeRegistry": (
        "tests.unit.constants",
        "TestsTestFlextLdifAclAttributeRegistry",
    ),
    "TestsTestFlextLdifConstants": (
        "tests.unit.utilities",
        "TestsTestFlextLdifConstants",
    ),
    "TestsTestFlextLdifMigrationPipeline": (
        "tests.unit.services",
        "TestsTestFlextLdifMigrationPipeline",
    ),
    "TestsTestFlextLdifProtocols": (
        "tests.unit.protocols",
        "TestsTestFlextLdifProtocols",
    ),
    "TestsTestFlextLdifServiceAPIs": (
        "tests.unit.utilities",
        "TestsTestFlextLdifServiceAPIs",
    ),
    "ValidateManyType": ("tests.unit.utilities", "ValidateManyType"),
    "__init__": ("tests.unit.__init__", ""),
    "complex_attribute_definition": (
        "tests.unit.services",
        "complex_attribute_definition",
    ),
    "complex_objectclass_definition": (
        "tests.unit.services",
        "complex_objectclass_definition",
    ),
    "constants": ("tests.unit.constants", ""),
    "models": ("tests.unit.models", ""),
    "protocols": ("tests.unit.protocols", ""),
    "schema_service": ("tests.unit.services", "schema_service"),
    "schema_service_oud": ("tests.unit.services", "schema_service_oud"),
    "services": ("tests.unit.services", ""),
    "simple_attribute_definition": (
        "tests.unit.services",
        "simple_attribute_definition",
    ),
    "simple_objectclass_definition": (
        "tests.unit.services",
        "simple_objectclass_definition",
    ),
    "utilities": ("tests.unit.utilities", ""),
    "version_module": ("tests.unit.__init__", "version_module"),
}

__all__ = [
    "GetAclAttributesServerType",
    "GetValidValuesType",
    "IsAclAttributeType",
    "IsValidTestType",
    "OidTestConstants",
    "TestAclAttributes",
    "TestAclParser",
    "TestAliasDiscovery",
    "TestAttributeFixer",
    "TestDnObjectClassMethods",
    "TestFlextLdifDeduplicationHelpers",
    "TestFlextLdifModels",
    "TestFlextLdifTypesStructure",
    "TestFlextLdifUtilitiesComprehensive",
    "TestIntegrationWithLdifFixtures",
    "TestLdifParser",
    "TestModelsNamespace",
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
    "TestServerTypes",
    "TestsFlextLdifCommonDictionaryTypes",
    "TestsFlextLdifDnOperationsPure",
    "TestsFlextLdifMigrationPipeline",
    "TestsFlextLdifMigrationPipelineQuirks",
    "TestsFlextLdifQuirksStandardizedConstants",
    "TestsFlextLdifSchemaServiceExecute",
    "TestsFlextLdifVersion",
    "TestsFlextLdifsFlextLdifWriterDnNormalization",
    "TestsTestFlextLdifAclAttributeRegistry",
    "TestsTestFlextLdifConstants",
    "TestsTestFlextLdifMigrationPipeline",
    "TestsTestFlextLdifProtocols",
    "TestsTestFlextLdifServiceAPIs",
    "ValidateManyType",
    "__init__",
    "complex_attribute_definition",
    "complex_objectclass_definition",
    "constants",
    "models",
    "protocols",
    "schema_service",
    "schema_service_oud",
    "services",
    "simple_attribute_definition",
    "simple_objectclass_definition",
    "utilities",
    "version_module",
]


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
