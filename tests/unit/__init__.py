# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Unit package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes

    from tests.unit import __init__, constants, models, protocols, services, utilities
    from tests.unit.__init__.test_version import TestsFlextLdifVersion, version_module
    from tests.unit.constants.test_acl_registry import (
        GetAclAttributesServerType,
        IsAclAttributeType,
        TestsTestFlextLdifAclAttributeRegistry,
    )
    from tests.unit.models.test_models import (
        TestFlextLdifModels,
        TestFlextLdifModels as m,
    )
    from tests.unit.protocols.test_protocols import (
        TestsTestFlextLdifProtocols,
        TestsTestFlextLdifProtocols as p,
    )
    from tests.unit.services.test_migration_pipeline import (
        TestsTestFlextLdifMigrationPipeline,
    )
    from tests.unit.services.test_quirks_standardization import (
        TestAliasDiscovery,
        TestQuirksAutoInterchange,
        TestQuirksWithRealLdifFixtures,
        TestsFlextLdifQuirksStandardizedConstants,
        TestsFlextLdifQuirksStandardizedConstants as c,
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
        TestObjectClassUtilities as u,
        TestServerTypes,
        TestServerTypes as t,
        TestsFlextLdifDnOperationsPure,
    )

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "GetAclAttributesServerType": (
        "tests.unit.constants.test_acl_registry",
        "GetAclAttributesServerType",
    ),
    "GetValidValuesType": (
        "tests.unit.utilities.test_utilities_constants",
        "GetValidValuesType",
    ),
    "IsAclAttributeType": (
        "tests.unit.constants.test_acl_registry",
        "IsAclAttributeType",
    ),
    "IsValidTestType": (
        "tests.unit.utilities.test_utilities_constants",
        "IsValidTestType",
    ),
    "OidTestConstants": (
        "tests.unit.test_migration_pipeline_quirks",
        "OidTestConstants",
    ),
    "TestAclAttributes": ("tests.unit.test_filters", "TestAclAttributes"),
    "TestAclParser": ("tests.unit.utilities.test_utilities_core", "TestAclParser"),
    "TestAliasDiscovery": (
        "tests.unit.services.test_quirks_standardization",
        "TestAliasDiscovery",
    ),
    "TestAttributeFixer": (
        "tests.unit.utilities.test_utilities_core",
        "TestAttributeFixer",
    ),
    "TestDnObjectClassMethods": (
        "tests.unit.utilities.test_utilities_core",
        "TestDnObjectClassMethods",
    ),
    "TestFlextLdifDeduplicationHelpers": (
        "tests.unit.test_helpers",
        "TestFlextLdifDeduplicationHelpers",
    ),
    "TestFlextLdifModels": ("tests.unit.models.test_models", "TestFlextLdifModels"),
    "TestFlextLdifTypesStructure": (
        "tests.unit.test_typings",
        "TestFlextLdifTypesStructure",
    ),
    "TestFlextLdifUtilitiesComprehensive": (
        "tests.unit.utilities.test_utilities_comprehensive",
        "TestFlextLdifUtilitiesComprehensive",
    ),
    "TestIntegrationWithLdifFixtures": (
        "tests.unit.test_typings",
        "TestIntegrationWithLdifFixtures",
    ),
    "TestLdifParser": ("tests.unit.utilities.test_utilities_core", "TestLdifParser"),
    "TestModelsNamespace": ("tests.unit.test_typings", "TestModelsNamespace"),
    "TestObjectClassUtilities": (
        "tests.unit.utilities.test_utilities_core",
        "TestObjectClassUtilities",
    ),
    "TestPhase1StandardizationResults": (
        "tests.unit.test_typings",
        "TestPhase1StandardizationResults",
    ),
    "TestQuirksAutoInterchange": (
        "tests.unit.services.test_quirks_standardization",
        "TestQuirksAutoInterchange",
    ),
    "TestQuirksWithRealLdifFixtures": (
        "tests.unit.services.test_quirks_standardization",
        "TestQuirksWithRealLdifFixtures",
    ),
    "TestRemovalOfOverEngineering": (
        "tests.unit.test_typings",
        "TestRemovalOfOverEngineering",
    ),
    "TestSchemaServiceBuilder": (
        "tests.unit.services.test_schema_service",
        "TestSchemaServiceBuilder",
    ),
    "TestSchemaServiceCanHandleAttribute": (
        "tests.unit.services.test_schema_service",
        "TestSchemaServiceCanHandleAttribute",
    ),
    "TestSchemaServiceIntegration": (
        "tests.unit.services.test_schema_service",
        "TestSchemaServiceIntegration",
    ),
    "TestSchemaServiceParseAttribute": (
        "tests.unit.services.test_schema_service",
        "TestSchemaServiceParseAttribute",
    ),
    "TestSchemaServiceParseObjectClass": (
        "tests.unit.services.test_schema_service",
        "TestSchemaServiceParseObjectClass",
    ),
    "TestSchemaServiceRepr": (
        "tests.unit.services.test_schema_service",
        "TestSchemaServiceRepr",
    ),
    "TestSchemaServiceValidateAttribute": (
        "tests.unit.services.test_schema_service",
        "TestSchemaServiceValidateAttribute",
    ),
    "TestSchemaServiceValidateObjectClass": (
        "tests.unit.services.test_schema_service",
        "TestSchemaServiceValidateObjectClass",
    ),
    "TestSchemaServiceWriteAttribute": (
        "tests.unit.services.test_schema_service",
        "TestSchemaServiceWriteAttribute",
    ),
    "TestSchemaServiceWriteObjectClass": (
        "tests.unit.services.test_schema_service",
        "TestSchemaServiceWriteObjectClass",
    ),
    "TestServerTypes": ("tests.unit.utilities.test_utilities_core", "TestServerTypes"),
    "TestsFlextLdifCommonDictionaryTypes": (
        "tests.unit.test_typings",
        "TestsFlextLdifCommonDictionaryTypes",
    ),
    "TestsFlextLdifDnOperationsPure": (
        "tests.unit.utilities.test_utilities_core",
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
        "tests.unit.services.test_quirks_standardization",
        "TestsFlextLdifQuirksStandardizedConstants",
    ),
    "TestsFlextLdifSchemaServiceExecute": (
        "tests.unit.services.test_schema_service",
        "TestsFlextLdifSchemaServiceExecute",
    ),
    "TestsFlextLdifVersion": (
        "tests.unit.__init__.test_version",
        "TestsFlextLdifVersion",
    ),
    "TestsFlextLdifsFlextLdifWriterDnNormalization": (
        "tests.unit.services.test_writer_dn_normalization",
        "TestsFlextLdifsFlextLdifWriterDnNormalization",
    ),
    "TestsTestFlextLdifAclAttributeRegistry": (
        "tests.unit.constants.test_acl_registry",
        "TestsTestFlextLdifAclAttributeRegistry",
    ),
    "TestsTestFlextLdifConstants": (
        "tests.unit.utilities.test_utilities_constants",
        "TestsTestFlextLdifConstants",
    ),
    "TestsTestFlextLdifMigrationPipeline": (
        "tests.unit.services.test_migration_pipeline",
        "TestsTestFlextLdifMigrationPipeline",
    ),
    "TestsTestFlextLdifProtocols": (
        "tests.unit.protocols.test_protocols",
        "TestsTestFlextLdifProtocols",
    ),
    "TestsTestFlextLdifServiceAPIs": (
        "tests.unit.utilities.test_utilities",
        "TestsTestFlextLdifServiceAPIs",
    ),
    "ValidateManyType": (
        "tests.unit.utilities.test_utilities_constants",
        "ValidateManyType",
    ),
    "__init__": ("tests.unit.__init__", ""),
    "c": (
        "tests.unit.services.test_quirks_standardization",
        "TestsFlextLdifQuirksStandardizedConstants",
    ),
    "complex_attribute_definition": (
        "tests.unit.services.test_schema_service",
        "complex_attribute_definition",
    ),
    "complex_objectclass_definition": (
        "tests.unit.services.test_schema_service",
        "complex_objectclass_definition",
    ),
    "constants": ("tests.unit.constants", ""),
    "m": ("tests.unit.models.test_models", "TestFlextLdifModels"),
    "models": ("tests.unit.models", ""),
    "p": ("tests.unit.protocols.test_protocols", "TestsTestFlextLdifProtocols"),
    "protocols": ("tests.unit.protocols", ""),
    "schema_service": ("tests.unit.services.test_schema_service", "schema_service"),
    "schema_service_oud": (
        "tests.unit.services.test_schema_service",
        "schema_service_oud",
    ),
    "services": ("tests.unit.services", ""),
    "simple_attribute_definition": (
        "tests.unit.services.test_schema_service",
        "simple_attribute_definition",
    ),
    "simple_objectclass_definition": (
        "tests.unit.services.test_schema_service",
        "simple_objectclass_definition",
    ),
    "t": ("tests.unit.utilities.test_utilities_core", "TestServerTypes"),
    "u": ("tests.unit.utilities.test_utilities_core", "TestObjectClassUtilities"),
    "utilities": ("tests.unit.utilities", ""),
    "version_module": ("tests.unit.__init__.test_version", "version_module"),
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
    "c",
    "complex_attribute_definition",
    "complex_objectclass_definition",
    "constants",
    "m",
    "models",
    "p",
    "protocols",
    "schema_service",
    "schema_service_oud",
    "services",
    "simple_attribute_definition",
    "simple_objectclass_definition",
    "t",
    "u",
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
