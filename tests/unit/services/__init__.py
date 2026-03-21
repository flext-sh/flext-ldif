# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Unit tests for services."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "TestAliasDiscovery": (
        "tests.unit.services.test_quirks_standardization",
        "TestAliasDiscovery",
    ),
    "TestQuirksAutoInterchange": (
        "tests.unit.services.test_quirks_standardization",
        "TestQuirksAutoInterchange",
    ),
    "TestQuirksWithRealLdifFixtures": (
        "tests.unit.services.test_quirks_standardization",
        "TestQuirksWithRealLdifFixtures",
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
    "TestsFlextLdifQuirksStandardizedConstants": (
        "tests.unit.services.test_quirks_standardization",
        "TestsFlextLdifQuirksStandardizedConstants",
    ),
    "TestsFlextLdifSchemaServiceExecute": (
        "tests.unit.services.test_schema_service",
        "TestsFlextLdifSchemaServiceExecute",
    ),
    "TestsFlextLdifsFlextLdifWriterDnNormalization": (
        "tests.unit.services.test_writer_dn_normalization",
        "TestsFlextLdifsFlextLdifWriterDnNormalization",
    ),
    "TestsTestFlextLdifMigrationPipeline": (
        "tests.unit.services.test_migration_pipeline",
        "TestsTestFlextLdifMigrationPipeline",
    ),
    "complex_attribute_definition": (
        "tests.unit.services.test_schema_service",
        "complex_attribute_definition",
    ),
    "complex_objectclass_definition": (
        "tests.unit.services.test_schema_service",
        "complex_objectclass_definition",
    ),
    "schema_service": ("tests.unit.services.test_schema_service", "schema_service"),
    "schema_service_oud": (
        "tests.unit.services.test_schema_service",
        "schema_service_oud",
    ),
    "simple_attribute_definition": (
        "tests.unit.services.test_schema_service",
        "simple_attribute_definition",
    ),
    "simple_objectclass_definition": (
        "tests.unit.services.test_schema_service",
        "simple_objectclass_definition",
    ),
}

__all__ = [
    "TestAliasDiscovery",
    "TestQuirksAutoInterchange",
    "TestQuirksWithRealLdifFixtures",
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
    "TestsFlextLdifQuirksStandardizedConstants",
    "TestsFlextLdifSchemaServiceExecute",
    "TestsFlextLdifsFlextLdifWriterDnNormalization",
    "TestsTestFlextLdifMigrationPipeline",
    "complex_attribute_definition",
    "complex_objectclass_definition",
    "schema_service",
    "schema_service_oud",
    "simple_attribute_definition",
    "simple_objectclass_definition",
]


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
