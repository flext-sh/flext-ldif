# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""FLEXT LDIF Utilities - Internal package exports."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes

    from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
    from flext_ldif._utilities.attribute import FlextLdifUtilitiesAttribute
    from flext_ldif._utilities.builders import (
        FilterConfigBuilder,
        ProcessConfigBuilder,
        TransformConfigBuilder,
        WriteConfigBuilder,
    )
    from flext_ldif._utilities.decorators import FlextLdifUtilitiesDecorators
    from flext_ldif._utilities.detection import FlextLdifUtilitiesDetection
    from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
    from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
    from flext_ldif._utilities.events import FlextLdifUtilitiesEvents
    from flext_ldif._utilities.filters import (
        AndFilter,
        ByAttrsFilter,
        ByAttrValueFilter,
        ByDnFilter,
        ByDnUnderBaseFilter,
        ByObjectClassFilter,
        CustomFilter,
        ExcludeAttrsFilter,
        Filter,
        FlextLdifUtilitiesFilters,
        IsSchemaFlextLdifUtilitiesFilters,
        NotFilter,
        OrFilter,
    )
    from flext_ldif._utilities.fluent import DnOps, EntryOps
    from flext_ldif._utilities.functional import FlextFunctional, f
    from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
    from flext_ldif._utilities.object_class import FlextLdifUtilitiesObjectClass
    from flext_ldif._utilities.oid import FlextLdifUtilitiesOID
    from flext_ldif._utilities.parser import FlextLdifUtilitiesParser
    from flext_ldif._utilities.parsers import FlextLdifUtilitiesParsers
    from flext_ldif._utilities.pipeline import (
        Pipeline,
        PipelineStep,
        ValidationPipeline,
        ValidationResult,
    )
    from flext_ldif._utilities.result import FlextLdifUtilitiesResult
    from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema
    from flext_ldif._utilities.server import FlextLdifUtilitiesServer
    from flext_ldif._utilities.transformers import (
        ConvertBooleansTransformer,
        CustomTransformer,
        FilterAttrsTransformer,
        FlextLdifUtilitiesTransformer,
        Normalize,
        NormalizeAttrsTransformer,
        NormalizeDnTransformer,
        RemoveAttrsTransformer,
        ReplaceBaseDnTransformer,
        Transform,
    )
    from flext_ldif._utilities.type_guards import FlextLdifUtilitiesTypeGuards
    from flext_ldif._utilities.type_helpers import FlextLdifTypeHelpers
    from flext_ldif._utilities.validation import FlextLdifUtilitiesValidation
    from flext_ldif._utilities.writer import FlextLdifUtilitiesWriter
    from flext_ldif._utilities.writers import FlextLdifUtilitiesWriters, logger

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "AndFilter": ("flext_ldif._utilities.filters", "AndFilter"),
    "ByAttrValueFilter": ("flext_ldif._utilities.filters", "ByAttrValueFilter"),
    "ByAttrsFilter": ("flext_ldif._utilities.filters", "ByAttrsFilter"),
    "ByDnFilter": ("flext_ldif._utilities.filters", "ByDnFilter"),
    "ByDnUnderBaseFilter": ("flext_ldif._utilities.filters", "ByDnUnderBaseFilter"),
    "ByObjectClassFilter": ("flext_ldif._utilities.filters", "ByObjectClassFilter"),
    "ConvertBooleansTransformer": (
        "flext_ldif._utilities.transformers",
        "ConvertBooleansTransformer",
    ),
    "CustomFilter": ("flext_ldif._utilities.filters", "CustomFilter"),
    "CustomTransformer": ("flext_ldif._utilities.transformers", "CustomTransformer"),
    "DnOps": ("flext_ldif._utilities.fluent", "DnOps"),
    "EntryOps": ("flext_ldif._utilities.fluent", "EntryOps"),
    "ExcludeAttrsFilter": ("flext_ldif._utilities.filters", "ExcludeAttrsFilter"),
    "Filter": ("flext_ldif._utilities.filters", "Filter"),
    "FilterAttrsTransformer": (
        "flext_ldif._utilities.transformers",
        "FilterAttrsTransformer",
    ),
    "FilterConfigBuilder": ("flext_ldif._utilities.builders", "FilterConfigBuilder"),
    "FlextFunctional": ("flext_ldif._utilities.functional", "FlextFunctional"),
    "FlextLdifTypeHelpers": (
        "flext_ldif._utilities.type_helpers",
        "FlextLdifTypeHelpers",
    ),
    "FlextLdifUtilitiesACL": ("flext_ldif._utilities.acl", "FlextLdifUtilitiesACL"),
    "FlextLdifUtilitiesAttribute": (
        "flext_ldif._utilities.attribute",
        "FlextLdifUtilitiesAttribute",
    ),
    "FlextLdifUtilitiesDN": ("flext_ldif._utilities.dn", "FlextLdifUtilitiesDN"),
    "FlextLdifUtilitiesDecorators": (
        "flext_ldif._utilities.decorators",
        "FlextLdifUtilitiesDecorators",
    ),
    "FlextLdifUtilitiesDetection": (
        "flext_ldif._utilities.detection",
        "FlextLdifUtilitiesDetection",
    ),
    "FlextLdifUtilitiesEntry": (
        "flext_ldif._utilities.entry",
        "FlextLdifUtilitiesEntry",
    ),
    "FlextLdifUtilitiesEvents": (
        "flext_ldif._utilities.events",
        "FlextLdifUtilitiesEvents",
    ),
    "FlextLdifUtilitiesFilters": (
        "flext_ldif._utilities.filters",
        "FlextLdifUtilitiesFilters",
    ),
    "FlextLdifUtilitiesMetadata": (
        "flext_ldif._utilities.metadata",
        "FlextLdifUtilitiesMetadata",
    ),
    "FlextLdifUtilitiesOID": ("flext_ldif._utilities.oid", "FlextLdifUtilitiesOID"),
    "FlextLdifUtilitiesObjectClass": (
        "flext_ldif._utilities.object_class",
        "FlextLdifUtilitiesObjectClass",
    ),
    "FlextLdifUtilitiesParser": (
        "flext_ldif._utilities.parser",
        "FlextLdifUtilitiesParser",
    ),
    "FlextLdifUtilitiesParsers": (
        "flext_ldif._utilities.parsers",
        "FlextLdifUtilitiesParsers",
    ),
    "FlextLdifUtilitiesResult": (
        "flext_ldif._utilities.result",
        "FlextLdifUtilitiesResult",
    ),
    "FlextLdifUtilitiesSchema": (
        "flext_ldif._utilities.schema",
        "FlextLdifUtilitiesSchema",
    ),
    "FlextLdifUtilitiesServer": (
        "flext_ldif._utilities.server",
        "FlextLdifUtilitiesServer",
    ),
    "FlextLdifUtilitiesTransformer": (
        "flext_ldif._utilities.transformers",
        "FlextLdifUtilitiesTransformer",
    ),
    "FlextLdifUtilitiesTypeGuards": (
        "flext_ldif._utilities.type_guards",
        "FlextLdifUtilitiesTypeGuards",
    ),
    "FlextLdifUtilitiesValidation": (
        "flext_ldif._utilities.validation",
        "FlextLdifUtilitiesValidation",
    ),
    "FlextLdifUtilitiesWriter": (
        "flext_ldif._utilities.writer",
        "FlextLdifUtilitiesWriter",
    ),
    "FlextLdifUtilitiesWriters": (
        "flext_ldif._utilities.writers",
        "FlextLdifUtilitiesWriters",
    ),
    "IsSchemaFlextLdifUtilitiesFilters": (
        "flext_ldif._utilities.filters",
        "IsSchemaFlextLdifUtilitiesFilters",
    ),
    "Normalize": ("flext_ldif._utilities.transformers", "Normalize"),
    "NormalizeAttrsTransformer": (
        "flext_ldif._utilities.transformers",
        "NormalizeAttrsTransformer",
    ),
    "NormalizeDnTransformer": (
        "flext_ldif._utilities.transformers",
        "NormalizeDnTransformer",
    ),
    "NotFilter": ("flext_ldif._utilities.filters", "NotFilter"),
    "OrFilter": ("flext_ldif._utilities.filters", "OrFilter"),
    "Pipeline": ("flext_ldif._utilities.pipeline", "Pipeline"),
    "PipelineStep": ("flext_ldif._utilities.pipeline", "PipelineStep"),
    "ProcessConfigBuilder": ("flext_ldif._utilities.builders", "ProcessConfigBuilder"),
    "RemoveAttrsTransformer": (
        "flext_ldif._utilities.transformers",
        "RemoveAttrsTransformer",
    ),
    "ReplaceBaseDnTransformer": (
        "flext_ldif._utilities.transformers",
        "ReplaceBaseDnTransformer",
    ),
    "Transform": ("flext_ldif._utilities.transformers", "Transform"),
    "TransformConfigBuilder": (
        "flext_ldif._utilities.builders",
        "TransformConfigBuilder",
    ),
    "ValidationPipeline": ("flext_ldif._utilities.pipeline", "ValidationPipeline"),
    "ValidationResult": ("flext_ldif._utilities.pipeline", "ValidationResult"),
    "WriteConfigBuilder": ("flext_ldif._utilities.builders", "WriteConfigBuilder"),
    "f": ("flext_ldif._utilities.functional", "f"),
    "logger": ("flext_ldif._utilities.writers", "logger"),
}

__all__ = [
    "AndFilter",
    "ByAttrValueFilter",
    "ByAttrsFilter",
    "ByDnFilter",
    "ByDnUnderBaseFilter",
    "ByObjectClassFilter",
    "ConvertBooleansTransformer",
    "CustomFilter",
    "CustomTransformer",
    "DnOps",
    "EntryOps",
    "ExcludeAttrsFilter",
    "Filter",
    "FilterAttrsTransformer",
    "FilterConfigBuilder",
    "FlextFunctional",
    "FlextLdifTypeHelpers",
    "FlextLdifUtilitiesACL",
    "FlextLdifUtilitiesAttribute",
    "FlextLdifUtilitiesDN",
    "FlextLdifUtilitiesDecorators",
    "FlextLdifUtilitiesDetection",
    "FlextLdifUtilitiesEntry",
    "FlextLdifUtilitiesEvents",
    "FlextLdifUtilitiesFilters",
    "FlextLdifUtilitiesMetadata",
    "FlextLdifUtilitiesOID",
    "FlextLdifUtilitiesObjectClass",
    "FlextLdifUtilitiesParser",
    "FlextLdifUtilitiesParsers",
    "FlextLdifUtilitiesResult",
    "FlextLdifUtilitiesSchema",
    "FlextLdifUtilitiesServer",
    "FlextLdifUtilitiesTransformer",
    "FlextLdifUtilitiesTypeGuards",
    "FlextLdifUtilitiesValidation",
    "FlextLdifUtilitiesWriter",
    "FlextLdifUtilitiesWriters",
    "IsSchemaFlextLdifUtilitiesFilters",
    "Normalize",
    "NormalizeAttrsTransformer",
    "NormalizeDnTransformer",
    "NotFilter",
    "OrFilter",
    "Pipeline",
    "PipelineStep",
    "ProcessConfigBuilder",
    "RemoveAttrsTransformer",
    "ReplaceBaseDnTransformer",
    "Transform",
    "TransformConfigBuilder",
    "ValidationPipeline",
    "ValidationResult",
    "WriteConfigBuilder",
    "f",
    "logger",
]


_LAZY_CACHE: dict[str, object] = {}


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


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete.

    Returns:
        List of public names from module exports.

    """
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
