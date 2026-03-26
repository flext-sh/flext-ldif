# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""FLEXT LDIF Utilities - Internal package exports."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core import FlextTypes

    from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
    from flext_ldif._utilities.attribute import FlextLdifUtilitiesAttribute
    from flext_ldif._utilities.builders import FlextLdifUtilitiesBuilders
    from flext_ldif._utilities.collection_ldif import FlextLdifUtilitiesCollectionLdif
    from flext_ldif._utilities.decorators import FlextLdifUtilitiesDecorators
    from flext_ldif._utilities.detection import FlextLdifUtilitiesDetection
    from flext_ldif._utilities.dispatch import FlextLdifUtilitiesDispatch
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
    from flext_ldif._utilities.functional import FlextLdifUtilitiesFunctional, f
    from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
    from flext_ldif._utilities.normalization import FlextLdifUtilitiesNormalization
    from flext_ldif._utilities.object_class import FlextLdifUtilitiesObjectClass
    from flext_ldif._utilities.oid import FlextLdifUtilitiesOID
    from flext_ldif._utilities.parser import FlextLdifUtilitiesParser
    from flext_ldif._utilities.parsers import FlextLdifUtilitiesParsers
    from flext_ldif._utilities.pipeline import FlextLdifUtilitiesPipeline
    from flext_ldif._utilities.processing import FlextLdifUtilitiesProcessing
    from flext_ldif._utilities.result import FlextLdifUtilitiesResult
    from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema
    from flext_ldif._utilities.server import FlextLdifUtilitiesServer
    from flext_ldif._utilities.transformers import (
        FlextLdifUtilitiesTransformer,
        FlextLdifUtilitiesTransformers,
    )
    from flext_ldif._utilities.validation import FlextLdifUtilitiesValidation
    from flext_ldif._utilities.writer import FlextLdifUtilitiesWriter
    from flext_ldif._utilities.writers import FlextLdifUtilitiesWriters, logger

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "AndFilter": ["flext_ldif._utilities.filters", "AndFilter"],
    "ByAttrValueFilter": ["flext_ldif._utilities.filters", "ByAttrValueFilter"],
    "ByAttrsFilter": ["flext_ldif._utilities.filters", "ByAttrsFilter"],
    "ByDnFilter": ["flext_ldif._utilities.filters", "ByDnFilter"],
    "ByDnUnderBaseFilter": ["flext_ldif._utilities.filters", "ByDnUnderBaseFilter"],
    "ByObjectClassFilter": ["flext_ldif._utilities.filters", "ByObjectClassFilter"],
    "CustomFilter": ["flext_ldif._utilities.filters", "CustomFilter"],
    "ExcludeAttrsFilter": ["flext_ldif._utilities.filters", "ExcludeAttrsFilter"],
    "Filter": ["flext_ldif._utilities.filters", "Filter"],
    "FlextLdifUtilitiesACL": ["flext_ldif._utilities.acl", "FlextLdifUtilitiesACL"],
    "FlextLdifUtilitiesAttribute": [
        "flext_ldif._utilities.attribute",
        "FlextLdifUtilitiesAttribute",
    ],
    "FlextLdifUtilitiesBuilders": [
        "flext_ldif._utilities.builders",
        "FlextLdifUtilitiesBuilders",
    ],
    "FlextLdifUtilitiesCollectionLdif": [
        "flext_ldif._utilities.collection_ldif",
        "FlextLdifUtilitiesCollectionLdif",
    ],
    "FlextLdifUtilitiesDN": ["flext_ldif._utilities.dn", "FlextLdifUtilitiesDN"],
    "FlextLdifUtilitiesDecorators": [
        "flext_ldif._utilities.decorators",
        "FlextLdifUtilitiesDecorators",
    ],
    "FlextLdifUtilitiesDetection": [
        "flext_ldif._utilities.detection",
        "FlextLdifUtilitiesDetection",
    ],
    "FlextLdifUtilitiesDispatch": [
        "flext_ldif._utilities.dispatch",
        "FlextLdifUtilitiesDispatch",
    ],
    "FlextLdifUtilitiesEntry": [
        "flext_ldif._utilities.entry",
        "FlextLdifUtilitiesEntry",
    ],
    "FlextLdifUtilitiesEvents": [
        "flext_ldif._utilities.events",
        "FlextLdifUtilitiesEvents",
    ],
    "FlextLdifUtilitiesFilters": [
        "flext_ldif._utilities.filters",
        "FlextLdifUtilitiesFilters",
    ],
    "FlextLdifUtilitiesFunctional": [
        "flext_ldif._utilities.functional",
        "FlextLdifUtilitiesFunctional",
    ],
    "FlextLdifUtilitiesMetadata": [
        "flext_ldif._utilities.metadata",
        "FlextLdifUtilitiesMetadata",
    ],
    "FlextLdifUtilitiesNormalization": [
        "flext_ldif._utilities.normalization",
        "FlextLdifUtilitiesNormalization",
    ],
    "FlextLdifUtilitiesOID": ["flext_ldif._utilities.oid", "FlextLdifUtilitiesOID"],
    "FlextLdifUtilitiesObjectClass": [
        "flext_ldif._utilities.object_class",
        "FlextLdifUtilitiesObjectClass",
    ],
    "FlextLdifUtilitiesParser": [
        "flext_ldif._utilities.parser",
        "FlextLdifUtilitiesParser",
    ],
    "FlextLdifUtilitiesParsers": [
        "flext_ldif._utilities.parsers",
        "FlextLdifUtilitiesParsers",
    ],
    "FlextLdifUtilitiesPipeline": [
        "flext_ldif._utilities.pipeline",
        "FlextLdifUtilitiesPipeline",
    ],
    "FlextLdifUtilitiesProcessing": [
        "flext_ldif._utilities.processing",
        "FlextLdifUtilitiesProcessing",
    ],
    "FlextLdifUtilitiesResult": [
        "flext_ldif._utilities.result",
        "FlextLdifUtilitiesResult",
    ],
    "FlextLdifUtilitiesSchema": [
        "flext_ldif._utilities.schema",
        "FlextLdifUtilitiesSchema",
    ],
    "FlextLdifUtilitiesServer": [
        "flext_ldif._utilities.server",
        "FlextLdifUtilitiesServer",
    ],
    "FlextLdifUtilitiesTransformer": [
        "flext_ldif._utilities.transformers",
        "FlextLdifUtilitiesTransformer",
    ],
    "FlextLdifUtilitiesTransformers": [
        "flext_ldif._utilities.transformers",
        "FlextLdifUtilitiesTransformers",
    ],
    "FlextLdifUtilitiesValidation": [
        "flext_ldif._utilities.validation",
        "FlextLdifUtilitiesValidation",
    ],
    "FlextLdifUtilitiesWriter": [
        "flext_ldif._utilities.writer",
        "FlextLdifUtilitiesWriter",
    ],
    "FlextLdifUtilitiesWriters": [
        "flext_ldif._utilities.writers",
        "FlextLdifUtilitiesWriters",
    ],
    "IsSchemaFlextLdifUtilitiesFilters": [
        "flext_ldif._utilities.filters",
        "IsSchemaFlextLdifUtilitiesFilters",
    ],
    "NotFilter": ["flext_ldif._utilities.filters", "NotFilter"],
    "OrFilter": ["flext_ldif._utilities.filters", "OrFilter"],
    "f": ["flext_ldif._utilities.functional", "f"],
    "logger": ["flext_ldif._utilities.writers", "logger"],
}

__all__ = [
    "AndFilter",
    "ByAttrValueFilter",
    "ByAttrsFilter",
    "ByDnFilter",
    "ByDnUnderBaseFilter",
    "ByObjectClassFilter",
    "CustomFilter",
    "ExcludeAttrsFilter",
    "Filter",
    "FlextLdifUtilitiesACL",
    "FlextLdifUtilitiesAttribute",
    "FlextLdifUtilitiesBuilders",
    "FlextLdifUtilitiesCollectionLdif",
    "FlextLdifUtilitiesDN",
    "FlextLdifUtilitiesDecorators",
    "FlextLdifUtilitiesDetection",
    "FlextLdifUtilitiesDispatch",
    "FlextLdifUtilitiesEntry",
    "FlextLdifUtilitiesEvents",
    "FlextLdifUtilitiesFilters",
    "FlextLdifUtilitiesFunctional",
    "FlextLdifUtilitiesMetadata",
    "FlextLdifUtilitiesNormalization",
    "FlextLdifUtilitiesOID",
    "FlextLdifUtilitiesObjectClass",
    "FlextLdifUtilitiesParser",
    "FlextLdifUtilitiesParsers",
    "FlextLdifUtilitiesPipeline",
    "FlextLdifUtilitiesProcessing",
    "FlextLdifUtilitiesResult",
    "FlextLdifUtilitiesSchema",
    "FlextLdifUtilitiesServer",
    "FlextLdifUtilitiesTransformer",
    "FlextLdifUtilitiesTransformers",
    "FlextLdifUtilitiesValidation",
    "FlextLdifUtilitiesWriter",
    "FlextLdifUtilitiesWriters",
    "IsSchemaFlextLdifUtilitiesFilters",
    "NotFilter",
    "OrFilter",
    "f",
    "logger",
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
