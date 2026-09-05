# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Utilities package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from ._transformer_attrs import FlextLdifUtilitiesNormalizeAttrsTransformer
    from ._transformer_base import FlextLdifUtilitiesTransformer
    from ._transformer_dn import FlextLdifUtilitiesNormalizeDnTransformer
    from .acl import FlextLdifUtilitiesACL
    from .attribute import FlextLdifUtilitiesAttribute
    from .collection_ldif import FlextLdifUtilitiesCollectionLdif
    from .dispatch import FlextLdifUtilitiesDispatch
    from .dn import FlextLdifUtilitiesDN
    from .entry import FlextLdifUtilitiesEntry
    from .events import FlextLdifUtilitiesEvents
    from .metadata import FlextLdifUtilitiesMetadata
    from .object_class import FlextLdifUtilitiesObjectClass
    from .oid import FlextLdifUtilitiesOID
    from .parser import FlextLdifUtilitiesParser
    from .pipeline import FlextLdifUtilitiesPipeline
    from .schema import FlextLdifUtilitiesSchema
    from .schema_build import FlextLdifUtilitiesSchemaBuild
    from .schema_extract import FlextLdifUtilitiesSchemaExtract
    from .schema_format import FlextLdifUtilitiesSchemaFormat
    from .schema_normalize import FlextLdifUtilitiesSchemaNormalize
    from .schema_parse import FlextLdifUtilitiesSchemaParse
    from .server import FlextLdifUtilitiesServer
    from .transformers import FlextLdifUtilitiesTransformers
    from .validation import FlextLdifUtilitiesValidation
    from .writer import FlextLdifUtilitiesWriter
__all__: tuple[str, ...] = (
    "FlextLdifUtilitiesACL",
    "FlextLdifUtilitiesAttribute",
    "FlextLdifUtilitiesCollectionLdif",
    "FlextLdifUtilitiesDN",
    "FlextLdifUtilitiesDispatch",
    "FlextLdifUtilitiesEntry",
    "FlextLdifUtilitiesEvents",
    "FlextLdifUtilitiesMetadata",
    "FlextLdifUtilitiesNormalizeAttrsTransformer",
    "FlextLdifUtilitiesNormalizeDnTransformer",
    "FlextLdifUtilitiesOID",
    "FlextLdifUtilitiesObjectClass",
    "FlextLdifUtilitiesParser",
    "FlextLdifUtilitiesPipeline",
    "FlextLdifUtilitiesSchema",
    "FlextLdifUtilitiesSchemaBuild",
    "FlextLdifUtilitiesSchemaExtract",
    "FlextLdifUtilitiesSchemaFormat",
    "FlextLdifUtilitiesSchemaNormalize",
    "FlextLdifUtilitiesSchemaParse",
    "FlextLdifUtilitiesServer",
    "FlextLdifUtilitiesTransformer",
    "FlextLdifUtilitiesTransformers",
    "FlextLdifUtilitiesValidation",
    "FlextLdifUtilitiesWriter",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            "._transformer_attrs": ("FlextLdifUtilitiesNormalizeAttrsTransformer",),
            "._transformer_base": ("FlextLdifUtilitiesTransformer",),
            "._transformer_dn": ("FlextLdifUtilitiesNormalizeDnTransformer",),
            ".acl": ("FlextLdifUtilitiesACL",),
            ".attribute": ("FlextLdifUtilitiesAttribute",),
            ".collection_ldif": ("FlextLdifUtilitiesCollectionLdif",),
            ".dispatch": ("FlextLdifUtilitiesDispatch",),
            ".dn": ("FlextLdifUtilitiesDN",),
            ".entry": ("FlextLdifUtilitiesEntry",),
            ".events": ("FlextLdifUtilitiesEvents",),
            ".metadata": ("FlextLdifUtilitiesMetadata",),
            ".object_class": ("FlextLdifUtilitiesObjectClass",),
            ".oid": ("FlextLdifUtilitiesOID",),
            ".parser": ("FlextLdifUtilitiesParser",),
            ".pipeline": ("FlextLdifUtilitiesPipeline",),
            ".schema": ("FlextLdifUtilitiesSchema",),
            ".schema_build": ("FlextLdifUtilitiesSchemaBuild",),
            ".schema_extract": ("FlextLdifUtilitiesSchemaExtract",),
            ".schema_format": ("FlextLdifUtilitiesSchemaFormat",),
            ".schema_normalize": ("FlextLdifUtilitiesSchemaNormalize",),
            ".schema_parse": ("FlextLdifUtilitiesSchemaParse",),
            ".server": ("FlextLdifUtilitiesServer",),
            ".transformers": ("FlextLdifUtilitiesTransformers",),
            ".validation": ("FlextLdifUtilitiesValidation",),
            ".writer": ("FlextLdifUtilitiesWriter",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
