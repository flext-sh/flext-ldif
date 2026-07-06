# AUTO-GENERATED FILE — Regenerate with: make gen
"""Utilities package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._utilities._transformer_attrs import (
        FlextLdifUtilitiesNormalizeAttrsTransformer,
    )
    from flext_ldif._utilities._transformer_base import FlextLdifUtilitiesTransformer
    from flext_ldif._utilities._transformer_dn import (
        FlextLdifUtilitiesNormalizeDnTransformer,
    )
    from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
    from flext_ldif._utilities.attribute import FlextLdifUtilitiesAttribute
    from flext_ldif._utilities.collection_ldif import FlextLdifUtilitiesCollectionLdif
    from flext_ldif._utilities.dispatch import FlextLdifUtilitiesDispatch
    from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
    from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
    from flext_ldif._utilities.events import FlextLdifUtilitiesEvents
    from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
    from flext_ldif._utilities.object_class import FlextLdifUtilitiesObjectClass
    from flext_ldif._utilities.oid import FlextLdifUtilitiesOID
    from flext_ldif._utilities.parser import FlextLdifUtilitiesParser
    from flext_ldif._utilities.pipeline import FlextLdifUtilitiesPipeline
    from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema
    from flext_ldif._utilities.schema_build import FlextLdifUtilitiesSchemaBuild
    from flext_ldif._utilities.schema_extract import FlextLdifUtilitiesSchemaExtract
    from flext_ldif._utilities.schema_format import FlextLdifUtilitiesSchemaFormat
    from flext_ldif._utilities.schema_normalize import FlextLdifUtilitiesSchemaNormalize
    from flext_ldif._utilities.schema_parse import FlextLdifUtilitiesSchemaParse
    from flext_ldif._utilities.server import FlextLdifUtilitiesServer
    from flext_ldif._utilities.transformers import FlextLdifUtilitiesTransformers
    from flext_ldif._utilities.validation import FlextLdifUtilitiesValidation
    from flext_ldif._utilities.writer import FlextLdifUtilitiesWriter
_LAZY_IMPORTS = build_lazy_import_map(
    {
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
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
