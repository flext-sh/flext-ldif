# AUTO-GENERATED FILE — Regenerate with: make gen
"""Utilities package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

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
