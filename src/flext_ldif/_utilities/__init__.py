# AUTO-GENERATED FILE — Regenerate with: make gen
"""Utilities package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".acl": ("FlextLdifUtilitiesACL",),
        ".attribute": ("FlextLdifUtilitiesAttribute",),
        ".collection_ldif": ("FlextLdifUtilitiesCollectionLdif",),
        ".detection": ("FlextLdifUtilitiesDetection",),
        ".dispatch": ("FlextLdifUtilitiesDispatch",),
        ".dn": ("FlextLdifUtilitiesDN",),
        ".entry": ("FlextLdifUtilitiesEntry",),
        ".events": ("FlextLdifUtilitiesEvents",),
        ".metadata": ("FlextLdifUtilitiesMetadata",),
        ".object_class": ("FlextLdifUtilitiesObjectClass",),
        ".oid": ("FlextLdifUtilitiesOID",),
        ".parser": ("FlextLdifUtilitiesParser",),
        ".parsers": ("FlextLdifUtilitiesParsers",),
        ".pipeline": ("FlextLdifUtilitiesPipeline",),
        ".result": (
            "FlextLdifUtilitiesResult",
            "r",
        ),
        ".schema": ("FlextLdifUtilitiesSchema",),
        ".server": ("FlextLdifUtilitiesServer",),
        ".transformers": (
            "FlextLdifUtilitiesTransformer",
            "FlextLdifUtilitiesTransformers",
        ),
        ".validation": ("FlextLdifUtilitiesValidation",),
        ".writer": ("FlextLdifUtilitiesWriter",),
        ".writers": ("FlextLdifUtilitiesWriters",),
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
