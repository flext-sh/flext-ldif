# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Utilities package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._utilities._transformer_attrs import (
        FlextLdifUtilitiesNormalizeAttrsTransformer,
    )
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
    from flext_ldif._utilities.transformers import (
        FlextLdifUtilitiesTransformer,
        FlextLdifUtilitiesTransformers,
    )
    from flext_ldif._utilities.validation import FlextLdifUtilitiesValidation
    from flext_ldif._utilities.writer import FlextLdifUtilitiesWriter


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
            ".transformers": (
                "FlextLdifUtilitiesTransformer",
                "FlextLdifUtilitiesTransformers",
            ),
            ".validation": ("FlextLdifUtilitiesValidation",),
            ".writer": ("FlextLdifUtilitiesWriter",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    ),
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
