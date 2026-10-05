# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Utilities package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import install_lazy_exports

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

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdifUtilitiesACL": ".acl",
        "FlextLdifUtilitiesAttribute": ".attribute",
        "FlextLdifUtilitiesCollectionLdif": ".collection_ldif",
        "FlextLdifUtilitiesDN": ".dn",
        "FlextLdifUtilitiesDispatch": ".dispatch",
        "FlextLdifUtilitiesEntry": ".entry",
        "FlextLdifUtilitiesEvents": ".events",
        "FlextLdifUtilitiesMetadata": ".metadata",
        "FlextLdifUtilitiesNormalizeAttrsTransformer": "._transformer_attrs",
        "FlextLdifUtilitiesNormalizeDnTransformer": "._transformer_dn",
        "FlextLdifUtilitiesOID": ".oid",
        "FlextLdifUtilitiesObjectClass": ".object_class",
        "FlextLdifUtilitiesParser": ".parser",
        "FlextLdifUtilitiesPipeline": ".pipeline",
        "FlextLdifUtilitiesSchema": ".schema",
        "FlextLdifUtilitiesSchemaBuild": ".schema_build",
        "FlextLdifUtilitiesSchemaExtract": ".schema_extract",
        "FlextLdifUtilitiesSchemaFormat": ".schema_format",
        "FlextLdifUtilitiesSchemaNormalize": ".schema_normalize",
        "FlextLdifUtilitiesSchemaParse": ".schema_parse",
        "FlextLdifUtilitiesServer": ".server",
        "FlextLdifUtilitiesTransformer": ".transformers",
        "FlextLdifUtilitiesTransformers": ".transformers",
        "FlextLdifUtilitiesValidation": ".validation",
        "FlextLdifUtilitiesWriter": ".writer",
    }),
    public_exports=__all__,
)
