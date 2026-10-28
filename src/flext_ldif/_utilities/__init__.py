# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Utilities package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._utilities._lazy_meta import FlextLdifUtilitiesLazyMeta
    from flext_ldif._utilities._lazy_tree import FlextLdifUtilitiesLazyTree
    from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
    from flext_ldif._utilities.attribute import FlextLdifUtilitiesAttribute
    from flext_ldif._utilities.collection_ldif import FlextLdifUtilitiesCollectionLdif
    from flext_ldif._utilities.dispatch import FlextLdifUtilitiesDispatch
    from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
    from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
    from flext_ldif._utilities.events import FlextLdifUtilitiesEvents
    from flext_ldif._utilities.flext_ldif_servers_oud_utilities import (
        FlextLdifServersOudUtilities,
    )
    from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
    from flext_ldif._utilities.object_class import FlextLdifUtilitiesObjectClass
    from flext_ldif._utilities.oid import FlextLdifUtilitiesOID
    from flext_ldif._utilities.parser import FlextLdifUtilitiesParser
    from flext_ldif._utilities.pipeline import FlextLdifUtilitiesPipeline
    from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema
    from flext_ldif._utilities.server import FlextLdifUtilitiesServer
    from flext_ldif._utilities.transformers import FlextLdifUtilitiesTransformers
    from flext_ldif._utilities.validation import FlextLdifUtilitiesValidation
    from flext_ldif._utilities.writer import FlextLdifUtilitiesWriter


__all__: tuple[str, ...] = (
    "FlextLdifServersOudUtilities",
    "FlextLdifUtilitiesACL",
    "FlextLdifUtilitiesAttribute",
    "FlextLdifUtilitiesCollectionLdif",
    "FlextLdifUtilitiesDN",
    "FlextLdifUtilitiesDispatch",
    "FlextLdifUtilitiesEntry",
    "FlextLdifUtilitiesEvents",
    "FlextLdifUtilitiesLazyMeta",
    "FlextLdifUtilitiesLazyTree",
    "FlextLdifUtilitiesMetadata",
    "FlextLdifUtilitiesOID",
    "FlextLdifUtilitiesObjectClass",
    "FlextLdifUtilitiesParser",
    "FlextLdifUtilitiesPipeline",
    "FlextLdifUtilitiesSchema",
    "FlextLdifUtilitiesServer",
    "FlextLdifUtilitiesTransformers",
    "FlextLdifUtilitiesValidation",
    "FlextLdifUtilitiesWriter",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdifServersOudUtilities": ".flext_ldif_servers_oud_utilities",
        "FlextLdifUtilitiesACL": ".acl",
        "FlextLdifUtilitiesAttribute": ".attribute",
        "FlextLdifUtilitiesCollectionLdif": ".collection_ldif",
        "FlextLdifUtilitiesDN": ".dn",
        "FlextLdifUtilitiesDispatch": ".dispatch",
        "FlextLdifUtilitiesEntry": ".entry",
        "FlextLdifUtilitiesEvents": ".events",
        "FlextLdifUtilitiesLazyMeta": "._lazy_meta",
        "FlextLdifUtilitiesLazyTree": "._lazy_tree",
        "FlextLdifUtilitiesMetadata": ".metadata",
        "FlextLdifUtilitiesOID": ".oid",
        "FlextLdifUtilitiesObjectClass": ".object_class",
        "FlextLdifUtilitiesParser": ".parser",
        "FlextLdifUtilitiesPipeline": ".pipeline",
        "FlextLdifUtilitiesSchema": ".schema",
        "FlextLdifUtilitiesServer": ".server",
        "FlextLdifUtilitiesTransformers": ".transformers",
        "FlextLdifUtilitiesValidation": ".validation",
        "FlextLdifUtilitiesWriter": ".writer",
    }),
    public_exports=__all__,
)
