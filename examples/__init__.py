# AUTO-GENERATED FILE — Regenerate with: make gen
"""Examples package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import install_lazy_exports

if TYPE_CHECKING:
    from examples.acl_processing import ExamplesFlextLdifAclProcessing, main
    from examples.constants import ExamplesFlextLdifConstants
    from examples.models import ExamplesFlextLdifModels
    from examples.protocols import ExamplesFlextLdifProtocols
    from examples.schema_batches import ExamplesFlextLdifSchemaBatches
    from examples.schema_building import (
        ExamplesFlextLdifSchemaBuilding,
        create_entry_or_none,
        object_class_entries,
    )
    from examples.schema_migration import ExamplesFlextLdifSchemaMigration
    from examples.schema_operations import (
        batch_schema_operations,
        intelligent_schema_building,
        parallel_schema_validation,
        railway_schema_pipeline,
        schema_migration_pipeline,
    )
    from examples.schema_pipeline import ExamplesFlextLdifSchemaPipeline
    from examples.schema_validation import ExamplesFlextLdifSchemaValidation
    from examples.typings import ExamplesFlextLdifTypes
    from examples.utilities import ExamplesFlextLdifUtilities
    from flext_ldif import c, d, e, h, m, p, r, s, t, u, x


__all__: tuple[str, ...] = (
    "ExamplesFlextLdifAclProcessing",
    "ExamplesFlextLdifConstants",
    "ExamplesFlextLdifModels",
    "ExamplesFlextLdifProtocols",
    "ExamplesFlextLdifSchemaBatches",
    "ExamplesFlextLdifSchemaBuilding",
    "ExamplesFlextLdifSchemaMigration",
    "ExamplesFlextLdifSchemaPipeline",
    "ExamplesFlextLdifSchemaValidation",
    "ExamplesFlextLdifTypes",
    "ExamplesFlextLdifUtilities",
    "batch_schema_operations",
    "c",
    "create_entry_or_none",
    "d",
    "e",
    "h",
    "intelligent_schema_building",
    "m",
    "main",
    "object_class_entries",
    "p",
    "parallel_schema_validation",
    "r",
    "railway_schema_pipeline",
    "s",
    "schema_migration_pipeline",
    "t",
    "u",
    "x",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "ExamplesFlextLdifAclProcessing": ".acl_processing",
        "ExamplesFlextLdifConstants": ".constants",
        "ExamplesFlextLdifModels": ".models",
        "ExamplesFlextLdifProtocols": ".protocols",
        "ExamplesFlextLdifSchemaBatches": ".schema_batches",
        "ExamplesFlextLdifSchemaBuilding": ".schema_building",
        "ExamplesFlextLdifSchemaMigration": ".schema_migration",
        "ExamplesFlextLdifSchemaPipeline": ".schema_pipeline",
        "ExamplesFlextLdifSchemaValidation": ".schema_validation",
        "ExamplesFlextLdifTypes": ".typings",
        "ExamplesFlextLdifUtilities": ".utilities",
        "batch_schema_operations": ".schema_operations",
        "c": "flext_ldif",
        "create_entry_or_none": ".schema_building",
        "d": "flext_ldif",
        "e": "flext_ldif",
        "h": "flext_ldif",
        "intelligent_schema_building": ".schema_operations",
        "m": "flext_ldif",
        "main": ".acl_processing",
        "object_class_entries": ".schema_building",
        "p": "flext_ldif",
        "parallel_schema_validation": ".schema_operations",
        "r": "flext_ldif",
        "railway_schema_pipeline": ".schema_operations",
        "s": "flext_ldif",
        "schema_migration_pipeline": ".schema_operations",
        "t": "flext_ldif",
        "u": "flext_ldif",
        "x": "flext_ldif",
    }),
    public_exports=__all__,
)
