# AUTO-GENERATED FILE — Regenerate with: make gen
"""Examples package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from examples.acl_processing import ExamplesFlextLdifAclProcessing, main
    from examples.advanced_processing import (
        access_all_utilities,
        basic_batch_processing,
        complete_processing_pipeline,
        parallel_processing,
        use_dn_utilities,
        use_encoding_utilities,
        use_file_utilities,
        use_ldif_utilities,
        use_text_utilities,
        use_time_utilities,
        use_validation_utilities,
    )
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
    from examples.utilities import ExamplesFlextLdifUtilities, u
    from flext_ldif import (
        build_lazy_import_map,
        c,
        cleanup_submodule_namespace,
        cli,
        config,
        core,
        d,
        e,
        h,
        install_lazy_exports,
        lazy,
        lazy_getattr,
        lazy_member,
        ldif,
        m,
        merge_lazy_imports,
        normalize_lazy_imports,
        p,
        r,
        resolve_lazy_members,
        s,
        settings,
        t,
        x,
    )


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
    "access_all_utilities",
    "basic_batch_processing",
    "batch_schema_operations",
    "build_lazy_import_map",
    "c",
    "cleanup_submodule_namespace",
    "cli",
    "complete_processing_pipeline",
    "config",
    "core",
    "create_entry_or_none",
    "d",
    "e",
    "h",
    "install_lazy_exports",
    "intelligent_schema_building",
    "lazy",
    "lazy_getattr",
    "lazy_member",
    "ldif",
    "m",
    "main",
    "merge_lazy_imports",
    "normalize_lazy_imports",
    "object_class_entries",
    "p",
    "parallel_processing",
    "parallel_schema_validation",
    "r",
    "railway_schema_pipeline",
    "resolve_lazy_members",
    "s",
    "schema_migration_pipeline",
    "settings",
    "t",
    "u",
    "use_dn_utilities",
    "use_encoding_utilities",
    "use_file_utilities",
    "use_ldif_utilities",
    "use_text_utilities",
    "use_time_utilities",
    "use_validation_utilities",
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
        "access_all_utilities": ".advanced_processing",
        "basic_batch_processing": ".advanced_processing",
        "batch_schema_operations": ".schema_operations",
        "build_lazy_import_map": "flext_ldif",
        "c": "flext_ldif",
        "cleanup_submodule_namespace": "flext_ldif",
        "cli": "flext_ldif",
        "complete_processing_pipeline": ".advanced_processing",
        "config": "flext_ldif",
        "core": "flext_ldif",
        "create_entry_or_none": ".schema_building",
        "d": "flext_ldif",
        "e": "flext_ldif",
        "h": "flext_ldif",
        "install_lazy_exports": "flext_ldif",
        "intelligent_schema_building": ".schema_operations",
        "lazy": "flext_ldif",
        "lazy_getattr": "flext_ldif",
        "lazy_member": "flext_ldif",
        "ldif": "flext_ldif",
        "m": "flext_ldif",
        "main": ".acl_processing",
        "merge_lazy_imports": "flext_ldif",
        "normalize_lazy_imports": "flext_ldif",
        "object_class_entries": ".schema_building",
        "p": "flext_ldif",
        "parallel_processing": ".advanced_processing",
        "parallel_schema_validation": ".schema_operations",
        "r": "flext_ldif",
        "railway_schema_pipeline": ".schema_operations",
        "resolve_lazy_members": "flext_ldif",
        "s": "flext_ldif",
        "schema_migration_pipeline": ".schema_operations",
        "settings": "flext_ldif",
        "t": "flext_ldif",
        "u": ".utilities",
        "use_dn_utilities": ".advanced_processing",
        "use_encoding_utilities": ".advanced_processing",
        "use_file_utilities": ".advanced_processing",
        "use_ldif_utilities": ".advanced_processing",
        "use_text_utilities": ".advanced_processing",
        "use_time_utilities": ".advanced_processing",
        "use_validation_utilities": ".advanced_processing",
        "x": "flext_ldif",
    }),
    public_exports=__all__,
)
