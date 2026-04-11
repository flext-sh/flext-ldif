# AUTO-GENERATED FILE — Regenerate with: make gen
"""Unit package."""

from __future__ import annotations

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)

_LAZY_IMPORTS = merge_lazy_imports(
    (
        ".servers",
        ".services",
        ".utilities",
    ),
    build_lazy_import_map(
        {
            ".test_acl_registry": ("test_acl_registry",),
            ".test_migration_pipeline": ("test_migration_pipeline",),
            ".test_migration_pipeline_quirks": ("test_migration_pipeline_quirks",),
            ".test_oid_utilities": ("test_oid_utilities",),
            ".test_parser_utilities": ("test_parser_utilities",),
            ".test_protocols": ("test_protocols",),
            ".test_server_utilities": ("test_server_utilities",),
            ".test_typings": ("test_typings",),
            ".test_version": ("test_version",),
        },
    ),
    exclude_names=(
        "cleanup_submodule_namespace",
        "install_lazy_exports",
        "lazy_getattr",
        "logger",
        "merge_lazy_imports",
        "output",
        "output_reporting",
    ),
    module_name=__name__,
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
