# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests.unit package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from types import MappingProxyType

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from . import servers as servers
    from . import services as services
    from . import utilities as utilities
    from flext_tests import c, d, e, h, m, p, r, s, t, td, tf, tk, tm, tv, u, x

    from .fixtures import (
        api,
        conversion_matrix,
        fixtures_dir,
        migration_dirs,
        migration_pipeline_factory,
        oid_acl_fixture,
        oid_acl_server,
        oid_entries,
        oid_entries_fixture,
        oid_integration_fixture,
        oid_schema_fixture,
        oid_schema_server,
        oid_server,
        oud_acl_fixture,
        oud_acl_server,
        oud_entries,
        oud_entries_fixture,
        oud_integration_fixture,
        oud_schema_fixture,
        oud_schema_server,
        oud_server,
        parser,
        server,
        writer,
    )
    from .test_acl_registry import TestsFlextLdifAclRegistry
    from .test_api_freeze import (
        CLASS_SYMBOLS,
        FACADE_ALIAS_OWNERS,
        METADATA_STRING_SYMBOLS,
        PRIVATE_ROOT_SYMBOLS,
        PUBLIC_API,
        TestsFlextLdifApiFreeze,
    )
    from .test_collections_models import TestsFlextLdifCollectionsModels
    from .test_constants_data_driven import TestsFlextLdifConstantsDataDriven
    from .test_migration_pipeline_servers import TestsFlextLdifMigrationPipelineServers
    from .test_oid_utilities import TestsFlextLdifOidUtilities
    from .test_parser_utilities import TestsFlextLdifParserUtilities
    from .test_version import FlextLdifVersion, TestsFlextLdifVersion, version_module
__all__: tuple[str, ...] = (
    "CLASS_SYMBOLS",
    "FACADE_ALIAS_OWNERS",
    "METADATA_STRING_SYMBOLS",
    "PRIVATE_ROOT_SYMBOLS",
    "PUBLIC_API",
    "FlextLdifVersion",
    "TestsFlextLdifAclRegistry",
    "TestsFlextLdifApiFreeze",
    "TestsFlextLdifCollectionsModels",
    "TestsFlextLdifConstantsDataDriven",
    "TestsFlextLdifMigrationPipelineServers",
    "TestsFlextLdifOidUtilities",
    "TestsFlextLdifParserUtilities",
    "TestsFlextLdifVersion",
    "api",
    "c",
    "conversion_matrix",
    "d",
    "e",
    "fixtures_dir",
    "h",
    "m",
    "migration_dirs",
    "migration_pipeline_factory",
    "oid_acl_fixture",
    "oid_acl_server",
    "oid_entries",
    "oid_entries_fixture",
    "oid_integration_fixture",
    "oid_schema_fixture",
    "oid_schema_server",
    "oid_server",
    "oud_acl_fixture",
    "oud_acl_server",
    "oud_entries",
    "oud_entries_fixture",
    "oud_integration_fixture",
    "oud_schema_fixture",
    "oud_schema_server",
    "oud_server",
    "p",
    "parser",
    "r",
    "s",
    "server",
    "servers",
    "services",
    "t",
    "td",
    "tf",
    "tk",
    "tm",
    "tv",
    "u",
    "utilities",
    "version_module",
    "writer",
    "x",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".fixtures": (
                "api",
                "conversion_matrix",
                "fixtures_dir",
                "migration_dirs",
                "migration_pipeline_factory",
                "oid_acl_fixture",
                "oid_acl_server",
                "oid_entries",
                "oid_entries_fixture",
                "oid_integration_fixture",
                "oid_schema_fixture",
                "oid_schema_server",
                "oid_server",
                "oud_acl_fixture",
                "oud_acl_server",
                "oud_entries",
                "oud_entries_fixture",
                "oud_integration_fixture",
                "oud_schema_fixture",
                "oud_schema_server",
                "oud_server",
                "parser",
                "server",
                "writer",
            ),
            ".servers": ("servers",),
            ".services": ("services",),
            ".test_acl_registry": ("TestsFlextLdifAclRegistry",),
            ".test_api_freeze": (
                "CLASS_SYMBOLS",
                "FACADE_ALIAS_OWNERS",
                "METADATA_STRING_SYMBOLS",
                "PRIVATE_ROOT_SYMBOLS",
                "PUBLIC_API",
                "TestsFlextLdifApiFreeze",
            ),
            ".test_collections_models": ("TestsFlextLdifCollectionsModels",),
            ".test_constants_data_driven": ("TestsFlextLdifConstantsDataDriven",),
            ".test_migration_pipeline_servers": (
                "TestsFlextLdifMigrationPipelineServers",
            ),
            ".test_oid_utilities": ("TestsFlextLdifOidUtilities",),
            ".test_parser_utilities": ("TestsFlextLdifParserUtilities",),
            ".test_version": (
                "FlextLdifVersion",
                "TestsFlextLdifVersion",
                "version_module",
            ),
            ".utilities": ("utilities",),
            "flext_tests": (
                "c",
                "d",
                "e",
                "h",
                "m",
                "p",
                "r",
                "s",
                "t",
                "td",
                "tf",
                "tk",
                "tm",
                "tv",
                "u",
                "x",
            ),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
