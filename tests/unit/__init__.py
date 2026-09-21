# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests.unit package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_tests import c, d, e, h, m, p, r, s, t, td, tf, tk, tm, tv, u, x

    from . import servers, services, utilities
    from .test_acl_registry import TestsFlextLdifAclRegistry
    from .test_api_freeze import TestsFlextLdifApiFreeze
    from .test_collections_models import TestsFlextLdifCollectionsModels
    from .test_constants_data_driven import TestsFlextLdifConstantsDataDriven
    from .test_migration_pipeline_servers import TestsFlextLdifMigrationPipelineServers
    from .test_oid_utilities import TestsFlextLdifOidUtilities
    from .test_parser_utilities import TestsFlextLdifParserUtilities
    from .test_version import TestsFlextLdifVersion
__all__: tuple[str, ...] = (
    "TestsFlextLdifAclRegistry",
    "TestsFlextLdifApiFreeze",
    "TestsFlextLdifCollectionsModels",
    "TestsFlextLdifConstantsDataDriven",
    "TestsFlextLdifMigrationPipelineServers",
    "TestsFlextLdifOidUtilities",
    "TestsFlextLdifParserUtilities",
    "TestsFlextLdifVersion",
    "c",
    "d",
    "e",
    "h",
    "m",
    "p",
    "r",
    "s",
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
    "x",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".servers": ("servers",),
            ".services": ("services",),
            ".test_acl_registry": ("TestsFlextLdifAclRegistry",),
            ".test_api_freeze": ("TestsFlextLdifApiFreeze",),
            ".test_collections_models": ("TestsFlextLdifCollectionsModels",),
            ".test_constants_data_driven": ("TestsFlextLdifConstantsDataDriven",),
            ".test_migration_pipeline_servers": (
                "TestsFlextLdifMigrationPipelineServers",
            ),
            ".test_oid_utilities": ("TestsFlextLdifOidUtilities",),
            ".test_parser_utilities": ("TestsFlextLdifParserUtilities",),
            ".test_version": ("TestsFlextLdifVersion",),
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
